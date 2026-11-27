"""
Known vulnerabilities of the versions a network audit saw
(docs/research/network_audit.md §7.2, §14, contract N7).

- A Debian package revision in a banner (OpenSSH 9.2p1 Debian 2+deb12u3) is
  looked up in OSV for that Debian release: the records a newer revision
  fixes. Never in NVD by the upstream version - Debian backports fixes
  without changing it.
- An Ubuntu banner does not tell its release: named, not looked up.
- Any other version nmap read (its CPE) goes to NVD by `virtualMatchString`:
  "possible" matches only - the caller reports them as such.
- The CISA KEV catalog marks the CVEs exploited in the wild; it is fetched at
  most once a day into a file next to the database, and a failed download
  keeps the previous copy.

Only products and versions leave the network - never an address or a
device name. NVD without a key allows 5 requests in 30 s: the lookups are
paced and capped, and cached for a day in the existing cve_cache.
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta

import httpx

from . import storage, wordpress_org

NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
OSV_URL = 'https://api.osv.dev/v1/query'
TIMEOUT = 25
NVD_PAUSE = 6.5            # 5 requests in 30 s without an API key
MAX_CPES = 8               # NVD lookups per run (the router's first); the rest are a gap
MAX_OSV = 20
CACHE_HOURS = 24
KEV_MAX_AGE_HOURS = 24
NOTICES = [
    {'name': 'NVD', 'notice': 'This product uses the NVD API but is not endorsed or certified by the NVD.',
     'url': 'https://nvd.nist.gov/'},
    {'name': 'OSV.dev', 'notice': 'Debian package vulnerabilities from OSV.dev (Debian Security Tracker data).',
     'url': 'https://osv.dev/'},
    {'name': 'CISA KEV', 'notice': 'Vulnerabilities exploited in the wild from the CISA Known Exploited '
                                   'Vulnerabilities catalog.',
     'url': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'},
]

_CPE_PART = re.compile(r'[A-Za-z0-9._~%-]+')
_CVE = re.compile(r'CVE-\d{4}-\d{4,}')
# nmap product (lower case) -> (Debian source package, its epoch)
_DEBIAN_PACKAGES = {'openssh': ('openssh', '1:')}
_SEVERITIES = ('critical', 'high', 'medium', 'low')

# seams for the tests: the only network calls of this module
_sleep = time.sleep


def _get(url: str, params: dict | None) -> tuple[int, object]:
    resp = httpx.get(url, params=params, timeout=TIMEOUT, headers={'User-Agent': wordpress_org.USER_AGENT})
    try:
        data = resp.json()
    except ValueError:
        data = None
    return resp.status_code, data


def _post(url: str, body: dict) -> tuple[int, object]:
    resp = httpx.post(url, json=body, timeout=TIMEOUT, headers={'User-Agent': wordpress_org.USER_AGENT})
    try:
        data = resp.json()
    except ValueError:
        data = None
    return resp.status_code, data


def _cached(key: str):
    row = storage.cve_get(key)
    if not row:
        return None
    updated = datetime.fromisoformat(row['updated_at'])
    if datetime.now() - updated > timedelta(hours=CACHE_HOURS):  # noqa: DTZ005 - cve_cache stores local naive time
        return None
    return row['data']


def cpe23(uri: str) -> str | None:
    """nmap's CPE 2.2 URI with a clean version -> a CPE 2.3 string, else None."""
    if not isinstance(uri, str) or not uri.startswith('cpe:/'):
        return None
    parts = uri[5:].split(':')
    if len(parts) < 4:
        return None
    part, vendor, product, version = parts[:4]
    if part not in ('a', 'o', 'h') or not all(_CPE_PART.fullmatch(x) for x in (vendor, product, version)):
        return None
    return f'cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*'


def version_source(port: dict) -> dict | None:
    """Where this port's version is looked up: {'kind': 'osv'|'nvd'|'skip', ...},
    or None when nmap read no version."""
    version = port.get('version') or ''
    product = (port.get('product') or '').lower()
    if 'ubuntu' in version.lower():
        return {'kind': 'skip',
                'reason': 'Ubuntu backports fixes and its banner does not tell the release: not looked up'}
    m = re.fullmatch(r'(\S+) Debian (\S+)', version)
    if m:
        upstream, revision = m.groups()
        release = re.search(r'deb(\d+)u', revision)
        package = _DEBIAN_PACKAGES.get(product)
        if not release or not package:
            return {'kind': 'skip', 'reason': f'Debian {product or "package"} {upstream}-{revision}: its release or '
                                              'package is not known, and Debian backports fixes - not looked up'}
        return {'kind': 'osv', 'ecosystem': f'Debian:{release.group(1)}', 'package': package[0],
                'version': f'{package[1]}{upstream}-{revision}'}
    for uri in port.get('cpe') or []:
        found = cpe23(uri) if isinstance(uri, str) and uri.startswith('cpe:/a:') else None
        if found:
            return {'kind': 'nvd', 'cpe': found}
    return None


def _cvss(metrics: dict) -> tuple[float | None, str | None]:
    for key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        for m in metrics.get(key) or []:
            data = m.get('cvssData') or {}
            score = data.get('baseScore')
            severity = (data.get('baseSeverity') or m.get('baseSeverity') or '').lower()
            if isinstance(score, (int, float)):
                return float(score), severity if severity in _SEVERITIES else None
    return None, None


def nvd_cves(cpe: str) -> tuple[list | None, str | None]:
    """([{'id', 'score', 'severity', 'summary'}], None) or (None, why)."""
    key = f'nvd::{cpe}'
    cached = _cached(key)
    if cached is not None:
        return cached, None
    try:
        code, data = _get(NVD_URL, {'virtualMatchString': cpe, 'resultsPerPage': 200})
    except httpx.HTTPError as e:
        return None, f'NVD: {type(e).__name__}'
    if code != 200:
        return None, f'NVD: HTTP {code}'
    if not isinstance(data, dict) or not isinstance(data.get('vulnerabilities'), list):
        return None, 'NVD: unexpected answer'
    cves = []
    for item in data['vulnerabilities']:
        cve = (item or {}).get('cve') if isinstance(item, dict) else None
        if not isinstance(cve, dict) or not _CVE.fullmatch(str(cve.get('id', ''))):
            continue
        score, severity = _cvss(cve.get('metrics') or {})
        summary = next((d.get('value', '') for d in cve.get('descriptions') or []
                        if isinstance(d, dict) and d.get('lang') == 'en'), '')
        cves.append({'id': cve['id'], 'score': score, 'severity': severity, 'summary': str(summary)[:300]})
    storage.cve_set(key, cves)
    return cves, None


def _kev_path():
    return storage.DB_PATH.parent / 'kev.json'


def kev() -> tuple[dict, str | None]:
    """{CVE: {'added', 'ransomware'}} from the CISA KEV catalog, at most a day
    old; a failed download keeps the previous copy and says so."""
    path = _kev_path()
    old = None
    try:
        old = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        old = None
    if isinstance(old, dict) and isinstance(old.get('vulns'), dict):
        try:
            fetched = datetime.fromisoformat(old.get('fetched', ''))
        except ValueError:
            fetched = None
        if fetched and datetime.now() - fetched < timedelta(hours=KEV_MAX_AGE_HOURS):  # noqa: DTZ005 - local time
            return old['vulns'], None
    else:
        old = None
    why = None
    try:
        code, data = _get(KEV_URL, None)
        if code != 200 or not isinstance(data, dict) or not isinstance(data.get('vulnerabilities'), list):
            why = f'HTTP {code}' if code != 200 else 'unexpected answer'
    except httpx.HTTPError as e:
        why = type(e).__name__
    if why:
        if old:
            return old['vulns'], f"KEV: {why}; the previous copy from {old.get('fetched', '?')} is used"
        return {}, f'KEV: {why}, no previous copy'
    vulns = {v['cveID']: {'added': str(v.get('dateAdded', '')),
                          'ransomware': v.get('knownRansomwareCampaignUse') == 'Known'}
             for v in data['vulnerabilities'] if isinstance(v, dict) and _CVE.fullmatch(str(v.get('cveID', '')))}
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_text(json.dumps({'fetched': datetime.now().isoformat(), 'vulns': vulns}),  # noqa: DTZ005 - local
                        encoding='utf-8')
    except OSError:
        pass                            # the catalog still serves this run
    return vulns, None


def osv_debian(ecosystem: str, package: str, version: str) -> tuple[dict | None, str | None]:
    """({'fixed': [CVE...], 'open': n}, None) - the records affecting this
    exact Debian package version, split into fixed in a newer revision and
    not fixed yet - or (None, why)."""
    key = f'osvdeb::{ecosystem}::{package}::{version}'
    cached = _cached(key)
    if cached is not None:
        return cached, None
    try:
        code, data = _post(OSV_URL, {'package': {'ecosystem': ecosystem, 'name': package}, 'version': version})
    except httpx.HTTPError as e:
        return None, f'OSV: {type(e).__name__}'
    if code != 200 or not isinstance(data, dict):
        return None, f'OSV: HTTP {code}' if code != 200 else 'OSV: unexpected answer'
    fixed, still_open = [], 0
    for record in data.get('vulns') or []:
        if not isinstance(record, dict):
            continue
        has_fix = any(isinstance(ev, dict) and ev.get('fixed')
                      for a in record.get('affected') or [] if isinstance(a, dict)
                      and (a.get('package') or {}).get('name') == package
                      for r in a.get('ranges') or [] if isinstance(r, dict)
                      for ev in r.get('events') or [])
        cves = [x for x in record.get('aliases') or [] if _CVE.fullmatch(str(x))]
        if not cves:
            m = _CVE.search(str(record.get('id', '')))
            cves = [m.group(0)] if m else []
        if has_fix:
            fixed += cves
        else:
            still_open += 1
    out = {'fixed': sorted(set(fixed)), 'open': still_open}
    storage.cve_set(key, out)
    return out, None


def lookup(services: list[dict], router_version: str | None) -> dict:
    """Every service's lookups, the router's, and the KEV catalog. Services
    over the NVD cap are listed in 'cut'; nothing but products and versions
    is sent."""
    out = {'services': [], 'router': None, 'kev': {}, 'kev_error': None, 'cut': [], 'skipped': []}
    asked: dict = {}
    requested = False

    def nvd(cpe: str):
        nonlocal requested
        if cpe in asked:
            return asked[cpe]
        if _cached(f'nvd::{cpe}') is None:
            if requested:
                _sleep(NVD_PAUSE)
            requested = True
        asked[cpe] = nvd_cves(cpe)
        return asked[cpe]

    if router_version and re.fullmatch(r'\d+(?:\.\d+){0,3}', router_version):
        cves, error = nvd(f'cpe:2.3:o:mikrotik:routeros:{router_version}:*:*:*:*:*:*:*')
        out['router'] = {'version': router_version, 'cves': cves, 'error': error}
    osv_count = 0
    for s in services:
        where = f"{s['ip']}:{s['port']}"
        if s['kind'] == 'skip':
            out['skipped'].append(f"{where}: {s['reason']}")
        elif s['kind'] == 'nvd':
            if s['cpe'] not in asked and len(asked) >= MAX_CPES:
                out['cut'].append(where)
                continue
            cves, error = nvd(s['cpe'])
            out['services'].append({**s, 'cves': cves, 'error': error})
        elif s['kind'] == 'osv':
            if osv_count >= MAX_OSV:
                out['cut'].append(where)
                continue
            osv_count += 1
            result, error = osv_debian(s['ecosystem'], s['package'], s['version'])
            out['services'].append({**s, 'fixed': (result or {}).get('fixed'), 'open': (result or {}).get('open'),
                                    'error': error})
    out['kev'], out['kev_error'] = kev()
    return out
