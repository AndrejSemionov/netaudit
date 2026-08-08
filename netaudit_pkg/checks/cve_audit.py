"""
CVE audit of installed software via SSH. Two steps:
  1. Collect facts about services (version + relevant config) - reuses
     the logic from server_security.py (_ssh_connect/_run).
  2. Version matching via OSV.dev (https://osv.dev, no key needed, batch query).

Result: a list of CVEs found for each service with severity (if a CVSS score
is available) and fix data (affected/fixed versions). The final "what to do"
verdict is given by the shared ai_analyze() in history.py - this just feeds
in a 'cve' section with facts and config, so the AI can match a vulnerability
against the actual configuration instead of just restating a raw CVSS score.

Cache: cve_cache in storage.py, 24h TTL - to avoid hammering OSV.dev on every run.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

import httpx

from ..registry import register
from .. import storage
from .server_security import _ssh_connect, _run, paramiko

OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch'
OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/{id}'
CACHE_TTL_HOURS = 24


# ===========================================================================
# Collecting service versions over SSH
# ===========================================================================

def _parse_version(text: str) -> str | None:
    m = re.search(r'(\d+\.\d+(?:\.\d+)?)', text)
    return m.group(1) if m else None


def collect_packages(client) -> list[dict]:
    """
    Returns a list of {name, version, ecosystem, raw} for known services,
    plus a general snapshot of installed deb packages (for ecosystem='Debian' in OSV).
    """
    packages = []

    # --- nginx ---
    out, _ = _run(client, 'nginx -v 2>&1')
    ver = _parse_version(out)
    if ver:
        packages.append({'name': 'nginx', 'version': ver, 'ecosystem': 'Debian', 'raw': out.strip()})

    # --- OpenSSH ---
    out, _ = _run(client, 'ssh -V 2>&1')
    ver = _parse_version(out)
    if ver:
        packages.append({'name': 'openssh', 'version': ver, 'ecosystem': 'Debian', 'raw': out.strip()})

    # --- MySQL / MariaDB ---
    out, _ = _run(client, 'mysql --version 2>/dev/null || mariadb --version 2>/dev/null')
    ver = _parse_version(out)
    if ver:
        name = 'mariadb' if 'mariadb' in out.lower() else 'mysql'
        packages.append({'name': name, 'version': ver, 'ecosystem': 'Debian', 'raw': out.strip()})

    # --- PHP ---
    out, _ = _run(client, 'php -v 2>/dev/null')
    ver = _parse_version(out)
    if ver:
        packages.append({'name': 'php', 'version': ver, 'ecosystem': 'Debian', 'raw': out.strip().splitlines()[0] if out.strip() else ''})

    # --- kernel ---
    out, _ = _run(client, 'uname -r')
    if out.strip():
        packages.append({'name': 'linux', 'version': out.strip(), 'ecosystem': 'Debian', 'raw': out.strip()})

    # --- WordPress (if wp-config.php is found in standard locations) ---
    out, _ = _run(client, "find /var/www -maxdepth 3 -iname 'wp-includes' -type d 2>/dev/null | head -1")
    wp_dir = out.strip()
    if wp_dir:
        base = wp_dir.rsplit('/wp-includes', 1)[0]
        ver_out, _ = _run(client, f"grep -m1 \"\\$wp_version = \" {base}/wp-includes/version.php 2>/dev/null")
        ver = _parse_version(ver_out)
        if ver:
            packages.append({'name': 'wordpress', 'version': ver, 'ecosystem': 'WordPress', 'raw': ver_out.strip()})

    return packages


# ===========================================================================
# OSV.dev - matching + details
# ===========================================================================

def _cache_get(name: str, version: str) -> list | None:
    row = storage.cve_get(f'{name}::{version}')
    if not row:
        return None
    updated = datetime.fromisoformat(row['updated_at'])
    if datetime.now() - updated > timedelta(hours=CACHE_TTL_HOURS):
        return None
    return row['data']


def _cache_set(name: str, version: str, data: list) -> None:
    storage.cve_set(f'{name}::{version}', data)


def query_osv(packages: list[dict]) -> dict[str, list]:
    """Returns {pkg_name: [vuln_ids...]} using a batch query, with caching."""
    to_query = []
    result: dict[str, list] = {}

    for p in packages:
        cached = _cache_get(p['name'], p['version'])
        if cached is not None:
            result[p['name']] = cached
        else:
            to_query.append(p)

    if not to_query:
        return result

    try:
        resp = httpx.post(
            OSV_BATCH_URL,
            json={'queries': [
                {'package': {'name': p['name'], 'ecosystem': p['ecosystem']}, 'version': p['version']}
                for p in to_query
            ]},
            timeout=20,
        )
        resp.raise_for_status()
        batch = resp.json().get('results', [])
    except httpx.HTTPError:
        # OSV is unreachable - don't fail the whole check, just skip CVE data for unqueried ones
        for p in to_query:
            result.setdefault(p['name'], [])
        return result

    for p, r in zip(to_query, batch):
        ids = [v['id'] for v in r.get('vulns', [])]
        result[p['name']] = ids
        _cache_set(p['name'], p['version'], ids)

    return result


def fetch_vuln_details(vuln_id: str) -> dict:
    try:
        resp = httpx.get(OSV_VULN_URL.format(id=vuln_id), timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError:
        return {'id': vuln_id, 'error': 'failed to fetch details'}

    severity = None
    for sev in data.get('severity', []):
        if sev.get('type') == 'CVSS_V3':
            severity = sev.get('score')

    fixed_versions = []
    for aff in data.get('affected', []):
        for rng in aff.get('ranges', []):
            for ev in rng.get('events', []):
                if 'fixed' in ev:
                    fixed_versions.append(ev['fixed'])

    return {
        'id': vuln_id,
        'summary': data.get('summary') or data.get('details', '')[:200],
        'severity': severity,
        'fixed_versions': sorted(set(fixed_versions)),
        'references': [r['url'] for r in data.get('references', [])[:3]],
    }


# ===========================================================================
# Combined check
# ===========================================================================

@register(
    id='cve_audit', label='CVE audit of installed software (SSH)', category='security',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Host', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'User', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH port', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Key path', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Password (if not using a key)', 'default': ''},
    ],
    required_tools=[],
    description='Collects installed software versions (nginx, ssh, mysql/mariadb, php, kernel, wordpress) '
                'over SSH and checks them against the OSV.dev vulnerability database. AI analysis (shared '
                'ai_analyze) will match found CVEs against the actual service config and say what actually needs updating.',
)
def check_cve_audit(host='', user='root', port=22, key_path='', password='') -> dict:
    if paramiko is None:
        return {'error': 'paramiko not installed'}
    if not host:
        return {'error': 'host not specified'}
    try:
        client = _ssh_connect(host, user, port, key_path, password)
    except Exception as e:
        return {'error': f'could not connect: {e}'}

    try:
        packages = collect_packages(client)
    finally:
        client.close()

    if not packages:
        return {'host': host, 'packages': [], 'findings': [],
                'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'ok': 0}}

    vuln_ids_by_pkg = query_osv(packages)

    findings = []
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'ok': 0}

    for p in packages:
        ids = vuln_ids_by_pkg.get(p['name'], [])
        if not ids:
            findings.append({
                'package': p['name'], 'version': p['version'],
                'severity': 'ok', 'cve': None, 'title': 'no known CVEs found',
            })
            counts['ok'] += 1
            continue
        for vid in ids[:10]:  # cap it so we don't DDoS OSV for a package with a hundred CVEs
            details = fetch_vuln_details(vid)
            score = details.get('severity')
            try:
                score_f = float(score.split('/')[0]) if score else None
            except (ValueError, AttributeError):
                score_f = None
            if score_f is not None:
                sev = 'critical' if score_f >= 9 else 'high' if score_f >= 7 else 'medium' if score_f >= 4 else 'low'
            else:
                sev = 'medium'  # unknown score - don't downplay it
            counts[sev] = counts.get(sev, 0) + 1
            findings.append({
                'package': p['name'], 'version': p['version'], 'severity': sev,
                'cve': vid, 'title': details.get('summary', ''),
                'fixed_versions': details.get('fixed_versions', []),
                'references': details.get('references', []),
            })

    return {
        'host': host,
        'packages': packages,
        'findings': findings,
        'summary': counts,
    }
