"""
Version data for the Laravel checks (docs/research/laravel_audit.md §3,
contract L3).

- Packages: a composer.lock (both sections) or vendor/composer/installed.json
  (Composer 2 and 1) read into name and version, the 'v' prefix stripped
  as cve_audit does.
- Vulnerabilities: OSV.dev, ecosystem Packagist (records from the GitHub
  Advisory Database, CC BY 4.0), asked through cve_audit.query_osv (one
  batch, a 24 h cache); each record is then read for its title, rating,
  CVE and the fix for this version.
- Support: endoflife.date's Laravel release lines (MIT): whether the
  release line still gets security fixes.

Free, no key. A failed or unexpected answer is said as such - never "no
vulnerabilities" or "supported".
"""

from __future__ import annotations

import json
from datetime import date
from urllib.parse import quote

import httpx

from . import wordpress_org

OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/{id}'
OSV_LINK = 'https://osv.dev/vulnerability/{id}'
EOL_URL = 'https://endoflife.date/api/laravel.json'
TIMEOUT = 15
MAX_PACKAGES = 500        # a lock beyond this is cut, and says so
MAX_ADVISORIES = 100      # records read in full; the rest are still reported, by id

NOTICES = [
    {'name': 'OSV.dev', 'notice': 'Vulnerability data from OSV.dev (osv.dev), the Packagist ecosystem; '
                                  'each record keeps the licence of its source.',
     'license': '', 'license_url': 'https://google.github.io/osv.dev/faq/'},
    {'name': 'GitHub Advisory Database',
     'notice': 'Advisories from the GitHub Advisory Database (github.com/advisories).',
     'license': 'CC BY 4.0', 'license_url': 'https://creativecommons.org/licenses/by/4.0/'},
    {'name': 'endoflife.date', 'notice': 'Laravel support dates from endoflife.date.',
     'license': 'MIT', 'license_url': 'https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE'},
]

_SEVERITY = {'CRITICAL': 'critical', 'HIGH': 'high', 'MODERATE': 'medium', 'LOW': 'low'}


def _get_json(url: str) -> tuple[int, object]:
    """The one HTTP call of this module: (status code, parsed JSON or None).
    Transport errors raise httpx.HTTPError."""
    resp = httpx.get(url, timeout=TIMEOUT, headers={'User-Agent': wordpress_org.USER_AGENT})
    try:
        data = resp.json()
    except ValueError:
        data = None
    return resp.status_code, data


def _ask(url: str) -> tuple[int, object]:
    """_get_json, once more after a transport error (a network blip)."""
    try:
        return _get_json(url)
    except httpx.HTTPError:
        return _get_json(url)


def lock_packages(text: str) -> list[dict] | None:
    """[{'name', 'version'}] from a composer.lock or installed.json; None
    when the text is not one (a "not found" page, composer.json)."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    if isinstance(data, dict):
        keys = [key for key in ('packages', 'packages-dev') if key in data]
        if not keys:
            return None
        sections = [data[key] for key in keys]
    elif isinstance(data, list):
        sections = [data]          # installed.json of Composer 1
    else:
        return None
    if not all(isinstance(section, list) for section in sections):
        return None
    packages = []
    for section in sections:
        for entry in section:
            if not isinstance(entry, dict):
                continue
            name, version = entry.get('name'), entry.get('version')
            if isinstance(name, str) and isinstance(version, str) and name and version:
                packages.append({'name': name, 'version': version.removeprefix('v')})
    if isinstance(data, list) and not packages:
        return None                # a JSON list of something else
    return packages


def _padded(a: tuple, b: tuple) -> tuple[tuple, tuple]:
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)), b + (0,) * (width - len(b))


def _within(version: tuple, introduced: str | None, fixed: str) -> bool:
    low = (0,) if introduced in (None, '0') else wordpress_org.version_tuple(introduced)
    high = wordpress_org.version_tuple(fixed)
    if low is None or high is None:
        return False
    v, lo = _padded(version, low)
    v, hi = _padded(version, high)
    return lo <= v < hi


def _fixes(record: dict, package: str, version: str) -> list[str]:
    """The release that fixes this version, or every fix of the package when
    the version is in no range that can be compared."""
    current = wordpress_org.version_tuple(version)
    every = []
    for affected in record.get('affected') or []:
        if not isinstance(affected, dict) or not isinstance(affected.get('package'), dict):
            continue
        if str(affected['package'].get('name', '')).lower() != package.lower():
            continue
        for rng in affected.get('ranges') or []:
            introduced = None
            events = rng.get('events') if isinstance(rng, dict) else None
            for event in events if isinstance(events, list) else []:
                if not isinstance(event, dict):
                    continue
                if 'introduced' in event:
                    introduced = str(event['introduced'])
                elif 'fixed' in event:
                    fixed = str(event['fixed'])
                    every.append(fixed)
                    if current is not None and _within(current, introduced, fixed):
                        return [fixed]
                    introduced = None
    return sorted(set(every), key=lambda v: (wordpress_org.version_tuple(v) or (), v))


def advisory(vuln_id: str, package: str, version: str) -> dict:
    """{'id', 'title', 'severity', 'cve', 'fixed', 'link', 'error'}. Without
    the record the advisory is still named, rated medium, with the reason."""
    out = {'id': vuln_id, 'title': None, 'severity': 'medium', 'cve': None, 'fixed': [],
           'link': OSV_LINK.format(id=quote(vuln_id, safe='')), 'error': None}
    try:
        code, data = _ask(OSV_VULN_URL.format(id=quote(vuln_id, safe='')))
    except httpx.HTTPError as e:
        return {**out, 'error': f'OSV.dev: {type(e).__name__}'}
    if code != 200 or not isinstance(data, dict):
        return {**out, 'error': f'OSV.dev: HTTP {code}' if code != 200 else 'OSV.dev: unexpected answer'}
    specific = data.get('database_specific') if isinstance(data.get('database_specific'), dict) else {}
    rating = specific.get('severity')
    aliases = data.get('aliases') if isinstance(data.get('aliases'), list) else []
    title = data.get('summary') or str(data.get('details') or '')[:200] or None
    return {**out, 'title': title, 'severity': _SEVERITY.get(str(rating).upper(), 'medium'),
            'cve': next((a for a in aliases if isinstance(a, str) and a.startswith('CVE-')), None),
            'fixed': _fixes(data, package, version)}


def _query_osv(packages: list[dict]) -> tuple[dict, set]:
    from .checks import cve_audit  # the checks package imports this module
    return cve_audit.query_osv(packages)


def vulnerabilities(packages: list[dict]) -> dict:
    """{'status': 'ok'|'error', 'matches': {name: [advisory]}, 'unanswered':
    [names OSV gave no answer for], 'error', 'checked': packages asked}."""
    asked = packages[:MAX_PACKAGES]
    result, errors = _query_osv([{'name': p['name'], 'version': p['version'], 'ecosystem': 'Packagist'}
                                 for p in asked])
    if asked and len(errors) >= len(asked):
        return {'status': 'error', 'matches': {}, 'unanswered': sorted(errors), 'checked': 0,
                'error': 'OSV.dev gave no answer (a network error or a server error)'}
    matches: dict[str, list] = {}
    read = 0
    for p in asked:
        if p['name'] in errors:
            continue
        found = []
        for vuln_id in result.get(p['name']) or []:
            if read < MAX_ADVISORIES:
                read += 1
                found.append(advisory(vuln_id, p['name'], p['version']))
            else:
                found.append({'id': vuln_id, 'title': None, 'severity': 'medium', 'cve': None, 'fixed': [],
                              'link': OSV_LINK.format(id=quote(vuln_id, safe='')),
                              'error': f'not read: more than {MAX_ADVISORIES} vulnerabilities'})
        matches[p['name']] = found
    unanswered = sorted(errors)
    if len(packages) > MAX_PACKAGES:
        unanswered += [p['name'] for p in packages[MAX_PACKAGES:]]
    return {'status': 'ok', 'matches': matches, 'unanswered': unanswered, 'error': None,
            'checked': len(asked) - len(errors)}


def support(version: str, today: date | None = None) -> dict:
    """{'status': 'supported'|'ended'|'unknown'|'error', 'cycle', 'eol',
    'latest', 'error'}. 'unknown': a release line endoflife.date does not
    list (a dev branch, a line newer than its data) - not "supported"."""
    today = today or date.today()  # noqa: DTZ011 - a calendar date is compared, the server's day is right
    out = {'status': 'unknown', 'cycle': None, 'eol': None, 'latest': None, 'error': None}
    try:
        code, data = _ask(EOL_URL)
    except httpx.HTTPError as e:
        return {**out, 'status': 'error', 'error': f'endoflife.date: {type(e).__name__}'}
    if code != 200:
        return {**out, 'status': 'error', 'error': f'endoflife.date: HTTP {code}'}
    cycles = {str(c['cycle']): c for c in data if isinstance(c, dict) and 'cycle' in c} \
        if isinstance(data, list) else {}
    if not cycles:
        return {**out, 'status': 'error', 'error': 'endoflife.date: unexpected answer'}
    parts = wordpress_org.version_tuple(version)
    if parts is None:
        return out
    line = next((key for key in (f'{parts[0]}.{parts[1]}' if len(parts) > 1 else None, str(parts[0]))
                 if key in cycles), None)
    if line is None:
        listed = [t for t in (wordpress_org.version_tuple(k) for k in cycles) if t]
        if listed and all(_padded(parts, t)[0] < _padded(parts, t)[1] for t in listed):
            return {**out, 'status': 'ended'}      # older than every line it lists
        return out
    cycle = cycles[line]
    out.update(cycle=line, latest=cycle.get('latest') if isinstance(cycle.get('latest'), str) else None)
    eol = cycle.get('eol')
    if eol is True:
        return {**out, 'status': 'ended'}
    if eol is False:
        return {**out, 'status': 'supported'}
    try:
        ends = date.fromisoformat(str(eol))
    except ValueError:
        return out
    return {**out, 'eol': ends.isoformat(), 'status': 'ended' if today >= ends else 'supported'}
