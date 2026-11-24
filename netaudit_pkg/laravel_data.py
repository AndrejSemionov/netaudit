"""
Version data for the Laravel checks (docs/research/laravel_audit.md §3,
contract L3, review pass 1).

- Packages: a composer.lock (both sections) or vendor/composer/installed.json
  (Composer 2 and 1) read into name and version, the 'v' prefix stripped
  as cve_audit does. A name or version that is not in Composer's format is
  not used - it came from the site - and is counted as unreadable.
- Vulnerabilities: OSV.dev's batch query, ecosystem Packagist (records from
  the GitHub Advisory Database, CC BY 4.0). Asked here, not through the SSH
  check's cve_audit.query_osv, whose parsing and cache stay as they are:
  only an element in OSV's format says "none known"; a paged, missing or
  malformed one is "no answer" for that package. Each record is then read
  for its title, rating, CVE and the fix of the range this version is in.
- Support: endoflife.date's Laravel release lines (MIT): whether the
  release line still gets security fixes.

Free, no key. A failed or unexpected answer is said as such - never "no
vulnerabilities" or "supported".
"""

from __future__ import annotations

import json
import re
from datetime import date
from urllib.parse import quote

import httpx

from . import wordpress_org

OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch'
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
# Composer's package name (its JSON schema, written so that a failing name
# is rejected in linear time - review pass 2), and a version as a lock writes
# it (1.2.3, v1.2.3, 1.0.0-beta1, dev-main, 2.x-dev, dev-feature/x, 1.2.3+build)
MAX_NAME = 200
MAX_VERSION = 100
_NAME = re.compile(r'[a-z0-9]+(?:[_.-][a-z0-9]+)*/[a-z0-9]+(?:(?:[_.]|-{1,2})[a-z0-9]+)*')
_VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+~/-]*')
_VULN_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,99}')


def _get_json(url: str) -> tuple[int, object]:
    """The one HTTP call of this module: (status code, parsed JSON or None).
    Transport errors raise httpx.HTTPError."""
    resp = httpx.get(url, timeout=TIMEOUT, headers={'User-Agent': wordpress_org.USER_AGENT})
    try:
        data = resp.json()
    except ValueError:
        data = None
    return resp.status_code, data


def _post_json(url: str, body: dict) -> tuple[int, object]:
    """The batch query: (status code, parsed JSON or None). Transport errors
    raise httpx.HTTPError."""
    resp = httpx.post(url, json=body, timeout=TIMEOUT * 2, headers={'User-Agent': wordpress_org.USER_AGENT})
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


def _valid(name, version) -> bool:
    return (isinstance(name, str) and isinstance(version, str)
            and len(name) <= MAX_NAME and len(version) <= MAX_VERSION
            and bool(_NAME.fullmatch(name)) and bool(_VERSION.fullmatch(version)))


def lock_packages(text: str) -> dict | None:
    """{'packages': [{'name', 'version'}], 'unreadable': entries not used,
    'conflicting': names listed with two versions} from a composer.lock or
    installed.json; None when the text is not one (a "not found" page,
    composer.json). Each name is in 'packages' once: an exact repeat is one
    package, a name with two versions is left out and named (review pass 2)."""
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
    versions: dict[str, str] = {}
    conflicting: set[str] = set()
    unreadable = 0
    for section in sections:
        for entry in section:
            name = entry.get('name') if isinstance(entry, dict) else None
            version = entry.get('version') if isinstance(entry, dict) else None
            if not _valid(name, version):
                unreadable += 1
                continue
            version = version.removeprefix('v')
            if name in versions and versions[name] != version:
                conflicting.add(name)
            versions.setdefault(name, version)
    if isinstance(data, list) and not versions:
        return None                # a JSON list of something else
    packages = [{'name': name, 'version': version} for name, version in versions.items() if name not in conflicting]
    return {'packages': packages, 'unreadable': unreadable, 'conflicting': sorted(conflicting)}


def _padded(a: tuple, b: tuple) -> tuple[tuple, tuple]:
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)), b + (0,) * (width - len(b))


def _at_least(version: tuple, bound: str | None) -> bool | None:
    if bound in (None, '0'):
        return True
    low = wordpress_org.version_tuple(bound)
    if low is None:
        return None
    v, lo = _padded(version, low)
    return v >= lo


def _below(version: tuple, bound: str, inclusive: bool = False) -> bool | None:
    high = wordpress_org.version_tuple(bound)
    if high is None:
        return None
    v, hi = _padded(version, high)
    return v <= hi if inclusive else v < hi


def _fixes(record: dict, package: str, version: str) -> list[str]:
    """The release that fixes the range this version is in - [] when the
    range has no fix (open, or last_affected) or the version is in no range
    that can be compared. A fix of another release line is never offered
    (review pass 1)."""
    current = wordpress_org.version_tuple(version)
    if current is None:
        return []
    for affected in record.get('affected') or []:
        if not isinstance(affected, dict) or not isinstance(affected.get('package'), dict):
            continue
        if str(affected['package'].get('name', '')).lower() != package.lower():
            continue
        for rng in affected.get('ranges') or []:
            events = rng.get('events') if isinstance(rng, dict) else None
            introduced = None
            for event in events if isinstance(events, list) else []:
                if not isinstance(event, dict):
                    continue
                if 'introduced' in event:
                    introduced = str(event['introduced'])
                elif 'fixed' in event or 'last_affected' in event:
                    bound = str(event.get('fixed', event.get('last_affected')))
                    inside = _at_least(current, introduced) and _below(current, bound, 'fixed' not in event)
                    if introduced is not None and inside:
                        return [bound] if 'fixed' in event else []
                    introduced = None
    return []


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


def _ids(element) -> list[str] | None:
    """The vulnerability ids of one batch element, or None when it is not one
    of OSV's documented answers: {} (none known) or {"vulns": [{"id": ...}]}.
    A page token - even an empty one - or a field OSV does not document is
    not the whole answer (review pass 2)."""
    if not isinstance(element, dict):
        return None
    if not element:
        return []
    if set(element) != {'vulns'} or not isinstance(element['vulns'], list):
        return None
    ids = [v.get('id') if isinstance(v, dict) else None for v in element['vulns']]
    if not all(isinstance(i, str) and _VULN_ID.fullmatch(i) for i in ids):
        return None
    return list(dict.fromkeys(ids))


def _osv_batch(packages: list[dict]) -> dict[str, list[str] | None] | None:
    """{name: ids, or None for no answer}; None when the batch as a whole
    gave no answer to read."""
    body = {'queries': [{'package': {'name': p['name'], 'ecosystem': 'Packagist'}, 'version': p['version']}
                        for p in packages]}
    try:
        code, data = _post_json(OSV_BATCH_URL, body)
    except httpx.HTTPError:
        return None
    results = data.get('results') if code == 200 and isinstance(data, dict) else None
    if not isinstance(results, list) or len(results) != len(packages):
        return None     # the answers' order is the questions' order: a count that differs cannot be read
    return {p['name']: _ids(element) for p, element in zip(packages, results)}


def vulnerabilities(packages: list[dict]) -> dict:
    """{'status': 'ok'|'error', 'matches': {name: [advisory]}, 'unanswered':
    [names with no answer, or not asked past MAX_PACKAGES], 'error',
    'checked': packages answered}."""
    # one answer per name: an exact repeat is asked once, a name with two
    # versions is not asked - its answers would overwrite each other (review pass 2)
    versions: dict[str, set] = {}
    for p in packages:
        versions.setdefault(p['name'], set()).add(p['version'])
    mixed = sorted(name for name, seen in versions.items() if len(seen) > 1)
    unique, seen_names = [], set(mixed)
    for p in packages:
        if p['name'] not in seen_names:
            seen_names.add(p['name'])
            unique.append(p)
    asked = unique[:MAX_PACKAGES]
    answers = _osv_batch(asked) if asked else {}
    if answers is None:
        return {'status': 'error', 'matches': {}, 'unanswered': [p['name'] for p in packages], 'checked': 0,
                'error': 'OSV.dev gave no answer to read (a network error, a server error or an unexpected answer)'}
    matches: dict[str, list] = {}
    unanswered = []
    read = 0
    for p in asked:
        ids = answers.get(p['name'])
        if ids is None:
            unanswered.append(p['name'])
            continue
        found = []
        for vuln_id in ids:
            if read < MAX_ADVISORIES:
                read += 1
                found.append(advisory(vuln_id, p['name'], p['version']))
            else:
                found.append({'id': vuln_id, 'title': None, 'severity': 'medium', 'cve': None, 'fixed': [],
                              'link': OSV_LINK.format(id=quote(vuln_id, safe='')),
                              'error': f'not read: more than {MAX_ADVISORIES} vulnerabilities'})
        matches[p['name']] = found
    unanswered += mixed + [p['name'] for p in unique[MAX_PACKAGES:]]
    return {'status': 'ok', 'matches': matches, 'unanswered': unanswered, 'error': None,
            'checked': len(matches)}


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
