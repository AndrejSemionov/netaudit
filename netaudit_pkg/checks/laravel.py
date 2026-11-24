"""
Laravel checked from outside (docs/research/laravel_audit.md §4, §6;
contract L2, L3): what any visitor of the site can see. GET requests only,
and only to the site itself; no POST, so Ignition's execute-solution is
never called.

A Laravel site does not show its version: from outside this check sees
misconfigurations - an open .env, debug tools left on, the project folder
served instead of public/ - and the versions only when composer.lock or
vendor/composer/installed.json is public by mistake. installed.json names
what is installed, the lock what was locked: the installed versions are
used and a disagreement is said (review pass 1). An entry that could not be
read, a package OSV gave no answer for, or a file too large to read is
"not checked", never "none known".

Is it Laravel: the XSRF-TOKEN cookie, a cookie encrypted by Laravel (its
value starts with base64 of '{"iv":'), the same on /login, or an open
Laravel tool or file. No sign -> 'not_laravel', nothing judged; no sign
and /login gave no answer -> could not tell.

The outcomes are those of wordpress_external: 'unreachable', 'not_laravel',
'danger' / 'warn', 'incomplete' (a part not checked), 'ok'. The score is
100 minus webprobe.PENALTY per finding; it names the items it could not
count. Content of an open .env, log or lock is read only for the verdict
and never kept.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from urllib.parse import urlparse

import httpx

from .. import laravel_data, webprobe
from ..findings import finding as _finding
from ..findings import subject_id
from ..registry import register

Page = webprobe.Page

ENV_FILES = ('.env', '.env.backup', '.env.bak', '.env.old', '.env.save', '.env.orig', '.env~',
             '.env.production', '.env.prod', '.env.local')
IGNITION = '_ignition/health-check'
TELESCOPE = 'telescope'
HORIZON = 'horizon'
LOGIN = 'login'
LOG_FILE = 'storage/logs/laravel.log'
COMPOSER_JSON = 'composer.json'
COMPOSER_LOCK = 'composer.lock'
INSTALLED = 'vendor/composer/installed.json'
GIT_CONFIG = '.git/config'
INVENTORIES = (COMPOSER_LOCK, INSTALLED)
INVENTORY_MAX_BODY = 4 * 1024 * 1024   # a real lock is often far more than a page's 256 KB
PROBES = (*ENV_FILES, IGNITION, TELESCOPE, HORIZON, LOG_FILE, COMPOSER_JSON, COMPOSER_LOCK, INSTALLED,
          GIT_CONFIG, LOGIN)

TRANSPORT_IDS = {'no_https': 'LV-TLS-001', 'no_redirect': 'LV-TLS-002', 'cert': 'LV-TLS-003',
                 'hsts': 'LV-HDR-001', 'nosniff': 'LV-HDR-002', 'framing': 'LV-HDR-003'}

_ENCRYPTED = 'eyJpdiI6'      # base64 of '{"iv":' - Laravel's EncryptCookies
_ENV_KEY = re.compile(r'^[ \t]*(APP_KEY|DB_PASSWORD)[ \t]*=', re.MULTILINE)
_DEBUGBAR = re.compile(r'<!-- Laravel Debugbar Widget -->|new PhpDebugBar\.\w{0,40}DebugBar\(')
_TELESCOPE = re.compile(r'<title>\s*Telescope\b|<div id="telescope"', re.IGNORECASE)
_HORIZON = re.compile(r'<title>\s*Horizon\b|<div id="horizon"', re.IGNORECASE)
# Monolog's line format: [2026-11-23 10:00:00] production.ERROR: ...
_LOG_LINE = re.compile(r'^\[\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[^\]]*\] [\w-]+\.'
                       r'(?:DEBUG|INFO|NOTICE|WARNING|ERROR|CRITICAL|ALERT|EMERGENCY):', re.MULTILINE)
_GIT_CONFIG = re.compile(r'^\s*\[core\]', re.MULTILINE)
# how a composer.lock, an installed.json of Composer 2 or of Composer 1 begins
_INVENTORY_START = re.compile(r'\s*(?:\{\s*"(?:_readme|content-hash|packages|packages-dev|dev)"|\[\s*\{\s*"name")')

_TRANSPORT = None   # tests put an httpx.MockTransport here


def _fetch(url: str, follow: bool = True, max_body: int | None = None) -> Page:
    """The one request seam of this check (webprobe.fetch)."""
    return webprobe.fetch(url, follow, transport=_TRANSPORT, max_body=max_body or webprobe.MAX_BODY)


def _fetch_twice(url: str, follow: bool = True, max_body: int | None = None) -> Page:
    return webprobe.fetch_twice(lambda u, f: _fetch(u, f, max_body), url, follow)


def _try(url: str, follow: bool = True, max_body: int | None = None) -> Page | None:
    try:
        return _fetch_twice(url, follow, max_body)
    except httpx.HTTPError:
        return None


def _cert_not_after(host: str, port: int) -> datetime:
    return webprobe.cert_not_after(host, port)


def _check_transport(home: Page, base: str, findings: list, checked: list) -> dict | None:
    return webprobe.check_transport(home, base, findings, checked, ids=TRANSPORT_IDS,
                                    fetch_twice_fn=lambda u: _fetch_twice(u),
                                    cert_fn=lambda h, p: _cert_not_after(h, p))


# --- cookies ------------------------------------------------------------------

def _cookie(raw: str) -> dict:
    """'name=value; Path=/; Secure' -> {'name', 'value', 'flags': {'secure': '', 'path': '/'}}."""
    first, *attrs = raw.split(';')
    name, _, value = first.partition('=')
    flags = {}
    for attr in attrs:
        key, _, val = attr.strip().partition('=')
        if key:
            flags[key.strip().lower()] = val.strip()
    return {'name': name.strip(), 'value': value.strip(), 'flags': flags}


def _is_session(cookie: dict) -> bool:
    name = cookie['name'].lower()
    return name != 'xsrf-token' and (name.endswith(('-session', '_session')) or cookie['value'].startswith(_ENCRYPTED))


def _cookie_sign(page: Page | None) -> str | None:
    if page is None:
        return None
    cookies = [_cookie(raw) for raw in page.cookies]
    if any(c['name'] == 'XSRF-TOKEN' for c in cookies):
        return 'the XSRF-TOKEN cookie'
    if any(c['value'].startswith(_ENCRYPTED) for c in cookies):
        return 'a cookie encrypted by Laravel'
    return None


# --- what the probes show ----------------------------------------------------------

def _opened(pages: dict, path: str, test) -> bool:
    """The site answered 200 with the content `test` looks for; only the
    verdict is kept, never the content."""
    page = pages.get(path)
    return webprobe.answered(page) and page.status == 200 and bool(test(page.text))


def _ignition_answer(pages: dict) -> str | None:
    """'true' / 'false' when Ignition's health check answers, 'unexpected'
    for its key with another value, None when it does not answer."""
    page = pages.get(IGNITION)
    if not (webprobe.answered(page) and page.status == 200):
        return None
    try:
        data = json.loads(page.text)
    except ValueError:
        return None
    if not isinstance(data, dict) or 'can_execute_commands' not in data:
        return None
    value = data['can_execute_commands']
    return json.dumps(value) if isinstance(value, bool) else 'unexpected'


def _inventory(pages: dict, path: str) -> dict | None:
    """{'packages', 'unreadable', 'partial'} of a public lock or
    installed.json; 'partial' when it is too large to read whole. None when
    it is not public."""
    page = pages.get(path)
    if not (webprobe.answered(page) and page.status == 200):
        return None
    if page.truncated:
        # the same fields as a read inventory (review #62 pass 4)
        return ({'packages': [], 'unreadable': 0, 'conflicting': [], 'partial': True}
                if _INVENTORY_START.match(page.text) else None)
    data = laravel_data.lock_packages(page.text)
    return None if data is None else {**data, 'partial': False}


def _composer_json(text: str) -> bool:
    try:
        data = json.loads(text)
    except ValueError:
        return False
    return isinstance(data, dict) and isinstance(data.get('require'), dict)


def _exposures(home: Page, pages: dict) -> dict:
    env_keys = {}
    for path in ENV_FILES:
        if _opened(pages, path, _ENV_KEY.search):
            env_keys[path] = sorted({m.group(1) for m in _ENV_KEY.finditer(pages[path].text)})
    return {
        'env': env_keys,
        'ignition': _ignition_answer(pages),
        'debugbar': bool(_DEBUGBAR.search(home.text)),
        'telescope': _opened(pages, TELESCOPE, _TELESCOPE.search),
        'horizon': _opened(pages, HORIZON, _HORIZON.search),
        'log': _opened(pages, LOG_FILE, _LOG_LINE.search),
        'composer_json': _opened(pages, COMPOSER_JSON, _composer_json),
        'lock': _inventory(pages, COMPOSER_LOCK),
        'installed': _inventory(pages, INSTALLED),
        'git': _opened(pages, GIT_CONFIG, _GIT_CONFIG.search),
    }


def _is_laravel(home: Page, pages: dict, seen: dict) -> tuple[bool | None, str]:
    """(True | False | None, why). None: no sign on the home page and /login
    gave no answer to judge by - "could not tell", not "no"."""
    sign = _cookie_sign(home)
    if sign:
        return True, f'{sign} on the home page'
    login = pages.get(LOGIN)
    sign = _cookie_sign(login if webprobe.answered(login) else None)
    if sign:
        return True, f'{sign} on /login'
    opened = [*seen['env']]
    opened += ['Ignition'] if seen['ignition'] in ('true', 'false') else []
    opened += [name for name, key in (('Laravel Debugbar', 'debugbar'), ('Telescope', 'telescope'),
                                      ('Horizon', 'horizon'), (LOG_FILE, 'log')) if seen[key]]
    inventories = [inventory for inventory in (seen['lock'], seen['installed']) if inventory]
    if any(p['name'] == 'laravel/framework' for inventory in inventories for p in inventory['packages']) \
            or any('laravel/framework' in inventory['conflicting'] for inventory in inventories):
        opened.append('a composer file with laravel/framework')
    if opened:
        return True, 'open: ' + ', '.join(opened)
    too_big = [path for path, inventory in ((COMPOSER_LOCK, seen['lock']), (INSTALLED, seen['installed']))
               if inventory and inventory['partial']]
    if too_big:
        # its packages were not read: no sign either way (review #62 pass 4)
        return None, (f'no Laravel cookies, tool or file seen; {", ".join(too_big)} is public but too large to '
                      f'read (over {INVENTORY_MAX_BODY // (1024 * 1024)} MB), so its packages could not be read')
    if not webprobe.answered(login):
        return None, (f'no Laravel cookies on the home page, and /login gave no answer '
                      f'({webprobe.why(login)})')
    return False, 'no Laravel cookies on the home page or /login, and no Laravel tool or file open'


# --- the parts ----------------------------------------------------------------------

def _check_session_cookie(home: Page, pages: dict, https: bool, findings: list, checked: list) -> None:
    login = pages.get(LOGIN)
    cookies = [_cookie(raw) for raw in home.cookies]
    if not any(_is_session(c) for c in cookies) and webprobe.answered(login):
        cookies = [_cookie(raw) for raw in login.cookies]
    named = (c for c in cookies if c['name'].lower().endswith(('-session', '_session')))
    session = next(named, None) or next((c for c in cookies if _is_session(c)), None)
    if session is None:
        checked.append({'item': 'session_cookie', 'status': 'not_checked',
                        'detail': 'the pages checked set no session cookie'})
        return
    name, flags = session['name'], session['flags']
    same_site = flags.get('samesite', '').lower()
    problems = []
    if https and 'secure' not in flags:
        problems.append('no Secure')
        findings.append(_finding('medium', 'the session cookie is sent without Secure',
                                 f'{name}: a browser may send it over plain http', id='LV-CKE-001',
                                 recommendation='Set SESSION_SECURE_COOKIE=true in .env.'))
    if 'httponly' not in flags:
        problems.append('no HttpOnly')
        findings.append(_finding('medium', 'the session cookie can be read by scripts',
                                 f'{name}: no HttpOnly, an injected script can steal the session',
                                 id='LV-CKE-002',
                                 recommendation="Keep 'http_only' => true in config/session.php."))
    if same_site in ('', 'none'):
        problems.append(f'SameSite={flags["samesite"]}' if same_site else 'no SameSite')
        findings.append(_finding('low', 'the session cookie has no SameSite protection',
                                 f'{name}: {"SameSite=None" if same_site else "no SameSite"}, other sites '
                                 'can make requests with it', id='LV-CKE-003',
                                 recommendation="Set 'same_site' => 'lax' in config/session.php "
                                                '(SESSION_SAME_SITE=lax).'))
    shown = ', '.join(k if not v else f'{k}={v}' for k, v in flags.items()
                      if k in ('secure', 'httponly', 'samesite'))
    if problems:
        checked.append({'item': 'session_cookie', 'status': 'problem', 'detail': f'{name}: {", ".join(problems)}'})
    else:
        checked.append({'item': 'session_cookie', 'status': 'ok', 'detail': f'{name}: {shown}'})


def _report_exposures(home: Page, pages: dict, seen: dict, findings: list, checked: list) -> None:
    unchecked = {path: webprobe.why(pages.get(path)) for path in PROBES
                 if path != LOGIN and not webprobe.answered(pages.get(path))}

    if seen['env']:
        files = ', '.join(f'{path} ({", ".join(keys)})' for path, keys in seen['env'].items())
        findings.append(_finding('critical', 'the .env file is public',
                                 f'{files}: the app key and passwords can be read by anyone (the content '
                                 'is not kept here)', id='LV-ENV-001',
                                 recommendation='Serve the site from public/ and deny .env* in the web server, '
                                                'then change APP_KEY, the database password and every other '
                                                'secret in it: anyone could have read them.'))
    if seen['ignition'] in ('true', 'false'):
        # the open route is the fact; running a solution would take a POST and is never tried (review pass 1)
        findings.append(_finding('high', "Ignition's health check is open: debug mode with runnable solutions on",
                                 f'{IGNITION} answers (can_execute_commands: {seen["ignition"]}). Ignition opens '
                                 'this route only with APP_DEBUG on and runnable solutions enabled; whether a '
                                 'solution can be run was not tried (GET requests only)', id='LV-IGN-001',
                                 recommendation='Set APP_DEBUG=false and APP_ENV=production, and keep '
                                                'IGNITION_ENABLE_RUNNABLE_SOLUTIONS off.'))
    if seen['debugbar']:
        findings.append(_finding('high', 'the Laravel debug bar is shown to visitors',
                                 'the home page carries Laravel Debugbar: queries, the session and the '
                                 'request are open to anyone', id='LV-DBG-001',
                                 recommendation='Set APP_DEBUG=false (or DEBUGBAR_ENABLED=false) and '
                                                'install barryvdh/laravel-debugbar with --dev only.'))
    for key, path, fid, name in (('telescope', TELESCOPE, 'LV-TEL-001', 'Telescope'),
                                 ('horizon', HORIZON, 'LV-HRZ-001', 'Horizon')):
        if seen[key]:
            findings.append(_finding('high', f'{name} is open to anyone', f'/{path} shows its dashboard: '
                                     'requests, queries, jobs and their data', id=fid,
                                     recommendation=f'Restrict it with the view{name} gate in '
                                                    f'{name}ServiceProvider, or turn it off in production.'))
    if seen['log']:
        findings.append(_finding('high', 'the Laravel log is public', LOG_FILE, id='LV-FILE-001',
                                 recommendation='Serve the site from public/, not the project folder: '
                                                'the log names paths, queries and errors.'))
    project = [path for path, found in ((COMPOSER_JSON, seen['composer_json']), (COMPOSER_LOCK, seen['lock']),
                                        (INSTALLED, seen['installed'])) if found is not None and found is not False]
    if project:
        findings.append(_finding('medium', 'project files are public', ', '.join(project), id='LV-FILE-002',
                                 recommendation='Serve the site from public/: these list every package and '
                                                'its version, a map for an attacker.'))
    if seen['git']:
        findings.append(_finding('high', 'the .git folder is public', GIT_CONFIG, id='LV-FILE-003',
                                 recommendation='Deny /.git in the web server and serve the site from public/: '
                                                'the source code can be downloaded.'))
    if unchecked:
        findings.append(_finding('info', f'{len(unchecked)} path(s) could not be checked',
                                 'no answer to judge by (a failed request, a server error or a rate limit), '
                                 'not confirmed closed: '
                                 + ', '.join(f'{path} ({why})' for path, why in unchecked.items()),
                                 requires_manual_verification=True))

    def item(name, paths, found, ok_detail):
        if found:
            checked.append({'item': name, 'status': 'problem', 'detail': ', '.join(found)})
        elif any(path in unchecked for path in paths):
            checked.append({'item': name, 'status': 'not_checked',
                            'detail': ', '.join(f'{path}: {unchecked[path]}' for path in paths if path in unchecked)})
        else:
            checked.append({'item': name, 'status': 'ok', 'detail': ok_detail})

    item('env', ENV_FILES, list(seen['env']), 'no .env file is public')
    if seen['ignition'] == 'unexpected':
        checked.append({'item': 'ignition', 'status': 'not_checked',
                        'detail': f'unexpected answer from {IGNITION}: can_execute_commands is neither true nor false'})
    else:
        item('ignition', [IGNITION], [IGNITION] if seen['ignition'] else [], 'closed')
    item('debugbar', [], ['on the home page'] if seen['debugbar'] else [], 'not on the home page')
    item('telescope', [TELESCOPE], [f'/{TELESCOPE}'] if seen['telescope'] else [], 'not open')
    item('horizon', [HORIZON], [f'/{HORIZON}'] if seen['horizon'] else [], 'not open')
    item('laravel_log', [LOG_FILE], [LOG_FILE] if seen['log'] else [], 'not public')
    item('project_files', [COMPOSER_JSON, COMPOSER_LOCK, INSTALLED], project, 'not public')
    item('git_config', [GIT_CONFIG], [GIT_CONFIG] if seen['git'] else [], 'not public')


def _entries(n: int) -> str:
    return f'{n} entry' if n == 1 else f'{n} entries'


def _packages(n: int) -> str:
    return f'{n} package' if n == 1 else f'{n} packages'


def _gaps(inventory: dict, path: str) -> list[str]:
    """What of one file was not compared: unreadable entries, a name with two versions."""
    gaps = []
    if inventory['unreadable']:
        gaps.append(f"{_entries(inventory['unreadable'])} of {path} could not be read (not in Composer's format)")
    if inventory['conflicting']:
        gaps.append(f'two versions of one name in {path}, not compared: {", ".join(inventory["conflicting"][:10])}'
                    + (f' and {len(inventory["conflicting"]) - 10} more' if len(inventory['conflicting']) > 10 else ''))
    return gaps


def _version_sources(seen: dict, too_big: list, source: str, checked: list) -> None:
    """When both files are public: whether they agree, said only for the
    packages both name and only when both were read in full (review pass 1-2)."""
    lock, installed = seen['lock'], seen['installed']
    if not (lock and installed):
        return
    if too_big:
        checked.append({'item': 'version_sources', 'status': 'not_checked',
                        'detail': f'{", ".join(too_big)} too large to read: only {source} is used'})
        return
    locked = {p['name']: p['version'] for p in lock['packages']}
    used = {p['name']: p['version'] for p in installed['packages']}
    common = [name for name in used if name in locked]
    differ = [f'{name} ({locked[name]} locked, {used[name]} installed)' for name in common if locked[name] != used[name]]
    partial = _gaps(lock, COMPOSER_LOCK) + _gaps(installed, INSTALLED)
    only_lock, only_installed = len(set(locked) - set(used)), len(set(used) - set(locked))
    scope = f'{_packages(len(common))} in both' + (f'; {only_lock} only in composer.lock' if only_lock else '') \
        + (f'; {only_installed} only in installed.json' if only_installed else '')
    if differ:
        more = f' and {len(differ) - 10} more' if len(differ) > 10 else ''
        detail = (f'composer.lock and installed.json disagree: {", ".join(differ[:10])}{more}; '
                  'the installed versions are used')
        checked.append({'item': 'version_sources', 'status': 'not_checked',
                        'detail': '; '.join([detail, *partial])})
    elif partial:
        checked.append({'item': 'version_sources', 'status': 'not_checked',
                        'detail': 'not compared in full: ' + '; '.join(partial)})
    elif not common:
        checked.append({'item': 'version_sources', 'status': 'not_checked',
                        'detail': f'no package in both files to compare ({scope})'})
    else:
        checked.append({'item': 'version_sources', 'status': 'ok',
                        'detail': scope.replace(' in both', ' in both agree', 1)})


def _check_versions(seen: dict, findings: list, checked: list) -> tuple[dict | None, dict | None, bool]:
    """Laravel's support and the packages' known vulnerabilities, when a
    lock or installed.json is public; installed.json first - it names what
    is installed. Returns (framework, packages, data used)."""
    public = [(path, seen['installed' if path == INSTALLED else 'lock']) for path in (INSTALLED, COMPOSER_LOCK)]
    public = [(path, inventory) for path, inventory in public if inventory]
    too_big = [path for path, inventory in public if inventory['partial']]
    readable = [(path, inventory) for path, inventory in public if not inventory['partial']]
    if not readable:
        why = (f'{", ".join(too_big)} public but too large to read (over {INVENTORY_MAX_BODY // (1024 * 1024)} MB)'
               if too_big else 'not visible from outside: composer.lock is not public (as it should be); '
                               'the version is read on the server')
        checked.append({'item': 'laravel_version', 'status': 'not_checked', 'detail': why})
        checked.append({'item': 'vulns', 'status': 'not_checked', 'detail': why})
        return None, None, False

    source, inventory = readable[0]
    packages = inventory['packages']
    _version_sources(seen, too_big, source, checked)
    locked = ' (locked in composer.lock; what is installed is not visible)' if source == COMPOSER_LOCK else ''
    gaps = _gaps(inventory, source)
    if not packages:
        # nothing to compare is not "none known" (review pass 2)
        why = '; '.join([f'no package with a readable version in {source}: nothing was compared', *gaps])
        detail = (f'two versions of laravel/framework in {source}: not judged'
                  if 'laravel/framework' in inventory['conflicting'] else why)
        checked.append({'item': 'laravel_version', 'status': 'not_checked', 'detail': detail})
        checked.append({'item': 'vulns', 'status': 'not_checked', 'detail': why})
        return None, {'source': source, 'count': 0, 'vulnerable': []}, False

    framework = None
    core = next((p for p in packages if p['name'] == 'laravel/framework'), None)
    if 'laravel/framework' in inventory['conflicting']:
        checked.append({'item': 'laravel_version', 'status': 'not_checked',
                        'detail': f'two versions of laravel/framework in {source}: not judged'})
    elif core is None:
        checked.append({'item': 'laravel_version', 'status': 'not_checked',
                        'detail': '; '.join([f'laravel/framework is not in {source}', *gaps])})
    else:
        support = laravel_data.support(core['version'])
        framework = {'version': core['version'], 'source': source, 'support': support}
        if support['status'] == 'ended':
            ended = f'ended {support["eol"]}' if support['eol'] else 'ended'
            findings.append(_finding('high', f'Laravel {core["version"]} no longer gets security fixes',
                                     f'release line {support["cycle"] or core["version"]}: security support '
                                     f'{ended} (endoflife.date){locked}', id='LV-EOL-001',
                                     recommendation='Upgrade to a supported Laravel release '
                                                    '(laravel.com/docs/releases).'))
            checked.append({'item': 'laravel_version', 'status': 'problem',
                            'detail': f'Laravel {core["version"]}{locked}: security support {ended}'})
        elif support['status'] == 'supported':
            until = f'security fixes until {support["eol"]}' if support['eol'] else 'supported'
            checked.append({'item': 'laravel_version', 'status': 'ok',
                            'detail': f'Laravel {core["version"]}{locked}: {until}'})
        else:
            checked.append({'item': 'laravel_version', 'status': 'not_checked',
                            'detail': support['error'] or f'endoflife.date does not list Laravel {core["version"]}'})

    data = laravel_data.vulnerabilities(packages)
    listed = {'source': source, 'count': len(packages), 'vulnerable': []}
    if data['status'] != 'ok':
        checked.append({'item': 'vulns', 'status': 'not_checked', 'detail': '; '.join([data['error'], *gaps])})
        return framework, listed, framework is not None
    found = 0
    for p in packages:
        vulns = data['matches'].get(p['name']) or []
        if vulns:
            listed['vulnerable'].append({'name': p['name'], 'version': p['version'], 'vulns': len(vulns)})
        for v in vulns:
            found += 1
            fixed = v.get('fixed') or []
            detail = ' · '.join([v.get('cve') or 'no CVE',
                                 f'fixed in {fixed[0]}' if fixed else 'no fixed release named for this version',
                                 *([v['error']] if v.get('error') else [])])
            # words, never a command built from the site's data (review pass 1)
            fix = (f'Update {p["name"]} to {fixed[0]} or later.' if fixed
                   else 'No fixed release is named for this version: follow the advisory.')
            findings.append(_finding(v.get('severity') or 'medium',
                                     f'{p["name"]} {p["version"]}: {v.get("title") or v["id"]}', detail,
                                     id=subject_id('LV-VULN-001', p['name'], v['id']), recommendation=fix,
                                     extra={'link': v['link']} if v.get('link') else {}))
    unanswered = data['unanswered']
    if unanswered:
        more = f' and {len(unanswered) - 20} more' if len(unanswered) > 20 else ''
        gaps.append(f'no answer from OSV.dev for: {", ".join(unanswered[:20])}{more}')
    gap = '; '.join(gaps)
    if found:
        checked.append({'item': 'vulns', 'status': 'problem',
                        'detail': f'{found} known in {len(listed["vulnerable"])} package(s){locked}, OSV.dev'})
        if gap:
            checked.append({'item': 'vuln_gaps', 'status': 'not_checked', 'detail': gap})
    elif gap:
        checked.append({'item': 'vulns', 'status': 'not_checked', 'detail': gap})
    else:
        checked.append({'item': 'vulns', 'status': 'ok',
                        'detail': f'none known for {len(packages)} package(s) in {source}, OSV.dev'})
    return framework, listed, True


@register(
    id='laravel_external', label='Laravel check (no access)', category='laravel', risk_level='PASSIVE',
    params=[{'name': 'url', 'type': 'text', 'label': 'Site URL', 'default': 'https://example.com', 'format': 'url'}],
    description='Checks a Laravel site the way any visitor sees it: a public .env, debug mode (Ignition, '
                'Debugbar), open Telescope and Horizon, a public log, project files and .git, the session '
                "cookie's flags, HTTPS and headers; the Laravel version's support and known vulnerabilities "
                'when composer.lock is public. GET requests only, no login.',
)
def check_laravel_external(url='https://example.com') -> dict:
    base = webprobe.base_url(url)
    if base is None:
        return {'url': url, 'verdict': 'unreachable', 'error': f'could not parse URL: {url}'}
    try:
        home = _fetch_twice(base)
    except httpx.HTTPError as e:
        return {'url': base, 'verdict': 'unreachable', 'error': f'could not open {base}: {e}'}
    if not 200 <= home.status < 300:
        return {'url': base, 'verdict': 'unreachable', 'error': f'{base} answered HTTP {home.status}'}
    # the scheme and host follow the site's redirect (http -> https, www); the
    # path stays as given: "/" -> "/en/" is routing inside the app, the
    # project's files are where the user pointed
    final = urlparse(home.url)
    base = f'{final.scheme}://{final.netloc}{urlparse(base).path}'

    pages = {path: _try(base + path, max_body=INVENTORY_MAX_BODY if path in INVENTORIES else None)
             for path in PROBES}
    seen = _exposures(home, pages)
    is_laravel, why = _is_laravel(home, pages, seen)
    if is_laravel is None:
        findings = [_finding('info', 'could not tell whether the site runs Laravel',
                             f'{why}; nothing was judged - try again later', requires_manual_verification=True)]
        return {'url': base, 'laravel': None, 'verdict': 'incomplete', 'findings': findings,
                'summary': webprobe.summary(findings)}
    if not is_laravel:
        findings = [_finding('info', 'no sign of Laravel', f'{why}; nothing was judged', confidence='medium')]
        return {'url': base, 'laravel': False, 'verdict': 'not_laravel', 'findings': findings,
                'summary': webprobe.summary(findings)}

    findings: list = []
    checked: list = []
    cert = _check_transport(home, base, findings, checked)
    _check_session_cookie(home, pages, base.startswith('https://'), findings, checked)
    _report_exposures(home, pages, seen, findings, checked)
    framework, packages, data_used = _check_versions(seen, findings, checked)

    verdict = webprobe.verdict(findings, checked)
    if verdict == 'ok':
        findings.append(_finding('ok', 'no issues seen from outside'))
    result = {'url': base, 'laravel': True, 'detected_by': why, 'verdict': verdict,
              'score': webprobe.score(findings, checked), 'certificate': cert, 'framework': framework,
              'packages': packages, 'checked': checked, 'findings': findings,
              'summary': webprobe.summary(findings)}
    if data_used:
        result['vuln_data'] = {'source': 'OSV.dev, endoflife.date', 'notices': laravel_data.NOTICES}
    return result
