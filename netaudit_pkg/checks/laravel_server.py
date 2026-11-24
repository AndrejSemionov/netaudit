"""
Laravel on the server, over SSH (docs/research/laravel_audit.md §5, contract
L4): every Laravel project under /var/www, /home and /srv, reading files only
- nothing is run in a project (no php, no artisan).

Two layers:
- collect(): fixed commands, each path one argument (shlex), find / head /
  grep / awk only, through sudo when it works and as the SSH user otherwise.
  What leaves the server is limited on the server: of .env only the lines of
  APP_DEBUG and APP_ENV (ENV_KEYS_PATTERN), of the cached config only
  app.env and app.debug (CONFIG_AWK) - never APP_KEY or a password.
- judge(): the verdicts from what was collected; a file that could not be
  read is "not checked", never "fine".

Facts from the Laravel 12 source: with bootstrap/cache/config.php present,
Laravel does not load .env at all (LoadEnvironmentVariables::bootstrap), so
the cached values are the ones in effect; values in .env follow Env::get
(true, (true), quotes) and PHP's bool cast for app.debug. Versions are read
as by laravel_external (installed.json first, then composer.lock; OSV.dev and
endoflife.date through laravel_data); cve_audit is not changed.
"""

from __future__ import annotations

import json
import posixpath
import re
import shlex
import uuid
from dataclasses import dataclass

from .. import laravel_data, webprobe
from ..findings import finding as _finding
from ..findings import subject_id
from ..registry import register
from ..ssh import HostKeyMismatchError, SSHExecutor
from ..ssh_utils import describe_sudo_refusal, run_sudo_with_exit_code
from . import laravel

try:
    import paramiko
except ImportError:  # pragma: no cover
    paramiko = None

ROOTS = ('/var/www', '/home', '/srv')
MAX_DEPTH = 6
MAX_PROJECTS = 20
MAX_COMPOSER_JSON = 256 * 1024
MAX_INVENTORY = laravel.INVENTORY_MAX_BODY
TIMEOUT = 60
SERVER_IDS = {'eol': 'LV-SRV-005', 'vuln': 'LV-SRV-006'}
LOCAL_ENVS = ('local', 'development')     # where Ignition and Telescope open up

# grep -E on the server: only the lines of these two keys leave it
ENV_KEYS_PATTERN = r'^[[:space:]]*(export[[:space:]]+)?(APP_DEBUG|APP_ENV)[[:space:]]*='
# awk on the server, over the var_export of `php artisan config:cache`: only
# the 'env' and 'debug' keys of the top-level 'app' block are printed
CONFIG_AWK = (
    "/^  'app' =>[ ]*$/ { inapp = 1; next }\n"
    "inapp && /^  '[^']*' =>/ { exit }\n"
    "inapp && /^    '(env|debug)' => / { print }\n"
)

_ENV_LINE = re.compile(r'^\s*(?:export\s+)?(APP_DEBUG|APP_ENV)\s*=(.*)$')
_CONFIG_LINE = re.compile(r"^    '(env|debug)' => (.*),$")
_PLAIN = re.compile(r'[A-Za-z0-9_.-]{1,40}')


class _Sentinel:
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return self.name


MISSING = _Sentinel('MISSING')        # the key is not set
AMBIGUOUS = _Sentinel('AMBIGUOUS')    # set twice with different values


# =============================================================================
# values
# =============================================================================

def _env_value(raw: str):
    """A value as Laravel's Env::get gives it: quotes removed, an inline
    comment of an unquoted value dropped, true/false/empty/null mapped."""
    value = raw.strip()
    if value[:1] in ('"', "'"):
        end = value.find(value[0], 1)
        value = value[1:end] if end > 0 else value[1:]
    else:
        value = re.split(r'\s+#', value, maxsplit=1)[0].strip()
        if value.startswith('#'):
            value = ''
    lowered = value.lower()
    if lowered in ('true', '(true)'):
        return True
    if lowered in ('false', '(false)'):
        return False
    if lowered in ('empty', '(empty)'):
        return ''
    if lowered in ('null', '(null)'):
        return None
    return value


def _put(values: dict, key: str, value) -> None:
    if values[key] is MISSING:
        values[key] = value
    elif values[key] is not AMBIGUOUS and values[key] != value:
        values[key] = AMBIGUOUS


def parse_env_lines(text: str) -> dict:
    values = {'APP_DEBUG': MISSING, 'APP_ENV': MISSING}
    for line in text.splitlines():
        m = _ENV_LINE.match(line)
        if m:
            _put(values, m.group(1), _env_value(m.group(2)))
    return values


def parse_config_lines(text: str) -> dict:
    values = {'APP_DEBUG': MISSING, 'APP_ENV': MISSING}
    for line in text.splitlines():
        m = _CONFIG_LINE.match(line)
        if not m:
            continue
        raw = m.group(2)
        if raw in ('true', 'false'):
            value = raw == 'true'
        elif raw == 'NULL':
            value = None
        elif len(raw) >= 2 and raw[0] == raw[-1] == "'":
            value = raw[1:-1].replace("\\'", "'").replace('\\\\', '\\')
        else:
            value = raw
        _put(values, 'APP_ENV' if m.group(1) == 'env' else 'APP_DEBUG', value)
    return values


def debug_on(value) -> bool:
    """config('app.debug') is (bool) env('APP_DEBUG', false): PHP's cast."""
    if isinstance(value, bool):
        return value
    if value is None or value is MISSING:
        return False
    return str(value) not in ('', '0')


def _shown(value) -> str:
    """APP_ENV as shown in the report: a plain word, or not shown."""
    return value if isinstance(value, str) and _PLAIN.fullmatch(value) else 'another value (not shown)'


# =============================================================================
# collect(): what is read on the server
# =============================================================================

@dataclass
class _Run:
    completed: bool
    rc: int | None
    out: str
    err: str


def _exec(ssh, argv: list[str], sudo: bool, timeout: int = TIMEOUT):
    """argv through sudo (run_sudo_with_exit_code) or as the SSH user; every
    element is one argument (shlex.join), never shell syntax."""
    if sudo:
        r = run_sudo_with_exit_code(ssh, argv, timeout=timeout)
        return _Run(r.completed, r.exit_code, r.stdout, r.stderr), r
    marker = f'__NETAUDIT_RC_{uuid.uuid4().hex}__'
    wrapped = f"{{ {shlex.join(argv)}; rc=$?; printf '\\n%s:%s\\n' '{marker}' \"$rc\"; }}"
    out, err = ssh.run(wrapped, timeout=timeout)
    if marker not in out:
        return _Run(False, None, out, err), None
    body, _, tail = out.rpartition(marker)
    try:
        rc = int(tail.lstrip(':').strip())
    except ValueError:
        return _Run(False, None, body, err), None
    return _Run(True, rc, body.removesuffix('\n'), err), None


def _search_argv() -> list[str]:
    return ['find', *ROOTS, '-maxdepth', str(MAX_DEPTH),
            '(', '-name', 'vendor', '-o', '-name', 'node_modules', '-o', '-name', '.git', ')', '-prune',
            '-o', '-type', 'f', '-name', 'artisan', '-printf', 'A%h\\0',
            '-o', '-type', 'l', '-name', 'current', '-printf', 'L%p\\0%l\\0']


def _errors(err: str) -> list[str]:
    """find's error lines, a missing root aside."""
    missing_roots = {f"find: '{root}': No such file or directory" for root in ROOTS}
    return [line.strip() for line in err.splitlines() if line.strip() and line.strip() not in missing_roots]


def _parse_search(run: _Run) -> dict:
    out = {'dirs': [], 'links': {}, 'partial': None, 'failed': None}
    if not run.completed:
        out['failed'] = 'the search gave no answer'
        return out
    tokens = run.out.split('\0')
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token.startswith('A/'):
            out['dirs'].append(token[1:])
        elif token.startswith('L/') and i + 1 < len(tokens):
            out['links'][token[1:]] = tokens[i + 1]
            i += 1
        i += 1
    errors = _errors(run.err)
    if run.rc not in (0, 1):
        out['failed'] = f'find exited with {run.rc}' + (f': {errors[0]}' if errors else '')
    elif errors and all('Permission denied' in e for e in errors):
        more = f' and {len(errors) - 3} more' if len(errors) > 3 else ''
        out['partial'] = '; '.join(errors[:3]) + more
    elif errors:
        out['failed'] = errors[0]
    return out


def select_projects(dirs: list[str], links: dict) -> tuple[list[str], dict]:
    """The project folders to check: of a zero-downtime deploy (releases/<n>
    next to a `current` symlink) only the release `current` points to; at
    most MAX_PROJECTS."""
    current: dict[str, set] = {}
    for link, target in links.items():
        site = posixpath.dirname(link)
        resolved = posixpath.normpath(target if target.startswith('/') else posixpath.join(site, target))
        current.setdefault(site, set()).add(resolved)
    selected, old = [], 0
    for folder in sorted(set(dirs)):
        parent = posixpath.dirname(folder)
        if posixpath.basename(parent) == 'releases':
            live = current.get(posixpath.dirname(parent))
            if live and folder not in live:
                old += 1
                continue
        selected.append(folder)
    return selected[:MAX_PROJECTS], {'old_releases': old, 'over_limit': max(0, len(selected) - MAX_PROJECTS)}


def _read_status(run: _Run) -> tuple[str, str | None]:
    if not run.completed:
        return 'error', 'no answer'
    first = next((line.strip() for line in run.err.splitlines() if line.strip()), '')
    if 'No such file or directory' in first:
        return 'missing', None
    if 'Permission denied' in first:
        return 'denied', 'Permission denied'
    return 'error', first or f'exit code {run.rc}'


def _read(ssh, path: str, limit: int, sudo: bool) -> dict:
    run, _ = _exec(ssh, ['head', '-c', str(limit + 1), path], sudo)
    if run.completed and run.rc == 0:
        return {'status': 'ok', 'text': run.out[:limit], 'truncated': len(run.out) > limit, 'reason': None}
    status, reason = _read_status(run)
    return {'status': status, 'text': '', 'truncated': False, 'reason': reason}


def _env_files(ssh, folder: str, sudo: bool) -> dict:
    run, _ = _exec(ssh, ['find', '-L', folder, '-mindepth', '1', '-maxdepth', '1', '-name', '.env*',
                         '-printf', '%f\\t%m\\t%u\\t%g\\t%y\\0'], sudo)
    files = []
    for record in run.out.split('\0'):
        fields = record.split('\t')
        if len(fields) == 5:
            try:
                mode = int(fields[1], 8)
            except ValueError:
                continue
            files.append({'name': fields[0], 'mode': mode, 'owner': fields[2], 'group': fields[3], 'type': fields[4]})
    if not run.completed or (run.rc != 0 and not files):
        status, reason = _read_status(run)
        return {'status': 'error', 'files': [], 'reason': reason or status}
    return {'status': 'ok', 'files': files, 'reason': None}


DIRS = ('storage', 'bootstrap/cache', 'bootstrap/cache/config.php')


def _dirs(ssh, folder: str, sudo: bool) -> dict:
    run, _ = _exec(ssh, ['find', *(f'{folder}/{name}' for name in DIRS), '-maxdepth', '0',
                         '-printf', '%p\\t%m\\t%y\\0'], sudo)
    if not run.completed:
        return {'status': 'error', 'reason': 'no answer', 'entries': {}, 'errors': {}}
    entries, errors = {}, {}
    for record in run.out.split('\0'):
        path, _, rest = record.partition('\t')
        mode, _, kind = rest.partition('\t')
        name = path.removeprefix(f'{folder}/')
        if name in DIRS:
            try:
                entries[name] = {'mode': int(mode, 8), 'type': kind}
            except ValueError:
                errors[name] = 'unexpected answer'
    for line in run.err.splitlines():
        for name in DIRS:
            if f"'{folder}/{name}'" in line and 'No such file or directory' not in line:
                errors[name] = 'Permission denied' if 'Permission denied' in line else line.strip()
    return {'status': 'ok', 'reason': None, 'entries': entries, 'errors': errors}


def _lines(ssh, argv: list[str], sudo: bool) -> dict:
    """grep / awk: 0 found, 1 nothing found (grep), 2 the file could not be read."""
    run, _ = _exec(ssh, argv, sudo)
    if run.completed and run.rc in (0, 1) and (run.rc == 0 or argv[0] == 'grep'):
        return {'status': 'ok', 'text': run.out, 'truncated': False, 'reason': None}
    status, reason = _read_status(run)
    return {'status': status, 'text': '', 'truncated': False, 'reason': reason}


def _requires_laravel(read: dict) -> bool:
    try:
        data = json.loads(read['text'])
    except ValueError:
        return False
    return isinstance(data, dict) and isinstance(data.get('require'), dict) and 'laravel/framework' in data['require']


def collect(ssh) -> dict:
    sudo, note = getattr(ssh, 'user', '') != 'root', None
    if sudo:
        run, result = _exec(ssh, _search_argv(), True)
        if result is not None and result.sudo_error:
            sudo, note = False, describe_sudo_refusal(ssh, result)
        elif not run.completed or (run.rc == 127 and 'sudo' in run.err):
            sudo, note = False, 'sudo did not run: ' + (run.err.strip().splitlines() or ['no answer'])[0]
        if not sudo:
            run, _ = _exec(ssh, _search_argv(), False)
    else:
        run, _ = _exec(ssh, _search_argv(), False)
    discovery = _parse_search(run)
    selected, skipped = select_projects(discovery['dirs'], discovery['links'])

    projects = {}
    for folder in selected:
        composer = _read(ssh, f'{folder}/composer.json', MAX_COMPOSER_JSON, sudo)
        project = {'composer_json': composer}
        projects[folder] = project
        if composer['status'] != 'ok' or not _requires_laravel(composer):
            continue
        project['installed'] = _read(ssh, f'{folder}/vendor/composer/installed.json', MAX_INVENTORY, sudo)
        project['lock'] = _read(ssh, f'{folder}/composer.lock', MAX_INVENTORY, sudo)
        project['env_files'] = _env_files(ssh, folder, sudo)
        project['dirs'] = _dirs(ssh, folder, sudo)
        project['env_lines'] = _lines(ssh, ['grep', '-E', ENV_KEYS_PATTERN, f'{folder}/.env'], sudo)
        cache = project['dirs']
        if 'bootstrap/cache/config.php' in cache['entries']:
            project['config_lines'] = _lines(ssh, ['awk', CONFIG_AWK, f'{folder}/bootstrap/cache/config.php'], sudo)
        else:
            project['config_lines'] = None
    return {'sudo': sudo, 'sudo_note': note, 'discovery': discovery, 'skipped': skipped, 'projects': projects}


# =============================================================================
# judge(): the verdicts
# =============================================================================

def _inventory(read: dict, name: str) -> tuple[dict | None, str | None]:
    if read['status'] == 'missing':
        return None, None
    if read['status'] != 'ok':
        return None, f'{name} could not be read: {read["reason"] or read["status"]}'
    if read['truncated']:
        return {'packages': [], 'unreadable': 0, 'conflicting': [], 'partial': True}, None
    data = laravel_data.lock_packages(read['text'])
    if data is None:
        return None, f'{name} is not a Composer file'
    return {**data, 'partial': False}, None


def _judge_env_files(path: str, env: dict, findings: list, add) -> None:
    if env['status'] != 'ok':
        add('env_files', 'not_checked', f'the .env files could not be listed: {env["reason"]}')
        return
    judged = [f for f in env['files'] if f['name'] != '.env.example' and f['type'] == 'f']
    open_ = [f for f in judged if f['mode'] & 0o004]
    for f in open_:
        findings.append(_finding('high', f'{path}/{f["name"]} can be read by every user on the server',
                                 f'mode {f["mode"]:o}, owner {f["owner"]}:{f["group"]}: the app key and the '
                                 'passwords in it are open to every account and process on the server',
                                 id=subject_id('LV-SRV-001', path, f['name']),
                                 recommendation='Make it readable by its owner and the web server only: '
                                                'mode 640, owned by the deploy user, group the web server.'))
    listed = ', '.join(f'{f["name"]} {f["mode"]:o}' for f in judged)
    if open_:
        add('env_files', 'problem', 'readable by everyone: ' + ', '.join(f'{f["name"]} {f["mode"]:o}' for f in open_))
    else:
        add('env_files', 'ok', listed or 'no .env file in the project folder')


def _values(project: dict) -> tuple[dict | None, str, str | None]:
    """(values, where they were read, why they could not be)."""
    dirs = project['dirs']
    if dirs['status'] != 'ok' or 'bootstrap/cache/config.php' in dirs.get('errors', {}):
        reason = dirs.get('reason') or dirs.get('errors', {}).get('bootstrap/cache/config.php')
        return None, '', f'could not tell whether the config is cached: {reason}'
    if 'bootstrap/cache/config.php' in dirs['entries']:
        lines = project['config_lines']
        source = 'cached config (bootstrap/cache/config.php; .env is not read)'
        if lines is None or lines['status'] != 'ok':
            return None, source, f'the cached config could not be read: {(lines or {}).get("reason") or "no answer"}'
        return parse_config_lines(lines['text']), source, None
    lines = project['env_lines']
    if lines['status'] == 'missing':
        return None, '.env', ('no .env file and no cached config: the values may come from the server\'s '
                              'environment, not visible here')
    if lines['status'] != 'ok':
        return None, '.env', f'.env could not be read: {lines["reason"] or lines["status"]}'
    return parse_env_lines(lines['text']), '.env', None


def _judge_values(path: str, project: dict, findings: list, add) -> dict:
    values, source, why = _values(project)
    if values is None:
        add('app_debug', 'not_checked', why)
        add('app_env', 'not_checked', why)
        return {'debug': None, 'env': None, 'source': None}
    cached = source != '.env'
    caveat = '' if cached else ' (a value set for the PHP process would win over .env)'
    debug, env = values['APP_DEBUG'], values['APP_ENV']
    app = {'debug': None, 'env': None, 'source': 'cached config' if cached else '.env'}

    if debug is AMBIGUOUS:
        add('app_debug', 'not_checked', f'APP_DEBUG is set twice with different values in {source}')
    elif debug is MISSING and cached:
        add('app_debug', 'not_checked', 'the cached config has no app.debug')
    elif debug is MISSING:
        app['debug'] = False
        add('app_debug', 'ok', 'not set in .env: off by default')
    elif debug_on(debug):
        app['debug'] = True
        findings.append(_finding('high', f'{path}: debug mode is on (APP_DEBUG)',
                                 f'on in the {source}: an error page shows code, queries and settings to '
                                 f'anyone{caveat}', id=subject_id('LV-SRV-002', path),
                                 recommendation='Set APP_DEBUG=false; if the config is cached, cache it again '
                                                '(php artisan config:cache).'))
        add('app_debug', 'problem', f'on ({source})')
    else:
        app['debug'] = False
        add('app_debug', 'ok', f'off ({source})')

    if env is AMBIGUOUS:
        add('app_env', 'not_checked', f'APP_ENV is set twice with different values in {source}')
    elif env is MISSING and cached:
        add('app_env', 'not_checked', 'the cached config has no app.env')
    else:
        name = 'production' if env in (MISSING, None) else env
        shown = _shown(name)
        app['env'] = shown
        if isinstance(name, str) and name.lower() in LOCAL_ENVS:
            findings.append(_finding('medium', f'{path}: APP_ENV is {shown}',
                                     f'in the {source}: Ignition, Telescope and Horizon open up in this '
                                     f'environment{caveat}', id=subject_id('LV-SRV-003', path),
                                     recommendation='Set APP_ENV=production on a live server.'))
            add('app_env', 'problem', f'{shown} ({source})')
        else:
            add('app_env', 'ok', f'{shown} ({source})' + (' - not set, the default' if env is MISSING else ''))
    return app


def _judge_dirs(path: str, dirs: dict, findings: list, add) -> None:
    if dirs['status'] != 'ok':
        add('writable_dirs', 'not_checked', f'could not be read: {dirs["reason"]}')
        return
    open_, gaps, fine = [], [], []
    for name in ('storage', 'bootstrap/cache'):
        entry = dirs['entries'].get(name)
        if entry is None:
            gaps.append(f'{name}: {dirs.get("errors", {}).get(name) or "not found"}')
        elif entry['mode'] & 0o002:
            open_.append(name)
            findings.append(_finding('medium', f'{path}/{name} can be written by every user on the server',
                                     f'mode {entry["mode"]:o}: any account can put files there that the app '
                                     'then loads or serves', id=subject_id('LV-SRV-004', path, name),
                                     recommendation='Remove write access for others (chmod o-w) and give it to '
                                                    "the web server's group instead (775)."))
        else:
            fine.append(f'{name} {entry["mode"]:o}')
    if open_:
        add('writable_dirs', 'problem', 'writable by everyone: ' + ', '.join(open_))
    elif gaps:
        add('writable_dirs', 'not_checked', '; '.join(gaps))
    else:
        add('writable_dirs', 'ok', ', '.join(fine))


def _judge_versions(path: str, project: dict, findings: list, checked: list) -> tuple[dict | None, dict | None, bool]:
    installed, installed_why = _inventory(project['installed'], 'vendor/composer/installed.json')
    lock, lock_why = _inventory(project['lock'], 'composer.lock')
    reasons = [r for r in (installed_why, lock_why) if r]
    why = '; '.join(reasons) or 'neither vendor/composer/installed.json nor composer.lock is in the project'
    extra = {'project': path}
    framework, packages, used = laravel._check_versions(
        {'installed': installed, 'lock': lock}, findings, checked, ids=SERVER_IDS, subject=(path,),
        prefix=f'{path}: ', extra=extra, missing_why=why)
    if (installed or lock) and reasons:
        # one file was used, the other could not be read: said, not hidden (as in review #62 pass 1)
        checked.append({**extra, 'item': 'version_sources', 'status': 'not_checked', 'detail': '; '.join(reasons)})
    return framework, packages, used


def judge(raw: dict, host: str) -> dict:
    findings: list = []
    checked: list = []
    discovery, skipped = raw['discovery'], dict(raw['skipped'])
    projects, gaps = [], []
    skipped['not_laravel'] = 0
    for path, project in raw['projects'].items():
        composer = project['composer_json']
        if composer['status'] != 'ok':
            gaps.append(f'{path}/composer.json could not be read: {composer["reason"] or composer["status"]}')
        elif not _requires_laravel(composer):
            skipped['not_laravel'] += 1
        else:
            projects.append((path, project))
    if discovery['failed']:
        gaps.insert(0, f'the search failed: {discovery["failed"]}')
    if discovery['partial']:
        gaps.insert(0, f'the search was partial: {discovery["partial"]}')
    if skipped['over_limit']:
        gaps.append(f'{skipped["over_limit"]} more project folder(s) past the limit of {MAX_PROJECTS} not checked')

    found = f'{len(projects)} Laravel project(s) under {", ".join(ROOTS)} (depth {MAX_DEPTH})'
    notes = [found]
    if skipped['old_releases']:
        notes.append(f'{skipped["old_releases"]} earlier release(s) of zero-downtime deploys not judged')
    if skipped['not_laravel']:
        notes.append(f'{skipped["not_laravel"]} folder(s) with artisan but without laravel/framework')
    checked.append({'item': 'discovery', 'status': 'not_checked' if gaps else 'ok', 'detail': '; '.join(notes + gaps)})

    base = {'host': host, 'skipped': skipped}
    if not raw['sudo'] and raw['sudo_note']:
        base.update(collected_without_sudo=True, sudo_note=raw['sudo_note'])
    if not projects:
        if gaps:
            findings.append(_finding('info', 'could not tell whether the server has a Laravel project',
                                     '; '.join(gaps), requires_manual_verification=True))
            return {**base, 'verdict': 'incomplete', 'projects': [], 'checked': checked, 'findings': findings,
                    'summary': webprobe.summary(findings)}
        findings.append(_finding('info', 'no Laravel project found', f'{found}; nothing was judged',
                                 confidence='medium'))
        return {**base, 'verdict': 'not_laravel', 'projects': [], 'checked': checked, 'findings': findings,
                'summary': webprobe.summary(findings)}

    out, data_used = [], False
    for path, project in projects:
        def add(item, status, detail, path=path):
            checked.append({'project': path, 'item': item, 'status': status, 'detail': detail})

        _judge_env_files(path, project['env_files'], findings, add)
        app = _judge_values(path, project, findings, add)
        _judge_dirs(path, project['dirs'], findings, add)
        framework, packages, used = _judge_versions(path, project, findings, checked)
        data_used = data_used or used
        out.append({'path': path, 'framework': framework, 'packages': packages, 'app': app})

    verdict = webprobe.verdict(findings, checked)
    if verdict == 'ok':
        findings.append(_finding('ok', 'no issues found in the Laravel projects'))
    result = {**base, 'verdict': verdict, 'score': webprobe.score(findings, checked), 'projects': out,
              'checked': checked, 'findings': findings, 'summary': webprobe.summary(findings)}
    if data_used:
        result['vuln_data'] = {'source': 'OSV.dev, endoflife.date', 'notices': laravel_data.NOTICES}
    return result


def audit_laravel_server(ssh, host: str) -> dict:
    return judge(collect(ssh), host)


@register(
    id='laravel_server', label='Laravel on the server (SSH)', category='laravel',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Host', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'User', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH port', 'default': 22, 'min': 1, 'max': 65535},
        {'name': 'key_path', 'type': 'text', 'label': 'Key path', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'SSH password (if no key)', 'default': ''},
        {'name': 'sudo_password', 'type': 'password', 'label': 'Sudo password (if sudo asks for one)', 'default': ''},
    ],
    required_tools=[],
    description='Finds every Laravel project on the server (/var/www, /home, /srv) and checks it by reading '
                'files only: who can read .env, APP_DEBUG and APP_ENV (from the cached config when there is '
                'one), storage and bootstrap/cache writable by all, whether the Laravel release still gets '
                'security fixes and the known vulnerabilities of its packages. Never reads APP_KEY or passwords, '
                'runs nothing in the project.',
)
def check_laravel_server(host='', user='root', port=22, key_path='', password='', sudo_password='') -> dict:  # nosec B107 - empty default is a CLI/API parameter, not a hardcoded credential
    if paramiko is None:
        return {'error': 'paramiko not installed'}
    if not host:
        return {'error': 'host not specified'}
    try:
        ssh = SSHExecutor(host, user, port, key_path, password, sudo_password=sudo_password).connect()
    except HostKeyMismatchError as e:
        return {'error': str(e)}
    # SSH libraries can fail with transport, auth, or socket errors; keep the check isolated.
    except Exception as e:  # noqa: BLE001
        return {'error': f'could not connect: {e}'}
    try:
        return audit_laravel_server(ssh, host)
    finally:
        ssh.close()
