"""
Laravel on the server, over SSH (docs/research/laravel_audit.md §5, contract
L4, review #63 pass 1): every Laravel project under /var/www, /home and
/srv, reading files only - nothing is run in a project (no php, no artisan).

Two layers:
- collect(): fixed commands, each path one argument (shlex), find / head /
  awk only. Names, modes and owners (find) are listed through sudo when it
  works. File *contents* are read with no more rights than the project's
  owner: as the owner (plain, `sudo -u`, or `runuser` when connected as
  root), or as the SSH user when the owner is root and sudo is not there -
  and only along a path that the reader or root alone can change: a folder
  another account may change, or a link read as root, is not followed. Of
  .env and the cached config only normalized tokens leave the server
  (ENV_AWK, CONFIG_AWK: `APP_DEBUG true`, `APP_ENV word:production`) -
  never a line, APP_KEY or a password.
- judge(): the verdicts from what was collected; a file that could not or
  may not be read is "not checked", never "fine".

Facts from the Laravel 12 source: with bootstrap/cache/config.php present,
Laravel does not load .env at all (LoadEnvironmentVariables::bootstrap), so
the cached values are the ones in effect; values in .env follow Env::get
(true, (true), quotes) and PHP's bool cast for app.debug, and a value set
for the PHP process would win over .env - so .env alone does not confirm
the configuration in effect. Versions are read as by laravel_external
(installed.json first, then composer.lock; OSV.dev and endoflife.date
through laravel_data); cve_audit is not changed.
"""

from __future__ import annotations

import json
import posixpath
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
MAX_CANDIDATES = 60        # folders with artisan examined
MAX_PROJECTS = 20          # Laravel projects read in full
MAX_COMPOSER_JSON = 256 * 1024
MAX_INVENTORY = laravel.INVENTORY_MAX_BODY
TIMEOUT = 60
SERVER_IDS = {'eol': 'LV-SRV-005', 'vuln': 'LV-SRV-006'}
LOCAL_ENVS = ('local', 'development')     # where Ignition and Telescope open up
INNER_DIRS = ('vendor', 'vendor/composer', 'bootstrap', 'bootstrap/cache')
FILES = ('composer.json', 'vendor/composer/installed.json', 'composer.lock', '.env', 'bootstrap/cache/config.php')
DIRS = ('storage', 'bootstrap/cache')
PROCESS_CAVEAT = 'a value set for the PHP process (php-fpm pool, systemd unit, container) would win over .env'

# awk on the server over .env: for each APP_DEBUG / APP_ENV line, a token of
# its value as Laravel's Env::get reads it - never the line itself
ENV_AWK = r"""{
  line = $0
  sub(/^[ \t]+/, "", line)
  sub(/^export[ \t]+/, "", line)
  if (line ~ /^APP_DEBUG[ \t]*=/) key = "APP_DEBUG"
  else if (line ~ /^APP_ENV[ \t]*=/) key = "APP_ENV"
  else next
  v = substr(line, index(line, "=") + 1)
  sub(/^[ \t]+/, "", v)
  q = substr(v, 1, 1)
  if (q == "\"" || q == "'") {
    v = substr(v, 2)
    e = index(v, q)
    if (e > 0) v = substr(v, 1, e - 1)
  } else {
    sub(/[ \t]+#.*$/, "", v)
    if (substr(v, 1, 1) == "#") v = ""
    sub(/[ \t]+$/, "", v)
  }
  l = tolower(v)
  if (l == "true" || l == "(true)") t = "true"
  else if (l == "false" || l == "(false)") t = "false"
  else if (l == "empty" || l == "(empty)" || v == "") t = "empty"
  else if (l == "null" || l == "(null)") t = "null"
  else if (key == "APP_DEBUG") t = (v == "0") ? "zero" : "set"
  else if (length(v) <= 40 && v ~ /^[A-Za-z0-9_.-]+$/) t = "word:" v
  else t = "other"
  print key " " t
}
"""
# awk on the server over the var_export of `php artisan config:cache`: tokens
# of the 'env' and 'debug' keys of the top-level 'app' block only
CONFIG_AWK = r"""/^  'app' =>[ ]*$/ { inapp = 1; next }
inapp && /^  '[^']*' =>/ { exit }
inapp && /^    'debug' => / {
  v = $0
  sub(/^    'debug' => /, "", v)
  sub(/,$/, "", v)
  print "APP_DEBUG " (v == "true" ? "true" : v == "false" ? "false" : v == "NULL" ? "null" : "other")
}
inapp && /^    'env' => / {
  v = $0
  sub(/^    'env' => /, "", v)
  sub(/,$/, "", v)
  if (v == "NULL") print "APP_ENV null"
  else if (length(v) <= 42 && v ~ /^'[A-Za-z0-9_.-]+'$/) print "APP_ENV word:" substr(v, 2, length(v) - 2)
  else print "APP_ENV other"
}
"""


class _Sentinel:
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return self.name


MISSING = _Sentinel('MISSING')        # the key is not set
AMBIGUOUS = _Sentinel('AMBIGUOUS')    # set twice with different values
OTHER = _Sentinel('OTHER')            # APP_ENV that is not a plain word: not shown
_SET = 'set'                          # APP_DEBUG with another non-empty value: true for PHP

_TOKENS = {'true': True, 'false': False, 'empty': '', 'null': None, 'zero': '0', 'set': _SET, 'other': OTHER}


# =============================================================================
# values
# =============================================================================

def parse_tokens(text: str) -> dict:
    """{'APP_DEBUG': value, 'APP_ENV': value} from the server's tokens; a
    key given twice with two values is AMBIGUOUS, a line not in the token
    format is ignored."""
    values = {'APP_DEBUG': MISSING, 'APP_ENV': MISSING}
    for line in text.splitlines():
        key, _, token = line.strip().partition(' ')
        if key not in values:
            continue
        if token.startswith('word:') and key == 'APP_ENV':
            value = token[5:]
        elif token in _TOKENS:
            value = _TOKENS[token]
        else:
            continue
        if values[key] is MISSING:
            values[key] = value
        elif values[key] is not AMBIGUOUS and values[key] != value:
            values[key] = AMBIGUOUS
    return values


def debug_on(value) -> bool:
    """config('app.debug') is (bool) env('APP_DEBUG', false): PHP's cast."""
    if isinstance(value, bool):
        return value
    if value is None or value is MISSING:
        return False
    return value not in ('', '0')


def _shown(value) -> str:
    return value if isinstance(value, str) and value not in ('', _SET) else 'another value (not shown)'


# =============================================================================
# collect(): what is read on the server
# =============================================================================

@dataclass
class _Run:
    completed: bool
    rc: int | None
    out: str
    err: str


def _wrap(ssh, command: str, timeout: int, stdin_data: str | None = None) -> _Run:
    marker = f'__NETAUDIT_RC_{uuid.uuid4().hex}__'
    wrapped = f"{{ {command}; rc=$?; printf '\\n%s:%s\\n' '{marker}' \"$rc\"; }}"
    if stdin_data is None:
        out, err = ssh.run(wrapped, timeout=timeout)
    else:
        out, err = ssh.run(wrapped, timeout=timeout, stdin_data=stdin_data)
    if marker not in out:
        return _Run(False, None, out, err)
    body, _, tail = out.rpartition(marker)
    try:
        rc = int(tail.lstrip(':').strip())
    except ValueError:
        return _Run(False, None, body, err)
    return _Run(True, rc, body.removesuffix('\n'), err)


def _exec(ssh, argv: list[str], sudo: bool, timeout: int = TIMEOUT):
    """argv as root through sudo (run_sudo_with_exit_code) or as the SSH
    user; every element is one argument (shlex.join), never shell syntax."""
    if sudo:
        r = run_sudo_with_exit_code(ssh, argv, timeout=timeout)
        return _Run(r.completed, r.exit_code, r.stdout, r.stderr), r
    return _wrap(ssh, shlex.join(argv), timeout), None


@dataclass
class _Reader:
    """How a project's contents are read: as `user`, by `via`
    ('plain' | 'sudo' (as root) | 'sudo-u' | 'runuser'), or not at all."""
    user: str
    via: str | None
    reason: str | None = None


def _reader(me: str, owner: str, sudo: bool) -> _Reader:
    if owner == me:
        return _Reader(me, 'plain')
    if me == 'root':
        return _Reader(owner, 'runuser')
    if owner == 'root':
        # as the SSH user, who has fewer rights than root, when sudo is not there
        return _Reader('root', 'sudo') if sudo else _Reader(me, 'plain')
    if sudo:
        return _Reader(owner, 'sudo-u')
    return _Reader(owner, None, f'contents are read as the project\'s owner ({owner}), and the SSH user '
                                f'cannot act as {owner}')


def _as(ssh, argv: list[str], reader: _Reader) -> _Run:
    if reader.via == 'plain':
        return _wrap(ssh, shlex.join(argv), TIMEOUT)
    if reader.via == 'sudo':
        return _exec(ssh, argv, True)[0]
    if reader.via == 'runuser':
        return _wrap(ssh, shlex.join(['runuser', '-u', reader.user, '--', *argv]), TIMEOUT)
    secret = getattr(ssh, 'sudo_password', None) or getattr(ssh, 'password', '')
    user = f'#{reader.user}' if reader.user.isdigit() else reader.user
    if secret:
        return _wrap(ssh, f"sudo -S -p '' -u {shlex.quote(user)} -- {shlex.join(argv)}", TIMEOUT, secret + '\n')
    return _wrap(ssh, f'sudo -n -u {shlex.quote(user)} -- {shlex.join(argv)}', TIMEOUT)


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
    """The folders to examine: of a zero-downtime deploy (releases/<n> next
    to a `current` symlink) only the release `current` points to; at most
    MAX_CANDIDATES."""
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
    return selected[:MAX_CANDIDATES], {'old_releases': old,
                                       'candidates_over': max(0, len(selected) - MAX_CANDIDATES)}


def _first_error(run: _Run) -> str:
    return next((line.strip() for line in run.err.splitlines() if line.strip()), '') or (
        f'exit code {run.rc}' if run.completed else 'no answer')


def _status(run: _Run) -> tuple[str, str | None]:
    first = _first_error(run)
    if 'No such file or directory' in first:
        return 'missing', None
    if 'Permission denied' in first:
        return 'denied', 'Permission denied'
    return 'error', first


def _meta(ssh, paths: list[str], follow: bool, sudo: bool) -> dict:
    """{'entries': path -> {'owner', 'group', 'mode', 'type'}, 'missing': paths
    find said do not exist, 'errors': path -> reason for every other path
    not listed}. A listing that failed as a whole leaves its reason on every
    path it did not list - never "missing" (review #63 pass 2)."""
    run, _ = _exec(ssh, ['find', '-L' if follow else '-P', *paths, '-maxdepth', '0',
                         '-printf', '%p\\t%u\\t%g\\t%m\\t%y\\0'], sudo)
    entries, errors, missing = {}, {}, set()
    for record in run.out.split('\0'):
        fields = record.split('\t')
        if len(fields) == 5 and fields[0] in paths:
            try:
                entries[fields[0]] = {'owner': fields[1], 'group': fields[2], 'mode': int(fields[3], 8),
                                      'type': fields[4]}
            except ValueError:
                errors[fields[0]] = 'unexpected answer'
    for line in run.err.splitlines():
        for path in paths:
            prefix = f"find: '{path}': "
            if line.startswith(prefix):
                reason = line[len(prefix):].strip()
                if reason == 'No such file or directory':
                    missing.add(path)
                else:
                    errors[path] = reason
    failed = not run.completed or run.rc not in (0, 1)
    whole = f'the listing failed: {_first_error(run)}' if failed else 'not listed'
    for path in paths:
        if path not in entries and path not in missing:
            errors.setdefault(path, whole)
    if failed:
        missing = set()
    return {'entries': entries, 'errors': errors, 'missing': missing}


def _ancestors(path: str) -> list[str]:
    out, current = [], path
    while True:
        out.append(current)
        if current == '/':
            return out[::-1]
        current = posixpath.dirname(current)


def _untrusted(chain: dict, folder_path: str, reader: str, members: dict) -> str | None:
    """Why a file in folder_path may not be read as `reader`: a folder on the
    way that another account may change, or that is a link. None when only
    the reader and root can change the way to it. A folder its group may
    change is trusted only when the group's members, listed on the server
    (`members`), are the reader and root - a group's name proves nothing
    (review #63 pass 2)."""
    for d in _ancestors(folder_path):
        m = chain['entries'].get(d)
        if m is None:
            return f'{d} could not be checked ({chain["errors"].get(d, "not listed")})'
        if m['type'] == 'l':
            return f'{d} is a symbolic link'
        if m['type'] != 'd':
            return f'{d} is not a folder'
        if m['owner'] not in (reader, 'root'):
            return f'{d} belongs to {m["owner"]}'
        if m['mode'] & 0o020:
            group = members.get(m['group'])
            if group is None:
                return f'{d} can be changed by the group {m["group"]}, whose members could not be listed'
            others = sorted(group - {reader, 'root'})
            if others:
                return f'{d} can be changed by the group {m["group"]} (members: {", ".join(others)})'
        if m['mode'] & 0o002 and not m['mode'] & 0o1000:
            return f'{d} can be changed by everyone'
    return None


def _skipped(reason: str) -> dict:
    return {'status': 'skipped', 'text': '', 'truncated': False, 'reason': reason}


def _content(ssh, folder: str, rel: str, reader: _Reader, chain: dict, files: dict, members: dict, argv_for):
    """One file of the project, read as `reader` only when it is a regular
    file on a path that only the reader or root can change; read as root,
    the file itself must be confirmed a regular file, not a link (review #63
    pass 2). Returns a Read dict when it is not read, else the run."""
    path = f'{folder}/{rel}'
    if reader.via is None:
        return _skipped(reader.reason)
    target = files['entries'].get(path)
    if target is None:
        if path in files['missing']:
            return {'status': 'missing', 'text': '', 'truncated': False, 'reason': None}
        return _skipped(f'{rel} could not be checked: {files["errors"].get(path, "not listed")}')
    if target['type'] != 'f':
        return _skipped(f'{rel} is not a regular file')
    why = _untrusted(chain, posixpath.dirname(path), reader.user, members)
    if why:
        return _skipped(f'{why}: {rel} is not read as {reader.user}')
    if reader.user == 'root':
        own = chain['entries'].get(path)
        if own is None:
            return _skipped(f'{rel} could not be confirmed as a regular file '
                            f'({chain["errors"].get(path, "not listed")}): not read as root')
        if own['type'] != 'f':
            return _skipped(f'{rel} is a symbolic link or not a regular file: not read as root')
    return _as(ssh, argv_for(path), reader)


def _read(ssh, folder, rel, limit, reader, chain, files, members) -> dict:
    result = _content(ssh, folder, rel, reader, chain, files, members,
                      lambda path: ['head', '-c', str(limit + 1), path])
    if isinstance(result, dict):
        return result
    if result.completed and result.rc == 0:
        return {'status': 'ok', 'text': result.out[:limit], 'truncated': len(result.out) > limit, 'reason': None}
    status, reason = _status(result)
    return {'status': status, 'text': '', 'truncated': False, 'reason': reason}


def _tokens(ssh, folder, rel, program, reader, chain, files, members) -> dict:
    result = _content(ssh, folder, rel, reader, chain, files, members, lambda path: ['awk', program, path])
    if isinstance(result, dict):
        return result
    if result.completed and result.rc == 0:
        return {'status': 'ok', 'text': result.out, 'truncated': False, 'reason': None}
    status, reason = _status(result)
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
    if run.completed and run.rc == 0:
        return {'status': 'ok', 'files': files, 'reason': None}
    # a listing with an error is not the whole list (review #63 pass 1)
    return {'status': 'partial' if files else 'error', 'files': files, 'reason': _first_error(run)}


def _group_members(ssh, groups: set, cache: dict) -> dict:
    """group -> its members (supplementary, and every user whose primary
    group it is), or None when they could not be listed. getent runs as the
    SSH user; it reads names only."""
    if 'passwd' not in cache:
        run = _wrap(ssh, 'getent passwd', TIMEOUT)
        users = None
        if run.completed and run.rc == 0:
            users = [(f[0], f[3]) for f in (line.split(':') for line in run.out.splitlines()) if len(f) >= 4]
        cache['passwd'] = users
    for group in groups - set(cache.get('groups', {})):
        run = _wrap(ssh, shlex.join(['getent', 'group', group]), TIMEOUT)
        fields = run.out.strip().split(':') if run.completed and run.rc == 0 else []
        if len(fields) != 4 or cache['passwd'] is None:
            members = None
        else:
            members = {m for m in fields[3].split(',') if m} | {u for u, gid in cache['passwd'] if gid == fields[2]}
        cache.setdefault('groups', {})[group] = members
    return cache.get('groups', {})


def manifest(read: dict) -> tuple[str, str | None]:
    """('laravel' | 'not_laravel' | 'gap', why): a composer.json that could
    not be read whole, or is not a manifest, is a gap - never 'not_laravel'."""
    if read['status'] != 'ok':
        return 'gap', f'composer.json could not be read: {read["reason"] or read["status"]}'
    if read['truncated']:
        return 'gap', 'composer.json is too large to read'
    try:
        data = json.loads(read['text'])
    except ValueError:
        return 'gap', 'composer.json is not valid JSON'
    if not isinstance(data, dict):
        return 'gap', 'composer.json is not a JSON object'
    require = data.get('require', {})
    if not isinstance(require, dict):
        return 'gap', 'the require of composer.json is not an object'
    return ('laravel', None) if 'laravel/framework' in require else ('not_laravel', None)


def collect(ssh) -> dict:
    me = getattr(ssh, 'user', '')
    sudo, note = me != 'root', None
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
    candidates, skipped = select_projects(discovery['dirs'], discovery['links'])
    skipped['over_limit'] = 0

    projects, laravel_projects, group_cache = {}, 0, {}
    for folder in candidates:
        paths = sorted({*_ancestors(folder), *(f'{folder}/{d}' for d in INNER_DIRS),
                        *(f'{folder}/{f}' for f in FILES)})
        chain = _meta(ssh, paths, False, sudo)
        files = _meta(ssh, [f'{folder}/{f}' for f in (*FILES, *DIRS)], True, sudo)
        owner = chain['entries'].get(folder, {}).get('owner')
        reader = _reader(me, owner, sudo) if owner else _Reader(
            '', None, f'the project folder could not be checked: {chain["errors"].get(folder, "not listed")}')
        writable = {m['group'] for m in chain['entries'].values() if m['type'] == 'd' and m['mode'] & 0o020}
        members = _group_members(ssh, writable, group_cache) if writable else {}
        composer = _read(ssh, folder, 'composer.json', MAX_COMPOSER_JSON, reader, chain, files, members)
        project = {'owner': owner, 'reader': {'user': reader.user, 'via': reader.via}, 'composer_json': composer}
        kind, _ = manifest(composer)
        if kind == 'laravel':
            laravel_projects += 1
            if laravel_projects > MAX_PROJECTS:
                skipped['over_limit'] += 1
                continue
        projects[folder] = project
        if kind != 'laravel':
            continue
        project['installed'] = _read(ssh, folder, 'vendor/composer/installed.json', MAX_INVENTORY, reader, chain,
                                     files, members)
        project['lock'] = _read(ssh, folder, 'composer.lock', MAX_INVENTORY, reader, chain, files, members)
        project['env_files'] = _env_files(ssh, folder, sudo)
        entries = {rel: {'mode': files['entries'][f'{folder}/{rel}']['mode'],
                         'type': files['entries'][f'{folder}/{rel}']['type']}
                   for rel in (*DIRS, 'bootstrap/cache/config.php') if f'{folder}/{rel}' in files['entries']}
        errors = {rel: files['errors'][f'{folder}/{rel}']
                  for rel in (*DIRS, 'bootstrap/cache/config.php') if f'{folder}/{rel}' in files['errors']}
        project['dirs'] = {'status': 'ok', 'reason': None, 'entries': entries, 'errors': errors}
        project['env_tokens'] = _tokens(ssh, folder, '.env', ENV_AWK, reader, chain, files, members)
        project['config_tokens'] = (_tokens(ssh, folder, 'bootstrap/cache/config.php', CONFIG_AWK, reader, chain,
                                            files, members) if 'bootstrap/cache/config.php' in entries else None)
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
    if env['status'] == 'error':
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
    partial = env['status'] == 'partial'
    if open_:
        add('env_files', 'problem', 'readable by everyone: ' + ', '.join(f'{f["name"]} {f["mode"]:o}' for f in open_))
        if partial:
            add('read_gaps', 'not_checked', f'not every .env file could be listed: {env["reason"]}')
    elif partial:
        add('env_files', 'not_checked', f'{listed or "none"} seen, but not every .env file could be listed: '
                                        f'{env["reason"]}')
    else:
        add('env_files', 'ok', listed or 'no .env file in the project folder')


def _values(project: dict) -> tuple[dict | None, str, str | None]:
    """(values, where they were read, why they could not be)."""
    dirs = project['dirs']
    errors = dirs.get('errors', {})
    if dirs['status'] != 'ok' or 'bootstrap/cache/config.php' in errors:
        reason = dirs.get('reason') or errors.get('bootstrap/cache/config.php')
        return None, '', f'could not tell whether the config is cached: {reason}'
    config = dirs['entries'].get('bootstrap/cache/config.php')
    if config is not None:
        source = 'cached config (bootstrap/cache/config.php; .env is not read)'
        tokens = project['config_tokens']
        if config['type'] != 'f':
            return None, source, 'bootstrap/cache/config.php is not a regular file'
        if tokens is None or tokens['status'] != 'ok':
            return None, source, f'the cached config could not be read: {(tokens or {}).get("reason") or "no answer"}'
        return parse_tokens(tokens['text']), source, None
    tokens = project['env_tokens']
    if tokens['status'] == 'missing':
        return None, '.env', ('no .env file and no cached config: the values may come from the server\'s '
                              'environment, not visible here')
    if tokens['status'] != 'ok':
        return None, '.env', f'.env could not be read: {tokens["reason"] or tokens["status"]}'
    return parse_tokens(tokens['text']), '.env', None


def _judge_values(path: str, project: dict, findings: list, add) -> dict:
    values, source, why = _values(project)
    if values is None:
        add('app_debug', 'not_checked', why)
        add('app_env', 'not_checked', why)
        return {'debug': None, 'env': None, 'source': None}
    cached = source != '.env'
    where = source if cached else f'.env; {PROCESS_CAVEAT}'
    debug, env = values['APP_DEBUG'], values['APP_ENV']
    app = {'debug': None, 'env': None, 'source': 'cached config' if cached else '.env'}

    if debug is AMBIGUOUS:
        add('app_debug', 'not_checked', f'APP_DEBUG is set twice with different values in {source}')
    elif debug is MISSING and cached:
        add('app_debug', 'not_checked', 'the cached config has no app.debug')
    elif debug is MISSING:
        app['debug'] = False
        add('app_debug', 'ok', f'not set in .env: off by default ({PROCESS_CAVEAT})')
    elif debug_on(debug):
        app['debug'] = True
        findings.append(_finding('high', f'{path}: debug mode is on (APP_DEBUG)',
                                 f'on in the {where}: an error page shows code, queries and settings to anyone',
                                 id=subject_id('LV-SRV-002', path),
                                 recommendation='Set APP_DEBUG=false; if the config is cached, cache it again '
                                                '(php artisan config:cache).'))
        add('app_debug', 'problem', f'on ({where})')
    else:
        app['debug'] = False
        add('app_debug', 'ok', f'off ({where})')

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
                                     f'in the {where}: Ignition, Telescope and Horizon open up in this environment',
                                     id=subject_id('LV-SRV-003', path),
                                     recommendation='Set APP_ENV=production on a live server.'))
            add('app_env', 'problem', f'{shown} ({where})')
        else:
            unset = ' - not set, the default' if env is MISSING else ''
            add('app_env', 'ok', f'{shown}{unset} ({where})')

    # only a cached config is the configuration in effect (review #63 pass 1)
    if cached:
        add('effective_config', 'ok', 'the cached config is what Laravel uses: it does not read .env then')
    else:
        add('effective_config', 'not_checked', f'values read from .env; {PROCESS_CAVEAT}, and so would a '
                                               '.env.<APP_ENV> the environment chooses: the configuration in '
                                               'effect is not confirmed')
    return app


def _judge_dirs(path: str, dirs: dict, findings: list, add) -> None:
    if dirs['status'] != 'ok':
        add('writable_dirs', 'not_checked', f'could not be read: {dirs["reason"]}')
        return
    open_, gaps, fine = [], [], []
    for name in DIRS:
        entry = dirs['entries'].get(name)
        if entry is None:
            gaps.append(f'{name}: {dirs.get("errors", {}).get(name) or "not found"}')
        elif entry['type'] != 'd':
            # the mode is the target's (find -L); a link to a file is no writable folder (review #63 pass 1)
            gaps.append(f'{name}: not a directory')
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
        if gaps:
            add('read_gaps', 'not_checked', '; '.join(gaps))
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
    discovery = raw['discovery']
    skipped = {'old_releases': 0, 'over_limit': 0, 'candidates_over': 0, **raw['skipped'], 'not_laravel': 0}
    projects, gaps = [], []
    for path, project in raw['projects'].items():
        kind, why = manifest(project['composer_json'])
        if kind == 'gap':
            gaps.append(f'{path}: {why}')
        elif kind == 'not_laravel':
            skipped['not_laravel'] += 1
        else:
            projects.append((path, project))
    if discovery['failed']:
        gaps.insert(0, f'the search failed: {discovery["failed"]}')
    if discovery['partial']:
        gaps.insert(0, f'the search was partial: {discovery["partial"]}')
    if skipped['over_limit']:
        gaps.append(f'{skipped["over_limit"]} more Laravel project(s) past the limit of {MAX_PROJECTS} not checked')
    if skipped['candidates_over']:
        gaps.append(f'{skipped["candidates_over"]} more folder(s) with artisan past the limit of {MAX_CANDIDATES} '
                    'not examined')

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
        out.append({'path': path, 'owner': project.get('owner'), 'framework': framework, 'packages': packages,
                    'app': app})

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
                'files only, with no more rights than the project\'s owner: who can read .env, APP_DEBUG and '
                'APP_ENV (from the cached config when there is one), storage and bootstrap/cache writable by '
                'all, whether the Laravel release still gets security fixes and the known vulnerabilities of '
                'its packages. Never reads APP_KEY or passwords, runs nothing in the project.',
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
