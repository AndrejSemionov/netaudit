"""
laravel_server: every Laravel project on a server, over SSH, reading files
only (docs/research/laravel_audit.md §5, contract L4).

Three layers are tested apart:
- the two programs that run on the server and must print nothing but the
  allowed lines (the grep of APP_DEBUG/APP_ENV, the awk of the cached
  config) - run here with the real grep and awk on sample files that hold
  secrets;
- collect(): the commands sent over SSH, through a fake that reads the
  marker-wrapped command, runs it against an in-memory file tree and
  answers like the real tools;
- judge(): the verdicts, from collected data built by hand.
The versions' data is faked at laravel_data.support / vulnerabilities
(tested in test_laravel_data.py).
"""

from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess  # nosec B404 - runs the real grep/awk on local sample files

import pytest

import netaudit_pkg.checks  # noqa: F401 - registers every check
from netaudit_pkg import laravel_data
from netaudit_pkg.checks import laravel_server
from netaudit_pkg.findings import subject_id
from netaudit_pkg.registry import registry

APP = '/var/www/app'
APP_KEY = 'base64:c2VjcmV0LWtleS1uZXZlci1zaG93bg=='
SUPPORTED = {'status': 'supported', 'cycle': '12', 'eol': '2027-02-24', 'latest': '12.73.0', 'error': None}
ENDED = {'status': 'ended', 'cycle': '10', 'eol': '2025-02-04', 'latest': '10.50.4', 'error': None}
GHSA = {'id': 'GHSA-78fx-h6xr-vch4', 'title': 'Laravel has a File Validation Bypass', 'severity': 'medium',
        'cve': 'CVE-2025-27515', 'fixed': ['10.48.29'],
        'link': 'https://osv.dev/vulnerability/GHSA-78fx-h6xr-vch4', 'error': None}
COMPOSER = json.dumps({'require': {'php': '^8.2', 'laravel/framework': '^12.0'}})
INSTALLED_12 = json.dumps({'packages': [{'name': 'laravel/framework', 'version': 'v12.3.0'},
                                        {'name': 'guzzlehttp/guzzle', 'version': '7.9.2'}]})
INSTALLED_10 = json.dumps({'packages': [{'name': 'laravel/framework', 'version': 'v10.0.0'}]})


# =============================================================================
# the programs that run on the server
# =============================================================================

ENV_SAMPLE = f"""APP_NAME=Shop
APP_ENV=local
APP_KEY={APP_KEY}
APP_DEBUG=true
APP_DEBUG_BAR=secret-one
APP_ENVIRONMENT=secret-two
#APP_DEBUG=false
  export APP_ENV="production"
DB_PASSWORD=hunter2-secret
"""

# what `php artisan config:cache` writes: var_export of every setting
CONFIG_SAMPLE = f"""<?php return array (
  'concurrency' =>
  array (
    'default' => 'process',
  ),
  'app' =>
  array (
    'name' => 'Shop',
    'env' => 'production',
    'debug' => false,
    'url' => 'https://shop.test',
    'key' => '{APP_KEY}',
    'maintenance' =>
    array (
      'driver' => 'file',
      'debug' => true,
    ),
  ),
  'database' =>
  array (
    'connections' =>
    array (
      'mysql' =>
      array (
        'password' => 'hunter2-secret',
      ),
    ),
  ),
  'ignition' =>
  array (
    'debug' => true,
    'env' => 'local',
  ),
);
"""


@pytest.mark.skipif(not shutil.which('grep'), reason='needs grep')
def test_the_env_grep_prints_only_the_two_keys(tmp_path):
    sample = tmp_path / '.env'
    sample.write_text(ENV_SAMPLE)
    out = subprocess.run(['grep', '-E', laravel_server.ENV_KEYS_PATTERN, str(sample)],  # nosec B603 B607
                         capture_output=True, text=True, check=False).stdout
    assert out.splitlines() == ['APP_ENV=local', 'APP_DEBUG=true', '  export APP_ENV="production"']
    for secret in (APP_KEY, 'hunter2', 'secret-one', 'secret-two'):
        assert secret not in out


@pytest.mark.skipif(not shutil.which('awk'), reason='needs awk')
def test_the_config_awk_prints_only_app_env_and_debug(tmp_path):
    sample = tmp_path / 'config.php'
    sample.write_text(CONFIG_SAMPLE)
    out = subprocess.run(['awk', laravel_server.CONFIG_AWK, str(sample)],  # nosec B603 B607
                         capture_output=True, text=True, check=False).stdout
    assert out.splitlines() == ["    'env' => 'production',", "    'debug' => false,"]
    for secret in (APP_KEY, 'hunter2', 'shop.test'):
        assert secret not in out


@pytest.mark.skipif(not shutil.which('awk'), reason='needs awk')
def test_the_config_awk_prints_nothing_without_an_app_block(tmp_path):
    sample = tmp_path / 'config.php'
    sample.write_text("<?php return array (\n  'database' =>\n  array (\n    'debug' => true,\n  ),\n);\n")
    out = subprocess.run(['awk', laravel_server.CONFIG_AWK, str(sample)],  # nosec B603 B607
                         capture_output=True, text=True, check=False).stdout
    assert out == ''


# =============================================================================
# parsing what came back
# =============================================================================

@pytest.mark.parametrize(('line', 'on'), [
    ('APP_DEBUG=true', True), ('APP_DEBUG="true"', True), ("APP_DEBUG='(true)'", True), ('APP_DEBUG=TRUE', True),
    ('APP_DEBUG=1', True), ('APP_DEBUG=yes', True), ('export APP_DEBUG=true', True),
    ('APP_DEBUG=false', False), ('APP_DEBUG=(false)', False), ('APP_DEBUG=0', False), ('APP_DEBUG=', False),
    ('APP_DEBUG=null', False), ('APP_DEBUG=empty', False), ('APP_DEBUG=false # was true', False),
    ('  APP_DEBUG = true', True),
])
def test_app_debug_follows_laravels_env_and_phps_bool(line, on):
    values = laravel_server.parse_env_lines(line + '\n')
    assert laravel_server.debug_on(values['APP_DEBUG']) is on


def test_a_quoted_value_keeps_its_hash():
    assert laravel_server.parse_env_lines('APP_ENV="local#x"\n')['APP_ENV'] == 'local#x'


def test_a_key_set_twice_with_two_values_is_ambiguous_and_once_more_with_one_is_not():
    values = laravel_server.parse_env_lines('APP_DEBUG=true\nAPP_DEBUG=false\nAPP_ENV=local\nAPP_ENV="local"\n')
    assert values['APP_DEBUG'] is laravel_server.AMBIGUOUS
    assert values['APP_ENV'] == 'local'


def test_a_key_not_set_is_missing():
    assert laravel_server.parse_env_lines('APP_ENV=production\n')['APP_DEBUG'] is laravel_server.MISSING


@pytest.mark.parametrize(('text', 'expected'), [
    ("    'env' => 'production',\n    'debug' => false,\n", {'APP_ENV': 'production', 'APP_DEBUG': False}),
    ("    'env' => 'local',\n    'debug' => true,\n", {'APP_ENV': 'local', 'APP_DEBUG': True}),
    ("    'env' => 'it\\'s',\n    'debug' => NULL,\n", {'APP_ENV': "it's", 'APP_DEBUG': None}),
    ('', {'APP_ENV': laravel_server.MISSING, 'APP_DEBUG': laravel_server.MISSING}),
])
def test_cached_config_values(text, expected):
    assert laravel_server.parse_config_lines(text) == expected


# =============================================================================
# judge(): verdicts from collected data
# =============================================================================

def _read(text='', status='ok', truncated=False, reason=None):
    return {'status': status, 'text': text, 'truncated': truncated, 'reason': reason}


def _project(*, composer=COMPOSER, installed=INSTALLED_12, lock=None, env=None, env_lines=None,
             config_lines=None, storage=0o775, cache=0o775, config_php=False, dirs_status='ok'):
    """One project as collect() returns it. env: [(name, mode, owner, group)]."""
    env = [('.env', 0o640, 'deploy', 'www-data')] if env is None else env
    entries = {}
    if storage is not None:
        entries['storage'] = {'mode': storage, 'type': 'd'}
    if cache is not None:
        entries['bootstrap/cache'] = {'mode': cache, 'type': 'd'}
    if config_php:
        entries['bootstrap/cache/config.php'] = {'mode': 0o644, 'type': 'f'}
    return {
        'composer_json': composer if isinstance(composer, dict) else _read(composer),
        'installed': installed if isinstance(installed, dict) else (_read(installed) if installed is not None
                                                                     else _read(status='missing')),
        'lock': lock if isinstance(lock, dict) else (_read(lock) if lock is not None else _read(status='missing')),
        'env_files': {'status': 'ok', 'reason': None,
                      'files': [{'name': n, 'mode': m, 'owner': o, 'group': g, 'type': 'f'} for n, m, o, g in env]},
        'dirs': {'status': dirs_status, 'reason': None if dirs_status == 'ok' else 'Permission denied',
                 'entries': entries},
        'env_lines': env_lines if isinstance(env_lines, dict) else _read(
            'APP_ENV=production\nAPP_DEBUG=false\n' if env_lines is None else env_lines),
        'config_lines': config_lines if isinstance(config_lines, dict) or config_lines is None
        else _read(config_lines),
    }


def _raw(projects=None, *, dirs=None, links=None, partial=None, failed=None, sudo=True, skipped=None):
    projects = {APP: _project()} if projects is None else projects
    return {'sudo': sudo, 'sudo_note': None if sudo else 'sudo needs a password',
            'discovery': {'dirs': list(projects) if dirs is None else dirs, 'links': links or {},
                          'partial': partial, 'failed': failed},
            'skipped': skipped or {'old_releases': 0, 'over_limit': 0},
            'projects': projects}


@pytest.fixture
def data(monkeypatch):
    state = {'support': SUPPORTED, 'vulns': None, 'asked': []}

    def vulns(packages):
        state['asked'].append(packages)
        if state['vulns'] is not None:
            return state['vulns']
        return {'status': 'ok', 'matches': {p['name']: [] for p in packages}, 'unanswered': [], 'error': None,
                'checked': len(packages)}

    monkeypatch.setattr(laravel_data, 'support', lambda version, today=None: state['support'])
    monkeypatch.setattr(laravel_data, 'vulnerabilities', vulns)
    return state


def _ids(result):
    return [f.get('id') for f in result.get('findings', [])]


def _by_id(result, fid):
    return next(f for f in result['findings'] if f.get('id') == fid)


def _checked(result, project=APP):
    return {c['item']: c['status'] for c in result['checked'] if c.get('project') == project}


def _detail(result, item, project=APP):
    return next(c['detail'] for c in result['checked'] if c['item'] == item and c.get('project') == project)


def test_registered_as_a_read_only_ssh_check_in_the_laravel_category():
    spec = registry.get('laravel_server')
    assert spec.category == 'laravel'
    assert spec.risk_level == 'READ_ONLY'
    assert [p['name'] for p in spec.params] == ['host', 'user', 'port', 'key_path', 'password', 'sudo_password']


def test_without_a_host():
    assert 'error' in laravel_server.check_laravel_server(host='')


def test_a_well_kept_project_is_ok(data):
    result = laravel_server.judge(_raw(), 'srv.test')
    checked = _checked(result)
    assert set(checked) == {'env_files', 'app_debug', 'app_env', 'writable_dirs', 'laravel_version', 'vulns'}
    assert set(checked.values()) == {'ok'}
    assert _checked(result, None) == {'discovery': 'ok'}
    assert result['verdict'] == 'ok'
    assert result['score'] == {'value': 100, 'complete': True, 'not_checked': []}
    assert result['projects'][0]['path'] == APP
    assert result['projects'][0]['framework']['version'] == '12.3.0'
    assert data['asked'] == [[{'name': 'laravel/framework', 'version': '12.3.0'},
                              {'name': 'guzzlehttp/guzzle', 'version': '7.9.2'}]]


def test_no_project_found_is_not_laravel(data):
    result = laravel_server.judge(_raw({}), 'srv.test')
    assert result['verdict'] == 'not_laravel'
    assert {f['severity'] for f in result['findings']} == {'info'}
    assert 'score' not in result


def test_no_project_found_in_a_partial_search_cannot_tell(data):
    result = laravel_server.judge(_raw({}, partial='Permission denied in /home/other'), 'srv.test')
    assert result['verdict'] == 'incomplete'
    assert 'Permission denied' in result['findings'][0]['detail']


def test_a_failed_search_is_an_error(data):
    result = laravel_server.judge(_raw({}, failed='find: unknown predicate -printf'), 'srv.test')
    assert result['verdict'] == 'incomplete'
    assert 'find' in result['findings'][0]['detail']


def test_a_partial_search_is_a_gap_next_to_the_projects_found(data):
    result = laravel_server.judge(_raw(partial='Permission denied in /home/other'), 'srv.test')
    assert _checked(result, None) == {'discovery': 'not_checked'}
    assert result['verdict'] == 'incomplete'


@pytest.mark.parametrize(('name', 'judged'), [('.env', True), ('.env.production', True), ('.env.backup', True),
                                              ('.env.example', False)])
def test_an_env_file_readable_by_everyone(data, name, judged):
    raw = _raw({APP: _project(env=[('.env', 0o640, 'deploy', 'www-data'), (name, 0o644, 'deploy', 'deploy')])})
    result = laravel_server.judge(raw, 'srv.test')
    fid = subject_id('LV-SRV-001', APP, name)
    if judged:
        f = _by_id(result, fid)
        assert f['severity'] == 'high'
        assert '644' in f['detail'] and 'deploy:deploy' in f['detail']
        assert _checked(result)['env_files'] == 'problem'
    else:
        assert fid not in _ids(result)
        assert _checked(result)['env_files'] == 'ok'


def test_no_env_file_and_no_cached_config_cannot_tell_the_values(data):
    result = laravel_server.judge(_raw({APP: _project(env=[], env_lines=_read(status='missing'))}), 'srv.test')
    checked = _checked(result)
    assert checked['app_debug'] == checked['app_env'] == 'not_checked'
    assert 'environment' in _detail(result, 'app_debug')


def test_debug_on_in_env(data):
    result = laravel_server.judge(_raw({APP: _project(env_lines='APP_ENV=production\nAPP_DEBUG=true\n')}), 'srv.test')
    f = _by_id(result, subject_id('LV-SRV-002', APP))
    assert f['severity'] == 'high' and '.env' in f['detail']
    assert _checked(result)['app_debug'] == 'problem'


def test_cached_config_wins_over_env(data):
    # Laravel does not read .env at all when the config is cached
    raw = _raw({APP: _project(env_lines='APP_ENV=local\nAPP_DEBUG=true\n', config_php=True,
                              config_lines="    'env' => 'production',\n    'debug' => false,\n")})
    result = laravel_server.judge(raw, 'srv.test')
    assert not [i for i in _ids(result) if i.startswith(('LV-SRV-002', 'LV-SRV-003'))]
    assert 'cached config' in _detail(result, 'app_debug')
    assert _checked(result)['app_debug'] == 'ok'


def test_debug_on_in_cached_config(data):
    raw = _raw({APP: _project(config_php=True, config_lines="    'env' => 'production',\n    'debug' => true,\n")})
    f = _by_id(laravel_server.judge(raw, 'srv.test'), subject_id('LV-SRV-002', APP))
    assert 'cached config' in f['detail']


def test_a_cached_config_that_could_not_be_read_is_not_checked(data):
    raw = _raw({APP: _project(config_php=True, config_lines=_read(status='denied', reason='Permission denied'))})
    result = laravel_server.judge(raw, 'srv.test')
    assert _checked(result)['app_debug'] == _checked(result)['app_env'] == 'not_checked'


@pytest.mark.parametrize(('env', 'flagged'), [('local', True), ('development', True), ('production', False),
                                              ('staging', False)])
def test_app_env(data, env, flagged):
    result = laravel_server.judge(_raw({APP: _project(env_lines=f'APP_ENV={env}\nAPP_DEBUG=false\n')}), 'srv.test')
    fid = subject_id('LV-SRV-003', APP)
    assert (fid in _ids(result)) is flagged
    if flagged:
        assert _by_id(result, fid)['severity'] == 'medium'


def test_debug_not_set_is_off_by_default(data):
    result = laravel_server.judge(_raw({APP: _project(env_lines='APP_ENV=production\n')}), 'srv.test')
    assert _checked(result)['app_debug'] == 'ok'
    assert 'not set' in _detail(result, 'app_debug')


def test_an_unreadable_env_is_not_checked(data):
    raw = _raw({APP: _project(env_lines=_read(status='denied', reason='Permission denied'))}, sudo=False)
    result = laravel_server.judge(raw, 'srv.test')
    assert _checked(result)['app_debug'] == 'not_checked'
    assert 'Permission denied' in _detail(result, 'app_debug')


def test_a_debug_set_twice_is_not_judged(data):
    result = laravel_server.judge(_raw({APP: _project(env_lines='APP_DEBUG=true\nAPP_DEBUG=false\n')}), 'srv.test')
    assert _checked(result)['app_debug'] == 'not_checked'
    assert 'twice' in _detail(result, 'app_debug')


def test_an_env_value_is_shown_only_when_it_is_a_plain_word(data):
    result = laravel_server.judge(_raw({APP: _project(env_lines='APP_ENV="loc al; $(id)"\n')}), 'srv.test')
    assert '$(id)' not in json.dumps(result)


@pytest.mark.parametrize(('storage', 'cache', 'flagged'), [(0o777, 0o775, ['storage']),
                                                           (0o775, 0o777, ['bootstrap/cache']),
                                                           (0o2777, 0o1777, ['storage', 'bootstrap/cache']),
                                                           (0o775, 0o755, [])])
def test_directories_writable_by_everyone(data, storage, cache, flagged):
    result = laravel_server.judge(_raw({APP: _project(storage=storage, cache=cache)}), 'srv.test')
    ids = [i for i in _ids(result) if i.startswith('LV-SRV-004')]
    assert ids == [subject_id('LV-SRV-004', APP, d) for d in flagged]
    assert _checked(result)['writable_dirs'] == ('problem' if flagged else 'ok')


def test_directories_that_could_not_be_read_are_not_checked(data):
    result = laravel_server.judge(_raw({APP: _project(storage=None, cache=None, dirs_status='error')}), 'srv.test')
    assert _checked(result)['writable_dirs'] == 'not_checked'


def test_an_ended_release_line_and_a_vulnerable_package(data):
    data['support'] = ENDED
    data['vulns'] = {'status': 'ok', 'matches': {'laravel/framework': [GHSA]}, 'unanswered': [], 'error': None,
                     'checked': 1}
    result = laravel_server.judge(_raw({APP: _project(installed=INSTALLED_10)}), 'srv.test')
    eol = _by_id(result, subject_id('LV-SRV-005', APP))
    assert eol['severity'] == 'high' and APP in eol['title']
    vuln = _by_id(result, subject_id('LV-SRV-006', APP, 'laravel/framework', GHSA['id']))
    assert vuln['severity'] == 'medium' and vuln['link'] == GHSA['link']
    assert not [i for i in _ids(result) if i.startswith(('LV-EOL', 'LV-VULN'))]
    assert result['vuln_data']['notices'] == laravel_data.NOTICES


def test_installed_json_first_and_the_lock_when_it_is_missing(data):
    result = laravel_server.judge(_raw({APP: _project(installed=None, lock=INSTALLED_10)}), 'srv.test')
    assert result['projects'][0]['framework']['source'] == 'composer.lock'
    assert 'locked' in _detail(result, 'laravel_version')


def test_no_version_file_on_the_server(data):
    result = laravel_server.judge(_raw({APP: _project(installed=None, lock=None)}), 'srv.test')
    checked = _checked(result)
    assert checked['laravel_version'] == checked['vulns'] == 'not_checked'
    assert 'neither' in _detail(result, 'vulns')
    assert data['asked'] == []


def test_a_version_file_that_could_not_be_read(data):
    raw = _raw({APP: _project(installed=_read(status='denied', reason='Permission denied'), lock=None)}, sudo=False)
    result = laravel_server.judge(raw, 'srv.test')
    assert _checked(result)['vulns'] == 'not_checked'
    assert 'Permission denied' in _detail(result, 'vulns')


def test_a_version_file_too_large_to_read(data):
    raw = _raw({APP: _project(installed=_read('{"packages": [', truncated=True), lock=None)})
    result = laravel_server.judge(raw, 'srv.test')
    assert 'too large' in _detail(result, 'vulns')


def test_artisan_without_laravel_framework_is_not_a_project(data):
    other = '/var/www/other'
    raw = _raw({APP: _project(), other: _project(composer=json.dumps({'require': {'symfony/console': '^7'}}))})
    result = laravel_server.judge(raw, 'srv.test')
    assert [p['path'] for p in result['projects']] == [APP]
    assert result['skipped']['not_laravel'] == 1


def test_a_composer_json_that_could_not_be_read_is_a_gap(data):
    raw = _raw({APP: _project(composer=_read(status='denied', reason='Permission denied'))}, sudo=False)
    result = laravel_server.judge(raw, 'srv.test')
    assert result['verdict'] == 'incomplete'
    assert 'Permission denied' in _detail(result, 'discovery', None)


def test_findings_name_their_project_and_items_carry_it(data):
    second = '/home/forge/shop.test'
    raw = _raw({APP: _project(), second: _project(env_lines='APP_DEBUG=true\n')})
    result = laravel_server.judge(raw, 'srv.test')
    assert _checked(result, second)['app_debug'] == 'problem'
    assert _checked(result, APP)['app_debug'] == 'ok'
    assert second in _by_id(result, subject_id('LV-SRV-002', second))['title']
    assert result['verdict'] == 'danger'


def test_skipped_releases_and_the_limit_are_said(data):
    raw = _raw(skipped={'old_releases': 3, 'over_limit': 2})
    result = laravel_server.judge(raw, 'srv.test')
    detail = _detail(result, 'discovery', None)
    assert '3 earlier release' in detail and '2 more' in detail
    assert _checked(result, None)['discovery'] == 'not_checked'     # projects past the limit were not checked


def test_no_secret_reaches_the_result(data):
    raw = _raw({APP: _project(env_lines=f'APP_DEBUG=true\nAPP_KEY={APP_KEY}\n')})
    assert APP_KEY not in json.dumps(laravel_server.judge(raw, 'srv.test'))


# =============================================================================
# select_projects(): zero-downtime releases and the limit
# =============================================================================

def test_only_the_current_release_is_checked():
    dirs = ['/home/forge/a/releases/1', '/home/forge/a/releases/2', '/var/www/b']
    links = {'/home/forge/a/current': '/home/forge/a/releases/2'}
    selected, skipped = laravel_server.select_projects(dirs, links)
    assert selected == ['/home/forge/a/releases/2', '/var/www/b']
    assert skipped == {'old_releases': 1, 'over_limit': 0}


def test_a_relative_current_link():
    dirs = ['/srv/a/releases/20261101', '/srv/a/releases/20261120']
    selected, _ = laravel_server.select_projects(dirs, {'/srv/a/current': 'releases/20261120/'})
    assert selected == ['/srv/a/releases/20261120']


def test_releases_without_a_current_link_are_all_checked():
    dirs = ['/srv/a/releases/1', '/srv/a/releases/2']
    assert laravel_server.select_projects(dirs, {})[0] == dirs


def test_at_most_max_projects():
    dirs = [f'/var/www/p{i:02d}' for i in range(laravel_server.MAX_PROJECTS + 2)]
    selected, skipped = laravel_server.select_projects(dirs, {})
    assert selected == dirs[:laravel_server.MAX_PROJECTS]
    assert skipped == {'old_releases': 0, 'over_limit': 2}


# =============================================================================
# collect(): the commands sent over SSH
# =============================================================================

_WRAPPED = re.compile(r"^\{ (?P<cmd>.*); rc=\$\?; printf '\\n%s:%s\\n' '(?P<marker>__NETAUDIT_RC_[0-9a-f]+__)' "
                      r'"\$rc"; \}$', re.DOTALL)


class FakeServer:
    """An SSH executor whose commands run against an in-memory tree.
    files: path -> dict(type 'f'|'d'|'l', mode, owner, group, text, target,
    root_only: readable only through sudo)."""

    def __init__(self, files, *, sudo='password', user='deploy'):
        self.files = files
        self.sudo_mode = sudo          # 'password' | 'nopasswd' | 'refused'
        self.user = user
        self.password = ''
        self.sudo_password = 'pw' if sudo == 'password' else ''
        self.commands = []             # (argv, through sudo)

    # the executor's interface -------------------------------------------------
    def run(self, cmd, timeout=20, stdin_data=None):
        m = _WRAPPED.match(cmd)
        assert m, f'every command is marker-wrapped: {cmd!r}'
        argv = shlex.split(m.group('cmd'))
        sudo = False
        if argv[0] == 'sudo':
            sudo = True
            argv = argv[argv.index('--') + 1:]
            if self.sudo_mode == 'refused' or (self.sudo_mode == 'password' and stdin_data != 'pw\n'):
                return f"\n{m.group('marker')}:1\n", 'sudo: a password is required\n'
        self.commands.append((argv, sudo))
        out, err, rc = self._tool(argv, sudo)
        return f"{out}\n{m.group('marker')}:{rc}\n", err

    def close(self):
        pass

    # the tools ------------------------------------------------------------------
    def _readable(self, path, sudo):
        entry = self.files.get(path)
        return entry is not None and (sudo or self.user == 'root' or not entry.get('root_only'))

    def _tool(self, argv, sudo):
        handler = {'find': self._find, 'head': self._head, 'grep': self._grep, 'awk': self._awk}.get(argv[0])
        assert handler, f'only find, head, grep and awk are run: {argv}'
        return handler(argv, sudo)

    def _find(self, argv, sudo):
        if 'artisan' in argv:                                   # the search
            out = ''
            for path, e in sorted(self.files.items()):
                if e['type'] == 'f' and path.endswith('/artisan') and '/vendor/' not in path:
                    out += 'A' + path.rsplit('/', 1)[0] + '\0'
                if e['type'] == 'l' and path.endswith('/current'):
                    out += f'L{path}\0{e["target"]}\0'
            denied = [p for p, e in self.files.items() if e.get('root_only') and e['type'] == 'd' and not sudo]
            err = ''.join(f"find: '{p}': Permission denied\n" for p in denied)
            return out, err, 1 if err else 0
        if '.env*' in argv:                                     # the .env files of one project
            root = argv[argv.index('-L') + 1]
            out = ''
            for path, e in sorted(self.files.items()):
                head, _, name = path.rpartition('/')
                if head == root and name.startswith('.env') and e['type'] == 'f':
                    out += f'{name}\t{e["mode"]:o}\t{e["owner"]}\t{e["group"]}\tf\0'
            return out, '', 0
        paths = argv[1:argv.index('-maxdepth')]                 # storage, bootstrap/cache, config.php
        out, err = '', ''
        for path in paths:
            e = self.files.get(path)
            if e is None:
                err += f"find: '{path}': No such file or directory\n"
            else:
                out += f'{path}\t{e["mode"]:o}\t{e["type"]}\0'
        return out, err, 1 if err else 0

    def _head(self, argv, sudo):
        assert argv[1] == '-c'
        path = argv[3]
        assert not path.rsplit('/', 1)[1].startswith('.env'), '.env is never read whole'
        assert not path.endswith('config.php'), 'the cached config is never read whole'
        if path not in self.files:
            return '', f"head: cannot open '{path}' for reading: No such file or directory\n", 1
        if not self._readable(path, sudo):
            return '', f"head: cannot open '{path}' for reading: Permission denied\n", 1
        return self.files[path]['text'][:int(argv[2])], '', 0

    def _grep(self, argv, sudo):
        assert argv[1:3] == ['-E', laravel_server.ENV_KEYS_PATTERN]
        path = argv[3]
        if path not in self.files:
            return '', f'grep: {path}: No such file or directory\n', 2
        if not self._readable(path, sudo):
            return '', f'grep: {path}: Permission denied\n', 2
        lines = [ln for ln in self.files[path]['text'].splitlines() if re.match(
            r'^\s*(export\s+)?(APP_DEBUG|APP_ENV)\s*=', ln)]
        return '\n'.join(lines), '', 0 if lines else 1

    def _awk(self, argv, sudo):
        assert argv[1] == laravel_server.CONFIG_AWK
        path = argv[2]
        if not self._readable(path, sudo):
            return '', f'awk: cannot open "{path}" (Permission denied)\n', 2
        text = self.files[path]['text']
        return '\n'.join(ln for ln in text.splitlines() if re.match(r"^    '(env|debug)' => ", ln)), '', 0


def _tree(root=APP, *, env_text='APP_ENV=production\nAPP_DEBUG=false\n', env_mode=0o640, root_only_env=True,
          installed=INSTALLED_12, extra=None):
    files = {
        f'{root}/artisan': {'type': 'f', 'mode': 0o755, 'text': '#!/usr/bin/env php'},
        f'{root}/composer.json': {'type': 'f', 'mode': 0o644, 'text': COMPOSER},
        f'{root}/vendor/composer/installed.json': {'type': 'f', 'mode': 0o644, 'text': installed},
        f'{root}/.env': {'type': 'f', 'mode': env_mode, 'owner': 'root', 'group': 'www-data', 'text': env_text,
                         'root_only': root_only_env},
        f'{root}/storage': {'type': 'd', 'mode': 0o775},
        f'{root}/bootstrap/cache': {'type': 'd', 'mode': 0o775},
    }
    files.update(extra or {})
    return files


def test_collect_with_sudo_reads_everything_it_needs(data):
    server = FakeServer(_tree())
    raw = laravel_server.collect(server)
    assert raw['sudo'] is True
    assert all(sudo for _argv, sudo in server.commands)
    project = raw['projects'][APP]
    assert project['env_lines']['status'] == 'ok'
    assert 'APP_DEBUG=false' in project['env_lines']['text']
    assert project['env_files']['files'][0]['mode'] == 0o640
    assert project['dirs']['entries']['storage']['mode'] == 0o775
    assert project['config_lines'] is None              # no cached config on this server
    tools = {argv[0] for argv, _sudo in server.commands}
    assert tools <= {'find', 'head', 'grep', 'awk'}


def test_collect_without_sudo_says_so_and_what_it_could_not_read(data):
    server = FakeServer(_tree(), sudo='refused')
    raw = laravel_server.collect(server)
    assert raw['sudo'] is False and 'password' in raw['sudo_note']
    assert not any(sudo for _argv, sudo in server.commands)
    assert raw['projects'][APP]['env_lines']['status'] == 'denied'
    result = laravel_server.judge(raw, 'srv.test')
    assert result['collected_without_sudo'] is True
    assert _checked(result)['app_debug'] == 'not_checked'


def test_collect_as_root_does_not_use_sudo(data):
    server = FakeServer(_tree(), sudo='refused', user='root')
    raw = laravel_server.collect(server)
    assert raw['sudo'] is False and raw['sudo_note'] is None
    assert raw['projects'][APP]['env_lines']['status'] == 'ok'
    assert 'collected_without_sudo' not in laravel_server.judge(raw, 'srv.test')


def test_collect_reads_the_cached_config_only_through_awk(data):
    config = {f'{APP}/bootstrap/cache/config.php': {'type': 'f', 'mode': 0o644, 'text': CONFIG_SAMPLE}}
    server = FakeServer(_tree(extra=config))
    raw = laravel_server.collect(server)
    lines = raw['projects'][APP]['config_lines']
    assert lines['status'] == 'ok'
    assert APP_KEY not in lines['text'] and 'hunter2' not in lines['text']
    result = laravel_server.judge(raw, 'srv.test')
    assert 'cached config' in _detail(result, 'app_debug')


def test_paths_from_the_server_reach_the_tools_as_one_argument(data):
    odd = "/var/www/it's $(touch x) a;b"
    server = FakeServer(_tree(odd))
    raw = laravel_server.collect(server)
    assert odd in raw['projects']
    assert any(argv[-1] == f'{odd}/.env' for argv, _sudo in server.commands if argv[0] == 'grep')


def test_collect_reads_a_version_file_up_to_the_limit(data, monkeypatch):
    monkeypatch.setattr(laravel_server, 'MAX_INVENTORY', 40)
    server = FakeServer(_tree(installed=INSTALLED_12))
    raw = laravel_server.collect(server)
    assert raw['projects'][APP]['installed']['truncated'] is True


def test_only_the_current_release_is_read(data):
    files = {}
    for release in ('1', '2'):
        files.update(_tree(f'/home/forge/shop/releases/{release}'))
    files['/home/forge/shop/current'] = {'type': 'l', 'mode': 0o777, 'target': 'releases/2'}
    raw = laravel_server.collect(FakeServer(files))
    assert list(raw['projects']) == ['/home/forge/shop/releases/2']
    assert raw['skipped']['old_releases'] == 1


def test_a_search_with_permission_errors_is_partial(data):
    files = _tree()
    files['/home/other'] = {'type': 'd', 'mode': 0o700, 'root_only': True}
    raw = laravel_server.collect(FakeServer(files, sudo='refused'))
    assert 'Permission denied' in raw['discovery']['partial']


def test_missing_roots_are_not_errors(data):
    server = FakeServer(_tree())
    original = server._find

    def find(argv, sudo):
        out, err, rc = original(argv, sudo)
        if 'artisan' in argv:
            err += "find: '/srv': No such file or directory\n"
            rc = 1
        return out, err, rc

    server._find = find
    raw = laravel_server.collect(server)
    assert raw['discovery']['partial'] is None and raw['discovery']['failed'] is None


def test_the_whole_audit_over_a_fake_server(data):
    files = _tree(env_text='APP_ENV=local\nAPP_DEBUG=true\n', env_mode=0o644, root_only_env=False)
    files[f'{APP}/storage']['mode'] = 0o777
    result = laravel_server.audit_laravel_server(FakeServer(files), 'srv.test')
    ids = set(_ids(result))
    assert {subject_id('LV-SRV-001', APP, '.env'), subject_id('LV-SRV-002', APP), subject_id('LV-SRV-003', APP),
            subject_id('LV-SRV-004', APP, 'storage')} <= ids
    assert result['verdict'] == 'danger'
    assert result['host'] == 'srv.test'
