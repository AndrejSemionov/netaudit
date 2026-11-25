"""
laravel_server: every Laravel project on a server, over SSH, reading files
only (docs/research/laravel_audit.md §5, contract L4; review #63 pass 1).

Three layers are tested apart:
- the two awk programs that run on the server and print only normalized
  tokens of APP_DEBUG / APP_ENV (from .env, from the cached config) - run
  here with the real awk on files that hold secrets;
- collect(): the commands sent over SSH, through a fake server with owners,
  groups and modes that reads the marker-wrapped command, runs it as the
  account it would run as (sudo, sudo -u, runuser) and answers like the real
  tools (its awk is the real one);
- judge(): the verdicts, from collected data built by hand.
The versions' data is faked at laravel_data.support / vulnerabilities
(tested in test_laravel_data.py).
"""

from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess  # nosec B404 - runs the real awk on local sample text

import pytest

import netaudit_pkg.checks  # noqa: F401 - registers every check
from netaudit_pkg import laravel_data
from netaudit_pkg.checks import laravel_server
from netaudit_pkg.findings import subject_id
from netaudit_pkg.registry import registry

pytestmark = pytest.mark.skipif(not shutil.which('awk'), reason='the server-side programs need awk')

APP = '/var/www/app'
APP_KEY = 'base64:c2VjcmV0LWtleS1uZXZlci1zaG93bg=='
SHADOW = 'root:$6$saltsalt$hashhashhash:19000:0:99999:7:::'
SUPPORTED = {'status': 'supported', 'cycle': '12', 'eol': '2027-02-24', 'latest': '12.73.0', 'error': None}
ENDED = {'status': 'ended', 'cycle': '10', 'eol': '2025-02-04', 'latest': '10.50.4', 'error': None}
GHSA = {'id': 'GHSA-78fx-h6xr-vch4', 'title': 'Laravel has a File Validation Bypass', 'severity': 'medium',
        'cve': 'CVE-2025-27515', 'fixed': ['10.48.29'],
        'link': 'https://osv.dev/vulnerability/GHSA-78fx-h6xr-vch4', 'error': None}
COMPOSER = json.dumps({'require': {'php': '^8.2', 'laravel/framework': '^12.0'}})
INSTALLED_12 = json.dumps({'packages': [{'name': 'laravel/framework', 'version': 'v12.3.0'},
                                        {'name': 'guzzlehttp/guzzle', 'version': '7.9.2'}]})
INSTALLED_10 = json.dumps({'packages': [{'name': 'laravel/framework', 'version': 'v10.0.0'}]})


def _awk(program: str, text: str) -> str:
    return subprocess.run(['awk', program], input=text, capture_output=True, text=True,  # nosec B603 B607
                          check=True).stdout


# =============================================================================
# the programs that run on the server: normalized tokens only
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
APP_ENV=hunter2 has spaces
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


def test_the_env_program_prints_only_normalized_tokens():
    out = _awk(laravel_server.ENV_AWK, ENV_SAMPLE)
    assert out.splitlines() == ['APP_ENV word:local', 'APP_DEBUG true', 'APP_ENV word:production', 'APP_ENV other']
    for secret in (APP_KEY, 'hunter2', 'secret-one', 'secret-two', '='):
        assert secret not in out


def test_the_config_program_prints_only_app_env_and_debug_tokens():
    out = _awk(laravel_server.CONFIG_AWK, CONFIG_SAMPLE)
    assert out.splitlines() == ['APP_ENV word:production', 'APP_DEBUG false']
    for secret in (APP_KEY, 'hunter2', 'shop.test', "'"):
        assert secret not in out


def test_the_config_program_prints_nothing_without_an_app_block():
    assert _awk(laravel_server.CONFIG_AWK, "<?php return array (\n  'database' => \n  array (\n"
                                          "    'debug' => true,\n  ),\n);\n") == ''


@pytest.mark.parametrize(('line', 'on'), [
    ('APP_DEBUG=true', True), ('APP_DEBUG="true"', True), ("APP_DEBUG='(true)'", True), ('APP_DEBUG=TRUE', True),
    ('APP_DEBUG=1', True), ('APP_DEBUG=yes', True), ('export APP_DEBUG=true', True), ('  APP_DEBUG = true', True),
    ('APP_DEBUG=false', False), ('APP_DEBUG=(false)', False), ('APP_DEBUG=0', False), ('APP_DEBUG=', False),
    ('APP_DEBUG=null', False), ('APP_DEBUG=empty', False), ('APP_DEBUG=false # was true', False),
    ('APP_DEBUG="0"', False),
])
def test_app_debug_follows_laravels_env_and_phps_bool(line, on):
    values = laravel_server.parse_tokens(_awk(laravel_server.ENV_AWK, line + '\n'))
    assert laravel_server.debug_on(values['APP_DEBUG']) is on


@pytest.mark.parametrize(('line', 'env'), [('APP_ENV=local', 'local'), ('APP_ENV="local#x"', 'OTHER'),
                                           ("APP_ENV='staging'", 'staging'), ('APP_ENV=prod # live', 'prod'),
                                           ('APP_ENV=' + 'x' * 41, 'OTHER')])
def test_app_env_is_a_plain_word_or_other(line, env):
    expected = laravel_server.OTHER if env == 'OTHER' else env
    assert laravel_server.parse_tokens(_awk(laravel_server.ENV_AWK, line + '\n'))['APP_ENV'] == expected


def test_a_key_set_twice_with_two_values_is_ambiguous_and_once_more_with_one_is_not():
    values = laravel_server.parse_tokens(_awk(laravel_server.ENV_AWK,
                                              'APP_DEBUG=true\nAPP_DEBUG=false\nAPP_ENV=local\nAPP_ENV="local"\n'))
    assert values['APP_DEBUG'] is laravel_server.AMBIGUOUS
    assert values['APP_ENV'] == 'local'


def test_a_key_not_set_is_missing_and_an_unknown_token_is_ignored():
    values = laravel_server.parse_tokens('APP_ENV word:production\nAPP_DEBUG; rm -rf\nAPP_KEY word:x\n')
    assert values == {'APP_ENV': 'production', 'APP_DEBUG': laravel_server.MISSING}


@pytest.mark.parametrize(('debug', 'env', 'expected'), [
    ('false', "'production'", {'APP_ENV': 'production', 'APP_DEBUG': False}),
    ('true', "'local'", {'APP_ENV': 'local', 'APP_DEBUG': True}),
    ('NULL', "'it\\'s'", {'APP_ENV': 'OTHER', 'APP_DEBUG': None}),
])
def test_cached_config_values(debug, env, expected):
    expected = {k: laravel_server.OTHER if v == 'OTHER' else v for k, v in expected.items()}
    text = f"<?php return array (\n  'app' => \n  array (\n    'env' => {env},\n    'debug' => {debug},\n  ),\n);\n"
    assert laravel_server.parse_tokens(_awk(laravel_server.CONFIG_AWK, text)) == expected


# =============================================================================
# judge(): verdicts from collected data
# =============================================================================

def _read(text='', status='ok', truncated=False, reason=None):
    return {'status': status, 'text': text, 'truncated': truncated, 'reason': reason}


def _project(*, composer=COMPOSER, installed=INSTALLED_12, lock=None, env=None, env_lines=None, env_status='ok',
             config_lines=None, storage=0o775, cache=0o775, config_php=False, dirs_status='ok', dir_errors=None,
             owner='deploy', storage_type='d'):
    """One project as collect() returns it. env: [(name, mode, owner, group)]; env_lines and
    config_lines are file text, turned into the server's tokens by the real awk programs."""
    env = [('.env', 0o640, 'deploy', 'www-data')] if env is None else env
    entries = {}
    if storage is not None:
        entries['storage'] = {'mode': storage, 'type': storage_type}
    if cache is not None:
        entries['bootstrap/cache'] = {'mode': cache, 'type': 'd'}
    if config_php:
        entries['bootstrap/cache/config.php'] = {'mode': 0o644, 'type': 'f'}

    def tokens(value, program):
        if isinstance(value, dict) or value is None:
            return value
        return _read(_awk(program, value))

    return {
        'owner': owner,
        'composer_json': composer if isinstance(composer, dict) else _read(composer),
        'installed': installed if isinstance(installed, dict) else (_read(installed) if installed is not None
                                                                     else _read(status='missing')),
        'lock': lock if isinstance(lock, dict) else (_read(lock) if lock is not None else _read(status='missing')),
        'env_files': {'status': env_status, 'reason': None if env_status == 'ok' else 'Permission denied',
                      'files': [{'name': n, 'mode': m, 'owner': o, 'group': g, 'type': 'f'} for n, m, o, g in env]},
        'dirs': {'status': dirs_status, 'reason': None if dirs_status == 'ok' else 'Permission denied',
                 'entries': entries, 'errors': dir_errors or {}},
        'env_tokens': tokens('APP_ENV=production\nAPP_DEBUG=false\n' if env_lines is None else env_lines,
                             laravel_server.ENV_AWK),
        'config_tokens': tokens(config_lines, laravel_server.CONFIG_AWK),
    }


def _raw(projects=None, *, dirs=None, links=None, partial=None, failed=None, sudo=True, skipped=None):
    projects = {APP: _project()} if projects is None else projects
    return {'sudo': sudo, 'sudo_note': None if sudo else 'sudo needs a password',
            'discovery': {'dirs': list(projects) if dirs is None else dirs, 'links': links or {},
                          'partial': partial, 'failed': failed},
            'skipped': skipped or {'old_releases': 0, 'over_limit': 0, 'candidates_over': 0},
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
    return [f['id'] for f in result.get('findings', []) if f.get('id')]   # the closing 'ok' finding has none


def _by_id(result, fid):
    return next(f for f in result['findings'] if f.get('id') == fid)


def _checked(result, project=APP):
    return {c['item']: c['status'] for c in result['checked'] if c.get('project') == project}


def _detail(result, item, project=APP):
    return next(c['detail'] for c in result['checked'] if c['item'] == item and c.get('project') == project)


CACHED = "<?php return array (\n  'app' => \n  array (\n    'env' => 'production',\n    'debug' => false,\n  ),\n);\n"


def test_registered_as_a_read_only_ssh_check_in_the_laravel_category():
    spec = registry.get('laravel_server')
    assert spec.category == 'laravel'
    assert spec.risk_level == 'READ_ONLY'
    assert [p['name'] for p in spec.params] == ['host', 'user', 'port', 'key_path', 'password', 'sudo_password']


def test_without_a_host():
    assert 'error' in laravel_server.check_laravel_server(host='')


def test_a_well_kept_project_with_a_cached_config_is_ok(data):
    result = laravel_server.judge(_raw({APP: _project(config_php=True, config_lines=CACHED)}), 'srv.test')
    checked = _checked(result)
    assert set(checked) == {'env_files', 'app_debug', 'app_env', 'effective_config', 'writable_dirs',
                            'laravel_version', 'vulns'}
    assert set(checked.values()) == {'ok'}
    assert _checked(result, None) == {'discovery': 'ok'}
    assert result['verdict'] == 'ok'
    assert result['score'] == {'value': 100, 'complete': True, 'not_checked': []}
    assert result['projects'][0]['path'] == APP
    assert result['projects'][0]['framework']['version'] == '12.3.0'
    assert data['asked'] == [[{'name': 'laravel/framework', 'version': '12.3.0'},
                              {'name': 'guzzlehttp/guzzle', 'version': '7.9.2'}]]


def test_values_from_env_alone_do_not_confirm_the_configuration_in_effect(data):
    # review #63 pass 1 (P4): a value of the PHP process, or .env.<APP_ENV>, would win over .env
    result = laravel_server.judge(_raw(), 'srv.test')
    checked = _checked(result)
    assert checked['app_debug'] == checked['app_env'] == 'ok'
    assert 'PHP process' in _detail(result, 'app_debug')
    assert checked['effective_config'] == 'not_checked'
    assert 'PHP process' in _detail(result, 'effective_config')
    assert result['verdict'] == 'incomplete'


def test_no_project_found_is_not_laravel(data):
    result = laravel_server.judge(_raw({}), 'srv.test')
    assert result['verdict'] == 'not_laravel'
    assert {f['severity'] for f in result['findings']} == {'info'}
    assert 'score' not in result


def test_no_project_found_in_a_partial_search_cannot_tell(data):
    result = laravel_server.judge(_raw({}, partial='Permission denied in /home/other'), 'srv.test')
    assert result['verdict'] == 'incomplete'
    assert 'Permission denied' in result['findings'][0]['detail']


def test_a_failed_search_is_not_checked(data):
    result = laravel_server.judge(_raw({}, failed='find: unknown predicate -printf'), 'srv.test')
    assert result['verdict'] == 'incomplete'
    assert 'find' in result['findings'][0]['detail']


def test_a_partial_search_is_a_gap_next_to_the_projects_found(data):
    result = laravel_server.judge(_raw({APP: _project(config_php=True, config_lines=CACHED)},
                                       partial='Permission denied in /home/other'), 'srv.test')
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


def test_a_partial_list_of_env_files_is_not_fine(data):
    # review #63 pass 1 (P3): one file seen and a Permission denied is not "every file is closed"
    result = laravel_server.judge(_raw({APP: _project(env_status='partial')}), 'srv.test')
    assert _checked(result)['env_files'] == 'not_checked'
    assert 'Permission denied' in _detail(result, 'env_files')


def test_an_open_env_file_next_to_a_partial_list_keeps_both(data):
    raw = _raw({APP: _project(env=[('.env', 0o644, 'deploy', 'deploy')], env_status='partial')})
    result = laravel_server.judge(raw, 'srv.test')
    assert _checked(result)['env_files'] == 'problem'
    assert _checked(result)['read_gaps'] == 'not_checked'
    assert 'Permission denied' in _detail(result, 'read_gaps')


def test_no_env_file_and_no_cached_config_cannot_tell_the_values(data):
    result = laravel_server.judge(_raw({APP: _project(env=[], env_lines=_read(status='missing'))}), 'srv.test')
    checked = _checked(result)
    assert checked['app_debug'] == checked['app_env'] == 'not_checked'
    assert 'environment' in _detail(result, 'app_debug')


def test_debug_on_in_env(data):
    result = laravel_server.judge(_raw({APP: _project(env_lines='APP_ENV=production\nAPP_DEBUG=true\n')}), 'srv.test')
    f = _by_id(result, subject_id('LV-SRV-002', APP))
    assert f['severity'] == 'high' and '.env' in f['detail'] and 'PHP process' in f['detail']
    assert _checked(result)['app_debug'] == 'problem'


def test_cached_config_wins_over_env(data):
    raw = _raw({APP: _project(env_lines='APP_ENV=local\nAPP_DEBUG=true\n', config_php=True, config_lines=CACHED)})
    result = laravel_server.judge(raw, 'srv.test')
    assert not [i for i in _ids(result) if i.startswith(('LV-SRV-002', 'LV-SRV-003'))]
    assert 'cached config' in _detail(result, 'app_debug')
    assert _checked(result)['app_debug'] == 'ok'
    assert _checked(result)['effective_config'] == 'ok'


def test_debug_on_in_cached_config(data):
    raw = _raw({APP: _project(config_php=True, config_lines=CACHED.replace('false', 'true'))})
    f = _by_id(laravel_server.judge(raw, 'srv.test'), subject_id('LV-SRV-002', APP))
    assert 'cached config' in f['detail']


@pytest.mark.parametrize('status', ['denied', 'skipped'])
def test_a_cached_config_that_was_not_read_is_not_checked(data, status):
    raw = _raw({APP: _project(config_php=True, config_lines=_read(status=status, reason='the reason'))})
    result = laravel_server.judge(raw, 'srv.test')
    assert _checked(result)['app_debug'] == _checked(result)['app_env'] == 'not_checked'
    assert 'the reason' in _detail(result, 'app_debug')


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
    assert 'not shown' in _detail(result, 'app_env')


@pytest.mark.parametrize(('storage', 'cache', 'flagged'), [(0o777, 0o775, ['storage']),
                                                           (0o775, 0o777, ['bootstrap/cache']),
                                                           (0o2777, 0o1777, ['storage', 'bootstrap/cache']),
                                                           (0o775, 0o755, [])])
def test_directories_writable_by_everyone(data, storage, cache, flagged):
    result = laravel_server.judge(_raw({APP: _project(storage=storage, cache=cache)}), 'srv.test')
    ids = [i for i in _ids(result) if i.startswith('LV-SRV-004')]
    assert ids == [subject_id('LV-SRV-004', APP, d) for d in flagged]
    assert _checked(result)['writable_dirs'] == ('problem' if flagged else 'ok')


def test_a_storage_that_is_not_a_directory_is_not_checked(data):
    # review #63 pass 1 (P3): the mode is the target's; a link to a file is not a writable directory
    result = laravel_server.judge(_raw({APP: _project(storage=0o777, storage_type='f')}), 'srv.test')
    assert not [i for i in _ids(result) if i.startswith('LV-SRV-004')]
    assert _checked(result)['writable_dirs'] == 'not_checked'
    assert 'not a directory' in _detail(result, 'writable_dirs')


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


def test_a_version_file_that_was_not_read(data):
    raw = _raw({APP: _project(installed=_read(status='skipped', reason='not read as root'), lock=None)})
    result = laravel_server.judge(raw, 'srv.test')
    assert _checked(result)['vulns'] == 'not_checked'
    assert 'not read as root' in _detail(result, 'vulns')


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


@pytest.mark.parametrize(('composer', 'why'), [
    (_read(status='denied', reason='Permission denied'), 'Permission denied'),
    (_read('{"require": {"laravel/framework": "^12', truncated=True), 'too large'),
    (_read('{"require": '), 'not valid JSON'),
    (_read('["x"]'), 'not a JSON object'),
])
def test_a_composer_json_that_could_not_be_read_is_a_gap_not_a_no(data, composer, why):
    # review #63 pass 1 (P2): a broken or cut manifest is not "no Laravel here"
    raw = _raw({APP: _project(composer=composer)})
    result = laravel_server.judge(raw, 'srv.test')
    assert result['verdict'] == 'incomplete'
    assert result['skipped']['not_laravel'] == 0
    assert why in _detail(result, 'discovery', None)


def test_findings_name_their_project_and_items_carry_it(data):
    second = '/home/forge/shop.test'
    raw = _raw({APP: _project(), second: _project(env_lines='APP_DEBUG=true\n')})
    result = laravel_server.judge(raw, 'srv.test')
    assert _checked(result, second)['app_debug'] == 'problem'
    assert _checked(result, APP)['app_debug'] == 'ok'
    assert second in _by_id(result, subject_id('LV-SRV-002', second))['title']
    assert result['verdict'] == 'danger'


def test_skipped_releases_and_the_limits_are_said(data):
    raw = _raw(skipped={'old_releases': 3, 'over_limit': 2, 'candidates_over': 4})
    result = laravel_server.judge(raw, 'srv.test')
    detail = _detail(result, 'discovery', None)
    assert '3 earlier release' in detail
    assert '2 more Laravel project' in detail and '4 more folder' in detail
    assert _checked(result, None)['discovery'] == 'not_checked'


def test_no_secret_reaches_the_result(data):
    raw = _raw({APP: _project(env_lines=f'APP_DEBUG=true\nAPP_KEY={APP_KEY}\n')})
    assert APP_KEY not in json.dumps(laravel_server.judge(raw, 'srv.test'))


# =============================================================================
# select_projects(): zero-downtime releases and the candidates' limit
# =============================================================================

def test_only_the_current_release_is_checked():
    dirs = ['/home/forge/a/releases/1', '/home/forge/a/releases/2', '/var/www/b']
    links = {'/home/forge/a/current': '/home/forge/a/releases/2'}
    selected, skipped = laravel_server.select_projects(dirs, links)
    assert selected == ['/home/forge/a/releases/2', '/var/www/b']
    assert skipped == {'old_releases': 1, 'candidates_over': 0}


def test_a_relative_current_link():
    dirs = ['/srv/a/releases/20261101', '/srv/a/releases/20261120']
    selected, _ = laravel_server.select_projects(dirs, {'/srv/a/current': 'releases/20261120/'})
    assert selected == ['/srv/a/releases/20261120']


def test_releases_without_a_current_link_are_all_checked():
    dirs = ['/srv/a/releases/1', '/srv/a/releases/2']
    assert laravel_server.select_projects(dirs, {})[0] == dirs


def test_at_most_max_candidates():
    dirs = [f'/var/www/p{i:03d}' for i in range(laravel_server.MAX_CANDIDATES + 2)]
    selected, skipped = laravel_server.select_projects(dirs, {})
    assert selected == dirs[:laravel_server.MAX_CANDIDATES]
    assert skipped == {'old_releases': 0, 'candidates_over': 2}


# =============================================================================
# collect(): the commands sent over SSH, run by a fake server with owners and modes
# =============================================================================

_WRAPPED = re.compile(r"^\{ (?P<cmd>.*); rc=\$\?; printf '\\n%s:%s\\n' '(?P<marker>__NETAUDIT_RC_[0-9a-f]+__)' "
                      r'"\$rc"; \}$', re.DOTALL)


class FakeServer:
    """An SSH executor whose commands run against an in-memory tree with
    owners, groups and modes. files: path -> dict(type 'f'|'d'|'l'|'p', mode,
    owner, group, text, target). A folder not listed is root's, 755."""

    def __init__(self, files, *, user='deploy', sudo='password', groups=None, runas=True, fail=None,
                 locale='C'):
        self.files = files
        # 'utf8': GNU tools quote paths with curly quotes, as on a server whose locale is UTF-8
        self.locale = locale
        self.user = user
        self.sudo_mode = sudo          # 'password' | 'nopasswd' | 'refused'
        self.runas = runas             # whether sudo -u <other user> is allowed
        # supplementary members of a group; every user's primary group is its own name
        self.groups = groups or {'www-data': {'www-data'}}
        # a command that fails as a whole: 'meta-L' / 'meta-P' / 'getent' -> (rc, stderr)
        self.fail = fail or {}
        self.password = ''
        self.sudo_password = 'pw' if sudo == 'password' else ''
        self.commands = []             # (argv, the account it ran as)
        self.through_sudo = []         # argv of the commands that went through sudo
        self.envs = []                 # the environment each command was given with env

    # the executor's interface -------------------------------------------------
    def run(self, cmd, timeout=20, stdin_data=None):
        m = _WRAPPED.match(cmd)
        assert m, f'every command is marker-wrapped: {cmd!r}'
        argv = shlex.split(m.group('cmd'))
        account = self.user
        if argv[0] == 'sudo':
            if self.sudo_mode == 'refused' or (self.sudo_mode == 'password' and stdin_data != 'pw\n'):
                return f"\n{m.group('marker')}:1\n", 'sudo: a password is required\n'
            opts, argv = argv[1:argv.index('--')], argv[argv.index('--') + 1:]
            account = opts[opts.index('-u') + 1] if '-u' in opts else 'root'
            self.through_sudo.append(argv)
            if account != 'root' and not self.runas:
                return (f"\n{m.group('marker')}:1\n",
                        f"Sorry, user {self.user} is not allowed to execute '{argv[0]}' as {account} on srv.\n")
        elif argv[0] == 'runuser':
            assert self.user == 'root', 'runuser is used only by root'
            account, argv = argv[2], argv[4:]
        env = {}
        if argv[0] == 'env':
            argv = argv[1:]
            while '=' in argv[0]:
                key, _, value = argv.pop(0).partition('=')
                env[key] = value
        self.commands.append((argv, account))
        self.envs.append(env)
        out, err, rc = self._tool(argv, account)
        if self.locale == 'utf8' and env.get('LC_ALL') != 'C':
            err = re.sub(r"'([^'\n]*)'", '\u2018\\1\u2019', err)
        return f"{out}\n{m.group('marker')}:{rc}\n", err

    def close(self):
        pass

    # the tree ------------------------------------------------------------------
    def _entry(self, path, follow):
        seen = 0
        while True:
            entry = self.files.get(path)
            if entry is None and (path == '/' or any(p.startswith(path.rstrip('/') + '/') for p in self.files)):
                entry = {'type': 'd', 'mode': 0o755, 'owner': 'root', 'group': 'root'}
            if entry is None or entry['type'] != 'l' or not follow:
                return path, entry
            target = entry['target']
            path = target if target.startswith('/') else path.rsplit('/', 1)[0] + '/' + target
            seen += 1
            assert seen < 5

    def _can_read(self, account, entry):
        if account == 'root':
            return True
        mode = entry['mode']
        if entry.get('owner') == account:
            return bool(mode & 0o400)
        if account in self.groups.get(entry.get('group'), set()):
            return bool(mode & 0o040)
        return bool(mode & 0o004)

    @staticmethod
    def _meta(path, entry):
        return f'{path}\t{entry.get("owner", "root")}\t{entry.get("group", "root")}\t{entry["mode"]:o}\t{entry["type"]}\0'

    # the tools ------------------------------------------------------------------
    def _tool(self, argv, account):
        handler = {'find': self._find, 'head': self._head, 'awk': self._awk, 'getent': self._getent}.get(argv[0])
        assert handler, f'only find, head, awk and getent are run: {argv}'
        return handler(argv, account)

    def _users(self):
        users = {'root', self.user, *(e.get('owner') for e in self.files.values() if e.get('owner'))}
        return sorted(users, key=lambda u: (u != 'root', u))

    def _getent(self, argv, account):
        if 'getent' in self.fail:
            rc, err = self.fail['getent']
            return '', err, rc
        users = self._users()
        names = [*users, *(g for g in self.groups if g not in users)]
        if argv[1] == 'passwd':
            return '\n'.join(f'{u}:x:{i}:{i}::/home/{u}:/bin/sh' for i, u in enumerate(users)), '', 0
        group = argv[2]
        if group not in names:
            return '', '', 2
        return f'{group}:x:{names.index(group)}:{",".join(sorted(self.groups.get(group, set())))}', '', 0

    def _find(self, argv, account):
        if 'artisan' in argv:                                   # the search
            out, err = '', ''
            for path, e in sorted(self.files.items()):
                hidden = [p for p, d in self.files.items() if d['type'] == 'd' and path.startswith(p + '/')
                          and not self._can_read(account, d)]
                if hidden:
                    continue
                if e['type'] == 'f' and path.endswith('/artisan') and '/vendor/' not in path:
                    out += 'A' + path.rsplit('/', 1)[0] + '\0'
                if e['type'] == 'l' and path.endswith('/current'):
                    out += f'L{path}\0{e["target"]}\0'
            for p, d in self.files.items():
                if d['type'] == 'd' and not self._can_read(account, d):
                    err += f"find: '{p}': Permission denied\n"
            return out, err, 1 if err else 0
        if '.env*' in argv:                                     # the .env files of one project
            root = argv[argv.index('-L') + 1]
            out = ''
            for path in sorted(self.files):
                head, _, name = path.rpartition('/')
                if head == root and name.startswith('.env'):
                    _, e = self._entry(path, True)
                    if e is not None:
                        out += f'{name}\t{e["mode"]:o}\t{e.get("owner", "root")}\t{e.get("group", "root")}\t{e["type"]}\0'
            return out, '', 0
        follow = argv[1] == '-L'                                # metadata of named paths
        if f'meta{argv[1]}' in self.fail:
            rc, err = self.fail[f'meta{argv[1]}']
            return '', err, rc
        paths = argv[2:argv.index('-maxdepth')]
        out, err = '', ''
        for path in paths:
            _, e = self._entry(path, follow)
            stat_error = (self.files.get(path) or {}).get('stat_error' + ('' if follow else '_P'))
            if stat_error:
                err += f"find: '{path}': {stat_error}\n"
            elif e is None:
                err += f"find: '{path}': No such file or directory\n"
            else:
                out += self._meta(path, e)
        return out, err, 1 if err else 0

    def _head(self, argv, account):
        assert argv[1] == '-c'
        path = argv[3]
        assert not path.rsplit('/', 1)[1].startswith('.env'), '.env is never read whole'
        assert not path.endswith('config.php'), 'the cached config is never read whole'
        _, e = self._entry(path, True)
        if e is None:
            return '', f"head: cannot open '{path}' for reading: No such file or directory\n", 1
        if not self._can_read(account, e):
            return '', f"head: cannot open '{path}' for reading: Permission denied\n", 1
        return e['text'][:int(argv[2])], '', 0

    def _awk(self, argv, account):
        assert argv[1] in (laravel_server.ENV_AWK, laravel_server.CONFIG_AWK)
        path = argv[2]
        _, e = self._entry(path, True)
        if e is None:
            return '', f'awk: cannot open "{path}" (No such file or directory)\n', 2
        if not self._can_read(account, e):
            return '', f'awk: cannot open "{path}" (Permission denied)\n', 2
        return _awk(argv[1], e['text']).rstrip('\n'), '', 0


def _tree(root=APP, *, owner='deploy', env_text='APP_ENV=production\nAPP_DEBUG=false\n', env_mode=0o640,
          env_owner=None, installed=INSTALLED_12, cache_mode=0o775, cache_group=None, extra=None):
    env_owner = env_owner or owner
    files = {
        root: {'type': 'd', 'mode': 0o755, 'owner': owner, 'group': owner},
        f'{root}/artisan': {'type': 'f', 'mode': 0o755, 'owner': owner, 'group': owner, 'text': '#!/usr/bin/env php'},
        f'{root}/composer.json': {'type': 'f', 'mode': 0o644, 'owner': owner, 'group': owner, 'text': COMPOSER},
        f'{root}/vendor': {'type': 'd', 'mode': 0o755, 'owner': owner, 'group': owner},
        f'{root}/vendor/composer': {'type': 'd', 'mode': 0o755, 'owner': owner, 'group': owner},
        f'{root}/vendor/composer/installed.json': {'type': 'f', 'mode': 0o644, 'owner': owner, 'group': owner,
                                                   'text': installed},
        f'{root}/.env': {'type': 'f', 'mode': env_mode, 'owner': env_owner, 'group': 'www-data', 'text': env_text},
        f'{root}/storage': {'type': 'd', 'mode': 0o775, 'owner': owner, 'group': 'www-data'},
        f'{root}/bootstrap': {'type': 'd', 'mode': 0o755, 'owner': owner, 'group': owner},
        f'{root}/bootstrap/cache': {'type': 'd', 'mode': cache_mode, 'owner': owner,
                                    'group': cache_group or 'www-data'},
    }
    files.update(extra or {})
    return files


def _ran_as(server, tool):
    return {account for argv, account in server.commands if argv[0] == tool}


def test_contents_are_read_as_the_project_owner(data):
    # review #63 pass 1 (P1): no more rights than the account that owns the project
    server = FakeServer(_tree(owner='shop'))
    raw = laravel_server.collect(server)
    assert _ran_as(server, 'head') == {'shop'} and _ran_as(server, 'awk') == {'shop'}
    assert raw['projects'][APP]['owner'] == 'shop'
    assert raw['projects'][APP]['env_tokens']['status'] == 'ok'
    assert raw['sudo'] is True
    assert {account for argv, account in server.commands if argv[0] == 'find'} == {'root'}   # names and modes


def test_a_link_planted_by_the_owner_reaches_only_what_the_owner_can_read(data):
    files = _tree(owner='shop')
    files['/etc/shadow'] = {'type': 'f', 'mode': 0o640, 'owner': 'root', 'group': 'shadow', 'text': SHADOW}
    files[f'{APP}/composer.json'] = {'type': 'l', 'mode': 0o777, 'owner': 'shop', 'group': 'shop',
                                     'target': '/etc/shadow'}
    raw = laravel_server.collect(FakeServer(files))
    assert raw['projects'][APP]['composer_json']['status'] == 'denied'
    assert SHADOW not in json.dumps(raw)


def test_the_ssh_users_own_project_is_read_without_sudo(data):
    server = FakeServer(_tree(owner='deploy'))
    laravel_server.collect(server)
    assert _ran_as(server, 'head') == {'deploy'}
    assert not [argv for argv in server.through_sudo if argv[0] in ('head', 'awk')]


def test_as_root_contents_are_read_through_runuser_as_the_owner(data):
    server = FakeServer(_tree(owner='shop'), user='root', sudo='refused')
    raw = laravel_server.collect(server)
    assert _ran_as(server, 'head') == {'shop'}
    assert raw['projects'][APP]['env_tokens']['status'] == 'ok'


def test_without_a_way_to_act_as_the_owner_contents_are_not_read(data):
    server = FakeServer(_tree(owner='shop'), sudo='refused')
    raw = laravel_server.collect(server)
    project = raw['projects'][APP]
    assert project['composer_json']['status'] == 'skipped'
    assert 'shop' in project['composer_json']['reason']
    assert not _ran_as(server, 'head')


def test_sudo_that_may_not_act_as_the_owner_is_said(data):
    server = FakeServer(_tree(owner='shop'), runas=False)
    raw = laravel_server.collect(server)
    reason = raw['projects'][APP]['composer_json']['reason']
    assert raw['projects'][APP]['composer_json']['status'] == 'error'
    assert 'not allowed' in reason


def test_a_root_project_is_read_as_root_only_along_a_path_root_alone_controls(data):
    # bootstrap/cache writable by its group: the cached config there is not read as root
    config = {f'{APP}/bootstrap/cache/config.php': {'type': 'f', 'mode': 0o640, 'owner': 'root',
                                                    'group': 'www-data', 'text': CACHED}}
    server = FakeServer(_tree(owner='root', cache_mode=0o775, extra=config))
    raw = laravel_server.collect(server)
    project = raw['projects'][APP]
    assert project['config_tokens']['status'] == 'skipped'
    assert 'bootstrap/cache' in project['config_tokens']['reason']
    assert project['env_tokens']['status'] == 'ok'                # the project folder is root's alone
    assert project['composer_json']['status'] == 'ok'
    result = laravel_server.judge(raw, 'srv.test')
    assert _checked(result)['app_debug'] == 'not_checked'


def test_a_root_project_inside_another_users_folder_is_not_read_as_root(data):
    files = _tree('/home/forge/app', owner='root')
    files['/home/forge'] = {'type': 'd', 'mode': 0o755, 'owner': 'forge', 'group': 'forge'}
    raw = laravel_server.collect(FakeServer(files))
    composer = raw['projects']['/home/forge/app']['composer_json']
    assert composer['status'] == 'skipped' and '/home/forge' in composer['reason']


def test_only_tokens_cross_for_env_and_config(data):
    files = _tree(owner='shop', cache_group='shop',
                  env_text=f'APP_DEBUG=true\nAPP_KEY={APP_KEY}\nDB_PASSWORD=hunter2-secret\n',
                  extra={f'{APP}/bootstrap/cache/config.php': {'type': 'f', 'mode': 0o640, 'owner': 'shop',
                                                               'group': 'www-data', 'text': CONFIG_SAMPLE}})
    raw = laravel_server.collect(FakeServer(files))
    dumped = json.dumps(raw)
    for secret in (APP_KEY, 'hunter2'):
        assert secret not in dumped
    assert raw['projects'][APP]['env_tokens']['text'] == 'APP_DEBUG true'
    assert raw['projects'][APP]['config_tokens']['text'] == 'APP_ENV word:production\nAPP_DEBUG false'


def test_a_file_that_is_not_a_regular_file_is_not_read(data):
    files = _tree(owner='shop')
    files[f'{APP}/vendor/composer/installed.json'] = {'type': 'p', 'mode': 0o644, 'owner': 'shop', 'group': 'shop'}
    server = FakeServer(files)
    raw = laravel_server.collect(server)
    installed = raw['projects'][APP]['installed']
    assert installed['status'] == 'skipped' and 'not a regular file' in installed['reason']
    assert not [argv for argv, _ in server.commands if argv[0] == 'head' and argv[-1].endswith('installed.json')]


def test_collect_without_sudo_says_so_and_what_it_could_not_read(data):
    server = FakeServer(_tree(owner='deploy', env_owner='root', env_mode=0o640), sudo='refused')
    raw = laravel_server.collect(server)
    assert raw['sudo'] is False and 'password' in raw['sudo_note']
    assert raw['projects'][APP]['env_tokens']['status'] == 'denied'
    result = laravel_server.judge(raw, 'srv.test')
    assert result['collected_without_sudo'] is True
    assert _checked(result)['app_debug'] == 'not_checked'


def test_paths_from_the_server_reach_the_tools_as_one_argument(data):
    odd = "/var/www/it's $(touch x) a;b"
    server = FakeServer(_tree(odd, owner='deploy'))
    raw = laravel_server.collect(server)
    assert odd in raw['projects']
    assert any(argv[-1] == f'{odd}/.env' for argv, _ in server.commands if argv[0] == 'awk')


def test_collect_reads_a_version_file_up_to_the_limit(data, monkeypatch):
    monkeypatch.setattr(laravel_server, 'MAX_INVENTORY', 40)
    raw = laravel_server.collect(FakeServer(_tree(installed=INSTALLED_12)))
    assert raw['projects'][APP]['installed']['truncated'] is True


def test_only_the_current_release_is_read(data):
    files = {}
    for release in ('1', '2'):
        files.update(_tree(f'/home/forge/shop/releases/{release}', owner='forge'))
    files['/home/forge/shop/current'] = {'type': 'l', 'mode': 0o777, 'owner': 'forge', 'target': 'releases/2'}
    raw = laravel_server.collect(FakeServer(files))
    assert list(raw['projects']) == ['/home/forge/shop/releases/2']
    assert raw['skipped']['old_releases'] == 1


def test_the_limit_counts_laravel_projects_only(data, monkeypatch):
    # review #63 pass 1 (P2): folders that are not Laravel do not use up the limit
    monkeypatch.setattr(laravel_server, 'MAX_PROJECTS', 2)
    files = {}
    for name in ('a', 'b', 'c'):
        files.update(_tree(f'/var/www/{name}'))
    files.update(_tree('/var/www/0-tool'))
    files['/var/www/0-tool/composer.json']['text'] = json.dumps({'require': {'symfony/console': '^7'}})
    raw = laravel_server.collect(FakeServer(files))
    assert sorted(raw['projects']) == ['/var/www/0-tool', '/var/www/a', '/var/www/b']
    assert raw['skipped']['over_limit'] == 1


def test_a_search_with_permission_errors_is_partial(data):
    files = _tree()
    files['/home/other'] = {'type': 'd', 'mode': 0o700, 'owner': 'other', 'group': 'other'}
    raw = laravel_server.collect(FakeServer(files, sudo='refused'))
    assert 'Permission denied' in raw['discovery']['partial']


def test_missing_roots_are_not_errors(data):
    server = FakeServer(_tree())
    original = server._find

    def find(argv, account):
        out, err, rc = original(argv, account)
        if 'artisan' in argv:
            err += "find: '/srv': No such file or directory\n"
            rc = 1
        return out, err, rc

    server._find = find
    raw = laravel_server.collect(server)
    assert raw['discovery']['partial'] is None and raw['discovery']['failed'] is None


def test_the_whole_audit_over_a_fake_server(data):
    files = _tree(owner='deploy', env_text='APP_ENV=local\nAPP_DEBUG=true\n', env_mode=0o644)
    files[f'{APP}/storage']['mode'] = 0o777
    result = laravel_server.audit_laravel_server(FakeServer(files), 'srv.test')
    ids = set(_ids(result))
    assert {subject_id('LV-SRV-001', APP, '.env'), subject_id('LV-SRV-002', APP), subject_id('LV-SRV-003', APP),
            subject_id('LV-SRV-004', APP, 'storage')} <= ids
    assert result['verdict'] == 'danger'
    assert result['host'] == 'srv.test'


# --- review #63 pass 2: an unconfirmed object, a group's real members, a failed listing ------------------

def test_a_root_read_needs_the_file_confirmed_as_a_regular_file(data):
    files = _tree(owner='root')
    files[f'{APP}/composer.json']['stat_error_P'] = 'Input/output error'      # find -P could not stat it
    server = FakeServer(files)
    raw = laravel_server.collect(server)
    composer = raw['projects'][APP]['composer_json']
    assert composer['status'] == 'skipped' and 'Input/output error' in composer['reason']
    assert not [argv for argv, _ in server.commands if argv[0] == 'head' and argv[-1].endswith('composer.json')]


def test_a_group_writable_folder_is_trusted_only_with_its_members_known(data):
    config = {f'{APP}/bootstrap/cache/config.php': {'type': 'f', 'mode': 0o640, 'owner': 'shop', 'group': 'shop',
                                                    'text': CACHED}}
    # the group is named like the owner, but has another member
    raw = laravel_server.collect(FakeServer(_tree(owner='shop', cache_group='shop', extra=config),
                                            groups={'shop': {'mallory'}}))
    tokens = raw['projects'][APP]['config_tokens']
    assert tokens['status'] == 'skipped'
    assert 'bootstrap/cache' in tokens['reason'] and 'mallory' in tokens['reason']
    # the same tree, its group holding the owner alone: read
    raw = laravel_server.collect(FakeServer(_tree(owner='shop', cache_group='shop', extra=config)))
    assert raw['projects'][APP]['config_tokens']['status'] == 'ok'


def test_group_root_with_another_member_is_not_trusted_for_a_root_read(data):
    config = {f'{APP}/bootstrap/cache/config.php': {'type': 'f', 'mode': 0o640, 'owner': 'root', 'group': 'root',
                                                    'text': CACHED}}
    files = _tree(owner='root', cache_group='root', extra=config)
    raw = laravel_server.collect(FakeServer(files, groups={'root': {'operator'}}))
    assert raw['projects'][APP]['config_tokens']['status'] == 'skipped'
    raw = laravel_server.collect(FakeServer(files))
    assert raw['projects'][APP]['config_tokens']['status'] == 'ok'


def test_group_members_that_cannot_be_listed_are_not_trusted(data):
    config = {f'{APP}/bootstrap/cache/config.php': {'type': 'f', 'mode': 0o640, 'owner': 'shop', 'group': 'shop',
                                                    'text': CACHED}}
    server = FakeServer(_tree(owner='shop', cache_group='shop', extra=config), fail={'getent': (2, '')})
    tokens = laravel_server.collect(server)['projects'][APP]['config_tokens']
    assert tokens['status'] == 'skipped' and 'members' in tokens['reason']


@pytest.mark.parametrize('which', ['meta-L', 'meta-P'])
def test_a_failed_metadata_listing_is_not_a_missing_file(data, which):
    server = FakeServer(_tree(owner='shop'), fail={which: (126, 'find: cannot execute: Permission denied\n')})
    raw = laravel_server.collect(server)
    composer = raw['projects'][APP]['composer_json']
    assert composer['status'] == 'skipped'
    assert 'cannot execute' in composer['reason']
    assert not [argv for argv, _ in server.commands if argv[0] == 'head']
    result = laravel_server.judge(raw, 'srv.test')
    assert result['verdict'] == 'incomplete'


def test_a_confirmed_missing_file_is_missing(data):
    raw = laravel_server.collect(FakeServer(_tree(owner='shop')))
    assert raw['projects'][APP]['lock']['status'] == 'missing'          # find said: No such file or directory
    assert raw['projects'][APP]['config_tokens'] is None


# --- a server whose locale is not C: the tools' messages are read in the C locale -------------------------

def test_every_tool_runs_in_the_c_locale(data):
    server = FakeServer(_tree(owner='shop'))
    laravel_server.collect(server)
    tools = [(argv[0], env) for (argv, _), env in zip(server.commands, server.envs) if argv[0] != 'getent']
    assert tools and all(env.get('LC_ALL') == 'C' for _, env in tools), tools


def test_a_missing_file_is_missing_on_a_utf8_server(data):
    raw = laravel_server.collect(FakeServer(_tree(owner='shop'), locale='utf8'))
    assert raw['projects'][APP]['lock']['status'] == 'missing'
    assert raw['discovery']['partial'] is None and raw['discovery']['failed'] is None
