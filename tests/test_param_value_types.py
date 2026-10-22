"""
A checkbox, number or select value is checked against its type before a check
runs (docs/research/param_value_types.md). Before, the CLI passed the typed
text on: `--auto_install false` was the true string 'false', and
`--lines '5; id'` reached `journalctl -n` as a second command.
"""

from __future__ import annotations

import importlib
import json
import logging
from argparse import Namespace

import pytest

import netaudit
from netaudit_pkg import engine
from netaudit_pkg.registry import CheckSpec, registry

SENTINEL = 'VALUE-NOT-ECHOED-7f3a'


def _param_value(param, value):
    return importlib.import_module('netaudit_pkg.registry').param_value(param, value)


CHECKBOX = {'name': 'flag', 'type': 'checkbox', 'default': False}
NUMBER = {'name': 'lines', 'type': 'number', 'default': 200}
SELECT = {'name': 'choice', 'type': 'select', 'options': ['a', 'b'], 'default': 'a', 'aliases': {'x': 'a'}}


# --- param_value() -----------------------------------------------------------

@pytest.mark.parametrize('value, expected', [
    ('true', True), ('TRUE', True), (' yes ', True), ('On', True), ('1', True),
    ('false', False), ('No', False), ('OFF', False), ('0', False), (' False ', False),
    (True, True), (False, False), (1, True), (0, False),
])
def test_checkbox_accepted(value, expected):
    assert _param_value(CHECKBOX, value) is expected


@pytest.mark.parametrize('value', ['', 'maybe', 'y', 2, None, 1.0, SENTINEL])
def test_checkbox_refused(value):
    with pytest.raises(ValueError) as exc:
        _param_value(CHECKBOX, value)
    assert 'true or false' in str(exc.value)
    assert SENTINEL not in str(exc.value)


@pytest.mark.parametrize('value, expected, kind', [
    (5, 5, int), ('5', 5, int), (' 5 ', 5, int), ('2.5', 2.5, float), ('1e3', 1000, int),
    (5.0, 5, int), (-3, -3, int), ('-3', -3, int), (2.5, 2.5, float),
])
def test_number_accepted(value, expected, kind):
    result = _param_value(NUMBER, value)
    assert result == expected
    assert type(result) is kind


@pytest.mark.parametrize('value', ['5; id', 'abc', '', 'nan', 'inf', True, None,
                                   float('nan'), float('inf'), SENTINEL])
def test_number_refused(value):
    with pytest.raises(ValueError) as exc:
        _param_value(NUMBER, value)
    assert 'a number' in str(exc.value)
    assert SENTINEL not in str(exc.value)


def test_select_accepts_an_option_and_an_alias():
    assert _param_value(SELECT, 'a') == 'a'
    assert _param_value(SELECT, 'b') == 'b'
    assert _param_value(SELECT, 'x') == 'a'


@pytest.mark.parametrize('value', ['A', 'c', '', None, 1, SENTINEL])
def test_select_refused(value):
    with pytest.raises(ValueError) as exc:
        _param_value(SELECT, value)
    assert '"a"' in str(exc.value) and '"b"' in str(exc.value)
    assert SENTINEL not in str(exc.value)


def test_select_without_options_and_other_types_are_unchanged():
    assert _param_value({'name': 's', 'type': 'select'}, 'anything') == 'anything'
    assert _param_value({'name': 't', 'type': 'text'}, '5; id') == '5; id'
    assert _param_value({'name': 'password', 'type': 'password'}, '-') == '-'


# --- the registry fits param_value() ------------------------------------------

def _all_params():
    return [(c['id'], p) for c in engine.list_available() for p in c['params']]


def test_registry_defaults_and_choices_fit_their_types():
    for check_id, p in _all_params():
        where = f'{check_id}.{p["name"]}'
        if p['type'] == 'checkbox':
            assert type(p['default']) is bool, where
        elif p['type'] == 'number':
            assert type(p['default']) in (int, float), where
        elif p['type'] == 'select':
            assert p.get('options'), where
            assert p['default'] in p['options'], where
            for alias, option in p.get('aliases', {}).items():
                assert option in p['options'], f'{where}: alias {alias!r}'
                assert alias not in p['options'], f'{where}: alias {alias!r}'


def test_aide_mode_keeps_the_documented_check_and_init():
    [mode] = [p for p in registry.get('aide_check').params if p['name'] == 'mode']
    assert _param_value(mode, 'init') == 'reinitialize the database'
    assert _param_value(mode, 'check') == 'check for changes'


# --- engine.typed_params() -----------------------------------------------------

def _typed_params(selected):
    return importlib.import_module('netaudit_pkg.engine').typed_params(selected)


def test_typed_params_converts_params_and_instances():
    selected = [
        {'id': 'rootkit_check', 'params': {'host': 'h', 'auto_install': 'false', 'port': '2222'}},
        {'id': 'docker_audit', 'instances': [{'host': 'a', 'include_stopped': 'yes'},
                                             {'host': 'b', 'include_stopped': False}]},
        {'id': '__no_such_check__', 'params': {'x': 'false'}},
    ]
    out = _typed_params(selected)
    assert out[0]['params'] == {'host': 'h', 'auto_install': False, 'port': 2222}
    assert [i['include_stopped'] for i in out[1]['instances']] == [True, False]
    assert out[2] == {'id': '__no_such_check__', 'params': {'x': 'false'}}
    assert selected[0]['params']['auto_install'] == 'false'  # the request is not changed in place


def test_typed_params_names_the_check_and_the_parameter():
    with pytest.raises(ValueError) as exc:
        _typed_params([{'id': 'ssh_auth_audit', 'params': {'host': 'h', 'lines': '5; id'}}])
    assert str(exc.value).startswith('ssh_auth_audit: lines takes a number')
    assert '5; id' not in str(exc.value)


# --- CLI ----------------------------------------------------------------------

def _ns(checks, rest, quick=False):
    return Namespace(checks=checks, ai=False, quick=quick, rest=rest, notify=False)


@pytest.fixture
def ran(monkeypatch, isolated_db):
    """What reached the engine; nothing is executed."""
    calls = []

    def report():
        return {'timestamp': '2026-10-22 12:00:00', 'results': {}, 'timing': {}, 'meta': {},
                'execution_context': {}, 'total_time': 0}

    monkeypatch.setattr(netaudit, 'run_checks', lambda selected: calls.append(selected) or report())
    monkeypatch.setattr(netaudit, 'run_checks_multi', lambda selected, **kw: calls.append(selected) or report())
    return calls


@pytest.fixture
def prompts(monkeypatch):
    asked = []
    monkeypatch.setattr(netaudit.getpass, 'getpass', lambda prompt: asked.append(prompt) or 'PW')
    return asked


def _params(ran, check_id):
    [selected] = ran
    [item] = [i for i in selected if i['id'] == check_id]
    return item['params']


def _refused(ns, caplog, capsys, *needles):
    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as exc:
        netaudit.cmd_run(ns)
    assert exc.value.code not in (0, None)
    out = capsys.readouterr()
    text = caplog.text + out.out + out.err
    for needle in needles:
        assert needle in text, f'{needle!r} not in {text!r}'
    return text


def test_cli_checkbox_words_reach_the_check_as_bools(ran):
    netaudit.cmd_run(_ns(['rootkit_check'], ['--host', '192.0.2.10', '--auto_install', 'false',
                                             '--use_rkhunter', 'no', '--use_chkrootkit', 'Yes']))
    params = _params(ran, 'rootkit_check')
    assert params['auto_install'] is False
    assert params['use_rkhunter'] is False
    assert params['use_chkrootkit'] is True


def test_cli_number_and_select_reach_the_check_converted(ran):
    netaudit.cmd_run(_ns(['mtr', 'aide_check', 'ssh_auth_audit'],
                         ['--target', '192.0.2.1', '--duration_sec', '2.5', '--host', '192.0.2.10',
                          '--mode', 'init', '--lines', '50']))
    assert _params(ran, 'mtr')['duration_sec'] == 2.5
    assert _params(ran, 'aide_check')['mode'] == 'reinitialize the database'
    assert _params(ran, 'ssh_auth_audit')['lines'] == 50


def test_cli_wrong_checkbox_is_refused_without_echo(ran, caplog, capsys):
    text = _refused(_ns(['rootkit_check'], ['--host', '192.0.2.10', '--auto_install', SENTINEL]),
                    caplog, capsys, '--auto_install', 'rootkit_check', 'true or false')
    assert SENTINEL not in text
    assert ran == []


def test_cli_checkbox_given_last_without_a_value_is_refused(ran, caplog, capsys):
    _refused(_ns(['docker_audit'], ['--host', '192.0.2.10', '--include_stopped']),
             caplog, capsys, '--include_stopped', 'true or false')
    assert ran == []


def test_cli_number_with_a_command_is_refused(ran, caplog, capsys):
    text = _refused(_ns(['ssh_auth_audit'], ['--host', '192.0.2.10', '--lines', '5; id']),
                    caplog, capsys, '--lines', 'ssh_auth_audit', 'a number')
    assert '5; id' not in text
    assert ran == []


def test_cli_select_outside_its_choices_is_refused(ran, caplog, capsys):
    _refused(_ns(['mikrotik_sniffer'], ['--target_ip', '192.168.88.20', '--analyze_threats', 'no']),
             caplog, capsys, '--analyze_threats', 'mikrotik_sniffer', '"нет"')
    assert ran == []


def test_cli_names_every_wrong_value_in_one_message(ran, caplog, capsys):
    text = _refused(_ns(['rootkit_check', 'ssh_auth_audit'],
                        ['--host', '192.0.2.10', '--auto_install', 'maybe', '--lines', 'many']),
                    caplog, capsys, '--auto_install (rootkit_check)', '--lines (ssh_auth_audit)')
    assert 'maybe' not in text and 'many' not in text
    assert ran == []


def test_cli_same_flag_is_checked_for_each_check(ran, caplog, capsys):
    text = _refused(_ns(['aide_check', 'sql_injection'],
                        ['--host', '192.0.2.10', '--url', 'https://site.example', '--mode', 'init']),
                    caplog, capsys, '--mode (sql_injection)')
    assert '--mode (aide_check)' not in text
    assert ran == []


def test_cli_wrong_value_of_the_last_check_is_refused_before_the_password_prompt(ran, prompts, caplog, capsys):
    _refused(_ns(['ssh_hardening', 'rootkit_check'],
                 ['--host', '192.0.2.10', '--password', '-', '--auto_install', 'maybe']),
             caplog, capsys, '--auto_install')
    assert prompts == []
    assert ran == []


def _hosts_file(tmp_path):
    path = tmp_path / 'hosts.json'
    path.write_text(json.dumps([{'host': '192.0.2.10'}, {'host': '192.0.2.11'}]), encoding='utf-8')
    return str(path)


def test_cli_group_run_converts_for_every_instance(ran, tmp_path):
    netaudit.cmd_run(_ns(['rootkit_check'], ['--hosts-file', _hosts_file(tmp_path), '--auto_install', 'false']))
    [selected] = ran
    assert [i['auto_install'] for i in selected[0]['instances']] == [False, False]


def test_cli_group_run_refuses_a_wrong_value_before_the_prompt(ran, prompts, tmp_path, caplog, capsys):
    text = _refused(_ns(['rootkit_check'], ['--hosts-file', _hosts_file(tmp_path), '--password', '-',
                                            '--use_rkhunter', SENTINEL]),
                    caplog, capsys, '--use_rkhunter (rootkit_check)')
    assert SENTINEL not in text
    assert prompts == []
    assert ran == []


def test_cli_run_without_typed_flags_is_unchanged(ran):
    netaudit.cmd_run(_ns(['rootkit_check'], ['--host', '192.0.2.10', '--port', '2222']))
    assert _params(ran, 'rootkit_check') == {'host': '192.0.2.10', 'port': 2222}


def test_cli_list_prints_the_choices_of_a_select(capsys):
    netaudit.cmd_list(Namespace())
    out = capsys.readouterr().out
    assert '--mode (select: check for changes | reinitialize the database, default=check for changes)' in out


# --- Web API ------------------------------------------------------------------

@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from web.app import app
    return TestClient(app)


@pytest.fixture
def typed_check(monkeypatch, isolated_db):
    """A throwaway check with typed params. Runs are synchronous, and no
    background stream or task is started: nothing can write after the
    temporary database is gone."""
    from netaudit_pkg import streaming
    from web import app as web_app

    isolated_db.setting_set('sync_threshold_sec', '100')
    monkeypatch.setattr(streaming, 'run_stream', lambda task: None)
    monkeypatch.setattr(web_app, '_execute_task', lambda *args, **kwargs: None)
    calls = []
    check_id = '__test_typed_params__'

    def func(host='', flag=False, lines=200, choice='a'):
        calls.append({'host': host, 'flag': flag, 'lines': lines, 'choice': choice})
        return {'ok': True}

    registry.register(CheckSpec(
        id=check_id, label='Test typed params', category='test', func=func,
        params=[{'name': 'host', 'type': 'text', 'label': 'Host', 'default': ''},
                {**CHECKBOX, 'label': 'Flag'}, {**NUMBER, 'label': 'Lines'},
                {'name': 'choice', 'type': 'select', 'label': 'Choice', 'options': ['a', 'b'], 'default': 'a'}],
    ))
    yield check_id, calls
    registry._checks.pop(check_id, None)


@pytest.mark.parametrize('endpoint', ['/api/run', '/api/estimate', '/api/stream/start'])
@pytest.mark.parametrize('params, needle', [
    ({'flag': SENTINEL}, 'flag takes true or false'),
    ({'lines': '5; id ' + SENTINEL}, 'lines takes a number'),
    ({'choice': SENTINEL}, 'choice takes one of'),
])
def test_api_refuses_a_wrong_value(client, typed_check, isolated_db, endpoint, params, needle):
    check_id, calls = typed_check
    resp = client.post(endpoint, json={'checks': [{'id': check_id, 'params': {'host': 'h', **params}}]})
    assert resp.status_code == 400
    assert needle in resp.text
    assert check_id in resp.text
    assert SENTINEL not in resp.text
    assert calls == []
    assert isolated_db.list_reports() == []


def test_api_refuses_a_wrong_value_in_instances(client, typed_check, isolated_db):
    check_id, calls = typed_check
    resp = client.post('/api/run', json={'checks': [{'id': check_id, 'instances': [
        {'host': 'a', 'flag': 'true'}, {'host': 'b', 'flag': 'maybe'}]}]})
    assert resp.status_code == 400
    assert calls == []


def test_api_converts_text_values(client, typed_check, isolated_db):
    check_id, calls = typed_check
    resp = client.post('/api/run', json={'checks': [{'id': check_id, 'params': {
        'host': 'h', 'flag': 'false', 'lines': '50', 'choice': 'b'}}]})
    assert resp.status_code == 200
    assert calls == [{'host': 'h', 'flag': False, 'lines': 50, 'choice': 'b'}]


def test_api_converts_text_values_in_instances(client, typed_check, isolated_db):
    check_id, calls = typed_check
    resp = client.post('/api/run', json={'checks': [{'id': check_id, 'instances': [
        {'host': 'a', 'flag': 'false'}, {'host': 'b', 'flag': 'yes'}]}]})
    assert resp.status_code == 200
    assert sorted((c['host'], c['flag']) for c in calls) == [('a', False), ('b', True)]


def test_api_values_of_the_web_form_are_unchanged(client, typed_check, isolated_db):
    check_id, calls = typed_check
    resp = client.post('/api/run', json={'checks': [{'id': check_id, 'params': {
        'host': 'h', 'flag': True, 'lines': 200, 'choice': 'a'}}]})
    assert resp.status_code == 200
    assert calls == [{'host': 'h', 'flag': True, 'lines': 200, 'choice': 'a'}]


def test_stream_start_runs_with_converted_values(client, typed_check, isolated_db):
    from web.app import _stream_tasks

    check_id, _ = typed_check
    resp = client.post('/api/stream/start', json={'checks': [{'id': check_id, 'params': {
        'host': 'h', 'flag': 'no', 'lines': '7'}}]})
    assert resp.status_code == 200
    task = _stream_tasks[resp.json()['task_id']]
    assert task.selected[0]['params'] == {'host': 'h', 'flag': False, 'lines': 7}


# --- collect_journal() --------------------------------------------------------

class _FakeSSH:
    def __init__(self):
        self.commands = []

    def run(self, cmd, timeout=20):
        self.commands.append(cmd)
        return '', ''


def test_collect_journal_quotes_the_line_count():
    from netaudit_pkg import log_collection

    ssh = _FakeSSH()
    log_collection.collect_journal(ssh, 'ssh', lines='5; id')
    [cmd] = ssh.commands
    assert "journalctl -u ssh -n '5; id' --no-pager" in cmd


def test_collect_journal_command_is_unchanged_for_a_number():
    from netaudit_pkg import log_collection

    ssh = _FakeSSH()
    log_collection.collect_journal(ssh, 'ssh', lines=200)
    [cmd] = ssh.commands
    assert 'journalctl -u ssh -n 200 --no-pager;' in cmd


# --- a number beyond the float range (review #49 R1) --------------------------

HUGE = 10 ** 310  # an int that float() cannot hold


@pytest.mark.parametrize('value', [HUGE, -HUGE, '1' * 311, '1' * 5000],
                         ids=['int', 'negative-int', 'text-311-digits', 'text-5000-digits'])
def test_number_beyond_the_float_range_is_refused(value):
    with pytest.raises(ValueError) as exc:
        _param_value(NUMBER, value)
    assert str(exc.value) == 'takes a number'


def test_large_number_within_the_float_range_is_kept():
    assert _param_value(NUMBER, 10 ** 300) == 10 ** 300
    assert _param_value(NUMBER, '1' * 300) == int('1' * 300)


def test_cli_number_beyond_the_float_range_is_refused(ran, caplog, capsys):
    text = _refused(_ns(['ssh_auth_audit'], ['--host', '192.0.2.10', '--lines', '1' * 311]),
                    caplog, capsys, '--lines (ssh_auth_audit) takes a number')
    assert '1' * 311 not in text
    assert ran == []


@pytest.mark.parametrize('endpoint', ['/api/run', '/api/estimate', '/api/stream/start'])
def test_api_number_beyond_the_float_range_is_400(client, typed_check, isolated_db, endpoint):
    check_id, calls = typed_check
    resp = client.post(endpoint, json={'checks': [{'id': check_id, 'params': {'host': 'h', 'lines': HUGE}}]})
    assert resp.status_code == 400
    assert 'lines takes a number' in resp.text
    assert calls == []


def test_trends_read_a_saved_number_beyond_the_float_range():
    """A CLI report saved before this check could hold such a number
    (`--lines` with 311 digits became an int): trends must not crash on it."""
    from netaudit_pkg import trends

    assert trends._setting('number', HUGE) == str(HUGE)
