"""
B2.2 - `netaudit run <checks> --hosts-file <json>` (docs/research/b2_2_cli_hosts_file.md,
on the approved B1 contract §3.1): one instance per host record, no secrets in
the file or on the command line, ambiguity and bad input refused before
anything runs. The single-host form keeps working as before.
"""

from __future__ import annotations

import json
import logging
from argparse import Namespace

import pytest

import netaudit
from netaudit_pkg import storage
from netaudit_pkg.registry import registry


def _ns(checks, rest, quick=False):
    return Namespace(checks=checks, ai=False, quick=quick, rest=rest)


def _hosts_file(tmp_path, records):
    path = tmp_path / 'hosts.json'
    path.write_text(records if isinstance(records, str) else json.dumps(records), encoding='utf-8')
    return str(path)


@pytest.fixture
def engine_calls(monkeypatch, isolated_db):
    """Captures what cmd_run hands to the engine; nothing is executed."""
    calls = {'multi': [], 'single': []}

    def report():
        return {'timestamp': '2026-10-11 12:00:00', 'results': {}, 'timing': {}, 'meta': {},
                'execution_context': {}, 'total_time': 0}

    def fake_multi(selected, **kwargs):
        calls['multi'].append(selected)
        return report()

    def fake_single(selected):
        calls['single'].append(selected)
        return report()

    monkeypatch.setattr(netaudit, 'run_checks_multi', fake_multi, raising=False)
    monkeypatch.setattr(netaudit, 'run_checks', fake_single)
    return calls


def _refused(capsys, caplog, ns, *needles):
    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as exc:
        netaudit.cmd_run(ns)
    assert exc.value.code != 0
    text = caplog.text + capsys.readouterr().err
    for needle in needles:
        assert needle in text, f'{needle!r} not in {text!r}'
    return text


# --- the group form ----------------------------------------------------------

def test_one_instance_per_host_with_common_flags_and_record_overrides(tmp_path, engine_calls, monkeypatch):
    prompts = []
    monkeypatch.setattr(netaudit.getpass, 'getpass', lambda prompt: prompts.append(prompt) or 'PW-FROM-PROMPT')
    hosts = _hosts_file(tmp_path, [{'host': '10.0.0.5'},
                                   {'host': 'web-2.example', 'user': 'audit', 'port': 2222}])

    netaudit.cmd_run(_ns(['ssh_hardening', 'kernel_hardening'],
                         ['--hosts-file', hosts, '--user', 'deploy', '--password', '-']))

    [selected] = engine_calls['multi']
    assert engine_calls['single'] == []
    assert [item['id'] for item in selected] == ['ssh_hardening', 'kernel_hardening']
    for item in selected:
        first, second = item['instances']
        assert (first['host'], first['user'], first['password']) == ('10.0.0.5', 'deploy', 'PW-FROM-PROMPT')
        assert (second['host'], second['user'], second['port']) == ('web-2.example', 'audit', 2222)
        assert isinstance(second['port'], int)
        assert second['password'] == 'PW-FROM-PROMPT'
    assert len(prompts) == 1  # asked once per parameter name for the whole run


@pytest.mark.parametrize('record, needle', [
    ({'host': 'h1', 'password': 'x'}, 'secret'),
    ({'host': 'h1', 'sudo_password': 'x'}, 'secret'),
    ({'host': 'h1', 'usr': 'root'}, 'usr'),
])
def test_secret_or_unknown_field_in_a_record_is_refused(tmp_path, engine_calls, capsys, caplog, record, needle):
    hosts = _hosts_file(tmp_path, [record])
    text = _refused(capsys, caplog, _ns(['ssh_hardening'], ['--hosts-file', hosts]), needle)
    assert "'x'" not in text  # the secret value itself is never echoed
    assert engine_calls['multi'] == []


@pytest.mark.parametrize('records', [
    [{'host': 'WEB-1'}, {'host': 'web-1'}],
    [{'host': '10.0.0.5', 'port': 22}, {'host': '10.0.0.5', 'port': 2222}],
    [{'host': '2001:db8::1'}, {'host': '2001:DB8:0:0::1'}],
])
def test_duplicate_host_is_refused(tmp_path, engine_calls, capsys, caplog, records):
    hosts = _hosts_file(tmp_path, records)
    _refused(capsys, caplog, _ns(['ssh_hardening'], ['--hosts-file', hosts]), 'more than once')
    assert engine_calls['multi'] == []


def test_host_flag_with_hosts_file_is_refused(tmp_path, engine_calls, capsys, caplog):
    hosts = _hosts_file(tmp_path, [{'host': 'h1'}])
    _refused(capsys, caplog, _ns(['ssh_hardening'], ['--hosts-file', hosts, '--host', 'h2']), '--host')
    assert engine_calls['multi'] == []


def test_quick_with_hosts_file_is_refused(tmp_path, engine_calls, capsys, caplog):
    hosts = _hosts_file(tmp_path, [{'host': 'h1'}])
    _refused(capsys, caplog, _ns([], ['--hosts-file', hosts], quick=True), '--quick', '--hosts-file')
    assert engine_calls['multi'] == []


def test_check_without_host_parameter_is_refused(tmp_path, engine_calls, capsys, caplog):
    hosts = _hosts_file(tmp_path, [{'host': 'h1'}])
    _refused(capsys, caplog, _ns(['ssh_hardening', 'ssl'], ['--hosts-file', hosts]), 'ssl')
    assert engine_calls['multi'] == []


def test_literal_password_on_the_command_line_is_refused_in_group_form(tmp_path, engine_calls, capsys, caplog):
    hosts = _hosts_file(tmp_path, [{'host': 'h1'}])
    text = _refused(capsys, caplog,
                    _ns(['ssh_hardening'], ['--hosts-file', hosts, '--password', 'LITERAL-SECRET']),
                    '--password -')
    assert 'LITERAL-SECRET' not in text
    assert engine_calls['multi'] == []


def test_unreadable_key_path_is_refused_by_path_only(tmp_path, engine_calls, capsys, caplog):
    missing = tmp_path / 'no_such_key'
    hosts = _hosts_file(tmp_path, [{'host': 'h1', 'key_path': str(missing)}])
    _refused(capsys, caplog, _ns(['ssh_hardening'], ['--hosts-file', hosts]), str(missing))
    assert engine_calls['multi'] == []


def test_readable_key_path_is_passed_expanded(tmp_path, engine_calls, monkeypatch):
    key = tmp_path / 'id_test'
    key.write_text('-----BEGIN OPENSSH PRIVATE KEY-----\nNOT-A-REAL-KEY\n', encoding='utf-8')
    monkeypatch.setenv('HOME', str(tmp_path))
    hosts = _hosts_file(tmp_path, [{'host': 'h1', 'key_path': '~/id_test'}])

    netaudit.cmd_run(_ns(['ssh_hardening'], ['--hosts-file', hosts]))

    [selected] = engine_calls['multi']
    assert selected[0]['instances'][0]['key_path'] == str(key)


@pytest.mark.parametrize('records', [
    [{'host': '-oProxyCommand=touch x'}],
    [{'host': 'two words'}],
    [{'host': ''}],
    [{'user': 'root'}],
    [{'host': 'h1', 'port': 0}],
    [{'host': 'h1', 'port': 70000}],
    [{'host': 'h1', 'port': '22'}],
    [{'host': 'h1', 'port': True}],
    [{'host': 'h1', 'user': 'root; id'}],
    [{'host': 'h1', 'key_path': ''}],
    'not json',
    '{"host": "h1"}',
    '[]',
    '["h1"]',
])
def test_bad_records_or_files_are_refused(tmp_path, engine_calls, capsys, caplog, records):
    hosts = _hosts_file(tmp_path, records)
    _refused(capsys, caplog, _ns(['ssh_hardening'], ['--hosts-file', hosts]), 'hosts file')
    assert engine_calls['multi'] == []


def test_missing_hosts_file_is_refused(tmp_path, engine_calls, capsys, caplog):
    _refused(capsys, caplog, _ns(['ssh_hardening'], ['--hosts-file', str(tmp_path / 'nope.json')]),
             'hosts file')


# --- repeated flags; the single-host form is unchanged ----------------------

def test_repeated_host_flag_is_refused_with_a_hint(engine_calls, capsys, caplog):
    _refused(capsys, caplog, _ns(['ssh_hardening'], ['--host', 'a', '--host', 'b']),
             'more than once', '--hosts-file')
    assert engine_calls['single'] == [] and engine_calls['multi'] == []


def test_any_repeated_parameter_is_refused_in_the_group_form(tmp_path, engine_calls, capsys, caplog):
    hosts = _hosts_file(tmp_path, [{'host': 'h1'}])
    _refused(capsys, caplog, _ns(['ssh_hardening'], ['--hosts-file', hosts, '--port', '22', '--port', '2222']),
             '--port', 'more than once')
    assert engine_calls['multi'] == []


def test_single_form_keeps_the_last_value_of_a_repeated_non_host_parameter(engine_calls):
    # review #35 pass 1: only a repeated --host is refused in the old form;
    # scripts that append an overriding flag keep working (last value wins)
    netaudit.cmd_run(_ns(['ssh_hardening'], ['--host', 'a', '--port', '22', '--port', '2222']))

    [selected] = engine_calls['single']
    assert selected == [{'id': 'ssh_hardening', 'params': {'host': 'a', 'port': 2222}}]


@pytest.mark.parametrize('value', ['LITERAL-UNUSED-SECRET', '-'])
def test_secret_flag_no_selected_check_uses_is_refused(tmp_path, engine_calls, capsys, caplog, monkeypatch, value):
    # review #35 pass 1: backup_check has `password` but no `sudo_password`
    asked = []
    monkeypatch.setattr(netaudit.getpass, 'getpass', lambda prompt: asked.append(prompt) or 'x')
    hosts = _hosts_file(tmp_path, [{'host': 'h1'}])
    text = _refused(capsys, caplog, _ns(['backup_check'], ['--hosts-file', hosts, '--sudo_password', value]),
                    '--sudo_password')
    assert 'LITERAL-UNUSED-SECRET' not in text
    assert asked == []
    assert engine_calls['multi'] == []


def test_single_host_form_still_uses_run_checks(engine_calls):
    netaudit.cmd_run(_ns(['ssh_hardening'], ['--host', 'a', '--port', '2222']))

    assert engine_calls['multi'] == []
    [selected] = engine_calls['single']
    assert selected == [{'id': 'ssh_hardening', 'params': {'host': 'a', 'port': 2222}}]


# --- end to end: real engine, stubbed check function ------------------------

def test_saved_group_report_holds_no_secret(tmp_path, isolated_db, monkeypatch):
    seen = []

    def fake_check(**params):
        seen.append(params)
        return {'findings': []}

    monkeypatch.setattr(registry.get('ssh_hardening'), 'func', fake_check)
    monkeypatch.setattr(netaudit.getpass, 'getpass', lambda prompt: 'E2E-SECRET-PW')
    hosts = _hosts_file(tmp_path, [{'host': 'h1'}, {'host': 'h2', 'user': 'audit'}])

    netaudit.cmd_run(_ns(['ssh_hardening'],
                         ['--hosts-file', hosts, '--password', '-', '--sudo_password', '-']))

    assert sorted(p['host'] for p in seen) == ['h1', 'h2']
    assert all(p['password'] == 'E2E-SECRET-PW' for p in seen)  # the check itself gets it
    [row] = storage._conn().execute('SELECT data FROM reports').fetchall()
    assert 'E2E-SECRET-PW' not in row[0]
    ctx = json.loads(row[0])['execution_context']['ssh_hardening']
    assert sorted(v['host'] for v in ctx.values()) == ['h1', 'h2']
