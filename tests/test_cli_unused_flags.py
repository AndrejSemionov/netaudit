"""
`run` refuses a flag that no selected check takes
(docs/research/cli_unused_flags.md): before, it was dropped without a word,
so `run ports --host X` audited this computer and `run dns_audit --url U`
audited example.com.
"""

from __future__ import annotations

import json
import logging
from argparse import Namespace

import pytest

import netaudit


def _ns(checks, rest, quick=False, notify=False):
    return Namespace(checks=checks, ai=False, quick=quick, rest=rest, notify=notify)


@pytest.fixture
def ran(monkeypatch, isolated_db):
    """What reached the engine; nothing is executed."""
    calls = []

    def report():
        return {'timestamp': '2026-10-18 12:00:00', 'results': {}, 'timing': {}, 'meta': {},
                'execution_context': {}, 'total_time': 0}

    monkeypatch.setattr(netaudit, 'run_checks', lambda selected: calls.append(selected) or report())
    monkeypatch.setattr(netaudit, 'run_checks_multi', lambda selected, **kw: calls.append(selected) or report())
    return calls


def _refused(ns, caplog, capsys, *needles):
    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as exc:
        netaudit.cmd_run(ns)
    assert exc.value.code not in (0, None)
    out = capsys.readouterr()
    text = caplog.text + out.out + out.err
    for needle in needles:
        assert needle in text, f'{needle!r} not in {text!r}'
    return text


# --- refused -----------------------------------------------------------------

def test_host_for_checks_that_audit_this_computer_is_refused(ran, caplog, capsys):
    text = _refused(_ns(['ports', 'firewall'], ['--host', '192.0.2.10']), caplog, capsys,
                    '--host', 'ports', 'firewall', 'this computer')
    assert ran == []
    assert '192.0.2.10' not in text


def test_url_for_dns_audit_is_refused(ran, caplog, capsys):
    _refused(_ns(['dns_audit'], ['--url', 'https://site.example']), caplog, capsys, '--url', 'dns_audit')
    assert ran == []


def test_a_typo_is_refused_and_its_value_never_echoed(ran, caplog, capsys):
    text = _refused(_ns(['ssh_hardening'], ['--hots', 'VALUE-NOT-ECHOED']), caplog, capsys, '--hots')
    assert 'VALUE-NOT-ECHOED' not in text
    assert ran == []


def test_several_unused_flags_are_named_in_one_message(ran, caplog, capsys):
    text = _refused(_ns(['ssl'], ['--url', 'https://site.example', '--zeta', '1', '--alpha', '2']),
                    caplog, capsys, '--alpha', '--zeta')
    assert text.index('--alpha') < text.index('--zeta')


def test_refusal_comes_before_any_password_prompt(ran, caplog, capsys, monkeypatch):
    monkeypatch.setattr(netaudit.getpass, 'getpass', lambda prompt: pytest.fail('asked for a password'))
    _refused(_ns(['ports'], ['--host', '192.0.2.10', '--password', '-']), caplog, capsys, '--host', '--password')


def test_quick_with_both_url_and_host_is_refused(ran, caplog, capsys):
    _refused(_ns([], ['--url', 'https://site.example', '--host', '192.0.2.10'], quick=True),
             caplog, capsys, '--host')
    assert ran == []


def test_group_run_refuses_an_unused_flag(ran, caplog, capsys, tmp_path):
    hosts = tmp_path / 'hosts.json'
    hosts.write_text(json.dumps([{'host': '10.0.0.5'}]), encoding='utf-8')
    _refused(_ns(['ssh_hardening'], ['--hosts-file', str(hosts), '--url', 'https://site.example']),
             caplog, capsys, '--url', 'ssh_hardening')
    assert ran == []


# --- unchanged ---------------------------------------------------------------

def test_a_mixed_run_where_every_flag_is_taken_still_works(ran):
    netaudit.cmd_run(_ns(['ssl', 'ssh_hardening'], ['--url', 'https://site.example', '--host', '10.0.0.5',
                                                    '--user', 'audit']))
    [selection] = ran
    params = {item['id']: item['params'] for item in selection}
    assert params['ssl'] == {'url': 'https://site.example'}
    assert params['ssh_hardening']['host'] == '10.0.0.5' and params['ssh_hardening']['user'] == 'audit'


def test_quick_bundles_with_their_own_flags_still_work(ran):
    netaudit.cmd_run(_ns([], ['--url', 'https://site.example', '--domain', 'site.example'], quick=True))
    netaudit.cmd_run(_ns([], ['--host', '10.0.0.5', '--user', 'audit', '--key_path', '/k'], quick=True))
    assert [len(selection) for selection in ran] == [4, 4]


def test_the_runs_own_flags_are_not_reported_as_unused(ran, tmp_path, monkeypatch):
    from netaudit_pkg import notify, storage
    storage.setting_set('telegram_token', 'T'); storage.setting_set('telegram_chat', '1')
    monkeypatch.setattr(notify, 'send_telegram', lambda *a, **k: None)
    netaudit.cmd_run(_ns(['ssh_hardening'], ['--host', '10.0.0.5', '--job', 'daily',
                                             '--notify-min-severity', 'high'], notify=True))
    hosts = tmp_path / 'hosts.json'
    hosts.write_text(json.dumps([{'host': '10.0.0.5'}]), encoding='utf-8')
    netaudit.cmd_run(_ns(['ssh_hardening'], ['--hosts-file', str(hosts), '--max-parallel', '2']))
    assert len(ran) == 2


# --- review #46 pass 1: a --name=value flag never echoes its value -----------

SECRET = 'VALUE-NEVER-ECHOED'


@pytest.mark.parametrize('rest', [
    [f'--password={SECRET}'],
    [f'--sudo_password={SECRET}'],
    [f'--hots={SECRET}'],
    [f'--password={SECRET}', '--host', '10.0.0.5'],
], ids=['password', 'sudo_password', 'unknown', 'before-another-flag'])
def test_single_run_never_echoes_an_equals_value(ran, caplog, capsys, rest, monkeypatch):
    monkeypatch.setattr(netaudit.getpass, 'getpass', lambda prompt: pytest.fail('asked for a password'))
    text = _refused(_ns(['ports'], rest), caplog, capsys, '--' + rest[0][2:].split('=')[0])
    assert SECRET not in text
    assert ran == []


@pytest.mark.parametrize('rest', [
    [f'--password={SECRET}'],
    [f'--hots={SECRET}', f'--hots={SECRET}'],
], ids=['unused', 'repeated'])
def test_group_run_never_echoes_an_equals_value(ran, caplog, capsys, rest, tmp_path, monkeypatch):
    monkeypatch.setattr(netaudit.getpass, 'getpass', lambda prompt: pytest.fail('asked for a password'))
    hosts = tmp_path / 'hosts.json'
    hosts.write_text(json.dumps([{'host': '10.0.0.5'}]), encoding='utf-8')
    text = _refused(_ns(['ssh_hardening'], ['--hosts-file', str(hosts), *rest]), caplog, capsys,
                    '--' + rest[0][2:].split('=')[0])
    assert SECRET not in text
    assert ran == []


def test_main_never_echoes_an_equals_password(ran, caplog, capsys, monkeypatch):
    import sys
    monkeypatch.setattr(sys, 'argv', ['netaudit.py', 'run', 'ports', f'--password={SECRET}'])
    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit):
        netaudit.main()
    out = capsys.readouterr()
    assert SECRET not in caplog.text + out.out + out.err
    assert '--password' in caplog.text
