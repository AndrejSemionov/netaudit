"""
C2 CLI (docs/research/c1_schedule_notifications.md §3.3, §4.2-§4.3):
`run --notify` saves the report before sending and reports a failed delivery
through the exit code; `setup-timer` validates every value that goes into a
systemd unit instead of escaping it, and never installs anything.
"""

from __future__ import annotations

import json
import logging
import os
import pwd
import shutil
import subprocess
import sys
from argparse import Namespace

import pytest

import netaudit
from netaudit_pkg import notify, storage

TOKEN = '123456:FAKE-TOKEN-NEVER-LOGGED'


def _ns(checks, rest, notify_flag=True, quick=False):
    return Namespace(checks=checks, ai=False, quick=quick, rest=rest, notify=notify_flag)


@pytest.fixture
def telegram(isolated_db):
    storage.setting_set('telegram_token', TOKEN)
    storage.setting_set('telegram_chat', '-100')


@pytest.fixture
def sent(monkeypatch):
    """Messages handed to Telegram, and whether the report was saved by then."""
    calls = []

    def fake_send(text, token, chat_id, **kwargs):
        calls.append({'text': text, 'token': token, 'chat': chat_id,
                      'reports_saved': len(storage.list_reports(limit=10))})

    monkeypatch.setattr(notify, 'send_telegram', fake_send)
    return calls


def _engine(monkeypatch, result, check_id='ssh_hardening', host='10.0.0.5'):
    def fake_run(selected):
        return {'timestamp': '2026-10-17 03:00:00', 'results': {check_id: result}, 'timing': {},
                'meta': {}, 'execution_context': {check_id: {'host': host}}, 'total_time': 0}
    monkeypatch.setattr(netaudit, 'run_checks', fake_run)


# --- run --notify ------------------------------------------------------------

def test_notify_without_telegram_is_refused_before_anything_runs(isolated_db, monkeypatch, caplog):
    ran = []
    monkeypatch.setattr(netaudit, 'run_checks', lambda selected: ran.append(selected))
    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as exc:
        netaudit.cmd_run(_ns(['ssh_hardening'], ['--host', '10.0.0.5']))
    assert exc.value.code != 0 and ran == []
    assert 'Telegram' in caplog.text


@pytest.mark.parametrize('rest', [['--job', 'daily'], ['--notify-min-severity', 'high']])
def test_notify_options_without_notify_are_refused(isolated_db, monkeypatch, rest):
    monkeypatch.setattr(netaudit, 'run_checks', lambda selected: pytest.fail('ran'))
    with pytest.raises(SystemExit):
        netaudit.cmd_run(_ns(['ssh_hardening'], ['--host', '10.0.0.5', *rest], notify_flag=False))


@pytest.mark.parametrize('rest', [['--notify-min-severity', 'info'], ['--job', 'Daily Job'],
                                  ['--job', 'a%h'], ['--job', 'x' * 33]])
def test_bad_notify_options_are_refused(telegram, monkeypatch, rest):
    monkeypatch.setattr(netaudit, 'run_checks', lambda selected: pytest.fail('ran'))
    with pytest.raises(SystemExit):
        netaudit.cmd_run(_ns(['ssh_hardening'], ['--host', '10.0.0.5', *rest]))


def test_report_is_saved_before_the_message_is_sent(telegram, monkeypatch, sent):
    _engine(monkeypatch, {'error': 'could not connect: timed out'})
    netaudit.cmd_run(_ns(['ssh_hardening'], ['--host', '10.0.0.5', '--job', 'daily']))
    [call] = sent
    assert call['reports_saved'] == 1
    assert call['token'] == TOKEN and 'daily' in call['text'] and '10.0.0.5' in call['text']


def test_nothing_to_report_sends_nothing_and_exits_normally(telegram, monkeypatch, sent):
    _engine(monkeypatch, {'findings': []})
    netaudit.cmd_run(_ns(['ssh_hardening'], ['--host', '10.0.0.5', '--notify-min-severity', 'critical']))
    assert sent == []


def test_failed_delivery_exits_non_zero_and_keeps_the_report(telegram, monkeypatch, caplog):
    _engine(monkeypatch, {'error': 'could not connect: timed out'})

    def failing(text, token, chat_id, **kwargs):
        raise notify.NotifyError('Telegram: HTTP 500')

    monkeypatch.setattr(notify, 'send_telegram', failing)
    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as exc:
        netaudit.cmd_run(_ns(['ssh_hardening'], ['--host', '10.0.0.5']))
    assert exc.value.code not in (0, None)
    assert len(storage.list_reports(limit=10)) == 1
    assert 'HTTP 500' in caplog.text and TOKEN not in caplog.text


def test_without_notify_nothing_changes(isolated_db, monkeypatch, sent):
    _engine(monkeypatch, {'error': 'could not connect: timed out'})
    netaudit.cmd_run(_ns(['ssh_hardening'], ['--host', '10.0.0.5'], notify_flag=False))
    assert sent == []


def test_a_refused_run_sends_a_failure_message(telegram, sent, tmp_path):
    with pytest.raises(SystemExit) as exc:
        netaudit.cmd_run(_ns(['ssh_hardening'], ['--hosts-file', str(tmp_path / 'missing.json'),
                                                 '--job', 'daily']))
    assert exc.value.code not in (0, None)
    [call] = sent
    assert 'refused' in call['text'] and 'daily' in call['text']
    assert call['reports_saved'] == 0


def test_a_crashed_run_sends_a_failure_message_and_still_fails(telegram, monkeypatch, sent):
    def boom(selected):
        raise RuntimeError('engine exploded')

    monkeypatch.setattr(netaudit, 'run_checks', boom)
    with pytest.raises(RuntimeError):
        netaudit.cmd_run(_ns(['ssh_hardening'], ['--host', '10.0.0.5']))
    [call] = sent
    assert 'RuntimeError' in call['text']


def test_group_run_notifies_too(telegram, monkeypatch, sent, tmp_path):
    hosts = tmp_path / 'hosts.json'
    hosts.write_text(json.dumps([{'host': '10.0.0.5'}, {'host': '10.0.0.6'}]), encoding='utf-8')

    def fake_multi(selected, **kwargs):
        return {'timestamp': '2026-10-17 03:00:00', 'timing': {}, 'meta': {}, 'total_time': 0,
                'results': {'ssh_hardening': {'_multi_host': True, 'by_host': {
                    '10.0.0.5': {'findings': []}, '10.0.0.6': {'error': 'timed out'}}}},
                'execution_context': {'ssh_hardening': {'10.0.0.5': {'host': '10.0.0.5'},
                                                        '10.0.0.6': {'host': '10.0.0.6'}}}}

    monkeypatch.setattr(netaudit, 'run_checks_multi', fake_multi)
    netaudit.cmd_run(_ns(['ssh_hardening'], ['--hosts-file', str(hosts)]))
    [call] = sent
    assert '10.0.0.6' in call['text']


def test_main_parses_notify_as_a_flag(monkeypatch):
    seen = []
    monkeypatch.setattr(netaudit, 'cmd_run', seen.append)
    monkeypatch.setattr(sys, 'argv', ['netaudit.py', 'run', 'ssh_hardening', '--host', 'h',
                                      '--notify', '--job', 'daily'])
    netaudit.main()
    [args] = seen
    assert args.notify is True
    assert args.checks == ['ssh_hardening']
    assert args.rest == ['--host', 'h', '--job', 'daily']


# --- setup-timer -------------------------------------------------------------

@pytest.fixture
def timer_env(telegram, monkeypatch, tmp_path):
    """A readable hosts file, a fake systemd-analyze, output into tmp_path."""
    hosts = tmp_path / 'hosts.json'
    hosts.write_text(json.dumps([{'host': '10.0.0.5'}]), encoding='utf-8')
    calendars = []

    def fake_calendar(spec):
        calendars.append(spec)
        return spec != 'bogus spec'

    monkeypatch.setattr(netaudit, '_systemd_calendar_ok', fake_calendar)
    monkeypatch.chdir(tmp_path)
    return {'hosts': hosts, 'dir': tmp_path, 'calendars': calendars}


def _setup_timer(argv, rest=()):
    args = netaudit.build_parser().parse_args(['setup-timer', *argv])
    args.rest = list(rest)
    args.func(args)


def _valid_argv(env, name='daily', calendar='daily'):
    return ['--name', name, '--on-calendar', calendar, '--hosts-file', str(env['hosts']),
            'ssh_hardening', 'kernel_hardening']


def test_setup_timer_writes_a_oneshot_service_and_a_persistent_timer(timer_env, capsys):
    _setup_timer(_valid_argv(timer_env))
    service = (timer_env['dir'] / 'netaudit-audit-daily.service').read_text()
    timer = (timer_env['dir'] / 'netaudit-audit-daily.timer').read_text()
    user = pwd.getpwuid(os.geteuid()).pw_name

    assert 'Type=oneshot' in service and 'TimeoutStartSec=1h' in service
    assert f'User={user}' in service
    [exec_start] = [line for line in service.splitlines() if line.startswith('ExecStart=')]
    assert exec_start.split()[2:] == ['run', 'ssh_hardening', 'kernel_hardening', '--hosts-file',
                                      str(timer_env['hosts'].resolve()), '--notify', '--job', 'daily',
                                      '--notify-min-severity', 'medium']
    assert 'password' not in service.lower()
    assert 'OnCalendar=daily' in timer and 'Persistent=true' in timer
    assert 'RandomizedDelaySec=5min' in timer and 'Unit=netaudit-audit-daily.service' in timer
    out = capsys.readouterr().out
    assert 'sudo cp' in out and 'systemctl enable --now netaudit-audit-daily.timer' in out
    assert timer_env['calendars'] == ['daily']


@pytest.mark.parametrize('name', ['Daily', 'has space', 'a%h', 'a$b', "a'b", 'a\nb', '-lead', 'x' * 33])
def test_setup_timer_refuses_a_bad_name(timer_env, name):
    with pytest.raises(SystemExit):
        _setup_timer(_valid_argv(timer_env, name=name))
    assert not list(timer_env['dir'].glob('netaudit-audit-*'))


@pytest.mark.parametrize('filename', ['hosts-%H.json', 'hosts $HOME.json', 'hosts space.json',
                                      'hosts"q.json', 'hosts;x.json'])
def test_setup_timer_refuses_an_unsafe_hosts_path(timer_env, filename):
    path = timer_env['dir'] / filename
    path.write_text(json.dumps([{'host': '10.0.0.5'}]), encoding='utf-8')
    with pytest.raises(SystemExit):
        _setup_timer(['--name', 'daily', '--on-calendar', 'daily', '--hosts-file', str(path), 'ssh_hardening'])
    assert not list(timer_env['dir'].glob('netaudit-audit-*'))


@pytest.mark.parametrize('argv_change', [
    {'hosts': 'missing.json'},
    {'checks': ['ssl']},
    {'calendar': 'bogus spec'},
    {'calendar': 'daily\nExecStart=/bin/sh'},
    {'calendar': 'daily %h'},
    {'timeout': 'forever'},
], ids=['unreadable-hosts', 'check-without-host', 'calendar-rejected', 'calendar-newline',
        'calendar-specifier', 'bad-timeout'])
def test_setup_timer_refusals(timer_env, argv_change):
    hosts = str(timer_env['dir'] / argv_change.get('hosts', 'hosts.json'))
    argv = ['--name', 'daily', '--on-calendar', argv_change.get('calendar', 'daily'), '--hosts-file', hosts]
    if 'timeout' in argv_change:
        argv += ['--timeout', argv_change['timeout']]
    argv += argv_change.get('checks', ['ssh_hardening'])
    with pytest.raises(SystemExit):
        _setup_timer(argv)
    assert not list(timer_env['dir'].glob('netaudit-audit-*'))


@pytest.mark.parametrize('rest', [['--password', 'SECRET-VALUE'], ['--sudo_password', '-'], ['--whatever', '1']])
def test_setup_timer_refuses_password_and_unknown_flags(timer_env, rest, caplog):
    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit):
        _setup_timer(_valid_argv(timer_env), rest=rest)
    assert 'SECRET-VALUE' not in caplog.text
    assert not list(timer_env['dir'].glob('netaudit-audit-*'))


def test_setup_timer_refuses_root(timer_env, monkeypatch):
    monkeypatch.setattr(netaudit.os, 'geteuid', lambda: 0)
    with pytest.raises(SystemExit):
        _setup_timer(_valid_argv(timer_env))


def test_setup_timer_needs_telegram(isolated_db, monkeypatch, tmp_path):
    hosts = tmp_path / 'hosts.json'
    hosts.write_text(json.dumps([{'host': '10.0.0.5'}]), encoding='utf-8')
    monkeypatch.setattr(netaudit, '_systemd_calendar_ok', lambda spec: True)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        _setup_timer(['--name', 'daily', '--on-calendar', 'daily', '--hosts-file', str(hosts), 'ssh_hardening'])


def test_setup_timer_without_systemd_analyze_is_refused(telegram, monkeypatch, tmp_path, caplog):
    hosts = tmp_path / 'hosts.json'
    hosts.write_text(json.dumps([{'host': '10.0.0.5'}]), encoding='utf-8')
    monkeypatch.setattr(netaudit.shutil, 'which', lambda name: None)
    monkeypatch.chdir(tmp_path)
    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit):
        _setup_timer(['--name', 'daily', '--on-calendar', 'daily', '--hosts-file', str(hosts), 'ssh_hardening'])
    assert 'systemd-analyze' in caplog.text
    assert not list(tmp_path.glob('netaudit-audit-*'))


@pytest.mark.skipif(shutil.which('systemd-analyze') is None, reason='needs systemd-analyze')
def test_generated_units_pass_systemd_analyze_verify(telegram, monkeypatch, tmp_path):
    hosts = tmp_path / 'hosts.json'
    hosts.write_text(json.dumps([{'host': '10.0.0.5'}]), encoding='utf-8')
    monkeypatch.chdir(tmp_path)
    _setup_timer(['--name', 'verify', '--on-calendar', 'Mon *-*-* 03:00:00', '--hosts-file', str(hosts),
                  'ssh_hardening'])
    files = [str(tmp_path / 'netaudit-audit-verify.service'), str(tmp_path / 'netaudit-audit-verify.timer')]
    proc = subprocess.run(['systemd-analyze', 'verify', *files], capture_output=True, text=True,
                          check=False, timeout=60)
    assert proc.returncode == 0, proc.stderr
