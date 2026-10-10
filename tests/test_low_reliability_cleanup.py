"""F7 part 1 (docs/research/low_reliability_cleanup.md): ssh_audit, dig, the
local firewall check and the measurement tools say when they did not get
their data. No network: run_cmd is faked; the ssh_audit shell snippets run in
a local /bin/sh with fake binaries first in PATH."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from netaudit_pkg.checks import capture, network, system


def _fake_run_cmd(monkeypatch, module, result):
    calls = []

    def fake(cmd, timeout=30, input_text=None):
        calls.append(cmd)
        return result(cmd) if callable(result) else result

    monkeypatch.setattr(module, 'tool_available', lambda name: True)
    monkeypatch.setattr(module, 'run_cmd', fake)
    return calls


# ===========================================================================
# RA-08: dig
# ===========================================================================

DIG_NOERROR = (';; Got answer:\n'
               ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n'
               ';; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n'
               ';; OPT PSEUDOSECTION:\n'
               '; EDNS: version: 0, flags:; udp: 65494\n'
               ';; ANSWER SECTION:\n'
               'example.com.\t\t300\tIN\tA\t93.184.215.14\n\n'
               ';; Query time: 3 msec\n'
               ';; SERVER: 127.0.0.53#53(127.0.0.53) (UDP)\n')


def _dig_status(status):
    return (';; Got answer:\n'
            f';; ->>HEADER<<- opcode: QUERY, status: {status}, id: 2\n'
            ';; Query time: 5 msec\n')


def test_dig_reports_nxdomain_as_a_status_not_an_empty_answer(monkeypatch):
    _fake_run_cmd(monkeypatch, network, (0, _dig_status('NXDOMAIN'), ''))
    result = network.check_dig('does-not-exist.example')
    assert result['status'] == 'NXDOMAIN'
    assert result['answers'] == []
    assert 'error' not in result


@pytest.mark.parametrize('status', ['SERVFAIL', 'REFUSED'])
def test_dig_failed_resolution_is_an_error(monkeypatch, status):
    _fake_run_cmd(monkeypatch, network, (0, _dig_status(status), ''))
    result = network.check_dig('example.com')
    assert status in result['error']


def test_dig_comment_lines_are_not_records_and_comments_are_requested(monkeypatch):
    calls = _fake_run_cmd(monkeypatch, network, (0, DIG_NOERROR, ''))
    result = network.check_dig('example.com')
    assert result['status'] == 'NOERROR'
    assert result['answers'] == [{'name': 'example.com.', 'ttl': '300', 'type': 'A', 'value': '93.184.215.14'}]
    assert '+comments' in calls[0]


# ===========================================================================
# RA-09: local firewall
# ===========================================================================

def test_local_firewall_shows_why_ufw_and_nft_failed(monkeypatch):
    def result(cmd):
        if cmd[0] == 'ufw':
            return 1, '', 'ERROR: You need to be root to run this script\n'
        return 1, '', 'Error: Operation not permitted\n'

    _fake_run_cmd(monkeypatch, system, result)
    out = system.check_firewall()
    assert 'You need to be root' in out['ufw']
    assert 'Operation not permitted' in out['nftables_rules_count']


# ===========================================================================
# RA-07: ssh_audit shell snippets, run for real in /bin/sh
# ===========================================================================

def _run_snippet(name, tmp_path, fakes: dict[str, str]):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    for tool, body in fakes.items():
        path = bin_dir / tool
        path.write_text('#!/bin/sh\n' + body + '\n')
        path.chmod(0o755)
    # only the fakes plus the basics the snippets pipe through
    for tool in ('tail', 'grep', 'head', 'cat', 'printf'):
        if tool not in fakes and shutil.which(tool):
            (bin_dir / tool).symlink_to(shutil.which(tool))
    env = {'PATH': str(bin_dir), 'LANG': 'C'}
    return subprocess.run(['/bin/sh', '-c', system.REMOTE_CHECKS[name]], env=env,
                          capture_output=True, text=True, timeout=10, check=False).stdout


def test_journal_permission_hint_is_not_swallowed(tmp_path):
    out = _run_snippet('failed_ssh_logins', tmp_path, {
        'journalctl': "echo 'Hint: You are currently not seeing messages from other users and the system.' >&2",
    })
    assert 'not seeing messages' in out


def test_missing_journalctl_is_reported(tmp_path):
    out = _run_snippet('failed_ssh_logins', tmp_path, {})
    assert 'journalctl exit 127' in out


def test_sshd_config_without_matching_lines_is_not_no_access(tmp_path):
    out = _run_snippet('sshd_config', tmp_path, {'grep': 'exit 1'})
    assert '(no explicit' in out
    assert 'no access' not in out


def test_sshd_config_read_error_is_shown(tmp_path):
    out = _run_snippet('sshd_config', tmp_path, {
        'grep': "echo 'grep: /etc/ssh/sshd_config: Permission denied' >&2; exit 2",
    })
    assert 'Permission denied' in out


def test_disabled_unattended_upgrades_is_not_not_found(tmp_path):
    out = _run_snippet('unattended_upgrades', tmp_path, {'systemctl': 'echo disabled; exit 1'})
    assert out.strip() == 'disabled'


# ===========================================================================
# RA-20: ping, arping, tshark
# ===========================================================================

def test_ping_without_statistics_is_an_error(monkeypatch):
    _fake_run_cmd(monkeypatch, network, (0, 'PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.\n', ''))
    result = network.check_ping('10.0.0.1', count=3)
    assert 'could not parse' in result['error']


def test_ping_total_loss_is_a_measurement_not_an_error(monkeypatch):
    out = '3 packets transmitted, 0 received, 100% packet loss, time 2003ms\n'
    _fake_run_cmd(monkeypatch, network, (1, out, ''))
    result = network.check_ping('10.0.0.1', count=3)
    assert result['loss_pct'] == 100.0
    assert 'error' not in result


def test_arping_without_statistics_is_an_error(monkeypatch):
    _fake_run_cmd(monkeypatch, network, (0, 'ARPING 192.168.88.1\n', ''))
    result = network.check_arping('192.168.88.1', count=2)
    assert 'could not parse' in result['error']


def test_tshark_counts_lines_it_could_not_parse(monkeypatch):
    out = '10.0.0.2|1.1.1.1|60|TCP\ngarbage line\nanother one\n'
    _fake_run_cmd(monkeypatch, capture, (0, out, ''))
    monkeypatch.setattr(capture, '_enrich_top', lambda dests, limit=15: dests)
    result = capture.check_tshark_capture(duration=1, analyze_threats='нет')
    assert result['total_packets'] == 1
    assert result['unparsed_lines'] == 2
