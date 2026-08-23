"""Tests for netaudit_pkg/checks/network.py.

speedtest coverage follows the same local-symbol patch pattern used by
test_dns_audit.py (patch('netaudit_pkg.checks.network.run_cmd', ...) and
patch('netaudit_pkg.checks.network.tool_available', ...)), not utils.run_cmd -
network.py imports both names directly, so patching utils would miss the
call site.
"""

from __future__ import annotations

import json
from unittest.mock import patch

from netaudit_pkg.checks.network import check_speedtest

# Real Ookla `speedtest --format=json` output captured on VM 192.168.88.20
# (Ubuntu 26.04, Ookla CLI 1.2.0.84) during the reality-check phase - not a
# hand-written fixture. See conversation notes: bandwidth is bytes/sec, not
# bits/sec, hence the *8/1_000_000 normalization in the implementation.
REAL_SPEEDTEST_JSON = json.dumps({
    "type": "result",
    "timestamp": "2026-08-23T17:07:16Z",
    "ping": {"jitter": 0.893, "latency": 5.778, "low": 5.389, "high": 6.838},
    "download": {
        "bandwidth": 34611046, "bytes": 379845538, "elapsed": 11105,
        "latency": {"iqm": 62.507, "low": 6.277, "high": 453.295, "jitter": 47.847},
    },
    "upload": {
        "bandwidth": 70911131, "bytes": 1014593755, "elapsed": 14993,
        "latency": {"iqm": 31.506, "low": 7.218, "high": 90.722, "jitter": 8.733},
    },
    "packetLoss": 0,
    "isp": "UAB Cgates",
    "interface": {
        "internalIp": "192.168.88.20", "name": "enp0s3",
        "macAddr": "08:00:27:0B:E1:82", "isVpn": False,
        "externalIp": "5.20.17.250",
    },
    "server": {
        "id": 18277, "host": "speedtest-vno.init.lt", "port": 8080,
        "name": "INIT", "location": "Vilnius", "country": "Lithuania",
        "ip": "84.55.36.195",
    },
    "result": {
        "id": "494b142d-5768-4b46-a516-7a97b17a821c",
        "url": "https://www.speedtest.net/result/c/494b142d-5768-4b46-a516-7a97b17a821c",
        "persisted": True,
    },
})


def test_speedtest_success_normalizes_bandwidth_to_mbps():
    with patch('netaudit_pkg.checks.network.tool_available', return_value=True), \
         patch('netaudit_pkg.checks.network.run_cmd', return_value=(0, REAL_SPEEDTEST_JSON, '')):
        result = check_speedtest()

    assert 'error' not in result
    # 34611046 B/s * 8 / 1_000_000 = 276.888368 -> round(.., 2)
    assert result['download_mbps'] == 276.89
    # 70911131 B/s * 8 / 1_000_000 = 567.289048 -> round(.., 2)
    assert result['upload_mbps'] == 567.29


def test_speedtest_success_keeps_raw_bandwidth_bytes():
    with patch('netaudit_pkg.checks.network.tool_available', return_value=True), \
         patch('netaudit_pkg.checks.network.run_cmd', return_value=(0, REAL_SPEEDTEST_JSON, '')):
        result = check_speedtest()

    assert result['bandwidth_bytes_per_sec'] == {
        'download': 34611046,
        'upload': 70911131,
    }


def test_speedtest_success_ping_jitter_loss():
    with patch('netaudit_pkg.checks.network.tool_available', return_value=True), \
         patch('netaudit_pkg.checks.network.run_cmd', return_value=(0, REAL_SPEEDTEST_JSON, '')):
        result = check_speedtest()

    assert result['ping_ms'] == 5.778
    assert result['jitter_ms'] == 0.893
    assert result['packet_loss_pct'] == 0


def test_speedtest_success_isp_and_server_fields():
    with patch('netaudit_pkg.checks.network.tool_available', return_value=True), \
         patch('netaudit_pkg.checks.network.run_cmd', return_value=(0, REAL_SPEEDTEST_JSON, '')):
        result = check_speedtest()

    assert result['isp'] == 'UAB Cgates'
    assert result['server'] == {
        'id': 18277,
        'name': 'INIT',
        'location': 'Vilnius',
        'country': 'Lithuania',
    }


def test_speedtest_success_does_not_leak_network_inventory_fields():
    # internalIp/externalIp/macAddr are deliberately excluded from the
    # normalized result - that's inventory/exposure data, not a speedtest
    # result field, per the frozen normalization contract.
    with patch('netaudit_pkg.checks.network.tool_available', return_value=True), \
         patch('netaudit_pkg.checks.network.run_cmd', return_value=(0, REAL_SPEEDTEST_JSON, '')):
        result = check_speedtest()

    assert 'interface' not in result
    assert 'internalIp' not in json.dumps(result)
    assert 'macAddr' not in json.dumps(result)


def test_speedtest_missing_tool():
    with patch('netaudit_pkg.checks.network.tool_available', return_value=False):
        result = check_speedtest()

    assert 'error' in result
    assert 'speedtest' in result['error'].lower()


def test_speedtest_command_failure_uses_stderr():
    with patch('netaudit_pkg.checks.network.tool_available', return_value=True), \
         patch('netaudit_pkg.checks.network.run_cmd',
               return_value=(1, '', 'Unable to connect to servers')):
        result = check_speedtest()

    assert 'error' in result
    assert 'Unable to connect to servers' in result['error']


def test_speedtest_command_failure_falls_back_to_stdout_tail_when_stderr_empty():
    with patch('netaudit_pkg.checks.network.tool_available', return_value=True), \
         patch('netaudit_pkg.checks.network.run_cmd',
               return_value=(1, 'some partial stdout output', '')):
        result = check_speedtest()

    assert 'error' in result
    assert 'some partial stdout output' in result['error']


def test_speedtest_invalid_json_on_success_exit_code():
    with patch('netaudit_pkg.checks.network.tool_available', return_value=True), \
         patch('netaudit_pkg.checks.network.run_cmd',
               return_value=(0, 'not actually json', '')):
        result = check_speedtest()

    assert 'error' in result
    assert 'json' in result['error'].lower()


def test_speedtest_invocation_uses_frozen_command_and_timeout():
    with patch('netaudit_pkg.checks.network.tool_available', return_value=True), \
         patch('netaudit_pkg.checks.network.run_cmd',
               return_value=(0, REAL_SPEEDTEST_JSON, '')) as mock_run:
        check_speedtest()

    assert mock_run.call_count == 1
    args, kwargs = mock_run.call_args
    cmd = args[0]

    assert cmd[0] == 'speedtest'
    assert '--accept-license' in cmd
    assert '--accept-gdpr' in cmd
    assert '--format=json' in cmd
    assert kwargs.get('timeout') == 60
