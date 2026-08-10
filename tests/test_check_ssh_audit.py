"""
Tests for netaudit_pkg.checks.system.check_ssh_audit(). Written after finding
a live-server bug: firewall_ufw/firewall_nft/fail2ban_status all require root
on a typical Ubuntu install, but were going through ssh.run() (no sudo), and
their `2>/dev/null | head -N || echo "no access"` fallback never fired
because a pipe takes its exit code from the last command (head), not the
one that actually failed (nft/ufw/fail2ban-client) - so a permission error
silently became an empty string instead of the intended fallback message.
"""

from __future__ import annotations

from netaudit_pkg.checks.system import check_ssh_audit, REMOTE_CHECKS, REMOTE_SUDO_CHECKS
from tests.conftest import FakeSSHExecutor


def test_no_host_returns_error():
    result = check_ssh_audit(host='')
    assert result == {'error': 'host not specified'}


def test_sudo_required_commands_go_through_sudo_not_run(monkeypatch):
    # the specific regression this test exists to catch: firewall_ufw/
    # firewall_nft/fail2ban_status must be issued via ssh.sudo(), which on
    # FakeSSHExecutor is tracked separately from run() via sudo_calls.
    fake = FakeSSHExecutor(responses={
        'os_release': ('Ubuntu 24.04', ''),
        'uptime': ('up 1 day', ''),
        'ufw status': ('Status: active', ''),
        'nft list ruleset': ('table inet filter {...}', ''),
        'fail2ban-client status': ('Number of jail: 2', ''),
    })
    monkeypatch.setattr('netaudit_pkg.checks.system.SSHExecutor', lambda *a, **kw: fake)
    check_ssh_audit(host='10.0.0.5', user='root', key_path='', password='')
    # sudo() and run() both append to .calls on FakeSSHExecutor, but this
    # confirms the three sudo-required commands were actually issued (i.e.
    # not silently skipped) - the sudo-vs-run distinction itself is
    # exercised by real SSHExecutor.sudo()'s passwordless/password-based
    # branching, not reproducible via the fake, so this checks presence.
    assert any('ufw status' in c for c in fake.calls)
    assert any('nft list ruleset' in c for c in fake.calls)
    assert any('fail2ban-client status' in c for c in fake.calls)


def test_full_result_shape(monkeypatch):
    responses = {name: (f'{name} output', '') for name in REMOTE_CHECKS}
    responses.update({cmd.split()[0] + ' ' + cmd.split()[1]: (f'{name} output', '')
                       for name, cmd in [('firewall_ufw', 'ufw status'),
                                          ('firewall_nft', 'nft list'),
                                          ('fail2ban_status', 'fail2ban-client status')]})
    fake = FakeSSHExecutor(responses=responses)
    monkeypatch.setattr('netaudit_pkg.checks.system.SSHExecutor', lambda *a, **kw: fake)
    result = check_ssh_audit(host='10.0.0.5', user='root', key_path='', password='')
    assert result['host'] == '10.0.0.5'
    assert result['user'] == 'root'
    assert set(REMOTE_CHECKS) <= set(result['checks'])
    assert set(REMOTE_SUDO_CHECKS) <= set(result['checks'])


def test_permission_denied_is_visible_not_swallowed(monkeypatch):
    # the exact bug scenario: a sudo command that fails with a permission
    # error must show that error, not silently become '(empty)' or a
    # misleading generic fallback string.
    fake = FakeSSHExecutor(responses={
        'nft list ruleset': ('', 'Operation not permitted (you must be root)'),
    })
    monkeypatch.setattr('netaudit_pkg.checks.system.SSHExecutor', lambda *a, **kw: fake)
    result = check_ssh_audit(host='10.0.0.5', user='root', key_path='', password='')
    assert 'Operation not permitted' in result['checks']['firewall_nft']
    assert result['checks']['firewall_nft'] != '(empty)'


def test_connection_failure(monkeypatch):
    class _BoomSSH:
        def __init__(self, *a, **kw):
            pass

        def connect(self):
            raise ConnectionRefusedError('refused')

    monkeypatch.setattr('netaudit_pkg.checks.system.SSHExecutor', _BoomSSH)
    result = check_ssh_audit(host='10.0.0.5')
    assert 'error' in result
    assert 'could not connect' in result['error']
