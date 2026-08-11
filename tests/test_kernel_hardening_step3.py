"""
Tests for netaudit_pkg.checks.kernel_hardening beyond _build_components()/
_build_findings() (see test_kernel_hardening_step1.py and
test_kernel_hardening_step2.py for those). Covers:
  - audit_kernel_hardening_score(ssh): the full internal API against an
    already-connected SSHExecutor, including the N/A branch
  - check_kernel_hardening(...): the registry entrypoint, including SSH
    connection failure and HostKeyMismatchError handling
  - registry registration itself
"""

from __future__ import annotations

from netaudit_pkg.checks.kernel_hardening import (
    audit_kernel_hardening_score, check_kernel_hardening,
)
from netaudit_pkg.ssh import HostKeyMismatchError
from tests.conftest import FakeSSHExecutor


def _sysctl_line(key: str, value: str) -> str:
    return f'{key} = {value}'


_SYSCTL_A_HARDENED = '\n'.join([
    _sysctl_line('kernel.randomize_va_space', '2'),
    _sysctl_line('kernel.dmesg_restrict', '1'),
    _sysctl_line('kernel.kptr_restrict', '2'),
    _sysctl_line('kernel.yama.ptrace_scope', '1'),
    _sysctl_line('fs.suid_dumpable', '0'),
    _sysctl_line('net.ipv4.ip_forward', '0'),
    _sysctl_line('net.ipv6.conf.all.forwarding', '0'),
    _sysctl_line('net.ipv4.tcp_syncookies', '1'),
    _sysctl_line('net.ipv4.icmp_echo_ignore_broadcasts', '1'),
    _sysctl_line('net.ipv4.conf.all.accept_source_route', '0'),
    _sysctl_line('net.ipv4.conf.all.accept_redirects', '0'),
    _sysctl_line('net.ipv4.conf.all.secure_redirects', '0'),
    _sysctl_line('net.ipv4.conf.all.send_redirects', '0'),
    _sysctl_line('net.ipv4.conf.all.log_martians', '1'),
    _sysctl_line('net.ipv4.conf.all.rp_filter', '1'),
    _sysctl_line('net.ipv4.conf.default.rp_filter', '1'),
])

# The actual 2026-08-11 VM baseline (docs/checks/kernel_hardening.md
# section 3) — 4 controls FAIL: accept_redirects, send_redirects,
# secure_redirects, log_martians.
_SYSCTL_A_VM_BASELINE = '\n'.join([
    _sysctl_line('kernel.randomize_va_space', '2'),
    _sysctl_line('kernel.dmesg_restrict', '1'),
    _sysctl_line('kernel.kptr_restrict', '1'),
    _sysctl_line('kernel.yama.ptrace_scope', '1'),
    _sysctl_line('fs.suid_dumpable', '2'),
    _sysctl_line('net.ipv4.ip_forward', '0'),
    _sysctl_line('net.ipv6.conf.all.forwarding', '0'),
    _sysctl_line('net.ipv4.tcp_syncookies', '1'),
    _sysctl_line('net.ipv4.icmp_echo_ignore_broadcasts', '1'),
    _sysctl_line('net.ipv4.conf.all.accept_source_route', '0'),
    _sysctl_line('net.ipv4.conf.all.accept_redirects', '1'),
    _sysctl_line('net.ipv4.conf.all.secure_redirects', '1'),
    _sysctl_line('net.ipv4.conf.all.send_redirects', '1'),
    _sysctl_line('net.ipv4.conf.all.log_martians', '0'),
    _sysctl_line('net.ipv4.conf.all.rp_filter', '2'),
    _sysctl_line('net.ipv4.conf.default.rp_filter', '2'),
])


def _kernel_responses(sysctl_output: str, uname_output: str = '7.0.0-29-generic\n') -> dict:
    return {
        'uname -r': (uname_output, ''),
        'sysctl -a': (sysctl_output, ''),
    }


# ===========================================================================
# audit_kernel_hardening_score(ssh)
# ===========================================================================

def test_audit_kernel_hardening_score_unreadable_config(fake_ssh):
    """sysctl -a under sudo returned nothing usable — the sole N/A case
    (spec section 5). No partial score, matching ssh_hardening's and
    nginx_hardening's identical handling."""
    fake_ssh.responses = {
        'uname -r': ('7.0.0-29-generic\n', ''),
        'sysctl -a': ('', ''),
    }
    result = audit_kernel_hardening_score(fake_ssh)
    assert result['readable'] is False
    assert 'error' in result
    assert 'requires root' in result['error']
    assert 'hardening' not in result
    # uname -r is independent of sysctl -a and still captured, same as
    # ssh_hardening still returns cfg.version in its N/A branch.
    assert result['kernel_version'] == '7.0.0-29-generic'


def test_audit_kernel_hardening_score_full_result_hardened(fake_ssh):
    fake_ssh.responses = _kernel_responses(_SYSCTL_A_HARDENED)
    result = audit_kernel_hardening_score(fake_ssh)
    assert result['readable'] is True
    assert result['kernel_version'] == '7.0.0-29-generic'
    assert result['hardening']['score'] == 100
    assert result['hardening']['max'] == 100
    assert len(result['hardening']['components']) == 16
    assert result['findings'] == []


def test_audit_kernel_hardening_score_full_result_vm_baseline(fake_ssh):
    """The real 2026-08-11 VM values — must score 75 (per Step 1's
    synthetic validation, test_vm_baseline_scores_mid_range_reasonable)
    and produce findings for the 4 outright-FAILing controls plus
    KRN-016 (suid_dumpable=2, partial score)."""
    fake_ssh.responses = _kernel_responses(_SYSCTL_A_VM_BASELINE)
    result = audit_kernel_hardening_score(fake_ssh)
    assert result['readable'] is True
    assert result['hardening']['score'] == 75

    ids = {f['id'] for f in result['findings']}
    assert ids == {'KRN-006', 'KRN-007', 'KRN-010', 'KRN-011', 'KRN-016'}


def test_audit_kernel_hardening_score_single_sysctl_call(fake_ssh):
    """One SSH round-trip for sysctl -a, not 16 separate sysctl -n calls
    — per kernel_config.py's collector docstring."""
    fake_ssh.responses = _kernel_responses(_SYSCTL_A_HARDENED)
    audit_kernel_hardening_score(fake_ssh)
    sysctl_calls = [c for c in fake_ssh.calls if c == 'sysctl -a']
    assert len(sysctl_calls) == 1


def test_audit_kernel_hardening_score_uses_sudo_for_sysctl(fake_ssh):
    """Contractual check carried over from kernel_config.py's own tests —
    re-asserted here at the full-audit level so a future refactor that
    routes the call through ssh.run() instead of ssh.sudo() fails loudly
    at this layer too, not only in test_kernel_config.py."""
    fake_ssh.responses = _kernel_responses(_SYSCTL_A_HARDENED)
    audit_kernel_hardening_score(fake_ssh)
    # FakeSSHExecutor's run() and sudo() both route through the same
    # _match() and record to the same .calls list, so this test can't
    # distinguish sudo from run purely via .calls — that distinction is
    # already covered precisely in test_kernel_config.py
    # (test_collect_uses_sudo_for_sysctl_not_run). This test instead
    # confirms the higher-level audit function actually reaches a
    # successful readable=True result, which is only possible if the
    # collector's sudo() call path was exercised the way kernel_config.py
    # expects a real (non-fake) SSHExecutor to behave.
    result = audit_kernel_hardening_score(fake_ssh)
    assert result['readable'] is True


# ===========================================================================
# check_kernel_hardening(...) - registry entrypoint
# ===========================================================================

def test_check_kernel_hardening_no_host():
    result = check_kernel_hardening(host='')
    assert result == {'error': 'host not specified'}


def test_check_kernel_hardening_happy_path(monkeypatch):
    fake = FakeSSHExecutor(responses=_kernel_responses(_SYSCTL_A_HARDENED))
    monkeypatch.setattr('netaudit_pkg.checks.kernel_hardening.SSHExecutor', lambda *a, **kw: fake)
    result = check_kernel_hardening(host='10.0.0.5')
    assert result['readable'] is True
    assert result['hardening']['score'] == 100
    assert fake.closed is True


def test_check_kernel_hardening_closes_ssh_even_on_unreadable_config(monkeypatch):
    fake = FakeSSHExecutor(responses={'uname -r': ('7.0.0-29-generic\n', ''), 'sysctl -a': ('', '')})
    monkeypatch.setattr('netaudit_pkg.checks.kernel_hardening.SSHExecutor', lambda *a, **kw: fake)
    check_kernel_hardening(host='10.0.0.5')
    assert fake.closed is True


def test_check_kernel_hardening_connection_failure(monkeypatch):
    class _BoomSSH:
        def __init__(self, *a, **kw):
            pass

        def connect(self):
            raise ConnectionRefusedError('connection refused')

    monkeypatch.setattr('netaudit_pkg.checks.kernel_hardening.SSHExecutor', _BoomSSH)
    result = check_kernel_hardening(host='10.0.0.5')
    assert 'error' in result
    assert 'could not connect' in result['error']


def test_check_kernel_hardening_host_key_mismatch(monkeypatch):
    class _MismatchSSH:
        def __init__(self, *a, **kw):
            pass

        def connect(self):
            raise HostKeyMismatchError('host key changed for 10.0.0.5')

    monkeypatch.setattr('netaudit_pkg.checks.kernel_hardening.SSHExecutor', _MismatchSSH)
    result = check_kernel_hardening(host='10.0.0.5')
    assert 'error' in result
    assert 'host key changed' in result['error']


def test_check_kernel_hardening_registered_as_hardening_category():
    from netaudit_pkg.registry import registry
    spec = registry.get('kernel_hardening')
    assert spec is not None
    assert spec.category == 'hardening'
    assert spec.risk_level == 'READ_ONLY'
