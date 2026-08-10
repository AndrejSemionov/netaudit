"""
Tests for netaudit_pkg.checks.ssh_hardening beyond _build_components() (see
test_ssh_hardening_components.py for the pure-function control tests).
Covers:
  - _build_findings(): the 11 self-generated findings (everything except
    SSH-AUTH-001/002/003, which audit_ssh_hardening() in server_security.py
    already covers)
  - audit_ssh_hardening_score(ssh): the full internal API against an
    already-connected SSHExecutor
  - check_ssh_hardening(...): the registry entrypoint, including SSH
    connection failure and HostKeyMismatchError handling
"""

from __future__ import annotations

from netaudit_pkg.ssh_config import SSHConfig
from netaudit_pkg.checks.ssh_hardening import (
    _build_findings, audit_ssh_hardening_score, check_ssh_hardening,
)
from netaudit_pkg.ssh import HostKeyMismatchError
from tests.conftest import FakeSSHExecutor


def _cfg(**kwargs) -> SSHConfig:
    defaults = dict(
        readable=True,
        permit_root_login='no',
        password_authentication=False,
        permit_empty_passwords=False,
        pubkey_authentication=True,
        kbd_interactive_authentication=False,
        hostbased_authentication=False,
        max_auth_tries=4,
        login_grace_time=60,
        x11_forwarding=False,
        allow_tcp_forwarding='no',
        allow_agent_forwarding=False,
        ciphers=['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com'],
        macs=['hmac-sha2-256-etm@openssh.com'],
        kex_algorithms=['curve25519-sha256'],
    )
    defaults.update(kwargs)
    return SSHConfig(**defaults)


SSHD_T_HARDENED = """\
port 22
permitrootlogin no
passwordauthentication no
permitemptypasswords no
pubkeyauthentication yes
kbdinteractiveauthentication no
hostbasedauthentication no
maxauthtries 4
logingracetime 60
x11forwarding no
allowtcpforwarding no
allowagentforwarding no
ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
macs hmac-sha2-256-etm@openssh.com
kexalgorithms curve25519-sha256
"""

SSHD_T_WEAK = """\
port 22
permitrootlogin yes
passwordauthentication yes
permitemptypasswords no
pubkeyauthentication yes
kbdinteractiveauthentication no
hostbasedauthentication no
maxauthtries 6
logingracetime 120
x11forwarding yes
allowtcpforwarding yes
allowagentforwarding yes
ciphers chacha20-poly1305@openssh.com,3des-cbc
macs hmac-sha1-etm@openssh.com
kexalgorithms diffie-hellman-group14-sha1
"""


def _ssh_responses(sshd_t_output: str, *, installed=True) -> dict:
    if not installed:
        return {'which sshd': ('NONE', '')}
    return {
        'which sshd': ('/usr/sbin/sshd', ''),
        'sshd -V': ('', 'OpenSSH_10.2p1 Ubuntu-2ubuntu3.5'),
        'sshd -T': (sshd_t_output, ''),
    }


# ===========================================================================
# _build_findings() - shape and coverage
# ===========================================================================

def test_findings_fully_hardened_config_produces_no_findings():
    assert _build_findings(_cfg()) == []


def test_findings_never_includes_ssh_auth_001_002_003():
    # those three are covered by audit_ssh_hardening() in server_security.py
    # - this module must not re-derive or duplicate them.
    cfg = _cfg(permit_root_login='yes', password_authentication=True, permit_empty_passwords=True)
    ids = {f.get('id') for f in _build_findings(cfg)}
    assert ids.isdisjoint({'SSH-AUTH-001', 'SSH-AUTH-002', 'SSH-AUTH-003'})


def test_findings_covers_all_eleven_self_generated_controls():
    cfg = _cfg(
        pubkey_authentication=False, kbd_interactive_authentication=True,
        hostbased_authentication=True, max_auth_tries=10, login_grace_time=300,
        x11_forwarding=True, allow_tcp_forwarding='yes', allow_agent_forwarding=True,
        ciphers=['3des-cbc'], macs=['hmac-sha1'], kex_algorithms=['diffie-hellman-group1-sha1'],
    )
    ids = {f['id'] for f in _build_findings(cfg)}
    assert ids == {
        'SSH-AUTH-004', 'SSH-AUTH-005', 'SSH-AUTH-006', 'SSH-AUTH-007', 'SSH-AUTH-008',
        'SSH-FWD-001', 'SSH-FWD-002', 'SSH-FWD-003',
        'SSH-CRYPTO-001', 'SSH-CRYPTO-002', 'SSH-CRYPTO-003',
    }


def test_findings_crypto_na_produces_no_finding():
    # empty crypto lists are N/A (section 6.4), not FAIL - no finding either
    cfg = _cfg(ciphers=[], macs=[], kex_algorithms=[])
    ids = {f.get('id') for f in _build_findings(cfg)}
    assert ids.isdisjoint({'SSH-CRYPTO-001', 'SSH-CRYPTO-002', 'SSH-CRYPTO-003'})


def test_findings_pubkey_authentication_severity():
    cfg = _cfg(pubkey_authentication=False)
    f = next(f for f in _build_findings(cfg) if f['id'] == 'SSH-AUTH-004')
    assert f['severity'] == 'high'


def test_findings_max_auth_tries_includes_value_in_detail():
    cfg = _cfg(max_auth_tries=12)
    f = next(f for f in _build_findings(cfg) if f['id'] == 'SSH-AUTH-007')
    assert '12' in f['detail']


def test_findings_allow_tcp_forwarding_partial_mode_produces_finding():
    # spec section 6.3: 'local'/'remote' are FAIL too, not just 'yes'
    cfg = _cfg(allow_tcp_forwarding='local')
    ids = {f.get('id') for f in _build_findings(cfg)}
    assert 'SSH-FWD-002' in ids


# ===========================================================================
# audit_ssh_hardening_score(ssh)
# ===========================================================================

def test_audit_ssh_hardening_score_not_installed(fake_ssh):
    fake_ssh.responses = _ssh_responses('', installed=False)
    result = audit_ssh_hardening_score(fake_ssh)
    assert result == {'installed': False}


def test_audit_ssh_hardening_score_unreadable_config(fake_ssh):
    fake_ssh.responses = {
        'which sshd': ('/usr/sbin/sshd', ''),
        'sshd -V': ('', 'OpenSSH_10.2p1'),
        'sshd -T': ('', ''),
    }
    result = audit_ssh_hardening_score(fake_ssh)
    assert result['installed'] is True
    assert 'error' in result
    assert 'requires root' in result['error']
    assert 'hardening' not in result


def test_audit_ssh_hardening_score_full_result_hardened(fake_ssh):
    fake_ssh.responses = _ssh_responses(SSHD_T_HARDENED)
    result = audit_ssh_hardening_score(fake_ssh)
    assert result['installed'] is True
    assert result['hardening']['score'] == 100
    assert result['hardening']['max'] == 100
    assert len(result['hardening']['components']) == 14
    assert result['findings'] == []


def test_audit_ssh_hardening_score_full_result_weak(fake_ssh):
    fake_ssh.responses = _ssh_responses(SSHD_T_WEAK)
    result = audit_ssh_hardening_score(fake_ssh)
    assert result['installed'] is True
    assert result['hardening']['score'] < 100
    # SSH-AUTH-001/002/003 shouldn't appear here - covered elsewhere
    ids = {f['id'] for f in result['findings']}
    assert ids.isdisjoint({'SSH-AUTH-001', 'SSH-AUTH-002', 'SSH-AUTH-003'})
    # but several self-generated findings should fire on this weak config
    assert 'SSH-FWD-001' in ids
    assert 'SSH-CRYPTO-002' in ids


def test_audit_ssh_hardening_score_does_not_duplicate_root_login_finding(fake_ssh):
    # the component for permit_root_login can carry finding_id='SSH-AUTH-001'
    # (referencing audit_ssh_hardening()'s finding), but this module's OWN
    # findings list must never contain it.
    fake_ssh.responses = _ssh_responses(SSHD_T_WEAK)
    result = audit_ssh_hardening_score(fake_ssh)
    titles = {f['title'] for f in result['findings']}
    assert 'PermitRootLogin yes' not in titles
    assert 'PasswordAuthentication yes' not in titles


def test_audit_ssh_hardening_score_single_ssh_session(fake_ssh):
    fake_ssh.responses = _ssh_responses(SSHD_T_HARDENED)
    audit_ssh_hardening_score(fake_ssh)
    sshd_t_calls = [c for c in fake_ssh.calls if 'sshd -T' in c]
    assert len(sshd_t_calls) == 1


# ===========================================================================
# check_ssh_hardening(...) - registry entrypoint
# ===========================================================================

def test_check_ssh_hardening_no_host():
    result = check_ssh_hardening(host='')
    assert result == {'error': 'host not specified'}


def test_check_ssh_hardening_happy_path(monkeypatch):
    fake = FakeSSHExecutor(responses=_ssh_responses(SSHD_T_HARDENED))
    monkeypatch.setattr('netaudit_pkg.checks.ssh_hardening.SSHExecutor', lambda *a, **kw: fake)
    result = check_ssh_hardening(host='10.0.0.5')
    assert result['installed'] is True
    assert result['hardening']['score'] == 100
    assert fake.closed is True


def test_check_ssh_hardening_closes_ssh_even_on_error(monkeypatch):
    fake = FakeSSHExecutor(responses={'which sshd': ('NONE', '')})
    monkeypatch.setattr('netaudit_pkg.checks.ssh_hardening.SSHExecutor', lambda *a, **kw: fake)
    check_ssh_hardening(host='10.0.0.5')
    assert fake.closed is True


def test_check_ssh_hardening_connection_failure(monkeypatch):
    class _BoomSSH:
        def __init__(self, *a, **kw):
            pass

        def connect(self):
            raise ConnectionRefusedError('connection refused')

    monkeypatch.setattr('netaudit_pkg.checks.ssh_hardening.SSHExecutor', _BoomSSH)
    result = check_ssh_hardening(host='10.0.0.5')
    assert 'error' in result
    assert 'could not connect' in result['error']


def test_check_ssh_hardening_host_key_mismatch(monkeypatch):
    class _MismatchSSH:
        def __init__(self, *a, **kw):
            pass

        def connect(self):
            raise HostKeyMismatchError('host key changed for 10.0.0.5')

    monkeypatch.setattr('netaudit_pkg.checks.ssh_hardening.SSHExecutor', _MismatchSSH)
    result = check_ssh_hardening(host='10.0.0.5')
    assert 'error' in result
    assert 'host key changed' in result['error']


def test_check_ssh_hardening_registered_as_hardening_category():
    from netaudit_pkg.registry import registry
    spec = registry.get('ssh_hardening')
    assert spec is not None
    assert spec.category == 'hardening'
