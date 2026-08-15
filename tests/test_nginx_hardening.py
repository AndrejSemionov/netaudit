"""
Tests for netaudit_pkg.checks.nginx_hardening beyond _build_components() (see
test_nginx_hardening_components.py for the pure-function control tests).
Covers:
  - _build_findings(): the two self-generated findings (NGX-TLS-002, NGX-EXP-001)
  - audit_nginx_hardening(ssh): the full internal API against an already-
    connected SSHExecutor
  - check_nginx_hardening(...): the registry entrypoint, including SSH
    connection failure and HostKeyMismatchError handling
"""

from __future__ import annotations

from netaudit_pkg.nginx_config import NginxConfig
from netaudit_pkg.checks.nginx_hardening import (
    _build_findings, audit_nginx_hardening, check_nginx_hardening,
)
from netaudit_pkg.ssh import HostKeyMismatchError
from tests.conftest import FakeSSHExecutor


def _cfg(**kwargs) -> NginxConfig:
    defaults = dict(
        installed=True, readable=True, server_tokens='off',
        ssl_protocols=['TLSv1.3'], has_ssl_certificate=True,
        headers_present={'strict-transport-security', 'x-frame-options', 'x-content-type-options'},
        autoindex_on=False,
    )
    defaults.update(kwargs)
    return NginxConfig(**defaults)


NGINX_T_HARDENED = """\
http {
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Content-Security-Policy "default-src 'self'";
    add_header Referrer-Policy no-referrer;
    add_header Permissions-Policy "geolocation=()";
    server {
        listen 443 ssl;
        ssl_certificate /etc/ssl/certs/example.pem;
        ssl_protocols TLSv1.3;
        ssl_ciphers ALL:@SECLEVEL=2;
        client_max_body_size 10m;
        server_tokens off;
        server_name example.com;
    }
    server {
        listen 80;
        server_name example.com;
        return 301 https://$host$request_uri;
    }
}
"""

NGINX_T_WEAK = """\
server {
    listen 443 ssl;
    ssl_certificate /etc/ssl/certs/example.pem;
    ssl_protocols TLSv1 TLSv1.1;
    server_tokens on;
    autoindex on;
}
"""


def _ssh_responses(conf: str, *, installed=True) -> dict:
    if not installed:
        return {'which nginx': ('NONE', '')}
    return {
        'which nginx': ('/usr/sbin/nginx', ''),
        'nginx -v': ('nginx/1.24.0', ''),
        'nginx -T': (conf, ''),
    }


# ===========================================================================
# _build_findings() - NGX-TLS-002
# ===========================================================================

def test_findings_empty_when_tls13_present():
    findings = _build_findings(_cfg(ssl_protocols=['TLSv1.3']))
    assert not any(f['id'] == 'NGX-TLS-002' for f in findings if 'id' in f)


def test_findings_tls_modern_warn_produces_finding():
    findings = _build_findings(_cfg(ssl_protocols=['TLSv1.2']))
    f = next(f for f in findings if f.get('id') == 'NGX-TLS-002')
    assert f['severity'] == 'low'
    assert 'TLS 1.3' in f['title']


def test_findings_tls_modern_fail_produces_finding():
    findings = _build_findings(_cfg(ssl_protocols=['TLSv1', 'TLSv1.1']))
    f = next(f for f in findings if f.get('id') == 'NGX-TLS-002')
    assert f['severity'] == 'low'
    assert 'no modern TLS' in f['title']


def test_findings_tls_modern_na_produces_no_finding():
    findings = _build_findings(_cfg(ssl_protocols=[], has_ssl_certificate=False))
    assert not any(f.get('id') == 'NGX-TLS-002' for f in findings)


# ===========================================================================
# _build_findings() - NGX-EXP-001
# ===========================================================================

def test_findings_empty_when_cert_present():
    findings = _build_findings(_cfg(has_ssl_certificate=True))
    assert not any(f.get('id') == 'NGX-EXP-001' for f in findings)


def test_findings_no_cert_produces_finding():
    findings = _build_findings(_cfg(has_ssl_certificate=False, ssl_protocols=[]))
    f = next(f for f in findings if f.get('id') == 'NGX-EXP-001')
    assert f['severity'] == 'high'
    assert 'no TLS certificate' in f['title']


# ===========================================================================
# _build_findings() - shape
# ===========================================================================

def test_findings_fully_hardened_config_produces_no_findings():
    findings = _build_findings(_cfg())
    assert findings == []


def test_findings_only_contains_the_two_self_generated_controls():
    # every id present must be one of the two this module generates itself -
    # everything else belongs to audit_nginx(), not here (spec section 5)
    findings = _build_findings(_cfg(ssl_protocols=['TLSv1.2'], has_ssl_certificate=False))
    ids = {f.get('id') for f in findings if 'id' in f}
    assert ids <= {'NGX-TLS-002', 'NGX-EXP-001'}


# ===========================================================================
# audit_nginx_hardening(ssh)
# ===========================================================================

def test_audit_nginx_hardening_not_installed(fake_ssh):
    fake_ssh.responses = _ssh_responses('', installed=False)
    result = audit_nginx_hardening(fake_ssh)
    assert result == {'installed': False}


def test_audit_nginx_hardening_unreadable_config(fake_ssh):
    fake_ssh.responses = {
        'which nginx': ('/usr/sbin/nginx', ''),
        'nginx -v': ('nginx version: nginx/1.24.0', ''),
        'nginx -T': ('', ''),
    }
    result = audit_nginx_hardening(fake_ssh)
    assert result['installed'] is True
    assert 'error' in result
    assert 'requires root' in result['error']
    assert 'hardening' not in result


def test_audit_nginx_hardening_full_result_hardened(fake_ssh):
    fake_ssh.responses = _ssh_responses(NGINX_T_HARDENED)
    result = audit_nginx_hardening(fake_ssh)
    assert result['installed'] is True
    assert result['hardening']['score'] == 100
    assert result['hardening']['max'] == 100
    assert len(result['hardening']['components']) == 16
    assert result['findings'] == []


def test_audit_nginx_hardening_full_result_weak(fake_ssh):
    fake_ssh.responses = _ssh_responses(NGINX_T_WEAK)
    result = audit_nginx_hardening(fake_ssh)
    assert result['installed'] is True
    assert result['hardening']['score'] < 100
    # NGX-EXP-001 shouldn't fire - this config has a cert, just weak TLS/config
    assert not any(f.get('id') == 'NGX-EXP-001' for f in result['findings'])
    # legacy TLS present, no modern protocol at all -> NGX-TLS-002 FAIL finding
    assert any(f.get('id') == 'NGX-TLS-002' for f in result['findings'])


def test_audit_nginx_hardening_does_not_call_audit_nginx_findings(fake_ssh):
    # audit_nginx_hardening()'s own findings list must only ever contain the
    # two self-generated controls - it must not also include audit_nginx()'s
    # findings (e.g. 'server_tokens is not disabled') merged in, since the
    # spec deliberately keeps these as two separate lists linked by
    # finding_id, not one combined list (section 5).
    fake_ssh.responses = _ssh_responses(NGINX_T_WEAK)
    result = audit_nginx_hardening(fake_ssh)
    titles = {f['title'] for f in result['findings']}
    assert 'server_tokens is not disabled' not in titles
    assert 'autoindex on' not in titles


def test_audit_nginx_hardening_two_nginx_t_calls_for_tier1_and_tier2(fake_ssh):
    # Known, accepted v1 tradeoff (see collect_nginx_config_v2()'s
    # docstring in nginx_config_v2.py, and docs/checks/nginx_hardening.md
    # section 7's Tier-2 planning): audit_nginx_hardening() runs `nginx -T`
    # twice over the same SSH session - once for the legacy NginxConfig
    # (Tier-1), once for NginxConfigV2 (Tier-2). This is NOT a bug; a
    # shared-collection refactor is explicitly deferred. This test exists
    # to make the tradeoff visible in the test suite, not to enforce a
    # single call.
    fake_ssh.responses = _ssh_responses(NGINX_T_HARDENED)
    audit_nginx_hardening(fake_ssh)
    nginx_t_calls = [c for c in fake_ssh.calls if 'nginx -T' in c]
    assert len(nginx_t_calls) == 2


# ===========================================================================
# check_nginx_hardening(...) - registry entrypoint
# ===========================================================================

def test_check_nginx_hardening_no_host():
    result = check_nginx_hardening(host='')
    assert result == {'error': 'host not specified'}


def test_check_nginx_hardening_happy_path(monkeypatch):
    fake = FakeSSHExecutor(responses=_ssh_responses(NGINX_T_HARDENED))
    monkeypatch.setattr('netaudit_pkg.checks.nginx_hardening.SSHExecutor', lambda *a, **kw: fake)
    result = check_nginx_hardening(host='10.0.0.5')
    assert result['installed'] is True
    assert result['hardening']['score'] == 100
    assert fake.closed is True


def test_check_nginx_hardening_closes_ssh_even_on_error(monkeypatch):
    fake = FakeSSHExecutor(responses={'which nginx': ('NONE', '')})
    monkeypatch.setattr('netaudit_pkg.checks.nginx_hardening.SSHExecutor', lambda *a, **kw: fake)
    check_nginx_hardening(host='10.0.0.5')
    assert fake.closed is True


def test_check_nginx_hardening_connection_failure(monkeypatch):
    class _BoomSSH:
        def __init__(self, *a, **kw):
            pass

        def connect(self):
            raise ConnectionRefusedError('connection refused')

    monkeypatch.setattr('netaudit_pkg.checks.nginx_hardening.SSHExecutor', _BoomSSH)
    result = check_nginx_hardening(host='10.0.0.5')
    assert 'error' in result
    assert 'could not connect' in result['error']


def test_check_nginx_hardening_host_key_mismatch(monkeypatch):
    class _MismatchSSH:
        def __init__(self, *a, **kw):
            pass

        def connect(self):
            raise HostKeyMismatchError('host key changed for 10.0.0.5')

    monkeypatch.setattr('netaudit_pkg.checks.nginx_hardening.SSHExecutor', _MismatchSSH)
    result = check_nginx_hardening(host='10.0.0.5')
    assert 'error' in result
    assert 'host key changed' in result['error']


def test_check_nginx_hardening_registered_as_hardening_category():
    from netaudit_pkg.registry import registry
    spec = registry.get('nginx_hardening')
    assert spec is not None
    assert spec.category == 'hardening'
