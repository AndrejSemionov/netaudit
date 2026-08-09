"""
Backward-compatibility tests for audit_nginx() after the nginx_config.py
collector/parser split (see that module's docstring). audit_nginx()'s
return shape and severity decisions must be unchanged - these tests pin
down the exact behavior that existed before the refactor, using the same
FakeSSHExecutor pattern as the rest of the suite.
"""

from __future__ import annotations

from netaudit_pkg.checks.server_security import audit_nginx
from tests.conftest import FakeSSHExecutor


def test_audit_nginx_not_installed(fake_ssh):
    fake_ssh.responses = {'which nginx': ('NONE', '')}
    result = audit_nginx(fake_ssh)
    assert result == {'installed': False}


def test_audit_nginx_unreadable_config(fake_ssh):
    fake_ssh.responses = {
        'which nginx': ('/usr/sbin/nginx', ''),
        'nginx -v': ('nginx version: nginx/1.24.0', ''),
        'nginx -T': ('', ''),
    }
    result = audit_nginx(fake_ssh)
    assert result['installed'] is True
    assert len(result['findings']) == 1
    assert result['findings'][0]['severity'] == 'low'
    assert 'no access to the config' in result['findings'][0]['title']


def test_audit_nginx_server_tokens_not_disabled():
    fake = FakeSSHExecutor(responses={
        'which nginx': ('/usr/sbin/nginx', ''),
        'nginx -v': ('nginx/1.24.0', ''),
        'nginx -T': ('server {\n    listen 443;\n}', ''),  # no server_tokens directive
    })
    result = audit_nginx(fake)
    titles = [f['title'] for f in result['findings']]
    assert 'server_tokens is not disabled' in titles


def test_audit_nginx_server_tokens_off_no_finding():
    fake = FakeSSHExecutor(responses={
        'which nginx': ('/usr/sbin/nginx', ''),
        'nginx -v': ('nginx/1.24.0', ''),
        'nginx -T': ('server_tokens off;\nssl_protocols TLSv1.2 TLSv1.3;\n'
                     'add_header Strict-Transport-Security "max-age=1" always;\n'
                     'add_header X-Frame-Options DENY always;\n'
                     'add_header X-Content-Type-Options nosniff always;', ''),
    })
    result = audit_nginx(fake)
    titles = [f['title'] for f in result['findings']]
    assert 'server_tokens is not disabled' not in titles


def test_audit_nginx_outdated_tls_detected():
    fake = FakeSSHExecutor(responses={
        'which nginx': ('/usr/sbin/nginx', ''),
        'nginx -v': ('nginx/1.24.0', ''),
        'nginx -T': ('server_tokens off;\nssl_protocols TLSv1 TLSv1.1 TLSv1.2;', ''),
    })
    result = audit_nginx(fake)
    tls_findings = [f for f in result['findings'] if 'TLS 1.0/1.1' in f['title']]
    assert len(tls_findings) == 1
    assert tls_findings[0]['severity'] == 'high'


def test_audit_nginx_modern_tls_no_finding():
    fake = FakeSSHExecutor(responses={
        'which nginx': ('/usr/sbin/nginx', ''),
        'nginx -v': ('nginx/1.24.0', ''),
        'nginx -T': ('server_tokens off;\nssl_protocols TLSv1.2 TLSv1.3;', ''),
    })
    result = audit_nginx(fake)
    tls_findings = [f for f in result['findings'] if 'TLS 1.0/1.1' in f['title']]
    assert len(tls_findings) == 0


def test_audit_nginx_missing_headers_detected():
    fake = FakeSSHExecutor(responses={
        'which nginx': ('/usr/sbin/nginx', ''),
        'nginx -v': ('nginx/1.24.0', ''),
        'nginx -T': ('server_tokens off;\nssl_protocols TLSv1.2 TLSv1.3;', ''),
    })
    result = audit_nginx(fake)
    titles = [f['title'] for f in result['findings']]
    assert 'missing header Strict-Transport-Security' in titles
    assert 'missing header X-Frame-Options' in titles
    assert 'missing header X-Content-Type-Options' in titles


def test_audit_nginx_autoindex_on_detected():
    fake = FakeSSHExecutor(responses={
        'which nginx': ('/usr/sbin/nginx', ''),
        'nginx -v': ('nginx/1.24.0', ''),
        'nginx -T': ('server_tokens off;\nssl_protocols TLSv1.2 TLSv1.3;\n'
                     'add_header Strict-Transport-Security "max-age=1" always;\n'
                     'add_header X-Frame-Options DENY always;\n'
                     'add_header X-Content-Type-Options nosniff always;\n'
                     'location /files {\n    autoindex on;\n}', ''),
    })
    result = audit_nginx(fake)
    titles = [f['title'] for f in result['findings']]
    assert 'autoindex on' in titles


def test_audit_nginx_clean_config_gives_ok():
    fake = FakeSSHExecutor(responses={
        'which nginx': ('/usr/sbin/nginx', ''),
        'nginx -v': ('nginx/1.24.0', ''),
        'nginx -T': ('server_tokens off;\nssl_protocols TLSv1.2 TLSv1.3;\n'
                     'add_header Strict-Transport-Security "max-age=1" always;\n'
                     'add_header X-Frame-Options DENY always;\n'
                     'add_header X-Content-Type-Options nosniff always;', ''),
    })
    result = audit_nginx(fake)
    assert len(result['findings']) == 1
    assert result['findings'][0]['severity'] == 'ok'
