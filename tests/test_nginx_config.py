"""
Tests for netaudit_pkg.nginx_config: the nginx -T collector/parser that both
audit_nginx() (findings) and the future nginx_hardening (scoring) consume.
"""

from __future__ import annotations

from netaudit_pkg.nginx_config import collect_nginx_config, _parse_nginx_config


# ===========================================================================
# _parse_nginx_config() — pure parsing, no I/O
# ===========================================================================

def test_parse_server_tokens_off():
    conf = 'server {\n    server_tokens off;\n}'
    cfg = _parse_nginx_config(conf)
    assert cfg.server_tokens == 'off'


def test_parse_server_tokens_on():
    conf = 'server {\n    server_tokens on;\n}'
    cfg = _parse_nginx_config(conf)
    assert cfg.server_tokens == 'on'


def test_parse_server_tokens_not_set():
    conf = 'server {\n    listen 443;\n}'
    cfg = _parse_nginx_config(conf)
    assert cfg.server_tokens is None


def test_parse_ssl_protocols_modern():
    conf = 'ssl_protocols TLSv1.2 TLSv1.3;'
    cfg = _parse_nginx_config(conf)
    assert cfg.ssl_protocols == ['TLSv1.2', 'TLSv1.3']


def test_parse_ssl_protocols_outdated():
    conf = 'ssl_protocols TLSv1 TLSv1.1 TLSv1.2;'
    cfg = _parse_nginx_config(conf)
    assert 'TLSv1' in cfg.ssl_protocols
    assert 'TLSv1.1' in cfg.ssl_protocols


def test_parse_ssl_protocols_absent():
    conf = 'server {\n    listen 443;\n}'
    cfg = _parse_nginx_config(conf)
    assert cfg.ssl_protocols == []


def test_parse_has_ssl_certificate():
    conf = 'ssl_certificate /etc/nginx/cert.pem;'
    cfg = _parse_nginx_config(conf)
    assert cfg.has_ssl_certificate is True


def test_parse_no_ssl_certificate():
    conf = 'server {\n    listen 80;\n}'
    cfg = _parse_nginx_config(conf)
    assert cfg.has_ssl_certificate is False


def test_parse_headers_present():
    conf = 'add_header Strict-Transport-Security "max-age=31536000" always;\n' \
           'add_header X-Frame-Options "DENY" always;'
    cfg = _parse_nginx_config(conf)
    assert 'strict-transport-security' in cfg.headers_present
    assert 'x-frame-options' in cfg.headers_present
    assert 'x-content-type-options' not in cfg.headers_present


def test_parse_autoindex_on():
    conf = 'location /files {\n    autoindex on;\n}'
    cfg = _parse_nginx_config(conf)
    assert cfg.autoindex_on is True


def test_parse_autoindex_off_or_absent():
    conf = 'location /files {\n    autoindex off;\n}'
    cfg = _parse_nginx_config(conf)
    assert cfg.autoindex_on is False


def test_parse_sets_installed_and_readable():
    cfg = _parse_nginx_config('server_tokens off;', version='nginx/1.24.0')
    assert cfg.installed is True
    assert cfg.readable is True
    assert cfg.version == 'nginx/1.24.0'


# ===========================================================================
# collect_nginx_config() — via FakeSSHExecutor
# ===========================================================================

def test_collect_not_installed(fake_ssh):
    fake_ssh.responses = {'which nginx': ('NONE', '')}
    cfg = collect_nginx_config(fake_ssh)
    assert cfg.installed is False
    assert cfg.readable is False


def test_collect_installed_but_unreadable(fake_ssh):
    fake_ssh.responses = {
        'which nginx': ('/usr/sbin/nginx', ''),
        'nginx -v': ('nginx version: nginx/1.24.0', ''),
        'nginx -T': ('', ''),  # no root -> empty output
    }
    cfg = collect_nginx_config(fake_ssh)
    assert cfg.installed is True
    assert cfg.readable is False
    assert cfg.version == 'nginx version: nginx/1.24.0'


def test_collect_full_config(fake_ssh):
    fake_ssh.responses = {
        'which nginx': ('/usr/sbin/nginx', ''),
        'nginx -v': ('nginx version: nginx/1.24.0', ''),
        'nginx -T': ('server_tokens off;\nssl_protocols TLSv1.2 TLSv1.3;\n'
                     'ssl_certificate /etc/nginx/cert.pem;', ''),
    }
    cfg = collect_nginx_config(fake_ssh)
    assert cfg.installed is True
    assert cfg.readable is True
    assert cfg.server_tokens == 'off'
    assert cfg.ssl_protocols == ['TLSv1.2', 'TLSv1.3']
    assert cfg.has_ssl_certificate is True


def test_collect_only_makes_expected_calls(fake_ssh):
    fake_ssh.responses = {'which nginx': ('NONE', '')}
    collect_nginx_config(fake_ssh)
    # not-installed case should short-circuit after the `which` check -
    # no point running `nginx -v`/`nginx -T` against a binary that isn't there
    assert len(fake_ssh.calls) == 1
