"""
Tests that audit_nginx()'s findings carry the correct, stable control ID
(Finding.id) matching docs/checks/nginx_hardening.md's control catalogue -
this is what will let the future nginx_hardening check's Component.finding_id
reference these exact findings instead of re-deriving its own.

Two findings deliberately have NO id (see audit_nginx()'s docstring):
  - "no access to the config" - not a control, it's the whole-group N/A signal
  - "no obvious issues found" - the aggregate ok-fallback, not one control

Everything else must carry a control id from the spec: NGX-CONF-001/002,
NGX-TLS-001/003, NGX-HDR-001/002/003.
"""

from __future__ import annotations

from netaudit_pkg.checks.server_security import audit_nginx
from tests.conftest import FakeSSHExecutor

# every control ID referenced anywhere in docs/checks/nginx_hardening.md's
# Tier 1 catalogue (section 6) - used to assert audit_nginx() never invents
# an id outside the documented catalogue.
SPEC_CONTROL_IDS = {
    'NGX-TLS-001', 'NGX-TLS-002', 'NGX-TLS-003',
    'NGX-HDR-001', 'NGX-HDR-002', 'NGX-HDR-003',
    'NGX-CONF-001', 'NGX-CONF-002',
    'NGX-EXP-001',
}


def _all_findings_config() -> str:
    """A config that trips every ID-bearing finding at once, so a single run
    can assert all expected IDs appear together with no duplicates."""
    return (
        # server_tokens left unset -> NGX-CONF-001 FAIL
        'ssl_protocols TLSv1 TLSv1.1;\n'  # -> NGX-TLS-001 FAIL
        # no ssl_certificate directive, so NGX-TLS-003's elif branch won't
        # fire here - covered separately below
        'location /files {\n    autoindex on;\n}'  # -> NGX-CONF-002 FAIL
        # no add_header lines at all -> NGX-HDR-001/002/003 all FAIL
    )


def test_unreadable_config_finding_has_no_id():
    fake = FakeSSHExecutor(responses={
        'which nginx': ('/usr/sbin/nginx', ''),
        'nginx -v': ('nginx/1.24.0', ''),
        'nginx -T': ('', ''),
    })
    result = audit_nginx(fake)
    assert 'id' not in result['findings'][0]


def test_ok_fallback_finding_has_no_id():
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
    assert 'id' not in result['findings'][0]


def test_server_tokens_finding_has_correct_id():
    fake = FakeSSHExecutor(responses={
        'which nginx': ('/usr/sbin/nginx', ''),
        'nginx -v': ('nginx/1.24.0', ''),
        'nginx -T': ('server {\n    listen 443;\n}', ''),
    })
    result = audit_nginx(fake)
    f = next(f for f in result['findings'] if f['title'] == 'server_tokens is not disabled')
    assert f['id'] == 'NGX-CONF-001'


def test_outdated_tls_finding_has_correct_id():
    fake = FakeSSHExecutor(responses={
        'which nginx': ('/usr/sbin/nginx', ''),
        'nginx -v': ('nginx/1.24.0', ''),
        'nginx -T': ('server_tokens off;\nssl_protocols TLSv1 TLSv1.1 TLSv1.2;', ''),
    })
    result = audit_nginx(fake)
    f = next(f for f in result['findings'] if f['title'] == 'outdated TLS 1.0/1.1 is enabled')
    assert f['id'] == 'NGX-TLS-001'


def test_ssl_protocols_not_set_finding_has_correct_id():
    fake = FakeSSHExecutor(responses={
        'which nginx': ('/usr/sbin/nginx', ''),
        'nginx -v': ('nginx/1.24.0', ''),
        'nginx -T': ('server_tokens off;\nssl_certificate /etc/nginx/cert.pem;', ''),
    })
    result = audit_nginx(fake)
    f = next(f for f in result['findings'] if f['title'] == 'ssl_protocols is not set explicitly')
    assert f['id'] == 'NGX-TLS-003'


def test_missing_header_findings_have_correct_ids():
    fake = FakeSSHExecutor(responses={
        'which nginx': ('/usr/sbin/nginx', ''),
        'nginx -v': ('nginx/1.24.0', ''),
        'nginx -T': ('server_tokens off;\nssl_protocols TLSv1.2 TLSv1.3;', ''),
    })
    result = audit_nginx(fake)
    by_title = {f['title']: f['id'] for f in result['findings'] if 'id' in f}
    assert by_title['missing header Strict-Transport-Security'] == 'NGX-HDR-001'
    assert by_title['missing header X-Frame-Options'] == 'NGX-HDR-002'
    assert by_title['missing header X-Content-Type-Options'] == 'NGX-HDR-003'


def test_autoindex_finding_has_correct_id():
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
    f = next(f for f in result['findings'] if f['title'] == 'autoindex on')
    assert f['id'] == 'NGX-CONF-002'


def test_all_ids_are_unique_within_one_run():
    fake = FakeSSHExecutor(responses={
        'which nginx': ('/usr/sbin/nginx', ''),
        'nginx -v': ('nginx/1.24.0', ''),
        'nginx -T': (_all_findings_config(), ''),
    })
    result = audit_nginx(fake)
    ids = [f['id'] for f in result['findings'] if 'id' in f]
    assert len(ids) == len(set(ids)), f'duplicate finding ids in one run: {ids}'


def test_all_ids_are_within_the_documented_spec_catalogue():
    fake = FakeSSHExecutor(responses={
        'which nginx': ('/usr/sbin/nginx', ''),
        'nginx -v': ('nginx/1.24.0', ''),
        'nginx -T': (_all_findings_config(), ''),
    })
    result = audit_nginx(fake)
    ids = {f['id'] for f in result['findings'] if 'id' in f}
    unexpected = ids - SPEC_CONTROL_IDS
    assert not unexpected, f'audit_nginx() produced an id not in the spec catalogue: {unexpected}'
