"""Tests for netaudit_pkg.checks.cert_transparency: date parsing, graceful
handling of crt.sh's known instability, and the findings logic (sensitive
hostnames, unexpected issuer, wildcards)."""

from __future__ import annotations

import httpx

from netaudit_pkg.checks.cert_transparency import (
    _parse_crtsh_date, _extract_hostnames, check_cert_transparency,
)


# ===========================================================================
# _parse_crtsh_date
# ===========================================================================

def test_parse_date_without_fractional_seconds():
    dt = _parse_crtsh_date('2024-01-01T00:00:00')
    assert dt is not None
    assert dt.year == 2024


def test_parse_date_with_fractional_seconds():
    dt = _parse_crtsh_date('2024-01-01T00:00:00.123456')
    assert dt is not None


def test_parse_date_empty_string():
    assert _parse_crtsh_date('') is None


def test_parse_date_garbage():
    assert _parse_crtsh_date('not a date') is None


# ===========================================================================
# _extract_hostnames
# ===========================================================================

def test_extract_hostnames_single_line():
    cert = {'name_value': 'example.com'}
    assert _extract_hostnames(cert) == {'example.com'}


def test_extract_hostnames_multiple_san_entries():
    cert = {'name_value': 'example.com\nwww.example.com\nstaging.example.com'}
    assert _extract_hostnames(cert) == {'example.com', 'www.example.com', 'staging.example.com'}


def test_extract_hostnames_lowercases():
    cert = {'name_value': 'EXAMPLE.COM'}
    assert _extract_hostnames(cert) == {'example.com'}


# ===========================================================================
# Graceful handling of crt.sh instability — this is the documented reason
# the module has a short timeout, so it's worth testing each failure path
# individually.
# ===========================================================================

def test_timeout_returns_clear_error(monkeypatch):
    def raise_timeout(*a, **kw):
        raise httpx.TimeoutException('timed out')
    monkeypatch.setattr(httpx, 'get', raise_timeout)
    result = check_cert_transparency(domain='example.com')
    assert 'error' in result
    assert 'did not respond' in result['error']


def test_http_error_status_returns_clear_error(monkeypatch):
    def raise_status(*a, **kw):
        class FakeResponse:
            status_code = 503
        raise httpx.HTTPStatusError('server error', request=None, response=FakeResponse())
    monkeypatch.setattr(httpx, 'get', raise_status)
    result = check_cert_transparency(domain='example.com')
    assert 'error' in result
    assert '503' in result['error']


def test_non_json_response_returns_clear_error(monkeypatch):
    def fake_get(*a, **kw):
        class R:
            def raise_for_status(self): pass
            def json(self): raise ValueError('not json')
        return R()
    monkeypatch.setattr(httpx, 'get', fake_get)
    result = check_cert_transparency(domain='example.com')
    assert 'error' in result


def test_empty_response_is_not_an_error(monkeypatch):
    """No certs found means the domain likely doesn't use HTTPS or isn't in
    CT logs yet - that's informational, not a failure."""
    def fake_get(*a, **kw):
        class R:
            def raise_for_status(self): pass
            def json(self): return []
        return R()
    monkeypatch.setattr(httpx, 'get', fake_get)
    result = check_cert_transparency(domain='example.com')
    assert 'error' not in result
    assert result['total_certificates'] == 0


# ===========================================================================
# Findings logic
# ===========================================================================

def _fake_get_with_certs(certs):
    def fake_get(*a, **kw):
        class R:
            def raise_for_status(self): pass
            def json(self): return certs
        return R()
    return fake_get


def test_sensitive_hostname_detected(monkeypatch):
    certs = [{'id': 1, 'name_value': 'staging.example.com', 'issuer_name': "Let's Encrypt",
              'not_after': '2099-01-01T00:00:00'}]
    monkeypatch.setattr(httpx, 'get', _fake_get_with_certs(certs))
    result = check_cert_transparency(domain='example.com')
    assert any('sensitive hostname' in f['title'] for f in result['findings'])


def test_ordinary_hostname_not_flagged(monkeypatch):
    certs = [{'id': 1, 'name_value': 'www.example.com', 'issuer_name': "Let's Encrypt",
              'not_after': '2099-01-01T00:00:00'}]
    monkeypatch.setattr(httpx, 'get', _fake_get_with_certs(certs))
    result = check_cert_transparency(domain='example.com')
    assert not any('sensitive hostname' in f['title'] for f in result['findings'])
    assert result['summary']['ok'] == 1


def test_unexpected_issuer_flagged_when_specified(monkeypatch):
    certs = [{'id': 1, 'name_value': 'example.com', 'issuer_name': 'Suspicious CA Inc',
              'not_after': '2099-01-01T00:00:00'}]
    monkeypatch.setattr(httpx, 'get', _fake_get_with_certs(certs))
    result = check_cert_transparency(domain='example.com', expected_issuer_contains="Let's Encrypt")
    unexpected = next(f for f in result['findings'] if 'unexpected issuer' in f['title'])
    assert unexpected['severity'] == 'high'


def test_expected_issuer_not_flagged(monkeypatch):
    certs = [{'id': 1, 'name_value': 'example.com', 'issuer_name': "Let's Encrypt Authority X3",
              'not_after': '2099-01-01T00:00:00'}]
    monkeypatch.setattr(httpx, 'get', _fake_get_with_certs(certs))
    result = check_cert_transparency(domain='example.com', expected_issuer_contains="Let's Encrypt")
    assert not any('unexpected issuer' in f['title'] for f in result['findings'])


def test_wildcard_certificate_flagged_low():
    from netaudit_pkg.checks.cert_transparency import WILDCARD_RE
    assert WILDCARD_RE.match('*.example.com')
    assert not WILDCARD_RE.match('www.example.com')


def test_unrelated_domain_san_filtered_out(monkeypatch):
    """A multi-domain cert covering both example.com and unrelated-site.com
    should only surface the example.com hostname, not the unrelated one."""
    certs = [{'id': 1, 'name_value': 'example.com\nunrelated-site.com',
              'issuer_name': "Let's Encrypt", 'not_after': '2099-01-01T00:00:00'}]
    monkeypatch.setattr(httpx, 'get', _fake_get_with_certs(certs))
    result = check_cert_transparency(domain='example.com')
    assert 'example.com' in result['subdomains']
    assert 'unrelated-site.com' not in result['subdomains']


def test_expired_certificates_excluded_by_default(monkeypatch):
    certs = [{'id': 1, 'name_value': 'old.example.com', 'issuer_name': "Let's Encrypt",
              'not_after': '2020-01-01T00:00:00'}]  # expired
    monkeypatch.setattr(httpx, 'get', _fake_get_with_certs(certs))
    result = check_cert_transparency(domain='example.com', include_expired=False)
    assert result['active_certificates'] == 0


def test_empty_domain_rejected():
    result = check_cert_transparency(domain='')
    assert 'error' in result
