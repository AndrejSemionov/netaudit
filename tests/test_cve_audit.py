"""Tests for netaudit_pkg.checks.cve_audit: package version collection over
SSH, OSV.dev query/cache logic, and CVSS-to-severity mapping."""

from __future__ import annotations

import httpx
import pytest

from netaudit_pkg.checks.cve_audit import (
    _parse_version, collect_packages, query_osv, fetch_vuln_details,
    check_cve_audit,
)
from tests.conftest import FakeSSHExecutor


# ===========================================================================
# _parse_version
# ===========================================================================

@pytest.mark.parametrize('text,expected', [
    ('nginx version: nginx/1.24.0', '1.24.0'),
    ('OpenSSH_9.6p1 Ubuntu-3ubuntu13', '9.6'),
    ('PHP 8.3.6 (cli)', '8.3.6'),
    ('no version here', None),
    ('', None),
])
def test_parse_version(text, expected):
    assert _parse_version(text) == expected


# ===========================================================================
# collect_packages
# ===========================================================================

def test_collect_packages_finds_nginx():
    fake = FakeSSHExecutor(responses={'nginx -v': ('nginx version: nginx/1.24.0', '')})
    packages = collect_packages(fake)
    nginx = next(p for p in packages if p['name'] == 'nginx')
    assert nginx['version'] == '1.24.0'
    assert nginx['ecosystem'] == 'Debian'


def test_collect_packages_distinguishes_mariadb_from_mysql():
    fake = FakeSSHExecutor(responses={
        'mysql --version': ('mysql  Ver 15.1 Distrib 10.11.6-MariaDB', ''),
    })
    packages = collect_packages(fake)
    db_pkg = next((p for p in packages if p['name'] in ('mysql', 'mariadb')), None)
    assert db_pkg is not None
    assert db_pkg['name'] == 'mariadb'


def test_collect_packages_finds_wordpress():
    fake = FakeSSHExecutor(responses={
        "find /var/www": ('/var/www/html/wp-includes\n', ''),
        'wp_version': ("$wp_version = '6.5.2';", ''),
    })
    packages = collect_packages(fake)
    wp = next((p for p in packages if p['name'] == 'wordpress'), None)
    assert wp is not None
    assert wp['version'] == '6.5.2'
    assert wp['ecosystem'] == 'WordPress'


def test_collect_packages_skips_services_not_found():
    fake = FakeSSHExecutor(responses={})  # nothing installed, all commands return ''
    packages = collect_packages(fake)
    assert packages == []


# ===========================================================================
# query_osv — caching behavior
# ===========================================================================

def test_query_osv_uses_cache_when_fresh(isolated_db, monkeypatch):
    isolated_db.cve_set('nginx::1.24.0', ['CVE-2024-0001'])

    def fail_if_called(*args, **kwargs):
        raise AssertionError('should not hit the network when cache is fresh')

    monkeypatch.setattr(httpx, 'post', fail_if_called)
    result = query_osv([{'name': 'nginx', 'version': '1.24.0', 'ecosystem': 'Debian'}])
    assert result['nginx'] == ['CVE-2024-0001']


def test_query_osv_queries_network_when_not_cached(isolated_db, monkeypatch):
    def fake_post(url, json, timeout):
        class R:
            def raise_for_status(self): pass
            def json(self): return {'results': [{'vulns': [{'id': 'CVE-2024-9999'}]}]}
        return R()

    monkeypatch.setattr(httpx, 'post', fake_post)
    result = query_osv([{'name': 'nginx', 'version': '1.24.0', 'ecosystem': 'Debian'}])
    assert result['nginx'] == ['CVE-2024-9999']
    # and it should now be cached
    cached = isolated_db.cve_get('nginx::1.24.0')
    assert cached['data'] == ['CVE-2024-9999']


def test_query_osv_network_failure_does_not_raise(isolated_db, monkeypatch):
    def fake_post(*a, **kw):
        raise httpx.HTTPError('connection refused')

    monkeypatch.setattr(httpx, 'post', fake_post)
    result = query_osv([{'name': 'nginx', 'version': '1.24.0', 'ecosystem': 'Debian'}])
    assert result['nginx'] == []  # empty, not an exception


# ===========================================================================
# fetch_vuln_details
# ===========================================================================

def test_fetch_vuln_details_parses_cvss_and_fixed_versions(monkeypatch):
    def fake_get(url, timeout):
        class R:
            def raise_for_status(self): pass
            def json(self):
                return {
                    'summary': 'Buffer overflow in foo',
                    'severity': [{'type': 'CVSS_V3', 'score': '9.8/AV:N/AC:L'}],
                    'affected': [{'ranges': [{'events': [{'introduced': '0'}, {'fixed': '1.24.1'}]}]}],
                    'references': [{'url': 'https://example.com/advisory'}],
                }
        return R()

    monkeypatch.setattr(httpx, 'get', fake_get)
    details = fetch_vuln_details('CVE-2024-0001')
    assert details['summary'] == 'Buffer overflow in foo'
    assert details['severity'] == '9.8/AV:N/AC:L'
    assert details['fixed_versions'] == ['1.24.1']


def test_fetch_vuln_details_network_error_returns_error_dict(monkeypatch):
    def fake_get(*a, **kw):
        raise httpx.HTTPError('timeout')

    monkeypatch.setattr(httpx, 'get', fake_get)
    details = fetch_vuln_details('CVE-2024-0001')
    assert 'error' in details


# ===========================================================================
# Full check_cve_audit flow
# ===========================================================================

def test_full_flow_no_packages_found(monkeypatch, isolated_db):
    fake = FakeSSHExecutor(responses={})
    monkeypatch.setattr('netaudit_pkg.checks.cve_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_cve_audit(host='1.2.3.4')
    assert result['packages'] == []
    assert result['summary']['ok'] == 0


def test_full_flow_package_with_no_cves(monkeypatch, isolated_db):
    fake = FakeSSHExecutor(responses={'nginx -v': ('nginx version: nginx/1.24.0', '')})
    monkeypatch.setattr('netaudit_pkg.checks.cve_audit.SSHExecutor', lambda *a, **kw: fake)

    def fake_post(url, json, timeout):
        class R:
            def raise_for_status(self): pass
            def json(self): return {'results': [{'vulns': []}]}
        return R()

    monkeypatch.setattr(httpx, 'post', fake_post)
    result = check_cve_audit(host='1.2.3.4')
    assert result['summary']['ok'] == 1
    assert result['findings'][0]['title'] == 'no known CVEs found'


@pytest.mark.parametrize('score,expected_severity', [
    ('9.8', 'critical'),
    ('7.5', 'high'),
    ('5.0', 'medium'),
    ('2.0', 'low'),
    (None, 'medium'),  # unknown score is not downplayed to low
])
def test_full_flow_severity_mapping(monkeypatch, isolated_db, score, expected_severity):
    fake = FakeSSHExecutor(responses={'nginx -v': ('nginx version: nginx/1.24.0', '')})
    monkeypatch.setattr('netaudit_pkg.checks.cve_audit.SSHExecutor', lambda *a, **kw: fake)

    def fake_post(url, json, timeout):
        class R:
            def raise_for_status(self): pass
            def json(self): return {'results': [{'vulns': [{'id': 'CVE-2024-0001'}]}]}
        return R()

    def fake_get(url, timeout):
        class R:
            def raise_for_status(self): pass
            def json(self):
                sev = [{'type': 'CVSS_V3', 'score': score}] if score else []
                return {'summary': 'test vuln', 'severity': sev, 'affected': [], 'references': []}
        return R()

    monkeypatch.setattr(httpx, 'post', fake_post)
    monkeypatch.setattr(httpx, 'get', fake_get)
    result = check_cve_audit(host='1.2.3.4')
    assert result['summary'][expected_severity] == 1


def test_empty_host_rejected():
    result = check_cve_audit(host='')
    assert 'error' in result
