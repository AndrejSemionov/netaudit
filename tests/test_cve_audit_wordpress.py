"""
W0 (docs/research/wordpress_audit.md §2, contract C5): OSV has no WordPress
data, so cve_audit used to answer "no known CVEs found" for any WordPress
version. The core status now comes from wordpress.org stable-check; when it
cannot be had, the package is a collection gap, never 'ok'.
"""

from __future__ import annotations

from netaudit_pkg import wordpress_org
from netaudit_pkg.checks import cve_audit

WP = {'name': 'wordpress', 'version': '6.8.3', 'upstream_version': '6.8.3', 'ecosystem': 'WordPress',
      'third_party_repo': False, 'version_collection_ok': True, 'raw': "$wp_version = '6.8.3';"}
NGINX = {'name': 'nginx', 'version': '1.24.0', 'ecosystem': 'Linux'}


class _NoSSH:
    def connect(self):
        return self

    def close(self):
        pass


def _run(monkeypatch, status, packages=None):
    sent = []

    def query_osv(queryable, os_id, version_id):
        sent.extend(p['name'] for p in queryable)
        return {p['name']: [] for p in queryable}, set()

    monkeypatch.setattr(cve_audit, 'SSHExecutor', lambda *a, **k: _NoSSH())
    monkeypatch.setattr(cve_audit, 'collect_packages', lambda ssh: list(packages or [NGINX, WP]))
    monkeypatch.setattr(cve_audit, 'collect_composer_packages', lambda ssh: [])
    monkeypatch.setattr(cve_audit, 'collect_os_release', lambda ssh: ('ubuntu', '24.04'))
    monkeypatch.setattr(cve_audit, 'query_osv', query_osv)
    asked = []

    def core_status(version):
        asked.append(version)
        return status

    monkeypatch.setattr(wordpress_org, 'core_status', core_status)
    return cve_audit.check_cve_audit(host='192.0.2.10'), sent, asked


def _wp(result):
    return [f for f in result['findings'] if f.get('package') == 'wordpress']


def test_wordpress_is_not_sent_to_osv(monkeypatch):
    _, sent, asked = _run(monkeypatch, {'status': 'latest', 'latest': '7.1.5', 'error': None})
    assert sent == ['nginx']
    assert asked == ['6.8.3']


def test_insecure_wordpress_is_high(monkeypatch):
    result, _, _ = _run(monkeypatch, {'status': 'insecure', 'latest': '7.1.5', 'error': None})
    [finding] = _wp(result)
    assert finding['severity'] == 'high'
    assert finding['id'] == 'CVE-WP-001'
    assert '6.8.3' in finding['title']
    assert finding['fixed_versions'] == ['7.1.5']
    assert result['summary']['high'] == 1


def test_outdated_wordpress_is_low(monkeypatch):
    result, _, _ = _run(monkeypatch, {'status': 'outdated', 'latest': '7.1.5', 'error': None})
    [finding] = _wp(result)
    assert finding['severity'] == 'low'
    assert finding['id'] == 'CVE-WP-002'


def test_latest_wordpress_is_ok(monkeypatch):
    result, _, _ = _run(monkeypatch, {'status': 'latest', 'latest': '7.1.5', 'error': None})
    [finding] = _wp(result)
    assert finding['severity'] == 'ok'
    assert 'no known CVEs found' not in finding['title']


def test_wordpress_status_unavailable_is_never_clean(monkeypatch):
    for status in ({'status': 'error', 'latest': None, 'error': 'wordpress.org: HTTP 503'},
                   {'status': 'unknown', 'latest': '7.1.5', 'error': None}):
        result, _, _ = _run(monkeypatch, status)
        [finding] = _wp(result)
        assert finding['severity'] == 'info'
        assert finding['requires_manual_verification'] is True
        assert 'does NOT mean' in finding['title']
        assert result['summary']['collection_error'] == 1
        assert result['summary']['ok'] == 1   # nginx only
