"""Tests for netaudit_pkg.checks.cve_audit: package version collection over
SSH, OS release detection, OSV.dev query/cache logic (including the
Debian:{release} ecosystem fix — see cve_audit.py's module docstring for
the google/osv.dev#4230 background), and CVSS-to-severity mapping."""

from __future__ import annotations

import httpx
import pytest

from netaudit_pkg.checks.cve_audit import (
    _parse_version, _resolve_ecosystem, collect_packages, collect_os_release,
    query_osv, fetch_vuln_details, check_cve_audit,
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
    fake = FakeSSHExecutor(responses={
        'nginx -v': ('nginx version: nginx/1.24.0', ''),
        "dpkg-query -W -f='${Version}' nginx": ('1.24.0-2', ''),
    })
    packages = collect_packages(fake)
    nginx = next(p for p in packages if p['name'] == 'nginx')
    assert nginx['version'] == '1.24.0-2'
    assert nginx['upstream_version'] == '1.24.0'
    assert nginx['ecosystem'] == 'Debian'


def test_collect_packages_nginx_falls_back_to_upstream_without_dpkg():
    """dpkg-query finds nothing (not installed via dpkg) - version falls
    back to the upstream number rather than being left empty."""
    fake = FakeSSHExecutor(responses={
        'nginx -v': ('nginx version: nginx/1.24.0', ''),
    })
    packages = collect_packages(fake)
    nginx = next(p for p in packages if p['name'] == 'nginx')
    assert nginx['version'] == '1.24.0'
    assert nginx['upstream_version'] == '1.24.0'


def test_collect_packages_distinguishes_mariadb_from_mysql():
    fake = FakeSSHExecutor(responses={
        'mysql --version': ('mysql  Ver 15.1 Distrib 10.11.6-MariaDB', ''),
    })
    packages = collect_packages(fake)
    db_pkg = next((p for p in packages if p['name'] in ('mysql', 'mariadb')), None)
    assert db_pkg is not None
    assert db_pkg['name'] == 'mariadb'


def test_collect_packages_uses_dpkg_version_for_mariadb_when_available():
    fake = FakeSSHExecutor(responses={
        'mysql --version': ('mysql  Ver 15.1 Distrib 10.11.6-MariaDB', ''),
        "dpkg-query -W -f='${Version}' mariadb-server": ('1:10.11.6-0+deb12u1', ''),
    })
    packages = collect_packages(fake)
    db_pkg = next(p for p in packages if p['name'] == 'mariadb')
    assert db_pkg['version'] == '1:10.11.6-0+deb12u1'
    # NOTE: upstream_version here reflects a pre-existing, separate bug in
    # _parse_version() - `mysql --version` prints the CLIENT utility
    # version (15.1) before the server version (10.11.6-MariaDB), and the
    # regex takes the first match. Not this fix's scope to correct (see
    # collect_packages' `linux` comment for the same "one fix at a time"
    # reasoning) - documented here so this isn't mistaken for a new
    # regression introduced by the dpkg-version change.
    assert db_pkg['upstream_version'] == '15.1'


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
# _dpkg_version — the debian-revision-vs-upstream-version fix
# ===========================================================================

def test_dpkg_version_returns_full_revision():
    from netaudit_pkg.checks.cve_audit import _dpkg_version
    fake = FakeSSHExecutor(responses={
        "dpkg-query -W -f='${Version}' nginx": ('1.28.3-1~deb13u2\n', ''),
    })
    assert _dpkg_version(fake, 'nginx') == '1.28.3-1~deb13u2'


def test_dpkg_version_returns_none_when_not_dpkg_installed():
    fake = FakeSSHExecutor(responses={})
    from netaudit_pkg.checks.cve_audit import _dpkg_version
    assert _dpkg_version(fake, 'nginx') is None


# ===========================================================================
# collect_os_release — Debian VERSION_ID detection
# ===========================================================================

def test_collect_os_release_parses_version_id():
    fake = FakeSSHExecutor(responses={
        "grep '^VERSION_ID='": ('VERSION_ID="13"\n', ''),
    })
    assert collect_os_release(fake) == '13'


def test_collect_os_release_handles_unquoted_version_id():
    """Some minimal/custom images may not quote the value - the regex
    must not assume quotes are always present."""
    fake = FakeSSHExecutor(responses={
        "grep '^VERSION_ID='": ('VERSION_ID=12\n', ''),
    })
    assert collect_os_release(fake) == '12'


def test_collect_os_release_returns_none_when_file_missing():
    fake = FakeSSHExecutor(responses={})
    assert collect_os_release(fake) is None


def test_collect_os_release_returns_none_on_garbage_output():
    fake = FakeSSHExecutor(responses={
        "grep '^VERSION_ID='": ('not a version line at all', ''),
    })
    assert collect_os_release(fake) is None


# ===========================================================================
# _resolve_ecosystem — the core of the Debian:{release} fix
# ===========================================================================

def test_resolve_ecosystem_debian_with_known_release():
    assert _resolve_ecosystem('Debian', '13') == 'Debian:13'


def test_resolve_ecosystem_debian_without_release_falls_back_to_bare():
    """VERSION_ID couldn't be determined - fall back to the bare 'Debian'
    string rather than skipping the query. Noisy beats nothing, per the
    module docstring."""
    assert _resolve_ecosystem('Debian', None) == 'Debian'


def test_resolve_ecosystem_wordpress_is_never_touched():
    """WordPress is a completely separate OSV ecosystem, unaffected by
    Debian release versioning - must pass through unchanged regardless of
    what debian_version_id is."""
    assert _resolve_ecosystem('WordPress', '13') == 'WordPress'
    assert _resolve_ecosystem('WordPress', None) == 'WordPress'


# ===========================================================================
# query_osv — caching behavior (cache key now includes ecosystem)
# ===========================================================================

def test_query_osv_uses_cache_when_fresh(isolated_db, monkeypatch):
    isolated_db.cve_set('nginx::1.24.0::Debian:13', ['CVE-2024-0001'])

    def fail_if_called(*args, **kwargs):
        raise AssertionError('should not hit the network when cache is fresh')

    monkeypatch.setattr(httpx, 'post', fail_if_called)
    result = query_osv(
        [{'name': 'nginx', 'version': '1.24.0', 'ecosystem': 'Debian'}],
        debian_version_id='13',
    )
    assert result['nginx'] == ['CVE-2024-0001']


def test_query_osv_cache_miss_when_ecosystem_differs(isolated_db, monkeypatch):
    """A cached result under the bare 'Debian' ecosystem (e.g. from before
    this fix, or a host where VERSION_ID couldn't be read) must NOT be
    served for a query now made with 'Debian:13' - this is the specific
    regression this module's fix is designed to prevent (stale noisy
    results silently surviving the ecosystem-string change)."""
    isolated_db.cve_set('nginx::1.24.0::Debian', ['CVE-OLD-NOISY-RESULT'])

    def fake_post(url, json, timeout):
        class R:
            def raise_for_status(self): pass
            def json(self): return {'results': [{'vulns': [{'id': 'CVE-2026-42533'}]}]}
        return R()

    monkeypatch.setattr(httpx, 'post', fake_post)
    result = query_osv(
        [{'name': 'nginx', 'version': '1.24.0', 'ecosystem': 'Debian'}],
        debian_version_id='13',
    )
    assert result['nginx'] == ['CVE-2026-42533']
    assert 'CVE-OLD-NOISY-RESULT' not in result['nginx']


def test_query_osv_queries_network_when_not_cached(isolated_db, monkeypatch):
    def fake_post(url, json, timeout):
        class R:
            def raise_for_status(self): pass
            def json(self): return {'results': [{'vulns': [{'id': 'CVE-2024-9999'}]}]}
        return R()

    monkeypatch.setattr(httpx, 'post', fake_post)
    result = query_osv(
        [{'name': 'nginx', 'version': '1.24.0', 'ecosystem': 'Debian'}],
        debian_version_id='13',
    )
    assert result['nginx'] == ['CVE-2024-9999']
    # and it should now be cached under the release-specific key
    cached = isolated_db.cve_get('nginx::1.24.0::Debian:13')
    assert cached['data'] == ['CVE-2024-9999']


def test_query_osv_sends_release_specific_ecosystem_in_request(isolated_db, monkeypatch):
    """The actual HTTP payload sent to OSV must contain 'Debian:13', not
    the bare 'Debian' - this is the literal fix for google/osv.dev#4230,
    checked at the wire level, not just via the cache key."""
    captured = {}

    def fake_post(url, json, timeout):
        captured['payload'] = json

        class R:
            def raise_for_status(self): pass
            def json(self): return {'results': [{'vulns': []}]}
        return R()

    monkeypatch.setattr(httpx, 'post', fake_post)
    query_osv([{'name': 'nginx', 'version': '1.28.3', 'ecosystem': 'Debian'}],
               debian_version_id='13')
    assert captured['payload']['queries'][0]['package']['ecosystem'] == 'Debian:13'


def test_query_osv_falls_back_to_bare_debian_without_version_id(isolated_db, monkeypatch):
    """When debian_version_id is None (couldn't be determined), the
    request must still go out with the bare 'Debian' ecosystem rather
    than failing or sending an empty/malformed string."""
    captured = {}

    def fake_post(url, json, timeout):
        captured['payload'] = json

        class R:
            def raise_for_status(self): pass
            def json(self): return {'results': [{'vulns': []}]}
        return R()

    monkeypatch.setattr(httpx, 'post', fake_post)
    query_osv([{'name': 'nginx', 'version': '1.28.3', 'ecosystem': 'Debian'}],
               debian_version_id=None)
    assert captured['payload']['queries'][0]['package']['ecosystem'] == 'Debian'


def test_query_osv_wordpress_package_unaffected_by_debian_version(isolated_db, monkeypatch):
    captured = {}

    def fake_post(url, json, timeout):
        captured['payload'] = json

        class R:
            def raise_for_status(self): pass
            def json(self): return {'results': [{'vulns': []}]}
        return R()

    monkeypatch.setattr(httpx, 'post', fake_post)
    query_osv([{'name': 'wordpress', 'version': '6.5.2', 'ecosystem': 'WordPress'}],
               debian_version_id='13')
    assert captured['payload']['queries'][0]['package']['ecosystem'] == 'WordPress'


def test_query_osv_network_failure_does_not_raise(isolated_db, monkeypatch):
    def fake_post(*a, **kw):
        raise httpx.HTTPError('connection refused')

    monkeypatch.setattr(httpx, 'post', fake_post)
    result = query_osv(
        [{'name': 'nginx', 'version': '1.24.0', 'ecosystem': 'Debian'}],
        debian_version_id='13',
    )
    assert result['nginx'] == []  # empty, not an exception


def test_query_osv_mixed_ecosystems_in_one_batch(isolated_db, monkeypatch):
    """A batch with both a Debian-family package and a WordPress package
    must resolve each independently - the Debian one gets narrowed, the
    WordPress one doesn't, in the same request."""
    captured = {}

    def fake_post(url, json, timeout):
        captured['payload'] = json

        class R:
            def raise_for_status(self): pass
            def json(self): return {'results': [{'vulns': []}, {'vulns': []}]}
        return R()

    monkeypatch.setattr(httpx, 'post', fake_post)
    query_osv(
        [
            {'name': 'nginx', 'version': '1.28.3', 'ecosystem': 'Debian'},
            {'name': 'wordpress', 'version': '6.5.2', 'ecosystem': 'WordPress'},
        ],
        debian_version_id='13',
    )
    ecosystems = [q['package']['ecosystem'] for q in captured['payload']['queries']]
    assert ecosystems == ['Debian:13', 'WordPress']


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


def test_full_flow_reads_os_release_and_narrows_debian_ecosystem(monkeypatch, isolated_db):
    """End-to-end: check_cve_audit() must read /etc/os-release over the
    same SSH session and pass the resulting release id all the way through
    to the actual OSV request - the fix's full round trip, not just the
    individual pieces in isolation."""
    fake = FakeSSHExecutor(responses={
        'nginx -v': ('nginx version: nginx/1.28.3', ''),
        "grep '^VERSION_ID='": ('VERSION_ID="13"\n', ''),
    })
    monkeypatch.setattr('netaudit_pkg.checks.cve_audit.SSHExecutor', lambda *a, **kw: fake)

    captured = {}

    def fake_post(url, json, timeout):
        captured['payload'] = json

        class R:
            def raise_for_status(self): pass
            def json(self): return {'results': [{'vulns': []}]}
        return R()

    monkeypatch.setattr(httpx, 'post', fake_post)
    check_cve_audit(host='1.2.3.4')
    assert captured['payload']['queries'][0]['package']['ecosystem'] == 'Debian:13'


def test_full_flow_uses_dpkg_revision_not_bare_upstream_version(monkeypatch, isolated_db):
    """Regression test for the exact bug found running this check against
    a real server: nginx 1.28.3 (vulnerable to CVE-2026-42533 per multiple
    independent security advisories) was reported as 'no known CVEs
    found' because the query used the bare upstream version '1.28.3'
    instead of the Debian package revision (e.g. '1.28.3-1~deb13u2') that
    OSV's Debian:13 ecosystem records actually compare against (Debian
    backports security fixes into revision-suffixed versions like
    DSA-6326-1's '1.26.3-3+deb13u6', not upstream version numbers). This
    test locks in that the dpkg revision - not the upstream number - is
    what actually goes out on the wire to OSV."""
    fake = FakeSSHExecutor(responses={
        'nginx -v': ('nginx version: nginx/1.28.3', ''),
        "dpkg-query -W -f='${Version}' nginx": ('1.28.3-1~deb13u2\n', ''),
        "grep '^VERSION_ID='": ('VERSION_ID="13"\n', ''),
    })
    monkeypatch.setattr('netaudit_pkg.checks.cve_audit.SSHExecutor', lambda *a, **kw: fake)

    captured = {}

    def fake_post(url, json, timeout):
        captured['payload'] = json

        class R:
            def raise_for_status(self): pass
            def json(self): return {'results': [{'vulns': [{'id': 'DEBIAN-CVE-2026-42533'}]}]}
        return R()

    monkeypatch.setattr(httpx, 'post', fake_post)
    result = check_cve_audit(host='1.2.3.4')

    nginx_query = captured['payload']['queries'][0]
    assert nginx_query['version'] == '1.28.3-1~deb13u2'
    assert nginx_query['version'] != '1.28.3'  # the bare upstream version - the bug this fixes

    # and the finding must actually surface in the result, not get lost
    nginx_findings = [f for f in result['findings'] if f['package'] == 'nginx']
    assert any(f['cve'] == 'DEBIAN-CVE-2026-42533' for f in nginx_findings)


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
