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
        'apt-cache show nginx': (_APT_SHOW_NGINX_NATIVE_DEBIAN, ''),
    })
    packages = collect_packages(fake)
    nginx = next(p for p in packages if p['name'] == 'nginx')
    assert nginx['version'] == '1.24.0-2'
    assert nginx['upstream_version'] == '1.24.0'
    assert nginx['ecosystem'] == 'Linux'
    assert nginx['third_party_repo'] is False


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


_APT_SHOW_NGINX_PPA = """Package: nginx
Version: 1.30.2-1~noble
Origin: nginx
Maintainer: nginx packaging <nginx-packaging@f5.com>
"""

_APT_SHOW_NGINX_NATIVE_UBUNTU = """Package: nginx
Version: 1.24.0-2ubuntu7.15
Origin: Ubuntu
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
"""

_APT_SHOW_NGINX_NATIVE_DEBIAN = """Package: nginx
Version: 1.26.3-3+deb13u6
Origin: Debian
Maintainer: Debian Nginx Maintainers <pkg-nginx-maintainers@alioth-lists.debian.net>
"""


def test_collect_packages_flags_nginx_org_ppa_as_third_party():
    """Regression test for the exact case found running this check
    against a real server: nginx installed from nginx.org's own apt repo
    (a legitimate, nginx-recommended install method) is flagged because
    the actual repository URL (from `apt-cache policy`, not a guess from
    the version string) is nginx.org, not archive.ubuntu.com."""
    fake = FakeSSHExecutor(responses={
        'nginx -v': ('nginx version: nginx/1.30.2', ''),
        "dpkg-query -W -f='${Version}' nginx": ('1.30.2-1~noble\n', ''),
        'apt-cache show nginx': (_APT_SHOW_NGINX_PPA, ''),
    })
    packages = collect_packages(fake)
    nginx = next(p for p in packages if p['name'] == 'nginx')
    assert nginx['third_party_repo'] is True


def test_collect_packages_does_not_flag_native_ubuntu_nginx():
    fake = FakeSSHExecutor(responses={
        'nginx -v': ('nginx version: nginx/1.24.0', ''),
        "dpkg-query -W -f='${Version}' nginx": ('1.24.0-2ubuntu7.15\n', ''),
        'apt-cache show nginx': (_APT_SHOW_NGINX_NATIVE_UBUNTU, ''),
    })
    packages = collect_packages(fake)
    nginx = next(p for p in packages if p['name'] == 'nginx')
    assert nginx['third_party_repo'] is False


def test_collect_packages_does_not_flag_native_debian_nginx():
    fake = FakeSSHExecutor(responses={
        'nginx -v': ('nginx version: nginx/1.26.3', ''),
        "dpkg-query -W -f='${Version}' nginx": ('1.26.3-3+deb13u6\n', ''),
        'apt-cache show nginx': (_APT_SHOW_NGINX_NATIVE_DEBIAN, ''),
    })
    packages = collect_packages(fake)
    nginx = next(p for p in packages if p['name'] == 'nginx')
    assert nginx['third_party_repo'] is False


def test_collect_packages_third_party_flag_false_without_dpkg_version():
    """If dpkg-query found nothing (package not dpkg-installed at all),
    third_party_repo must be False, not an accidental True from an empty
    apt-cache policy lookup - there's no dpkg package to check the source
    of in the first place."""
    fake = FakeSSHExecutor(responses={
        'nginx -v': ('nginx version: nginx/1.24.0', ''),
    })
    packages = collect_packages(fake)
    nginx = next(p for p in packages if p['name'] == 'nginx')
    assert nginx['third_party_repo'] is False


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
        'apt-cache show mariadb-server': ('Package: mariadb-server\nOrigin: Debian\n', ''),
    })
    packages = collect_packages(fake)
    db_pkg = next(p for p in packages if p['name'] == 'mariadb')
    assert db_pkg['version'] == '1:10.11.6-0+deb12u1'
    assert db_pkg['third_party_repo'] is False
    # NOTE: upstream_version here reflects a pre-existing, separate bug in
    # _parse_version() - `mysql --version` prints the CLIENT utility
    # version (15.1) before the server version (10.11.6-MariaDB), and the
    # regex takes the first match. Not this fix's scope to correct - documented here so this isn't mistaken for a new
    # regression introduced by the dpkg-version change.
    assert db_pkg['upstream_version'] == '15.1'


def test_collect_packages_uses_dpkg_version_for_kernel_when_available():
    """Regression test for the kernel-specific version of the same fix
    already applied to nginx/openssh/mariadb: `uname -r` reports the
    ABI/release string, not the dpkg package's own version - Debian's own
    documentation is explicit that these are not the same thing ('3.16.0-4
    is *not* the kernel version but the ABI name used'). The dpkg version
    of linux-image-<uname -r> is what OSV's Ubuntu/Debian ecosystem
    records actually compare against."""
    fake = FakeSSHExecutor(responses={
        'uname -r': ('6.8.0-124-generic\n', ''),
        "dpkg-query -W -f='${Version}' linux-image-6.8.0-124-generic": ('6.8.0-124.124\n', ''),
        'apt-cache show linux-image-6.8.0-124-generic=6.8.0-124.124': (
            'Package: linux-image-6.8.0-124-generic\nOrigin: Ubuntu\n', ''),
    })
    packages = collect_packages(fake)
    kernel = next(p for p in packages if p['name'] == 'linux')
    assert kernel['version'] == '6.8.0-124.124'
    assert kernel['upstream_version'] == '6.8.0-124-generic'
    assert kernel['third_party_repo'] is False


def test_collect_packages_kernel_falls_back_to_uname_without_dpkg():
    """A custom-built, cloud-provider, or otherwise non-dpkg-tracked
    kernel (no matching linux-image-<release> package in dpkg) falls back
    to the uname -r string for OSV matching, same fallback shape every
    other Debian-family package in this module already has - a less
    precise match beats no match at all."""
    fake = FakeSSHExecutor(responses={
        'uname -r': ('6.8.0-124-generic\n', ''),
    })
    packages = collect_packages(fake)
    kernel = next(p for p in packages if p['name'] == 'linux')
    assert kernel['version'] == '6.8.0-124-generic'
    assert kernel['upstream_version'] == '6.8.0-124-generic'
    assert kernel['third_party_repo'] is False


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
# _get_package_origin / _is_official_distro_source — vendor-repo
# detection via apt-cache show's Origin field (a fact independent of
# which mirror the package was fetched through, unlike checking the
# repository URL's domain against a hardcoded list of official domains -
# see this module's git history for why that approach was replaced: it
# incorrectly flagged a real server's mirror-sourced native packages
# (Hetzner's own Ubuntu mirror) as third-party)
# ===========================================================================

def test_get_package_origin_nginx_org_ppa():
    """The exact real-world case: nginx.org's own apt repo."""
    from netaudit_pkg.checks.cve_audit import _get_package_origin
    fake = FakeSSHExecutor(responses={
        'apt-cache show nginx=1.30.2-1~noble': (_APT_SHOW_NGINX_PPA, ''),
    })
    assert _get_package_origin(fake, 'nginx', '1.30.2-1~noble') == 'nginx'


def test_get_package_origin_native_ubuntu_archive():
    from netaudit_pkg.checks.cve_audit import _get_package_origin
    fake = FakeSSHExecutor(responses={
        'apt-cache show nginx=1.24.0-2ubuntu7.15': (_APT_SHOW_NGINX_NATIVE_UBUNTU, ''),
    })
    assert _get_package_origin(fake, 'nginx', '1.24.0-2ubuntu7.15') == 'Ubuntu'


def test_get_package_origin_native_debian_archive():
    from netaudit_pkg.checks.cve_audit import _get_package_origin
    fake = FakeSSHExecutor(responses={
        'apt-cache show nginx=1.26.3-3+deb13u6': (_APT_SHOW_NGINX_NATIVE_DEBIAN, ''),
    })
    assert _get_package_origin(fake, 'nginx', '1.26.3-3+deb13u6') == 'Debian'


def test_get_package_origin_mirror_sourced_native_package_still_says_ubuntu():
    """Regression test for the exact case that broke the previous
    (URL-domain-based) approach: a package fetched through a third-party
    hosting-provider mirror (Hetzner's own Ubuntu mirror,
    mirror.hetzner.com) that is still a genuinely native Ubuntu package.
    The Origin field says 'Ubuntu' regardless of which mirror served the
    bytes - confirmed against real `apt-cache show` output from a live
    server using this exact mirror."""
    from netaudit_pkg.checks.cve_audit import _get_package_origin
    fake = FakeSSHExecutor(responses={
        'apt-cache show openssh-client=1:9.6p1-3ubuntu13.18': (
            'Package: openssh-client\nOrigin: Ubuntu\n'
            'Original-Maintainer: Debian OpenSSH Maintainers <debian-ssh@lists.debian.org>\n',
            ''),
    })
    assert _get_package_origin(fake, 'openssh-client', '1:9.6p1-3ubuntu13.18') == 'Ubuntu'


def test_get_package_origin_queries_by_exact_version_not_bare_name():
    """Regression test for the exact bug found running this check
    against a real server: `apt-cache show nginx` (no version) returned
    an 'Origin: Ubuntu' record ahead of the actually-installed nginx.org
    package's 'Origin: nginx' record, because the local apt cache held
    entries for BOTH the Ubuntu-archive build (never installed, just
    indexed) and the nginx.org build for the same package name -
    checking the first match answered the wrong question. This test
    locks in that the query is version-pinned (`pkg=version`), so a fake
    SSH executor that only has a response for the un-pinned bare-name
    command must NOT be matched - proving the real code sends the
    version-qualified command, not the bare one."""
    from netaudit_pkg.checks.cve_audit import _get_package_origin

    class _StrictFakeSSH:
        """Does not use substring matching - only responds to the exact
        command string, to catch a version-less regression precisely."""

        def __init__(self, exact_responses):
            self.exact_responses = exact_responses

        def run(self, cmd):
            return self.exact_responses.get(cmd, ('', ''))

    fake = _StrictFakeSSH({
        'apt-cache show nginx=1.30.2-1~noble 2>/dev/null': (_APT_SHOW_NGINX_PPA, ''),
    })
    assert _get_package_origin(fake, 'nginx', '1.30.2-1~noble') == 'nginx'


def test_get_package_origin_returns_none_when_no_origin_field():
    from netaudit_pkg.checks.cve_audit import _get_package_origin
    fake = FakeSSHExecutor(responses={
        'apt-cache show nginx=1.24.0-2ubuntu7': ('Package: nginx\nVersion: 1.24.0-2ubuntu7\n', ''),
    })
    assert _get_package_origin(fake, 'nginx', '1.24.0-2ubuntu7') is None


def test_get_package_origin_returns_none_on_empty_output():
    from netaudit_pkg.checks.cve_audit import _get_package_origin
    fake = FakeSSHExecutor(responses={})
    assert _get_package_origin(fake, 'nginx', '1.24.0-2ubuntu7') is None


def test_is_official_distro_source_ubuntu():
    from netaudit_pkg.checks.cve_audit import _is_official_distro_source
    assert _is_official_distro_source('Ubuntu') is True


def test_is_official_distro_source_debian():
    from netaudit_pkg.checks.cve_audit import _is_official_distro_source
    assert _is_official_distro_source('Debian') is True


def test_is_official_distro_source_vendor_origin():
    from netaudit_pkg.checks.cve_audit import _is_official_distro_source
    assert _is_official_distro_source('nginx') is False


def test_is_official_distro_source_ppa_origin():
    from netaudit_pkg.checks.cve_audit import _is_official_distro_source
    assert _is_official_distro_source('LP-PPA-git-core') is False


def test_is_official_distro_source_none_is_not_official():
    """Unknown origin (couldn't determine at all) must NOT default to
    'assume official' - that's the same optimistic-default mistake this
    module's ecosystem-resolution fix eliminated elsewhere."""
    from netaudit_pkg.checks.cve_audit import _is_official_distro_source
    assert _is_official_distro_source(None) is False


# ===========================================================================
# collect_os_release — distro ID + VERSION_ID detection
# ===========================================================================

def test_collect_os_release_parses_debian():
    fake = FakeSSHExecutor(responses={
        "grep -E '^(ID|VERSION_ID)='": ('ID=debian\nVERSION_ID="13"\n', ''),
    })
    assert collect_os_release(fake) == ('debian', '13')


def test_collect_os_release_parses_ubuntu_dotted_version():
    """Ubuntu's VERSION_ID is dotted (year.month), not a plain integer -
    the regex must accept this shape, not just Debian's bare integer."""
    fake = FakeSSHExecutor(responses={
        "grep -E '^(ID|VERSION_ID)='": ('ID=ubuntu\nVERSION_ID="24.04"\n', ''),
    })
    assert collect_os_release(fake) == ('ubuntu', '24.04')


def test_collect_os_release_handles_unquoted_version_id():
    """Some minimal/custom images may not quote the value - the regex
    must not assume quotes are always present."""
    fake = FakeSSHExecutor(responses={
        "grep -E '^(ID|VERSION_ID)='": ('ID=debian\nVERSION_ID=12\n', ''),
    })
    assert collect_os_release(fake) == ('debian', '12')


def test_collect_os_release_returns_none_none_when_file_missing():
    fake = FakeSSHExecutor(responses={})
    assert collect_os_release(fake) == (None, None)


def test_collect_os_release_returns_none_on_garbage_output():
    fake = FakeSSHExecutor(responses={
        "grep -E '^(ID|VERSION_ID)='": ('not a version line at all', ''),
    })
    assert collect_os_release(fake) == (None, None)


def test_collect_os_release_partial_output_still_parses_what_it_can():
    """If only one of the two fields is present (unusual but not
    impossible - a heavily trimmed os-release), the function returns
    whichever it found rather than discarding both on a partial match."""
    fake = FakeSSHExecutor(responses={
        "grep -E '^(ID|VERSION_ID)='": ('VERSION_ID="13"\n', ''),
    })
    assert collect_os_release(fake) == (None, '13')


# ===========================================================================
# _resolve_ecosystem — Debian AND Ubuntu ecosystem resolution
# ===========================================================================

def test_resolve_ecosystem_debian_with_known_release():
    assert _resolve_ecosystem('Linux', 'debian', '13') == 'Debian:13'


def test_resolve_ecosystem_ubuntu_lts_gets_lts_suffix():
    """Ubuntu LTS releases (X.04) get a ':LTS' suffix in OSV's ecosystem
    string - confirmed against OSV's own published records
    (osv.dev/list?ecosystem=Ubuntu shows 'Ubuntu:24.04:LTS'). This is the
    exact case that was silently broken before this fix: a real Ubuntu
    24.04 server had every generic-Linux package resolve to the
    nonexistent 'Debian:24' ecosystem instead."""
    assert _resolve_ecosystem('Linux', 'ubuntu', '24.04') == 'Ubuntu:24.04:LTS'


def test_resolve_ecosystem_ubuntu_non_lts_gets_no_suffix():
    """Non-LTS interim releases (X.10, etc) get no ':LTS' suffix -
    confirmed against OSV's own published records showing bare
    'Ubuntu:25.10' entries alongside 'Ubuntu:24.04:LTS' ones."""
    assert _resolve_ecosystem('Linux', 'ubuntu', '25.10') == 'Ubuntu:25.10'


def test_resolve_ecosystem_almalinux():
    assert _resolve_ecosystem('Linux', 'almalinux', '9') == 'AlmaLinux:9'


def test_resolve_ecosystem_rocky_linux():
    assert _resolve_ecosystem('Linux', 'rocky', '9') == 'Rocky Linux:9'


def test_resolve_ecosystem_alpine_gets_v_prefix():
    """Alpine's OSV ecosystem string has a 'v' prefix on the version
    ('Alpine:v3.19', not 'Alpine:3.19') - confirmed against OSV's own
    data dump documentation, a different shape from every other distro
    in the registry."""
    assert _resolve_ecosystem('Linux', 'alpine', '3.19') == 'Alpine:v3.19'


def test_resolve_ecosystem_returns_none_without_version():
    """VERSION_ID couldn't be determined - there's no distro-specific
    ecosystem string to build, so this returns None (package should be
    reported as not-checked, not silently guessed at with a possibly-wrong
    ecosystem). Applies regardless of os_id."""
    assert _resolve_ecosystem('Linux', 'debian', None) is None
    assert _resolve_ecosystem('Linux', 'ubuntu', None) is None
    assert _resolve_ecosystem('Linux', None, None) is None


def test_resolve_ecosystem_unregistered_distro_returns_none():
    """An os_id with no entry in _DISTRO_ECOSYSTEM_BUILDERS (a distro this
    module hasn't added yet - RHEL itself has no OSV ecosystem string as
    of this writing, SUSE/openSUSE aren't registered pending format
    verification) returns None - honestly reporting 'can't check this on
    this distro yet' rather than guessing at an ecosystem string or
    defaulting to Debian, which would silently misreport results (this
    module's original bug - see top docstring). Recognizing the distro's
    identity (os_id is set correctly) is a different state from having a
    working ecosystem builder for it - both currently produce None here,
    but for documented, distinct reasons."""
    assert _resolve_ecosystem('Linux', 'rhel', '9') is None
    assert _resolve_ecosystem('Linux', 'opensuse-leap', '15.6') is None
    assert _resolve_ecosystem('Linux', 'linuxmint', '21') is None


def test_resolve_ecosystem_new_distro_is_a_pure_registry_addition():
    """Structural check: adding a new distro should be possible by adding
    one entry to _DISTRO_ECOSYSTEM_BUILDERS, without touching
    _resolve_ecosystem()'s own logic. This test verifies the registry is
    actually consulted (not hardcoded if/elif branches reintroduced later)
    by monkeypatching in a fake entry and confirming it's picked up."""
    from netaudit_pkg.checks import cve_audit as module
    original = dict(module._DISTRO_ECOSYSTEM_BUILDERS)
    try:
        module._DISTRO_ECOSYSTEM_BUILDERS['fakedistro'] = lambda v: f'FakeDistro:{v}'
        assert _resolve_ecosystem('Linux', 'fakedistro', '7') == 'FakeDistro:7'
    finally:
        module._DISTRO_ECOSYSTEM_BUILDERS.clear()
        module._DISTRO_ECOSYSTEM_BUILDERS.update(original)


def test_resolve_ecosystem_wordpress_is_never_touched():
    """WordPress is a completely separate OSV ecosystem, unaffected by
    distro identity entirely - must pass through unchanged regardless of
    os_id/version_id."""
    assert _resolve_ecosystem('WordPress', 'debian', '13') == 'WordPress'
    assert _resolve_ecosystem('WordPress', 'ubuntu', '24.04') == 'WordPress'
    assert _resolve_ecosystem('WordPress', None, None) == 'WordPress'


# ===========================================================================
# query_osv — caching behavior (cache key now includes ecosystem)
# ===========================================================================

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
        [{'name': 'nginx', 'version': '1.24.0', 'ecosystem': 'Linux'}],
        os_id='debian', version_id='13',
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
        [{'name': 'nginx', 'version': '1.24.0', 'ecosystem': 'Linux'}],
        os_id='debian', version_id='13',
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
    query_osv([{'name': 'nginx', 'version': '1.28.3', 'ecosystem': 'Linux'}],
               os_id='debian', version_id='13')
    assert captured['payload']['queries'][0]['package']['ecosystem'] == 'Debian:13'


def test_query_osv_sends_ubuntu_lts_ecosystem_in_request(isolated_db, monkeypatch):
    """Regression test for the exact bug found running this check against
    a real Ubuntu 24.04 server: nginx/openssh/mariadb all silently used a
    nonexistent 'Debian:24' ecosystem (VERSION_ID '24.04' truncated by the
    old Debian-only version of this code), returning zero matches. This
    locks in that a real Ubuntu host now gets 'Ubuntu:24.04:LTS' on the
    wire, not 'Debian:24' or any other malformed variant."""
    captured = {}

    def fake_post(url, json, timeout):
        captured['payload'] = json

        class R:
            def raise_for_status(self): pass
            def json(self): return {'results': [{'vulns': []}]}
        return R()

    monkeypatch.setattr(httpx, 'post', fake_post)
    query_osv([{'name': 'nginx', 'version': '1.30.2-1~noble', 'ecosystem': 'Linux'}],
               os_id='ubuntu', version_id='24.04')
    assert captured['payload']['queries'][0]['package']['ecosystem'] == 'Ubuntu:24.04:LTS'


def test_query_osv_returns_none_when_distro_unresolvable(isolated_db, monkeypatch):
    """When the distro can't be resolved to a known OSV ecosystem
    (missing version_id, or an unrecognized os_id), the package is never
    sent to OSV at all - result[name] is None, not an empty list and not
    a guessed-at ecosystem string. This is the honesty fix: the old
    behavior silently defaulted to 'Debian' here, which could produce a
    wrong-ecosystem query on a non-Debian host instead of admitting the
    limitation."""
    def fail_if_called(*a, **kw):
        raise AssertionError('should not query OSV for an unresolvable ecosystem')

    monkeypatch.setattr(httpx, 'post', fail_if_called)
    result = query_osv([{'name': 'nginx', 'version': '1.28.3', 'ecosystem': 'Linux'}],
                        os_id=None, version_id=None)
    assert result['nginx'] is None


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
               os_id='debian', version_id='13')
    assert captured['payload']['queries'][0]['package']['ecosystem'] == 'WordPress'


def test_query_osv_network_failure_does_not_raise(isolated_db, monkeypatch):
    def fake_post(*a, **kw):
        raise httpx.HTTPError('connection refused')

    monkeypatch.setattr(httpx, 'post', fake_post)
    result = query_osv(
        [{'name': 'nginx', 'version': '1.24.0', 'ecosystem': 'Linux'}],
        os_id='debian', version_id='13',
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
            {'name': 'nginx', 'version': '1.28.3', 'ecosystem': 'Linux'},
            {'name': 'wordpress', 'version': '6.5.2', 'ecosystem': 'WordPress'},
        ],
        os_id='debian', version_id='13',
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
    assert details['vendor_priority'] is None


def test_fetch_vuln_details_parses_ubuntu_vendor_priority(monkeypatch):
    """Regression test for the exact real-world case: UBUNTU-CVE-2012-4542
    carries severity [{'type': 'Ubuntu', 'score': 'low'}] alongside a CVSS
    score - confirmed against the real OSV API response for this ID."""
    def fake_get(url, timeout):
        class R:
            def raise_for_status(self): pass
            def json(self):
                return {
                    'summary': 'block/scsi_ioctl.c ... bypass access restrictions',
                    'severity': [{'type': 'Ubuntu', 'score': 'low'}],
                    'affected': [],
                    'references': [],
                }
        return R()

    monkeypatch.setattr(httpx, 'get', fake_get)
    details = fetch_vuln_details('UBUNTU-CVE-2012-4542')
    assert details['vendor_priority'] == 'low'
    assert details['severity'] is None  # no CVSS_V3 entry in this fixture


def test_fetch_vuln_details_parses_debian_vendor_priority(monkeypatch):
    def fake_get(url, timeout):
        class R:
            def raise_for_status(self): pass
            def json(self):
                return {'summary': 'x', 'severity': [{'type': 'Debian', 'score': 'medium'}],
                        'affected': [], 'references': []}
        return R()

    monkeypatch.setattr(httpx, 'get', fake_get)
    details = fetch_vuln_details('DEBIAN-CVE-2024-0001')
    assert details['vendor_priority'] == 'medium'


def test_fetch_vuln_details_both_cvss_and_vendor_priority_present(monkeypatch):
    """A record can carry both CVSS_V3 and a vendor priority (the real
    UBUNTU-CVE-2012-4542 case does) - both must be extracted, not just
    whichever comes first."""
    def fake_get(url, timeout):
        class R:
            def raise_for_status(self): pass
            def json(self):
                return {
                    'summary': 'x',
                    'severity': [
                        {'type': 'CVSS_V3', 'score': '7.5/AV:L/AC:L'},
                        {'type': 'Ubuntu', 'score': 'low'},
                    ],
                    'affected': [], 'references': [],
                }
        return R()

    monkeypatch.setattr(httpx, 'get', fake_get)
    details = fetch_vuln_details('UBUNTU-CVE-2012-4542')
    assert details['severity'] == '7.5/AV:L/AC:L'
    assert details['vendor_priority'] == 'low'


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
    fake = FakeSSHExecutor(responses={
        'nginx -v': ('nginx version: nginx/1.24.0', ''),
        "grep -E '^(ID|VERSION_ID)='": ('ID=debian\nVERSION_ID="13"\n', ''),
    })
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
    same SSH session and pass the resulting distro id + release id all
    the way through to the actual OSV request - the fix's full round
    trip, not just the individual pieces in isolation."""
    fake = FakeSSHExecutor(responses={
        'nginx -v': ('nginx version: nginx/1.28.3', ''),
        "grep -E '^(ID|VERSION_ID)='": ('ID=debian\nVERSION_ID="13"\n', ''),
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
        "grep -E '^(ID|VERSION_ID)='": ('ID=debian\nVERSION_ID="13"\n', ''),
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


def test_full_flow_ubuntu_host_uses_ubuntu_ecosystem_not_debian(monkeypatch, isolated_db):
    """Regression test for the exact bug found running this check against
    a real Ubuntu 24.04 server: nginx 1.30.2-1~noble, openssh
    1:9.6p1-3ubuntu13.18, and mariadb 1:10.11.14-0ubuntu0.24.04.1 all
    showed 'no known CVEs found' because every query used a nonexistent
    'Debian:24' ecosystem (VERSION_ID '24.04' truncated by the old
    Debian-only version of this code, which had no concept of Ubuntu
    being a different OSV ecosystem namespace at all). This test locks in
    the full round trip: an Ubuntu host's ID=ubuntu/VERSION_ID=24.04 must
    produce 'Ubuntu:24.04:LTS' on the actual wire request, for every
    Debian-placeholder package in the batch."""
    fake = FakeSSHExecutor(responses={
        'nginx -v': ('nginx version: nginx/1.30.2', ''),
        "dpkg-query -W -f='${Version}' nginx": ('1.30.2-1~noble\n', ''),
        'ssh -V': ('OpenSSH_9.6p1 Ubuntu-3ubuntu13.18', ''),
        "dpkg-query -W -f='${Version}' openssh-client": ('1:9.6p1-3ubuntu13.18\n', ''),
        "grep -E '^(ID|VERSION_ID)='": ('ID=ubuntu\nVERSION_ID="24.04"\n', ''),
    })
    monkeypatch.setattr('netaudit_pkg.checks.cve_audit.SSHExecutor', lambda *a, **kw: fake)

    captured = {}

    def fake_post(url, json, timeout):
        captured['payload'] = json

        class R:
            def raise_for_status(self): pass
            def json(self): return {'results': [{'vulns': []}] * len(json['queries'])}
        return R()

    monkeypatch.setattr(httpx, 'post', fake_post)
    check_cve_audit(host='1.2.3.4')

    ecosystems = {q['package']['ecosystem'] for q in captured['payload']['queries']}
    assert ecosystems == {'Ubuntu:24.04:LTS'}
    assert 'Debian:24' not in ecosystems  # the exact malformed string the old code produced


def test_full_flow_unrecognized_distro_reports_not_supported_not_ok(monkeypatch, isolated_db):
    """Honesty check: a host running a distro this module can't resolve
    to an OSV ecosystem (e.g. a RHEL-family box) must NOT show its
    packages as 'ok'/no known CVEs - that would look identical to an
    actually-checked-and-clean result. It must show up as
    'not_supported' instead, with no OSV request made for that package at
    all."""
    fake = FakeSSHExecutor(responses={
        'nginx -v': ('nginx version: nginx/1.24.0', ''),
        "grep -E '^(ID|VERSION_ID)='": ('ID=rhel\nVERSION_ID="9"\n', ''),
    })
    monkeypatch.setattr('netaudit_pkg.checks.cve_audit.SSHExecutor', lambda *a, **kw: fake)

    def fail_if_called(*a, **kw):
        raise AssertionError('should not query OSV for an unresolvable distro')

    monkeypatch.setattr(httpx, 'post', fail_if_called)
    result = check_cve_audit(host='1.2.3.4')

    assert result['summary']['not_supported'] == 1
    assert result['summary']['ok'] == 0
    nginx_finding = next(f for f in result['findings'] if f['package'] == 'nginx')
    assert nginx_finding['severity'] == 'not_supported'


def test_full_flow_third_party_repo_not_reported_as_ok(monkeypatch, isolated_db):
    """Regression test for the exact case found running this check
    against a real server: nginx installed from nginx.org's official apt
    repo (version '1.30.2-1~noble') on an Ubuntu 24.04 host. Ecosystem
    resolution correctly produces 'Ubuntu:24.04:LTS', and OSV correctly
    returns zero matches for that exact version string (Ubuntu's security
    team doesn't track nginx.org's packages at all) - but this must show
    up as 'third_party_repo', not 'ok', since an empty OSV result here
    means 'no data' rather than 'verified clean'."""
    fake = FakeSSHExecutor(responses={
        'nginx -v': ('nginx version: nginx/1.30.2', ''),
        "dpkg-query -W -f='${Version}' nginx": ('1.30.2-1~noble\n', ''),
        'apt-cache show nginx': (_APT_SHOW_NGINX_PPA, ''),
        "grep -E '^(ID|VERSION_ID)='": ('ID=ubuntu\nVERSION_ID="24.04"\n', ''),
    })
    monkeypatch.setattr('netaudit_pkg.checks.cve_audit.SSHExecutor', lambda *a, **kw: fake)

    def fake_post(url, json, timeout):
        class R:
            def raise_for_status(self): pass
            def json(self): return {'results': [{'vulns': []}]}
        return R()

    monkeypatch.setattr(httpx, 'post', fake_post)
    result = check_cve_audit(host='1.2.3.4')

    assert result['summary']['third_party_repo'] == 1
    assert result['summary']['ok'] == 0
    nginx_finding = next(f for f in result['findings'] if f['package'] == 'nginx')
    assert nginx_finding['severity'] == 'third_party_repo'
    assert nginx_finding['title'] != 'no known CVEs found'


def test_full_flow_third_party_repo_with_actual_cve_still_reported(monkeypatch, isolated_db):
    """A third-party-repo package where OSV DOES find a match (unusual,
    but possible if the vendor's version happens to overlap a tracked
    range) must still surface the real finding - the third_party_repo
    flag only changes behavior for the EMPTY-result case, it never
    suppresses an actual match."""
    fake = FakeSSHExecutor(responses={
        'nginx -v': ('nginx version: nginx/1.30.2', ''),
        "dpkg-query -W -f='${Version}' nginx": ('1.30.2-1~noble\n', ''),
        'apt-cache show nginx': (_APT_SHOW_NGINX_PPA, ''),
        "grep -E '^(ID|VERSION_ID)='": ('ID=ubuntu\nVERSION_ID="24.04"\n', ''),
    })
    monkeypatch.setattr('netaudit_pkg.checks.cve_audit.SSHExecutor', lambda *a, **kw: fake)

    def fake_post(url, json, timeout):
        class R:
            def raise_for_status(self): pass
            def json(self): return {'results': [{'vulns': [{'id': 'UBUNTU-CVE-2026-42533'}]}]}
        return R()

    monkeypatch.setattr(httpx, 'post', fake_post)
    result = check_cve_audit(host='1.2.3.4')

    assert result['summary']['third_party_repo'] == 0
    nginx_findings = [f for f in result['findings'] if f['package'] == 'nginx']
    assert any(f['cve'] == 'UBUNTU-CVE-2026-42533' for f in nginx_findings)


@pytest.mark.parametrize('score,expected_severity', [
    ('9.8', 'critical'),
    ('7.5', 'high'),
    ('5.0', 'medium'),
    ('2.0', 'low'),
    (None, 'medium'),  # unknown score is not downplayed to low
])
def test_full_flow_severity_mapping(monkeypatch, isolated_db, score, expected_severity):
    fake = FakeSSHExecutor(responses={
        'nginx -v': ('nginx version: nginx/1.24.0', ''),
        "grep -E '^(ID|VERSION_ID)='": ('ID=debian\nVERSION_ID="13"\n', ''),
    })
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


@pytest.mark.parametrize('vendor_priority,expected_severity', [
    ('negligible', 'low'),
    ('low', 'low'),
    ('medium', 'medium'),
    ('high', 'high'),
    ('critical', 'critical'),
])
def test_full_flow_ubuntu_vendor_priority_used_when_present(
        monkeypatch, isolated_db, vendor_priority, expected_severity):
    """Vendor priority (Ubuntu/Debian) takes precedence over CVSS when
    both are present - per Canonical's own published guidance, the
    vendor's own assessment for their own distro is more accurate."""
    fake = FakeSSHExecutor(responses={
        'nginx -v': ('nginx version: nginx/1.24.0', ''),
        "grep -E '^(ID|VERSION_ID)='": ('ID=ubuntu\nVERSION_ID="24.04"\n', ''),
    })
    monkeypatch.setattr('netaudit_pkg.checks.cve_audit.SSHExecutor', lambda *a, **kw: fake)

    def fake_post(url, json, timeout):
        class R:
            def raise_for_status(self): pass
            def json(self): return {'results': [{'vulns': [{'id': 'UBUNTU-CVE-2024-0001'}]}]}
        return R()

    def fake_get(url, timeout):
        class R:
            def raise_for_status(self): pass
            def json(self):
                return {
                    'summary': 'test vuln',
                    # a high CVSS score alongside the vendor priority - if
                    # vendor priority isn't actually preferred, this test
                    # would see the wrong severity bucket
                    'severity': [
                        {'type': 'CVSS_V3', 'score': '9.8/AV:N/AC:L'},
                        {'type': 'Ubuntu', 'score': vendor_priority},
                    ],
                    'affected': [], 'references': [],
                }
        return R()

    monkeypatch.setattr(httpx, 'post', fake_post)
    monkeypatch.setattr(httpx, 'get', fake_get)
    result = check_cve_audit(host='1.2.3.4')
    assert result['summary'][expected_severity] == 1


def test_full_flow_regression_ubuntu_2012_4542_shaped_finding(monkeypatch, isolated_db):
    """Regression test for the exact real-world case that motivated this
    fix: UBUNTU-CVE-2012-4542, a real OSV.dev record for the Ubuntu
    kernel source package, carries severity [{'type': 'Ubuntu', 'score':
    'low'}] and Ubuntu's own site marks it "For informational purposes
    only. We recommend not to cherry-pick updates." Before this fix, this
    module's CVSS-only severity mapping had no way to see the vendor's
    own low-priority assessment and defaulted such findings toward
    'medium' or higher, burying genuinely actionable findings in a wall
    of Ubuntu's own already-triaged-as-low-priority historical noise. This
    test locks in that the real API response shape for this exact CVE
    resolves to 'low', not 'medium'."""
    fake = FakeSSHExecutor(responses={
        'uname -r': ('7.0.0-29-generic\n', ''),
        "dpkg-query -W -f='${Version}' linux-image-7.0.0-29-generic": ('7.0.0-29.29\n', ''),
        "grep -E '^(ID|VERSION_ID)='": ('ID=ubuntu\nVERSION_ID="26.04"\n', ''),
    })
    monkeypatch.setattr('netaudit_pkg.checks.cve_audit.SSHExecutor', lambda *a, **kw: fake)

    def fake_post(url, json, timeout):
        class R:
            def raise_for_status(self): pass
            def json(self): return {'results': [{'vulns': [{'id': 'UBUNTU-CVE-2012-4542'}]}]}
        return R()

    def fake_get(url, timeout):
        class R:
            def raise_for_status(self): pass
            def json(self):
                # shape confirmed against the real api.osv.dev response
                return {
                    'summary': None,
                    'details': 'block/scsi_ioctl.c in the Linux kernel through 3.8 ...',
                    'severity': [{'type': 'Ubuntu', 'score': 'low'}],
                    'affected': [],
                    'references': [{'url': 'https://ubuntu.com/security/CVE-2012-4542'}],
                }
        return R()

    monkeypatch.setattr(httpx, 'post', fake_post)
    monkeypatch.setattr(httpx, 'get', fake_get)
    result = check_cve_audit(host='1.2.3.4')

    assert result['summary']['low'] == 1
    assert result['summary'].get('medium', 0) == 0
    linux_finding = next(f for f in result['findings'] if f['cve'] == 'UBUNTU-CVE-2012-4542')
    assert linux_finding['severity'] == 'low'


def test_empty_host_rejected():
    result = check_cve_audit(host='')
    assert 'error' in result
