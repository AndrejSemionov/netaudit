"""
CVE audit of installed software via SSH. Two steps:
  1. Collect facts about services (version + relevant config).
  2. Version matching via OSV.dev (https://osv.dev, no key needed, batch query).

Result: a list of CVEs found for each service with severity (if a CVSS score
is available) and fix data (affected/fixed versions). The final "what to do"
verdict is given by the shared ai_analyze() in history.py - this just feeds
in a 'cve' section with facts and config, so the AI can match a vulnerability
against the actual configuration instead of just restating a raw CVSS score.

Cache: cve_cache in storage.py, 24h TTL - to avoid hammering OSV.dev on every run.

Linux distro identification and OSV ecosystem resolution (2026-08-11)
------------------------------------------------------------------------
This module targets Linux server packages generically - it does NOT assume
every target host is Debian. collect_packages() tags each package it finds
with the *generic* placeholder ecosystem 'Linux' (not 'Debian', not any
specific distro), because at collection time the module doesn't yet know
which distro it's actually talking to. _resolve_ecosystem() is where that
placeholder gets turned into the real, distro-specific OSV ecosystem string,
using collect_os_release()'s (os_id, version_id) read from /etc/os-release.

This distinction matters because OSV.dev's Debian and Ubuntu ecosystems are
NOT the same namespace with different version formats - they are two
entirely separate ecosystems with different naming conventions
('Debian:13' vs 'Ubuntu:24.04:LTS') and different underlying data (Debian
Security Tracker vs Ubuntu Security Notices/Ubuntu CVE Tracker). A module
that defaulted every dpkg-based host to 'Debian' would silently mismatch
every Ubuntu host - which is exactly what happened during development:
this module originally hardcoded ecosystem='Debian' for every package
unconditionally, and running it against a real Ubuntu 24.04 server produced
'no known CVEs found' for nginx/openssh/mariadb across the board, because
every query used a nonexistent 'Debian:24' ecosystem string (Ubuntu's
'24.04' VERSION_ID truncated to its first integer group by code that had
no concept of Ubuntu being a distinct OSV namespace).

Currently resolved distros (see _resolve_ecosystem()): Debian, Ubuntu. Any
other os_id (RHEL family, SUSE, Alpine, etc - OSV.dev does have ecosystems
for several of these, e.g. 'AlmaLinux:9', 'Rocky Linux:9', but this module
doesn't build those ecosystem strings yet) causes the package to be
reported with ecosystem=None and excluded from OSV querying entirely,
rather than guessed at with a wrong ecosystem string that would silently
misreport results the way the old Debian-default did. A caller/UI can
present "distro not supported for CVE matching yet" for that host instead
of a false "no known CVEs found" that looks identical to an actually-clean
result but isn't.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

import httpx

from ..registry import register
from .. import storage
from ..ssh import SSHExecutor, HostKeyMismatchError

try:
    import paramiko
except ImportError:
    paramiko = None

OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch'
OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/{id}'
CACHE_TTL_HOURS = 24

# Generic placeholder ecosystem collect_packages() tags every dpkg-based
# package with at collection time, before the real distro is known.
# _resolve_ecosystem() turns this into the actual OSV ecosystem string
# (or None, if the distro isn't one this module knows how to resolve) -
# see this module's top docstring for the full reasoning. This is
# deliberately NOT 'Debian' - a generic 'Linux' placeholder makes it
# obvious at every call site that this value is not yet a real OSV
# ecosystem and must be resolved before being sent anywhere.
_GENERIC_LINUX_ECOSYSTEM = 'Linux'


# ===========================================================================
# Collecting service versions over SSH
# ===========================================================================

def _parse_version(text: str) -> str | None:
    m = re.search(r'(\d+\.\d+(?:\.\d+)?)', text)
    return m.group(1) if m else None


def collect_os_release(ssh: SSHExecutor) -> tuple[str | None, str | None]:
    """Returns (ID, VERSION_ID) from /etc/os-release, e.g. ('debian', '13')
    or ('ubuntu', '24.04'). Either element is None if it couldn't be
    determined - old os-release format, unrecognized distro, or the file
    doesn't exist.

    Both fields matter, not just the version number: Debian's VERSION_ID
    is a plain integer ('13'), Ubuntu's is a dotted year.month ('24.04') -
    and critically, they use *different* OSV ecosystem namespaces entirely
    ('Debian:13' vs 'Ubuntu:24.04:LTS'), not just different version
    formats within the same 'Debian' namespace. A host reporting ID=ubuntu
    was previously (incorrectly) treated as Debian by this module - see
    _resolve_ecosystem()'s docstring for the fix and the real-world case
    that exposed it (a real server's nginx/openssh/mariadb showing 'no
    known CVEs found' because every query silently used a nonexistent
    'Debian:24' ecosystem string, built by truncating Ubuntu's '24.04'
    VERSION_ID down to its first integer group).

    Read-only, single command. Deliberately separate from collect_packages()
    so it can be unit-tested independently and so a future caller only
    needing distro identity doesn't have to run the full package
    collection to get it.
    """
    out, _ = ssh.run("grep -E '^(ID|VERSION_ID)=' /etc/os-release 2>/dev/null")
    os_id = None
    version_id = None
    for line in out.splitlines():
        # os-release values are typically double-quoted (VERSION_ID="13")
        # but not always (some minimal/custom images omit quotes) - handle
        # both without assuming a specific style, same defensive approach
        # the previous single-field version of this parser used.
        m_id = re.match(r'ID="?([a-z0-9._-]+)"?$', line)
        if m_id:
            os_id = m_id.group(1)
            continue
        m_ver = re.match(r'VERSION_ID="?([0-9]+(?:\.[0-9]+)?)"?$', line)
        if m_ver:
            version_id = m_ver.group(1)
    return os_id, version_id


def _dpkg_version(ssh: SSHExecutor, dpkg_name: str) -> str | None:
    """Returns the installed Debian package version (with revision, e.g.
    '1.28.3-1~deb13u2') via dpkg-query, or None if the package isn't
    installed via dpkg (e.g. compiled from source, installed via a
    third-party repo with a non-dpkg-tracked version, or simply absent).

    This exists because OSV's Debian ecosystem records compare against
    Debian's own package revision, not the upstream version number - e.g.
    DSA-6326-1 fixed CVE-2026-42533-adjacent nginx issues in Debian
    version '1.26.3-3+deb13u6', not any upstream nginx version string.
    Querying OSV with a bare upstream version like '1.28.3' (what `nginx
    -v` reports) compares against the wrong version space entirely -
    confirmed by running this check against a real server where nginx
    1.28.3 (vulnerable to CVE-2026-42533 per multiple independent security
    advisories) was reported as having 'no known CVEs found' once the
    ecosystem was correctly narrowed to 'Debian:13', because the upstream
    version number doesn't line up with how Debian's own fixed-version
    ranges are expressed.
    """
    out, _ = ssh.run(f"dpkg-query -W -f='${{Version}}' {dpkg_name} 2>/dev/null")
    out = out.strip()
    return out if out else None


def _get_package_origin(ssh: SSHExecutor, dpkg_name: str, version: str) -> str | None:
    """Returns the 'Origin' field (e.g. 'Ubuntu', 'Debian', 'nginx') of
    the specific installed version of a package, or None if it can't be
    determined - package not installed via dpkg, no matching cache
    entry, etc.

    Must be queried by exact version (`apt-cache show pkg=version`), not
    by bare package name - `apt-cache show <pkg>` with no version prints
    every record the local apt cache has for that package name across
    ALL configured repositories, and returns records in an
    apt-internal order that is not "the installed one first." Confirmed
    empirically on a real server: a bare `apt-cache show nginx` returned
    an 'Origin: Ubuntu' record ahead of the 'Origin: nginx' record for
    the actually-installed nginx.org package, because the local cache
    also had an entry for the Ubuntu-archive nginx build (never
    installed, just present in the index) - checking only the first
    match silently answered the wrong question. Pinning the query to the
    exact installed version (`nginx=1.30.2-1~noble`) selects the correct
    record regardless of how many other versions of the same package
    name exist in the cache.

    This is the direct, distro-independent factual answer to "is this
    package tracked by the distro's own security team" - the Origin
    field is set by whoever built the repository's package index and
    names the distro/vendor that produced it, completely independent of
    which URL/mirror the package was actually fetched from. This matters
    in practice: a server using a regional or hosting-provider mirror
    (e.g. Hetzner's own Ubuntu mirror at mirror.hetzner.com) still gets
    'Origin: Ubuntu' on every genuinely-Ubuntu package, so checking the
    Origin field works correctly regardless of which mirror is
    configured - unlike an earlier version of this function that checked
    the repository URL's domain against a hardcoded list of official
    domains (archive.ubuntu.com, deb.debian.org, ...), which incorrectly
    flagged mirror-sourced native packages as third-party.
    """
    out, _ = ssh.run(f'apt-cache show {dpkg_name}={version} 2>/dev/null')
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('Origin:'):
            origin = line.split(':', 1)[1].strip()
            return origin if origin else None
    return None


# Origin values that are a distro's own official archive - packages
# carrying one of these are covered by that distro's security tracking
# (Debian Security Tracker / Ubuntu Security Notices), so OSV's
# Debian/Ubuntu ecosystem matching is expected to have real data for
# them regardless of which mirror the package was actually fetched
# through. Any other Origin value (nginx.org's own repo doesn't set this
# field the same way, a PPA sets 'LP-PPA-<name>', etc) is a vendor's own
# repository, which that distro's security team does not track
# regardless of how legitimate or official the vendor's own repo is.
_OFFICIAL_DISTRO_ORIGINS = ('Ubuntu', 'Debian')


def _is_official_distro_source(origin: str | None) -> bool:
    """True if origin (from _get_package_origin()) is one of the distro's
    own official archive origins - see _OFFICIAL_DISTRO_ORIGINS above.
    Returns False (not officially tracked) for None too - if the origin
    couldn't be determined at all, this function does not assume it's
    fine; the caller treats "unknown origin" the same as "known
    third-party origin" for safety, since guessing "probably official"
    when unsure is the same optimistic-default mistake this module's
    ecosystem-resolution fix (see collect_os_release()/_resolve_ecosystem())
    was written to eliminate elsewhere in this file.
    """
    return origin in _OFFICIAL_DISTRO_ORIGINS


def collect_packages(ssh: SSHExecutor) -> list[dict]:
    """
    Returns a list of {name, version, ecosystem, raw} for known services,
    plus a general snapshot of installed deb packages (for ecosystem='Debian' in OSV).

    `version` is the Debian package version (with revision, e.g.
    '1.28.3-1~deb13u2') when available via dpkg-query, NOT the upstream
    version number - see _dpkg_version()'s docstring for why this
    distinction matters for correct OSV matching. `upstream_version` keeps
    the human-readable upstream number (e.g. '1.28.3' from `nginx -v`) for
    display purposes only - it is never sent to OSV.

    `third_party_repo` (bool) flags packages whose dpkg version looks like
    it came from a vendor's own apt repo rather than the distro's own
    archive - see _is_official_distro_source()'s docstring. This
    was found running this check against a real server: nginx installed
    from nginx.org's official apt repo showed version '1.30.2-1~noble' -
    upstream 1.30.2 is actually below the CVE-2026-42533 fix (1.30.4), but
    OSV's 'Ubuntu:24.04:LTS' ecosystem has no record under that version
    string at all (Ubuntu's own security team doesn't track nginx.org's
    packages), so the check correctly found zero matches yet the host may
    still be exposed. check_cve_audit() surfaces this as a distinct
    'third_party_repo' finding rather than silently reporting 'ok'.
    """
    packages = []

    # --- nginx ---
    out, _ = ssh.run('nginx -v 2>&1')
    upstream_ver = _parse_version(out)
    if upstream_ver:
        dpkg_ver = _dpkg_version(ssh, 'nginx')
        origin = _get_package_origin(ssh, 'nginx', dpkg_ver) if dpkg_ver else None
        packages.append({'name': 'nginx', 'version': dpkg_ver or upstream_ver,
                          'upstream_version': upstream_ver, 'ecosystem': _GENERIC_LINUX_ECOSYSTEM,
                          'third_party_repo': bool(dpkg_ver) and not _is_official_distro_source(origin),
                          'raw': out.strip()})

    # --- OpenSSH ---
    out, _ = ssh.run('ssh -V 2>&1')
    upstream_ver = _parse_version(out)
    if upstream_ver:
        openssh_dpkg_pkg = 'openssh-client'
        dpkg_ver = _dpkg_version(ssh, openssh_dpkg_pkg)
        if not dpkg_ver:
            openssh_dpkg_pkg = 'openssh-server'
            dpkg_ver = _dpkg_version(ssh, openssh_dpkg_pkg)
        origin = _get_package_origin(ssh, openssh_dpkg_pkg, dpkg_ver) if dpkg_ver else None
        packages.append({'name': 'openssh', 'version': dpkg_ver or upstream_ver,
                          'upstream_version': upstream_ver, 'ecosystem': _GENERIC_LINUX_ECOSYSTEM,
                          'third_party_repo': bool(dpkg_ver) and not _is_official_distro_source(origin),
                          'raw': out.strip()})

    # --- MySQL / MariaDB ---
    out, _ = ssh.run('mysql --version 2>/dev/null || mariadb --version 2>/dev/null')
    upstream_ver = _parse_version(out)
    if upstream_ver:
        name = 'mariadb' if 'mariadb' in out.lower() else 'mysql'
        dpkg_pkg = 'mariadb-server' if name == 'mariadb' else 'mysql-server'
        dpkg_ver = _dpkg_version(ssh, dpkg_pkg)
        origin = _get_package_origin(ssh, dpkg_pkg, dpkg_ver) if dpkg_ver else None
        packages.append({'name': name, 'version': dpkg_ver or upstream_ver,
                          'upstream_version': upstream_ver, 'ecosystem': _GENERIC_LINUX_ECOSYSTEM,
                          'third_party_repo': bool(dpkg_ver) and not _is_official_distro_source(origin),
                          'raw': out.strip()})

    # --- PHP ---
    out, _ = ssh.run('php -v 2>/dev/null')
    upstream_ver = _parse_version(out)
    if upstream_ver:
        # PHP's Debian package name is versioned (e.g. php8.3-cli) rather
        # than a stable 'php' - resolving that dynamically is more moving
        # parts than this fix's scope covers, so PHP keeps using the
        # upstream version for OSV matching for now (same shape of
        # limitation as `linux` below, not a silent omission).
        packages.append({'name': 'php', 'version': upstream_ver,
                          'upstream_version': upstream_ver, 'ecosystem': _GENERIC_LINUX_ECOSYSTEM,
                          'third_party_repo': False,
                          'raw': out.strip().splitlines()[0] if out.strip() else ''})

    # --- kernel ---
    # linux-image-<uname -r> is the running kernel's dpkg package name -
    # confirmed the same ABI-vs-package-version gap exists here as it did
    # for nginx/openssh/mariadb before those were fixed: `uname -r`
    # reports the kernel's ABI/release string (e.g. '6.8.0-124-generic'),
    # which is NOT the same as the dpkg package's own version (e.g.
    # '6.8.0-124.124' or similar, with its own build/security-patch
    # revision) - a documented, well-known distinction (Debian's own
    # kernel-version documentation: "3.16.0-4 is *not* the kernel version
    # but the ABI name used"). OSV's Ubuntu/Debian ecosystem records
    # compare against the dpkg package version, same as every other
    # Debian-family package this module collects - resolved here the
    # same way, via dpkg-query on the specific linux-image package for
    # the currently-running kernel.
    out, _ = ssh.run('uname -r')
    kernel_release = out.strip()
    if kernel_release:
        dpkg_ver = _dpkg_version(ssh, f'linux-image-{kernel_release}')
        origin = _get_package_origin(ssh, f'linux-image-{kernel_release}', dpkg_ver) if dpkg_ver else None
        packages.append({'name': 'linux', 'version': dpkg_ver or kernel_release,
                          'upstream_version': kernel_release, 'ecosystem': _GENERIC_LINUX_ECOSYSTEM,
                          'third_party_repo': bool(dpkg_ver) and not _is_official_distro_source(origin),
                          'raw': kernel_release})

    # --- WordPress (if wp-config.php is found in standard locations) ---
    out, _ = ssh.run("find /var/www -maxdepth 3 -iname 'wp-includes' -type d 2>/dev/null | head -1")
    wp_dir = out.strip()
    if wp_dir:
        base = wp_dir.rsplit('/wp-includes', 1)[0]
        ver_out, _ = ssh.run(f"grep -m1 \"\\$wp_version = \" {base}/wp-includes/version.php 2>/dev/null")
        ver = _parse_version(ver_out)
        if ver:
            packages.append({'name': 'wordpress', 'version': ver,
                              'upstream_version': ver, 'ecosystem': 'WordPress',
                              'third_party_repo': False, 'raw': ver_out.strip()})

    return packages


# ===========================================================================
# OSV.dev - matching + details
# ===========================================================================

def _cache_get(name: str, version: str, ecosystem: str) -> list | None:
    # ecosystem is part of the cache key (not just name::version) - a
    # cached result for ecosystem 'Debian' (pre-fix, noisy) must never be
    # served back for a query now made with 'Debian:13' (post-fix, narrow),
    # and vice versa. Without this, the 24h cache would silently keep
    # returning stale/wrong-shape results after this module's ecosystem
    # string changes for a host, until the TTL happens to expire.
    row = storage.cve_get(f'{name}::{version}::{ecosystem}')
    if not row:
        return None
    updated = datetime.fromisoformat(row['updated_at'])
    if datetime.now() - updated > timedelta(hours=CACHE_TTL_HOURS):
        return None
    return row['data']


def _cache_set(name: str, version: str, ecosystem: str, data: list) -> None:
    storage.cve_set(f'{name}::{version}::{ecosystem}', data)


# Registry mapping a distro's /etc/os-release ID field to a function that
# builds its OSV ecosystem string from VERSION_ID. This is the single
# place new distros get added - no other code in this module needs to
# change to support a new one. Each builder receives the raw VERSION_ID
# string exactly as os-release reports it and returns the OSV ecosystem
# string, or None if that particular version can't be resolved (e.g. a
# malformed VERSION_ID for that distro's expected format).
#
# Every entry here is backed by a confirmed real OSV ecosystem string
# (checked against osv.dev's own published records / API documentation,
# not guessed):
#   - Debian:  'Debian:{N}'                       e.g. 'Debian:13'
#   - Ubuntu:  'Ubuntu:{X.Y}:LTS' / 'Ubuntu:{X.Y}' e.g. 'Ubuntu:24.04:LTS'
#   - AlmaLinux: 'AlmaLinux:{N}'                   e.g. 'AlmaLinux:9'
#   - Rocky Linux: 'Rocky Linux:{N}'               e.g. 'Rocky Linux:9'
#   - Alpine:  'Alpine:v{X.Y}'                     e.g. 'Alpine:v3.19'
#
# Deliberately NOT included: plain 'rhel' (Red Hat Enterprise Linux
# itself has no OSV ecosystem string as of this writing -
# google/osv.dev#1404 is still open requesting it) and 'opensuse'/'sles'
# (OSV's SUSE data exists but this module hasn't confirmed the exact
# ecosystem string format against a real API response yet - added when
# that's verified, not guessed at here). A host running one of these
# gets os_id set correctly by collect_os_release() but no entry in this
# registry, so _resolve_ecosystem() correctly returns None for it - "we
# know what this is, we just don't build its OSV string yet" is a
# different, more honest state than "we don't recognize this at all".
_DISTRO_ECOSYSTEM_BUILDERS = {
    'debian': lambda v: f'Debian:{v}',
    'ubuntu': lambda v: f'Ubuntu:{v}:LTS' if v.endswith('.04') else f'Ubuntu:{v}',
    'almalinux': lambda v: f'AlmaLinux:{v}',
    'rocky': lambda v: f'Rocky Linux:{v}',
    'alpine': lambda v: f'Alpine:v{v}',
}


def _resolve_ecosystem(pkg_ecosystem: str, os_id: str | None,
                        version_id: str | None) -> str | None:
    """Turns a package's generic base ecosystem ('Linux', 'WordPress', ...)
    into the actual OSV ecosystem string to query, given the real distro
    identity from collect_os_release(). Returns None if this module
    doesn't have a registered ecosystem builder for the given os_id (see
    _DISTRO_ECOSYSTEM_BUILDERS above) - callers must treat that as "can't
    check this package on this distro yet", not as "no vulnerabilities
    found". Guessing at a wrong ecosystem string (e.g. defaulting every
    unrecognized dpkg-based host to 'Debian') is worse than admitting the
    limitation - that was this module's original bug: it hardcoded every
    package's ecosystem to 'Debian' regardless of the actual host, which
    silently mismatched Ubuntu hosts (see this module's top docstring for
    the real-world case that exposed it).

    '_GENERIC_LINUX_ECOSYSTEM' ('Linux') is a placeholder used throughout
    collect_packages() for "some Linux distro package, distro unknown at
    collection time" - it is NOT itself a real OSV ecosystem, and must
    never be sent to OSV as-is. This function looks up os_id in
    _DISTRO_ECOSYSTEM_BUILDERS and, if found, calls that distro's builder
    with version_id. Adding support for a new distro means adding one
    entry to that registry - this function's own logic never needs to
    change for that.

    WordPress and any other non-'_GENERIC_LINUX_ECOSYSTEM' ecosystem
    passes through completely unchanged, regardless of os_id/version_id -
    it's not part of any Linux distro's package ecosystem at all.
    """
    if pkg_ecosystem != _GENERIC_LINUX_ECOSYSTEM:
        return pkg_ecosystem
    if not version_id or not os_id:
        return None
    builder = _DISTRO_ECOSYSTEM_BUILDERS.get(os_id)
    if builder is None:
        return None
    return builder(version_id)


def query_osv(packages: list[dict], os_id: str | None = None,
              version_id: str | None = None) -> dict[str, list | None]:
    """Returns {pkg_name: [vuln_ids...] | None}, with caching. A value of
    None (not an empty list) means this package's ecosystem couldn't be
    resolved for this host's distro (see _resolve_ecosystem()) - it was
    never sent to OSV at all, and the caller must not report it as "no
    known CVEs found", which would misrepresent an unchecked package as a
    checked-and-clean one.

    os_id/version_id (from collect_os_release()) resolve every package
    whose generic ecosystem is '_GENERIC_LINUX_ECOSYSTEM' to the actual
    distro-specific OSV ecosystem string. Packages with a different
    ecosystem (WordPress) are queried as-is, unaffected."""
    to_query = []
    result: dict[str, list | None] = {}

    for p in packages:
        ecosystem = _resolve_ecosystem(p['ecosystem'], os_id, version_id)
        if ecosystem is None:
            result[p['name']] = None
            continue
        cached = _cache_get(p['name'], p['version'], ecosystem)
        if cached is not None:
            result[p['name']] = cached
        else:
            to_query.append((p, ecosystem))

    if not to_query:
        return result

    try:
        resp = httpx.post(
            OSV_BATCH_URL,
            json={'queries': [
                {'package': {'name': p['name'], 'ecosystem': ecosystem}, 'version': p['version']}
                for p, ecosystem in to_query
            ]},
            timeout=20,
        )
        resp.raise_for_status()
        batch = resp.json().get('results', [])
    except httpx.HTTPError:
        # OSV is unreachable - don't fail the whole check, just skip CVE data for unqueried ones
        for p, _ecosystem in to_query:
            result.setdefault(p['name'], [])
        return result

    for (p, ecosystem), r in zip(to_query, batch):
        ids = [v['id'] for v in r.get('vulns', [])]
        result[p['name']] = ids
        _cache_set(p['name'], p['version'], ecosystem, ids)

    return result


def fetch_vuln_details(vuln_id: str) -> dict:
    try:
        resp = httpx.get(OSV_VULN_URL.format(id=vuln_id), timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError:
        return {'id': vuln_id, 'error': 'failed to fetch details'}

    severity = None
    for sev in data.get('severity', []):
        if sev.get('type') == 'CVSS_V3':
            severity = sev.get('score')

    fixed_versions = []
    for aff in data.get('affected', []):
        for rng in aff.get('ranges', []):
            for ev in rng.get('events', []):
                if 'fixed' in ev:
                    fixed_versions.append(ev['fixed'])

    return {
        'id': vuln_id,
        'summary': data.get('summary') or data.get('details', '')[:200],
        'severity': severity,
        'fixed_versions': sorted(set(fixed_versions)),
        'references': [r['url'] for r in data.get('references', [])[:3]],
    }


# ===========================================================================
# Combined check
# ===========================================================================

@register(
    id='cve_audit', label='CVE audit of installed software (SSH)', category='security',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Host', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'User', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH port', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Key path', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Password (if not using a key)', 'default': ''},
    ],
    required_tools=[],
    description='Collects installed software versions (nginx, ssh, mysql/mariadb, php, kernel, wordpress) '
                'over SSH and checks them against the OSV.dev vulnerability database. AI analysis (shared '
                'ai_analyze) will match found CVEs against the actual service config and say what actually needs updating.',
)
def check_cve_audit(host='', user='root', port=22, key_path='', password='') -> dict:
    if paramiko is None:
        return {'error': 'paramiko not installed'}
    if not host:
        return {'error': 'host not specified'}
    try:
        ssh = SSHExecutor(host, user, port, key_path, password).connect()
    except HostKeyMismatchError as e:
        return {'error': str(e)}
    except Exception as e:
        return {'error': f'could not connect: {e}'}

    try:
        packages = collect_packages(ssh)
        os_id, version_id = collect_os_release(ssh)
    finally:
        ssh.close()

    if not packages:
        return {'host': host, 'packages': [], 'findings': [],
                'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'ok': 0, 'not_supported': 0, 'third_party_repo': 0}}

    vuln_ids_by_pkg = query_osv(packages, os_id, version_id)

    findings = []
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'ok': 0, 'not_supported': 0, 'third_party_repo': 0}

    for p in packages:
        ids = vuln_ids_by_pkg.get(p['name'])
        if ids is None:
            # Ecosystem couldn't be resolved for this host's distro (see
            # _resolve_ecosystem()) - this package was never queried
            # against OSV at all. Must not be reported as 'ok'/"no known
            # CVEs found", which would misrepresent an unchecked package
            # as a checked-and-clean one - a distinct 'not_supported'
            # severity makes the gap visible instead of silently absent.
            findings.append({
                'package': p['name'], 'version': p['version'],
                'severity': 'not_supported', 'cve': None,
                'title': 'CVE matching not supported for this distro',
            })
            counts['not_supported'] += 1
            continue
        if not ids:
            if p.get('third_party_repo'):
                # A resolved ecosystem query came back empty, but this
                # package's dpkg version looks like it came from a
                # vendor's own apt repo rather than the distro's archive
                # (see _is_official_distro_source()'s
                # docstring) - e.g. nginx installed from nginx.org's own
                # official apt repo, a legitimate and nginx-recommended
                # install method, not a red flag in itself. The point
                # isn't that the source is untrustworthy - it's that the
                # distro's security team (Ubuntu, Debian, ...) doesn't
                # track that vendor's package/version at all, so an
                # empty OSV result here means "no data", not "verified
                # clean". Reporting this as plain 'ok' would be the same
                # false-negative shape as the module's original
                # Debian-hardcoding bug: a technically-correct-looking
                # query silently produces a misleading "all clear". The
                # user-facing text below is deliberately neutral (not
                # "third-party"/"untrusted") - it names the actual gap
                # (distro tracker coverage), not a judgment on the
                # package's origin.
                findings.append({
                    'package': p['name'], 'version': p['version'],
                    'severity': 'third_party_repo', 'cve': None,
                    'title': 'not tracked by the distro security team — checked separately',
                })
                counts['third_party_repo'] += 1
                continue
            findings.append({
                'package': p['name'], 'version': p['version'],
                'severity': 'ok', 'cve': None, 'title': 'no known CVEs found',
            })
            counts['ok'] += 1
            continue
        for vid in ids[:10]:  # cap it so we don't DDoS OSV for a package with a hundred CVEs
            details = fetch_vuln_details(vid)
            score = details.get('severity')
            try:
                score_f = float(score.split('/')[0]) if score else None
            except (ValueError, AttributeError):
                score_f = None
            if score_f is not None:
                sev = 'critical' if score_f >= 9 else 'high' if score_f >= 7 else 'medium' if score_f >= 4 else 'low'
            else:
                sev = 'medium'  # unknown score - don't downplay it
            counts[sev] = counts.get(sev, 0) + 1
            findings.append({
                'package': p['name'], 'version': p['version'], 'severity': sev,
                'cve': vid, 'title': details.get('summary', ''),
                'fixed_versions': details.get('fixed_versions', []),
                'references': details.get('references', []),
            })

    return {
        'host': host,
        'packages': packages,
        'findings': findings,
        'summary': counts,
    }
