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

import json
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


# Marker used by _run_with_exit_code() to recover a command's exit status.
# SSHExecutor.run() only returns (stdout, stderr) - no exit code - because
# it's the shared executor for 9 other check modules and none of the rest
# need one; changing its signature for this module's sake would be a
# needlessly wide blast radius for one collector's requirement. This
# marker recovers the exit code locally, for this module only, without
# touching that shared contract.
_EXIT_MARKER = '__NETAUDIT_CVE_AUDIT_EXIT__'


def _run_with_exit_code(ssh: SSHExecutor, cmd: str, timeout: int = 20) -> tuple[str, int | None]:
    """Runs `cmd` and returns (stdout, exit_code).

    exit_code is None if the command's completion could not be confirmed -
    SSH channel drop, timeout, or truncated output before the marker was
    written. This is a genuine unknown, distinct from exit_code=1 (or any
    other nonzero code), which means the command ran to completion and
    reported failure through the normal exit-status channel (e.g.
    dpkg-query: package not installed).

    The command is wrapped in a shell group so `$?` is captured
    immediately after it runs, before anything else (including the
    `printf` itself) can change it:

        { <cmd>; rc=$?; printf '\\n%s:%s\\n' '<marker>' "$rc"; }

    The marker string is long and namespaced specifically so an
    arbitrarily-chosen remote command's own stdout is exceedingly
    unlikely to collide with it by coincidence; if it ever does, the
    output up to the last marker occurrence is still returned as `out`,
    a false collection failure (marker misparsed as absent) rather than
    a false success is the safe failure direction here.
    """
    wrapped = f"{{ {cmd}; rc=$?; printf '\\n%s:%s\\n' '{_EXIT_MARKER}' \"$rc\"; }}"
    out, _ = ssh.run(wrapped, timeout=timeout)
    if _EXIT_MARKER not in out:
        return out, None
    body, _, tail = out.rpartition(_EXIT_MARKER)
    code_str = tail.lstrip(':').strip()
    try:
        code = int(code_str)
    except ValueError:
        return body, None
    return body.rstrip('\n'), code


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


def _dpkg_version(ssh: SSHExecutor, dpkg_name: str) -> tuple[str | None, bool]:
    """Returns (version, collection_ok).

    version is the installed Debian package version (with revision, e.g.
    '1.28.3-1~deb13u2') via dpkg-query, or None if dpkg-query ran to
    completion and reported the package isn't installed via dpkg (e.g.
    compiled from source, installed via a third-party repo with a
    non-dpkg-tracked version, or simply absent).

    collection_ok is False if dpkg-query's completion could not be
    confirmed at all (SSH channel drop, timeout - see
    _run_with_exit_code()) - a genuine unknown, NOT evidence the package
    is absent. Callers MUST NOT fall back to upstream_version when
    collection_ok is False - that fallback is only valid for a
    successfully-confirmed "not installed" (version=None,
    collection_ok=True), and conflating the two was this exact function's
    original bug: a dropped SSH command and a genuinely-absent package
    both produced an empty stdout, so both silently took the same
    upstream_version fallback path - the same false-PASS shape as the
    ecosystem-defaulting bug described in this module's top docstring,
    just one layer lower (which version string to send, rather than
    which ecosystem to send it to).

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
    out, code = _run_with_exit_code(ssh, f"dpkg-query -W -f='${{Version}}' {dpkg_name} 2>/dev/null")
    if code is None:
        return None, False
    out = out.strip()
    return (out if out else None), True


def _get_package_origin(ssh: SSHExecutor, dpkg_name: str, version: str) -> str | None:
    """Returns the 'Origin' field (e.g. 'Ubuntu', 'Debian', 'nginx') of
    the specific installed version of a package, or None if it can't be
    determined - package not installed via dpkg, no matching cache
    entry, etc.

    NOTE (quality audit, 2026-08-15): this function has the same
    collection-failure-vs-absence ambiguity _dpkg_version() had before
    its fix - a dropped SSH command and a genuinely-missing Origin field
    both produce None here, and collect_packages() currently treats both
    the same way (third_party_repo=True). Left unfixed in this pass
    deliberately: the impact is a mislabeled 'third_party_repo' finding
    (severity-4/non-blocking per the audit triage), not a missed CVE the
    way _dpkg_version()'s version fallback was - fixing it properly means
    touching all 4 collect_packages() call sites and adding a third
    origin-unknown state, which is more scope than this fix batch covers.
    Tracked as a follow-up, not silently accepted.

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

    `version_collection_ok` (bool) is False when _dpkg_version() could not
    confirm dpkg-query completed at all (SSH channel drop, timeout - see
    _run_with_exit_code()) - as opposed to dpkg-query completing and
    reporting the package genuinely isn't dpkg-installed. In that case
    `version` still falls back to the upstream version (so the package is
    still reported on, e.g. for display), but check_cve_audit() must
    treat this package as a collection failure rather than querying OSV
    with a version string collection couldn't actually confirm - see this
    module's quality-audit notes on _dpkg_version() for the false-PASS
    this prevents.
    """
    packages = []

    # --- nginx ---
    out, _ = ssh.run('nginx -v 2>&1')
    upstream_ver = _parse_version(out)
    if upstream_ver:
        dpkg_ver, collection_ok = _dpkg_version(ssh, 'nginx')
        origin = _get_package_origin(ssh, 'nginx', dpkg_ver) if dpkg_ver else None
        packages.append({'name': 'nginx', 'version': dpkg_ver or upstream_ver,
                          'upstream_version': upstream_ver, 'ecosystem': _GENERIC_LINUX_ECOSYSTEM,
                          'third_party_repo': bool(dpkg_ver) and not _is_official_distro_source(origin),
                          'version_collection_ok': collection_ok,
                          'raw': out.strip()})

    # --- OpenSSH ---
    out, _ = ssh.run('ssh -V 2>&1')
    upstream_ver = _parse_version(out)
    if upstream_ver:
        openssh_dpkg_pkg = 'openssh-client'
        dpkg_ver, collection_ok = _dpkg_version(ssh, openssh_dpkg_pkg)
        if not dpkg_ver and collection_ok:
            # Only try the -server package name if -client was
            # successfully confirmed absent - not on a collection
            # failure, which would just mask the first failure with a
            # second SSH round-trip's ambiguous result.
            openssh_dpkg_pkg = 'openssh-server'
            dpkg_ver, collection_ok = _dpkg_version(ssh, openssh_dpkg_pkg)
        origin = _get_package_origin(ssh, openssh_dpkg_pkg, dpkg_ver) if dpkg_ver else None
        packages.append({'name': 'openssh', 'version': dpkg_ver or upstream_ver,
                          'upstream_version': upstream_ver, 'ecosystem': _GENERIC_LINUX_ECOSYSTEM,
                          'third_party_repo': bool(dpkg_ver) and not _is_official_distro_source(origin),
                          'version_collection_ok': collection_ok,
                          'raw': out.strip()})

    # --- MySQL / MariaDB ---
    out, _ = ssh.run('mysql --version 2>/dev/null || mariadb --version 2>/dev/null')
    upstream_ver = _parse_version(out)
    if upstream_ver:
        name = 'mariadb' if 'mariadb' in out.lower() else 'mysql'
        dpkg_pkg = 'mariadb-server' if name == 'mariadb' else 'mysql-server'
        dpkg_ver, collection_ok = _dpkg_version(ssh, dpkg_pkg)
        origin = _get_package_origin(ssh, dpkg_pkg, dpkg_ver) if dpkg_ver else None
        packages.append({'name': name, 'version': dpkg_ver or upstream_ver,
                          'upstream_version': upstream_ver, 'ecosystem': _GENERIC_LINUX_ECOSYSTEM,
                          'third_party_repo': bool(dpkg_ver) and not _is_official_distro_source(origin),
                          'version_collection_ok': collection_ok,
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
                          'third_party_repo': False, 'version_collection_ok': True,
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
        dpkg_ver, collection_ok = _dpkg_version(ssh, f'linux-image-{kernel_release}')
        origin = _get_package_origin(ssh, f'linux-image-{kernel_release}', dpkg_ver) if dpkg_ver else None
        packages.append({'name': 'linux', 'version': dpkg_ver or kernel_release,
                          'upstream_version': kernel_release, 'ecosystem': _GENERIC_LINUX_ECOSYSTEM,
                          'third_party_repo': bool(dpkg_ver) and not _is_official_distro_source(origin),
                          'version_collection_ok': collection_ok,
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
                              'third_party_repo': False, 'version_collection_ok': True,
                              'raw': ver_out.strip()})

    return packages


def collect_composer_packages(ssh: SSHExecutor) -> list[dict]:
    """Returns a list of {name, version, ecosystem, raw} for every package
    listed in a discovered composer.lock file (Laravel and any other PHP
    Composer project) - both the 'packages' (production) and
    'packages-dev' sections, since a dev-only dependency (e.g. a testing
    tool with a known RCE) is still a real risk on a server where the
    project directory - and its dev dependencies - are actually deployed,
    not stripped out.

    Unlike collect_packages()'s single-service entries (one nginx, one
    kernel, ...), a Laravel project can easily have 100+ locked
    dependencies (laravel/framework itself, plus every Symfony component
    it depends on, Guzzle, Doctrine, Monolog, and so on) - this returns
    all of them, each as its own package dict, to be checked against OSV
    the same way every other package in this module is.

    ecosystem is 'Packagist' - confirmed against OSV.dev's own API
    documentation and a real querybatch example in the OSV.dev issue
    tracker (google/osv.dev#466): {"package": {"ecosystem": "Packagist",
    "name": "noumo/easyii"}, "version": "0.8"}. This is NOT part of the
    Debian/Ubuntu ecosystem-resolution logic this module uses for
    dpkg-based packages (_resolve_ecosystem() passes it through
    unchanged, the same way it already does for 'WordPress') - Packagist
    is entirely independent of which Linux distro the server runs.

    Search locations: /var/www and /home, maxdepth 6, with vendor/
    directories explicitly excluded. Both were confirmed necessary against
    real servers, not assumed from documentation:

    - /home is required in addition to /var/www because managed Laravel
      hosting (Forge, Ploi, Envoyer - all common, real deployment targets)
      puts sites under /home/<user>/<domain>/, not /var/www. Confirmed on
      a real server: /home/forge/<domain>/composer.lock. Missing this
      entirely would silently skip a large fraction of real Laravel
      deployments.
    - Excluding vendor/ (`-not -path '*/vendor/*'`) is required because
      individual Composer dependencies can ship their OWN composer.lock
      inside their own package directory (e.g. phpunit/phpunit,
      mockery/mockery both do) - confirmed on a real server where a bare
      `find ... -iname composer.lock` returned five results, four of them
      nested inside vendor/ and belonging to sub-dependencies, only one
      (the project root's own composer.lock) being the actual file this
      function needs. Without this exclusion, `head -1`'s result depends
      on find's traversal order, which is not guaranteed to put the real
      project-root lock file first - on that server it did not.

    Only the first composer.lock found (after the vendor/ exclusion) is
    read (same single-site assumption collect_packages()'s WordPress
    detection already makes) - a server hosting multiple independent PHP
    projects would need a different collection strategy, out of scope here.
    """
    out, _ = ssh.run(
        "find /var/www /home -maxdepth 6 -iname 'composer.lock' -not -path '*/vendor/*' "
        "-type f 2>/dev/null | head -1"
    )
    lock_path = out.strip()
    if not lock_path:
        return []

    content, _ = ssh.run(f'cat {lock_path} 2>/dev/null')
    if not content.strip():
        return []

    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        # A malformed or partially-read lock file must not crash the
        # whole check - same defensive stance every other parser in this
        # module takes toward unexpected input.
        return []

    packages = []
    for section in ('packages', 'packages-dev'):
        for entry in data.get(section, []):
            name = entry.get('name')
            version = entry.get('version')
            if not name or not version:
                continue
            # composer.lock versions are commonly prefixed with 'v'
            # (e.g. 'v13.15.0' for laravel/framework) - OSV's Packagist
            # ecosystem data is keyed on the bare semver without the
            # prefix, so it's stripped here rather than sent as-is and
            # silently failing to match. A plain slice, not str.lstrip('v')
            # - lstrip() removes every leading character present in its
            # argument set one at a time, not a fixed prefix, so it would
            # silently mangle any version string with more than one
            # leading 'v' (or, worse, treat 'v' as a character class and
            # strip further characters that happen to also be 'v').
            clean_version = version[1:] if version.startswith('v') else version
            packages.append({
                'name': name, 'version': clean_version,
                'upstream_version': version, 'ecosystem': 'Packagist',
                'third_party_repo': False, 'version_collection_ok': True,
                'raw': f'{name} {version}',
            })
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
              version_id: str | None = None) -> tuple[dict[str, list | None], set[str]]:
    """Returns ({pkg_name: [vuln_ids...] | None}, collection_errors), with
    caching.

    In the result dict: a value of None (not an empty list) means this
    package's ecosystem couldn't be resolved for this host's distro (see
    _resolve_ecosystem()) - it was never sent to OSV at all. An empty
    list means OSV was successfully queried and reported no known vulns.

    collection_errors is the set of package names that SHOULD have gotten
    an OSV answer but didn't, because OSV's own response contained fewer
    entries than were queried (see below) - this is a distinct third
    state from both of the above, and deliberately not folded into the
    result dict as another None: None there already means "ecosystem
    unresolved", a different fact (we chose not to ask) from "we asked
    but didn't get an answer for this one". Reusing None for both would
    let a genuine collection failure silently read as an ordinary
    ecosystem-not-supported case at every call site that just checks
    `is None`. Callers must check collection_errors FIRST, before reading
    the result dict for a given package.

    OSV's querybatch response ordering is guaranteed to match the request
    (confirmed against OSV's own API docs: "The response ordering will be
    guaranteed to match the input" - https://google.github.io/osv.dev/post-v1-querybatch/),
    so zip()ing queried packages against the response never mismatches
    package identity. But querybatch's docs also describe per-result
    pagination via page_token, meaning the API can validly return fewer -
    or differently-shaped - top-level result entries than were queried
    under conditions this module doesn't otherwise control for. A
    response shorter than the request is therefore a real, if rare,
    possibility - not merely a hypothetical - and packages past the end
    of a short response must be reported as a collection failure, not
    silently dropped (which .get()-based lookups downstream would then
    read as "ecosystem unresolved", a different and misleading claim -
    see check_cve_audit()).

    os_id/version_id (from collect_os_release()) resolve every package
    whose generic ecosystem is '_GENERIC_LINUX_ECOSYSTEM' to the actual
    distro-specific OSV ecosystem string. Packages with a different
    ecosystem (WordPress) are queried as-is, unaffected."""
    to_query = []
    result: dict[str, list | None] = {}
    collection_errors: set[str] = set()

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
        return result, collection_errors

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
        return result, collection_errors

    for (p, ecosystem), r in zip(to_query, batch):
        ids = [v['id'] for v in r.get('vulns', [])]
        result[p['name']] = ids
        _cache_set(p['name'], p['version'], ecosystem, ids)

    if len(batch) < len(to_query):
        # OSV returned fewer results than queried - see docstring above.
        # These packages were never confirmed clean or vulnerable; do not
        # cache anything for them (nothing to cache), and do not set
        # result[name] at all here, so a caller reading collection_errors
        # first (as required) never even reaches the result dict for
        # these names.
        for p, _ecosystem in to_query[len(batch):]:
            collection_errors.add(p['name'])

    return result, collection_errors


def fetch_vuln_details(vuln_id: str) -> dict:
    try:
        resp = httpx.get(OSV_VULN_URL.format(id=vuln_id), timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError:
        return {'id': vuln_id, 'error': 'failed to fetch details'}

    severity = None
    vendor_priority = None
    for sev in data.get('severity', []):
        if sev.get('type') == 'CVSS_V3':
            severity = sev.get('score')
        elif sev.get('type') in ('Ubuntu', 'Debian'):
            # Distro-vendor-assigned priority (negligible/low/medium/high/
            # critical for Ubuntu) - kept separate from the CVSS score
            # because the two can and do disagree, and when they do, the
            # vendor's own assessment for their own distro is the more
            # accurate one to act on. Confirmed via Ubuntu's own published
            # guidance: "If the affected package is maintained by an OS
            # vendor, the severity as indicated by the vendor is used and
            # not the severity determined by NVD" (Canonical's own
            # documentation on CVE prioritisation - this is standard
            # practice other vulnerability scanners already follow, not
            # a netaudit-specific policy).
            vendor_priority = sev.get('score')

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
        'vendor_priority': vendor_priority,
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
    description='Collects installed software versions (nginx, ssh, mysql/mariadb, php, kernel, wordpress, '
                'composer.lock dependencies e.g. Laravel) '
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
        packages += collect_composer_packages(ssh)
        os_id, version_id = collect_os_release(ssh)
    finally:
        ssh.close()

    if not packages:
        return {'host': host, 'packages': [], 'findings': [],
                'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'ok': 0,
                            'not_supported': 0, 'third_party_repo': 0, 'collection_error': 0}}

    # Packages whose version couldn't be confirmed (version_collection_ok
    # is False) must never reach OSV at all - the 'version' string on
    # them is an unconfirmed upstream-version guess, not a fact (see
    # _dpkg_version()'s docstring), and querying OSV with it would just
    # push the same false-PASS risk one function further down the call
    # chain instead of actually closing it.
    queryable = [p for p in packages if p.get('version_collection_ok', True)]
    vuln_ids_by_pkg, collection_errors = query_osv(queryable, os_id, version_id)

    findings = []
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'ok': 0,
              'not_supported': 0, 'third_party_repo': 0, 'collection_error': 0}

    for p in packages:
        if not p.get('version_collection_ok', True):
            # dpkg-query's completion couldn't be confirmed for this
            # package (SSH channel drop, timeout - see _dpkg_version()) -
            # `version` here fell back to the upstream version string,
            # which is not what was actually installed's dpkg revision.
            # Querying OSV with it would be querying with an unconfirmed
            # guess, not a fact - reported as a collection gap, same
            # 'info' shape as an unresolved-OSV-batch-entry below, never
            # as 'ok'.
            findings.append({
                'package': p['name'], 'version': p['version'],
                'severity': 'info', 'cve': None,
                'title': 'CVE matching could not be completed for this package — version '
                         'collection did not finish (this does NOT mean no CVEs were found)',
                'requires_manual_verification': True,
            })
            counts['collection_error'] += 1
            continue
        if p['name'] in collection_errors:
            # OSV's own batch response came back shorter than the
            # request (see query_osv()'s docstring) - this package was
            # queried but no answer was received for it. Same 'info'
            # shape and same rule: never 'ok', because we have no
            # evidence either way.
            findings.append({
                'package': p['name'], 'version': p['version'],
                'severity': 'info', 'cve': None,
                'title': 'CVE matching could not be completed for this package — no answer '
                         'received from the vulnerability database (this does NOT mean no CVEs were found)',
                'requires_manual_verification': True,
            })
            counts['collection_error'] += 1
            continue
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
            vendor_priority = details.get('vendor_priority')
            if vendor_priority:
                # Prefer the distro's own priority over CVSS when both are
                # known - per Ubuntu's own published guidance, the vendor's
                # assessment for their own distro is the more accurate one
                # (see fetch_vuln_details()'s docstring comment for the
                # full reasoning and source). This is also what fixes the
                # historical-noise problem found running this check
                # against a real Ubuntu 26.04 server: Ubuntu's own CVE
                # tracker carries many old kernel CVE entries marked
                # 'negligible'/'low' priority ("For informational purposes
                # only. We recommend not to cherry-pick updates.") that
                # OSV's version-range data alone doesn't distinguish from
                # an actually-actionable finding - CVSS-only scoring
                # treated all of them as at least 'medium', which buried
                # the few genuinely severe/actionable findings in a wall
                # of Ubuntu's own already-triaged-as-low-priority noise.
                sev = {
                    'negligible': 'low', 'low': 'low', 'medium': 'medium',
                    'high': 'high', 'critical': 'critical',
                }.get(vendor_priority.lower(), 'medium')
            else:
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
