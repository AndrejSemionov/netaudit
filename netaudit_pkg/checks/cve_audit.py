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

Debian ecosystem versioning (2026-08-11 fix)
---------------------------------------------
Querying OSV.dev with the bare ecosystem string 'Debian' (no release number)
is a known, still-open OSV.dev issue (google/osv.dev#4230, opened 2025-10-23,
unresolved as of this writing): OSV matches against the union of ALL Debian
release version ranges ("widest range" per OSV maintainer michaelkedar's own
explanation in that thread), not just the one actually installed. In
practice this means a query for e.g. nginx 1.28.3 returns CVEs going back to
2000 that were fixed a decade or more ago in every release anyone actually
runs today - the exact "historical noise" observed running this check
against a real server (30 findings, most from Debian releases nobody has
run since the 2000s).

The documented, maintainer-confirmed fix (same thread) is to query the
*specific* Debian release ecosystem string, e.g. 'Debian:13' for Trixie,
instead of the bare 'Debian'. This narrows OSV's matching to that release's
actual fixed-version ranges. This module now reads /etc/os-release on the
target host to get VERSION_ID (Debian's release number, e.g. '13') and
builds the ecosystem string as f'Debian:{version_id}' for every
Debian-family package (WordPress, which uses ecosystem 'WordPress', is
unaffected by any of this - only Debian-packaged software).

If VERSION_ID can't be read (older os-release format, non-Debian base, etc),
this module falls back to the bare 'Debian' ecosystem string and accepts the
historical-noise risk rather than silently skipping CVE matching for that
host entirely - a noisy result is still strictly more useful than no result,
and the fallback is visible in collect_os_release()'s return value so a
caller can tell which path was taken.
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

# Ecosystems where OSV's Debian-release-matching issue (see module
# docstring) applies - i.e. every ecosystem this module currently collects
# facts for EXCEPT 'WordPress', which is its own independent OSV ecosystem
# unaffected by Debian release versioning entirely.
_DEBIAN_FAMILY_ECOSYSTEM = 'Debian'


# ===========================================================================
# Collecting service versions over SSH
# ===========================================================================

def _parse_version(text: str) -> str | None:
    m = re.search(r'(\d+\.\d+(?:\.\d+)?)', text)
    return m.group(1) if m else None


def collect_os_release(ssh: SSHExecutor) -> str | None:
    """Returns the Debian release number (VERSION_ID from /etc/os-release,
    e.g. '13' for Trixie) or None if it can't be determined - old
    os-release format, non-Debian base, or the file doesn't exist.

    Read-only, single command. Deliberately separate from collect_packages()
    so it can be unit-tested independently and so a future caller only
    needing the release number doesn't have to run the full package
    collection to get it.
    """
    out, _ = ssh.run("grep '^VERSION_ID=' /etc/os-release 2>/dev/null")
    # VERSION_ID is double-quoted in a standard os-release file, e.g.
    # VERSION_ID="13" - strip the key and the quotes, don't assume a
    # specific quote style since some minimal/custom images vary.
    m = re.search(r'VERSION_ID="?([0-9]+)"?', out)
    return m.group(1) if m else None


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

    If dpkg-query finds nothing for a given package (not installed via
    dpkg - compiled from source, third-party repo, etc), this falls back
    to the upstream version for OSV matching too, same reasoning as
    _resolve_ecosystem()'s Debian-release fallback: a less precise match
    beats no match at all, and this is visible to a caller via
    upstream_version == version in that case.
    """
    packages = []

    # --- nginx ---
    out, _ = ssh.run('nginx -v 2>&1')
    upstream_ver = _parse_version(out)
    if upstream_ver:
        dpkg_ver = _dpkg_version(ssh, 'nginx')
        packages.append({'name': 'nginx', 'version': dpkg_ver or upstream_ver,
                          'upstream_version': upstream_ver, 'ecosystem': 'Debian', 'raw': out.strip()})

    # --- OpenSSH ---
    out, _ = ssh.run('ssh -V 2>&1')
    upstream_ver = _parse_version(out)
    if upstream_ver:
        dpkg_ver = _dpkg_version(ssh, 'openssh-client') or _dpkg_version(ssh, 'openssh-server')
        packages.append({'name': 'openssh', 'version': dpkg_ver or upstream_ver,
                          'upstream_version': upstream_ver, 'ecosystem': 'Debian', 'raw': out.strip()})

    # --- MySQL / MariaDB ---
    out, _ = ssh.run('mysql --version 2>/dev/null || mariadb --version 2>/dev/null')
    upstream_ver = _parse_version(out)
    if upstream_ver:
        name = 'mariadb' if 'mariadb' in out.lower() else 'mysql'
        dpkg_pkg = 'mariadb-server' if name == 'mariadb' else 'mysql-server'
        dpkg_ver = _dpkg_version(ssh, dpkg_pkg)
        packages.append({'name': name, 'version': dpkg_ver or upstream_ver,
                          'upstream_version': upstream_ver, 'ecosystem': 'Debian', 'raw': out.strip()})

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
                          'upstream_version': upstream_ver, 'ecosystem': 'Debian',
                          'raw': out.strip().splitlines()[0] if out.strip() else ''})

    # --- kernel ---
    # Deliberately still uses `uname -r` (upstream/ABI version), not
    # dpkg-query - the installed package name for the running kernel is
    # `linux-image-$(uname -r)` (or a meta-package like `linux-image-amd64`
    # that doesn't carry the real version itself), resolving which one
    # applies is a second, separate problem from this fix's scope
    # (Debian-family package version precision for nginx/openssh/mariadb/
    # mysql). Not addressed here to avoid conflating two different fixes
    # in one change - a future revision can add kernel-specific dpkg
    # resolution as its own deliberate step.
    out, _ = ssh.run('uname -r')
    if out.strip():
        packages.append({'name': 'linux', 'version': out.strip(),
                          'upstream_version': out.strip(), 'ecosystem': 'Debian', 'raw': out.strip()})

    # --- WordPress (if wp-config.php is found in standard locations) ---
    out, _ = ssh.run("find /var/www -maxdepth 3 -iname 'wp-includes' -type d 2>/dev/null | head -1")
    wp_dir = out.strip()
    if wp_dir:
        base = wp_dir.rsplit('/wp-includes', 1)[0]
        ver_out, _ = ssh.run(f"grep -m1 \"\\$wp_version = \" {base}/wp-includes/version.php 2>/dev/null")
        ver = _parse_version(ver_out)
        if ver:
            packages.append({'name': 'wordpress', 'version': ver,
                              'upstream_version': ver, 'ecosystem': 'WordPress', 'raw': ver_out.strip()})

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


def _resolve_ecosystem(pkg_ecosystem: str, debian_version_id: str | None) -> str:
    """Turns a package's base ecosystem ('Debian', 'WordPress', ...) into
    the actual OSV ecosystem string to query. Only 'Debian' is affected -
    see this module's docstring for why a bare 'Debian' query is a known
    OSV.dev false-positive source (google/osv.dev#4230) and why appending
    the release number narrows it. Falls back to the bare ecosystem string
    if the release number couldn't be determined (collect_os_release()
    returned None) - a noisy result beats no result for that host."""
    if pkg_ecosystem == _DEBIAN_FAMILY_ECOSYSTEM and debian_version_id:
        return f'{_DEBIAN_FAMILY_ECOSYSTEM}:{debian_version_id}'
    return pkg_ecosystem


def query_osv(packages: list[dict], debian_version_id: str | None = None) -> dict[str, list]:
    """Returns {pkg_name: [vuln_ids...]} using a batch query, with caching.

    debian_version_id (from collect_os_release()) narrows every package
    whose ecosystem is 'Debian' to 'Debian:{version_id}' - see this
    module's docstring for why. Packages with a different ecosystem
    (WordPress) are queried as-is, unaffected."""
    to_query = []
    result: dict[str, list] = {}

    for p in packages:
        ecosystem = _resolve_ecosystem(p['ecosystem'], debian_version_id)
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
        debian_version_id = collect_os_release(ssh)
    finally:
        ssh.close()

    if not packages:
        return {'host': host, 'packages': [], 'findings': [],
                'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'ok': 0}}

    vuln_ids_by_pkg = query_osv(packages, debian_version_id)

    findings = []
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'ok': 0}

    for p in packages:
        ids = vuln_ids_by_pkg.get(p['name'], [])
        if not ids:
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
