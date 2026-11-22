"""
wordpress.org data for the WordPress checks (docs/research/wordpress_audit.md §3).

- Core: https://api.wordpress.org/core/stable-check/1.0/ maps every released
  version to 'latest', 'outdated' or 'insecure'. OSV has no WordPress data
  (W0), so this is the source for cve_audit and wordpress_external alike.
- Plugins: https://api.wordpress.org/plugins/info/1.2/ gives the latest
  version of a plugin hosted on wordpress.org; premium and custom plugins
  are not there (404), which is "not known", not "up to date".

Both are free and need no key. A failed or unexpected answer comes back as
status 'error' with the reason - callers must not turn it into a clean result.
"""

from __future__ import annotations

import re

import httpx

from . import __version__

STABLE_CHECK_URL = 'https://api.wordpress.org/core/stable-check/1.0/'
PLUGIN_INFO_URL = 'https://api.wordpress.org/plugins/info/1.2/'
TIMEOUT = 15
USER_AGENT = f'NetAudit/{__version__} (+https://github.com/AndrejSemionov/netaudit)'

_NUMERIC = re.compile(r'\d+(?:\.\d+)*')


def _get_json(url: str, params: dict | None = None) -> tuple[int, object]:
    """The one HTTP call of this module: (status code, parsed JSON or None).
    Transport errors raise httpx.HTTPError."""
    resp = httpx.get(url, params=params, timeout=TIMEOUT, headers={'User-Agent': USER_AGENT})
    try:
        data = resp.json()
    except ValueError:
        data = None
    return resp.status_code, data


def _ask(url: str, params: dict | None = None) -> tuple[int, object]:
    """_get_json, once more after a transport error (a network blip)."""
    try:
        return _get_json(url, params)
    except httpx.HTTPError:
        return _get_json(url, params)


def normalize_core_version(version: str) -> str:
    """'4.7.0' -> '4.7': stable-check lists the first release of a branch
    without its '.0' (it has '4.7' and '6.0', never '4.7.0')."""
    version = version.strip()
    if re.fullmatch(r'\d+\.\d+\.0', version):
        return version[:-2]
    return version


def core_status(version: str) -> dict:
    """{'status': 'latest'|'outdated'|'insecure'|'unknown'|'error', 'latest', 'error'}.
    'unknown': the version is not a release wordpress.org knows (a
    pre-release, a typo, a fork) - not checked, not clean."""
    try:
        code, data = _ask(STABLE_CHECK_URL)
    except httpx.HTTPError as e:
        return {'status': 'error', 'latest': None, 'error': f'wordpress.org stable-check: {e}'}
    if code != 200:
        return {'status': 'error', 'latest': None, 'error': f'wordpress.org stable-check: HTTP {code}'}
    if not isinstance(data, dict) or not data:
        return {'status': 'error', 'latest': None, 'error': 'wordpress.org stable-check: unexpected answer'}
    latest = next((v for v, state in data.items() if state == 'latest'), None)
    state = data.get(normalize_core_version(version))
    if state not in ('latest', 'outdated', 'insecure'):
        return {'status': 'unknown', 'latest': latest, 'error': None}
    return {'status': state, 'latest': latest, 'error': None}


def plugin_latest(slug: str) -> dict:
    """{'status': 'ok'|'not_found'|'error', 'version', 'error'}."""
    params = {'action': 'plugin_information', 'request[slug]': slug,
              'request[fields][sections]': '0', 'request[fields][versions]': '0'}
    try:
        code, data = _ask(PLUGIN_INFO_URL, params)
    except httpx.HTTPError as e:
        return {'status': 'error', 'version': None, 'error': f'wordpress.org plugins: {e}'}
    if code == 404:
        return {'status': 'not_found', 'version': None, 'error': None}
    if code != 200:
        return {'status': 'error', 'version': None, 'error': f'wordpress.org plugins: HTTP {code}'}
    version = data.get('version') if isinstance(data, dict) else None
    if not isinstance(version, str) or not version_tuple(version):
        return {'status': 'error', 'version': None, 'error': 'wordpress.org plugins: no version in the answer'}
    return {'status': 'ok', 'version': version, 'error': None}


def version_tuple(version: str | None) -> tuple[int, ...] | None:
    """'6.2.5' -> (6, 2, 5); anything that is not dotted numbers -> None
    ('trunk', '1.0-beta'): such a version is not compared at all."""
    if not isinstance(version, str) or not _NUMERIC.fullmatch(version.strip()):
        return None
    return tuple(int(part) for part in version.strip().split('.'))


def is_older(version: str | None, than: str | None) -> bool | None:
    """True/False, or None when either side is not comparable.
    Trailing zeros do not count: '6.2' and '6.2.0' are the same release."""
    a, b = version_tuple(version), version_tuple(than)
    if a is None or b is None:
        return None
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) < b + (0,) * (width - len(b))
