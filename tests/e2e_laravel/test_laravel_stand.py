"""
E2E: laravel_external against real Laravel sites from the official skeleton
(tests/e2e_laravel/setup.sh; docs/research/laravel_audit.md §7, L6). The
signals in §2 and §4 of the research come from the Laravel and package
sources; here they meet a running Laravel. OSV.dev and endoflife.date
answers are real.

Runs only on the CI stand: NETAUDIT_E2E_LV1 and NETAUDIT_E2E_LV2 are the two
sites' URLs.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 - runs awk and grep on the stand's own files

import pytest

from netaudit_pkg.checks import laravel, laravel_server

LV1 = os.environ.get('NETAUDIT_E2E_LV1')
LV2 = os.environ.get('NETAUDIT_E2E_LV2')
STAND_DIR = os.environ.get('NETAUDIT_E2E_LV_DIR')   # the two projects' folders
OPEN_ITEMS = ('env', 'ignition', 'debugbar', 'telescope', 'horizon', 'laravel_log', 'project_files', 'git_config')

pytestmark = pytest.mark.skipif(not (LV1 and LV2), reason='the Laravel E2E stand is not configured')


@pytest.fixture(scope='module')
def site1():
    return laravel.check_laravel_external(LV1)


@pytest.fixture(scope='module')
def site2():
    return laravel.check_laravel_external(LV2)


def _ids(result):
    return {f.get('id') for f in result['findings']}


def _by_id(result, fid):
    return next(f for f in result['findings'] if f.get('id') == fid)


def _checked(result):
    return {c['item']: c['status'] for c in result['checked']}


def _detail(result, item):
    return next(c['detail'] for c in result['checked'] if c['item'] == item)


# --- lv1: served from public/, production settings ---------------------------

def test_the_skeleton_is_told_by_its_cookies(site1):
    assert site1['laravel'] is True
    assert 'XSRF-TOKEN' in site1['detected_by']


def test_nothing_is_open_on_a_site_served_from_public(site1):
    statuses = _checked(site1)
    for item in OPEN_ITEMS:
        assert statuses[item] == 'ok', (item, _detail(site1, item))
    assert not {'LV-ENV-001', 'LV-IGN-001', 'LV-DBG-001', 'LV-TEL-001', 'LV-HRZ-001',
                'LV-FILE-001', 'LV-FILE-002', 'LV-FILE-003'} & _ids(site1)


def test_versions_are_not_visible_from_outside(site1):
    statuses = _checked(site1)
    assert statuses['laravel_version'] == statuses['vulns'] == 'not_checked'
    assert site1['framework'] is None


def test_the_skeletons_session_cookie(site1):
    # plain http: Secure is not asked; the skeleton sets HttpOnly and SameSite=lax
    assert _checked(site1)['session_cookie'] == 'ok'
    assert 'laravel-session' in _detail(site1, 'session_cookie')


# --- lv2: the project folder as the site root, the skeleton's .env, debug tools --

def test_public_env_is_found_and_its_key_is_not_kept(site2):
    f = _by_id(site2, 'LV-ENV-001')
    assert f['severity'] == 'critical'
    assert 'APP_KEY' in f['detail']
    assert 'base64:' not in json.dumps(site2)


def test_debug_tools_are_found(site2):
    assert {'LV-IGN-001', 'LV-DBG-001', 'LV-TEL-001'} <= _ids(site2)
    assert _checked(site2)['horizon'] == 'ok'      # not installed on the stand


def test_files_of_the_project_folder_are_found(site2):
    assert {'LV-FILE-001', 'LV-FILE-002', 'LV-FILE-003'} <= _ids(site2)
    assert 'e2e stand' not in json.dumps(site2)    # the log line itself is not kept


def test_versions_from_the_public_files(site2):
    # both are public on the stand: installed.json names what is installed, and agrees with the lock
    framework = site2['framework']
    assert framework['source'] == 'vendor/composer/installed.json'
    assert framework['version'].startswith('12.')
    statuses = _checked(site2)
    assert statuses['version_sources'] == 'ok', _detail(site2, 'version_sources')
    # live endoflife.date and OSV.dev answers: judged, whichever way
    assert statuses['laravel_version'] in ('ok', 'problem'), _detail(site2, 'laravel_version')
    assert statuses['vulns'] in ('ok', 'problem'), _detail(site2, 'vulns')
    assert site2['packages']['count'] > 50
    assert {n['name'] for n in site2['vuln_data']['notices']} >= {'OSV.dev', 'endoflife.date'}


# --- both: the stand serves plain http ---------------------------------------------

def test_plain_http_is_reported(site1, site2):
    for site in (site1, site2):
        assert 'LV-TLS-001' in _ids(site)
        assert _checked(site)['https'] == 'problem'
        assert site['verdict'] == 'danger'


# --- the programs laravel_server runs on a server, on files a real Laravel wrote ---

def test_the_config_awk_on_a_real_cached_config():
    # lv1's config was cached by `php artisan config:cache` (setup.sh): every setting, secrets included
    path = f'{STAND_DIR}/lv1/bootstrap/cache/config.php'
    out = subprocess.run(['awk', laravel_server.CONFIG_AWK, path],  # nosec B603 B607
                         capture_output=True, text=True, check=True).stdout
    assert out.splitlines() == ['APP_ENV word:production', 'APP_DEBUG false']
    assert laravel_server.parse_tokens(out) == {'APP_ENV': 'production', 'APP_DEBUG': False}


def test_the_env_program_on_the_skeletons_env():
    out = subprocess.run(['awk', laravel_server.ENV_AWK, f'{STAND_DIR}/lv2/.env'],  # nosec B603 B607
                         capture_output=True, text=True, check=True).stdout
    assert sorted(out.splitlines()) == ['APP_DEBUG true', 'APP_ENV word:local']
    values = laravel_server.parse_tokens(out)
    assert values['APP_ENV'] == 'local' and laravel_server.debug_on(values['APP_DEBUG'])
    assert 'base64:' not in out
