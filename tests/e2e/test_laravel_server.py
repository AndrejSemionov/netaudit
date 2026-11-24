"""
E2E: laravel_server on the SSH stand (tests/e2e/laravel-projects.sh;
docs/research/laravel_audit.md §5, L4). The real find, head, grep, awk and
sudo of a Debian 12 server; OSV.dev and endoflife.date answers are real.

Runs only in the CI job `e2e-ssh` (NETAUDIT_E2E_* variables).
"""

from __future__ import annotations

import json
import os

import pytest

from netaudit_pkg.checks import laravel_server
from netaudit_pkg.findings import subject_id

HOST = os.environ.get('NETAUDIT_E2E_HOST', '')
PORT = int(os.environ.get('NETAUDIT_E2E_PORT', '22'))
KEY = os.environ.get('NETAUDIT_E2E_KEY', '')
PASSWORD = os.environ.get('NETAUDIT_E2E_PASSWORD', '')
SHOP, BLOG, API = '/var/www/shop', '/srv/blog', '/srv/api/releases/2'

pytestmark = pytest.mark.skipif(not (HOST and KEY and PASSWORD),
                                reason='needs the CI SSH stand (NETAUDIT_E2E_* variables)')


def _run(user: str, sudo_password: str = '') -> dict:
    return laravel_server.check_laravel_server(host=HOST, user=user, port=PORT, key_path=KEY, password='',
                                               sudo_password=sudo_password)


@pytest.fixture(scope='module')
def with_sudo():
    return _run('pwsudo', PASSWORD)


@pytest.fixture(scope='module')
def without_sudo():
    return _run('nosudo')


def _ids(result):
    return {f['id'] for f in result['findings'] if f.get('id')}


def _checked(result, project):
    return {c['item']: c['status'] for c in result['checked'] if c.get('project') == project}


def _detail(result, item, project):
    return next(c['detail'] for c in result['checked'] if c['item'] == item and c.get('project') == project)


def test_every_project_once_and_only_the_current_release(with_sudo):
    assert 'error' not in with_sudo, with_sudo
    assert [p['path'] for p in with_sudo['projects']] == [API, BLOG, SHOP]
    assert with_sudo['skipped'] == {'old_releases': 1, 'over_limit': 0, 'not_laravel': 1}
    assert 'collected_without_sudo' not in with_sudo


def test_the_shop_is_flagged_for_everything_it_does_wrong(with_sudo):
    ids = _ids(with_sudo)
    assert {subject_id('LV-SRV-001', SHOP, '.env'), subject_id('LV-SRV-002', SHOP),
            subject_id('LV-SRV-003', SHOP), subject_id('LV-SRV-004', SHOP, 'storage'),
            subject_id('LV-SRV-005', SHOP)} <= ids
    # Laravel 10.0.0 has known vulnerabilities (OSV.dev, live)
    assert any(i.startswith(subject_id('LV-SRV-006', SHOP, 'laravel/framework')) for i in ids)
    assert with_sudo['verdict'] == 'danger'


def test_the_cached_config_wins_over_env(with_sudo):
    checked = _checked(with_sudo, BLOG)
    assert checked['app_debug'] == checked['app_env'] == 'ok'
    assert 'cached config' in _detail(with_sudo, 'app_debug', BLOG)
    assert checked['env_files'] == 'ok'
    assert not {subject_id('LV-SRV-002', BLOG), subject_id('LV-SRV-003', BLOG)} & _ids(with_sudo)


def test_the_old_release_is_not_judged(with_sudo):
    assert not [i for i in _ids(with_sudo) if '%2Fsrv%2Fapi%2Freleases%2F1' in i]
    assert _checked(with_sudo, API)['app_debug'] == 'ok'


def test_no_secret_leaves_the_server(with_sudo, without_sudo):
    for result in (with_sudo, without_sudo):
        dumped = json.dumps(result)
        assert 'ZTJlLXN0YW5kLWtleQ' not in dumped
        assert 'e2e-db-secret' not in dumped


def test_without_sudo_what_could_not_be_read_is_said(without_sudo):
    assert 'error' not in without_sudo, without_sudo
    assert without_sudo['collected_without_sudo'] is True
    assert _checked(without_sudo, BLOG)['app_debug'] == 'not_checked'
    assert 'Permission denied' in _detail(without_sudo, 'app_debug', BLOG)
    # files every user can read are still judged
    assert subject_id('LV-SRV-001', SHOP, '.env') in _ids(without_sudo)
