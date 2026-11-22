"""
E2E: wordpress_external against real WordPress sites from the official
image (tests/e2e_wordpress/setup.sh; docs/research/wordpress_audit.md, C6).
The signals in §4 of the research come from the WordPress source; here they
meet a running WordPress. wordpress.org answers are real.

Runs only on the CI stand: NETAUDIT_E2E_WP1 and NETAUDIT_E2E_WP2 are the
two sites' URLs.
"""

from __future__ import annotations

import json
import os

import pytest

from netaudit_pkg.checks import wordpress

WP1 = os.environ.get('NETAUDIT_E2E_WP1')
WP2 = os.environ.get('NETAUDIT_E2E_WP2')
CORE = '6.4.3'   # the image in setup.sh

pytestmark = pytest.mark.skipif(not (WP1 and WP2), reason='the WordPress E2E stand is not configured')


@pytest.fixture(scope='module')
def site1():
    return wordpress.check_wordpress_external(WP1)


@pytest.fixture(scope='module')
def site2():
    return wordpress.check_wordpress_external(WP2)


def _ids(result):
    return {f.get('id') for f in result['findings']}


def _checked(result):
    return {c['item']: c['status'] for c in result['checked']}


# --- wp1: plain permalinks, nothing hidden, files left behind ----------------

def test_core_version_from_the_generator_and_its_status(site1):
    assert site1['wordpress'] is True
    assert site1['core']['version'] == CORE
    assert site1['core']['source'] == 'generator'
    # an insecure release never becomes secure again
    assert site1['core']['status'] == 'insecure'
    assert 'WP-CORE-001' in _ids(site1)


def test_plugin_version_from_its_readme(site1):
    cf7 = next(p for p in site1['plugins'] if p['slug'] == 'contact-form-7')
    assert cf7['version'] == '5.9'
    assert cf7['version_source'] == 'readme.txt'
    assert cf7['status'] == 'outdated'
    assert 'WP-PLG-001:contact-form-7' in _ids(site1)


def test_rest_api_shows_the_author(site1):
    assert 'e2e-admin' in site1['users']['exposed']
    assert 'rest' in site1['users']['sources']
    assert 'WP-USR-001' in _ids(site1)


def test_xmlrpc_answers_a_get(site1):
    assert 'WP-XMLRPC-001' in _ids(site1)


def test_public_debug_log_and_config_copy(site1):
    assert {'WP-FILE-001', 'WP-FILE-002'} <= _ids(site1)
    # only the verdict is kept, never the file
    assert 'getenv_docker' not in json.dumps(site1)
    assert site1['verdict'] == 'danger'


# --- wp2: pretty permalinks, generator and REST users removed ------------------

def test_hidden_version_is_not_checked(site2):
    assert site2['wordpress'] is True
    assert site2['core']['version'] is None
    assert _checked(site2)['core'] == 'not_checked'
    assert not {'WP-CORE-001', 'WP-CORE-002'} & _ids(site2)


def test_author_archive_still_shows_the_author(site2):
    assert 'e2e-admin' in site2['users']['exposed']
    assert 'rest' not in site2['users']['sources']
    assert 'author' in site2['users']['sources']


def test_only_the_stock_service_files_are_public(site2):
    # the official image ships readme.html and license.txt; nothing else was left on wp2
    ids = _ids(site2)
    assert 'WP-FILE-004' in ids
    assert not {'WP-FILE-001', 'WP-FILE-002', 'WP-FILE-003'} & ids
    statuses = _checked(site2)
    assert (statuses['debug_log'], statuses['config_copies'], statuses['uploads_listing']) == ('ok', 'ok', 'ok')
    assert (statuses['readme_html'], statuses['license_txt']) == ('problem', 'problem')


# --- both: the stand serves plain http -----------------------------------------

def test_plain_http_is_reported_and_there_is_no_certificate(site1, site2):
    for site in (site1, site2):
        assert 'WP-TLS-001' in _ids(site)
        statuses = _checked(site)
        assert statuses['https'] == 'problem'
        assert 'certificate' not in statuses and 'http_redirect' not in statuses
        assert site['verdict'] == 'danger'
        assert site['score']['value'] < 50
