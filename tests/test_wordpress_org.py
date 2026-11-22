"""
wordpress.org data for the WordPress checks (docs/research/wordpress_audit.md §3):
core status from stable-check, the latest plugin version from plugins/info.
A failed or unknown answer is reported as such - never as "up to date".
No network: the one HTTP seam, wordpress_org._get_json, is faked.
"""

from __future__ import annotations

import httpx
import pytest

from netaudit_pkg import wordpress_org

STABLE = {'4.7': 'insecure', '7.0.9': 'outdated', '7.1': 'insecure', '7.1.5': 'latest'}


def _answer(status, data=None, exc=None, calls=None):
    def fake(url, params=None):
        if calls is not None:
            calls.append((url, params))
        if exc is not None:
            raise exc
        return status, data
    return fake


@pytest.mark.parametrize('raw, expected', [
    ('4.7.0', '4.7'),      # stable-check has no "x.y.0" keys
    ('6.8.3', '6.8.3'),
    ('7.0', '7.0'),
    ('7.1.5', '7.1.5'),
    (' 7.1.5\n', '7.1.5'),
])
def test_core_version_is_normalized_like_stable_check(raw, expected):
    assert wordpress_org.normalize_core_version(raw) == expected


@pytest.mark.parametrize('version, status', [
    ('4.7.0', 'insecure'),
    ('7.1', 'insecure'),
    ('7.0.9', 'outdated'),
    ('7.1.5', 'latest'),
])
def test_core_status_from_stable_check(monkeypatch, version, status):
    calls = []
    monkeypatch.setattr(wordpress_org, '_get_json', _answer(200, STABLE, calls=calls))
    result = wordpress_org.core_status(version)
    assert result['status'] == status
    assert result['latest'] == '7.1.5'
    assert result['error'] is None
    assert calls == [(wordpress_org.STABLE_CHECK_URL, None)]


def test_version_missing_from_the_list_is_unknown_not_latest(monkeypatch):
    monkeypatch.setattr(wordpress_org, '_get_json', _answer(200, STABLE))
    result = wordpress_org.core_status('7.2-RC2')
    assert result['status'] == 'unknown'
    assert result['latest'] == '7.1.5'


@pytest.mark.parametrize('fake', [
    _answer(None, exc=httpx.ConnectError('down')),
    _answer(503, {'error': 'busy'}),
    _answer(200, ['not', 'a', 'map']),
    _answer(200, {}),
])
def test_core_status_failure_is_an_error(monkeypatch, fake):
    monkeypatch.setattr(wordpress_org, '_get_json', fake)
    result = wordpress_org.core_status('7.1.5')
    assert result['status'] == 'error'
    assert result['error']
    assert result['latest'] is None


def test_plugin_latest_version(monkeypatch):
    calls = []
    monkeypatch.setattr(wordpress_org, '_get_json',
                        _answer(200, {'slug': 'contact-form-7', 'version': '6.2.5'}, calls=calls))
    assert wordpress_org.plugin_latest('contact-form-7') == {'status': 'ok', 'version': '6.2.5', 'error': None}
    url, params = calls[0]
    assert url == wordpress_org.PLUGIN_INFO_URL
    assert params['action'] == 'plugin_information'
    assert params['request[slug]'] == 'contact-form-7'


def test_plugin_missing_from_wordpress_org_is_not_found(monkeypatch):
    # premium and custom plugins (WPML, a theme's own plugin) are not on wordpress.org
    monkeypatch.setattr(wordpress_org, '_get_json', _answer(404, {'error': 'Plugin not found.'}))
    assert wordpress_org.plugin_latest('sitepress-multilingual-cms') == {
        'status': 'not_found', 'version': None, 'error': None}


@pytest.mark.parametrize('fake', [
    _answer(None, exc=httpx.ReadTimeout('slow')),
    _answer(500, None),
    _answer(200, {'slug': 'x'}),
])
def test_plugin_latest_failure_is_an_error(monkeypatch, fake):
    monkeypatch.setattr(wordpress_org, '_get_json', fake)
    result = wordpress_org.plugin_latest('x')
    assert result['status'] == 'error'
    assert result['version'] is None
    assert result['error']


@pytest.mark.parametrize('version, expected', [
    ('6.2.5', (6, 2, 5)),
    ('6.2', (6, 2)),
    ('10.0.1', (10, 0, 1)),
    ('trunk', None),
    ('1.0-beta', None),
    ('', None),
    (None, None),
])
def test_version_tuple(version, expected):
    assert wordpress_org.version_tuple(version) == expected


def test_older_means_a_lower_tuple():
    assert wordpress_org.is_older('6.2', '6.2.1')
    assert wordpress_org.is_older('4.1.0', '4.4.1')
    assert not wordpress_org.is_older('6.2.5', '6.2.5')
    assert not wordpress_org.is_older('6.10', '6.9')
    assert not wordpress_org.is_older('6.2', '6.2.0')   # trailing zeros are the same release
    assert not wordpress_org.is_older('6.2.0', '6.2')
    assert wordpress_org.is_older('trunk', '1.0') is None
