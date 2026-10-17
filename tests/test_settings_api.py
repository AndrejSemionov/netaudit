"""
/api/settings (docs/research/settings_api_secrets.md): GET returns only the
settings page's keys and never a secret, POST writes only those keys. The
Web login and MikroTik capture keep their own endpoints.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from netaudit_pkg import history_capture, storage
from web.app import app

MARK = 'SETTINGS-TEST-MARKER'
PUBLIC = {'sync_threshold_sec', 'ema_alpha', 'ai_language', 'telegram_chat'}
SECRETS = {'anthropic_api_key', 'telegram_token', 'hibp_api_key'}
EXPECTED_KEYS = PUBLIC | SECRETS | {'web_auth_user', 'web_auth_configured'}
FOREIGN = ['web_auth_password_hash', 'web_auth_salt', 'web_auth_user', 'history_capture_password',
           'history_capture_target_ip', 'history_capture_router', 'x_secret_token']


@pytest.fixture
def client():
    return TestClient(app)


def _store_everything():
    for key in [*SECRETS, *FOREIGN, 'history_capture_user', 'history_capture_enabled']:
        storage.setting_set(key, f'{MARK}-{key}')
    storage.setting_set('sync_threshold_sec', '3.5')
    storage.setting_set('ema_alpha', '0.3')
    storage.setting_set('ai_language', 'ru')
    storage.setting_set('telegram_chat', '-100123')


# --- GET ---------------------------------------------------------------------

def test_get_returns_only_the_settings_page_keys_and_no_secret(isolated_db, client):
    _store_everything()
    body = client.get('/api/settings').json()
    assert set(body) == EXPECTED_KEYS
    assert MARK not in json.dumps(body).replace(f'{MARK}-web_auth_user', '')
    assert all(body[k] == {'set': True} for k in SECRETS)
    assert body['web_auth_user'] == f'{MARK}-web_auth_user'      # a login name, shown on the page
    assert body['web_auth_configured'] is True
    assert (body['sync_threshold_sec'], body['ema_alpha'], body['ai_language'], body['telegram_chat']) == \
        ('3.5', '0.3', 'ru', '-100123')


def test_get_on_an_empty_database_has_defaults(isolated_db, client):
    body = client.get('/api/settings').json()
    assert set(body) == EXPECTED_KEYS
    assert all(body[k] == {'set': False} for k in SECRETS)
    assert body['web_auth_configured'] is False and body['web_auth_user'] == ''
    assert body['sync_threshold_sec'] and body['ema_alpha'] and body['ai_language']


def test_history_capture_password_never_comes_back(isolated_db, client):
    history_capture.save_settings({'password': f'{MARK}-router', 'target_ip': '192.168.88.10'})
    assert MARK not in client.get('/api/settings').text
    assert MARK not in client.get('/api/history_capture/settings').text


# --- POST --------------------------------------------------------------------

@pytest.mark.parametrize('key', FOREIGN)
def test_post_refuses_a_key_it_does_not_own_and_writes_nothing(isolated_db, client, key):
    storage.setting_set('ema_alpha', '0.4')
    before = storage.settings_all()
    r = client.post('/api/settings', json={'settings': {'ema_alpha': '0.9', key: f'{MARK}-value'}})
    assert r.status_code == 400
    assert key in r.text and MARK not in r.text
    assert storage.settings_all() == before                    # the allowed key was not written either


def test_post_cannot_change_the_web_login_hash(isolated_db, client):
    from netaudit_pkg.web_auth import _hash_password
    storage.setting_set('web_auth_user', 'admin')
    storage.setting_set('web_auth_password_hash', _hash_password('right-password'))
    good = storage.setting_get('web_auth_password_hash')
    assert client.post('/api/settings', json={'settings': {'web_auth_password_hash': 'x'}}).status_code == 400
    assert storage.setting_get('web_auth_password_hash') == good
    # the dedicated endpoint still works
    assert client.post('/api/settings/web-auth', json={'user': 'admin', 'password': 'new-password-1'}).status_code == 200
    assert storage.setting_get('web_auth_password_hash') != good


def test_post_writes_the_allowed_keys_and_keeps_a_secret_on_empty(isolated_db, client):
    storage.setting_set('telegram_token', 'OLD-TOKEN')
    r = client.post('/api/settings', json={'settings': {
        'sync_threshold_sec': '2.0', 'ema_alpha': '0.5', 'telegram_chat': '-1', 'ai_language': 'en',
        'anthropic_api_key': 'NEW-KEY', 'hibp_api_key': 'HIBP', 'telegram_token': ''}})
    assert r.status_code == 200
    assert storage.setting_get('sync_threshold_sec') == '2.0'
    assert storage.setting_get('telegram_chat') == '-1'
    assert storage.setting_get('ai_language') == 'en'
    assert storage.setting_get('anthropic_api_key') == 'NEW-KEY'
    assert storage.setting_get('telegram_token') == 'OLD-TOKEN'


def test_history_capture_keeps_its_own_ip_check(isolated_db, client):
    r = client.post('/api/history_capture/settings', json={'target_ip': '1.2.3.4"; /system reboot; "'})
    assert r.status_code == 400
    assert storage.setting_get('history_capture_target_ip') in (None, '')
