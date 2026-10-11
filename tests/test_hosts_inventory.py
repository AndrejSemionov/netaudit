"""
B2.3 - saved SSH hosts without secrets (docs/research/b2_3_hosts_inventory.md,
on the approved B1 contract §3.1): a new ssh_hosts table and /api/hosts that
hold only id/label/host/user/port/key_path; a secret is refused at the API and
at the storage layer, never echoed back, never stored.
"""

from __future__ import annotations

import asyncio
import json
import re
import sqlite3
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from netaudit_pkg.hosts import HostRecordError
from web.app import api_add_host, app

SECRET = 'INVENTORY-TEST-SECRET-PW'
FIELDS = {'id', 'label', 'host', 'user', 'port', 'key_path'}
INDEX = Path(__file__).resolve().parent.parent / 'web' / 'static' / 'index.html'


@pytest.fixture
def client():
    return TestClient(app)


def _raw_rows(storage) -> str:
    return repr(storage._conn().execute('SELECT * FROM ssh_hosts').fetchall())


# --- storage -----------------------------------------------------------------

def test_storage_round_trip(isolated_db):
    hid = isolated_db.ssh_host_add({'host': '10.0.0.5', 'user': 'audit', 'port': 2222,
                                    'key_path': '~/.ssh/audit'}, label='db primary')
    other = isolated_db.ssh_host_add({'host': 'web-2.example'})

    assert isolated_db.ssh_hosts_list() == [
        {'id': hid, 'label': 'db primary', 'host': '10.0.0.5', 'user': 'audit', 'port': 2222,
         'key_path': '~/.ssh/audit'},
        {'id': other, 'label': '', 'host': 'web-2.example', 'user': None, 'port': None, 'key_path': None},
    ]
    isolated_db.ssh_host_delete(hid)
    assert [h['id'] for h in isolated_db.ssh_hosts_list()] == [other]


def test_same_host_with_another_user_is_a_separate_record(isolated_db):
    isolated_db.ssh_host_add({'host': 'h1', 'user': 'root'})
    isolated_db.ssh_host_add({'host': 'h1', 'user': 'audit', 'port': 2222})
    assert len(isolated_db.ssh_hosts_list()) == 2


def test_ipv6_aliases_are_refused_by_picker_validation_without_rewriting_hosts(isolated_db):
    from web.app import api_validate_host_selection

    first = isolated_db.ssh_host_add({'host': '2001:db8::1'})
    second = isolated_db.ssh_host_add({'host': '2001:0db8:0:0:0:0:0:1', 'user': 'audit'})
    assert [record['host'] for record in isolated_db.ssh_hosts_list()] == [
        '2001:db8::1', '2001:0db8:0:0:0:0:0:1',
    ]
    request = _json_request('/api/hosts/validate-selection', {'ids': [first, second]})
    with pytest.raises(HTTPException) as error:
        asyncio.run(api_validate_host_selection(request))
    assert error.value.status_code == 409
    assert error.value.detail == {'duplicate_id': second}


def test_picker_validation_accepts_distinct_hosts_and_refuses_bad_ids(isolated_db):
    from web.app import api_validate_host_selection

    first = isolated_db.ssh_host_add({'host': 'h1'})
    second = isolated_db.ssh_host_add({'host': 'h2'})
    request = _json_request('/api/hosts/validate-selection', {'ids': [first, second]})
    assert asyncio.run(api_validate_host_selection(request)) == {'ok': True}
    for ids in ([first, first], [first, 99999], [True], ['INVENTORY-TEST-SECRET-PW'], list(range(65))):
        request = _json_request('/api/hosts/validate-selection', {'ids': ids})
        with pytest.raises(HTTPException) as error:
            asyncio.run(api_validate_host_selection(request))
        assert error.value.status_code == 400
        assert SECRET not in str(error.value.detail)


@pytest.mark.parametrize('record, label', [
    ({'host': 'h1', 'password': SECRET}, ''),
    ({'host': 'h1', 'sudo_password': SECRET}, ''),
    ({'host': 'h1', 'note': 'x'}, ''),
    ({'host': '-oProxyCommand=x'}, ''),
    ({'host': 'h1', 'port': 0}, ''),
    ({'host': 'h1'}, 'x' * 101),
    ({'host': 'h1'}, 'bad\nlabel'),
])
def test_storage_refuses_secrets_and_bad_records(isolated_db, record, label):
    with pytest.raises(HostRecordError) as exc:
        isolated_db.ssh_host_add(record, label=label)
    assert SECRET not in str(exc.value)
    assert isolated_db.ssh_hosts_list() == []
    assert SECRET not in _raw_rows(isolated_db)


def test_migration_from_version_4_adds_the_table_and_keeps_data(tmp_path, monkeypatch):
    from netaudit_pkg import storage

    db = tmp_path / 'old.db'
    conn = sqlite3.connect(db)
    for migration in storage.MIGRATIONS[:4]:
        migration(conn)
    conn.execute("INSERT INTO targets (label, value, kind) VALUES ('home', '10.0.0.1', 'ip')")
    conn.execute('PRAGMA user_version = 4')
    conn.commit()
    conn.close()

    monkeypatch.setattr(storage, 'DB_PATH', db)
    if hasattr(storage._local, 'conn'):
        storage._local.conn.close()
        del storage._local.conn
    try:
        assert storage.ssh_hosts_list() == []
        assert [t['value'] for t in storage.targets_list()] == ['10.0.0.1']
        assert storage._conn().execute('PRAGMA user_version').fetchone()[0] == len(storage.MIGRATIONS)
    finally:
        storage._local.conn.close()
        del storage._local.conn


# --- API ---------------------------------------------------------------------

def test_api_add_list_delete(client, isolated_db):
    resp = client.post('/api/hosts', json={'label': 'web', 'host': 'web-2.example', 'user': 'audit',
                                           'port': 2222, 'key_path': '~/.ssh/audit'})
    assert resp.status_code == 200
    hid = resp.json()['id']

    [record] = client.get('/api/hosts').json()
    assert set(record) == FIELDS
    assert record == {'id': hid, 'label': 'web', 'host': 'web-2.example', 'user': 'audit',
                      'port': 2222, 'key_path': '~/.ssh/audit'}

    assert client.delete(f'/api/hosts/{hid}').status_code == 200
    assert client.get('/api/hosts').json() == []


@pytest.mark.parametrize('payload', [
    {'host': 'h1', 'password': SECRET},
    {'host': 'h1', 'sudo_password': SECRET},
    {'host': 'h1', 'label': 'x', 'token': SECRET},
])
def test_api_refuses_secrets_without_echoing_them(client, isolated_db, payload):
    resp = client.post('/api/hosts', json=payload)
    assert resp.status_code == 400
    assert SECRET not in resp.text
    assert client.get('/api/hosts').json() == []
    assert SECRET not in _raw_rows(isolated_db)


@pytest.mark.parametrize('payload', [
    {'host': 'h1', 'port': 'twenty-two'},
    {'host': 'h1', 'port': 70000},
    {'host': 'two words'},
    {'label': 'no host'},
    ['not', 'an', 'object'],
])
def test_api_refuses_bad_records_with_400(client, isolated_db, payload):
    resp = client.post('/api/hosts', json=payload)
    assert resp.status_code == 400
    assert client.get('/api/hosts').json() == []


@pytest.mark.parametrize('payload', [
    {'host': SECRET + '!'},
    {'host': 'h1', 'user': SECRET + '!'},
    {'host': 'h1', 'port': SECRET},
    {'host': 'h1', SECRET: 'x'},
])
def test_api_invalid_field_values_never_echo_payload(isolated_db, payload):
    request = _json_request('/api/hosts', payload)
    with pytest.raises(HTTPException) as error:
        asyncio.run(api_add_host(request))
    assert error.value.status_code == 400
    assert SECRET not in str(error.value.detail)
    assert isolated_db.ssh_hosts_list() == []


def _json_request(path, payload):
    raw = json.dumps(payload).encode()
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {'type': 'http.request', 'body': b'', 'more_body': False}
        sent = True
        return {'type': 'http.request', 'body': raw, 'more_body': False}

    return Request({'type': 'http', 'method': 'POST', 'path': path,
                    'headers': [(b'content-type', b'application/json')]}, receive)


def test_targets_api_is_unchanged(client, isolated_db):
    assert client.post('/api/targets', json={'value': '10.0.0.9', 'label': 'x', 'kind': 'ip'}).status_code == 200
    assert [t['value'] for t in client.get('/api/targets').json()] == ['10.0.0.9']
    assert client.get('/api/hosts').json() == []


# --- frontend guards ---------------------------------------------------------

def test_hosts_settings_form_has_no_password_field():
    html = INDEX.read_text(encoding='utf-8')
    group = re.search(r'<div class="settings-group">(?:(?!<div class="settings-group">).)*?id="sshHostsList"'
                      r'(?:(?!<div class="settings-group">).)*', html, re.DOTALL)
    assert group, 'settings group for saved SSH hosts not found'
    assert 'type="password"' not in group.group(0)
    for field in ('newSshHostLabel', 'newSshHostHost', 'newSshHostUser', 'newSshHostPort', 'newSshHostKey'):
        assert f'id="{field}"' in group.group(0)


def test_run_tab_has_the_saved_hosts_picker():
    html = INDEX.read_text(encoding='utf-8')
    assert 'id="hostPicker"' in html
    assert 'function applySavedHosts(' in html
