"""Task 8, P1 (docs/research/preset_secrets_and_command_injection.md): presets
never hold secret params - not in SQLite, not in GET /api/presets, and the
Web UI does not send them when saving a preset."""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netaudit_pkg.redaction import redact_preset_checks
from web.app import app

PW = 'FAKE-TEST-PW'
STATIC = Path(__file__).resolve().parent.parent / 'web' / 'static'


# ===========================================================================
# redact_preset_checks
# ===========================================================================

def test_redact_preset_checks_flat_params():
    checks = [{'id': 'server_audit', 'params': {'host': 'a', 'password': PW}},
              {'id': 'mtr', 'params': {'target': '8.8.8.8'}}]
    assert redact_preset_checks(checks) == [
        {'id': 'server_audit', 'params': {'host': 'a'}},
        {'id': 'mtr', 'params': {'target': '8.8.8.8'}},
    ]


def test_redact_preset_checks_instances_and_nested_values():
    checks = [{'id': 'cve_audit', 'instances': [{'host': 'a', 'password': PW}, {'host': 'b', 'password': ''}]},
              {'id': 'x', 'params': {'nested': {'password': PW, 'keep': 1}}}]
    assert redact_preset_checks(checks) == [
        {'id': 'cve_audit', 'instances': [{'host': 'a'}, {'host': 'b'}]},
        {'id': 'x', 'params': {'nested': {'keep': 1}}},
    ]


def test_redact_preset_checks_does_not_mutate_input():
    checks = [{'id': 'server_audit', 'params': {'host': 'a', 'password': PW}}]
    snapshot = json.dumps(checks)
    redact_preset_checks(checks)
    assert json.dumps(checks) == snapshot


@pytest.mark.parametrize('value', [None, 'text', 42, {'password': PW}])
def test_redact_preset_checks_any_json_shape(value):
    assert PW not in json.dumps(redact_preset_checks(value))


# ===========================================================================
# storage: last barrier on write, redaction on read
# ===========================================================================

def _raw_presets(storage) -> list[str]:
    conn = sqlite3.connect(storage.DB_PATH)
    try:
        return [r[0] for r in conn.execute('SELECT checks FROM presets')]
    finally:
        conn.close()


def test_preset_save_never_writes_a_secret(isolated_db):
    isolated_db.preset_save('p', [{'id': 'server_audit', 'params': {'host': 'a', 'password': PW}}])
    assert all(PW not in raw for raw in _raw_presets(isolated_db))
    saved = next(p for p in isolated_db.presets_list() if p['name'] == 'p')
    assert saved['checks'] == [{'id': 'server_audit', 'params': {'host': 'a'}}]


def test_presets_list_strips_rows_saved_before_the_fix(isolated_db):
    isolated_db.presets_list()  # creates the schema and seed presets
    conn = sqlite3.connect(isolated_db.DB_PATH)
    try:
        conn.execute('INSERT INTO presets (name, checks, created_at) VALUES (?,?,?)',
                     ('old', json.dumps([{'id': 'server_audit', 'params': {'host': 'a', 'password': PW}}]),
                      '2026-01-01T00:00:00'))
        conn.commit()
    finally:
        conn.close()
    listed = isolated_db.presets_list()
    assert PW not in json.dumps(listed)
    old = next(p for p in listed if p['name'] == 'old')
    assert old['checks'] == [{'id': 'server_audit', 'params': {'host': 'a'}}]


# ===========================================================================
# Web API
# ===========================================================================

def test_api_preset_round_trip_has_no_secret(isolated_db):
    client = TestClient(app)
    resp = client.post('/api/presets', json={'name': 'with-pw', 'checks': [
        {'id': 'server_audit', 'params': {'host': '10.0.0.1', 'password': PW}},
        {'id': 'cve_audit', 'instances': [{'host': 'a', 'password': PW}, {'host': 'b'}]},
    ]})
    assert resp.status_code == 200
    body = client.get('/api/presets')
    assert PW not in body.text
    saved = next(p for p in body.json() if p['name'] == 'with-pw')
    assert saved['checks'] == [{'id': 'server_audit', 'params': {'host': '10.0.0.1'}},
                               {'id': 'cve_audit', 'instances': [{'host': 'a'}, {'host': 'b'}]}]
    assert all(PW not in raw for raw in _raw_presets(isolated_db))


# ===========================================================================
# Web UI: the secret is not sent for a preset save
# ===========================================================================

def _function_body(source: str, name: str) -> str:
    start = source.index(f'function {name}(')
    end = source.index('\n}\n', start)
    return source[start:end]


def test_save_preset_leaves_out_password_inputs():
    html = (STATIC / 'index.html').read_text(encoding='utf-8')
    save = _function_body(html, 'saveCurrentAsPreset')
    assert 'withoutSecretParams(getSelected())' in save
    strip = _function_body(html, 'withoutSecretParams')
    assert 'input[type=password]' in strip


def test_preset_saved_message_says_passwords_are_not_saved():
    i18n = (STATIC / 'i18n.js').read_text(encoding='utf-8')
    ru = re.search(r"'preset\.saved': '([^']*)'", i18n).group(1)
    en = re.findall(r"'preset\.saved': '([^']*)'", i18n)[1]
    assert 'пароли не сохраняются' in ru
    assert 'passwords are not saved' in en
