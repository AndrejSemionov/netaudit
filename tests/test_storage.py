"""
Tests for netaudit_pkg.storage.

All tests use the isolated_db fixture from conftest.py, which points storage
at a fresh temp SQLite file per test - no test here touches the real
~/.netaudit/netaudit.db.
"""

from __future__ import annotations

import json

import pytest


# ===========================================================================
# Migrations & seed presets
# ===========================================================================

def test_migrations_create_expected_tables(isolated_db):
    conn = isolated_db._conn()
    tables = {row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    expected = {'reports', 'timing_stats', 'settings', 'presets', 'targets',
                'rep_list', 'asn_cache', 'cve_cache', 'traffic_history'}
    assert expected <= tables


def test_migrations_are_idempotent(isolated_db):
    """Opening a second connection against the same (already-migrated) DB
    file shouldn't re-run migrations or error out - _conn() is per-thread,
    but re-invoking _migrate on an up-to-date DB must be a safe no-op."""
    conn = isolated_db._conn()
    version_before = conn.execute('PRAGMA user_version').fetchone()[0]
    isolated_db._migrate(conn)  # call again directly
    version_after = conn.execute('PRAGMA user_version').fetchone()[0]
    assert version_before == version_after


def test_seed_presets_created_on_first_access(isolated_db):
    presets = isolated_db.presets_list()
    assert len(presets) == 5  # the 5 default presets from _seed_presets


def test_seed_presets_not_duplicated_on_repeat_calls(isolated_db):
    isolated_db.presets_list()
    conn = isolated_db._conn()
    isolated_db._seed_presets(conn)  # calling again shouldn't add more
    presets = isolated_db.presets_list()
    assert len(presets) == 5


def test_seed_preset_names_are_intentionally_russian(isolated_db):
    """Documents a deliberate design choice (not a translation oversight):
    preset names stay in Russian because they're used as lookup keys in
    web/static/i18n.js's PRESET_NAME_TR dict for display translation.
    Renaming them here without updating that dict would break the
    translation for both new installs and any already-stored presets."""
    presets = isolated_db.presets_list()
    names = {p['name'] for p in presets}
    assert '🌐 Неполадки в сети' in names
    assert '🔒 Аудит сайта (снаружи)' in names


# ===========================================================================
# Reports
# ===========================================================================

def test_save_and_load_report(isolated_db):
    report = {'timestamp': '2026-01-01 12:00:00', 'results': {'mtr': {'ok': True}}, 'total_time': 1.5}
    report_id = isolated_db.save_report(report)
    loaded = isolated_db.load_report(report_id)
    assert loaded['results'] == {'mtr': {'ok': True}}


def test_load_nonexistent_report_returns_none(isolated_db):
    assert isolated_db.load_report(999999) is None


def test_list_reports_returns_most_recent_first(isolated_db):
    isolated_db.save_report({'timestamp': '2026-01-01 00:00:00', 'results': {'a': {}}, 'total_time': 1})
    isolated_db.save_report({'timestamp': '2026-01-02 00:00:00', 'results': {'b': {}}, 'total_time': 1})
    reports = isolated_db.list_reports()
    assert reports[0]['checks'] == ['b']
    assert reports[1]['checks'] == ['a']


def test_list_reports_respects_limit(isolated_db):
    for i in range(5):
        isolated_db.save_report({'timestamp': f'2026-01-0{i+1} 00:00:00', 'results': {'x': {}}, 'total_time': 1})
    assert len(isolated_db.list_reports(limit=2)) == 2


# ===========================================================================
# Settings
# ===========================================================================

def test_setting_get_returns_default_when_unset(isolated_db):
    assert isolated_db.setting_get('nonexistent_key', 'fallback') == 'fallback'


def test_setting_set_and_get(isolated_db):
    isolated_db.setting_set('ai_language', 'en')
    assert isolated_db.setting_get('ai_language') == 'en'


def test_setting_set_overwrites_previous_value(isolated_db):
    isolated_db.setting_set('key1', 'first')
    isolated_db.setting_set('key1', 'second')
    assert isolated_db.setting_get('key1') == 'second'


def test_settings_all_returns_dict(isolated_db):
    isolated_db.setting_set('a', '1')
    isolated_db.setting_set('b', '2')
    all_settings = isolated_db.settings_all()
    assert all_settings['a'] == '1'
    assert all_settings['b'] == '2'


# ===========================================================================
# CVE cache
# ===========================================================================

def test_cve_set_and_get(isolated_db):
    isolated_db.cve_set('nginx::1.24.0', ['CVE-2024-0001', 'CVE-2024-0002'])
    result = isolated_db.cve_get('nginx::1.24.0')
    assert result['data'] == ['CVE-2024-0001', 'CVE-2024-0002']
    assert 'updated_at' in result


def test_cve_get_missing_key_returns_none(isolated_db):
    assert isolated_db.cve_get('never-cached::1.0') is None


def test_cve_set_overwrites_previous_entry(isolated_db):
    isolated_db.cve_set('nginx::1.24.0', ['CVE-A'])
    isolated_db.cve_set('nginx::1.24.0', ['CVE-B'])
    result = isolated_db.cve_get('nginx::1.24.0')
    assert result['data'] == ['CVE-B']


# ===========================================================================
# Targets
# ===========================================================================

def test_target_add_and_list(isolated_db):
    isolated_db.target_add('8.8.8.8', label='Google DNS', kind='ip')
    targets = isolated_db.targets_list()
    assert any(t['value'] == '8.8.8.8' for t in targets)


def test_target_delete(isolated_db):
    tid = isolated_db.target_add('1.1.1.1', kind='ip')
    isolated_db.target_delete(tid)
    targets = isolated_db.targets_list()
    assert not any(t['value'] == '1.1.1.1' for t in targets)


# ===========================================================================
# Reputation lists (allow/block)
# ===========================================================================

def test_rep_add_and_list(isolated_db):
    isolated_db.rep_add('8.8.8.8', 'allow', note='Google DNS')
    entries = isolated_db.rep_list('allow')
    assert any(e['pattern'] == '8.8.8.8' for e in entries)


def test_rep_list_filters_by_type(isolated_db):
    isolated_db.rep_add('1.1.1.1', 'allow')
    isolated_db.rep_add('6.6.6.6', 'block')
    allow_entries = isolated_db.rep_list('allow')
    block_entries = isolated_db.rep_list('block')
    assert all(e['list_type'] == 'allow' for e in allow_entries)
    assert all(e['list_type'] == 'block' for e in block_entries)


def test_rep_delete(isolated_db):
    rid = isolated_db.rep_add('2.2.2.2', 'block')
    isolated_db.rep_delete(rid)
    entries = isolated_db.rep_list('block')
    assert not any(e['pattern'] == '2.2.2.2' for e in entries)


# ===========================================================================
# ASN cache
# ===========================================================================

def test_asn_set_and_get(isolated_db):
    isolated_db.asn_set('8.8.8.8', 'Google LLC', 'US')
    result = isolated_db.asn_get('8.8.8.8')
    assert result['org'] == 'Google LLC'
    assert result['country'] == 'US'


def test_asn_get_missing_returns_none(isolated_db):
    assert isolated_db.asn_get('9.9.9.9') is None


# ===========================================================================
# Presets (beyond the seed data)
# ===========================================================================

def test_preset_save_and_list(isolated_db):
    checks = [{'id': 'mtr', 'params': {'target': '8.8.8.8'}}]
    isolated_db.preset_save('My custom preset', checks)
    presets = isolated_db.presets_list()
    custom = next(p for p in presets if p['name'] == 'My custom preset')
    assert custom['checks'] == checks


def test_preset_delete(isolated_db):
    pid = isolated_db.preset_save('Temporary preset', [])
    isolated_db.preset_delete(pid)
    presets = isolated_db.presets_list()
    assert not any(p['name'] == 'Temporary preset' for p in presets)
