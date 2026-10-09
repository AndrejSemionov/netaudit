"""Legacy password scrub: every database here is created under tmp_path."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from pathlib import Path

import pytest

from netaudit_pkg import scrub_legacy_secrets as scrub

SECRET = 'FAKE-TEST-PW-ONLY'


def _db(tmp_path: Path, *reports: dict | str) -> Path:
    path = tmp_path / 'reports.db'
    conn = sqlite3.connect(path)
    try:
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('CREATE TABLE reports (id INTEGER PRIMARY KEY, timestamp TEXT, '
                     'checks TEXT, total_time REAL, data TEXT NOT NULL)')
        for report in reports:
            payload = report if isinstance(report, str) else json.dumps(report)
            conn.execute('INSERT INTO reports (timestamp, checks, total_time, data) VALUES (?,?,?,?)',
                         ('2026-01-01', 'ssh_hardening', 1.0, payload))
        conn.commit()
    finally:
        conn.close()
    return path


def _report(context: dict, *, results: dict | None = None) -> dict:
    return {'timestamp': '2026-01-01', 'results': results or {'ssh_hardening': {'ok': True}},
            'execution_context': {'ssh_hardening': context}, 'total_time': 1.0}


def _raw(path: Path) -> list[str]:
    conn = sqlite3.connect(f'{path.as_uri()}?mode=ro', uri=True)
    try:
        return [r[0] for r in conn.execute('SELECT data FROM reports ORDER BY id')]
    finally:
        conn.close()


def test_dry_run_counts_without_mutation_or_backup(tmp_path):
    db = _db(tmp_path, _report({'host': 'a', 'password': SECRET}), _report({'host': 'b'}))
    before = _raw(db)
    result = scrub.scan_database(db)
    assert (result.total, result.affected, result.malformed, result.eligible) == (2, 1, 0, True)
    assert _raw(db) == before
    assert sorted(p.name for p in tmp_path.iterdir() if p.suffix == '.db') == ['reports.db']


def test_apply_scrubs_flat_and_multi_host_preserving_other_data(tmp_path):
    first = _report({'host': 'a', 'password': SECRET}, results={'ssh_hardening': {'ok': True}})
    second = _report({'a': {'host': 'a', 'password': SECRET},
                      'b': {'host': 'b', 'password': SECRET}})
    db = _db(tmp_path, first, second)
    backup = tmp_path / 'original.db'
    result = scrub.apply_scrub(db, backup)
    assert result.status == 'complete' and result.affected == 2
    assert all(SECRET not in raw for raw in _raw(db))
    assert all(SECRET in raw for raw in _raw(backup))
    rows = [json.loads(raw) for raw in _raw(db)]
    assert rows[0] == _report({'host': 'a'})
    assert rows[1] == _report({'a': {'host': 'a'}, 'b': {'host': 'b'}})
    conn = sqlite3.connect(db)
    try:
        assert conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert conn.execute('SELECT id, timestamp, checks, total_time FROM reports ORDER BY id').fetchall() == [
            (1, '2026-01-01', 'ssh_hardening', 1.0),
            (2, '2026-01-01', 'ssh_hardening', 1.0),
        ]
    finally:
        conn.close()


def test_noop_does_not_create_backup_and_is_repeatable(tmp_path):
    db = _db(tmp_path, _report({'host': 'a'}))
    backup = tmp_path / 'unused.db'
    assert scrub.apply_scrub(db, backup).status == 'noop'
    assert scrub.apply_scrub(db, backup).status == 'noop'
    assert not backup.exists()


@pytest.mark.parametrize('bad', ['not-json', '[]', '42'])
def test_invalid_report_blocks_apply_before_backup(tmp_path, bad):
    db = _db(tmp_path, _report({'host': 'a', 'password': SECRET}), bad)
    before = _raw(db)
    assert scrub.scan_database(db).eligible is False
    with pytest.raises(scrub.ScrubError):
        scrub.apply_scrub(db, tmp_path / 'backup.db')
    assert _raw(db) == before
    assert not (tmp_path / 'backup.db').exists()


def test_unsupported_context_shape_fails_closed(tmp_path):
    report = {'results': {}, 'execution_context': {'x': [{'password': SECRET}]}}
    db = _db(tmp_path, report)
    assert scrub.scan_database(db).eligible is False
    with pytest.raises(scrub.ScrubError):
        scrub.apply_scrub(db, tmp_path / 'backup.db')


def test_scalar_execution_context_is_unsupported_even_without_visible_key(tmp_path):
    db = _db(tmp_path, {'results': {}, 'execution_context': 'legacy-unstructured-data'})
    assert scrub.scan_database(db).unsupported == 1
    with pytest.raises(scrub.ScrubError):
        scrub.apply_scrub(db, tmp_path / 'backup.db')


def test_non_text_report_data_fails_closed(tmp_path):
    db = _db(tmp_path, _report({'host': 'a', 'password': SECRET}))
    conn = sqlite3.connect(db)
    try:
        conn.execute('INSERT INTO reports (timestamp, checks, total_time, data) VALUES (?,?,?,?)',
                     ('2026-01-01', 'ssh_hardening', 0, sqlite3.Binary(b'\xff')))
        conn.commit()
    finally:
        conn.close()
    assert scrub.scan_database(db).malformed == 1
    with pytest.raises(scrub.ScrubError):
        scrub.apply_scrub(db, tmp_path / 'backup.db')


def test_outside_context_secret_key_is_advisory_only(tmp_path):
    report = _report({'host': 'a', 'password': SECRET}, results={'x': {'password': 'not-a-credential'}})
    db = _db(tmp_path, report)
    assert scrub.scan_database(db).outside_context == 1
    scrub.apply_scrub(db, tmp_path / 'backup.db')
    assert json.loads(_raw(db)[0])['results']['x']['password'] == 'not-a-credential'


def test_backup_private_before_sqlite_writes_and_never_overwrites(tmp_path, monkeypatch):
    db = _db(tmp_path, _report({'host': 'a', 'password': SECRET}))
    backup = tmp_path / 'backup.db'
    original_umask = os.umask(0o022)
    os.umask(original_umask)
    original_connect = scrub.sqlite3.connect

    def inspect_connect(database, *args, **kwargs):
        if str(database) == str(backup):
            assert backup.exists()
            assert stat.S_IMODE(backup.stat().st_mode) == 0o600
            previous = os.umask(0o077)
            os.umask(previous)
            assert previous == 0o077
        return original_connect(database, *args, **kwargs)

    monkeypatch.setattr(scrub.sqlite3, 'connect', inspect_connect)
    scrub.apply_scrub(db, backup)
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    for suffix in ('-journal', '-wal', '-shm'):
        sidecar = Path(f'{backup}{suffix}')
        if sidecar.exists():
            assert stat.S_IMODE(sidecar.stat().st_mode) & 0o077 == 0
    previous = os.umask(0o077)
    os.umask(previous)
    assert previous == original_umask
    with pytest.raises(scrub.ScrubError):
        scrub.apply_scrub(db, backup)


def test_locked_database_fails_without_backup_or_update(tmp_path):
    db = _db(tmp_path, _report({'host': 'a', 'password': SECRET}))
    blocker = sqlite3.connect(db)
    blocker.execute('BEGIN IMMEDIATE')
    try:
        with pytest.raises(scrub.ScrubError):
            scrub.apply_scrub(db, tmp_path / 'backup.db')
    finally:
        blocker.rollback()
        blocker.close()
    assert SECRET in _raw(db)[0]
    assert not (tmp_path / 'backup.db').exists()


def test_non_wal_database_is_refused_before_backup(tmp_path):
    db = _db(tmp_path, _report({'host': 'a', 'password': SECRET}))
    conn = sqlite3.connect(db)
    try:
        conn.execute('PRAGMA journal_mode=DELETE')
    finally:
        conn.close()
    with pytest.raises(scrub.ScrubError, match='WAL'):
        scrub.apply_scrub(db, tmp_path / 'backup.db')
    assert SECRET in _raw(db)[0]
    assert not (tmp_path / 'backup.db').exists()


def test_database_symlink_and_existing_backup_are_rejected(tmp_path):
    db = _db(tmp_path, _report({'host': 'a', 'password': SECRET}))
    alias = tmp_path / 'alias.db'
    alias.symlink_to(db)
    with pytest.raises(scrub.ScrubError):
        scrub.scan_database(alias)
    backup = tmp_path / 'backup.db'
    backup.write_bytes(b'existing user data')
    with pytest.raises(scrub.ScrubError):
        scrub.apply_scrub(db, backup)
    assert backup.read_bytes() == b'existing user data'


def test_source_database_sidecar_cannot_be_backup_path(tmp_path):
    db = _db(tmp_path, _report({'host': 'a', 'password': SECRET}))
    for suffix in ('-journal', '-wal', '-shm'):
        candidate = Path(f'{db}{suffix}')
        with pytest.raises(scrub.ScrubError):
            scrub.apply_scrub(db, candidate)
    assert SECRET in _raw(db)[0]


def test_failure_before_commit_rolls_back_and_keeps_private_backup(tmp_path, monkeypatch):
    db = _db(tmp_path, _report({'host': 'a', 'password': SECRET}))
    backup = tmp_path / 'backup.db'

    def fail_after_first(conn, updates):
        row_id, data = updates[0]
        conn.execute('UPDATE reports SET data=? WHERE id=?', (data, row_id))
        raise RuntimeError(SECRET)

    monkeypatch.setattr(scrub, '_perform_updates', fail_after_first)
    with pytest.raises(scrub.ScrubError) as exc:
        scrub.apply_scrub(db, backup)
    assert SECRET not in str(exc.value)
    assert SECRET in _raw(db)[0]
    assert SECRET in _raw(backup)[0]
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600


def test_post_commit_vacuum_failure_is_incomplete_not_rollback(tmp_path, monkeypatch):
    db = _db(tmp_path, _report({'host': 'a', 'password': SECRET}))

    def fail_vacuum(conn):
        raise sqlite3.OperationalError('disk full ' + SECRET)

    monkeypatch.setattr(scrub, '_run_vacuum', fail_vacuum)
    result = scrub.apply_scrub(db, tmp_path / 'backup.db')
    assert result.status == 'incomplete' and result.stage == 'vacuum'
    assert SECRET not in str(result)
    assert SECRET not in _raw(db)[0]


def test_checkpoint_busy_is_incomplete(tmp_path, monkeypatch):
    db = _db(tmp_path, _report({'host': 'a', 'password': SECRET}))
    monkeypatch.setattr(scrub, '_checkpoint', lambda conn: (1, 1, 0))
    result = scrub.apply_scrub(db, tmp_path / 'backup.db')
    assert result.status == 'incomplete' and result.stage == 'checkpoint'


def test_preflight_warns_when_free_space_is_low(tmp_path, monkeypatch):
    db = _db(tmp_path, _report({'host': 'a', 'password': SECRET}))
    monkeypatch.setattr(scrub.shutil, 'disk_usage', lambda path: type('Usage', (), {'free': 0})())
    assert scrub.scan_database(db).space_warning is True


def test_cli_apply_uses_only_aggregate_output(tmp_path, capsys):
    db = _db(tmp_path, _report({'host': 'a', 'password': SECRET}))
    backup = tmp_path / 'backup.db'
    assert scrub.main(['--database', str(db), '--apply', '--backup', str(backup)]) == 0
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err
    assert 'affected=1' in captured.out
    assert SECRET not in _raw(db)[0]


def test_cli_apply_warns_about_space_at_backup_location(tmp_path, capsys, monkeypatch):
    db = _db(tmp_path, _report({'host': 'a', 'password': SECRET}))
    backup = tmp_path / 'backup.db'
    monkeypatch.setattr(scrub, '_space_warning', lambda source, destination=None: destination == backup)
    assert scrub.main(['--database', str(db), '--apply', '--backup', str(backup)]) == 0
    assert 'space_warning=True' in capsys.readouterr().out


def test_cli_warns_of_sensitive_backup_after_precommit_failure(tmp_path, capsys, monkeypatch):
    db = _db(tmp_path, _report({'host': 'a', 'password': SECRET}))
    backup = tmp_path / 'backup.db'

    def fail_updates(conn, updates):
        raise RuntimeError(SECRET)

    monkeypatch.setattr(scrub, '_perform_updates', fail_updates)
    assert scrub.main(['--database', str(db), '--apply', '--backup', str(backup)]) == 2
    output = capsys.readouterr()
    assert str(backup) in output.err
    assert 'may contain original secrets' in output.err
    assert SECRET not in output.err
    assert backup.exists() and SECRET in _raw(backup)[0]


def test_cli_no_backup_warning_when_backup_reservation_fails(tmp_path, capsys, monkeypatch):
    db = _db(tmp_path, _report({'host': 'a', 'password': SECRET}))
    backup = tmp_path / 'backup.db'
    monkeypatch.setattr(scrub, '_reserve_backup', lambda path: (_ for _ in ()).throw(scrub.ScrubError('reserve failed')))
    assert scrub.main(['--database', str(db), '--apply', '--backup', str(backup)]) == 2
    assert 'may contain original secrets' not in capsys.readouterr().err
    assert not backup.exists()


def test_cli_requires_explicit_path_and_never_prints_secret(tmp_path, capsys):
    assert scrub.main([]) != 0
    db = _db(tmp_path, _report({'host': 'a', 'password': SECRET}))
    assert scrub.main(['--database', str(db)]) == 0
    assert scrub.main(['--database', str(db), '--apply']) != 0
    assert SECRET not in (capsys.readouterr().out + capsys.readouterr().err)


# ===========================================================================
# Task 8 (D2-A): the presets table is scanned and scrubbed with the reports
# ===========================================================================

def _add_presets(path: Path, *presets: list | str) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.execute('CREATE TABLE IF NOT EXISTS presets (id INTEGER PRIMARY KEY, name TEXT UNIQUE, '
                     'checks TEXT NOT NULL, created_at TEXT)')
        for i, checks in enumerate(presets):
            payload = checks if isinstance(checks, str) else json.dumps(checks)
            conn.execute('INSERT INTO presets (name, checks, created_at) VALUES (?,?,?)',
                         (f'p{i}', payload, '2026-01-01'))
        conn.commit()
    finally:
        conn.close()


def _raw_presets(path: Path) -> list[str]:
    conn = sqlite3.connect(f'{path.as_uri()}?mode=ro', uri=True)
    try:
        return [r[0] for r in conn.execute('SELECT checks FROM presets ORDER BY id')]
    finally:
        conn.close()


_PRESET_WITH_PW = [{'id': 'server_audit', 'params': {'host': 'a', 'password': SECRET}},
                   {'id': 'cve_audit', 'instances': [{'host': 'b', 'password': SECRET}]}]
_PRESET_CLEAN = [{'id': 'mtr', 'params': {'target': '8.8.8.8'}}]


def test_dry_run_counts_presets(tmp_path):
    db = _db(tmp_path, _report({'host': 'a'}))
    _add_presets(db, _PRESET_WITH_PW, _PRESET_CLEAN)
    before = _raw_presets(db)
    scan = scrub.scan_database(db)
    assert (scan.presets_total, scan.presets_affected, scan.presets_malformed) == (2, 1, 0)
    assert (scan.affected, scan.eligible) == (0, True)
    assert _raw_presets(db) == before


def test_apply_scrubs_presets_and_reports_together(tmp_path):
    db = _db(tmp_path, _report({'host': 'a', 'password': SECRET}))
    _add_presets(db, _PRESET_WITH_PW, _PRESET_CLEAN)
    backup = tmp_path / 'original.db'
    result = scrub.apply_scrub(db, backup)
    assert (result.status, result.affected, result.presets_affected) == ('complete', 1, 1)
    assert all(SECRET not in raw for raw in _raw(db) + _raw_presets(db))
    assert [json.loads(raw) for raw in _raw_presets(db)] == [
        [{'id': 'server_audit', 'params': {'host': 'a'}}, {'id': 'cve_audit', 'instances': [{'host': 'b'}]}],
        _PRESET_CLEAN,
    ]
    assert SECRET in _raw_presets(backup)[0]


def test_apply_scrubs_presets_when_reports_are_clean(tmp_path):
    db = _db(tmp_path, _report({'host': 'a'}))
    _add_presets(db, _PRESET_WITH_PW)
    result = scrub.apply_scrub(db, tmp_path / 'original.db')
    assert (result.status, result.affected, result.presets_affected) == ('complete', 0, 1)
    assert SECRET not in _raw_presets(db)[0]
    assert scrub.apply_scrub(db, tmp_path / 'again.db').status == 'noop'


@pytest.mark.parametrize('bad', ['not-json', '42', '{"id": "x"}'])
def test_malformed_preset_blocks_apply_before_backup(tmp_path, bad):
    db = _db(tmp_path, _report({'host': 'a', 'password': SECRET}))
    _add_presets(db, bad)
    assert scrub.scan_database(db).presets_malformed == 1
    backup = tmp_path / 'backup.db'
    with pytest.raises(scrub.ScrubError):
        scrub.apply_scrub(db, backup)
    assert not backup.exists()
    assert SECRET in _raw(db)[0]


def test_database_without_presets_table(tmp_path):
    db = _db(tmp_path, _report({'host': 'a', 'password': SECRET}))
    scan = scrub.scan_database(db)
    assert (scan.presets_total, scan.presets_affected) == (0, 0)
    assert scrub.apply_scrub(db, tmp_path / 'b.db').status == 'complete'


def test_cli_reports_preset_counts_without_secrets(tmp_path, capsys):
    db = _db(tmp_path, _report({'host': 'a'}))
    _add_presets(db, _PRESET_WITH_PW)
    assert scrub.main(['--database', str(db)]) == 0
    out = capsys.readouterr().out
    assert 'presets=1 presets_affected=1 presets_malformed=0' in out
    assert scrub.main(['--database', str(db), '--apply', '--backup', str(tmp_path / 'b.db')]) == 0
    out = capsys.readouterr().out
    assert 'presets_affected=1' in out
    assert SECRET not in out
