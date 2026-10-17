"""
D6 of docs/research/c1_schedule_notifications.md: the database holds the AI
key, the Telegram token and the MikroTik password, so `~/.netaudit` is 0700
and the database file 0600 - on a fresh install and after an upgrade.
"""

from __future__ import annotations

import sqlite3
import stat

import pytest

from netaudit_pkg import storage


@pytest.fixture(autouse=True)
def _close_connection():
    yield
    if hasattr(storage._local, 'conn'):
        storage._local.conn.close()
        del storage._local.conn


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def _reconnect():
    if hasattr(storage._local, 'conn'):
        storage._local.conn.close()
        del storage._local.conn
    return storage._conn()


def test_fresh_database_and_directory_are_private(tmp_path, monkeypatch):
    db = tmp_path / 'home' / '.netaudit' / 'netaudit.db'
    monkeypatch.setattr(storage, 'DB_PATH', db)
    _reconnect()
    storage.setting_set('telegram_token', 'FAKE')

    assert _mode(db.parent) == 0o700
    assert _mode(db) == 0o600
    for side in (db.with_name(db.name + '-wal'), db.with_name(db.name + '-shm')):
        if side.exists():
            assert _mode(side) & 0o077 == 0, side


def test_existing_open_permissions_are_tightened(tmp_path, monkeypatch):
    home = tmp_path / 'home' / '.netaudit'
    home.mkdir(parents=True)
    home.chmod(0o775)
    db = home / 'netaudit.db'
    sqlite3.connect(db).close()
    db.chmod(0o644)
    monkeypatch.setattr(storage, 'DB_PATH', db)

    _reconnect()

    assert _mode(home) == 0o700
    assert _mode(db) == 0o600


def _open_install(tmp_path, monkeypatch):
    home = tmp_path / 'home' / '.netaudit'
    home.mkdir(parents=True)
    home.chmod(0o775)
    db = home / 'netaudit.db'
    sqlite3.connect(db).close()
    db.chmod(0o644)
    monkeypatch.setattr(storage, 'DB_PATH', db)
    return home, db


def _chmod_refused(*args, **kwargs):
    raise PermissionError(1, 'Operation not permitted')


def test_a_refused_chmod_on_an_open_database_is_not_silent(tmp_path, monkeypatch):
    # review C2 pass 1: chmod may be refused (another owner) while writing is
    # still allowed - secrets must not be stored in a file others can read
    _home, db = _open_install(tmp_path, monkeypatch)
    monkeypatch.setattr(storage.os, 'chmod', _chmod_refused)
    with pytest.raises(storage.InsecureStorageError) as exc:
        _reconnect()
    assert str(db.parent) in str(exc.value) or str(db) in str(exc.value)
    assert _mode(db) == 0o644


def test_already_private_files_need_no_chmod(tmp_path, monkeypatch):
    home, db = _open_install(tmp_path, monkeypatch)
    home.chmod(0o700)
    db.chmod(0o600)
    monkeypatch.setattr(storage.os, 'chmod', _chmod_refused)
    _reconnect()
    storage.setting_set('telegram_token', 'FAKE')
    assert storage.setting_get('telegram_token') == 'FAKE'
