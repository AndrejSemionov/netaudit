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


def _private_install(tmp_path, monkeypatch, side_mode):
    home = tmp_path / 'home' / '.netaudit'
    home.mkdir(parents=True)
    home.chmod(0o700)
    db = home / 'netaudit.db'
    sqlite3.connect(db).close()
    db.chmod(0o600)
    monkeypatch.setattr(storage, 'DB_PATH', db)
    sides = [db.with_name(db.name + suffix) for suffix in ('-wal', '-shm')]
    for side in sides:
        side.write_bytes(b'')
        side.chmod(side_mode)
    return db, sides


def _vanish_after_first_probe(monkeypatch, sides):
    """SQLite removes -wal/-shm when the last connection closes: the file is
    there when first looked at and gone right after (review C2 pass 2)."""
    gone = set()
    real_stat, real_exists = storage.Path.stat, storage.Path.exists

    def after(self, result):
        if self in sides and self not in gone:
            gone.add(self)
            self.unlink()
        return result

    monkeypatch.setattr(storage.Path, 'stat', lambda self, **kw: after(self, real_stat(self, **kw)))
    monkeypatch.setattr(storage.Path, 'exists', lambda self, **kw: after(self, real_exists(self, **kw)))


@pytest.mark.parametrize('side_mode', [0o600, 0o644], ids=['private', 'open'])
def test_sidecars_vanishing_during_the_check_are_not_an_error(tmp_path, monkeypatch, side_mode):
    db, sides = _private_install(tmp_path, monkeypatch, side_mode)
    _vanish_after_first_probe(monkeypatch, sides)
    storage._make_private()
    assert _mode(db) == 0o600 and _mode(db.parent) == 0o700


def test_sidecars_vanishing_after_chmod_are_not_an_error(tmp_path, monkeypatch):
    db, sides = _private_install(tmp_path, monkeypatch, 0o644)
    real_chmod = storage.os.chmod

    def chmod_then_vanish(path, mode):
        real_chmod(path, mode)
        if path in sides:
            path.unlink()

    monkeypatch.setattr(storage.os, 'chmod', chmod_then_vanish)
    storage._make_private()
    assert not any(side.exists() for side in sides)
    assert _mode(db) == 0o600


def test_the_database_itself_vanishing_is_still_an_error(tmp_path, monkeypatch):
    db, _sides = _private_install(tmp_path, monkeypatch, 0o600)
    db.chmod(0o644)
    real_chmod = storage.os.chmod

    def chmod_then_vanish(path, mode):
        real_chmod(path, mode)
        if path == db:
            path.unlink()

    monkeypatch.setattr(storage.os, 'chmod', chmod_then_vanish)
    with pytest.raises(FileNotFoundError):
        storage._make_private()
