"""Tests for netaudit_pkg.checks.backup_check: file discovery parsing,
archive integrity checks, and the full check flow across freshness/size/
copy-count/disk-usage findings."""

from __future__ import annotations

import time

import pytest

from netaudit_pkg.checks.backup_check import (
    _find_files, _check_archive_integrity, _check_disk_space, check_backup,
)
from tests.conftest import FakeSSHExecutor


NOW = time.time()
RECENT = NOW - 3600 * 5   # 5 hours ago
OLD = NOW - 3600 * 200    # ~8.3 days ago


# ===========================================================================
# _find_files
# ===========================================================================

def test_find_files_parses_output():
    fake = FakeSSHExecutor(responses={
        'find': (f'{RECENT}|52428800|db.sql.gz\n{RECENT-3600}|50000000|db_old.sql.gz\n', ''),
    })
    files = _find_files(fake, '/var/backups')
    assert len(files) == 2
    assert files[0]['name'] == 'db.sql.gz'
    assert files[0]['size'] == 52428800


def test_find_files_missing_directory_returns_none():
    fake = FakeSSHExecutor(responses={
        'find': ('', "find: '/nonexistent': No such file or directory"),
    })
    assert _find_files(fake, '/nonexistent') is None


def test_find_files_empty_directory_returns_empty_list():
    """Distinguishing 'directory does not exist' (None) from 'directory
    exists but is empty' ([]) matters - they produce different findings."""
    fake = FakeSSHExecutor(responses={'find': ('', '')})
    assert _find_files(fake, '/empty') == []


# ===========================================================================
# _check_archive_integrity
# ===========================================================================

@pytest.mark.parametrize('filename,response_key', [
    ('dump.tar.gz', 'tar -tzf'),
    ('dump.gz', 'gzip -t'),
    ('dump.zip', 'unzip -t'),
    ('dump.tar.bz2', 'tar -tjf'),
])
def test_archive_integrity_ok(filename, response_key):
    fake = FakeSSHExecutor(responses={response_key: ('OK\n', '')})
    assert _check_archive_integrity(fake, '/var/backups', filename) is None


@pytest.mark.parametrize('filename,response_key', [
    ('dump.tar.gz', 'tar -tzf'),
    ('dump.gz', 'gzip -t'),
])
def test_archive_integrity_corrupt(filename, response_key):
    fake = FakeSSHExecutor(responses={response_key: ('FAIL\n', '')})
    error = _check_archive_integrity(fake, '/var/backups', filename)
    assert error is not None
    assert 'integrity check' in error


def test_archive_integrity_unknown_format_not_checked():
    fake = FakeSSHExecutor(responses={})
    assert _check_archive_integrity(fake, '/var/backups', 'dump.custom_format') is None


def test_archive_integrity_sql_html_error_page_detected():
    """A bare .sql dump that's actually an HTML error page is a common sign
    the dump job hit an auth/redirect failure instead of writing real data."""
    fake = FakeSSHExecutor(responses={'head -c 200': ('<html><body>Error 500</body></html>', '')})
    error = _check_archive_integrity(fake, '/var/backups', 'dump.sql')
    assert error is not None
    assert 'HTML' in error


def test_archive_integrity_sql_looks_fine():
    fake = FakeSSHExecutor(responses={'head -c 200': ('-- MySQL dump\nCREATE TABLE...', '')})
    assert _check_archive_integrity(fake, '/var/backups', 'dump.sql') is None


# ===========================================================================
# _check_disk_space
# ===========================================================================

def test_disk_space_parsed():
    fake = FakeSSHExecutor(responses={'df -P': ('/dev/sda1 1000 500 500 50% /\n', '')})
    pct, err = _check_disk_space(fake, '/var/backups')
    assert pct == 50
    assert err is None


def test_disk_space_unparseable():
    fake = FakeSSHExecutor(responses={'df -P': ('garbage output\n', '')})
    pct, err = _check_disk_space(fake, '/var/backups')
    assert pct is None
    assert err is not None


# ===========================================================================
# Full check_backup flow
# ===========================================================================

def test_healthy_backup_directory(monkeypatch):
    fake = FakeSSHExecutor(responses={
        'find': (f'{RECENT}|52428800|db.sql.gz\n{RECENT-3600}|50000000|db_old.sql.gz\n', ''),
        'gzip -t': ('OK\n', ''),
        'df -P': ('/dev/sda1 1000 500 500 50% /\n', ''),
    })
    monkeypatch.setattr('netaudit_pkg.checks.backup_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_backup(host='1.2.3.4', directories='/var/backups', max_age_hours=26, min_copies=2)
    assert result['summary']['ok'] == 1
    assert result['summary']['high'] == 0


def test_missing_directory_flagged_high(monkeypatch):
    fake = FakeSSHExecutor(responses={
        'find': ('', "No such file or directory"),
    })
    monkeypatch.setattr('netaudit_pkg.checks.backup_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_backup(host='1.2.3.4', directories='/missing')
    assert result['summary']['high'] == 1
    assert any('does not exist' in f['title'] for f in result['findings'])


def test_empty_directory_flagged_high(monkeypatch):
    fake = FakeSSHExecutor(responses={'find': ('', '')})
    monkeypatch.setattr('netaudit_pkg.checks.backup_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_backup(host='1.2.3.4', directories='/empty')
    assert result['summary']['high'] == 1
    assert any('no backup files' in f['title'] for f in result['findings'])


def test_stale_backup_flagged_high(monkeypatch):
    fake = FakeSSHExecutor(responses={
        'find': (f'{OLD}|50000000|old.sql.gz\n', ''),
        'gzip -t': ('OK\n', ''),
        'df -P': ('/dev/sda1 1000 500 500 50% /\n', ''),
    })
    monkeypatch.setattr('netaudit_pkg.checks.backup_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_backup(host='1.2.3.4', directories='/var/backups', max_age_hours=26, min_copies=1)
    assert any('stale' in f['title'] for f in result['findings'])
    assert result['summary']['high'] >= 1


def test_suspiciously_small_backup_flagged(monkeypatch):
    fake = FakeSSHExecutor(responses={
        'find': (f'{RECENT}|100|tiny.sql.gz\n', ''),
        'gzip -t': ('OK\n', ''),
        'df -P': ('/dev/sda1 1000 500 500 50% /\n', ''),
    })
    monkeypatch.setattr('netaudit_pkg.checks.backup_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_backup(host='1.2.3.4', directories='/var/backups', min_copies=1)
    assert any('suspiciously small' in f['title'] for f in result['findings'])


def test_too_few_copies_flagged_medium(monkeypatch):
    fake = FakeSSHExecutor(responses={
        'find': (f'{RECENT}|52428800|db.sql.gz\n', ''),  # only 1 file
        'gzip -t': ('OK\n', ''),
        'df -P': ('/dev/sda1 1000 500 500 50% /\n', ''),
    })
    monkeypatch.setattr('netaudit_pkg.checks.backup_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_backup(host='1.2.3.4', directories='/var/backups', min_copies=2)
    copy_finding = next(f for f in result['findings'] if 'copies' in f['title'])
    assert copy_finding['severity'] == 'medium'
    # the fix for the original 3-2-1 overclaim: must not assert the 3-2-1 rule
    # is satisfied or violated, only that local retention is thin
    assert '3-2-1' not in copy_finding['title']


def test_corrupted_archive_flagged_high(monkeypatch):
    fake = FakeSSHExecutor(responses={
        'find': (f'{RECENT}|52428800|db.sql.gz\n{RECENT-3600}|50000000|db2.sql.gz\n', ''),
        'gzip -t': ('FAIL\n', ''),
        'df -P': ('/dev/sda1 1000 500 500 50% /\n', ''),
    })
    monkeypatch.setattr('netaudit_pkg.checks.backup_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_backup(host='1.2.3.4', directories='/var/backups', min_copies=1)
    assert any('integrity check' in f['title'] for f in result['findings'])


def test_full_disk_flagged_medium(monkeypatch):
    fake = FakeSSHExecutor(responses={
        'find': (f'{RECENT}|52428800|db.sql.gz\n{RECENT-3600}|50000000|db2.sql.gz\n', ''),
        'gzip -t': ('OK\n', ''),
        'df -P': ('/dev/sda1 1000 950 50 95% /\n', ''),
    })
    monkeypatch.setattr('netaudit_pkg.checks.backup_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_backup(host='1.2.3.4', directories='/var/backups', min_copies=1)
    assert any('% full' in f['title'] for f in result['findings'])


def test_multiple_directories_checked_independently(monkeypatch):
    call_dirs = []

    class TrackingExecutor(FakeSSHExecutor):
        def run(self, cmd, timeout=20):
            if 'find' in cmd:
                call_dirs.append(cmd)
                if '/good' in cmd:
                    return (f'{RECENT}|52428800|db.sql.gz\n{RECENT-1}|52428800|db2.sql.gz\n', '')
                return ('', 'No such file or directory')
            return super().run(cmd, timeout)

    fake = TrackingExecutor(responses={'gzip -t': ('OK\n', ''), 'df -P': ('/dev/sda1 1 1 1 50% /\n', '')})
    monkeypatch.setattr('netaudit_pkg.checks.backup_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_backup(host='1.2.3.4', directories='/good, /missing', min_copies=1)
    assert len(result['directories']) == 2
    assert result['summary']['high'] == 1  # only /missing is flagged


def test_empty_host_rejected():
    result = check_backup(host='')
    assert 'error' in result


def test_empty_directories_rejected():
    result = check_backup(host='1.2.3.4', directories='')
    assert 'error' in result
