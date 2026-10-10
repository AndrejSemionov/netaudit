"""F4: failed collection must not be reported as a clean target."""

from __future__ import annotations

import time

import pytest

from netaudit_pkg.checks.backup_check import check_backup
from netaudit_pkg.checks.docker_audit import check_docker_audit
from tests.conftest import ExitCodeFakeSSHExecutor


@pytest.mark.parametrize('exit_code,output', [(1, 'error during connect: EOF'),
                                              (None, '')])
def test_docker_ps_failure_is_not_zero_containers(monkeypatch, exit_code, output):
    fake = ExitCodeFakeSSHExecutor(
        installed_tools={'docker'},
        responses={'docker ps -q': output},
        exit_codes={'docker ps -q': exit_code},
    )
    monkeypatch.setattr('netaudit_pkg.checks.docker_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_docker_audit(host='127.0.0.1')
    assert 'error' in result
    assert not any(f['severity'] == 'ok' for f in result.get('findings', []))


def test_docker_inspect_failure_names_incomplete_coverage(monkeypatch):
    fake = ExitCodeFakeSSHExecutor(
        installed_tools={'docker'},
        responses={'docker ps -q': 'bad\n', 'docker inspect': 'not json'},
        exit_codes={'docker ps -q': 0, 'docker inspect': 0},
    )
    monkeypatch.setattr('netaudit_pkg.checks.docker_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_docker_audit(host='127.0.0.1')
    assert result['containers_checked'] == 1
    assert result.get('warnings') or result.get('error')
    assert not any(f['severity'] == 'ok' for f in result.get('findings', []))


def test_docker_partial_inspection_always_has_visible_incomplete_finding(monkeypatch):
    fake = ExitCodeFakeSSHExecutor(
        installed_tools={'docker'},
        responses={'docker ps -q': 'bad\ngood\n',
                   'docker inspect bad': 'not json',
                   'docker inspect good': '[{"Config": {"User": "root", "Image": "app:latest"}, "HostConfig": {}}]'},
        exit_codes={'docker ps -q': 0, 'docker inspect bad': 0, 'docker inspect good': 0},
    )
    monkeypatch.setattr('netaudit_pkg.checks.docker_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_docker_audit(host='127.0.0.1')
    assert result['containers_inspected'] == 1
    assert any('incomplete' in f['title'].lower() for f in result['findings'])
    assert any('root' in f['title'].lower() for f in result['findings'])


@pytest.mark.parametrize('exit_code,output', [(1, 'find: Permission denied'),
                                              (None, '')])
def test_backup_find_failure_is_not_empty_directory(monkeypatch, exit_code, output):
    fake = ExitCodeFakeSSHExecutor(
        responses={'find ': output},
        exit_codes={'find ': exit_code},
    )
    monkeypatch.setattr('netaudit_pkg.checks.backup_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_backup(host='127.0.0.1', directories='/var/backups')
    assert result['directories'][0].get('error')
    assert not any('no backup files' in f['title'] or 'does not exist' in f['title']
                   for f in result['findings'])
    assert not any(f['severity'] == 'ok' for f in result['findings'])


@pytest.mark.parametrize('dir_code', [0, None])
def test_backup_child_disappearing_does_not_mean_directory_absent(monkeypatch, dir_code):
    fake = ExitCodeFakeSSHExecutor(
        responses={'find ': 'find: /var/backups/old.sql.gz: No such file or directory',
                   'test -d ': ''},
        exit_codes={'find ': 1, 'test -d ': dir_code},
    )
    monkeypatch.setattr('netaudit_pkg.checks.backup_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_backup(host='127.0.0.1', directories='/var/backups')
    assert result['directories'][0].get('error') != 'directory does not exist'
    assert any('could not list backup directory' in f['title'] for f in result['findings'])
    assert not any('does not exist' in f['title'] for f in result['findings'])


def test_backup_missing_root_is_confirmed_by_test_d(monkeypatch):
    fake = ExitCodeFakeSSHExecutor(
        responses={'find ': 'find: /var/missing: No such file or directory',
                   'test -d ': ''},
        exit_codes={'find ': 1, 'test -d ': 1},
    )
    monkeypatch.setattr('netaudit_pkg.checks.backup_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_backup(host='127.0.0.1', directories='/var/missing')
    assert result['directories'][0]['error'] == 'directory does not exist'


def test_backup_missing_archive_tool_is_unknown_not_corrupted(monkeypatch):
    listing = f'{time.time() - 60}|2048|db.sql.gz\n'
    fake = ExitCodeFakeSSHExecutor(
        responses={'find ': listing, 'gzip -t': 'FAIL',
                   'df -P': '/dev/sda1 1 1 1 50% /\n'},
        exit_codes={'find ': 0, 'gzip -t': 127, 'df -P': 0},
        stderrs={'gzip -t': 'gzip: command not found'},
    )
    monkeypatch.setattr('netaudit_pkg.checks.backup_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_backup(host='127.0.0.1', directories='/var/backups', min_copies=1)
    assert result['directories'][0].get('integrity_ok') is None
    assert not any('fails the integrity check' in f['title'] for f in result['findings'])
    assert not any(f['severity'] == 'ok' for f in result['findings'])
