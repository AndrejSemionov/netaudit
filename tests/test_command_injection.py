"""Task 8, P2/P3 (docs/research/preset_secrets_and_command_injection.md):
operator-supplied values and paths read from the target never reach a remote
shell or RouterOS command as code.

Shell-level tests run the exact command a check builds through a real
/bin/sh in a temporary directory; nothing touches a real host.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path

import pytest

from netaudit_pkg.checks.backup_check import (
    _check_disk_space,
    _find_files,
    check_backup,
)
from netaudit_pkg.checks.capture import check_mikrotik_sniffer
from netaudit_pkg.checks.cve_audit import collect_composer_packages, collect_packages
from netaudit_pkg.checks.systemd_hardening import check_systemd_hardening
from tests.conftest import ExitCodeFakeSSHExecutor, FakeSSHExecutor


def _no_ssh(*args, **kwargs):
    raise AssertionError('no SSH connection may be opened for an invalid value')


class _LocalShell:
    """Runs commands that mention `tmp` through a real /bin/sh in `tmp`;
    answers `find` probes from `finds`; returns ('', '') for everything else."""

    def __init__(self, tmp: Path, finds: dict[str, str] | None = None):
        self.tmp = tmp
        self.finds = finds or {}
        self.calls: list[str] = []

    def run(self, cmd, timeout=20, stdin_data=None):
        self.calls.append(cmd)
        for prefix, out in self.finds.items():
            if cmd.startswith(prefix):
                return out, ''
        if str(self.tmp) not in cmd:
            return '', ''
        proc = subprocess.run(['/bin/sh', '-c', cmd], cwd=self.tmp, capture_output=True, text=True,  # nosec B603 - test-only local shell
                              timeout=timeout, env={**os.environ, 'HOME': str(self.tmp)}, check=False)
        return proc.stdout, proc.stderr

    def close(self):
        pass


# ===========================================================================
# systemd_hardening: unit name
# ===========================================================================

@pytest.mark.parametrize('unit', ['x; id', '-x', '--root=/', 'nginx.service --no-pager',
                                  'a$(id)', 'a/b.service', 'x' * 257])
def test_invalid_unit_is_rejected_before_connecting(monkeypatch, unit):
    monkeypatch.setattr('netaudit_pkg.checks.systemd_hardening.SSHExecutor', _no_ssh)
    assert check_systemd_hardening(host='1.2.3.4', unit=unit) == {'error': 'invalid systemd unit name'}


@pytest.mark.parametrize('unit', ['nginx.service', 'nginx', 'getty@tty1.service',
                                  'dev-disk-by\\x2duuid.swap', 'a:b_c.service'])
def test_valid_unit_reaches_ssh(monkeypatch, unit):
    fake = ExitCodeFakeSSHExecutor(responses={'systemctl show': 'loaded\n'},
                                   exit_codes={'systemctl show': 0})
    monkeypatch.setattr('netaudit_pkg.checks.systemd_hardening.SSHExecutor', lambda *a, **kw: fake)
    result = check_systemd_hardening(host='1.2.3.4', unit=unit)
    assert result.get('error') != 'invalid systemd unit name'
    assert fake.calls


def test_systemctl_show_quotes_the_unit(monkeypatch):
    fake = ExitCodeFakeSSHExecutor(responses={'systemctl show': 'loaded\n'},
                                   exit_codes={'systemctl show': 0})
    monkeypatch.setattr('netaudit_pkg.checks.systemd_hardening.SSHExecutor', lambda *a, **kw: fake)
    check_systemd_hardening(host='1.2.3.4', unit='dev-disk-by\\x2duuid.swap')
    assert "systemctl show --property=LoadState --value 'dev-disk-by\\x2duuid.swap'" in fake.calls[0]


# ===========================================================================
# backup_check: directories
# ===========================================================================

@pytest.mark.parametrize('directories', ['var/backups', '-delete', '/var/backups, -delete', '~/backups'])
def test_relative_or_option_like_directory_is_rejected_before_connecting(monkeypatch, directories):
    monkeypatch.setattr('netaudit_pkg.checks.backup_check.SSHExecutor', _no_ssh)
    result = check_backup(host='1.2.3.4', directories=directories)
    assert result['error'].startswith('backup directories must be absolute paths:')


def test_find_and_df_quote_the_directory(tmp_path):
    directory = f"{tmp_path}/b'$(touch {tmp_path}/PWNED_BKP)"
    shell = _LocalShell(tmp_path)
    assert _find_files(shell, directory) is None  # the quoted name does not exist
    _check_disk_space(shell, directory)
    assert not (tmp_path / 'PWNED_BKP').exists()
    assert len(shell.calls) == 3
    assert f'test -d {shlex.quote(directory)}' in shell.calls[1]


def test_find_lists_a_directory_with_quotes_in_its_name(tmp_path):
    directory = tmp_path / "it's"
    directory.mkdir()
    (directory / 'db.sql.gz').write_bytes(b'x' * 10)
    files = _find_files(_LocalShell(tmp_path), str(directory))
    assert [f['name'] for f in files] == ['db.sql.gz']


# ===========================================================================
# MikroTik target_ip
# ===========================================================================

BAD_IPS = ['1.1.1.1"; /system reboot; :put "', '1.1.1.1 ', 'router.local', '1.1.1']


@pytest.mark.parametrize('target_ip', BAD_IPS)
def test_mikrotik_sniffer_rejects_a_non_ip_target(monkeypatch, target_ip):
    monkeypatch.setattr('netaudit_pkg.checks.capture.SSHExecutor', _no_ssh)
    result = check_mikrotik_sniffer(target_ip=target_ip)
    assert result == {'error': 'target_ip must be an IP address'}


@pytest.mark.parametrize('target_ip', ['192.168.88.10', 'fe80::1'])
def test_mikrotik_sniffer_accepts_ipv4_and_ipv6(monkeypatch, target_ip):
    fake = FakeSSHExecutor()
    monkeypatch.setattr('netaudit_pkg.checks.capture.SSHExecutor', lambda *a, **kw: fake)
    check_mikrotik_sniffer(target_ip=target_ip)
    assert fake.calls == [f'/ip firewall connection print terse where src-address~"{target_ip}"']


@pytest.mark.parametrize('target_ip', BAD_IPS)
def test_history_capture_snapshot_rejects_a_non_ip_target(monkeypatch, target_ip):
    from netaudit_pkg import history_capture
    monkeypatch.setattr(history_capture, 'SSHExecutor', _no_ssh)
    settings = {'router': '192.168.88.1', 'user': 'admin', 'password': '', 'port': 22, 'target_ip': target_ip}
    with pytest.raises(RuntimeError, match='target_ip must be an IP address'):
        history_capture._take_snapshot(settings)


def test_history_capture_settings_refuse_a_non_ip_target(isolated_db):
    from fastapi.testclient import TestClient

    from netaudit_pkg import history_capture
    from web.app import app

    with pytest.raises(ValueError, match='target_ip must be an IP address'):
        history_capture.save_settings({'target_ip': BAD_IPS[0]})
    assert history_capture.get_settings()['target_ip'] == ''

    client = TestClient(app)
    resp = client.post('/api/history_capture/settings', json={'target_ip': BAD_IPS[0]})
    assert resp.status_code == 400
    assert history_capture.get_settings()['target_ip'] == ''

    assert client.post('/api/history_capture/settings', json={'target_ip': '192.168.88.10'}).status_code == 200
    assert client.post('/api/history_capture/settings', json={'target_ip': ''}).status_code == 200
    assert history_capture.get_settings()['target_ip'] == ''


# ===========================================================================
# cve_audit: paths read from the target
# ===========================================================================

def test_wordpress_path_from_find_is_not_executed(tmp_path):
    """A web user names a directory under /var/www; `find` hands that name to
    NetAudit, which must not run it as shell code (task 8, E3)."""
    wp_dir = f'{tmp_path}/site$(touch {tmp_path}/PWNED_WP)/wp-includes'
    shell = _LocalShell(tmp_path, finds={'find /var/www': wp_dir + '\n'})
    collect_packages(shell)
    assert not (tmp_path / 'PWNED_WP').exists()
    grep = next(c for c in shell.calls if 'version.php' in c)
    assert f"'{wp_dir}/version.php'" in grep


def test_wordpress_version_is_still_read_from_a_normal_path(tmp_path):
    wp = tmp_path / 'html' / 'wp-includes'
    wp.mkdir(parents=True)
    (wp / 'version.php').write_text("<?php\n$wp_version = '6.5.2';\n")
    shell = _LocalShell(tmp_path, finds={'find /var/www': f'{wp}\n'})
    wordpress = next(p for p in collect_packages(shell) if p['name'] == 'wordpress')
    assert wordpress['version'] == '6.5.2'


def test_composer_lock_path_from_find_is_not_executed(tmp_path):
    lock_path = f'{tmp_path}/app;touch {tmp_path}/PWNED_COMPOSER;/composer.lock'
    shell = _LocalShell(tmp_path, finds={'find /var/www /home': lock_path + '\n'})
    assert collect_composer_packages(shell) == []
    assert not (tmp_path / 'PWNED_COMPOSER').exists()
    assert f"cat '{lock_path}'" in shell.calls[-1]
