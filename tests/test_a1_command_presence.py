"""A1: command presence must distinguish absence from an unknown probe result.

The local-shell test covers the actual Bash/dash exit-code difference; the
collector tests keep an unconfirmed probe from becoming "not installed".
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

from netaudit_pkg.checks.nginx_hardening import audit_nginx_hardening
from netaudit_pkg.checks.ssh_hardening import audit_ssh_hardening_score
from netaudit_pkg.nginx_config import NginxConfig, collect_nginx_config
from netaudit_pkg.nginx_config_v2 import collect_nginx_config_v2
from netaudit_pkg.ssh_config import collect_ssh_config
from netaudit_pkg.ssh_utils import probe_remote_tool


class LocalShellSSH:
    def __init__(self, shell: str):
        self.shell = shell

    def run(self, cmd: str, timeout: int = 20):
        env = dict(os.environ, PATH='/usr/bin:/bin')
        proc = subprocess.run([self.shell, '-c', cmd], capture_output=True, text=True,
                              env=env, timeout=timeout, check=False)
        return proc.stdout, proc.stderr


@pytest.mark.parametrize('shell', ['/bin/sh', '/bin/bash'])
def test_probe_handles_bash_and_dash_absence_codes(shell):
    if not Path(shell).exists():
        pytest.skip(f'{shell} unavailable')
    result = probe_remote_tool(LocalShellSSH(shell), '__netaudit_missing_binary__')
    assert result.status == 'absent'


@pytest.mark.parametrize('shell', ['/bin/sh', '/bin/bash'])
def test_probe_finds_system_directory_outside_user_path(shell, tmp_path):
    if not Path(shell).exists():
        pytest.skip(f'{shell} unavailable')
    tool = tmp_path / 'netaudit-test-binary'
    tool.write_text('#!/bin/sh\nexit 0\n')
    tool.chmod(0o755)
    result = probe_remote_tool(LocalShellSSH(shell), tool.name, extra_dirs=(str(tmp_path),))
    assert result.status == 'present'


class ProbeSSH:
    """One completed or unconfirmed command -v probe; sudo must not run on UNKNOWN."""

    def __init__(self, code: int | None, output: str = ''):
        self.code = code
        self.output = output
        self.calls: list[str] = []

    def run(self, cmd: str, timeout: int = 20):
        self.calls.append(cmd)
        marker = re.search(r'(__NETAUDIT_RC_[0-9a-f]+__)', cmd)
        if marker is None or self.code is None:
            return self.output, ''
        return f'{self.output}\n{marker.group(1)}:{self.code}\n', ''


@pytest.mark.parametrize('code', [1, 127])
def test_nginx_collectors_confirm_absence_from_both_shell_codes(code):
    for collect in (collect_nginx_config, collect_nginx_config_v2):
        ssh = ProbeSSH(code)
        cfg = collect(ssh)
        assert cfg.installed is False
        assert len(ssh.calls) == 1


@pytest.mark.parametrize('collect', [collect_nginx_config, collect_nginx_config_v2, collect_ssh_config])
@pytest.mark.parametrize('code,output', [(None, ''), (2, ''), (0, '')])
def test_unknown_probe_does_not_claim_tool_absent_or_run_sudo(collect, code, output):
    ssh = ProbeSSH(code, output)
    cfg = collect(ssh)
    assert cfg.installed is None
    assert cfg.error
    assert len(ssh.calls) == 1


def test_nginx_hardening_does_not_turn_unknown_probe_into_not_installed(monkeypatch):
    monkeypatch.setattr('netaudit_pkg.checks.nginx_hardening.collect_nginx_config',
                        lambda ssh: NginxConfig(installed=None, error='probe failed'))
    result = audit_nginx_hardening(object())
    assert result.get('installed') is None
    assert 'probe failed' in result['error']


def test_ssh_hardening_does_not_turn_unknown_probe_into_not_installed():
    result = audit_ssh_hardening_score(ProbeSSH(None))
    assert result.get('installed') is None
    assert result['error']
