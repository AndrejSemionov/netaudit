"""F8 (docs/research/tool_presence_sbin.md): SSHExecutor's tool presence uses
the A1 probe (system directories in front of PATH, exit marker), and an
unknown result is never "not installed" and never triggers an install."""

from __future__ import annotations

import re

import pytest

from netaudit_pkg.ssh import SSHExecutor
from netaudit_pkg.ssh_utils import ToolProbe
from tests.conftest import FakeSSHExecutor

_MARKER = re.compile(r"'(__NETAUDIT_RC_[0-9a-f]+__)'")


def _executor(probe_out: str, probe_code):
    """A real SSHExecutor (never connected) whose run() answers the probe."""
    ssh = SSHExecutor('203.0.113.5', 'audit')
    ssh.calls = []

    def run(cmd, timeout=20, stdin_data=None):
        ssh.calls.append(cmd)
        if 'command -v' in cmd:
            marker = _MARKER.search(cmd)
            if probe_code is None or not marker:
                return probe_out, ''
            return f'{probe_out}\n{marker.group(1)}:{probe_code}\n', ''
        return '', ''

    ssh.run = run
    ssh.sudo = lambda cmd, timeout=20: (ssh.calls.append(f'sudo {cmd}') or ('', ''))
    return ssh


def test_tool_presence_looks_in_system_directories():
    ssh = _executor('/usr/sbin/lynis', 0)
    assert ssh.tool_presence('lynis').status == 'present'
    assert ssh.is_tool_installed('lynis') is True
    assert "PATH='/usr/sbin:/sbin'" in ssh.calls[0]


def test_confirmed_absence_is_absent():
    ssh = _executor('', 1)
    assert ssh.tool_presence('lynis').status == 'absent'
    assert ssh.is_tool_installed('lynis') is False


def test_unknown_probe_is_unknown_and_not_installed_is_false():
    ssh = _executor('', None)  # no completion marker
    probe = ssh.tool_presence('lynis')
    assert probe.status == 'unknown'
    assert ssh.is_tool_installed('lynis') is False


def test_ensure_tool_installed_never_installs_on_an_unknown_probe():
    ssh = _executor('', None)
    installed, error = ssh.ensure_tool_installed('lynis')
    assert installed is False
    assert 'could not determine whether lynis is installed' in error
    assert not any('apt-get' in c for c in ssh.calls)


def _unknown(fake):
    fake.tool_presence = lambda tool: ToolProbe('unknown', f'{tool} presence check did not complete')
    return fake


@pytest.mark.parametrize('module,func,tool,kwargs', [
    ('lynis_audit', 'check_lynis_audit', 'lynis', {}),
    ('aide_check', 'check_aide', 'aide', {'mode': 'check'}),
    ('docker_audit', 'check_docker_audit', 'docker', {}),
])
def test_callers_report_an_unknown_probe_instead_of_not_installed(monkeypatch, module, func, tool, kwargs):
    import importlib
    mod = importlib.import_module(f'netaudit_pkg.checks.{module}')
    fake = _unknown(FakeSSHExecutor())
    monkeypatch.setattr(mod, 'SSHExecutor', lambda *a, **kw: fake)
    result = getattr(mod, func)(host='203.0.113.5', auto_install=True, **kwargs) if module != 'docker_audit' \
        else getattr(mod, func)(host='203.0.113.5', **kwargs)
    assert f'could not determine whether {tool} is installed' in result['error']
    assert 'not installed' not in result['error']
    assert tool not in fake.installed_tools  # no install attempted


def test_rootkit_reports_an_unknown_probe_per_tool(monkeypatch):
    from netaudit_pkg.checks import rootkit_check
    fake = _unknown(FakeSSHExecutor())
    monkeypatch.setattr(rootkit_check, 'SSHExecutor', lambda *a, **kw: fake)
    result = rootkit_check.check_rootkit(host='203.0.113.5', auto_install=True)
    assert 'could not determine whether rkhunter is installed' in result['detail']
    assert 'could not determine whether chkrootkit is installed' in result['detail']
    assert 'is not installed' not in result['detail']
    assert not fake.installed_tools
