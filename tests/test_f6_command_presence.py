"""F6: Bash and dash absence agree; malformed command output stays unknown."""

from __future__ import annotations

import pytest
import re

from netaudit_pkg.checks.server_security import _sql_binary_verdict
from netaudit_pkg.fail2ban_config import CommandResult as Fail2banResult
from netaudit_pkg.fail2ban_config import _binary_check, binary_verdict, collect_fail2ban_config
from netaudit_pkg.firewall_config import CommandResult as FirewallResult
from netaudit_pkg.firewall_config import _tool_is_present, collect_ufw, tool_is_present
from netaudit_pkg.sql_config import CommandResult as SQLResult
from netaudit_pkg.sql_config import collect_mariadb_present, collect_mysql_present
from tests.conftest import ExitCodeFakeSSHExecutor


@pytest.mark.parametrize('collect,tool', [
    (lambda ssh: _tool_is_present(ssh, 'ufw'), 'ufw'),
    (_binary_check, 'fail2ban-client'),
    (collect_mysql_present, 'mysql'),
    (collect_mariadb_present, 'mariadb'),
])
def test_system_sbin_binary_is_found_outside_nonroot_path(collect, tool):
    """Debian's non-root SSH PATH may exclude /usr/sbin and /sbin."""
    class SbinOnlySSH:
        def __init__(self):
            self.calls = []

        def run(self, cmd, timeout=20):
            self.calls.append(cmd)
            marker = re.search(r'(__NETAUDIT_RC_[0-9a-f]+__)', cmd)
            assert marker is not None
            found = 'PATH=/usr/sbin:/sbin:"$PATH"' in cmd
            output = f'/usr/sbin/{tool}' if found else ''
            code = 0 if found else 1
            return f'{output}\n{marker.group(1)}:{code}\n', ''

    ssh = SbinOnlySSH()
    result = collect(ssh)
    assert result.exit_code == 0
    assert result.stdout.strip() == f'/usr/sbin/{tool}'
    assert len(ssh.calls) == 1


@pytest.mark.parametrize('exit_code', [1, 127])
def test_absence_requires_empty_output_and_accepts_bash_and_dash(exit_code):
    assert tool_is_present(FirewallResult(True, exit_code, '', 'command -v ufw')) is False
    assert binary_verdict(Fail2banResult(True, exit_code, '', 'command -v fail2ban-client')) == 'NOT_PRESENT'
    assert _sql_binary_verdict(SQLResult(True, exit_code, '', 'command -v mysql')) == 'NOT_FOUND'


@pytest.mark.parametrize('exit_code,output', [(1, 'permission denied'),
                                                   (127, 'shell startup error'),
                                                   (0, '')])
def test_malformed_probe_cannot_be_called_present_or_absent(exit_code, output):
    assert tool_is_present(FirewallResult(True, exit_code, output, 'command -v ufw')) is None
    assert binary_verdict(Fail2banResult(True, exit_code, output, 'command -v fail2ban-client')) == 'UNKNOWN'
    assert _sql_binary_verdict(SQLResult(True, exit_code, output, 'command -v mysql')) == 'UNKNOWN'


def test_bash_absent_ufw_skips_privileged_status_call():
    fake = ExitCodeFakeSSHExecutor(
        responses={'command -v ufw': ''}, exit_codes={'command -v ufw': 1},
    )
    presence, status = collect_ufw(fake)
    assert tool_is_present(presence) is False
    assert status is None
    assert not any('ufw status' in cmd for cmd in fake.calls)


def test_bash_absent_fail2ban_skips_privileged_status_call():
    fake = ExitCodeFakeSSHExecutor(
        responses={'command -v fail2ban-client': ''},
        exit_codes={'command -v fail2ban-client': 1},
    )
    evidence = collect_fail2ban_config(fake)
    assert binary_verdict(evidence.binary_check) == 'NOT_PRESENT'
    assert evidence.status_sudo is None
    assert not any('sudo' in cmd and 'fail2ban-client status' in cmd for cmd in fake.calls)
