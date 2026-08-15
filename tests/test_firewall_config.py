"""Tests for netaudit_pkg.firewall_config: read-only firewall evidence
collection (UFW, nftables live+config, iptables) over SSH, with sudo+
exit-code recovery. This module deliberately collects ONLY evidence -
no findings, no ACTIVE/INACTIVE/UNKNOWN verdicts - see firewall_config.py's
own docstring. These tests verify the evidence is correctly classified
into completed/exit_code/stdout, not that any particular firewall state
is "good" or "bad" (that's server_security.py's audit_firewall()'s job,
tested separately).
"""

from __future__ import annotations

from netaudit_pkg.firewall_config import (
    NFTABLES_CONFIG_PATHS,
    FirewallEvidence,
    _cat_file,
    _run_sudo_with_exit_code,
    _tool_is_present,
    collect_firewall_config,
    collect_iptables_live,
    collect_nftables_config,
    collect_nftables_live,
    collect_ufw,
    tool_is_present,
)
from tests.conftest import ExitCodeFakeSSHExecutor

# ===========================================================================
# _tool_is_present / tool_is_present — command -v exit-code convention
# ===========================================================================

def test_tool_is_present_true_on_exit_0_with_path():
    fake = ExitCodeFakeSSHExecutor(
        responses={'command -v ufw': '/usr/sbin/ufw'},
        exit_codes={'command -v ufw': 0},
    )
    result = _tool_is_present(fake, 'ufw')
    assert result.completed is True
    assert result.exit_code == 0
    assert tool_is_present(result) is True


def test_tool_is_present_false_on_exit_127():
    """command -v's own documented convention: exit 127, empty stdout,
    means the tool is genuinely not on PATH - this is valid evidence of
    absence, NOT a collection failure."""
    fake = ExitCodeFakeSSHExecutor(
        responses={'command -v ufw': ''},
        exit_codes={'command -v ufw': 127},
    )
    result = _tool_is_present(fake, 'ufw')
    assert result.completed is True
    assert result.exit_code == 127
    assert tool_is_present(result) is False


def test_tool_is_present_none_on_collection_failure():
    """No completion marker at all (dropped SSH command/timeout) - a
    genuine unknown, must not be read as either present or absent."""
    fake = ExitCodeFakeSSHExecutor()  # no responses/exit_codes registered
    result = _tool_is_present(fake, 'ufw')
    assert result.completed is False
    assert tool_is_present(result) is None


def test_tool_is_present_none_on_unexpected_exit_code():
    """An exit code that's neither 0 nor 127 (command -v isn't documented
    to produce this, but the function must not guess at a meaning for
    it) - treated as unknown, not silently as present or absent."""
    fake = ExitCodeFakeSSHExecutor(
        responses={'command -v ufw': ''},
        exit_codes={'command -v ufw': 2},
    )
    result = _tool_is_present(fake, 'ufw')
    assert result.completed is True
    assert result.exit_code == 2
    assert tool_is_present(result) is None


# ===========================================================================
# collect_ufw — the full minimal set: absent, active, inactive, sudo
# permission failure, unexpected exit, empty successful output,
# command -v collection failure
# ===========================================================================

def test_collect_ufw_not_present():
    """ufw isn't on PATH at all - status is never attempted (no
    unnecessary privileged round trip for a binary that doesn't exist)."""
    fake = ExitCodeFakeSSHExecutor(
        responses={'command -v ufw': ''},
        exit_codes={'command -v ufw': 127},
    )
    presence, status = collect_ufw(fake)
    assert tool_is_present(presence) is False
    assert status is None
    # confirm ufw status was never actually attempted
    assert not any('ufw status' in c for c in fake.calls)


def test_collect_ufw_active():
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v ufw': '/usr/sbin/ufw',
            'ufw status': 'Status: active\n\nTo  Action  From\n--  ------  ----\n22/tcp  ALLOW  Anywhere',
        },
        exit_codes={'command -v ufw': 0, 'ufw status': 0},
    )
    presence, status = collect_ufw(fake)
    assert tool_is_present(presence) is True
    assert status.completed is True
    assert status.exit_code == 0
    assert 'Status: active' in status.stdout


def test_collect_ufw_inactive():
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v ufw': '/usr/sbin/ufw',
            'ufw status': 'Status: inactive',
        },
        exit_codes={'command -v ufw': 0, 'ufw status': 0},
    )
    presence, status = collect_ufw(fake)
    assert tool_is_present(presence) is True
    assert status.completed is True
    assert status.exit_code == 0
    assert 'Status: inactive' in status.stdout


def test_collect_ufw_sudo_permission_failure():
    """ufw is present, but the sudo call itself fails (e.g. sudo
    authentication failure, no NOPASSWD rule and no password configured)
    - ufw status runs to completion and reports a confirmed nonzero exit,
    distinct from a collection failure (completed=True, not False)."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v ufw': '/usr/sbin/ufw',
            'ufw status': 'sudo: a password is required',
        },
        exit_codes={'command -v ufw': 0, 'ufw status': 1},
    )
    presence, status = collect_ufw(fake)
    assert tool_is_present(presence) is True
    assert status.completed is True
    assert status.exit_code == 1


def test_collect_ufw_unexpected_exit_code():
    """ufw present, status command completes with some exit code this
    module doesn't specifically special-case (e.g. 2) - still a
    CONFIRMED result (completed=True), left for the semantic layer to
    decide what an unrecognized-but-confirmed exit code means."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v ufw': '/usr/sbin/ufw',
            'ufw status': '',
        },
        exit_codes={'command -v ufw': 0, 'ufw status': 2},
    )
    _, status = collect_ufw(fake)
    assert status.completed is True
    assert status.exit_code == 2


def test_collect_ufw_empty_successful_output():
    """ufw present, status command exits 0 but with empty/unrecognized
    stdout (not matching 'Status: active' or 'Status: inactive' text) -
    a confirmed success with ambiguous content. This collector doesn't
    interpret the text at all (that's the semantic layer's job) - it
    just reports completed=True, exit_code=0, stdout=''."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v ufw': '/usr/sbin/ufw',
            'ufw status': '',
        },
        exit_codes={'command -v ufw': 0, 'ufw status': 0},
    )
    _, status = collect_ufw(fake)
    assert status.completed is True
    assert status.exit_code == 0
    assert status.stdout == ''


def test_collect_ufw_command_v_collection_failure():
    """The `command -v ufw` step itself fails to complete (dropped SSH
    channel) - presence is UNKNOWN, and status must not be attempted at
    all (collect_ufw() must not assume absence OR presence when the
    presence check itself is inconclusive)."""
    fake = ExitCodeFakeSSHExecutor()  # no responses/exit_codes at all
    presence, status = collect_ufw(fake)
    assert presence.completed is False
    assert tool_is_present(presence) is None
    assert status is None
    assert not any('ufw status' in c for c in fake.calls)


# ===========================================================================
# _run_sudo_with_exit_code — sudo-flavored exit-code recovery
# ===========================================================================

def test_run_sudo_with_exit_code_uses_sh_dash_c_wrapping():
    """The command sent to ssh.sudo() must be `sh -c <quoted script>`,
    NOT a bare `{ cmd; ...; }` shell group - sudo can't parse `{` as an
    argument (it's a shell reserved word, not an executable). This is a
    regression test for the exact bug found while designing this
    function: naively reusing ssh_utils.run_command_with_exit_code()'s
    wrapping style against ssh.sudo() would silently break."""
    fake = ExitCodeFakeSSHExecutor(
        responses={'nft list ruleset': 'table inet filter { }'},
        exit_codes={'nft list ruleset': 0},
    )
    _run_sudo_with_exit_code(fake, 'nft list ruleset')
    assert len(fake.calls) == 1
    sent = fake.calls[0]
    assert sent.startswith('sh -c ')
    assert not sent.lstrip().startswith('{')


def test_run_sudo_with_exit_code_success():
    fake = ExitCodeFakeSSHExecutor(
        responses={'iptables -S': '-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT'},
        exit_codes={'iptables -S': 0},
    )
    result = _run_sudo_with_exit_code(fake, 'iptables -S')
    assert result.completed is True
    assert result.exit_code == 0
    assert '-P INPUT DROP' in result.stdout


def test_run_sudo_with_exit_code_collection_failure():
    fake = ExitCodeFakeSSHExecutor()  # nothing registered
    result = _run_sudo_with_exit_code(fake, 'iptables -S')
    assert result.completed is False
    assert result.exit_code is None


# ===========================================================================
# collect_nftables_live / collect_iptables_live
# ===========================================================================

def test_collect_nftables_live_success_with_rules():
    fake = ExitCodeFakeSSHExecutor(
        responses={'nft list ruleset': 'table inet filter {\n  chain input {\n  }\n}'},
        exit_codes={'nft list ruleset': 0},
    )
    result = collect_nftables_live(fake)
    assert result.completed is True
    assert result.exit_code == 0
    assert 'table inet filter' in result.stdout


def test_collect_nftables_live_success_empty_ruleset():
    """A legitimate empty ruleset (zero tables configured) - exit 0,
    empty stdout. Must NOT be confused with a permission-denied failure,
    which also produces empty stdout but a nonzero (or unconfirmed) exit."""
    fake = ExitCodeFakeSSHExecutor(
        responses={'nft list ruleset': ''},
        exit_codes={'nft list ruleset': 0},
    )
    result = collect_nftables_live(fake)
    assert result.completed is True
    assert result.exit_code == 0
    assert result.stdout == ''


def test_collect_nftables_live_permission_denied():
    fake = ExitCodeFakeSSHExecutor(
        responses={'nft list ruleset': ''},
        exit_codes={'nft list ruleset': 1},
    )
    result = collect_nftables_live(fake)
    assert result.completed is True
    assert result.exit_code == 1


def test_collect_iptables_live_success():
    fake = ExitCodeFakeSSHExecutor(
        responses={'iptables -S': '-P INPUT ACCEPT\n-P FORWARD DROP\n-P OUTPUT ACCEPT'},
        exit_codes={'iptables -S': 0},
    )
    result = collect_iptables_live(fake)
    assert result.completed is True
    assert '-P INPUT ACCEPT' in result.stdout


# ===========================================================================
# collect_nftables_config — file evidence, no sudo, path fallthrough
# ===========================================================================

def test_collect_nftables_config_reads_first_path():
    fake = ExitCodeFakeSSHExecutor(
        responses={
            f'cat {NFTABLES_CONFIG_PATHS[0]}': 'table inet filter { }',
        },
        exit_codes={f'cat {NFTABLES_CONFIG_PATHS[0]}': 0},
    )
    result = collect_nftables_config(fake)
    assert result.completed is True
    assert result.path == NFTABLES_CONFIG_PATHS[0]
    assert 'table inet filter' in result.content


def test_collect_nftables_config_falls_through_to_second_path():
    """First path is empty/absent, second path has real content - the
    collector must try the next candidate rather than stopping at the
    first empty result."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            f'cat {NFTABLES_CONFIG_PATHS[0]}': '',
            f'cat {NFTABLES_CONFIG_PATHS[1]}': 'table inet filter { }',
        },
        exit_codes={
            f'cat {NFTABLES_CONFIG_PATHS[0]}': 1,  # file doesn't exist
            f'cat {NFTABLES_CONFIG_PATHS[1]}': 0,
        },
    )
    result = collect_nftables_config(fake)
    assert result.path == NFTABLES_CONFIG_PATHS[1]
    assert 'table inet filter' in result.content


def test_collect_nftables_config_no_path_readable_returns_last_attempt():
    """None of the three candidate paths yields a non-empty confirmed
    read - the LAST attempted path's FileResult is returned (a real
    command/exit_code combination the caller can reason about, not a
    synthetic placeholder)."""
    fake = ExitCodeFakeSSHExecutor(
        responses={p: '' for p_prefix in ('cat ',) for p in
                   [f'{p_prefix}{path}' for path in NFTABLES_CONFIG_PATHS]},
        exit_codes={f'cat {path}': 1 for path in NFTABLES_CONFIG_PATHS},
    )
    result = collect_nftables_config(fake)
    assert result.path == NFTABLES_CONFIG_PATHS[-1]
    assert result.completed is True
    assert result.exit_code == 1


def test_collect_nftables_config_permission_denied_moves_to_next_path():
    """First path exists but is unreadable (permission denied, confirmed
    nonzero exit) - collector tries the next path rather than treating
    the permission error as proof no config exists anywhere."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            f'cat {NFTABLES_CONFIG_PATHS[0]}': '',
            f'cat {NFTABLES_CONFIG_PATHS[1]}': 'table inet filter { }',
        },
        exit_codes={
            f'cat {NFTABLES_CONFIG_PATHS[0]}': 1,
            f'cat {NFTABLES_CONFIG_PATHS[1]}': 0,
        },
    )
    result = collect_nftables_config(fake)
    assert result.path == NFTABLES_CONFIG_PATHS[1]


def test_collect_nftables_config_collection_failure_on_all_paths():
    """None of the paths' reads even completes (dropped SSH channel) -
    the last attempt's FileResult correctly reports completed=False."""
    fake = ExitCodeFakeSSHExecutor()  # nothing registered at all
    result = collect_nftables_config(fake)
    assert result.completed is False
    assert result.path == NFTABLES_CONFIG_PATHS[-1]


def test_cat_file_does_not_use_sudo():
    """Config file reads must go through plain ssh.run(), never
    ssh.sudo() - see firewall_config.py's docstring for why (a config
    file's own filesystem permissions are the meaningful signal, not
    forced root access for symmetry with the other collectors)."""

    class _SudoTrackingFake(ExitCodeFakeSSHExecutor):
        def __init__(self):
            super().__init__(
                responses={'cat /etc/nftables.conf': 'content'},
                exit_codes={'cat /etc/nftables.conf': 0},
            )
            self.sudo_called = False

        def sudo(self, cmd, timeout=20):
            self.sudo_called = True
            return super().sudo(cmd, timeout=timeout)

    fake = _SudoTrackingFake()
    _cat_file(fake, '/etc/nftables.conf')
    assert fake.sudo_called is False


# ===========================================================================
# collect_firewall_config — full evidence collection in one call
# ===========================================================================

def test_collect_firewall_config_returns_all_fields():
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v ufw': '',
            'ufw status': '',
            'nft list ruleset': 'table inet filter { }',
            f'cat {NFTABLES_CONFIG_PATHS[0]}': '',
            'iptables -S': '-P INPUT ACCEPT',
        },
        exit_codes={
            'command -v ufw': 127,
            'nft list ruleset': 0,
            f'cat {NFTABLES_CONFIG_PATHS[0]}': 1,
            'iptables -S': 0,
        },
    )
    evidence = collect_firewall_config(fake)
    assert isinstance(evidence, FirewallEvidence)
    assert tool_is_present(evidence.ufw_present) is False
    assert evidence.ufw_status is None
    assert evidence.nftables_live.exit_code == 0
    assert evidence.iptables_live.exit_code == 0
