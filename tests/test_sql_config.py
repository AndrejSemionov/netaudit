"""Tests for netaudit_pkg.sql_config: read-only MySQL/MariaDB evidence
collection (binary presence x2, listening sockets, bind-address config)
over SSH, with exit-code recovery via the shared ssh_utils helper. This
module deliberately collects ONLY evidence - no findings, no PRESENT/
LOCAL/EXTERNAL verdicts - see sql_config.py's own docstring. These tests
verify the evidence is correctly captured into completed/exit_code/
stdout, not that any particular MySQL configuration is "good" or "bad"
(that's server_security.py's audit_sql()'s job, tested separately).
"""

from __future__ import annotations

from netaudit_pkg.sql_config import (
    MYSQL_CONFIG_DIR,
    SQLEvidence,
    collect_bind_address_config,
    collect_listener,
    collect_mariadb_present,
    collect_mysql_present,
    collect_sql_config,
)
from tests.conftest import ExitCodeFakeSSHExecutor

# ===========================================================================
# collect_mysql_present / collect_mariadb_present
# ===========================================================================

def test_collect_mysql_present_found():
    fake = ExitCodeFakeSSHExecutor(
        responses={'command -v mysql': '/usr/bin/mysql'},
        exit_codes={'command -v mysql': 0},
    )
    result = collect_mysql_present(fake)
    assert result.completed is True
    assert result.exit_code == 0
    assert '/usr/bin/mysql' in result.stdout


def test_collect_mysql_present_confirmed_absent():
    """command -v's documented convention: exit 127, empty stdout, means
    genuinely not on PATH - a confirmed fact, not a collection failure."""
    fake = ExitCodeFakeSSHExecutor(
        responses={'command -v mysql': ''},
        exit_codes={'command -v mysql': 127},
    )
    result = collect_mysql_present(fake)
    assert result.completed is True
    assert result.exit_code == 127


def test_collect_mysql_present_collection_failure():
    """No completion marker at all (dropped SSH command/timeout) - must
    not be silently read as either present or absent."""
    fake = ExitCodeFakeSSHExecutor()  # nothing registered
    result = collect_mysql_present(fake)
    assert result.completed is False
    assert result.exit_code is None


def test_collect_mysql_present_other_nonzero_exit_not_classified():
    """An exit code that's neither 0 nor 127 (e.g. 2 - some other shell
    or command -v failure mode) must still be returned as a confirmed
    completed=True result with that exact exit code - the collector must
    NOT collapse it into NOT_PRESENT (that's 127's meaning specifically)
    or into any other classification. Interpreting exit=2 is entirely
    the semantic layer's job."""
    fake = ExitCodeFakeSSHExecutor(
        responses={'command -v mysql': ''},
        exit_codes={'command -v mysql': 2},
    )
    result = collect_mysql_present(fake)
    assert result.completed is True
    assert result.exit_code == 2


def test_collect_mariadb_present_other_nonzero_exit_not_classified():
    """Same as test_collect_mysql_present_other_nonzero_exit_not_classified
    but for mariadb - both presence checks must independently preserve an
    unrecognized nonzero exit code without classifying it."""
    fake = ExitCodeFakeSSHExecutor(
        responses={'command -v mariadb': ''},
        exit_codes={'command -v mariadb': 2},
    )
    result = collect_mariadb_present(fake)
    assert result.completed is True
    assert result.exit_code == 2


def test_collect_mariadb_present_found():
    fake = ExitCodeFakeSSHExecutor(
        responses={'command -v mariadb': '/usr/bin/mariadb'},
        exit_codes={'command -v mariadb': 0},
    )
    result = collect_mariadb_present(fake)
    assert result.completed is True
    assert result.exit_code == 0


def test_collect_mysql_and_mariadb_are_independent_checks():
    """mysql present, mariadb absent (or vice versa) must be captured as
    two distinct facts, not blurred into "some SQL binary exists" -
    regression test for the original which-mysql-mariadb combined check."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v mysql': '',
            'command -v mariadb': '/usr/sbin/mariadb',
        },
        exit_codes={
            'command -v mysql': 127,
            'command -v mariadb': 0,
        },
    )
    mysql_result = collect_mysql_present(fake)
    mariadb_result = collect_mariadb_present(fake)
    assert mysql_result.exit_code == 127
    assert mariadb_result.exit_code == 0


# ===========================================================================
# collect_listener
# ===========================================================================

def test_collect_listener_raw_output_no_remote_filtering():
    """The collector must return ALL listening sockets raw - no remote
    grep, no port-specific filtering. Regression test for the original
    `ss -tlnp | grep :3306` design, whose exit-code collision this
    collector exists to eliminate."""
    raw_ss_output = (
        'tcp   LISTEN 0      60             127.0.0.1:3306      0.0.0.0:*\n'
        'tcp   LISTEN 0      511              0.0.0.0:80        0.0.0.0:*\n'
        'tcp   LISTEN 0      511                 [::]:443          [::]:*\n'
    )
    fake = ExitCodeFakeSSHExecutor(
        responses={'ss -tlnp': raw_ss_output},
        exit_codes={'ss -tlnp': 0},
    )
    result = collect_listener(fake)
    assert result.completed is True
    assert result.exit_code == 0
    # every line must be present, unfiltered - not just the 3306 one
    assert '127.0.0.1:3306' in result.stdout
    assert ':80' in result.stdout
    assert ':443' in result.stdout


def test_collect_listener_success_empty_output():
    """A legitimate empty listener table (nothing listening at all) -
    exit 0, empty stdout. Must not be confused with a collection
    failure, which also produces empty stdout but a nonzero/unconfirmed
    exit."""
    fake = ExitCodeFakeSSHExecutor(
        responses={'ss -tlnp': ''},
        exit_codes={'ss -tlnp': 0},
    )
    result = collect_listener(fake)
    assert result.completed is True
    assert result.exit_code == 0
    assert result.stdout == ''


def test_collect_listener_confirmed_failure():
    fake = ExitCodeFakeSSHExecutor(
        responses={'ss -tlnp': ''},
        exit_codes={'ss -tlnp': 1},
    )
    result = collect_listener(fake)
    assert result.completed is True
    assert result.exit_code == 1


def test_collect_listener_collection_failure():
    fake = ExitCodeFakeSSHExecutor()  # nothing registered
    result = collect_listener(fake)
    assert result.completed is False
    assert result.exit_code is None


def test_collect_listener_does_not_use_sudo():
    """This collector does not assume `ss -tlnp` requires root - it must
    go through plain ssh.run(), never ssh.sudo() (see sql_config.py's
    docstring: privilege requirements are not presumed, only confirmed
    via exit code if they turn out to matter)."""

    class _SudoTrackingFake(ExitCodeFakeSSHExecutor):
        def __init__(self):
            super().__init__(responses={'ss -tlnp': 'x'}, exit_codes={'ss -tlnp': 0})
            self.sudo_called = False

        def sudo(self, cmd, timeout=20):
            self.sudo_called = True
            return super().sudo(cmd, timeout=timeout)

    fake = _SudoTrackingFake()
    collect_listener(fake)
    assert fake.sudo_called is False


# ===========================================================================
# collect_bind_address_config
# ===========================================================================

def test_collect_bind_address_config_finds_directive():
    fake = ExitCodeFakeSSHExecutor(
        responses={f"grep -rh '^\\s*bind-address' {MYSQL_CONFIG_DIR}": 'bind-address = 0.0.0.0'},
        exit_codes={f"grep -rh '^\\s*bind-address' {MYSQL_CONFIG_DIR}": 0},
    )
    result = collect_bind_address_config(fake)
    assert result.completed is True
    assert result.exit_code == 0
    assert '0.0.0.0' in result.stdout


def test_collect_bind_address_config_no_match_confirmed():
    """grep runs to completion and finds nothing - exit 1 (grep's own
    "no match" convention), a CONFIRMED absence, not a collection
    failure."""
    fake = ExitCodeFakeSSHExecutor(
        responses={f"grep -rh '^\\s*bind-address' {MYSQL_CONFIG_DIR}": ''},
        exit_codes={f"grep -rh '^\\s*bind-address' {MYSQL_CONFIG_DIR}": 1},
    )
    result = collect_bind_address_config(fake)
    assert result.completed is True
    assert result.exit_code == 1


def test_collect_bind_address_config_includes_commented_lines():
    """The collector returns matching lines raw, INCLUDING commented-out
    ones - filtering '#bind-address' out is semantic-layer work, not
    this collector's. Regression-relevant: the original code's comment
    about avoiding a false HIGH on commented template lines must be
    preserved at the semantic layer, not lost by having the collector
    filter it out silently."""
    fake = ExitCodeFakeSSHExecutor(
        responses={f"grep -rh '^\\s*bind-address' {MYSQL_CONFIG_DIR}":
                   '#bind-address = 0.0.0.0\nbind-address = 127.0.0.1'},
        exit_codes={f"grep -rh '^\\s*bind-address' {MYSQL_CONFIG_DIR}": 0},
    )
    result = collect_bind_address_config(fake)
    assert '#bind-address' in result.stdout
    assert 'bind-address = 127.0.0.1' in result.stdout


def test_collect_bind_address_config_collection_failure():
    fake = ExitCodeFakeSSHExecutor()  # nothing registered
    result = collect_bind_address_config(fake)
    assert result.completed is False
    assert result.exit_code is None


def test_collect_bind_address_config_does_not_use_sudo():
    """Config file reads must go through plain ssh.run(), never
    ssh.sudo() - same reasoning as firewall_config.py's nftables config
    read (a config file's own filesystem permissions are the meaningful
    signal, not forced root for symmetry)."""

    class _SudoTrackingFake(ExitCodeFakeSSHExecutor):
        def __init__(self):
            super().__init__(
                responses={f"grep -rh '^\\s*bind-address' {MYSQL_CONFIG_DIR}": ''},
                exit_codes={f"grep -rh '^\\s*bind-address' {MYSQL_CONFIG_DIR}": 1},
            )
            self.sudo_called = False

        def sudo(self, cmd, timeout=20):
            self.sudo_called = True
            return super().sudo(cmd, timeout=timeout)

    fake = _SudoTrackingFake()
    collect_bind_address_config(fake)
    assert fake.sudo_called is False


# ===========================================================================
# collect_sql_config — full evidence collection in one call
# ===========================================================================

def test_collect_sql_config_returns_all_fields():
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v mysql': '/usr/bin/mysql',
            'command -v mariadb': '',
            'ss -tlnp': 'tcp LISTEN 0 60 127.0.0.1:3306 0.0.0.0:*',
            f"grep -rh '^\\s*bind-address' {MYSQL_CONFIG_DIR}": 'bind-address = 127.0.0.1',
        },
        exit_codes={
            'command -v mysql': 0,
            'command -v mariadb': 127,
            'ss -tlnp': 0,
            f"grep -rh '^\\s*bind-address' {MYSQL_CONFIG_DIR}": 0,
        },
    )
    evidence = collect_sql_config(fake)
    assert isinstance(evidence, SQLEvidence)
    assert evidence.mysql_present.exit_code == 0
    assert evidence.mariadb_present.exit_code == 127
    assert '3306' in evidence.listener.stdout
    assert '127.0.0.1' in evidence.bind_address_config.stdout


def test_collect_sql_config_total_collection_failure_still_returns_shape():
    """Every source failing to collect must still produce a valid
    SQLEvidence with completed=False fields - not raise, not return a
    partial/malformed structure."""
    fake = ExitCodeFakeSSHExecutor()  # nothing registered at all
    evidence = collect_sql_config(fake)
    assert evidence.mysql_present.completed is False
    assert evidence.mariadb_present.completed is False
    assert evidence.listener.completed is False
    assert evidence.bind_address_config.completed is False
