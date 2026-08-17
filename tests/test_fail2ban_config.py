"""Tests for netaudit_pkg.fail2ban_config: read-only fail2ban evidence
collection (binary presence, unprivileged status, sudo status, per-jail
sudo status) over SSH, with sudo+exit-code recovery. This module
deliberately collects ONLY evidence - no findings, no PRESENT/
ACCESS_DENIED/CONFIRMED_NO_JAILS verdicts - see fail2ban_config.py's own
docstring. These tests verify the evidence is correctly classified into
completed/exit_code/stdout and correctly split per jail, not that any
particular fail2ban state is "good" or "bad" (that's server_security.py's
audit_fail2ban()'s job, tested separately).

Session-note anchors covered here (see fail2ban_config.py's own
docstring for full background):
  FB-1: which/command -v collection failure vs confirmed NOT_PRESENT
  FB-2: exit_code==0 is NOT sufficient evidence of a successful
        `fail2ban-client status` - the empirically-confirmed
        46.62.147.41 case (exit 0 + "ERROR ... you must be root" in
        stdout) is reproduced directly below.
  FB-3: sudo is always attempted; unpriv is retained as evidence only
  FB-4/FB-5: per-jail evidence is independent per jail, sudo-first,
        partial collection must be visible (not silently zeroed)
  FB-6: jail-list parse failure vs confirmed-empty jail list
"""

from __future__ import annotations

import shlex

from netaudit_pkg.fail2ban_config import (
    Fail2banCommands,
    _binary_check,
    _parse_jail_list,
    _run_sudo_with_exit_code,
    binary_verdict,
    collect_fail2ban_config,
)
from tests.conftest import ExitCodeFakeSSHExecutor

# ===========================================================================
# Fail2banCommands - command grammar provider (pure, no I/O)
# ===========================================================================
#
# Locks in the empirically-confirmed 46.62.147.41 wrapper grammar (see
# project session notes): fail2ban-status-only takes NO leading "status"
# argument - the wrapper script hardcodes it - so a jail_status() call
# must produce '<wrapper> <jail>', never '<wrapper> status <jail>'
# (confirmed on the real host to fail with exit 255, "Sorry but the jail
# 'status' does not exist").

def test_client_mode_status():
    assert Fail2banCommands(mode='client').status() == 'fail2ban-client status'


def test_client_mode_jail_status():
    cmds = Fail2banCommands(mode='client')
    assert cmds.jail_status('sshd') == 'fail2ban-client status sshd'


def test_wrapper_mode_status_has_no_leading_status_argument():
    """The central empirically-confirmed grammar fact: the wrapper's
    top-level status call is the bare wrapper path, with no 'status'
    argument - fail2ban-status-only already hardcodes it internally."""
    cmds = Fail2banCommands(mode='status-wrapper')
    assert cmds.status() == '/usr/local/bin/fail2ban-status-only'


def test_wrapper_mode_jail_status_has_no_leading_status_argument():
    """Same grammar fact for the per-jail call - '<wrapper> <jail>', NOT
    '<wrapper> status <jail>' (which was confirmed on the real host to
    produce exit 255 - the wrapper would treat 'status' itself as an
    invalid jail name)."""
    cmds = Fail2banCommands(mode='status-wrapper')
    assert cmds.jail_status('sshd') == '/usr/local/bin/fail2ban-status-only sshd'


def test_wrapper_mode_custom_path():
    cmds = Fail2banCommands(mode='status-wrapper', wrapper_path='/opt/custom/f2b-status')
    assert cmds.status() == '/opt/custom/f2b-status'
    assert cmds.jail_status('nginx-auth') == '/opt/custom/f2b-status nginx-auth'


def test_jail_name_with_shell_metacharacters_is_quoted():
    """jail_status() must never build an unquoted, shell-injectable
    command string - both modes."""
    client_cmds = Fail2banCommands(mode='client')
    wrapper_cmds = Fail2banCommands(mode='status-wrapper')
    dangerous_name = 'sshd; rm -rf /'
    assert 'fail2ban-client status ' in client_cmds.jail_status(dangerous_name)
    assert shlex.quote(dangerous_name) in client_cmds.jail_status(dangerous_name)
    assert shlex.quote(dangerous_name) in wrapper_cmds.jail_status(dangerous_name)


def test_unknown_mode_raises_explicit_error_no_fallback():
    """An unrecognized mode must fail loudly and immediately, not
    silently fall back to a default or guess - see this module's
    Fail2banCommands docstring on why no auto-fallback between modes is
    ever attempted anywhere in this design."""
    import pytest
    with pytest.raises(ValueError, match='unknown fail2ban command mode'):
        Fail2banCommands(mode='not-a-real-mode')


def test_default_mode_is_client_preserving_prior_behavior():
    """Backward compatibility requirement for this cycle: the default
    mode must produce EXACTLY the command strings this module already
    used before Fail2banCommands existed - 'fail2ban-client status' and
    'fail2ban-client status <jail>' - so every existing caller that
    doesn't know about modes yet keeps working identically."""
    cmds = Fail2banCommands()
    assert cmds.mode == 'client'
    assert cmds.status() == 'fail2ban-client status'
    assert cmds.jail_status('sshd') == 'fail2ban-client status sshd'


def test_for_mode_classmethod_equivalent_to_constructor():
    assert Fail2banCommands.for_mode('client').status() == Fail2banCommands(mode='client').status()
    assert (Fail2banCommands.for_mode('status-wrapper').status()
            == Fail2banCommands(mode='status-wrapper').status())

# ===========================================================================
# _binary_check / binary_verdict — command -v exit-code convention
# ===========================================================================

def test_binary_verdict_present_on_exit_0():
    fake = ExitCodeFakeSSHExecutor(
        responses={'command -v fail2ban-client': '/usr/bin/fail2ban-client'},
        exit_codes={'command -v fail2ban-client': 0},
    )
    result = _binary_check(fake)
    assert result.completed is True
    assert result.exit_code == 0
    assert binary_verdict(result) == 'PRESENT'


def test_binary_verdict_not_present_on_exit_127():
    """command -v's own documented convention: exit 127, empty stdout,
    means the binary is genuinely not on PATH - valid evidence of
    absence, NOT a collection failure. Reproduces the real
    192.168.88.20 case ('Command not found')."""
    fake = ExitCodeFakeSSHExecutor(
        responses={'command -v fail2ban-client': ''},
        exit_codes={'command -v fail2ban-client': 127},
    )
    result = _binary_check(fake)
    assert result.completed is True
    assert result.exit_code == 127
    assert binary_verdict(result) == 'NOT_PRESENT'


def test_binary_verdict_unknown_on_other_nonzero_exit():
    """A confirmed exit code that is neither 0 nor 127 must NOT be read
    as NOT_PRESENT - 127 is the only documented 'not found' convention.
    This is the FB-1 correction: '127 != any nonzero'."""
    for code in (1, 2, 126):
        fake = ExitCodeFakeSSHExecutor(
            responses={'command -v fail2ban-client': 'some unexpected output'},
            exit_codes={'command -v fail2ban-client': code},
        )
        result = _binary_check(fake)
        assert result.completed is True
        assert result.exit_code == code
        assert binary_verdict(result) == 'UNKNOWN', f'exit_code={code} must be UNKNOWN, not NOT_PRESENT'


def test_binary_verdict_unknown_on_collection_failure():
    """No completion marker at all (dropped SSH command/timeout) - a
    genuine unknown, must not be read as either PRESENT or NOT_PRESENT."""
    fake = ExitCodeFakeSSHExecutor()  # no responses/exit_codes registered
    result = _binary_check(fake)
    assert result.completed is False
    assert result.exit_code is None
    assert binary_verdict(result) == 'UNKNOWN'


# ===========================================================================
# _parse_jail_list — pure parser, no I/O
# ===========================================================================

def test_parse_jail_list_multiple_jails():
    stdout = (
        'Status\n'
        '|- Number of jail:\t6\n'
        '`- Jail list:\tnginx-botsearch, nginx-http-auth, nginx-limit-req, '
        'recidive, sshd, sshd-ddos'
    )
    jails = _parse_jail_list(stdout)
    assert jails == ['nginx-botsearch', 'nginx-http-auth', 'nginx-limit-req',
                      'recidive', 'sshd', 'sshd-ddos']


def test_parse_jail_list_single_jail():
    stdout = 'Status\n|- Number of jail:\t1\n`- Jail list:\tsshd'
    assert _parse_jail_list(stdout) == ['sshd']


def test_parse_jail_list_confirmed_empty():
    """A 'Jail list:' line that parses successfully but lists nothing -
    this IS a confirmed-empty result, distinct from a parse failure."""
    stdout = 'Status\n|- Number of jail:\t0\n`- Jail list:\t'
    assert _parse_jail_list(stdout) == []


def test_parse_jail_list_parse_failure_returns_none():
    """No 'Jail list:' line at all (e.g. an error message, or an
    unrecognized fail2ban-client output format) - None, NOT an empty
    list. Callers must not collapse this into 'confirmed zero jails'.
    Reproduces the 46.62.147.41 unpriv-denied shape as an example of
    text that must NOT parse as an empty jail list."""
    stdout = ('2026-08-16 18:34:19,309 fail2ban                [345062]: '
              'ERROR   Permission denied to socket: /var/run/fail2ban/fail2ban.sock, '
              '(you must be root)')
    assert _parse_jail_list(stdout) is None


# ===========================================================================
# _run_sudo_with_exit_code
# ===========================================================================

def test_run_sudo_with_exit_code_success():
    fake = ExitCodeFakeSSHExecutor(
        responses={'fail2ban-client status': 'Status\n|- Number of jail:\t1'},
        exit_codes={'fail2ban-client status': 0},
    )
    result = _run_sudo_with_exit_code(fake, 'fail2ban-client status')
    assert result.completed is True
    assert result.exit_code == 0
    assert 'Number of jail' in result.stdout


def test_run_sudo_with_exit_code_collection_failure():
    fake = ExitCodeFakeSSHExecutor()  # no marker ever appears
    result = _run_sudo_with_exit_code(fake, 'fail2ban-client status')
    assert result.completed is False
    assert result.exit_code is None


# ===========================================================================
# collect_fail2ban_config — end-to-end evidence assembly
# ===========================================================================

def test_collect_not_present_short_circuits_status_and_jails():
    """Reproduces 192.168.88.20: binary confirmed absent. status_unpriv
    is still collected (cheap, no privilege escalation), but status_sudo
    stays None and no per-jail calls happen at all - no pointless
    privileged round trip (possibly prompting for a sudo password)
    against a binary confirmed absent from PATH."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v fail2ban-client': '',
            'fail2ban-client status': "bash: fail2ban-client: command not found",
        },
        exit_codes={
            'command -v fail2ban-client': 127,
            'fail2ban-client status': 127,
        },
    )
    evidence = collect_fail2ban_config(fake)
    assert binary_verdict(evidence.binary_check) == 'NOT_PRESENT'
    assert evidence.status_sudo is None
    assert evidence.jails == []
    # confirm no sudo status call, and no per-jail calls, were ever attempted
    assert not any(c.startswith('sudo ') for c in fake.calls)


class UnprivDistinctFake(ExitCodeFakeSSHExecutor):
    """Distinguishes the unprivileged ssh.run() transport from the sudo
    ssh.sudo() transport so a test can give each a genuinely different
    canned response, even though both may wrap the exact same underlying
    command string (e.g. 'fail2ban-client status'). Ordinary
    ExitCodeFakeSSHExecutor can't do this - its run()/sudo() both route
    through the same substring-matching _respond(), which is correct for
    collectors where unpriv/sudo variants of a command are never both
    collected in the same call (firewall_config.py, sql_config.py), but
    fail2ban_config.py deliberately collects BOTH (status_unpriv AND
    status_sudo) from the same underlying command text - see this
    module's docstring, "Privilege model".

    `unpriv_responses`/`unpriv_exit_codes` behave exactly like the base
    class's `responses`/`exit_codes` dicts but only apply to calls made
    through .run() (i.e. run_command_with_exit_code()'s unprivileged
    path); .sudo() calls fall through to the base class's normal
    substring matching.
    """
    def __init__(self, *args, unpriv_responses: dict[str, str] | None = None,
                 unpriv_exit_codes: dict[str, int] | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._unpriv_responses = unpriv_responses or {}
        self._unpriv_exit_codes = unpriv_exit_codes or {}

    def run(self, cmd, timeout=20):
        self.calls.append(f'RUN:{cmd}')
        for substr, stdout in self._unpriv_responses.items():
            if substr in cmd:
                import re as _re
                m = _re.search(r'__NETAUDIT_RC_[0-9a-f]+__', cmd)
                marker = m.group(0) if m else None
                code = self._unpriv_exit_codes.get(substr)
                if marker and code is not None:
                    return f'{stdout}\n{marker}:{code}\n', ''
                return stdout, ''  # no exit code registered -> collection failure shape
        return self._respond(cmd)

    def sudo(self, cmd, timeout=20):
        self.calls.append(f'SUDO:{cmd}')
        return self._respond(cmd)


def test_collect_installed_unpriv_denied_sudo_success_real_host_shape():
    """Reproduces 46.62.147.41 exactly: unprivileged status returns
    exit_code=0 with an embedded ERROR/permission-denied message (must
    NOT be read as success by this collector - it just stores it), sudo
    status succeeds with 6 real jails, and each jail is then queried via
    sudo individually. This is the empirically-confirmed FB-2/FB-3
    shape - the entire reason status_sudo (not status_unpriv) must be
    authoritative."""
    unpriv_error_text = (
        '2026-08-16 18:34:19,309 fail2ban                [345062]: '
        'ERROR   Permission denied to socket: /var/run/fail2ban/fail2ban.sock, '
        '(you must be root)'
    )
    sudo_status_text = (
        'Status\n'
        '|- Number of jail:\t6\n'
        '`- Jail list:\tnginx-botsearch, nginx-http-auth, nginx-limit-req, '
        'recidive, sshd, sshd-ddos'
    )
    fake = UnprivDistinctFake(
        unpriv_responses={'fail2ban-client status': unpriv_error_text},
        unpriv_exit_codes={'fail2ban-client status': 0},
        responses={
            'command -v fail2ban-client': '/usr/bin/fail2ban-client',
            'status nginx-botsearch': 'Status for the jail: nginx-botsearch\n`- Currently banned:\t0\n`- Total banned:\t0',
            'status nginx-http-auth': 'Status for the jail: nginx-http-auth\n`- Currently banned:\t0\n`- Total banned:\t0',
            'status nginx-limit-req': 'Status for the jail: nginx-limit-req\n`- Currently banned:\t0\n`- Total banned:\t0',
            'status recidive': 'Status for the jail: recidive\n`- Currently banned:\t0\n`- Total banned:\t0',
            'status sshd-ddos': 'Status for the jail: sshd-ddos\n`- Currently banned:\t0\n`- Total banned:\t0',
            'status sshd': 'Status for the jail: sshd\n`- Currently banned:\t2\n`- Total banned:\t5',
            'fail2ban-client status': sudo_status_text,  # sudo top-level status
        },
        exit_codes={
            'command -v fail2ban-client': 0,
            'status nginx-botsearch': 0,
            'status nginx-http-auth': 0,
            'status nginx-limit-req': 0,
            'status recidive': 0,
            'status sshd-ddos': 0,
            'status sshd': 0,
            'fail2ban-client status': 0,
        },
    )
    evidence = collect_fail2ban_config(fake)

    assert binary_verdict(evidence.binary_check) == 'PRESENT'

    # the unpriv call - exit 0, but content is the permission-denied error,
    # NOT the real jail status. Collector stores this AS-IS, no interpretation.
    assert evidence.status_unpriv.completed is True
    assert evidence.status_unpriv.exit_code == 0
    assert 'ERROR' in evidence.status_unpriv.stdout
    assert 'you must be root' in evidence.status_unpriv.stdout
    assert 'Jail list' not in evidence.status_unpriv.stdout

    # the sudo call - authoritative, genuinely different content
    assert evidence.status_sudo is not None
    assert evidence.status_sudo.completed is True
    assert evidence.status_sudo.exit_code == 0
    assert 'Jail list' in evidence.status_sudo.stdout
    assert evidence.status_sudo.stdout != evidence.status_unpriv.stdout

    assert len(evidence.jails) == 6
    names = {j.name for j in evidence.jails}
    assert names == {'nginx-botsearch', 'nginx-http-auth', 'nginx-limit-req',
                      'recidive', 'sshd', 'sshd-ddos'}
    sshd_jail = next(j for j in evidence.jails if j.name == 'sshd')
    assert sshd_jail.status.completed is True
    assert sshd_jail.status.exit_code == 0
    assert 'Currently banned:\t2' in sshd_jail.status.stdout
    # confirm every per-jail query actually went through sudo, not unpriv:
    # each jail name must appear in a SUDO: call and never in a RUN: call
    for jail_name in names:
        assert any(c.startswith('SUDO:') and jail_name in c for c in fake.calls), \
            f'expected a sudo call for jail {jail_name}'
        assert not any(c.startswith('RUN:') and jail_name in c for c in fake.calls), \
            f'jail {jail_name} must not be queried via unprivileged run()'


def test_collect_status_unpriv_shape_is_preserved_verbatim():
    """Directly verifies FB-3's central empirical fact is preserved as
    raw evidence: exit_code==0 with an ERROR/permission-denied string in
    stdout is stored AS-IS in status_unpriv, with no interpretation by
    the collector (no ACCESS_DENIED verdict assigned here - that's the
    semantic layer's job)."""
    unpriv_error_text = (
        'ERROR   Permission denied to socket: /var/run/fail2ban/fail2ban.sock, '
        '(you must be root)'
    )
    sudo_status_text = 'Status\n|- Number of jail:\t0\n`- Jail list:\t'
    fake = UnprivDistinctFake(
        unpriv_responses={'fail2ban-client status': unpriv_error_text},
        unpriv_exit_codes={'fail2ban-client status': 0},
        responses={
            'command -v fail2ban-client': '/usr/bin/fail2ban-client',
            'fail2ban-client status': sudo_status_text,
        },
        exit_codes={
            'command -v fail2ban-client': 0,
            'fail2ban-client status': 0,
        },
    )
    evidence = collect_fail2ban_config(fake)

    assert evidence.status_unpriv.completed is True
    assert evidence.status_unpriv.exit_code == 0
    assert 'ERROR' in evidence.status_unpriv.stdout
    assert 'Permission denied' in evidence.status_unpriv.stdout
    # sudo status is the authoritative, DIFFERENT result
    assert evidence.status_sudo.stdout != evidence.status_unpriv.stdout
    assert evidence.jails == []  # confirmed-empty, per sudo_status_text


def test_collect_sudo_status_nonzero_is_confirmed_not_collection_failure():
    """sudo fail2ban-client status completes with a nonzero exit
    (permission denied, sudo auth failure, or some other command error)
    - completed=True, NOT completed=False. The collector does not decide
    ACCESS_DENIED vs COMMAND_ERROR here (semantic layer's job) - it just
    reports the confirmed nonzero result. No per-jail calls happen since
    the jail list was never successfully obtained."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v fail2ban-client': '/usr/bin/fail2ban-client',
            'fail2ban-client status': 'sudo: a password is required',
        },
        exit_codes={
            'command -v fail2ban-client': 0,
            'fail2ban-client status': 1,
        },
    )
    evidence = collect_fail2ban_config(fake)
    assert evidence.status_sudo.completed is True
    assert evidence.status_sudo.exit_code == 1
    assert evidence.jails == []


def test_collect_sudo_status_collection_failure():
    """binary present, but the sudo status call itself never completes
    (SSH channel drop, timeout) - status_sudo.completed is False, NOT a
    confirmed nonzero exit. No per-jail calls happen."""
    fake = ExitCodeFakeSSHExecutor(
        responses={'command -v fail2ban-client': '/usr/bin/fail2ban-client'},
        exit_codes={'command -v fail2ban-client': 0},
        # no entry for 'fail2ban-client status' - simulates dropped command
    )
    evidence = collect_fail2ban_config(fake)
    assert evidence.status_sudo is not None
    assert evidence.status_sudo.completed is False
    assert evidence.status_sudo.exit_code is None
    assert evidence.jails == []


def test_collect_status_sudo_exit_0_but_parse_failure():
    """sudo status succeeds (exit 0) but its output has no recognizable
    'Jail list:' line at all - jails must stay empty (PARSE_FAILURE, not
    CONFIRMED_NO_JAILS). This collector cannot itself distinguish these
    two cases in evidence.jails (both are []); the semantic layer must
    re-parse status_sudo.stdout itself to tell them apart. This test
    exists to lock in that status_sudo.stdout is preserved verbatim so
    that re-parse is possible."""
    garbled = 'Some unexpected fail2ban-client output with no jail list line'
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v fail2ban-client': '/usr/bin/fail2ban-client',
            'fail2ban-client status': garbled,
        },
        exit_codes={
            'command -v fail2ban-client': 0,
            'fail2ban-client status': 0,
        },
    )
    evidence = collect_fail2ban_config(fake)
    assert evidence.status_sudo.completed is True
    assert evidence.status_sudo.exit_code == 0
    assert evidence.jails == []
    assert evidence.status_sudo.stdout == garbled
    # the semantic layer's own re-parse must find no jail list
    assert _parse_jail_list(evidence.status_sudo.stdout) is None


# ===========================================================================
# Per-jail partial collection — the central new architectural case vs SQL
# ===========================================================================

def test_collect_per_jail_partial_collection_preserves_each_jails_own_result():
    """3 jails: one succeeds with a nonzero ban count, one fails (no
    marker - collection failure), one succeeds with zero bans. All three
    JailEvidence entries must be present, each carrying its OWN
    completed/exit_code independently - the collector must never
    silently drop the failed jail or coerce its result to a zero ban
    count."""
    status_text = 'Status\n|- Number of jail:\t3\n`- Jail list:\tsshd, nginx-auth, recidive'

    class PartialFailFake(ExitCodeFakeSSHExecutor):
        def sudo(self, cmd, timeout=20):
            self.calls.append(cmd)
            if 'status nginx-auth' in cmd:
                # simulate a dropped/incomplete sudo call for this one jail only
                return 'partial garbage, no marker here', ''
            return self._respond(cmd)

    fake = PartialFailFake(
        responses={
            'command -v fail2ban-client': '/usr/bin/fail2ban-client',
            'status sshd': 'Status for the jail: sshd\n`- Currently banned:\t5\n`- Total banned:\t12',
            'status recidive': 'Status for the jail: recidive\n`- Currently banned:\t0\n`- Total banned:\t0',
            'fail2ban-client status': status_text,
        },
        exit_codes={
            'command -v fail2ban-client': 0,
            'status sshd': 0,
            'status recidive': 0,
            'fail2ban-client status': 0,
        },
    )
    evidence = collect_fail2ban_config(fake)

    assert len(evidence.jails) == 3
    by_name = {j.name: j for j in evidence.jails}

    assert by_name['sshd'].status.completed is True
    assert by_name['sshd'].status.exit_code == 0
    assert 'Currently banned:\t5' in by_name['sshd'].status.stdout

    assert by_name['nginx-auth'].status.completed is False
    assert by_name['nginx-auth'].status.exit_code is None

    assert by_name['recidive'].status.completed is True
    assert by_name['recidive'].status.exit_code == 0
    assert 'Currently banned:\t0' in by_name['recidive'].status.stdout


def test_collect_confirmed_empty_jail_list_is_distinct_shape_from_parse_failure():
    """A genuinely empty jail list (fail2ban installed and running, zero
    jails configured) - parses successfully, jails == [], AND
    status_sudo.stdout still contains a real 'Jail list:' line (so the
    semantic layer's own re-parse can confirm this was SUCCESS +
    confirmed-empty, not a parse failure masquerading as empty)."""
    status_text = 'Status\n|- Number of jail:\t0\n`- Jail list:\t'
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v fail2ban-client': '/usr/bin/fail2ban-client',
            'fail2ban-client status': status_text,
        },
        exit_codes={
            'command -v fail2ban-client': 0,
            'fail2ban-client status': 0,
        },
    )
    evidence = collect_fail2ban_config(fake)
    assert evidence.jails == []
    assert _parse_jail_list(evidence.status_sudo.stdout) == []  # confirmed empty, not None


# ===========================================================================
# collect_fail2ban_config with commands=Fail2banCommands(mode='status-wrapper')
# ===========================================================================
#
# These prove the collector actually consults `commands` for command
# construction rather than building 'fail2ban-client status ...' strings
# itself anywhere - the real point of Fail2banCommands existing. See
# project session notes (46.62.147.41): this is the exact production
# shape - sudoers scoped to /usr/local/bin/fail2ban-status-only, not the
# raw fail2ban-client binary.

def test_collect_wrapper_mode_uses_bare_wrapper_path_for_top_level_status():
    """The collector's top-level sudo status call must be exactly the
    wrapper path with no 'status' argument appended - the client-mode
    template ('<cmd> status') must not leak into wrapper mode."""
    status_text = 'Status\n|- Number of jail:\t1\n`- Jail list:\tsshd'
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v fail2ban-client': '/usr/bin/fail2ban-client',
            '/usr/local/bin/fail2ban-status-only': status_text,
        },
        exit_codes={
            'command -v fail2ban-client': 0,
            '/usr/local/bin/fail2ban-status-only': 0,
        },
    )
    commands = Fail2banCommands(mode='status-wrapper')
    evidence = collect_fail2ban_config(fake, commands=commands)
    assert evidence.status_sudo is not None
    assert evidence.status_sudo.completed is True
    assert evidence.status_sudo.exit_code == 0
    assert len(evidence.jails) == 1
    # the wrapper path was actually invoked, and NOT the client-mode
    # 'fail2ban-client status' template
    assert any('/usr/local/bin/fail2ban-status-only' in c for c in fake.calls)
    assert not any('fail2ban-client status' in c for c in fake.calls
                   if 'command -v' not in c)


def test_collect_wrapper_mode_per_jail_uses_wrapper_plus_bare_jail_name():
    """Per-jail sudo calls in wrapper mode must be '<wrapper> <jail>',
    never '<wrapper> status <jail>' - confirmed on the real host that
    the latter produces exit 255 ('Sorry but the jail 'status' does not
    exist') since the wrapper already hardcodes 'status' internally."""
    status_text = ('Status\n|- Number of jail:\t2\n'
                   '`- Jail list:\tsshd, nginx-auth')
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v fail2ban-client': '/usr/bin/fail2ban-client',
            '/usr/local/bin/fail2ban-status-only sshd':
                'Status for the jail: sshd\n`- Currently banned:\t0\n`- Total banned:\t1',
            '/usr/local/bin/fail2ban-status-only nginx-auth':
                'Status for the jail: nginx-auth\n`- Currently banned:\t2\n`- Total banned:\t5',
            '/usr/local/bin/fail2ban-status-only': status_text,
        },
        exit_codes={
            'command -v fail2ban-client': 0,
            '/usr/local/bin/fail2ban-status-only sshd': 0,
            '/usr/local/bin/fail2ban-status-only nginx-auth': 0,
            '/usr/local/bin/fail2ban-status-only': 0,
        },
    )
    commands = Fail2banCommands(mode='status-wrapper')
    evidence = collect_fail2ban_config(fake, commands=commands)
    assert len(evidence.jails) == 2
    by_name = {j.name: j for j in evidence.jails}
    assert by_name['sshd'].status.completed is True
    assert by_name['sshd'].status.exit_code == 0
    assert 'Currently banned:\t0' in by_name['sshd'].status.stdout
    assert by_name['nginx-auth'].status.completed is True
    assert 'Currently banned:\t2' in by_name['nginx-auth'].status.stdout
    # confirm the actual calls used the wrapper grammar, never a
    # 'status <jail>'-style call that would hit the wrapper's own
    # internal 'status' hardcoding a second time
    assert any('/usr/local/bin/fail2ban-status-only sshd' in c for c in fake.calls)
    assert not any('/usr/local/bin/fail2ban-status-only status sshd' in c for c in fake.calls)


def test_collect_client_mode_still_default_when_commands_omitted():
    """Backward-compatibility regression: calling collect_fail2ban_config()
    exactly as every pre-existing caller does (no `commands` argument at
    all) must produce identical command strings to before Fail2banCommands
    existed - 'fail2ban-client status' and 'fail2ban-client status
    <jail>' - not a wrapper-mode default and not a required argument."""
    status_text = 'Status\n|- Number of jail:\t1\n`- Jail list:\tsshd'
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v fail2ban-client': '/usr/bin/fail2ban-client',
            'status sshd': 'Status for the jail: sshd\n`- Currently banned:\t0\n`- Total banned:\t0',
            'fail2ban-client status': status_text,
        },
        exit_codes={
            'command -v fail2ban-client': 0,
            'status sshd': 0,
            'fail2ban-client status': 0,
        },
    )
    evidence = collect_fail2ban_config(fake)  # no commands= argument
    assert evidence.status_sudo.completed is True
    assert len(evidence.jails) == 1
    assert any('fail2ban-client status' in c for c in fake.calls)
