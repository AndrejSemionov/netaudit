"""Tests for netaudit_pkg.log_collection — Collection Contract v2
(Iteration 2). Written test-first, before implementation, per the
project's methodology: contract freeze -> tests -> implementation.

Test order (agreed, do not reorder):
  1. FILE + readable=True           -> run(), no sudo
  2. FILE + readable=False+sudo     -> sudo(), never run() for content
  3. FILE + available=False         -> no CollectionResult at all
  4. JOURNAL + exit=0 + content     -> confirmed data
  5. JOURNAL + exit=0 + empty       -> confirmed empty, not a failure
  6. JOURNAL + exit!=0              -> access denied / failure, never
                                        auto-escalated to sudo
  7. line_count
  8. TAIL limit (-n N is actually used)
  9. FULL/WINDOW are not executed (NotImplementedError)
"""

from __future__ import annotations

import pytest

from netaudit_pkg.checks.log_discovery_audit import LogFileState, LogSource, SourceType
from netaudit_pkg.log_collection import (
    DEFAULT_TAIL_LINES,
    CollectionMode,
    SourceKind,
    collect_file,
    collect_journal,
)
from tests.conftest import ExitCodeFakeSSHExecutor


def _log_source(path, available=True, readable=True, requires_sudo=False,
                 state=LogFileState.ACTIVE) -> LogSource:
    return LogSource(
        source_type=SourceType.AUTH_LOG, path=path, available=available, readable=readable,
        requires_sudo=requires_sudo, state=state, size_bytes=1000, last_modified_epoch=1,
        owner='syslog', group='adm', mode='640',
    )


# ===========================================================================
# 1. FILE + readable=True
# ===========================================================================


def test_collect_file_readable_uses_run_not_sudo():
    fake = ExitCodeFakeSSHExecutor(
        responses={'tail -n 200 /var/log/auth.log': 'line1\nline2\nline3'},
        exit_codes={'tail -n 200 /var/log/auth.log': 0},
    )
    source = _log_source('/var/log/auth.log', available=True, readable=True, requires_sudo=False)

    result = collect_file(fake, source)

    assert result is not None
    assert result.source_kind == SourceKind.FILE
    assert result.source_path == '/var/log/auth.log'
    assert result.result.completed is True
    assert result.result.exit_code == 0
    assert 'line1' in result.result.stdout


def test_collect_file_readable_never_calls_sudo():
    """Central invariant: a readable=True file must go through run(),
    never sudo() — collect_file must not second-guess Discovery's
    already-made access decision."""

    class SudoTracker(ExitCodeFakeSSHExecutor):
        def sudo(self, cmd: str, timeout: int = 20):
            raise AssertionError(f'collect_file() must not call sudo() when readable=True; got: {cmd!r}')

    fake = SudoTracker(
        responses={'tail -n 200 /var/log/auth.log': 'line1'},
        exit_codes={'tail -n 200 /var/log/auth.log': 0},
    )
    source = _log_source('/var/log/auth.log', readable=True, requires_sudo=False)

    collect_file(fake, source)  # raises via SudoTracker.sudo() if this invariant is ever broken


# ===========================================================================
# 2. FILE + readable=False + requires_sudo=True
# ===========================================================================


def test_collect_file_requires_sudo_uses_sudo():
    fake = ExitCodeFakeSSHExecutor(
        responses={'tail -n 200 /var/log/auth.log': 'protected line1\nprotected line2'},
        exit_codes={'tail -n 200 /var/log/auth.log': 0},
    )
    source = _log_source('/var/log/auth.log', available=True, readable=False, requires_sudo=True)

    result = collect_file(fake, source)

    assert result is not None
    assert result.result.exit_code == 0
    assert 'protected line1' in result.result.stdout


def test_collect_file_requires_sudo_never_calls_plain_run_for_content():
    """The inverse invariant of the readable=True case: a
    readable=False+requires_sudo=True file must go through sudo(), never
    a plain run() — content protected by file permissions must not be
    silently fetched (or silently attempted) without elevation."""

    class RunTracker(ExitCodeFakeSSHExecutor):
        def run(self, cmd: str, timeout: int = 20):
            if 'tail' in cmd:
                raise AssertionError(
                    f'collect_file() must not call run() for tail content when requires_sudo=True; got: {cmd!r}'
                )
            return super().run(cmd, timeout)

    fake = RunTracker(
        responses={'tail -n 200 /var/log/auth.log': 'protected content'},
        exit_codes={'tail -n 200 /var/log/auth.log': 0},
    )
    source = _log_source('/var/log/auth.log', readable=False, requires_sudo=True)

    collect_file(fake, source)  # raises via RunTracker.run() if this invariant is ever broken


# ===========================================================================
# 3. FILE + available=False
# ===========================================================================


def test_collect_file_unavailable_returns_none_without_any_ssh_call():
    """An unavailable source has nothing to collect — no CommandResult,
    no attempted read, no CollectionResult at all. Confirmed by ensuring
    NO ssh command is ever issued for it."""

    class NoCallTracker(ExitCodeFakeSSHExecutor):
        def run(self, cmd: str, timeout: int = 20):
            raise AssertionError(f'collect_file() must not issue any command for available=False; got: {cmd!r}')

        def sudo(self, cmd: str, timeout: int = 20):
            raise AssertionError(f'collect_file() must not issue any command for available=False; got: {cmd!r}')

    fake = NoCallTracker(responses={}, exit_codes={})
    source = _log_source('/var/log/fail2ban.log', available=False, readable=False,
                          requires_sudo=False, state=None)

    result = collect_file(fake, source)

    assert result is None


# ===========================================================================
# 4. JOURNAL + exit=0 + content
# ===========================================================================


def test_collect_journal_with_content():
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'journalctl -u ssh -n 200 --no-pager':
                'Aug 18 08:00:01 server sshd[123]: Failed password for invalid user admin',
        },
        exit_codes={'journalctl -u ssh -n 200 --no-pager': 0},
    )
    result = collect_journal(fake, 'ssh')

    assert result.source_kind == SourceKind.JOURNAL
    assert result.unit_name == 'ssh'
    assert result.source_path is None
    assert result.result.exit_code == 0
    assert 'Failed password' in result.result.stdout


def test_collect_journal_never_calls_sudo():
    """Collection Contract v2: JOURNAL always goes through run(), never
    sudo() in Iteration 2 — see log_collection.py's docstring on why
    'works without sudo' is an observed fact on real hosts, not a
    property this module assumes or auto-escalates around."""

    class SudoTracker(ExitCodeFakeSSHExecutor):
        def sudo(self, cmd: str, timeout: int = 20):
            raise AssertionError(f'collect_journal() must never call sudo() in Iteration 2; got: {cmd!r}')

    fake = SudoTracker(
        responses={'journalctl -u ssh -n 200 --no-pager': 'some log line'},
        exit_codes={'journalctl -u ssh -n 200 --no-pager': 0},
    )
    collect_journal(fake, 'ssh')  # raises via SudoTracker.sudo() if this invariant is ever broken


# ===========================================================================
# 5. JOURNAL + exit=0 + empty stdout — confirmed empty, not a failure
# ===========================================================================


def test_collect_journal_confirmed_empty_is_not_a_failure():
    """exit_code==0 with empty stdout means 'ran fine, zero matching
    events' — e.g. no failed SSH logins in the requested window. This
    must be distinguishable from (and not conflated with) an
    access-denied failure, which is exit_code!=0."""
    fake = ExitCodeFakeSSHExecutor(
        responses={'journalctl -u ssh -n 200 --no-pager': ''},
        exit_codes={'journalctl -u ssh -n 200 --no-pager': 0},
    )
    result = collect_journal(fake, 'ssh')

    assert result.result.completed is True
    assert result.result.exit_code == 0
    assert result.result.stdout == ''
    assert result.line_count == 0


# ===========================================================================
# 6. JOURNAL + exit!=0 — access denied / failure, never auto-escalated
# ===========================================================================


def test_collect_journal_permission_denied_is_a_failure_not_auto_escalated():
    """A real access-denied case (nonzero exit) must surface as a
    failure in the result, not silently succeed with misleadingly-empty
    content, and must NOT trigger an automatic retry via sudo()."""

    class SudoTracker(ExitCodeFakeSSHExecutor):
        def sudo(self, cmd: str, timeout: int = 20):
            raise AssertionError('collect_journal() must not auto-escalate to sudo() on a nonzero exit code')

    fake = SudoTracker(
        responses={
            'journalctl -u ssh -n 200 --no-pager':
                'No journal files were opened due to insufficient permissions.',
        },
        exit_codes={'journalctl -u ssh -n 200 --no-pager': 1},
    )
    result = collect_journal(fake, 'ssh')

    assert result.result.completed is True
    assert result.result.exit_code == 1
    assert 'insufficient permissions' in result.result.stdout


def test_collect_journal_collection_failure_is_distinct_from_confirmed_empty():
    """A dropped/truncated SSH command (no completion marker recovered
    at all) must surface as completed=False, exit_code=None — never the
    same shape as a confirmed exit=0/empty-stdout result (test 5) or a
    confirmed exit!=0 failure (this section's other test)."""
    fake = ExitCodeFakeSSHExecutor(responses={}, exit_codes={})
    result = collect_journal(fake, 'ssh')

    assert result.result.completed is False
    assert result.result.exit_code is None


# ===========================================================================
# 7. line_count
# ===========================================================================


def test_line_count_reflects_actual_returned_lines():
    fake = ExitCodeFakeSSHExecutor(
        responses={'tail -n 200 /var/log/auth.log': 'line1\nline2\nline3'},
        exit_codes={'tail -n 200 /var/log/auth.log': 0},
    )
    source = _log_source('/var/log/auth.log', readable=True)
    result = collect_file(fake, source)
    assert result.line_count == 3


def test_line_count_is_none_on_collection_failure():
    """A collection failure (no confirmed result at all) must not report
    a misleading line_count of 0 — that would look identical to a
    confirmed-empty result. line_count is None here, not 0."""
    fake = ExitCodeFakeSSHExecutor(responses={}, exit_codes={})
    source = _log_source('/var/log/auth.log', readable=True)
    result = collect_file(fake, source)
    assert result.result.completed is False
    assert result.line_count is None


def test_line_count_zero_for_confirmed_empty_file():
    fake = ExitCodeFakeSSHExecutor(
        responses={'tail -n 200 /var/log/mail.log': ''},
        exit_codes={'tail -n 200 /var/log/mail.log': 0},
    )
    source = _log_source('/var/log/mail.log', readable=True)
    result = collect_file(fake, source)
    assert result.result.completed is True
    assert result.line_count == 0


# ===========================================================================
# 8. TAIL limit — -n N is actually constructed and honored
# ===========================================================================


def test_default_tail_lines_constant_is_used_in_command():
    fake = ExitCodeFakeSSHExecutor(
        responses={f'tail -n {DEFAULT_TAIL_LINES} /var/log/auth.log': 'x'},
        exit_codes={f'tail -n {DEFAULT_TAIL_LINES} /var/log/auth.log': 0},
    )
    source = _log_source('/var/log/auth.log', readable=True)
    collect_file(fake, source)  # no explicit `lines=` — must use DEFAULT_TAIL_LINES
    matching = [c for c in fake.calls if f'tail -n {DEFAULT_TAIL_LINES}' in c]
    assert len(matching) == 1


def test_custom_line_limit_is_honored_for_file():
    fake = ExitCodeFakeSSHExecutor(
        responses={'tail -n 50 /var/log/auth.log': 'x'},
        exit_codes={'tail -n 50 /var/log/auth.log': 0},
    )
    source = _log_source('/var/log/auth.log', readable=True)
    collect_file(fake, source, lines=50)
    matching = [c for c in fake.calls if 'tail -n 50 ' in c]
    assert len(matching) == 1


def test_custom_line_limit_is_honored_for_journal():
    fake = ExitCodeFakeSSHExecutor(
        responses={'journalctl -u ssh -n 50 --no-pager': 'x'},
        exit_codes={'journalctl -u ssh -n 50 --no-pager': 0},
    )
    collect_journal(fake, 'ssh', lines=50)
    matching = [c for c in fake.calls if '-n 50' in c]
    assert len(matching) == 1


# ===========================================================================
# 9. FULL / WINDOW are not executed
# ===========================================================================


def test_collect_file_full_mode_raises_not_implemented():
    fake = ExitCodeFakeSSHExecutor(responses={}, exit_codes={})
    source = _log_source('/var/log/auth.log', readable=True)
    with pytest.raises(NotImplementedError):
        collect_file(fake, source, mode=CollectionMode.FULL)


def test_collect_file_window_mode_raises_not_implemented():
    fake = ExitCodeFakeSSHExecutor(responses={}, exit_codes={})
    source = _log_source('/var/log/auth.log', readable=True)
    with pytest.raises(NotImplementedError):
        collect_file(fake, source, mode=CollectionMode.WINDOW)


def test_collect_journal_full_mode_raises_not_implemented():
    fake = ExitCodeFakeSSHExecutor(responses={}, exit_codes={})
    with pytest.raises(NotImplementedError):
        collect_journal(fake, 'ssh', mode=CollectionMode.FULL)


def test_full_and_window_modes_never_issue_any_ssh_command():
    """Reserved-but-unimplemented modes must fail closed before issuing
    any command — never fall back to TAIL or attempt an unbounded read."""

    class NoCallTracker(ExitCodeFakeSSHExecutor):
        def run(self, cmd: str, timeout: int = 20):
            raise AssertionError(f'FULL/WINDOW must not issue any command; got: {cmd!r}')

        def sudo(self, cmd: str, timeout: int = 20):
            raise AssertionError(f'FULL/WINDOW must not issue any command; got: {cmd!r}')

    fake = NoCallTracker(responses={}, exit_codes={})
    source = _log_source('/var/log/auth.log', readable=True)
    with pytest.raises(NotImplementedError):
        collect_file(fake, source, mode=CollectionMode.FULL)
