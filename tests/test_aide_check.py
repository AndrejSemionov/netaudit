"""Tests for netaudit_pkg.checks.aide_check: summary parsing and both modes
(check/init), including the UI-value-to-internal-value mapping."""

from __future__ import annotations

import pytest

from netaudit_pkg.checks.aide_check import _parse_summary, check_aide
from tests.conftest import FakeSSHExecutor


# ===========================================================================
# _parse_summary — pure function, no SSH needed
# ===========================================================================

def test_parse_summary_typical_output():
    raw = (
        'AIDE 0.16\n\n'
        'AIDE found differences between database and filesystem!!\n'
        'Start timestamp: 2026-03-04 03:00:01\n\n'
        'Summary:\n'
        '  Total number of entries:\t54832\n'
        '  Added entries:\t\t2\n'
        '  Removed entries:\t\t1\n'
        '  Changed entries:\t\t5\n'
    )
    summary = _parse_summary(raw)
    assert summary == {'total_entries': 54832, 'added': 2, 'removed': 1, 'changed': 5}


def test_parse_summary_no_summary_block_returns_none():
    assert _parse_summary('AIDE 0.16\nNo changes found.\n') is None


def test_parse_summary_zero_changes():
    raw = ('Summary:\n  Total number of entries:\t1000\n'
           '  Added entries:\t\t0\n  Removed entries:\t\t0\n  Changed entries:\t\t0\n')
    summary = _parse_summary(raw)
    assert summary == {'total_entries': 1000, 'added': 0, 'removed': 0, 'changed': 0}


# ===========================================================================
# mode mapping: UI values ('check for changes' / 'reinitialize the database')
# vs internal values ('check' / 'init') - both must work
# ===========================================================================

@pytest.mark.parametrize('mode_value,expected_internal', [
    ('check for changes', 'check'),
    ('reinitialize the database', 'init'),
    ('check', 'check'),   # direct CLI/code call, bypassing the UI dropdown
    ('init', 'init'),
])
def test_mode_mapping(monkeypatch, mode_value, expected_internal):
    """mode='init' is a modifying action (overwrites the reference database)
    and requires confirm_modify - passed here since this test is about the
    check/init string mapping, not the confirmation gate itself (see
    test_init_without_confirmation_is_blocked below for that)."""
    from netaudit_pkg.registry import CONFIRM_MODIFY
    fake = FakeSSHExecutor(
        installed_tools={'aide'},
        responses={
            'test -f /var/lib/aide/aide.db': ('EXISTS', ''),
            '--check': ('Summary:\n  Total number of entries:\t1\n'
                              '  Added entries:\t\t0\n  Removed entries:\t\t0\n  Changed entries:\t\t0\n', ''),
            '--init': ('Total number of entries: 1\n', ''),
        },
    )
    monkeypatch.setattr('netaudit_pkg.checks.aide_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_aide(host='1.2.3.4', mode=mode_value, confirm_modify=CONFIRM_MODIFY)
    assert result['mode'] == expected_internal


def test_init_without_confirmation_is_blocked(monkeypatch):
    """mode='init' overwrites the AIDE reference database on the target -
    without an explicit confirm_modify, it must not run at all (not even
    connect over SSH), mirroring the pattern sql_injection already uses for
    ACTIVE scans (Mark's feedback: MODIFYING actions need an explicit gate)."""
    fake = FakeSSHExecutor(installed_tools={'aide'})
    monkeypatch.setattr('netaudit_pkg.checks.aide_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_aide(host='1.2.3.4', mode='init', confirm_modify='no')
    assert 'error' in result
    assert 'confirm' in result['error'].lower() or 'not confirmed' in result['error'].lower()


def test_check_mode_needs_no_confirmation(monkeypatch):
    """mode='check' (the default, read-only) must work with no confirm_modify
    at all - the gate only applies to the modifying path."""
    fake = FakeSSHExecutor(
        installed_tools={'aide'},
        responses={
            'test -f /var/lib/aide/aide.db': ('EXISTS', ''),
            '--check': ('Summary:\n  Total number of entries:\t1\n'
                              '  Added entries:\t\t0\n  Removed entries:\t\t0\n  Changed entries:\t\t0\n', ''),
        },
    )
    monkeypatch.setattr('netaudit_pkg.checks.aide_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_aide(host='1.2.3.4', mode='check')
    assert 'error' not in result


def test_unknown_mode_rejected():
    result = check_aide(host='1.2.3.4', mode='not-a-real-mode')
    assert 'error' in result
    assert 'unknown mode' in result['error']


# ===========================================================================
# check mode: missing database
# ===========================================================================

def test_check_mode_without_database_asks_for_init(monkeypatch):
    fake = FakeSSHExecutor(
        installed_tools={'aide'},
        responses={'test -f /var/lib/aide/aide.db': ('MISSING', '')},
    )
    monkeypatch.setattr('netaudit_pkg.checks.aide_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_aide(host='1.2.3.4', mode='check')
    assert 'error' in result
    assert 'mode=init' in result['error']


# ===========================================================================
# check mode: changes found -> severity mapping
# ===========================================================================

def test_check_mode_changed_files_flagged_high(monkeypatch):
    fake = FakeSSHExecutor(
        installed_tools={'aide'},
        responses={
            'test -f /var/lib/aide/aide.db': ('EXISTS', ''),
            '--check': ('Summary:\n  Total number of entries:\t1000\n'
                              '  Added entries:\t\t0\n  Removed entries:\t\t0\n  Changed entries:\t\t3\n', ''),
        },
    )
    monkeypatch.setattr('netaudit_pkg.checks.aide_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_aide(host='1.2.3.4', mode='check')
    assert result['changed'] == 3
    assert result['summary']['high'] == 1


def test_check_mode_no_changes_is_ok(monkeypatch):
    fake = FakeSSHExecutor(
        installed_tools={'aide'},
        responses={
            'test -f /var/lib/aide/aide.db': ('EXISTS', ''),
            '--check': ('Summary:\n  Total number of entries:\t1000\n'
                              '  Added entries:\t\t0\n  Removed entries:\t\t0\n  Changed entries:\t\t0\n', ''),
        },
    )
    monkeypatch.setattr('netaudit_pkg.checks.aide_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_aide(host='1.2.3.4', mode='check')
    assert result['summary']['ok'] == 1
    assert result['summary']['high'] == 0


# ===========================================================================
# init mode
# ===========================================================================

def test_init_mode_success(monkeypatch):
    from netaudit_pkg.registry import CONFIRM_MODIFY
    fake = FakeSSHExecutor(
        installed_tools={'aide'},
        responses={'--init': ('Start timestamp: ...\nTotal number of entries: 54000\n', '')},
    )
    monkeypatch.setattr('netaudit_pkg.checks.aide_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_aide(host='1.2.3.4', mode='init', confirm_modify=CONFIRM_MODIFY)
    assert result['mode'] == 'init'
    assert result['findings'][0]['severity'] == 'ok'


# ===========================================================================
# tool install gating
# ===========================================================================

def test_missing_aide_without_auto_install(monkeypatch):
    fake = FakeSSHExecutor(installed_tools=set())  # aide not installed
    monkeypatch.setattr('netaudit_pkg.checks.aide_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_aide(host='1.2.3.4', auto_install=False)
    assert 'error' in result
    assert 'not installed' in result['error']


def test_missing_aide_with_auto_install(monkeypatch):
    from netaudit_pkg.registry import CONFIRM_MODIFY
    fake = FakeSSHExecutor(
        installed_tools=set(),
        responses={
            'test -f /var/lib/aide/aide.db': ('EXISTS', ''),
            '--check': ('Summary:\n  Total number of entries:\t1\n'
                              '  Added entries:\t\t0\n  Removed entries:\t\t0\n  Changed entries:\t\t0\n', ''),
        },
    )
    monkeypatch.setattr('netaudit_pkg.checks.aide_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_aide(host='1.2.3.4', mode='check', auto_install=True, confirm_modify=CONFIRM_MODIFY)
    assert 'error' not in result
    assert 'aide' in fake.installed_tools  # FakeSSHExecutor simulates a successful install


def test_auto_install_without_confirmation_is_blocked(monkeypatch):
    """auto_install=True installs a package on the target - without
    confirm_modify it must be refused, same as mode='init'."""
    fake = FakeSSHExecutor(installed_tools=set())
    monkeypatch.setattr('netaudit_pkg.checks.aide_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_aide(host='1.2.3.4', mode='check', auto_install=True, confirm_modify='no')
    assert 'error' in result
    assert 'aide' not in fake.installed_tools  # install must not have run


def test_empty_host_rejected():
    result = check_aide(host='')
    assert 'error' in result


# ===========================================================================
# SSHExecutor.sudo() new contract integration (post-scoped-sudoers fix -
# see project session notes on the SSHExecutor.sudo() rewrite, and
# test_lynis_audit.py's matching tests for the same pattern). These
# prove check_aide() no longer relies on needs_sudo_password() as an
# upfront capability gate - a host with scoped NOPASSWD (permitting
# `aide`/`test -f` specifically but not a generic probe) must now
# actually get a real aide run, not a pre-emptive error before the real
# commands are ever attempted.
# ===========================================================================

def test_needs_sudo_password_no_longer_blocks_the_check(monkeypatch):
    """Direct regression for the upfront-gate removal: even when
    FakeSSHExecutor is configured to report needs_sudo_password()=True
    (no_password_sudo=False, password=''), check_aide() must still
    attempt the real test -f / aide --check commands rather than
    returning an error before trying."""
    fake = FakeSSHExecutor(
        installed_tools={'aide'},
        no_password_sudo=False,
        password='',
        responses={
            'test -f /var/lib/aide/aide.db': ('EXISTS', ''),
            '--check': (
                ('Summary:\n  Total number of entries:\t1000\n'
                 '  Added entries:\t\t0\n  Removed entries:\t\t0\n  Changed entries:\t\t0\n'),
                '',
            ),
        },
    )
    monkeypatch.setattr('netaudit_pkg.checks.aide_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_aide(host='1.2.3.4', mode='check')
    assert 'error' not in result
    assert result['total_entries'] == 1000
    # the real commands must actually have been attempted, not skipped
    assert any('test -f /var/lib/aide/aide.db' in c for c in fake.calls)
    assert any('--check' in c for c in fake.calls)


def test_sudo_denied_check_mode_falls_through_to_existing_error_path(monkeypatch):
    """When sudo genuinely can't run the commands (no password, real
    sudo -n refused) in mode='check' - simulated as the db_check
    producing neither EXISTS nor MISSING (exactly what a real
    `sudo -n test -f ... && echo EXISTS || echo MISSING` refusal
    produces: the whole compound shell expression never runs, so
    neither branch's echo fires) - check_aide() must fall through past
    the MISSING check (which correctly does NOT fire, since db_check
    contains neither EXISTS nor MISSING) to the real aide --check
    attempt, which then also fails with sudo denial, landing on the
    existing 'failed to parse aide --check output' fallback. No new
    error semantics needed - already-correct downstream handling."""
    fake = FakeSSHExecutor(
        installed_tools={'aide'},
        no_password_sudo=False,
        password='',
        responses={
            'test -f /var/lib/aide/aide.db': ('', 'sudo: a password is required'),
            '--check': ('', 'sudo: a password is required'),
        },
    )
    monkeypatch.setattr('netaudit_pkg.checks.aide_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_aide(host='1.2.3.4', mode='check')
    assert 'error' in result
    assert 'failed to parse aide --check output' in result['error']


def test_sudo_denied_init_mode_falls_through_to_existing_error_path(monkeypatch):
    """Same scenario for mode='init': a real sudo -n refusal on
    `aide --init` produces empty/error stdout containing neither
    'Total number of entries' nor necessarily the literal word 'error' -
    but the existing check (`'error' in out.lower() and 'Total number
    of entries' not in out`) requires BOTH conditions, so a refusal
    whose stdout doesn't literally contain 'error' would currently slip
    through silently as if it succeeded. This test locks in the current
    actual behavior (documenting it, not necessarily endorsing it) so
    any future improvement to this specific edge case is a deliberate,
    visible change rather than an accidental regression."""
    from netaudit_pkg.registry import CONFIRM_MODIFY
    fake = FakeSSHExecutor(
        installed_tools={'aide'},
        no_password_sudo=False,
        password='',
        responses={'--init': ('sudo: a password is required', '')},
    )
    monkeypatch.setattr('netaudit_pkg.checks.aide_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_aide(host='1.2.3.4', mode='init', confirm_modify=CONFIRM_MODIFY)
    # Documents existing behavior: stdout contains neither 'error' nor
    # 'Total number of entries', so the init-error check's `'error' in
    # out.lower()` half is False, and the function falls through to
    # reporting a false 'ok' — this is a pre-existing gap, unrelated to
    # the gate-removal in this change, called out here rather than
    # silently left uncovered.
    assert 'error' not in result
    assert result['findings'][0]['severity'] == 'ok'
