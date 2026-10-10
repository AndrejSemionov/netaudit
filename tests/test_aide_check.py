"""Tests for netaudit_pkg.checks.aide_check: summary parsing and both modes
(check/init), including the UI-value-to-internal-value mapping."""

from __future__ import annotations

import pytest

from netaudit_pkg.checks.aide_check import _parse_summary, check_aide
from tests.conftest import ExitCodeFakeSSHExecutor, FakeSSHExecutor

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
# Fakes. Database presence, --init and the activating mv go through
# ssh_utils.run_sudo_with_exit_code() and need a registered exit code;
# `aide --check` also needs a confirmed exit code after F3.
# ===========================================================================

SUMMARY_CLEAN = ('Summary:\n  Total number of entries:\t1\n'
                 '  Added entries:\t\t0\n  Removed entries:\t\t0\n  Changed entries:\t\t0\n')
DB = 'test -f /var/lib/aide/aide.db;'
DB_GZ = 'test -f /var/lib/aide/aide.db.gz'
MV = 'aide.db.new /var'
MV_GZ = 'aide.db.new.gz'
SUDO_REFUSED = 'sudo: a password is required'


def _aide_fake(responses=None, exit_codes=None, stderrs=None, installed_tools=None):
    """Default: aide installed, the plain database exists."""
    return ExitCodeFakeSSHExecutor(
        installed_tools={'aide'} if installed_tools is None else installed_tools,
        responses={DB: '', **(responses or {})},
        exit_codes={DB: 0, '--check': 0, **(exit_codes or {})},
        stderrs=stderrs,
    )


def _patch(monkeypatch, fake):
    monkeypatch.setattr('netaudit_pkg.checks.aide_check.SSHExecutor', lambda *a, **kw: fake)


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
    fake = _aide_fake(
        responses={'--check': SUMMARY_CLEAN, '--init': 'Total number of entries: 1\n', MV: ''},
        exit_codes={'--init': 0, MV: 0},
    )
    _patch(monkeypatch, fake)
    result = check_aide(host='1.2.3.4', mode=mode_value, confirm_modify=CONFIRM_MODIFY)
    assert result['mode'] == expected_internal


def test_init_without_confirmation_is_blocked(monkeypatch):
    """mode='init' overwrites the AIDE reference database on the target -
    without an explicit confirm_modify, it must not run at all (not even
    connect over SSH), mirroring the pattern sql_injection already uses for
    ACTIVE scans (Mark's feedback: MODIFYING actions need an explicit gate)."""
    fake = FakeSSHExecutor(installed_tools={'aide'})
    _patch(monkeypatch, fake)
    result = check_aide(host='1.2.3.4', mode='init', confirm_modify='no')
    assert 'error' in result
    assert 'confirm' in result['error'].lower() or 'not confirmed' in result['error'].lower()


def test_check_mode_needs_no_confirmation(monkeypatch):
    """mode='check' (the default, read-only) must work with no confirm_modify
    at all - the gate only applies to the modifying path."""
    _patch(monkeypatch, _aide_fake(responses={'--check': SUMMARY_CLEAN}))
    result = check_aide(host='1.2.3.4', mode='check')
    assert 'error' not in result


def test_unknown_mode_rejected():
    result = check_aide(host='1.2.3.4', mode='not-a-real-mode')
    assert 'error' in result
    assert 'unknown mode' in result['error']


# ===========================================================================
# check mode: database presence
# ===========================================================================

def test_check_mode_without_database_asks_for_init(monkeypatch):
    fake = _aide_fake(responses={DB_GZ: ''}, exit_codes={DB: 1, DB_GZ: 1})
    _patch(monkeypatch, fake)
    result = check_aide(host='1.2.3.4', mode='check')
    assert 'error' in result
    assert 'mode=init' in result['error']


def test_check_mode_gz_database_counts_as_present(monkeypatch):
    fake = _aide_fake(responses={DB_GZ: '', '--check': SUMMARY_CLEAN}, exit_codes={DB: 1, DB_GZ: 0})
    _patch(monkeypatch, fake)
    result = check_aide(host='1.2.3.4', mode='check')
    assert 'error' not in result


def test_check_mode_both_presence_tests_run_under_sudo(monkeypatch):
    """Task 7 (E4): `sudo -n test -f A || test -f B` ran only the first
    test under sudo. Each test is now its own sudo call."""
    fake = _aide_fake(responses={DB_GZ: ''}, exit_codes={DB: 1, DB_GZ: 1})
    _patch(monkeypatch, fake)
    check_aide(host='1.2.3.4', mode='check')
    tests = [c.split('; rc=')[0] for c in fake.calls if 'test -f' in c]
    assert tests == ['{ sudo -n -- test -f /var/lib/aide/aide.db',
                     '{ sudo -n -- test -f /var/lib/aide/aide.db.gz']


def test_check_mode_sudo_refusal_is_not_a_missing_database(monkeypatch):
    """Task 7 (E4): a refused sudo used to read as MISSING and told the
    user to run init, the path that then reported false success."""
    fake = _aide_fake(exit_codes={DB: 1}, stderrs={DB: SUDO_REFUSED + '\n'})
    _patch(monkeypatch, fake)
    result = check_aide(host='1.2.3.4', mode='check')
    assert result['error'] == f'sudo refused the AIDE database check: {SUDO_REFUSED}'
    assert 'mode=init' not in result['error']
    assert '"Sudo password"' in result['hint']  # the field's name since task 10
    assert not any('--check' in c for c in fake.calls)


def test_check_mode_presence_not_confirmed_is_an_error(monkeypatch):
    fake = _aide_fake(exit_codes={DB: None})  # no exit code -> no marker -> not completed
    _patch(monkeypatch, fake)
    result = check_aide(host='1.2.3.4', mode='check')
    assert result['error'] == 'could not confirm whether the AIDE database exists'


def test_check_mode_aide_check_sudo_refusal_is_named(monkeypatch):
    fake = _aide_fake(responses={'--check': ''}, exit_codes={'--check': 1},
                      stderrs={'--check': SUDO_REFUSED})
    _patch(monkeypatch, fake)
    result = check_aide(host='1.2.3.4', mode='check')
    assert result['error'] == f'sudo refused aide --check: {SUDO_REFUSED}'


# ===========================================================================
# check mode: changes found -> severity mapping
# ===========================================================================

def test_check_mode_changed_files_flagged_high(monkeypatch):
    fake = _aide_fake(responses={'--check': ('Summary:\n  Total number of entries:\t1000\n'
                                             '  Added entries:\t\t0\n  Removed entries:\t\t0\n  Changed entries:\t\t3\n')},
                      exit_codes={'--check': 4})
    _patch(monkeypatch, fake)
    result = check_aide(host='1.2.3.4', mode='check')
    assert result['changed'] == 3
    assert result['summary']['high'] == 1


def test_check_mode_no_changes_is_ok(monkeypatch):
    fake = _aide_fake(responses={'--check': ('Summary:\n  Total number of entries:\t1000\n'
                                             '  Added entries:\t\t0\n  Removed entries:\t\t0\n  Changed entries:\t\t0\n')})
    _patch(monkeypatch, fake)
    result = check_aide(host='1.2.3.4', mode='check')
    assert result['summary']['ok'] == 1
    assert result['summary']['high'] == 0


# ===========================================================================
# init mode: success only on confirmed exit codes (task 7, E4)
# ===========================================================================

def _init(monkeypatch, fake):
    from netaudit_pkg.registry import CONFIRM_MODIFY
    _patch(monkeypatch, fake)
    return check_aide(host='1.2.3.4', mode='init', confirm_modify=CONFIRM_MODIFY)


def test_init_mode_success(monkeypatch):
    fake = _aide_fake(responses={'--init': 'Start timestamp: ...\nTotal number of entries: 54000\n', MV: ''},
                      exit_codes={'--init': 0, MV: 0})
    result = _init(monkeypatch, fake)
    assert result['mode'] == 'init'
    assert result['findings'][0]['severity'] == 'ok'
    sudo_calls = [c.split('; rc=')[0] for c in fake.calls if 'sudo' in c]
    assert sudo_calls == ['{ sudo -n -- aide --config /etc/aide/aide.conf --init',
                          '{ sudo -n -- mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db']


def test_init_mode_gz_database_is_activated(monkeypatch):
    fake = _aide_fake(responses={'--init': 'ok', MV: '', MV_GZ: ''},
                      exit_codes={'--init': 0, MV: 1, MV_GZ: 0})
    result = _init(monkeypatch, fake)
    assert result['findings'][0]['severity'] == 'ok'


def test_init_mode_sudo_refusal_is_an_error_not_ok(monkeypatch):
    """Replaces test_sudo_denied_init_mode_falls_through_to_existing_error_path,
    which locked in the false 'initialized' result."""
    fake = _aide_fake(responses={'--init': ''}, exit_codes={'--init': 1},
                      stderrs={'--init': SUDO_REFUSED + '\n'})
    result = _init(monkeypatch, fake)
    assert result['error'] == f'sudo refused aide --init: {SUDO_REFUSED}'
    assert '"Sudo password"' in result['hint']
    assert 'findings' not in result
    assert not any('mv ' in c for c in fake.calls)


def test_init_mode_aide_error_code_is_named(monkeypatch):
    fake = _aide_fake(responses={'--init': ''}, exit_codes={'--init': 17},
                      stderrs={'--init': 'missing configuration\n'})
    result = _init(monkeypatch, fake)
    assert result['error'] == 'aide --init failed (exit 17: configuration error)'
    assert 'missing configuration' in result['detail']


def test_init_mode_unknown_aide_exit_code_is_reported(monkeypatch):
    fake = _aide_fake(responses={'--init': ''}, exit_codes={'--init': 42})
    result = _init(monkeypatch, fake)
    assert result['error'] == 'aide --init failed (exit 42)'


def test_init_mode_not_completed_is_an_error(monkeypatch):
    fake = _aide_fake(responses={'--init': 'partial output'})
    result = _init(monkeypatch, fake)
    assert result['error'] == 'aide --init did not complete'


def test_init_mode_database_not_activated_is_an_error(monkeypatch):
    fake = _aide_fake(responses={'--init': 'ok', MV: '', MV_GZ: ''},
                      exit_codes={'--init': 0, MV: 1, MV_GZ: 1})
    result = _init(monkeypatch, fake)
    assert result['error'] == 'AIDE database was built but not activated (mv aide.db.new failed)'


# ===========================================================================
# tool install gating
# ===========================================================================

def test_missing_aide_without_auto_install(monkeypatch):
    fake = FakeSSHExecutor(installed_tools=set())  # aide not installed
    _patch(monkeypatch, fake)
    result = check_aide(host='1.2.3.4', auto_install=False)
    assert 'error' in result
    assert 'not installed' in result['error']


def test_missing_aide_with_auto_install(monkeypatch):
    from netaudit_pkg.registry import CONFIRM_MODIFY
    fake = _aide_fake(installed_tools=set(), responses={'--check': SUMMARY_CLEAN})
    _patch(monkeypatch, fake)
    result = check_aide(host='1.2.3.4', mode='check', auto_install=True, confirm_modify=CONFIRM_MODIFY)
    assert 'error' not in result
    assert 'aide' in fake.installed_tools  # FakeSSHExecutor simulates a successful install


def test_auto_install_without_confirmation_is_blocked(monkeypatch):
    """auto_install=True installs a package on the target - without
    confirm_modify it must be refused, same as mode='init'."""
    fake = FakeSSHExecutor(installed_tools=set())
    _patch(monkeypatch, fake)
    result = check_aide(host='1.2.3.4', mode='check', auto_install=True, confirm_modify='no')
    assert 'error' in result
    assert 'aide' not in fake.installed_tools  # install must not have run


def test_empty_host_rejected():
    result = check_aide(host='')
    assert 'error' in result
