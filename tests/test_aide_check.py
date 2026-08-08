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
    fake = FakeSSHExecutor(
        installed_tools={'aide'},
        responses={
            'test -f /var/lib/aide/aide.db': ('EXISTS', ''),
            'aide --check': ('Summary:\n  Total number of entries:\t1\n'
                              '  Added entries:\t\t0\n  Removed entries:\t\t0\n  Changed entries:\t\t0\n', ''),
            'aide --init': ('Total number of entries: 1\n', ''),
        },
    )
    monkeypatch.setattr('netaudit_pkg.checks.aide_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_aide(host='1.2.3.4', mode=mode_value)
    assert result['mode'] == expected_internal


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
            'aide --check': ('Summary:\n  Total number of entries:\t1000\n'
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
            'aide --check': ('Summary:\n  Total number of entries:\t1000\n'
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
    fake = FakeSSHExecutor(
        installed_tools={'aide'},
        responses={'aide --init': ('Start timestamp: ...\nTotal number of entries: 54000\n', '')},
    )
    monkeypatch.setattr('netaudit_pkg.checks.aide_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_aide(host='1.2.3.4', mode='init')
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
    fake = FakeSSHExecutor(
        installed_tools=set(),
        responses={
            'test -f /var/lib/aide/aide.db': ('EXISTS', ''),
            'aide --check': ('Summary:\n  Total number of entries:\t1\n'
                              '  Added entries:\t\t0\n  Removed entries:\t\t0\n  Changed entries:\t\t0\n', ''),
        },
    )
    monkeypatch.setattr('netaudit_pkg.checks.aide_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_aide(host='1.2.3.4', mode='check', auto_install=True)
    assert 'error' not in result
    assert 'aide' in fake.installed_tools  # FakeSSHExecutor simulates a successful install


def test_empty_host_rejected():
    result = check_aide(host='')
    assert 'error' in result
