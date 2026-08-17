"""
Tests for netaudit_pkg.checks.lynis_audit: report.dat parsing, findings
mapping, and the auto_install confirmation gate.

This module previously had no test coverage at all.
"""

from __future__ import annotations

from netaudit_pkg.checks.lynis_audit import (
    _parse_report, _to_findings, check_lynis_audit,
)
from netaudit_pkg.registry import CONFIRM_MODIFY
from tests.conftest import FakeSSHExecutor


# ===========================================================================
# _parse_report
# ===========================================================================

def test_parse_report_extracts_hardening_index():
    raw = (
        'hardening_index=72\n'
        'os_fullname=Ubuntu 24.04\n'
        'tests_executed=250\n'
    )
    parsed = _parse_report(raw)
    assert parsed['hardening_index'] == 72
    assert parsed['os_name'] == 'Ubuntu 24.04'
    assert parsed['tests_performed'] == 250


def test_parse_report_extracts_warnings_and_suggestions():
    raw = (
        'hardening_index=60\n'
        'warning[]=AUTH-9262|SSH root login enabled|\n'
        'suggestion[]=STRG-1846|Consider disabling USB storage|\n'
    )
    parsed = _parse_report(raw)
    assert len(parsed['warnings']) == 1
    assert parsed['warnings'][0][0] == 'AUTH-9262'
    assert 'SSH root login enabled' in parsed['warnings'][0][1]
    assert len(parsed['suggestions']) == 1
    assert parsed['suggestions'][0][0] == 'STRG-1846'


def test_parse_report_no_warnings_gives_empty_lists():
    raw = 'hardening_index=95\n'
    parsed = _parse_report(raw)
    assert parsed['warnings'] == []
    assert parsed['suggestions'] == []


# ===========================================================================
# _to_findings
# ===========================================================================

def test_to_findings_maps_warnings_to_high_and_suggestions_to_low():
    parsed = {
        'warnings': [('AUTH-9262', 'SSH root login enabled')],
        'suggestions': [('STRG-1846', 'Consider disabling USB storage')],
    }
    findings = _to_findings(parsed)
    severities = {f['severity'] for f in findings}
    assert 'high' in severities
    assert 'low' in severities
    high = next(f for f in findings if f['severity'] == 'high')
    assert 'AUTH-9262' in high['detail']


def test_to_findings_no_issues_gives_single_ok_finding():
    findings = _to_findings({'warnings': [], 'suggestions': []})
    assert len(findings) == 1
    assert findings[0]['severity'] == 'ok'


# ===========================================================================
# check_lynis_audit: basic flow
# ===========================================================================

REPORT_DAT = (
    'hardening_index=80\n'
    'os_fullname=Ubuntu 24.04\n'
    'tests_executed=240\n'
)


def test_empty_host_rejected():
    result = check_lynis_audit(host='')
    assert 'error' in result


def test_successful_audit_returns_hardening_index(monkeypatch):
    fake = FakeSSHExecutor(
        installed_tools={'lynis'},
        responses={'cat /var/log/lynis-report.dat': (REPORT_DAT, '')},
    )
    monkeypatch.setattr('netaudit_pkg.checks.lynis_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_lynis_audit(host='1.2.3.4')
    assert 'error' not in result
    assert result['hardening_index'] == 80
    assert result['os_name'] == 'Ubuntu 24.04'


def test_missing_report_file_is_an_error(monkeypatch):
    fake = FakeSSHExecutor(
        installed_tools={'lynis'},
        responses={'cat /var/log/lynis-report.dat': ('', 'No such file or directory')},
    )
    monkeypatch.setattr('netaudit_pkg.checks.lynis_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_lynis_audit(host='1.2.3.4')
    assert 'error' in result


# ===========================================================================
# auto_install confirmation gate (Mark's feedback: MODIFYING actions need
# an explicit gate, same pattern as sql_injection's ACTIVE-scan gate)
# ===========================================================================

def test_missing_lynis_without_auto_install_is_an_error(monkeypatch):
    fake = FakeSSHExecutor(installed_tools=set())
    monkeypatch.setattr('netaudit_pkg.checks.lynis_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_lynis_audit(host='1.2.3.4', auto_install=False)
    assert 'error' in result
    assert 'lynis' not in fake.installed_tools  # must not have attempted install


def test_auto_install_without_confirmation_is_blocked(monkeypatch):
    """auto_install=True installs a package on the target - without an
    explicit confirm_modify it must be refused before attempting install."""
    fake = FakeSSHExecutor(installed_tools=set())
    monkeypatch.setattr('netaudit_pkg.checks.lynis_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_lynis_audit(host='1.2.3.4', auto_install=True, confirm_modify='no')
    assert 'error' in result
    assert 'lynis' not in fake.installed_tools  # install must not have run


def test_auto_install_with_confirmation_proceeds(monkeypatch):
    fake = FakeSSHExecutor(
        installed_tools=set(),
        responses={'cat /var/log/lynis-report.dat': (REPORT_DAT, '')},
    )
    monkeypatch.setattr('netaudit_pkg.checks.lynis_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_lynis_audit(host='1.2.3.4', auto_install=True, confirm_modify=CONFIRM_MODIFY)
    assert 'error' not in result
    assert 'lynis' in fake.installed_tools


def test_already_installed_lynis_needs_no_confirmation(monkeypatch):
    """If lynis is already installed, auto_install/confirm_modify are moot -
    the gate must not block a read-only run just because those params exist."""
    fake = FakeSSHExecutor(
        installed_tools={'lynis'},
        responses={'cat /var/log/lynis-report.dat': (REPORT_DAT, '')},
    )
    monkeypatch.setattr('netaudit_pkg.checks.lynis_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_lynis_audit(host='1.2.3.4')
    assert 'error' not in result


# ===========================================================================
# SSHExecutor.sudo() new contract integration (post-scoped-sudoers fix -
# see project session notes on the SSHExecutor.sudo() rewrite). These
# tests exist specifically to prove check_lynis_audit() no longer relies
# on needs_sudo_password() as an upfront capability gate - a host with
# scoped NOPASSWD (permitting `lynis`/`cat` specifically but not a
# generic probe) must now actually get a real lynis run, not a
# pre-emptive error before the real commands are ever attempted.
# ===========================================================================

def test_needs_sudo_password_no_longer_blocks_the_check(monkeypatch):
    """Direct regression for the upfront-gate removal: even when
    FakeSSHExecutor is configured to report needs_sudo_password()=True
    (no_password_sudo=False, password=''), check_lynis_audit() must
    still attempt the real lynis/cat commands rather than returning an
    error before trying - the actual command result (success here) is
    what must decide the outcome, not a generic capability guess made
    before any real command was run."""
    fake = FakeSSHExecutor(
        installed_tools={'lynis'},
        no_password_sudo=False,
        password='',
        responses={'cat /var/log/lynis-report.dat': (REPORT_DAT, '')},
    )
    monkeypatch.setattr('netaudit_pkg.checks.lynis_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_lynis_audit(host='1.2.3.4')
    assert 'error' not in result
    assert result['hardening_index'] == 80
    # the real commands must actually have been attempted, not skipped
    assert any('lynis audit system' in c for c in fake.calls)
    assert any('cat /var/log/lynis-report.dat' in c for c in fake.calls)


def test_sudo_denied_with_no_password_falls_through_to_existing_error_path(monkeypatch):
    """When sudo genuinely can't run the commands (no password, and the
    real sudo -n attempt is refused) - simulated here as the report file
    read producing empty output, exactly as a real `sudo -n cat ...`
    refusal would - check_lynis_audit() must still surface the existing,
    already-correct error path ('failed to read
    /var/log/lynis-report.dat'), not a new/different error. This proves
    the fix doesn't require inventing new error semantics - the
    downstream empty-output check already does the right thing once the
    upfront gate stops short-circuiting before it."""
    fake = FakeSSHExecutor(
        installed_tools={'lynis'},
        no_password_sudo=False,
        password='',
        responses={'cat /var/log/lynis-report.dat': ('', 'sudo: a password is required')},
    )
    monkeypatch.setattr('netaudit_pkg.checks.lynis_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_lynis_audit(host='1.2.3.4')
    assert 'error' in result
    assert 'failed to read' in result['error']
