"""F3: a clean result requires a confirmed run of the security tool."""

from __future__ import annotations

from netaudit_pkg.checks.aide_check import check_aide
from netaudit_pkg.checks.lynis_audit import check_lynis_audit
from netaudit_pkg.checks.rootkit_check import check_rootkit
from tests.conftest import ExitCodeFakeSSHExecutor


def _patch(monkeypatch, module: str, fake: ExitCodeFakeSSHExecutor) -> None:
    monkeypatch.setattr(f'netaudit_pkg.checks.{module}.SSHExecutor', lambda *a, **kw: fake)


def test_rootkit_sudo_refused_both_tools_is_not_clean(monkeypatch):
    fake = ExitCodeFakeSSHExecutor(
        installed_tools={'rkhunter', 'chkrootkit'},
        responses={'rkhunter --check': '', 'chkrootkit': ''},
        exit_codes={'rkhunter --check': 1, 'chkrootkit': 1},
        stderrs={'rkhunter --check': 'sudo: a password is required',
                 'chkrootkit': 'sudo: a password is required'},
    )
    _patch(monkeypatch, 'rootkit_check', fake)
    result = check_rootkit(host='127.0.0.1')
    assert result.get('error') == 'no tool ran'
    assert 'password' in result['detail']
    assert all(f['severity'] != 'ok' for f in result.get('findings', []))


def test_rootkit_partial_run_does_not_claim_all_clear(monkeypatch):
    fake = ExitCodeFakeSSHExecutor(
        installed_tools={'rkhunter', 'chkrootkit'},
        responses={'rkhunter --check': '[ Rootkit Hunter version 1.4.6 ]\nNo warnings.\n',
                   'chkrootkit': ''},
        exit_codes={'rkhunter --check': 0, 'chkrootkit': 1},
        stderrs={'chkrootkit': 'sudo: a password is required'},
    )
    _patch(monkeypatch, 'rootkit_check', fake)
    result = check_rootkit(host='127.0.0.1')
    assert result['tools']['rkhunter']['ran'] is True
    assert result['tools']['chkrootkit']['ran'] is False
    assert result.get('warnings')
    assert all(f['severity'] != 'ok' for f in result['findings'])


def test_rootkit_warning_exit_keeps_finding(monkeypatch):
    fake = ExitCodeFakeSSHExecutor(
        installed_tools={'rkhunter'},
        responses={'rkhunter --check': 'Warning: suspicious file\n'},
        exit_codes={'rkhunter --check': 1},
    )
    _patch(monkeypatch, 'rootkit_check', fake)
    result = check_rootkit(host='127.0.0.1', use_chkrootkit=False)
    assert any(f['severity'] == 'medium' for f in result['findings'])
    assert any('sudo -n -- rkhunter --check' in c for c in fake.calls)


_OLD_REPORT = 'hardening_index=90\ntests_executed=240\n'


def test_lynis_failed_audit_cannot_reuse_old_report(monkeypatch):
    fake = ExitCodeFakeSSHExecutor(
        installed_tools={'lynis'},
        responses={'lynis audit system': '', 'cat /var/log/lynis-report.dat': _OLD_REPORT},
        exit_codes={'lynis audit system': 1, 'cat /var/log/lynis-report.dat': 0},
        stderrs={'lynis audit system': 'sudo: a password is required'},
    )
    _patch(monkeypatch, 'lynis_audit', fake)
    result = check_lynis_audit(host='127.0.0.1')
    assert 'error' in result
    assert 'hardening_index' not in result
    assert not any('cat /var/log/lynis-report.dat' in c for c in fake.calls)


def test_lynis_report_read_must_complete(monkeypatch):
    fake = ExitCodeFakeSSHExecutor(
        installed_tools={'lynis'},
        responses={'lynis audit system': 'audit complete',
                   'cat /var/log/lynis-report.dat': _OLD_REPORT},
        exit_codes={'lynis audit system': 0, 'cat /var/log/lynis-report.dat': 1},
        stderrs={'cat /var/log/lynis-report.dat': 'sudo: a password is required'},
    )
    _patch(monkeypatch, 'lynis_audit', fake)
    result = check_lynis_audit(host='127.0.0.1')
    assert 'error' in result
    assert 'hardening_index' not in result


_CLEAN_SUMMARY = ('Summary:\n  Total number of entries: 1\n'
                  '  Added entries: 0\n  Removed entries: 0\n  Changed entries: 0\n')
_CHANGED_SUMMARY = ('Summary:\n  Total number of entries: 1\n'
                    '  Added entries: 0\n  Removed entries: 0\n  Changed entries: 1\n')


def _aide_fake(check_output: str, check_code: int | None):
    return ExitCodeFakeSSHExecutor(
        installed_tools={'aide'},
        responses={'test -f /var/lib/aide/aide.db;': '', '--check': check_output},
        exit_codes={'test -f /var/lib/aide/aide.db;': 0, '--check': check_code},
    )


def test_aide_text_only_clean_without_completion_is_not_clean(monkeypatch):
    fake = _aide_fake('no differences', None)
    _patch(monkeypatch, 'aide_check', fake)
    result = check_aide(host='127.0.0.1')
    assert 'error' in result
    assert 'findings' not in result


def test_aide_change_bit_remains_finding(monkeypatch):
    fake = _aide_fake(_CHANGED_SUMMARY, 4)
    _patch(monkeypatch, 'aide_check', fake)
    result = check_aide(host='127.0.0.1')
    assert result['summary']['high'] == 1
    assert any('sudo -n -- aide --config' in c for c in fake.calls)


def test_aide_change_bit_and_zero_summary_is_inconsistent(monkeypatch):
    fake = _aide_fake(_CLEAN_SUMMARY, 4)
    _patch(monkeypatch, 'aide_check', fake)
    result = check_aide(host='127.0.0.1')
    assert 'error' in result
    assert 'findings' not in result
