"""Tests for netaudit_pkg.checks.rootkit_check: rkhunter/chkrootkit output
parsing, confidence levels, and the full check flow with both tools."""

from __future__ import annotations


from netaudit_pkg.checks.rootkit_check import (
    _parse_rkhunter, _parse_chkrootkit, check_rootkit,
)
from tests.conftest import FakeSSHExecutor


# ===========================================================================
# _parse_rkhunter
# ===========================================================================

def test_parse_rkhunter_extracts_warnings():
    raw = (
        '[ Rootkit Hunter version 1.4.6 ]\n'
        'Checking system commands...\n\n'
        "Warning: The SSH configuration option 'PermitRootLogin' has not been set.\n"
        'Warning: The SSH daemon is not running.\n'
        'System checks summary\n'
    )
    findings = _parse_rkhunter(raw)
    assert len(findings) == 2
    assert all(f['confidence'] == 'low' for f in findings)
    assert all(f['severity'] == 'medium' for f in findings)


def test_parse_rkhunter_no_warnings():
    raw = '[ Rootkit Hunter version 1.4.6 ]\nAll checks skipped\n'
    assert _parse_rkhunter(raw) == []


# ===========================================================================
# _parse_chkrootkit
# ===========================================================================

def test_parse_chkrootkit_infected_flagged_high_low_confidence():
    raw = "Checking `bindshell'... INFECTED (PORTS: 465)\n"
    findings = _parse_chkrootkit(raw)
    assert len(findings) == 1
    assert findings[0]['severity'] == 'high'
    assert findings[0]['confidence'] == 'low'


def test_parse_chkrootkit_not_infected_produces_no_finding():
    raw = "Checking `amd'... not found\nChecking `basename'... not infected\n"
    assert _parse_chkrootkit(raw) == []


def test_parse_chkrootkit_vulnerable_but_disabled_keeps_default_confidence():
    """This status describes a factual, verifiable state (the command exists
    but isn't in use), not a tool-specific false-positive-prone heuristic -
    it should stay at the default 'high' confidence, unlike INFECTED."""
    raw = "Checking `chkutmp'... Vulnerable but disabled\n"
    findings = _parse_chkrootkit(raw)
    assert len(findings) == 1
    assert findings[0]['severity'] == 'low'
    assert findings[0]['confidence'] == 'high'


def test_parse_chkrootkit_mixed_output():
    raw = (
        "Checking `amd'... not found\n"
        "Checking `basename'... not infected\n"
        "Checking `bindshell'... INFECTED (PORTS: 465)\n"
        "Checking `lkm'... not infected\n"
        "Checking `z2'... not tested\n"
        "Checking `chkutmp'... Vulnerable but disabled\n"
    )
    findings = _parse_chkrootkit(raw)
    assert len(findings) == 2  # only INFECTED and Vulnerable-but-disabled produce findings


# ===========================================================================
# Full check_rootkit flow
# ===========================================================================

def test_both_tools_run_when_both_selected(monkeypatch):
    fake = FakeSSHExecutor(
        installed_tools={'rkhunter', 'chkrootkit'},
        responses={
            'rkhunter --check': ('Warning: test warning\n', ''),
            'chkrootkit': ("Checking `bindshell'... not infected\n", ''),
        },
    )
    monkeypatch.setattr('netaudit_pkg.checks.rootkit_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_rootkit(host='1.2.3.4')
    assert result['tools']['rkhunter']['ran'] is True
    assert result['tools']['chkrootkit']['ran'] is True


def test_only_selected_tool_runs(monkeypatch):
    fake = FakeSSHExecutor(
        installed_tools={'rkhunter', 'chkrootkit'},
        responses={'rkhunter --check': ('[ Rootkit Hunter version 1.4.6 ]\nNo warnings.\n', '')},
    )
    monkeypatch.setattr('netaudit_pkg.checks.rootkit_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_rootkit(host='1.2.3.4', use_rkhunter=True, use_chkrootkit=False)
    assert 'rkhunter' in result['tools']
    assert 'chkrootkit' not in result['tools']


def test_neither_tool_selected_is_an_error():
    result = check_rootkit(host='1.2.3.4', use_rkhunter=False, use_chkrootkit=False)
    assert 'error' in result


def test_missing_tool_without_auto_install_reported_but_other_tool_still_runs(monkeypatch):
    fake = FakeSSHExecutor(
        installed_tools={'chkrootkit'},  # rkhunter missing
        responses={'chkrootkit': ("Checking `bindshell'... not infected\n", '')},
    )
    monkeypatch.setattr('netaudit_pkg.checks.rootkit_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_rootkit(host='1.2.3.4', auto_install=False)
    assert result['tools']['rkhunter']['ran'] is False
    assert result['tools']['chkrootkit']['ran'] is True
    assert any('rkhunter' in w for w in result.get('warnings', []))


def test_findings_tagged_with_source_tool(monkeypatch):
    fake = FakeSSHExecutor(
        installed_tools={'rkhunter', 'chkrootkit'},
        responses={
            'rkhunter --check': ('Warning: test\n', ''),
            'chkrootkit': ("Checking `bindshell'... INFECTED\n", ''),
        },
    )
    monkeypatch.setattr('netaudit_pkg.checks.rootkit_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_rootkit(host='1.2.3.4')
    sources = {f['source'] for f in result['findings']}
    assert sources == {'rkhunter', 'chkrootkit'}


def test_clean_result_when_no_findings(monkeypatch):
    fake = FakeSSHExecutor(
        installed_tools={'rkhunter', 'chkrootkit'},
        responses={
            'rkhunter --check': ('[ Rootkit Hunter version 1.4.6 ]\nNo warnings.\n', ''),
            'chkrootkit': ("Checking `amd'... not found\n", ''),
        },
    )
    monkeypatch.setattr('netaudit_pkg.checks.rootkit_check.SSHExecutor', lambda *a, **kw: fake)
    result = check_rootkit(host='1.2.3.4')
    assert result['summary']['ok'] == 1


def test_empty_host_rejected():
    result = check_rootkit(host='')
    assert 'error' in result
