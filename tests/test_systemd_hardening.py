"""
Tests for netaudit_pkg.checks.systemd_hardening: JSON parsing from
`systemd-analyze security --json=short`, exposure-weight -> severity
mapping, and extracting the exact overall score from the plain-text form.

Schema confirmed against real output (systemd 255, Ubuntu 24.04):
--json=short returns a flat array of {set, name, json_field, description,
exposure} rows, where `set=false` means the directive is NOT restricted
(exposed), `exposure` is a string weight or null. It does NOT include the
"Overall exposure level" line or the weight/badness/range values needed to
recompute it - naively summing per-directive `exposure` over-counts (12.7
computed vs 9.6 actual, verified against a live nginx.service) since the
official formula normalizes over weight_sum, which isn't exposed in JSON.
So the overall score/predicate is parsed from a separate plain-text call.
"""

from __future__ import annotations

from netaudit_pkg.checks.systemd_hardening import (
    _parse_json,
    _parse_overall,
    _severity_for_weight,
    _to_findings,
    check_systemd_hardening,
)
from tests.conftest import ExitCodeFakeSSHExecutor

# ===========================================================================
# _severity_for_weight
# ===========================================================================

def test_severity_not_exposed_is_ok():
    assert _severity_for_weight(0.5, is_exposed=False) == 'ok'


def test_severity_high_weight_exposed_is_high():
    assert _severity_for_weight(0.4, is_exposed=True) == 'high'


def test_severity_medium_weight_exposed_is_medium():
    assert _severity_for_weight(0.2, is_exposed=True) == 'medium'


def test_severity_low_weight_exposed_is_low():
    assert _severity_for_weight(0.1, is_exposed=True) == 'low'


# ===========================================================================
# _parse_json
# ===========================================================================

def test_parse_json_extracts_directives():
    raw = '''[
        {"set": false, "name": "PrivateNetwork=", "json_field": "PrivateNetwork",
         "description": "Service has access to the host's network", "exposure": "0.5"},
        {"set": true, "name": "NoNewPrivileges=", "json_field": "NoNewPrivileges",
         "description": "Service processes may acquire new privileges", "exposure": "0.2"}
    ]'''
    parsed = _parse_json(raw)
    assert len(parsed['directives']) == 2
    assert parsed['directives'][0]['name'] == 'PrivateNetwork='


def test_parse_json_handles_null_exposure():
    raw = '''[
        {"set": null, "name": "SupplementaryGroups=", "json_field": "SupplementaryGroups",
         "description": "Service runs as root, option does not matter", "exposure": null}
    ]'''
    parsed = _parse_json(raw)
    assert parsed['directives'][0]['exposure'] is None


# ===========================================================================
# _parse_overall
# ===========================================================================

def test_parse_overall_extracts_score_and_predicate():
    text = (
        '  UMask=  Files created by service are world-readable by default  0.1\n\n'
        '\u2192 Overall exposure level for nginx.service: 9.6 UNSAFE \U0001F628\n'
    )
    score, predicate = _parse_overall(text)
    assert score == 9.6
    assert predicate == 'UNSAFE'


def test_parse_overall_missing_line_returns_none():
    score, predicate = _parse_overall('garbage output, no summary line here')
    assert score is None
    assert predicate is None


# ===========================================================================
# _to_findings
# ===========================================================================

def test_to_findings_maps_unset_directives_by_weight():
    parsed = {'directives': [
        {'set': False, 'name': 'PrivateNetwork=',
         'description': "Service has access to the host's network", 'exposure': '0.5'},
        {'set': False, 'name': 'NoNewPrivileges=',
         'description': 'Service processes may acquire new privileges', 'exposure': '0.2'},
    ]}
    findings = _to_findings(parsed, 'nginx.service')
    severities = {f['title']: f['severity'] for f in findings}
    assert severities['PrivateNetwork= not restricted'] == 'high'
    assert severities['NoNewPrivileges= not restricted'] == 'medium'


def test_to_findings_set_directives_are_skipped():
    parsed = {'directives': [
        {'set': True, 'name': 'PrivateNetwork=',
         'description': "Service has access to the host's network", 'exposure': '0.5'},
    ]}
    findings = _to_findings(parsed, 'nginx.service')
    assert len(findings) == 1
    assert findings[0]['severity'] == 'ok'


def test_to_findings_not_applicable_directive_is_skipped():
    """set=null (not applicable to this unit type) should not be flagged,
    same as set=true."""
    parsed = {'directives': [
        {'set': None, 'name': 'SupplementaryGroups=',
         'description': 'not applicable', 'exposure': None},
    ]}
    findings = _to_findings(parsed, 'nginx.service')
    assert len(findings) == 1
    assert findings[0]['severity'] == 'ok'


def test_to_findings_no_exposed_directives_gives_ok():
    parsed = {'directives': [
        {'set': True, 'name': 'PrivateNetwork=', 'description': 'ok', 'exposure': '0.5'},
    ]}
    findings = _to_findings(parsed, 'nginx.service')
    assert len(findings) == 1
    assert findings[0]['severity'] == 'ok'


# ===========================================================================
# check_systemd_hardening() - integration tests (previously untested
# entirely). Found during a quality-audit pass over the whole project's
# error handling: the original code used `raw, err = ssh.sudo(...2>&1)`
# with NO exit-code recovery, so `err` was always empty (2>&1 merges it
# into stdout) and a genuine sudo denial (nonzero exit, merged stderr
# text in stdout) fell all the way through to json.loads(raw), landing
# on the misleading 'failed to parse systemd-analyze output as JSON'
# error instead of a message that actually names the real cause. These
# tests lock in the fix: sudo denial/collection failure now gets its
# own explicit, honest error - and the second (overall-score) call
# failing independently no longer silently produces null/null with no
# explanation.
# ===========================================================================

def test_check_systemd_hardening_success_end_to_end(monkeypatch):
    directives = ('[{"set": false, "name": "PrivateNetwork=", "json_field": "PrivateNetwork", '
                  '"description": "Service has access to the host\'s network", "exposure": "0.5"}]')
    overall_text = ('  PrivateNetwork=  exposed  0.5\n\n'
                     '\u2192 Overall exposure level for nginx.service: 4.5 OK\n')
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'systemctl status': 'Active: active (running)',
            '--json=short': directives,
            'security nginx.service --no-pager 2>&1': overall_text,
        },
        exit_codes={
            '--json=short': 0,
            'security nginx.service --no-pager 2>&1': 0,
        },
    )
    monkeypatch.setattr('netaudit_pkg.checks.systemd_hardening.SSHExecutor', lambda *a, **kw: fake)
    result = check_systemd_hardening(host='1.2.3.4', unit='nginx.service')
    assert 'error' not in result
    assert result['overall_exposure'] == 4.5
    assert result['overall_predicate'] == 'OK'
    assert any(f['title'] == 'PrivateNetwork= not restricted' for f in result['findings'])


def test_check_systemd_hardening_unit_not_found(monkeypatch):
    fake = ExitCodeFakeSSHExecutor(responses={
        'systemctl status': ('Unit typo.service could not be found.', ''),
    })
    monkeypatch.setattr('netaudit_pkg.checks.systemd_hardening.SSHExecutor', lambda *a, **kw: fake)
    result = check_systemd_hardening(host='1.2.3.4', unit='typo.service')
    assert 'error' in result
    assert 'not found' in result['error']


def test_check_systemd_hardening_sudo_denied_gives_honest_error_not_json_error(monkeypatch):
    """The central regression this fix closes: a sudo denial on the
    JSON call must surface as an honest sudo/completion error, never as
    'failed to parse systemd-analyze output as JSON' (which was the old
    code's actual behavior in this exact scenario - the denial text
    merged via 2>&1 was non-empty, so it slipped past the empty-output
    check and hit json.loads() instead)."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'systemctl status': 'Active: active (running)',
            '--json=short': 'sudo: a password is required',
        },
        exit_codes={
            '--json=short': 1,
        },
    )
    monkeypatch.setattr('netaudit_pkg.checks.systemd_hardening.SSHExecutor', lambda *a, **kw: fake)
    result = check_systemd_hardening(host='1.2.3.4', unit='nginx.service')
    assert 'error' in result
    assert 'JSON' not in result['error']  # must NOT be the misleading old message
    assert 'systemd-analyze security failed' in result['error']
    assert 'a password is required' in result['detail']


def test_check_systemd_hardening_sudo_collection_failure_no_json_error(monkeypatch):
    """Same regression, but for a genuine collection failure (no
    completion marker recovered at all - dropped SSH command) rather
    than a confirmed nonzero exit. Must also never reach json.loads()."""
    fake = ExitCodeFakeSSHExecutor(responses={
        'systemctl status': 'Active: active (running)',
        # deliberately no '--json=short' entry in exit_codes -> no marker
        # ever appears -> completed=False
    })
    monkeypatch.setattr('netaudit_pkg.checks.systemd_hardening.SSHExecutor', lambda *a, **kw: fake)
    result = check_systemd_hardening(host='1.2.3.4', unit='nginx.service')
    assert 'error' in result
    assert 'JSON' not in result['error']
    assert 'did not complete' in result['error']


def test_check_systemd_hardening_old_systemd_still_gets_specific_message(monkeypatch):
    """A genuinely too-old systemd (no --json=short support) must still
    get the specific 'requires systemd >= 246' message, not the generic
    sudo-denial framing - this preserves a real, useful pre-existing
    distinction that the fix must not lose."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'systemctl status': 'Active: active (running)',
            '--json=short': 'Unknown option --json.',
        },
        exit_codes={
            '--json=short': 1,
        },
    )
    monkeypatch.setattr('netaudit_pkg.checks.systemd_hardening.SSHExecutor', lambda *a, **kw: fake)
    result = check_systemd_hardening(host='1.2.3.4', unit='nginx.service')
    assert 'error' in result
    assert 'not available on this host' in result['error']
    assert 'systemd >= 246' in result['hint']


def test_check_systemd_hardening_overall_score_failure_does_not_lose_directive_findings(monkeypatch):
    """The second call (overall score) failing independently must NOT
    invalidate the per-directive findings from the first (already-
    successful) call - overall_exposure/overall_predicate come back as
    None, but the findings list (and any real directive issues in it)
    must still be present, with an explicit low-severity note about the
    missing overall score rather than a silent null/null."""
    directives = ('[{"set": false, "name": "PrivateNetwork=", "json_field": "PrivateNetwork", '
                  '"description": "exposed", "exposure": "0.5"}]')
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'systemctl status': 'Active: active (running)',
            '--json=short': directives,
            'security nginx.service --no-pager 2>&1': 'sudo: a password is required',
        },
        exit_codes={
            '--json=short': 0,
            'security nginx.service --no-pager 2>&1': 1,
        },
    )
    monkeypatch.setattr('netaudit_pkg.checks.systemd_hardening.SSHExecutor', lambda *a, **kw: fake)
    result = check_systemd_hardening(host='1.2.3.4', unit='nginx.service')
    assert 'error' not in result
    assert result['overall_exposure'] is None
    assert result['overall_predicate'] is None
    assert any(f['title'] == 'PrivateNetwork= not restricted' for f in result['findings'])
    assert any('could not determine the overall exposure score' in f['title'] for f in result['findings'])
    low_finding = next(f for f in result['findings']
                       if 'could not determine the overall exposure score' in f['title'])
    assert low_finding['severity'] == 'low'
    assert low_finding.get('requires_manual_verification') is True


def test_check_systemd_hardening_overall_score_unparseable_but_completed(monkeypatch):
    """The second call completes successfully (exit 0) but its output
    doesn't contain a recognizable 'Overall exposure level' line - a
    parse failure distinct from a sudo/completion failure, still
    surfaced explicitly rather than silently returning null/null."""
    directives = ('[{"set": true, "name": "PrivateNetwork=", "json_field": "PrivateNetwork", '
                  '"description": "ok", "exposure": "0.5"}]')
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'systemctl status': 'Active: active (running)',
            '--json=short': directives,
            'security nginx.service --no-pager 2>&1': 'unexpected output format, no summary line',
        },
        exit_codes={
            '--json=short': 0,
            'security nginx.service --no-pager 2>&1': 0,
        },
    )
    monkeypatch.setattr('netaudit_pkg.checks.systemd_hardening.SSHExecutor', lambda *a, **kw: fake)
    result = check_systemd_hardening(host='1.2.3.4', unit='nginx.service')
    assert 'error' not in result
    assert result['overall_exposure'] is None
    assert any('could not extract the overall exposure score' in f['title'] for f in result['findings'])
