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
    _parse_json, _parse_overall, _to_findings, _severity_for_weight,
)


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
