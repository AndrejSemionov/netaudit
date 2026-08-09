"""
Tests for netaudit_pkg.checks.systemd_hardening: JSON parsing from
`systemd-analyze security --json=short` and exposure-weight -> severity mapping.

Schema confirmed against real output (systemd 257, Ubuntu 24.04):
a flat array of {set, name, json_field, description, exposure} rows, where
`set=false` means the directive is NOT restricted (exposed), `exposure` is
a string weight or null. There is no trailing overall-score row in --json
mode (unlike text mode) - overall_exposure is computed by summing weights.
"""

from __future__ import annotations

from netaudit_pkg.checks.systemd_hardening import (
    _parse_json, _to_findings, _severity_for_weight,
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
        {"set": true, "name": "NotifyAccess=", "json_field": "NotifyAccess",
         "description": "Service child processes cannot alter service state", "exposure": null}
    ]'''
    parsed = _parse_json(raw)
    assert parsed['directives'][0]['exposure'] is None


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
    findings, total = _to_findings(parsed, 'nginx.service')
    severities = {f['title']: f['severity'] for f in findings}
    assert severities['PrivateNetwork= not restricted'] == 'high'
    assert severities['NoNewPrivileges= not restricted'] == 'medium'
    assert total == 0.7


def test_to_findings_set_directives_are_skipped():
    parsed = {'directives': [
        {'set': True, 'name': 'PrivateNetwork=',
         'description': "Service has access to the host's network", 'exposure': '0.5'},
    ]}
    findings, total = _to_findings(parsed, 'nginx.service')
    assert len(findings) == 1
    assert findings[0]['severity'] == 'ok'
    assert total == 0.0


def test_to_findings_null_exposure_is_skipped_from_findings():
    parsed = {'directives': [
        {'set': False, 'name': 'NotifyAccess=', 'description': 'no exposure weight',
         'exposure': None},
    ]}
    findings, total = _to_findings(parsed, 'nginx.service')
    # no exposure weight -> nothing to flag, falls through to the "ok" case
    assert len(findings) == 1
    assert findings[0]['severity'] == 'ok'
    assert total == 0.0


def test_to_findings_no_exposed_directives_gives_ok():
    parsed = {'directives': [
        {'set': True, 'name': 'PrivateNetwork=', 'description': 'ok', 'exposure': '0.5'},
    ]}
    findings, total = _to_findings(parsed, 'nginx.service')
    assert len(findings) == 1
    assert findings[0]['severity'] == 'ok'
