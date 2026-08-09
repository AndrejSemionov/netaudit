"""
Tests for netaudit_pkg.checks.systemd_hardening: JSON parsing from
`systemd-analyze security --json=short` and exposure-weight -> severity mapping.
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
        {"name": "PrivateNetwork=", "description": "Service has access to the host network",
         "exposure": 0.5, "exposed": true},
        {"name": "NoNewPrivileges=", "description": "Service processes may acquire new privileges",
         "exposure": 0.2, "exposed": true}
    ]'''
    parsed = _parse_json(raw)
    assert len(parsed['directives']) == 2
    assert parsed['directives'][0]['name'] == 'PrivateNetwork='


def test_to_findings_maps_exposed_directives_by_weight():
    parsed = {'directives': [
        {'name': 'PrivateNetwork=', 'description': 'Service has access to the host network',
         'exposure': 0.5, 'exposed': True},
        {'name': 'NoNewPrivileges=', 'description': 'Service processes may acquire new privileges',
         'exposure': 0.2, 'exposed': True},
    ]}
    findings = _to_findings(parsed, 'nginx.service')
    severities = {f['title']: f['severity'] for f in findings}
    assert severities['PrivateNetwork= not restricted'] == 'high'
    assert severities['NoNewPrivileges= not restricted'] == 'medium'


def test_to_findings_no_exposed_directives_gives_ok():
    parsed = {'directives': [
        {'name': 'PrivateNetwork=', 'description': 'ok', 'exposure': 0.5, 'exposed': False},
    ]}
    findings = _to_findings(parsed, 'nginx.service')
    assert len(findings) == 1
    assert findings[0]['severity'] == 'ok'
