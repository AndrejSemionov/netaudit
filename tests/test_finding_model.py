"""
Tests for netaudit_pkg/findings.py - the shared Finding dataclass that
replaced nine identical copies of a `_finding()` helper across check modules.

test_findings.py (existing) tests the finding() shortcut indirectly through
each check module's `_finding` alias. This file tests the Finding dataclass
and the finding() shortcut directly: validation, defaults, and the exact
dict shape expected downstream (history.py, the web UI, AI analysis).
"""

from __future__ import annotations

import pytest

from netaudit_pkg.findings import Finding, finding, SEVERITIES, CONFIDENCES


def test_valid_severity_and_confidence_accepted():
    for sev in SEVERITIES:
        Finding(severity=sev, title='t')  # must not raise
    for conf in CONFIDENCES:
        Finding(severity='high', title='t', confidence=conf)  # must not raise


def test_invalid_severity_raises():
    with pytest.raises(ValueError, match='severity'):
        Finding(severity='catastrophic', title='t')


def test_invalid_confidence_raises():
    with pytest.raises(ValueError, match='confidence'):
        Finding(severity='high', title='t', confidence='certain')


def test_ok_severity_is_valid():
    """'ok' isn't in the reviewer's suggested severity set (critical/high/
    medium/low/info) but is already used throughout the codebase (dns_audit,
    lynis_audit, server_security...) to mean 'checked, no issue found' -
    dropping it would be a breaking change to every existing check."""
    Finding(severity='ok', title='no issues')  # must not raise


def test_to_dict_minimal_matches_legacy_shape():
    """The old per-module _finding() always returned exactly these four keys
    unless id was given. to_dict() must match, or every existing report
    consumer (history.py, the web UI, AI analysis) breaks."""
    d = Finding(severity='high', title='t', detail='d').to_dict()
    assert d == {'severity': 'high', 'title': 't', 'detail': 'd', 'confidence': 'high'}


def test_to_dict_omits_unset_optional_fields():
    d = Finding(severity='low', title='t').to_dict()
    assert 'id' not in d
    assert 'check' not in d
    assert 'description' not in d
    assert 'evidence' not in d
    assert 'recommendation' not in d
    assert 'requires_manual_verification' not in d


def test_to_dict_includes_set_optional_fields():
    d = Finding(
        severity='high', title='t', id='DOCKER-001', check='docker_audit',
        description='desc', evidence='ev', recommendation='rec',
        requires_manual_verification=True,
    ).to_dict()
    assert d['id'] == 'DOCKER-001'
    assert d['check'] == 'docker_audit'
    assert d['description'] == 'desc'
    assert d['evidence'] == 'ev'
    assert d['recommendation'] == 'rec'
    assert d['requires_manual_verification'] is True


def test_finding_shortcut_matches_legacy_function_signature():
    """finding(severity, title, detail='', confidence='high', id=None) must
    be a drop-in replacement for the old _finding() call sites."""
    d = finding('medium', 'title', 'detail', confidence='low', id='X-1')
    assert d == {'severity': 'medium', 'title': 'title', 'detail': 'detail',
                 'confidence': 'low', 'id': 'X-1'}


def test_finding_shortcut_positional_only_matches_legacy_default():
    d = finding('high', 'title only')
    assert d == {'severity': 'high', 'title': 'title only', 'detail': '', 'confidence': 'high'}


def test_finding_shortcut_rejects_invalid_severity():
    with pytest.raises(ValueError):
        finding('nonsense', 'title')
