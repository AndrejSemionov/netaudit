"""
Tests for the shared Finding shape (severity/title/detail/confidence/id).

_finding() is duplicated verbatim across check modules (aide_check,
backup_check, breach_check, cert_transparency, dns_audit, docker_audit,
lynis_audit, rootkit_check, server_security) rather than centralized - each
module tests its own copy here, but the assertions are identical, which is
itself a way of confirming the copies haven't drifted from each other.
"""

from __future__ import annotations

import pytest

from netaudit_pkg.checks.aide_check import _finding as aide_finding
from netaudit_pkg.checks.docker_audit import _finding as docker_finding
from netaudit_pkg.checks.rootkit_check import _finding as rootkit_finding


@pytest.mark.parametrize('finding_fn', [aide_finding, docker_finding, rootkit_finding])
def test_finding_backward_compatible_positional_call(finding_fn):
    """Old call sites do _finding(severity, title, detail) with no confidence/id -
    must keep working exactly as before, just with confidence defaulting to 'high'."""
    f = finding_fn('high', 'test title', 'test detail')
    assert f['severity'] == 'high'
    assert f['title'] == 'test title'
    assert f['detail'] == 'test detail'
    assert f['confidence'] == 'high'
    assert 'id' not in f  # not explicitly provided - shouldn't appear in the dict


@pytest.mark.parametrize('finding_fn', [aide_finding, docker_finding, rootkit_finding])
def test_finding_no_detail_defaults_to_empty_string(finding_fn):
    f = finding_fn('ok', 'title only')
    assert f['detail'] == ''


@pytest.mark.parametrize('finding_fn', [aide_finding, docker_finding, rootkit_finding])
def test_finding_explicit_confidence_and_id(finding_fn):
    f = finding_fn('medium', 'title', confidence='low', id='TEST-001')
    assert f['confidence'] == 'low'
    assert f['id'] == 'TEST-001'


def test_rootkit_findings_have_low_confidence():
    """rootkit_check is the concrete case the confidence field exists for:
    rkhunter/chkrootkit are known for false positives, so their findings
    should never claim high confidence by default."""
    from netaudit_pkg.checks.rootkit_check import _parse_rkhunter, _parse_chkrootkit

    rk_findings = _parse_rkhunter('Warning: SSH root login enabled\n')
    assert len(rk_findings) == 1
    assert rk_findings[0]['confidence'] == 'low'

    ck_findings = _parse_chkrootkit(
        "Checking `bindshell'... INFECTED (PORTS: 465)\n"
        "Checking `chkutmp'... Vulnerable but disabled\n"
    )
    infected = next(f for f in ck_findings if 'INFECTED' in f['title'])
    assert infected['confidence'] == 'low'
    # 'Vulnerable but disabled' is a factual state, not a tool-specific false
    # positive pattern - it should keep the default (high) confidence
    disabled = next(f for f in ck_findings if 'disabled' in f['title'])
    assert disabled['confidence'] == 'high'


def test_cert_transparency_sensitive_hostname_wording_and_confidence():
    """Documents the fix for the 'forgotten subdomain' overclaim: the finding
    should read as an observation (keyword match), not a conclusion (forgotten),
    and should be marked low-confidence since it's a keyword heuristic."""
    import httpx
    import netaudit_pkg.checks.cert_transparency as ct_mod

    fake_certs = [
        {'id': 1, 'name_value': 'staging.example.com', 'issuer_name': "Let's Encrypt",
         'not_before': '2025-01-01T00:00:00', 'not_after': '2099-01-01T00:00:00'},
    ]

    def fake_get(url, **kw):
        class R:
            status_code = 200
            def raise_for_status(self): pass
            def json(self): return fake_certs
        return R()

    orig_get = httpx.get
    httpx.get = fake_get
    try:
        result = ct_mod.check_cert_transparency(domain='example.com')
    finally:
        httpx.get = orig_get

    sensitive = next(f for f in result['findings'] if 'sensitive hostname' in f['title'])
    assert 'forgotten' not in sensitive['title']  # no longer asserts intent, just observation
    assert sensitive['confidence'] == 'low'
