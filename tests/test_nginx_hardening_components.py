"""
Pure-function tests for netaudit_pkg.checks.nginx_hardening._build_components() -
no SSH mock needed, same pattern as test_scoring.py. Covers each of the 9
Tier-1 controls' PASS/FAIL/WARN/N/A logic individually, then the 8 synthetic
regression scenarios (A-G, C2) from docs/checks/nginx_hardening.md section
8.1, run through the real weighted_score() to pin the exact final scores.
"""

from __future__ import annotations

import pytest

from netaudit_pkg.nginx_config import NginxConfig
from netaudit_pkg.checks.nginx_hardening import _build_components
from netaudit_pkg.scoring import weighted_score


def _cfg(**kwargs) -> NginxConfig:
    """NginxConfig with sane hardened defaults, overridable per test - keeps
    each test focused on the one field it's actually exercising."""
    defaults = dict(
        installed=True, readable=True, server_tokens='off',
        ssl_protocols=['TLSv1.3'], has_ssl_certificate=True,
        headers_present={'strict-transport-security', 'x-frame-options', 'x-content-type-options'},
        autoindex_on=False,
    )
    defaults.update(kwargs)
    return NginxConfig(**defaults)


def _by_name(components, name):
    return next(c for c in components if c.name == name)


# ===========================================================================
# NGX-TLS-001 - legacy protocols disabled
# ===========================================================================

def test_tls_legacy_pass_when_absent():
    c = _by_name(_build_components(_cfg(ssl_protocols=['TLSv1.2', 'TLSv1.3'])), 'tls_legacy_disabled')
    assert c.score == 100 and c.applicable and c.finding_id is None


def test_tls_legacy_fail_when_tlsv1_present():
    c = _by_name(_build_components(_cfg(ssl_protocols=['TLSv1', 'TLSv1.2'])), 'tls_legacy_disabled')
    assert c.score == 0 and c.finding_id == 'NGX-TLS-001'


def test_tls_legacy_fail_when_tlsv1_1_present():
    c = _by_name(_build_components(_cfg(ssl_protocols=['TLSv1.1', 'TLSv1.2'])), 'tls_legacy_disabled')
    assert c.score == 0 and c.finding_id == 'NGX-TLS-001'


def test_tls_legacy_na_when_no_protocols_configured():
    c = _by_name(_build_components(_cfg(ssl_protocols=[], has_ssl_certificate=False)), 'tls_legacy_disabled')
    assert c.applicable is False
    assert c.finding_id == 'NGX-TLS-001'


def test_tls_legacy_weight():
    c = _by_name(_build_components(_cfg()), 'tls_legacy_disabled')
    assert c.weight == 0.20


# ===========================================================================
# NGX-TLS-002 - modern protocol level (three-state)
# ===========================================================================

def test_tls_modern_pass_when_tlsv13_present():
    c = _by_name(_build_components(_cfg(ssl_protocols=['TLSv1.2', 'TLSv1.3'])), 'tls_modern_protocol')
    assert c.score == 100 and c.finding_id is None


def test_tls_modern_warn_when_only_tlsv12():
    c = _by_name(_build_components(_cfg(ssl_protocols=['TLSv1.2'])), 'tls_modern_protocol')
    assert c.score == 80 and c.finding_id == 'NGX-TLS-002'


def test_tls_modern_fail_when_neither():
    c = _by_name(_build_components(_cfg(ssl_protocols=['TLSv1', 'TLSv1.1'])), 'tls_modern_protocol')
    assert c.score == 0 and c.finding_id == 'NGX-TLS-002'


def test_tls_modern_na_when_no_protocols_configured():
    c = _by_name(_build_components(_cfg(ssl_protocols=[], has_ssl_certificate=False)), 'tls_modern_protocol')
    assert c.applicable is False


def test_tls_modern_weight():
    c = _by_name(_build_components(_cfg()), 'tls_modern_protocol')
    assert c.weight == 0.10


# ===========================================================================
# NGX-TLS-003 - ssl_protocols explicitly configured
# ===========================================================================

def test_tls_explicit_pass_when_non_empty():
    c = _by_name(_build_components(_cfg(ssl_protocols=['TLSv1', 'TLSv1.1'])), 'tls_protocols_explicit')
    # PASS regardless of *which* protocols are listed - explicitness only,
    # per section 6.1: quality is NGX-TLS-001/002's job, not this control's.
    assert c.score == 100 and c.finding_id is None


def test_tls_explicit_fail_when_empty_but_cert_present():
    c = _by_name(_build_components(_cfg(ssl_protocols=[], has_ssl_certificate=True)), 'tls_protocols_explicit')
    assert c.score == 0 and c.finding_id == 'NGX-TLS-003'


def test_tls_explicit_na_when_no_certificate():
    c = _by_name(_build_components(_cfg(ssl_protocols=[], has_ssl_certificate=False)), 'tls_protocols_explicit')
    assert c.applicable is False
    assert c.finding_id == 'NGX-TLS-003'


def test_tls_explicit_na_takes_priority_over_empty_protocols_when_no_cert():
    # has_ssl_certificate=False with non-empty ssl_protocols shouldn't happen
    # in practice, but N/A must key strictly on has_ssl_certificate per spec,
    # not on ssl_protocols emptiness - this pins that down.
    c = _by_name(_build_components(_cfg(ssl_protocols=['TLSv1.3'], has_ssl_certificate=False)),
                  'tls_protocols_explicit')
    assert c.applicable is False


def test_tls_explicit_weight():
    c = _by_name(_build_components(_cfg()), 'tls_protocols_explicit')
    assert c.weight == 0.10


# ===========================================================================
# NGX-HDR-001/002/003 - security headers
# ===========================================================================

@pytest.mark.parametrize('component_name,header_key,weight,finding_id', [
    ('hsts', 'strict-transport-security', 0.10, 'NGX-HDR-001'),
    ('x_frame_options', 'x-frame-options', 0.05, 'NGX-HDR-002'),
    ('x_content_type_options', 'x-content-type-options', 0.05, 'NGX-HDR-003'),
])
def test_header_pass_when_present(component_name, header_key, weight, finding_id):
    c = _by_name(_build_components(_cfg(headers_present={header_key})), component_name)
    assert c.score == 100 and c.weight == weight and c.finding_id is None


@pytest.mark.parametrize('component_name,header_key,weight,finding_id', [
    ('hsts', 'strict-transport-security', 0.10, 'NGX-HDR-001'),
    ('x_frame_options', 'x-frame-options', 0.05, 'NGX-HDR-002'),
    ('x_content_type_options', 'x-content-type-options', 0.05, 'NGX-HDR-003'),
])
def test_header_fail_when_absent(component_name, header_key, weight, finding_id):
    c = _by_name(_build_components(_cfg(headers_present=set())), component_name)
    assert c.score == 0 and c.finding_id == finding_id
    assert c.applicable is True  # never N/A per the 6.0 status matrix


# ===========================================================================
# NGX-CONF-001 - server_tokens (never N/A, see spec section 4)
# ===========================================================================

def test_server_tokens_pass_when_off():
    c = _by_name(_build_components(_cfg(server_tokens='off')), 'server_tokens')
    assert c.score == 100 and c.finding_id is None


def test_server_tokens_fail_when_on():
    c = _by_name(_build_components(_cfg(server_tokens='on')), 'server_tokens')
    assert c.score == 0 and c.finding_id == 'NGX-CONF-001'


def test_server_tokens_fail_when_not_set():
    # None (directive absent) is FAIL, not N/A - nginx's documented default
    # is 'on', a determinate fact (spec section 4).
    c = _by_name(_build_components(_cfg(server_tokens=None)), 'server_tokens')
    assert c.score == 0 and c.applicable is True and c.finding_id == 'NGX-CONF-001'


def test_server_tokens_weight():
    c = _by_name(_build_components(_cfg()), 'server_tokens')
    assert c.weight == 0.08


# ===========================================================================
# NGX-CONF-002 - autoindex disabled
# ===========================================================================

def test_autoindex_pass_when_disabled():
    c = _by_name(_build_components(_cfg(autoindex_on=False)), 'autoindex_disabled')
    assert c.score == 100 and c.finding_id is None


def test_autoindex_fail_when_enabled():
    c = _by_name(_build_components(_cfg(autoindex_on=True)), 'autoindex_disabled')
    assert c.score == 0 and c.finding_id == 'NGX-CONF-002'


def test_autoindex_weight():
    c = _by_name(_build_components(_cfg()), 'autoindex_disabled')
    assert c.weight == 0.12


# ===========================================================================
# NGX-EXP-001 - TLS available (never N/A, see spec section 6.4 / 8.1)
# ===========================================================================

def test_tls_available_pass_when_cert_present():
    c = _by_name(_build_components(_cfg(has_ssl_certificate=True)), 'tls_available')
    assert c.score == 100 and c.applicable is True and c.finding_id is None


def test_tls_available_fail_when_no_cert():
    c = _by_name(_build_components(_cfg(has_ssl_certificate=False, ssl_protocols=[])), 'tls_available')
    assert c.score == 0 and c.applicable is True and c.finding_id == 'NGX-EXP-001'


def test_tls_available_weight():
    c = _by_name(_build_components(_cfg()), 'tls_available')
    assert c.weight == 0.20


# ===========================================================================
# Component set shape
# ===========================================================================

def test_build_components_returns_nine_components():
    components = _build_components(_cfg())
    assert len(components) == 9
    assert {c.name for c in components} == {
        'tls_legacy_disabled', 'tls_modern_protocol', 'tls_protocols_explicit',
        'hsts', 'x_frame_options', 'x_content_type_options',
        'server_tokens', 'autoindex_disabled', 'tls_available',
    }


def test_build_components_weights_sum_to_one():
    components = _build_components(_cfg())
    assert abs(sum(c.weight for c in components) - 1.0) < 1e-9


def test_build_components_feeds_weighted_score_without_error():
    # end-to-end sanity: the components _build_components() produces are
    # actually valid input to weighted_score(), not just individually
    # well-formed - this would raise ValueError if e.g. two applicable
    # components' N/A logic ever left the weight sum inconsistent.
    result = weighted_score(_build_components(_cfg()))
    assert result['score'] == 100
    assert result['max'] == 100


# ===========================================================================
# Synthetic validation scenarios (docs/checks/nginx_hardening.md section 8.1)
# ===========================================================================
# Exact input fields per scenario are fixed in the spec (2026-08-10 update) -
# these tests are the executable form of that table, so a future change to
# weights or control logic that breaks the documented scores fails loudly
# here instead of silently drifting from the spec.

@pytest.mark.parametrize('name,kwargs,expected_score', [
    ('A_fully_hardened', dict(
        server_tokens='off', ssl_protocols=['TLSv1.3'], has_ssl_certificate=True,
        headers_present={'strict-transport-security', 'x-frame-options', 'x-content-type-options'},
        autoindex_on=False,
    ), 100),
    ('B_tls12_only', dict(
        server_tokens='off', ssl_protocols=['TLSv1.2'], has_ssl_certificate=True,
        headers_present={'strict-transport-security', 'x-frame-options', 'x-content-type-options'},
        autoindex_on=False,
    ), 98),
    ('C_legacy_present', dict(
        server_tokens='off', ssl_protocols=['TLSv1', 'TLSv1.2'], has_ssl_certificate=True,
        headers_present={'strict-transport-security', 'x-frame-options', 'x-content-type-options'},
        autoindex_on=False,
    ), 78),
    ('C2_legacy_no_modern', dict(
        server_tokens='off', ssl_protocols=['TLSv1', 'TLSv1.1'], has_ssl_certificate=True,
        headers_present={'strict-transport-security', 'x-frame-options', 'x-content-type-options'},
        autoindex_on=False,
    ), 70),
    ('D_no_headers', dict(
        server_tokens='off', ssl_protocols=['TLSv1.3'], has_ssl_certificate=True,
        headers_present=set(), autoindex_on=False,
    ), 80),
    ('E_bad_config_bad_tls', dict(
        server_tokens='on', ssl_protocols=['TLSv1', 'TLSv1.1'], has_ssl_certificate=True,
        headers_present={'x-frame-options', 'x-content-type-options'}, autoindex_on=True,
    ), 40),
    ('F_no_tls_at_all', dict(
        server_tokens='off', ssl_protocols=[], has_ssl_certificate=False,
        headers_present={'x-frame-options', 'x-content-type-options'}, autoindex_on=False,
    ), 50),
    ('G_realistic_mixed', dict(
        server_tokens='on', ssl_protocols=['TLSv1.2'], has_ssl_certificate=True,
        headers_present={'x-frame-options', 'x-content-type-options'}, autoindex_on=False,
    ), 80),
])
def test_synthetic_scenario_matches_spec(name, kwargs, expected_score):
    cfg = _cfg(**kwargs)
    result = weighted_score(_build_components(cfg))
    assert result['score'] == expected_score, (
        f'scenario {name}: expected {expected_score}, got {result["score"]} - '
        f'check docs/checks/nginx_hardening.md section 8.1 for the documented inputs'
    )


def test_scenario_f_all_tls_components_are_na():
    # the specific regression this scenario exists to catch: with no TLS at
    # all, NGX-TLS-001/002/003 must all be N/A (not FAIL) - a synthetic FAIL
    # across the board was rejected in favor of accurate N/A + a correctly
    # weighted NGX-EXP-001 (spec section 4.1 / 8.1 "No TLS" finding).
    cfg = _cfg(server_tokens='off', ssl_protocols=[], has_ssl_certificate=False,
               headers_present={'x-frame-options', 'x-content-type-options'}, autoindex_on=False)
    components = _build_components(cfg)
    for control_name in ('tls_legacy_disabled', 'tls_modern_protocol', 'tls_protocols_explicit'):
        assert _by_name(components, control_name).applicable is False
    assert _by_name(components, 'tls_available').applicable is True
    assert _by_name(components, 'tls_available').score == 0
