"""
Pure-function tests for netaudit_pkg.checks.nginx_hardening._build_components() -
no SSH mock needed, same pattern as test_scoring.py. Covers each of the 9
Tier-1 controls' PASS/FAIL/WARN/N/A logic and weights individually
(section 8.3's rebalanced values - the 9 legacy weights are no longer
self-sufficient at 1.0 on their own; they sum to 0.635 as their share of
the full 16-component model), then the synthetic regression scenarios,
carried forward from docs/checks/nginx_hardening.md section 8.1 but
re-run through the full 9-legacy + 7-Tier-2 = 16-component model per
section 8.3, since a 9-component-only score is no longer a valid
`weighted_score()` input at all (see test_legacy_components_alone_do_not_
sum_to_one below for why).
"""

from __future__ import annotations

import pytest

from netaudit_pkg.nginx_config import NginxConfig
from netaudit_pkg.nginx_config_v2 import parse_nginx_config_v2
from netaudit_pkg.checks.nginx_hardening import _build_components, _build_tier2_components
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


def _cfg_v2(conf: str):
    """Thin wrapper around parse_nginx_config_v2() for synthetic Tier-2
    fixtures below - keeps the A-G scenario definitions readable as raw
    nginx config text rather than hand-built NginxConfigV2 objects."""
    return parse_nginx_config_v2(conf)


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
    assert c.weight == 0.16  # section 8.3, trimmed from 0.20


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
    assert c.weight == 0.07  # section 8.3, trimmed from 0.10


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
    assert c.weight == 0.05  # section 8.3, trimmed from 0.10


# ===========================================================================
# NGX-HDR-001/002/003 - security headers
# ===========================================================================

@pytest.mark.parametrize('component_name,header_key,weight,finding_id', [
    ('hsts', 'strict-transport-security', 0.055, 'NGX-HDR-001'),
    ('x_frame_options', 'x-frame-options', 0.025, 'NGX-HDR-002'),
    ('x_content_type_options', 'x-content-type-options', 0.025, 'NGX-HDR-003'),
])
def test_header_pass_when_present(component_name, header_key, weight, finding_id):
    c = _by_name(_build_components(_cfg(headers_present={header_key})), component_name)
    assert c.score == 100 and c.weight == weight and c.finding_id is None


@pytest.mark.parametrize('component_name,header_key,weight,finding_id', [
    ('hsts', 'strict-transport-security', 0.055, 'NGX-HDR-001'),
    ('x_frame_options', 'x-frame-options', 0.025, 'NGX-HDR-002'),
    ('x_content_type_options', 'x-content-type-options', 0.025, 'NGX-HDR-003'),
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
    assert c.weight == 0.06  # section 8.3, trimmed from 0.08


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
    assert c.weight == 0.09  # section 8.3, trimmed from 0.12


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
    assert c.weight == 0.10  # section 8.3, trimmed from 0.20


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


def test_legacy_components_alone_do_not_sum_to_one():
    # Section 8.3's rebalancing means the 9 legacy weights are only
    # meaningful as part of the full 16-component model - they sum to
    # 0.635, their fixed share (see docs/checks/nginx_hardening.md
    # section 8.3: "TLS 40% / Headers 20% / Config 20% / Exposure 20%"
    # unchanged, but Tier-2 controls now occupy part of each group).
    # weighted_score(_build_components(cfg)) alone would raise ValueError
    # (weights must sum to 1.0) - this is deliberate, not a bug: see
    # audit_nginx_hardening()'s docstring for why there is no
    # legacy-only fallback score.
    components = _build_components(_cfg())
    assert abs(sum(c.weight for c in components) - 0.635) < 1e-9


def test_full_16_component_model_sums_to_one():
    legacy = _build_components(_cfg())
    tier2 = _build_tier2_components(_cfg_v2('http { server { listen 80; } }'))
    assert len(legacy) == 9
    assert len(tier2) == 7
    total = sum(c.weight for c in legacy) + sum(c.weight for c in tier2)
    assert abs(total - 1.0) < 1e-9


def test_full_16_component_model_feeds_weighted_score_without_error():
    # end-to-end sanity: legacy + Tier-2 components together are valid
    # input to weighted_score() - this is the only combination that is
    # (see test_legacy_components_alone_do_not_sum_to_one above).
    legacy = _build_components(_cfg())
    tier2 = _build_tier2_components(_cfg_v2(
        'http { '
        'add_header Content-Security-Policy "default-src \'self\'"; '
        'add_header Referrer-Policy no-referrer; '
        'add_header Permissions-Policy "geolocation=()"; '
        'server { listen 443 ssl; ssl_ciphers ALL:@SECLEVEL=2; '
        'client_max_body_size 10m; '
        'server_name example.com; } '
        'server { listen 80; server_name example.com; '
        'return 301 https://$host$request_uri; } }'
    ))
    result = weighted_score(legacy + tier2)
    assert result['score'] == 100
    assert result['max'] == 100


# ===========================================================================
# Synthetic validation scenarios - full 16-component model
# ===========================================================================
# Carried forward from docs/checks/nginx_hardening.md section 8.1's A-G
# scenarios, but re-run through the full 9-legacy + 7-Tier-2 = 16-component
# model per section 8.3, since a 9-component-only score is no longer a
# valid weighted_score() input (test_legacy_components_alone_do_not_sum_
# to_one above). Each scenario now carries both a legacy `kwargs` dict and
# a Tier-2 nginx config string; expected_score is the real weighted_score()
# result for that combination, not hand-calculated - a future change to
# weights or control logic that shifts these fails loudly here.

_TIER2_GOOD = '''http {
    add_header Content-Security-Policy "default-src 'self'";
    add_header Referrer-Policy no-referrer;
    add_header Permissions-Policy "geolocation=()";
    server {
        listen 443 ssl;
        ssl_ciphers ALL:@SECLEVEL=2;
        client_max_body_size 10m;
        server_name example.com;
    }
    server {
        listen 80;
        server_name example.com;
        return 301 https://$host$request_uri;
    }
}'''

_TIER2_NO_TLS_NO_HEADERS = '''http {
    server {
        listen 80;
        server_name example.com;
    }
}'''

_TIER2_BAD = '''http {
    server {
        listen 443 ssl;
        ssl_ciphers ALL:RC4;
        client_max_body_size 0;
        server_name a.example.com;
    }
    server {
        listen 443 ssl;
        server_name b.example.com;
    }
    server {
        listen 80;
        server_name a.example.com;
    }
}'''


@pytest.mark.parametrize('name,legacy_kwargs,tier2_conf,expected_score', [
    ('A_fully_hardened', dict(
        server_tokens='off', ssl_protocols=['TLSv1.3'], has_ssl_certificate=True,
        headers_present={'strict-transport-security', 'x-frame-options', 'x-content-type-options'},
        autoindex_on=False,
    ), _TIER2_GOOD, 100),
    ('B_tls12_only', dict(
        server_tokens='off', ssl_protocols=['TLSv1.2'], has_ssl_certificate=True,
        headers_present={'strict-transport-security', 'x-frame-options', 'x-content-type-options'},
        autoindex_on=False,
    ), _TIER2_GOOD, 99),
    ('C_legacy_present', dict(
        server_tokens='off', ssl_protocols=['TLSv1', 'TLSv1.2'], has_ssl_certificate=True,
        headers_present={'strict-transport-security', 'x-frame-options', 'x-content-type-options'},
        autoindex_on=False,
    ), _TIER2_GOOD, 83),
    ('C2_legacy_no_modern', dict(
        server_tokens='off', ssl_protocols=['TLSv1', 'TLSv1.1'], has_ssl_certificate=True,
        headers_present={'strict-transport-security', 'x-frame-options', 'x-content-type-options'},
        autoindex_on=False,
    ), _TIER2_GOOD, 77),
    ('D_no_headers', dict(
        server_tokens='off', ssl_protocols=['TLSv1.3'], has_ssl_certificate=True,
        headers_present=set(), autoindex_on=False,
    ), _TIER2_GOOD, 90),
    ('E_bad_config_bad_tls', dict(
        server_tokens='on', ssl_protocols=['TLSv1', 'TLSv1.1'], has_ssl_certificate=True,
        headers_present={'x-frame-options', 'x-content-type-options'}, autoindex_on=True,
    ), _TIER2_BAD, 20),
    ('F_no_tls_at_all', dict(
        server_tokens='off', ssl_protocols=[], has_ssl_certificate=False,
        headers_present={'x-frame-options', 'x-content-type-options'}, autoindex_on=False,
    ), _TIER2_NO_TLS_NO_HEADERS, 54),
    ('G_realistic_mixed', dict(
        server_tokens='on', ssl_protocols=['TLSv1.2'], has_ssl_certificate=True,
        headers_present={'x-frame-options', 'x-content-type-options'}, autoindex_on=False,
    ), _TIER2_BAD, 51),
])
def test_synthetic_scenario_matches_spec(name, legacy_kwargs, tier2_conf, expected_score):
    legacy = _build_components(_cfg(**legacy_kwargs))
    tier2 = _build_tier2_components(_cfg_v2(tier2_conf))
    result = weighted_score(legacy + tier2)
    assert result['score'] == expected_score, (
        f'scenario {name}: expected {expected_score}, got {result["score"]} - '
        f'check docs/checks/nginx_hardening.md section 8.3 for the weight model'
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


# ===========================================================================
# Tier-2-specific synthetic scenarios (worst-case aggregation, N/A/UNKNOWN
# redistribution, lowest-weight visibility) - complements the legacy-focused
# A-G scenarios above with cases that specifically exercise the Tier-2
# controls' own aggregation and applicability logic.
# ===========================================================================

def test_synthetic_single_critical_legacy_fail_visible_but_not_catastrophic():
    # tls_legacy_disabled (0.16, the highest single Tier-1 weight) failing
    # alone should produce a visible but proportionate drop, not near-zero.
    legacy_kwargs = dict(
        server_tokens='off', ssl_protocols=['TLSv1', 'TLSv1.3'], has_ssl_certificate=True,
        headers_present={'strict-transport-security', 'x-frame-options', 'x-content-type-options'},
        autoindex_on=False,
    )
    legacy = _build_components(_cfg(**legacy_kwargs))
    tier2 = _build_tier2_components(_cfg_v2(_TIER2_GOOD))
    result = weighted_score(legacy + tier2)
    assert 80 <= result['score'] < 100


def test_synthetic_single_critical_tier2_fail_visible_but_not_catastrophic():
    # tls_004_ciphers (0.12) failing alone, everything else hardened.
    legacy = _build_components(_cfg(
        server_tokens='off', ssl_protocols=['TLSv1.3'], has_ssl_certificate=True,
        headers_present={'strict-transport-security', 'x-frame-options', 'x-content-type-options'},
        autoindex_on=False,
    ))
    tier2_conf = '''http {
        add_header Content-Security-Policy "default-src 'self'";
        add_header Referrer-Policy no-referrer;
        add_header Permissions-Policy "geolocation=()";
        server {
            listen 443 ssl;
            ssl_ciphers ALL:RC4;
            client_max_body_size 10m;
            server_name example.com;
        }
        server {
            listen 80;
            server_name example.com;
            return 301 https://$host$request_uri;
        }
    }'''
    tier2 = _build_tier2_components(_cfg_v2(tier2_conf))
    result = weighted_score(legacy + tier2)
    assert 80 <= result['score'] < 100


def test_synthetic_legacy_only_fail_tier2_all_pass():
    # All 9 legacy FAIL, all 7 Tier-2 PASS - the fully-hardened Tier-2
    # weight (0.365) alone should keep this well above zero.
    legacy = _build_components(_cfg(
        server_tokens='on', ssl_protocols=['TLSv1', 'TLSv1.1'], has_ssl_certificate=True,
        headers_present=set(), autoindex_on=True,
    ))
    tier2 = _build_tier2_components(_cfg_v2(_TIER2_GOOD))
    result = weighted_score(legacy + tier2)
    assert 40 < result['score'] < 60


def test_synthetic_tier2_only_fail_legacy_all_pass():
    # All 7 Tier-2 FAIL, all 9 legacy PASS.
    legacy = _build_components(_cfg())
    tier2 = _build_tier2_components(_cfg_v2(_TIER2_BAD))
    result = weighted_score(legacy + tier2)
    assert 50 < result['score'] < 75


def test_synthetic_lowest_weight_control_still_visible():
    # exp_003_default_server (0.04, the lowest Tier-2 weight) failing
    # alone must still produce a measurable, non-zero drop.
    legacy = _build_components(_cfg())
    tier2_conf = '''http {
        add_header Content-Security-Policy "default-src 'self'";
        add_header Referrer-Policy no-referrer;
        add_header Permissions-Policy "geolocation=()";
        server {
            listen 443 ssl;
            ssl_ciphers ALL:@SECLEVEL=2;
            client_max_body_size 10m;
            server_name a.example.com;
        }
        server {
            listen 443 ssl;
            server_name b.example.com;
        }
        server {
            listen 80;
            server_name a.example.com;
            return 301 https://$host$request_uri;
        }
    }'''
    tier2 = _build_tier2_components(_cfg_v2(tier2_conf))
    result = weighted_score(legacy + tier2)
    assert 90 <= result['score'] < 100
    exp003 = _by_name(tier2, 'exp_003_default_server')
    assert exp003.score == 0
    assert exp003.finding_id == 'NGX-EXP-003'


def test_synthetic_http_only_vm_shaped_config():
    # Mirrors this project's own real VM baseline shape: single HTTP-only
    # server, no TLS, no security headers, no client_max_body_size set
    # (resolves to nginx's honest 1m default -> PASS). This is the exact
    # shape docs/checks/nginx_hardening.md Milestone 1 captured.
    #
    # server_tokens='on' here (not the VM's actual 'build') because legacy
    # NginxConfig.server_tokens doesn't have a 'build' state distinct from
    # 'on' - that's a known Tier-1 parser gap (section 7's "server_tokens
    # build" note), tracked separately from this Tier-2 weight-model test.
    legacy = _build_components(_cfg(
        server_tokens='on', ssl_protocols=[], has_ssl_certificate=False,
        headers_present=set(), autoindex_on=False,
    ))
    tier2 = _build_tier2_components(_cfg_v2(_TIER2_NO_TLS_NO_HEADERS))
    result = weighted_score(legacy + tier2)
    # Not asserting an exact score here (that's what the real VM baseline
    # regression tests in test_nginx_hardening_tier2.py are for) - this
    # confirms the shape doesn't error and lands in a plausible low-but-
    # not-zero range, consistent with the real VM's observed score of 53.
    assert 30 < result['score'] < 70
