"""
Tests for the Tier-2 nginx_hardening controls (docs/checks/nginx_hardening.md
section 7 + section 8.3's weight model) — currently just NGX-TLS-004, the
first end-to-end control (parser -> resolver -> per-server verdict ->
multi-vhost aggregation -> Component). Extended as each remaining Tier-2
control lands.

Separate from test_nginx_hardening.py/test_nginx_hardening_components.py
(Tier-1) so Tier-2 fixtures and Tier-1 fixtures don't get tangled together -
mirrors the parser/resolvers split (test_nginx_config_v2.py,
test_nginx_v2_resolvers.py).
"""

from __future__ import annotations

from netaudit_pkg.nginx_config_v2 import parse_nginx_config_v2
from netaudit_pkg.checks.nginx_hardening import (
    _aggregate_server_verdicts,
    _c_hdr_004_csp,
    _c_hdr_005_referrer_policy,
    _c_hdr_006_permissions_policy,
    _c_tls_004_ciphers,
    _is_structurally_trivial_csp,
    _parse_permissions_policy,
    _verdict_hdr_004_csp,
    _verdict_hdr_005_referrer_policy,
    _verdict_hdr_006_permissions_policy,
    _verdict_tls_004_ciphers,
)


# ===========================================================================
# _aggregate_server_verdicts() — shared multi-vhost aggregation helper
# ===========================================================================

def test_aggregate_all_pass():
    result = _aggregate_server_verdicts([('PASS', 'a'), ('PASS', 'b')])
    assert result == ('PASS', 'a; b')


def test_aggregate_any_fail_wins():
    result = _aggregate_server_verdicts([('PASS', 'a'), ('FAIL', 'b')])
    assert result[0] == 'FAIL'
    assert result[1] == 'b'


def test_aggregate_unknown_beats_pass_when_no_fail():
    result = _aggregate_server_verdicts([('UNKNOWN', 'a'), ('PASS', 'b')])
    assert result[0] == 'UNKNOWN'
    assert result[1] == 'a'


def test_aggregate_fail_beats_unknown():
    result = _aggregate_server_verdicts([('UNKNOWN', 'a'), ('FAIL', 'b')])
    assert result[0] == 'FAIL'


def test_aggregate_na_excluded_leaves_pass():
    result = _aggregate_server_verdicts([('N/A', 'a'), ('PASS', 'b')])
    assert result == ('PASS', 'b')


def test_aggregate_na_excluded_leaves_fail():
    result = _aggregate_server_verdicts([('N/A', 'a'), ('FAIL', 'b')])
    assert result[0] == 'FAIL'


def test_aggregate_all_na_is_na():
    result = _aggregate_server_verdicts([('N/A', 'a'), ('N/A', 'b')])
    assert result == ('N/A', 'no applicable server block')


def test_aggregate_single_server_pass():
    result = _aggregate_server_verdicts([('PASS', 'only')])
    assert result == ('PASS', 'only')


def test_aggregate_empty_list_is_na():
    result = _aggregate_server_verdicts([])
    assert result == ('N/A', 'no applicable server block')


# ===========================================================================
# NGX-TLS-004 — per-server verdict fixtures
# (docs/checks/nginx_hardening.md section 7's finalized semantics)
# ===========================================================================

def _verdict_for(cipher_str: str) -> tuple[str, str]:
    conf = f'http {{ server {{ listen 443 ssl; ssl_ciphers {cipher_str}; }} }}'
    cfg = parse_nginx_config_v2(conf)
    return _verdict_tls_004_ciphers(cfg.servers[0], cfg.http_directives)


def test_tls004_no_ssl_listen_is_na():
    cfg = parse_nginx_config_v2('http { server { listen 80; } }')
    verdict, _ = _verdict_tls_004_ciphers(cfg.servers[0], cfg.http_directives)
    assert verdict == 'N/A'


def test_tls004_nginx_default_alias_is_unknown():
    # nginx's own compiled-in default (HIGH:!aNULL:!MD5) contains a bare
    # HIGH alias — per the spec's explicit ruling, this is NOT automatically
    # PASS just because it's the documented nginx default.
    verdict, _ = _verdict_for('HIGH:!aNULL:!MD5')
    assert verdict == 'UNKNOWN'


def test_tls004_enull_is_fail():
    verdict, evidence = _verdict_for('ALL:eNULL')
    assert verdict == 'FAIL'
    assert 'eNULL' in evidence


def test_tls004_null_is_fail():
    verdict, _ = _verdict_for('ALL:NULL')
    assert verdict == 'FAIL'


def test_tls004_export_is_fail():
    verdict, _ = _verdict_for('ALL:EXPORT')
    assert verdict == 'FAIL'


def test_tls004_bare_all_with_exclusions_still_unknown():
    # Not sufficient proof per spec: ALL:!aNULL:!eNULL:!EXPORT doesn't
    # prove absence of RSA key transport, DH/ECDH without forward secrecy,
    # CBC, etc. — must NOT be PASS.
    verdict, _ = _verdict_for('ALL:!aNULL:!eNULL:!EXPORT')
    assert verdict == 'UNKNOWN'


def test_tls004_bare_high_is_unknown():
    verdict, _ = _verdict_for('HIGH')
    assert verdict == 'UNKNOWN'


def test_tls004_bare_default_is_unknown():
    verdict, _ = _verdict_for('DEFAULT')
    assert verdict == 'UNKNOWN'


def test_tls004_seclevel_2_is_pass():
    verdict, evidence = _verdict_for('ALL:@SECLEVEL=2')
    assert verdict == 'PASS'
    assert 'SECLEVEL=2' in evidence


def test_tls004_seclevel_3_is_pass():
    verdict, _ = _verdict_for('ALL:@SECLEVEL=3')
    assert verdict == 'PASS'


def test_tls004_seclevel_1_is_unknown():
    verdict, _ = _verdict_for('ALL:@SECLEVEL=1')
    assert verdict == 'UNKNOWN'


def test_tls004_seclevel_0_is_unknown():
    verdict, _ = _verdict_for('ALL:@SECLEVEL=0')
    assert verdict == 'UNKNOWN'


def test_tls004_seclevel_2_with_later_forbidden_inclusion_is_fail():
    verdict, evidence = _verdict_for('ALL:@SECLEVEL=2:RC4')
    assert verdict == 'FAIL'
    assert 'RC4' in evidence


def test_tls004_seclevel_2_with_explicit_exclusion_is_pass():
    verdict, _ = _verdict_for('ALL:@SECLEVEL=2:!RC4')
    assert verdict == 'PASS'


def test_tls004_exclusion_token_never_matches_forbidden_class():
    # !RC4 must not be misread as including RC4 — the '!' prefix check
    # must run before the forbidden-class membership check.
    verdict, _ = _verdict_for('ALL:!RC4:!MD5:!DES:!3DES:!aNULL:!eNULL:!EXPORT:@SECLEVEL=2')
    assert verdict == 'PASS'


def test_tls004_krsa_is_fail_but_bare_rsa_in_suite_name_would_not_be():
    # kRSA (key exchange) is forbidden per OWASP; this fixture only tests
    # the token itself, not a full suite name like ECDHE-RSA-... (the
    # resolver operates on ':' split tokens of the cipher STRING grammar,
    # not on OpenSSL suite names, so this distinction doesn't require
    # special-casing here — it falls out of what a real ssl_ciphers value
    # looks like).
    verdict, evidence = _verdict_for('ALL:kRSA')
    assert verdict == 'FAIL'
    assert 'kRSA' in evidence


def test_tls004_variable_in_value_is_unknown():
    conf = 'http { server { listen 443 ssl; ssl_ciphers $custom_ciphers; } }'
    cfg = parse_nginx_config_v2(conf)
    verdict, evidence = _verdict_tls_004_ciphers(cfg.servers[0], cfg.http_directives)
    assert verdict == 'UNKNOWN'
    assert 'variable' in evidence


def test_tls004_evidence_includes_server_name():
    conf = 'http { server { listen 443 ssl; server_name example.com; ssl_ciphers ALL:RC4; } }'
    cfg = parse_nginx_config_v2(conf)
    verdict, evidence = _verdict_tls_004_ciphers(cfg.servers[0], cfg.http_directives)
    assert 'example.com' in evidence


def test_tls004_evidence_falls_back_to_listen_when_no_server_name():
    conf = 'http { server { listen 443 ssl; ssl_ciphers ALL:RC4; } }'
    cfg = parse_nginx_config_v2(conf)
    verdict, evidence = _verdict_tls_004_ciphers(cfg.servers[0], cfg.http_directives)
    assert '443' in evidence


# ===========================================================================
# _c_tls_004_ciphers() — Component-level, weight, and multi-vhost aggregation
# ===========================================================================

def test_tls004_component_weight_is_012():
    cfg = parse_nginx_config_v2('http { server { listen 80; } }')
    comp = _c_tls_004_ciphers(cfg)
    assert comp.weight == 0.12


def test_tls004_component_no_servers_at_all_is_na():
    cfg = parse_nginx_config_v2('http { }')
    comp = _c_tls_004_ciphers(cfg)
    assert comp.applicable is False


def test_tls004_component_pass_scores_100():
    conf = 'http { server { listen 443 ssl; ssl_ciphers ALL:@SECLEVEL=2; } }'
    cfg = parse_nginx_config_v2(conf)
    comp = _c_tls_004_ciphers(cfg)
    assert comp.score == 100
    assert comp.finding_id is None


def test_tls004_component_fail_scores_0_with_finding_id():
    conf = 'http { server { listen 443 ssl; ssl_ciphers ALL:RC4; } }'
    cfg = parse_nginx_config_v2(conf)
    comp = _c_tls_004_ciphers(cfg)
    assert comp.score == 0
    assert comp.finding_id == 'NGX-TLS-004'
    assert comp.reason is not None


def test_tls004_component_unknown_is_not_applicable_no_finding():
    conf = 'http { server { listen 443 ssl; ssl_ciphers HIGH; } }'
    cfg = parse_nginx_config_v2(conf)
    comp = _c_tls_004_ciphers(cfg)
    assert comp.applicable is False
    assert comp.finding_id is None


def test_tls004_multivhost_one_fail_among_pass_aggregates_fail():
    conf = '''
    http {
        server {
            listen 443 ssl;
            server_name good.example.com;
            ssl_ciphers ALL:@SECLEVEL=2;
        }
        server {
            listen 443 ssl;
            server_name bad.example.com;
            ssl_ciphers ALL:RC4;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    comp = _c_tls_004_ciphers(cfg)
    assert comp.score == 0
    assert comp.finding_id == 'NGX-TLS-004'
    assert 'bad.example.com' in comp.reason


def test_tls004_multivhost_na_plus_pass_aggregates_pass():
    conf = '''
    http {
        server {
            listen 80;
            server_name httponly.example.com;
        }
        server {
            listen 443 ssl;
            server_name secure.example.com;
            ssl_ciphers ALL:@SECLEVEL=2;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    comp = _c_tls_004_ciphers(cfg)
    assert comp.score == 100
    assert comp.applicable is True


def test_tls004_multivhost_all_na_is_na():
    conf = 'http { server { listen 80; } server { listen 8080; } }'
    cfg = parse_nginx_config_v2(conf)
    comp = _c_tls_004_ciphers(cfg)
    assert comp.applicable is False


# ===========================================================================
# Real VM baseline regression anchor
# ===========================================================================

VM_BASELINE_CONF = '''
http {
	sendfile on;
	server_tokens build;
	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_prefer_server_ciphers off;
	include /etc/nginx/sites-enabled/*;
}

# configuration file /etc/nginx/sites-enabled/netaudit:
server {
    listen 80;
    server_name 192.168.88.20;
    # listen 443 ssl;
    auth_basic "NetAudit";
    location / {
        proxy_pass http://127.0.0.1:8000;
    }
}
'''


def test_vm_baseline_tls004_is_na_no_tls_at_all():
    cfg = parse_nginx_config_v2(VM_BASELINE_CONF)
    comp = _c_tls_004_ciphers(cfg)
    assert comp.applicable is False
    assert comp.score == 0


# ===========================================================================
# NGX-HDR-004 (Content-Security-Policy) — structural triviality helper
# ===========================================================================

def test_csp_empty_value_is_trivial():
    assert _is_structurally_trivial_csp('') is True


def test_csp_bare_star_is_trivial():
    assert _is_structurally_trivial_csp('default-src *') is True


def test_csp_self_is_not_trivial():
    assert _is_structurally_trivial_csp("default-src 'self'") is False


def test_csp_multiple_directives_all_star_is_trivial():
    assert _is_structurally_trivial_csp('default-src *; script-src *') is True


def test_csp_one_constraining_directive_among_trivial_ones_is_not_trivial():
    assert _is_structurally_trivial_csp("default-src *; script-src 'self'") is False


def test_csp_whitespace_only_is_trivial():
    assert _is_structurally_trivial_csp('   ;  ;  ') is True


# ===========================================================================
# NGX-HDR-004 — per-server verdict
# ===========================================================================

def test_hdr004_absent_is_fail():
    cfg = parse_nginx_config_v2('http { server { listen 80; } }')
    verdict, evidence = _verdict_hdr_004_csp(cfg.servers[0], cfg)
    assert verdict == 'FAIL'
    assert 'absent' in evidence


def test_hdr004_trivial_star_is_fail():
    conf = 'http { server { listen 80; add_header Content-Security-Policy "default-src *"; } }'
    cfg = parse_nginx_config_v2(conf)
    verdict, _ = _verdict_hdr_004_csp(cfg.servers[0], cfg)
    assert verdict == 'FAIL'


def test_hdr004_non_trivial_is_pass():
    conf = '''http { server { listen 80; add_header Content-Security-Policy "default-src 'self'"; } }'''
    cfg = parse_nginx_config_v2(conf)
    verdict, _ = _verdict_hdr_004_csp(cfg.servers[0], cfg)
    assert verdict == 'PASS'


def test_hdr004_variable_is_unknown():
    conf = 'http { server { listen 80; add_header Content-Security-Policy $csp_value; } }'
    cfg = parse_nginx_config_v2(conf)
    verdict, evidence = _verdict_hdr_004_csp(cfg.servers[0], cfg)
    assert verdict == 'UNKNOWN'
    assert 'variable' in evidence


def test_hdr004_applies_without_ssl_listen():
    # Security headers apply regardless of TLS status — this control is
    # not gated on `ssl`, unlike NGX-TLS-004.
    conf = '''http { server { listen 80; add_header Content-Security-Policy "default-src 'self'"; } }'''
    cfg = parse_nginx_config_v2(conf)
    verdict, _ = _verdict_hdr_004_csp(cfg.servers[0], cfg)
    assert verdict == 'PASS'


# ===========================================================================
# NGX-HDR-004 — all-or-nothing inheritance (shared model, resolvers.py)
# ===========================================================================

def test_hdr004_server_own_add_header_blocks_http_csp_inheritance():
    # server defines an add_header (for a DIFFERENT header) — per the
    # all-or-nothing rule, http's CSP must NOT be inherited.
    conf = '''
    http {
        add_header Content-Security-Policy "default-src 'self'";
        server {
            listen 80;
            add_header X-Custom test;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    verdict, evidence = _verdict_hdr_004_csp(cfg.servers[0], cfg)
    assert verdict == 'FAIL'
    assert 'absent' in evidence


def test_hdr004_server_silent_inherits_http_csp():
    conf = '''
    http {
        add_header Content-Security-Policy "default-src 'self'";
        server {
            listen 80;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    verdict, _ = _verdict_hdr_004_csp(cfg.servers[0], cfg)
    assert verdict == 'PASS'


def test_hdr004_multiple_add_header_same_level_last_wins():
    conf = '''
    http {
        server {
            listen 80;
            add_header Content-Security-Policy "default-src *";
            add_header Content-Security-Policy "default-src 'self'";
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    verdict, _ = _verdict_hdr_004_csp(cfg.servers[0], cfg)
    assert verdict == 'PASS'  # last (non-trivial) one wins


# ===========================================================================
# _c_hdr_004_csp() — Component-level, weight, and multi-vhost aggregation
# ===========================================================================

def test_hdr004_component_weight_is_0055():
    cfg = parse_nginx_config_v2('http { server { listen 80; } }')
    comp = _c_hdr_004_csp(cfg)
    assert comp.weight == 0.055


def test_hdr004_component_pass_scores_100():
    conf = '''http { server { listen 80; add_header Content-Security-Policy "default-src 'self'"; } }'''
    cfg = parse_nginx_config_v2(conf)
    comp = _c_hdr_004_csp(cfg)
    assert comp.score == 100
    assert comp.finding_id is None


def test_hdr004_component_fail_scores_0_with_finding_id():
    cfg = parse_nginx_config_v2('http { server { listen 80; } }')
    comp = _c_hdr_004_csp(cfg)
    assert comp.score == 0
    assert comp.finding_id == 'NGX-HDR-004'
    assert comp.reason is not None


def test_hdr004_component_unknown_is_not_applicable_no_finding():
    conf = 'http { server { listen 80; add_header Content-Security-Policy $csp_value; } }'
    cfg = parse_nginx_config_v2(conf)
    comp = _c_hdr_004_csp(cfg)
    assert comp.applicable is False
    assert comp.finding_id is None


def test_hdr004_multivhost_mixed_pass_fail_aggregates_fail():
    conf = '''
    http {
        server {
            listen 80;
            server_name good.example.com;
            add_header Content-Security-Policy "default-src 'self'";
        }
        server {
            listen 80;
            server_name bad.example.com;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    comp = _c_hdr_004_csp(cfg)
    assert comp.score == 0
    assert comp.finding_id == 'NGX-HDR-004'
    assert 'bad.example.com' in comp.reason


def test_hdr004_multivhost_all_pass_aggregates_pass():
    conf = '''
    http {
        server {
            listen 80;
            server_name a.example.com;
            add_header Content-Security-Policy "default-src 'self'";
        }
        server {
            listen 443 ssl;
            server_name b.example.com;
            add_header Content-Security-Policy "default-src 'self'";
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    comp = _c_hdr_004_csp(cfg)
    assert comp.score == 100
    assert comp.finding_id is None


def test_vm_baseline_hdr004_is_fail_no_csp_anywhere():
    cfg = parse_nginx_config_v2(VM_BASELINE_CONF)
    comp = _c_hdr_004_csp(cfg)
    assert comp.score == 0
    assert comp.finding_id == 'NGX-HDR-004'


# ===========================================================================
# NGX-HDR-005 (Referrer-Policy) — all 8 W3C enum values, per-server verdict
# ===========================================================================

_VALID_REFERRER_VALUES = [
    'no-referrer',
    'no-referrer-when-downgrade',
    'same-origin',
    'origin',
    'strict-origin',
    'origin-when-cross-origin',
    'strict-origin-when-cross-origin',
    'unsafe-url',
]


def _hdr005_verdict_for(value: str) -> tuple[str, str]:
    conf = f'http {{ server {{ listen 80; add_header Referrer-Policy {value}; }} }}'
    cfg = parse_nginx_config_v2(conf)
    return _verdict_hdr_005_referrer_policy(cfg.servers[0], cfg)


def test_hdr005_no_referrer_is_pass():
    verdict, _ = _hdr005_verdict_for('no-referrer')
    assert verdict == 'PASS'


def test_hdr005_no_referrer_when_downgrade_is_pass():
    verdict, _ = _hdr005_verdict_for('no-referrer-when-downgrade')
    assert verdict == 'PASS'


def test_hdr005_same_origin_is_pass():
    verdict, _ = _hdr005_verdict_for('same-origin')
    assert verdict == 'PASS'


def test_hdr005_origin_is_pass():
    verdict, _ = _hdr005_verdict_for('origin')
    assert verdict == 'PASS'


def test_hdr005_strict_origin_is_pass():
    verdict, _ = _hdr005_verdict_for('strict-origin')
    assert verdict == 'PASS'


def test_hdr005_origin_when_cross_origin_is_pass():
    verdict, _ = _hdr005_verdict_for('origin-when-cross-origin')
    assert verdict == 'PASS'


def test_hdr005_strict_origin_when_cross_origin_is_pass():
    verdict, _ = _hdr005_verdict_for('strict-origin-when-cross-origin')
    assert verdict == 'PASS'


def test_hdr005_unsafe_url_is_pass_no_security_grading():
    # Deliberate: docs/checks/nginx_hardening.md section 7 explicitly
    # decided NGX-HDR-005 does not grade security strength between valid
    # W3C tokens. unsafe-url is weaker than strict-origin in practice,
    # but this control only checks presence + syntactic validity.
    verdict, _ = _hdr005_verdict_for('unsafe-url')
    assert verdict == 'PASS'


def test_hdr005_all_eight_valid_values_are_exhaustively_covered():
    assert len(_VALID_REFERRER_VALUES) == 8
    for value in _VALID_REFERRER_VALUES:
        verdict, _ = _hdr005_verdict_for(value)
        assert verdict == 'PASS', f'{value} should be PASS'


def test_hdr005_absent_is_fail():
    cfg = parse_nginx_config_v2('http { server { listen 80; } }')
    verdict, evidence = _verdict_hdr_005_referrer_policy(cfg.servers[0], cfg)
    assert verdict == 'FAIL'
    assert 'absent' in evidence


def test_hdr005_typo_invalid_literal_is_fail():
    # Per W3C: "unknown policy values will be ignored" — a typo is
    # functionally equivalent to absence, so it gets FAIL, not UNKNOWN.
    verdict, evidence = _hdr005_verdict_for('strict-orgin')
    assert verdict == 'FAIL'
    assert 'not a valid W3C token' in evidence


def test_hdr005_arbitrary_garbage_is_fail():
    verdict, _ = _hdr005_verdict_for('some-made-up-policy')
    assert verdict == 'FAIL'


def test_hdr005_variable_is_unknown():
    conf = 'http { server { listen 80; add_header Referrer-Policy $policy_var; } }'
    cfg = parse_nginx_config_v2(conf)
    verdict, evidence = _verdict_hdr_005_referrer_policy(cfg.servers[0], cfg)
    assert verdict == 'UNKNOWN'
    assert 'variable' in evidence


def test_hdr005_applies_without_ssl_listen():
    conf = 'http { server { listen 80; add_header Referrer-Policy no-referrer; } }'
    cfg = parse_nginx_config_v2(conf)
    verdict, _ = _verdict_hdr_005_referrer_policy(cfg.servers[0], cfg)
    assert verdict == 'PASS'


# ===========================================================================
# NGX-HDR-005 — all-or-nothing inheritance
# ===========================================================================

def test_hdr005_server_own_add_header_blocks_http_inheritance():
    conf = '''
    http {
        add_header Referrer-Policy no-referrer;
        server {
            listen 80;
            add_header X-Custom test;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    verdict, evidence = _verdict_hdr_005_referrer_policy(cfg.servers[0], cfg)
    assert verdict == 'FAIL'
    assert 'absent' in evidence


def test_hdr005_server_silent_inherits_http_value():
    conf = '''
    http {
        add_header Referrer-Policy no-referrer;
        server {
            listen 80;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    verdict, _ = _verdict_hdr_005_referrer_policy(cfg.servers[0], cfg)
    assert verdict == 'PASS'


# ===========================================================================
# _c_hdr_005_referrer_policy() — Component-level, weight, multi-vhost
# ===========================================================================

def test_hdr005_component_weight_is_002():
    cfg = parse_nginx_config_v2('http { server { listen 80; } }')
    comp = _c_hdr_005_referrer_policy(cfg)
    assert comp.weight == 0.02


def test_hdr005_component_pass_scores_100():
    conf = 'http { server { listen 80; add_header Referrer-Policy no-referrer; } }'
    cfg = parse_nginx_config_v2(conf)
    comp = _c_hdr_005_referrer_policy(cfg)
    assert comp.score == 100
    assert comp.finding_id is None


def test_hdr005_component_fail_scores_0_with_finding_id():
    cfg = parse_nginx_config_v2('http { server { listen 80; } }')
    comp = _c_hdr_005_referrer_policy(cfg)
    assert comp.score == 0
    assert comp.finding_id == 'NGX-HDR-005'
    assert comp.reason is not None


def test_hdr005_component_unknown_is_not_applicable_no_finding():
    conf = 'http { server { listen 80; add_header Referrer-Policy $v; } }'
    cfg = parse_nginx_config_v2(conf)
    comp = _c_hdr_005_referrer_policy(cfg)
    assert comp.applicable is False
    assert comp.finding_id is None


def test_hdr005_multivhost_mixed_pass_fail_aggregates_fail():
    conf = '''
    http {
        server {
            listen 80;
            server_name good.example.com;
            add_header Referrer-Policy no-referrer;
        }
        server {
            listen 80;
            server_name bad.example.com;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    comp = _c_hdr_005_referrer_policy(cfg)
    assert comp.score == 0
    assert comp.finding_id == 'NGX-HDR-005'
    assert 'bad.example.com' in comp.reason


def test_vm_baseline_hdr005_is_fail_no_referrer_policy_anywhere():
    cfg = parse_nginx_config_v2(VM_BASELINE_CONF)
    comp = _c_hdr_005_referrer_policy(cfg)
    assert comp.score == 0
    assert comp.finding_id == 'NGX-HDR-005'


# ===========================================================================
# NGX-HDR-006 (Permissions-Policy) — feature=allowlist parsing
# ===========================================================================

def test_pp_parse_empty_allowlist():
    assert _parse_permissions_policy('geolocation=()') == {'geolocation': '()'}


def test_pp_parse_self_allowlist():
    assert _parse_permissions_policy('geolocation=(self)') == {'geolocation': '(self)'}


def test_pp_parse_bare_wildcard():
    assert _parse_permissions_policy('geolocation=*') == {'geolocation': '*'}


def test_pp_parse_multiple_features():
    result = _parse_permissions_policy('geolocation=(self), camera=()')
    assert result == {'geolocation': '(self)', 'camera': '()'}


def test_pp_parse_invalid_syntax_returns_none():
    assert _parse_permissions_policy('garbage no equals sign') is None


def test_pp_parse_empty_string_returns_none():
    assert _parse_permissions_policy('') is None


def test_pp_parse_origin_list():
    result = _parse_permissions_policy('geolocation=(self "https://example.com")')
    assert result == {'geolocation': '(self "https://example.com")'}


# ===========================================================================
# NGX-HDR-006 — per-server verdict
# ===========================================================================

def _hdr006_verdict_for(value: str) -> tuple[str, str]:
    conf = f'http {{ server {{ listen 80; add_header Permissions-Policy "{value}"; }} }}'
    cfg = parse_nginx_config_v2(conf)
    return _verdict_hdr_006_permissions_policy(cfg.servers[0], cfg)


def test_hdr006_absent_is_fail():
    cfg = parse_nginx_config_v2('http { server { listen 80; } }')
    verdict, evidence = _verdict_hdr_006_permissions_policy(cfg.servers[0], cfg)
    assert verdict == 'FAIL'
    assert 'absent' in evidence


def test_hdr006_invalid_syntax_is_fail():
    verdict, evidence = _hdr006_verdict_for('not valid syntax at all')
    assert verdict == 'FAIL'
    assert 'not valid feature=allowlist syntax' in evidence


def test_hdr006_empty_allowlist_is_pass():
    # geolocation=() — explicit deny-all is a non-wildcard, constraining
    # allowlist per section 7's semantics.
    verdict, _ = _hdr006_verdict_for('geolocation=()')
    assert verdict == 'PASS'


def test_hdr006_self_allowlist_is_pass():
    verdict, _ = _hdr006_verdict_for('geolocation=(self)')
    assert verdict == 'PASS'


def test_hdr006_bare_wildcard_is_unknown():
    # Valid syntax, but this project cannot prove * constrains anything —
    # per section 7's explicit ruling, this does NOT earn PASS.
    verdict, evidence = _hdr006_verdict_for('geolocation=*')
    assert verdict == 'UNKNOWN'
    assert 'wildcard' in evidence


def test_hdr006_mixed_wildcard_and_restricted_is_pass():
    # geolocation=*, camera=() — credit is given for the restricted
    # feature even though another feature is unrestricted, per section
    # 7's decision not to build a per-feature required-list.
    verdict, _ = _hdr006_verdict_for('geolocation=*, camera=()')
    assert verdict == 'PASS'


def test_hdr006_variable_is_unknown():
    conf = 'http { server { listen 80; add_header Permissions-Policy $pp_value; } }'
    cfg = parse_nginx_config_v2(conf)
    verdict, evidence = _verdict_hdr_006_permissions_policy(cfg.servers[0], cfg)
    assert verdict == 'UNKNOWN'
    assert 'variable' in evidence


def test_hdr006_applies_without_ssl_listen():
    verdict, _ = _hdr006_verdict_for('geolocation=()')
    assert verdict == 'PASS'


# ===========================================================================
# NGX-HDR-006 — all-or-nothing inheritance
# ===========================================================================

def test_hdr006_server_own_add_header_blocks_http_inheritance():
    conf = '''
    http {
        add_header Permissions-Policy "geolocation=()";
        server {
            listen 80;
            add_header X-Custom test;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    verdict, evidence = _verdict_hdr_006_permissions_policy(cfg.servers[0], cfg)
    assert verdict == 'FAIL'
    assert 'absent' in evidence


def test_hdr006_server_silent_inherits_http_value():
    conf = '''
    http {
        add_header Permissions-Policy "geolocation=()";
        server {
            listen 80;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    verdict, _ = _verdict_hdr_006_permissions_policy(cfg.servers[0], cfg)
    assert verdict == 'PASS'


# ===========================================================================
# _c_hdr_006_permissions_policy() — Component-level, weight, multi-vhost
# ===========================================================================

def test_hdr006_component_weight_is_002():
    cfg = parse_nginx_config_v2('http { server { listen 80; } }')
    comp = _c_hdr_006_permissions_policy(cfg)
    assert comp.weight == 0.02


def test_hdr006_component_pass_scores_100():
    conf = 'http { server { listen 80; add_header Permissions-Policy "geolocation=()"; } }'
    cfg = parse_nginx_config_v2(conf)
    comp = _c_hdr_006_permissions_policy(cfg)
    assert comp.score == 100
    assert comp.finding_id is None


def test_hdr006_component_fail_scores_0_with_finding_id():
    cfg = parse_nginx_config_v2('http { server { listen 80; } }')
    comp = _c_hdr_006_permissions_policy(cfg)
    assert comp.score == 0
    assert comp.finding_id == 'NGX-HDR-006'
    assert comp.reason is not None


def test_hdr006_component_unknown_is_not_applicable_no_finding():
    conf = 'http { server { listen 80; add_header Permissions-Policy "geolocation=*"; } }'
    cfg = parse_nginx_config_v2(conf)
    comp = _c_hdr_006_permissions_policy(cfg)
    assert comp.applicable is False
    assert comp.finding_id is None


def test_hdr006_multivhost_mixed_pass_fail_aggregates_fail():
    conf = '''
    http {
        server {
            listen 80;
            server_name good.example.com;
            add_header Permissions-Policy "geolocation=()";
        }
        server {
            listen 80;
            server_name bad.example.com;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    comp = _c_hdr_006_permissions_policy(cfg)
    assert comp.score == 0
    assert comp.finding_id == 'NGX-HDR-006'
    assert 'bad.example.com' in comp.reason


def test_vm_baseline_hdr006_is_fail_no_permissions_policy_anywhere():
    cfg = parse_nginx_config_v2(VM_BASELINE_CONF)
    comp = _c_hdr_006_permissions_policy(cfg)
    assert comp.score == 0
    assert comp.finding_id == 'NGX-HDR-006'
