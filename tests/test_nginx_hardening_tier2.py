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
    _c_tls_004_ciphers,
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
