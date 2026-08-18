"""Tests for Tier-2 nginx_hardening Finding generation — the fix for the
Control -> Finding contract violation confirmed in
test_tier2_failing_components_have_matching_findings /
test_tier2_specific_finding_ids_present_when_failing
(test_nginx_hardening.py). Written test-first: this file exercises the
not-yet-written Tier-2 finding-generation function directly, one test
per contract, before wiring it into audit_nginx_hardening().

Each of the 7 Tier-2 controls got its own individual contract review
(project session notes, 2026-08-18) — severities are NOT copied
mechanically across controls. See each test's docstring for that
control's specific severity precedent.

Uses parse_nginx_config_v2() on raw config text (same pattern as
test_nginx_hardening_tier2.py) rather than constructing
ServerBlock/NginxConfigV2 by hand, so fixtures exercise the real parser
too.
"""

from __future__ import annotations

from netaudit_pkg.nginx_config_v2 import parse_nginx_config_v2
from netaudit_pkg.checks.nginx_hardening import (
    _build_tier2_components,
    build_tier2_findings,
)


def _find(findings: list[dict], finding_id: str) -> dict | None:
    return next((f for f in findings if f.get('id') == finding_id), None)


# ===========================================================================
# NGX-HDR-004 — Content-Security-Policy (reference contract)
# ===========================================================================

def test_hdr004_fail_produces_finding():
    conf = '''
    http {
        server {
            listen 80;
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)

    f = _find(findings, 'NGX-HDR-004')
    assert f is not None
    assert f['severity'] == 'medium'
    assert f['title'] == 'Content-Security-Policy is missing or not restrictive'
    assert 'Content-Security-Policy absent' in f['detail']
    assert 'Content-Security-Policy absent' in f['evidence']
    assert 'CSP' in f['recommendation'] or 'Content-Security-Policy' in f['recommendation']


def test_hdr004_pass_produces_no_finding():
    conf = '''
    http {
        add_header Content-Security-Policy "default-src 'self'";
        server {
            listen 80;
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)
    assert _find(findings, 'NGX-HDR-004') is None


# ===========================================================================
# NGX-HDR-005 — Referrer-Policy
# severity: 'low' — narrow-scope protection, same class as the existing
# X-Frame-Options/X-Content-Type-Options 'low' findings, not HSTS/CSP's
# broader class. Lowest Tier-2 header weight (0.02).
# ===========================================================================

def test_hdr005_fail_produces_finding():
    conf = '''
    http {
        server {
            listen 80;
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)

    f = _find(findings, 'NGX-HDR-005')
    assert f is not None
    assert f['severity'] == 'low'
    assert f['title'] == 'Referrer-Policy is missing or invalid'
    assert 'Referrer-Policy absent' in f['detail']


def test_hdr005_pass_produces_no_finding():
    conf = '''
    http {
        add_header Referrer-Policy no-referrer;
        server {
            listen 80;
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)
    assert _find(findings, 'NGX-HDR-005') is None


# ===========================================================================
# NGX-HDR-006 — Permissions-Policy
# severity: 'low' — same reasoning/weight class as NGX-HDR-005.
# ===========================================================================

def test_hdr006_fail_produces_finding():
    conf = '''
    http {
        server {
            listen 80;
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)

    f = _find(findings, 'NGX-HDR-006')
    assert f is not None
    assert f['severity'] == 'low'
    assert f['title'] == 'Permissions-Policy is missing or invalid'
    assert 'Permissions-Policy absent' in f['detail']


def test_hdr006_pass_produces_no_finding():
    conf = '''
    http {
        add_header Permissions-Policy "geolocation=()";
        server {
            listen 80;
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)
    assert _find(findings, 'NGX-HDR-006') is None


# ===========================================================================
# NGX-CONF-003 — client_max_body_size
# severity: 'medium' — comparable to existing autoindex/server_tokens
# findings; explicit 0 is a documented, direct resource-exhaustion
# exposure (nginx.org), not merely information disclosure.
# ===========================================================================

def test_conf003_fail_produces_finding_for_explicit_zero():
    conf = '''
    http {
        server {
            listen 80;
            client_max_body_size 0;
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)

    f = _find(findings, 'NGX-CONF-003')
    assert f is not None
    assert f['severity'] == 'medium'
    assert f['title'] == 'client_max_body_size is unrestricted or invalid'
    assert 'explicitly 0' in f['detail']


def test_conf003_pass_produces_no_finding():
    conf = '''
    http {
        server {
            listen 80;
            client_max_body_size 10m;
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)
    assert _find(findings, 'NGX-CONF-003') is None


def test_conf003_default_is_pass_no_finding():
    """Directive absent entirely -> nginx's own compiled-in 1m default
    -> PASS, per the control's own documented semantics — no Finding."""
    conf = '''
    http {
        server {
            listen 80;
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)
    assert _find(findings, 'NGX-CONF-003') is None


# ===========================================================================
# NGX-EXP-002 — HTTP -> HTTPS redirect
# severity: 'medium' — no direct existing-finding precedent (genuinely
# new check); reasoned from first principles: HTTPS exists and is
# paired, but not enforced — a real but avoidable exposure window, less
# severe than NGX-EXP-001 (no TLS at all) since the secure endpoint DOES
# exist.
# ===========================================================================

def test_exp002_fail_produces_finding():
    conf = '''
    http {
        server {
            listen 80;
            server_name example.com;
        }
        server {
            listen 443 ssl;
            ssl_certificate /etc/ssl/certs/example.pem;
            server_name example.com;
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)

    f = _find(findings, 'NGX-EXP-002')
    assert f is not None
    assert f['severity'] == 'medium'
    assert f['title'] == 'HTTP traffic is not redirected to HTTPS'
    assert 'no redirect' in f['detail']


def test_exp002_pass_produces_no_finding():
    conf = '''
    http {
        server {
            listen 80;
            server_name example.com;
            return 301 https://$host$request_uri;
        }
        server {
            listen 443 ssl;
            ssl_certificate /etc/ssl/certs/example.pem;
            server_name example.com;
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)
    assert _find(findings, 'NGX-EXP-002') is None


def test_exp002_http_only_by_design_produces_no_finding():
    """UNKNOWN (no HTTPS pair found — HTTP-only site by design, this
    project's own VM baseline shape) must not produce a Finding —
    applicable=False, per the general applicable=False -> no Finding rule."""
    conf = '''
    http {
        server {
            listen 80;
            server_name example.com;
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)
    assert _find(findings, 'NGX-EXP-002') is None


# ===========================================================================
# NGX-EXP-003 — default_server ambiguity
# severity: 'low' — narrow-scope, config-hygiene finding (docs explicitly
# note the low weight reflects rarity, not reduced severity when it
# fires, but the actual per-occurrence consequence — an unrecognized
# Host header reaching an unintended vhost — is situational, not a
# direct exposure like EXP-001/002). Same class as X-Frame-Options/
# X-Content-Type-Options.
# ===========================================================================

def test_exp003_fail_produces_finding():
    conf = '''
    http {
        server {
            listen 80;
            server_name a.example.com;
        }
        server {
            listen 80;
            server_name b.example.com;
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)

    f = _find(findings, 'NGX-EXP-003')
    assert f is not None
    assert f['severity'] == 'low'
    assert f['title'] == 'Ambiguous default server for shared address:port'
    assert 'no explicit' in f['detail']


def test_exp003_explicit_default_produces_no_finding():
    conf = '''
    http {
        server {
            listen 80 default_server;
            server_name a.example.com;
        }
        server {
            listen 80;
            server_name b.example.com;
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)
    assert _find(findings, 'NGX-EXP-003') is None


def test_exp003_single_server_produces_no_finding():
    conf = '''
    http {
        server {
            listen 80;
            server_name example.com;
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)
    assert _find(findings, 'NGX-EXP-003') is None


# ===========================================================================
# NGX-TLS-004 — weak/forbidden cipher suite
# severity: 'high' — direct analogue of the existing NGX-TLS-001 ('high',
# "outdated TLS 1.0/1.1 is enabled") — both are proven cryptographic
# transport weaknesses, the most severe class this catalogue checks.
# ===========================================================================

def test_tls004_fail_produces_finding_for_forbidden_cipher():
    conf = '''
    http {
        server {
            listen 443 ssl;
            ssl_certificate /etc/ssl/certs/example.pem;
            ssl_ciphers RC4;
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)

    f = _find(findings, 'NGX-TLS-004')
    assert f is not None
    assert f['severity'] == 'high'
    assert f['title'] == 'Weak or forbidden cipher suite explicitly enabled'
    assert 'forbidden class' in f['detail']


def test_tls004_pass_produces_no_finding():
    conf = '''
    http {
        server {
            listen 443 ssl;
            ssl_certificate /etc/ssl/certs/example.pem;
            ssl_ciphers "ALL:@SECLEVEL=2";
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)
    assert _find(findings, 'NGX-TLS-004') is None


def test_tls004_bare_alias_unknown_produces_no_finding():
    """The common real-world case (bare HIGH/DEFAULT alias, no
    SECLEVEL) resolves to UNKNOWN/applicable=False — no Finding, per
    this control's documented asymmetric-proof design. This is the
    exact case observed live on 46.62.147.41 (project session notes)."""
    conf = '''
    http {
        server {
            listen 443 ssl;
            ssl_certificate /etc/ssl/certs/example.pem;
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)
    assert _find(findings, 'NGX-TLS-004') is None


def test_tls004_no_ssl_listen_na_produces_no_finding():
    conf = '''
    http {
        server {
            listen 80;
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)
    assert _find(findings, 'NGX-TLS-004') is None


# ===========================================================================
# General contract checks — apply across all 7 controls
# ===========================================================================

def test_all_seven_finding_ids_are_the_only_possible_tier2_ids():
    """build_tier2_findings() must never emit a Finding.id outside the
    documented 7-control catalogue — guards against a typo or a stray
    extra Finding slipping in unnoticed."""
    conf = '''
    http {
        server {
            listen 80;
            server_name a.example.com;
        }
        server {
            listen 80;
            server_name b.example.com;
        }
        server {
            listen 443 ssl;
            ssl_certificate /etc/ssl/certs/example.pem;
            ssl_ciphers RC4;
            client_max_body_size 0;
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)

    allowed = {'NGX-TLS-004', 'NGX-HDR-004', 'NGX-HDR-005', 'NGX-HDR-006',
               'NGX-CONF-003', 'NGX-EXP-002', 'NGX-EXP-003'}
    ids = {f['id'] for f in findings if f.get('id')}
    assert ids <= allowed


def test_no_duplicate_finding_ids():
    """One Component -> at most one Finding — build_tier2_findings()
    must never emit two Findings with the same id."""
    conf = '''
    http {
        server {
            listen 80;
            server_name a.example.com;
        }
        server {
            listen 80;
            server_name b.example.com;
        }
        server {
            listen 443 ssl;
            ssl_certificate /etc/ssl/certs/example.pem;
            ssl_ciphers RC4;
            client_max_body_size 0;
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)

    ids = [f['id'] for f in findings if f.get('id')]
    assert len(ids) == len(set(ids))


def test_fully_hardened_config_produces_zero_tier2_findings():
    conf = '''
    http {
        add_header Content-Security-Policy "default-src 'self'";
        add_header Referrer-Policy no-referrer;
        add_header Permissions-Policy "geolocation=()";
        server {
            listen 443 ssl;
            ssl_certificate /etc/ssl/certs/example.pem;
            ssl_ciphers "ALL:@SECLEVEL=2";
            client_max_body_size 10m;
            server_name example.com;
        }
        server {
            listen 80;
            server_name example.com;
            return 301 https://$host$request_uri;
        }
    }
    '''
    cfg_v2 = parse_nginx_config_v2(conf)
    components = _build_tier2_components(cfg_v2)
    findings = build_tier2_findings(components)
    assert findings == []
