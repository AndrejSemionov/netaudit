"""
nginx configuration hardening score: TLS, security headers, configuration
and exposure, scored 0-100 per docs/checks/nginx_hardening.md.

Two-layer API, deliberately:

    audit_nginx_hardening(ssh)      <- internal, reusable: takes an already-
                                        connected SSHExecutor, does no I/O
                                        setup/teardown itself.
    check_nginx_hardening(...)      <- registry entrypoint: opens its own SSH
                                        session when run standalone, then
                                        delegates to audit_nginx_hardening().

This mirrors audit_nginx() (server_security.py): both consume the same
collect_nginx_config(ssh) so a caller holding one open SSHExecutor can run
audit_nginx() and audit_nginx_hardening() over a single session instead of
two. audit_nginx_hardening() deliberately does NOT call audit_nginx() -
both are independent consumers of NginxConfig, not layered on each other;
see docs/checks/nginx_hardening.md section 5 for how the two are linked
instead (via Component.finding_id referencing audit_nginx()'s finding ids).

Control catalogue, weights, and every PASS/FAIL/N/A condition below are
fixed by docs/checks/nginx_hardening.md - this module is the direct
implementation of that spec, not a fresh design. See that document for the
full rationale (synthetic validation, why Exposure is 20% not 10%, etc.).
"""

from __future__ import annotations

from ..registry import register
from ..findings import finding as _finding
from ..scoring import Component, weighted_score
from ..ssh import SSHExecutor, HostKeyMismatchError
from ..nginx_config import NginxConfig, collect_nginx_config

try:
    import paramiko
except ImportError:
    paramiko = None

# ===========================================================================
# Component builders
# ===========================================================================
#
# Each _c_* function returns a single Component for one control, in the
# exact order of docs/checks/nginx_hardening.md section 6 (6.1 TLS, 6.2
# Headers, 6.3 Configuration, 6.4 Exposure). Weights are the final ones from
# section 8.1 - not re-derived here, just transcribed.
#
# TLS N/A rule (section 4.1 / 6.1): NGX-TLS-001/002/003 all become
# inapplicable when there's no TLS to evaluate. NGX-TLS-001/002 key off
# `ssl_protocols` being empty; NGX-TLS-003 keys off `has_ssl_certificate`
# being False (per the 6.0 status matrix - "no TLS configured at all" for
# NGX-TLS-003 is specifically "no certificate", since a cert could exist
# with ssl_protocols still unset, which is NGX-TLS-003's own FAIL case, not
# its N/A case).


def _c_tls_legacy_disabled(cfg: NginxConfig) -> Component:
    # NGX-TLS-001 - Legacy protocols disabled, weight 0.20, severity high
    if not cfg.ssl_protocols:
        return Component(name='tls_legacy_disabled', weight=0.20, score=0, max=100,
                          applicable=False, reason='ssl_protocols not configured — no TLS to evaluate',
                          finding_id='NGX-TLS-001')
    legacy_present = 'TLSv1' in cfg.ssl_protocols or 'TLSv1.1' in cfg.ssl_protocols
    score = 0 if legacy_present else 100
    return Component(name='tls_legacy_disabled', weight=0.20, score=score, max=100,
                      finding_id='NGX-TLS-001' if legacy_present else None)


def _c_tls_modern_protocol(cfg: NginxConfig) -> Component:
    # NGX-TLS-002 - Modern protocol level, weight 0.10, severity low.
    # Three-state: PASS=100 (TLSv1.3), WARN=80 (TLSv1.2 only), FAIL=0
    # (neither), N/A when ssl_protocols is empty. No audit_nginx()
    # counterpart exists for this control - see _f_tls_modern_protocol().
    if not cfg.ssl_protocols:
        return Component(name='tls_modern_protocol', weight=0.10, score=0, max=100,
                          applicable=False, reason='ssl_protocols not configured — no TLS to evaluate',
                          finding_id='NGX-TLS-002')
    if 'TLSv1.3' in cfg.ssl_protocols:
        score = 100
    elif 'TLSv1.2' in cfg.ssl_protocols:
        score = 80
    else:
        score = 0
    return Component(name='tls_modern_protocol', weight=0.10, score=score, max=100,
                      finding_id='NGX-TLS-002' if score < 100 else None)


def _c_tls_protocols_explicit(cfg: NginxConfig) -> Component:
    # NGX-TLS-003 - ssl_protocols explicitly configured, weight 0.10, severity low.
    # N/A when there's no TLS vhost at all (no cert) - distinct from
    # NGX-TLS-001/002's N/A trigger (empty ssl_protocols), per the 6.0
    # status matrix: this control's FAIL case IS "ssl_protocols empty" (a
    # cert exists but the protocol list wasn't set), so N/A has to be a
    # different condition or FAIL could never fire.
    if not cfg.has_ssl_certificate:
        return Component(name='tls_protocols_explicit', weight=0.10, score=0, max=100,
                          applicable=False, reason='no ssl_certificate configured — no TLS vhost to evaluate',
                          finding_id='NGX-TLS-003')
    explicit = bool(cfg.ssl_protocols)
    score = 100 if explicit else 0
    return Component(name='tls_protocols_explicit', weight=0.10, score=score, max=100,
                      finding_id=None if explicit else 'NGX-TLS-003')


def _c_header(cfg: NginxConfig, *, name: str, header_key: str, weight: float,
              finding_id: str) -> Component:
    # Shared shape for NGX-HDR-001/002/003 - all three are binary
    # present/absent checks against headers_present, differing only in
    # weight and which header/control id they cover.
    present = header_key in cfg.headers_present
    score = 100 if present else 0
    return Component(name=name, weight=weight, score=score, max=100,
                      finding_id=None if present else finding_id)


def _c_hsts(cfg: NginxConfig) -> Component:
    # NGX-HDR-001 - Strict-Transport-Security, weight 0.10, severity medium
    return _c_header(cfg, name='hsts', header_key='strict-transport-security',
                      weight=0.10, finding_id='NGX-HDR-001')


def _c_x_frame_options(cfg: NginxConfig) -> Component:
    # NGX-HDR-002 - X-Frame-Options, weight 0.05, severity low
    return _c_header(cfg, name='x_frame_options', header_key='x-frame-options',
                      weight=0.05, finding_id='NGX-HDR-002')


def _c_x_content_type_options(cfg: NginxConfig) -> Component:
    # NGX-HDR-003 - X-Content-Type-Options, weight 0.05, severity low
    return _c_header(cfg, name='x_content_type_options', header_key='x-content-type-options',
                      weight=0.05, finding_id='NGX-HDR-003')


def _c_server_tokens(cfg: NginxConfig) -> Component:
    # NGX-CONF-001 - server_tokens, weight 0.08, severity medium.
    # Never N/A (section 4): None means "on" is nginx's documented default,
    # a determinate FAIL, not an unknown.
    off = cfg.server_tokens == 'off'
    score = 100 if off else 0
    return Component(name='server_tokens', weight=0.08, score=score, max=100,
                      finding_id=None if off else 'NGX-CONF-001')


def _c_autoindex(cfg: NginxConfig) -> Component:
    # NGX-CONF-002 - autoindex disabled, weight 0.12, severity medium
    disabled = not cfg.autoindex_on
    score = 100 if disabled else 0
    return Component(name='autoindex_disabled', weight=0.12, score=score, max=100,
                      finding_id=None if disabled else 'NGX-CONF-002')


def _c_tls_available(cfg: NginxConfig) -> Component:
    # NGX-EXP-001 - TLS available, weight 0.20, severity high. Never N/A -
    # this is the one control that stays applicable even with no TLS at
    # all, deliberately (section 8.1's "No TLS" finding: this is what keeps
    # a no-TLS server's score honestly low instead of the TLS group's
    # weight vanishing via N/A redistribution). No audit_nginx() counterpart
    # exists for this control - see _f_tls_available().
    has_tls = cfg.has_ssl_certificate
    score = 100 if has_tls else 0
    return Component(name='tls_available', weight=0.20, score=score, max=100,
                      finding_id=None if has_tls else 'NGX-EXP-001')


def _f_tls_modern_protocol(cfg: NginxConfig) -> dict | None:
    """NGX-TLS-002 finding - the one control with no audit_nginx() counterpart
    (audit_nginx() only flags legacy-protocol presence via NGX-TLS-001; it
    never had an opinion on "TLS 1.2 present but not 1.3", since that's a
    hardening-scoring judgment, not a pre-existing finding to reuse per
    section 5). Returns None on PASS/N/A - only WARN and FAIL produce a
    finding, matching the "no finding on PASS" rule the other 7 controls
    get for free by reusing audit_nginx()'s already-conditional findings."""
    if not cfg.ssl_protocols:
        return None  # N/A - no TLS to have an opinion about
    if 'TLSv1.3' in cfg.ssl_protocols:
        return None  # PASS
    if 'TLSv1.2' in cfg.ssl_protocols:
        return _finding('low', 'TLS 1.3 is not enabled', 'only TLSv1.2 is present — TLS 1.3 is the '
                        'recommended modern baseline; TLS 1.2 remains an acceptable fallback',
                        id='NGX-TLS-002')
    return _finding('low', 'no modern TLS protocol is enabled', 'ssl_protocols does not include '
                    'TLSv1.2 or TLSv1.3', id='NGX-TLS-002')


def _f_tls_available(cfg: NginxConfig) -> dict | None:
    """NGX-EXP-001 finding - the other control with no audit_nginx() counterpart
    (audit_nginx() never flags "no TLS at all" as its own finding; the closest
    existing ones - NGX-TLS-001/003 - only fire when ssl_protocols/cert-related
    facts are already present in some form). Returns None on PASS."""
    if cfg.has_ssl_certificate:
        return None  # PASS
    return _finding('high', 'no TLS certificate configured', 'nginx has no ssl_certificate directive — '
                    'the site is served over plain HTTP with no encryption available at all',
                    id='NGX-EXP-001')


def _build_findings(cfg: NginxConfig) -> list[dict]:
    """The two self-generated findings nginx_hardening produces on its own
    (NGX-TLS-002, NGX-EXP-001) - every other control's finding already comes
    from audit_nginx() and is referenced via Component.finding_id, not
    re-derived here (section 5: "does not re-derive its own findings from
    scratch where audit_nginx() already produces one for the same control").
    Callers that want the full finding set (e.g. the web UI showing "why did
    this score?") combine this with audit_nginx()'s findings themselves -
    audit_nginx_hardening() does not call audit_nginx() to fetch them (see
    this module's docstring for why)."""
    findings = [_f_tls_modern_protocol(cfg), _f_tls_available(cfg)]
    return [f for f in findings if f is not None]


def _build_components(cfg: NginxConfig) -> list[Component]:
    """All 9 Tier-1 controls, in docs/checks/nginx_hardening.md section 6
    order. Individual builders decide their own applicability; this
    function does not add any group-level N/A logic itself - the
    NginxConfig.readable == False case (section 4.1's group-level N/A) is
    handled one level up, in audit_nginx_hardening(), before this is ever
    called, since in that case there's no meaningful cfg data to build
    components from at all."""
    return [
        _c_tls_legacy_disabled(cfg),
        _c_tls_modern_protocol(cfg),
        _c_tls_protocols_explicit(cfg),
        _c_hsts(cfg),
        _c_x_frame_options(cfg),
        _c_x_content_type_options(cfg),
        _c_server_tokens(cfg),
        _c_autoindex(cfg),
        _c_tls_available(cfg),
    ]


# ===========================================================================
# Internal reusable API
# ===========================================================================

def audit_nginx_hardening(ssh: SSHExecutor) -> dict:
    """Scores nginx's own hardening (TLS, security headers, configuration,
    exposure) from an already-connected SSHExecutor. Does NOT open or close
    the SSH session itself - see this module's docstring for the two-layer
    API rationale (mirrors audit_nginx() in server_security.py).

    Deliberately does not call audit_nginx() - both are independent
    consumers of collect_nginx_config(cfg); the link between them is
    Component.finding_id referencing audit_nginx()'s finding ids, not a
    function call (docs/checks/nginx_hardening.md section 5).
    """
    cfg = collect_nginx_config(ssh)
    if not cfg.installed:
        return {'installed': False}
    if not cfg.readable:
        # group-level N/A (spec section 4.1): nginx -T needed root and
        # didn't have it, so nothing was parsed - no control in this module
        # has a legitimate opinion. No hardening score at all, per
        # weighted_score()'s own contract that a score with zero applicable
        # components is undefined, not a fake number.
        return {'installed': True, 'version': cfg.version,
                'error': 'nginx -T requires root — no read access to the config'}

    hardening = weighted_score(_build_components(cfg))
    findings = _build_findings(cfg)

    return {
        'installed': True,
        'version': cfg.version,
        'hardening': hardening,
        'findings': findings,
    }


# ===========================================================================
# Registry entrypoint
# ===========================================================================

@register(
    id='nginx_hardening', label='nginx configuration hardening (SSH)', category='hardening',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Host', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'User', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH port', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Key path', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Password (if not using a key)', 'default': ''},
    ],
    required_tools=[],
    description='Scores nginx TLS, security headers, configuration and exposure against '
                'docs/checks/nginx_hardening.md (9 controls, 0-100 hardening score). Read-only.',
)
def check_nginx_hardening(host='', user='root', port=22, key_path='', password='') -> dict:
    """Public registry entrypoint - opens its own SSH session when run
    standalone, then delegates to audit_nginx_hardening(). Callers that
    already hold an open SSHExecutor (e.g. a future combined nginx run
    alongside audit_nginx()) should call audit_nginx_hardening(ssh) directly
    instead, to avoid a second SSH connection to the same host."""
    if paramiko is None:
        return {'error': 'paramiko not installed'}
    if not host:
        return {'error': 'host not specified'}

    try:
        ssh = SSHExecutor(host, user, port, key_path, password).connect()
    except HostKeyMismatchError as e:
        return {'error': str(e)}
    except Exception as e:
        return {'error': f'could not connect: {e}'}

    try:
        return audit_nginx_hardening(ssh)
    finally:
        ssh.close()
