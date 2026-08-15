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

from typing import Literal

from ..registry import register
from ..findings import finding as _finding
from ..scoring import Component, weighted_score
from ..ssh import SSHExecutor, HostKeyMismatchError
from ..nginx_config import NginxConfig, collect_nginx_config
from ..nginx_config_v2 import NginxConfigV2, ServerBlock
from ..nginx_v2_resolvers import resolve_cascading_value

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
# Tier-2 component builders (docs/checks/nginx_hardening.md section 7 +
# section 8.3's weight model). Each control's per-ServerBlock verdict
# function returns one of PASS/FAIL/UNKNOWN/N/A plus a short evidence
# string; _aggregate_server_verdicts() then combines however many
# ServerBlocks NginxConfigV2 has into the single Component
# _build_tier2_components() needs (weighted_score() takes one Component
# per control, not one per server).
# ===========================================================================

Verdict = Literal['PASS', 'FAIL', 'UNKNOWN', 'N/A']


def _aggregate_server_verdicts(verdicts: list[tuple[Verdict, str]]) -> tuple[Verdict, str]:
    """The single place worst-case multi-vhost aggregation is decided for
    every Tier-2 control (see this session's multi-vhost aggregation
    decision, recorded here rather than in a separate doc since it's
    purely an implementation-layer rule, not a control semantics
    decision docs/checks/nginx_hardening.md section 7 needs to state).

    N/A entries are excluded entirely before aggregation - they don't
    participate in the FAIL > UNKNOWN > PASS priority at all, they're
    simply not counted. Only if EVERY server is N/A does the aggregate
    become N/A. Among the remaining (non-N/A) verdicts: any FAIL makes
    the whole control FAIL; else any UNKNOWN makes it UNKNOWN; else it's
    PASS. This is deliberately the most conservative aggregation
    available - a single provably-bad vhost cannot be outvoted by
    several good ones, matching this project's asymmetric-proof stance
    (a control can't claim safety it hasn't demonstrated everywhere it
    applies).

    Evidence is concatenated (one line per contributing server, `; `
    joined) so a report reader can see which server(s) drove the
    aggregate result, not just the final verdict - this is why each
    per-server verdict function returns its own evidence string rather
    than aggregation reconstructing it after the fact.
    """
    applicable = [(v, e) for v, e in verdicts if v != 'N/A']
    if not applicable:
        return 'N/A', 'no applicable server block'

    for target in ('FAIL', 'UNKNOWN', 'PASS'):
        matching = [e for v, e in applicable if v == target]
        if matching:
            return target, '; '.join(matching)

    # unreachable - every element of `applicable` is PASS/FAIL/UNKNOWN,
    # so one of the three loop iterations above always matches
    raise AssertionError('unreachable: no verdict matched PASS/FAIL/UNKNOWN')


def _server_label(server: ServerBlock) -> str:
    """Short, human-readable identifier for a ServerBlock in Tier-2
    evidence text - the primary server_name if one is set (nginx.org:
    "The first name becomes the primary server name"), else a
    listen-based fallback for anonymous/catch-all server blocks (no
    server_name at all is valid nginx config - the empty server_name
    default per nginx.org's `server_name` directive).
    """
    if server.server_names:
        return server.server_names[0]
    if server.listens:
        le = server.listens[0]
        return f'{le.address}:{le.port}' if le.port is not None else le.address
    return f'server#{server.order}'


def _verdict_tls_004_ciphers(server: ServerBlock, http_directives: dict[str, list[str]]) -> tuple[Verdict, str]:
    """NGX-TLS-004 - weak cipher policy, per docs/checks/nginx_hardening.md
    section 7's finalized semantics for a single ServerBlock:

    N/A: server has no `listen ... ssl` endpoint at all - nothing to
    evaluate.
    FAIL: effective ssl_ciphers string provably includes a forbidden
    class without a preceding `!`/`-` exclusion (eNULL/NULL, aNULL,
    EXPORT, RC4, DES/3DES, MD5, kRSA).
    PASS: either `@SECLEVEL=n` (n>=2, last occurrence wins) with no
    later explicit inclusion of a forbidden class, or a value containing
    an nginx variable is never PASS (see UNKNOWN below).
    UNKNOWN: bare aliases (HIGH/DEFAULT/ALL/MEDIUM) without SECLEVEL or
    explicit exclusions, unresolvable +/- constructs, the directive
    absent entirely (nginx's own compiled-in default HIGH:!aNULL:!MD5
    contains a bare HIGH alias - not automatically PASS, per the spec's
    explicit ruling on this exact case), or a value containing an nginx
    variable.
    """
    if not any(le.ssl for le in server.listens):
        return 'N/A', 'no ssl listen endpoint'

    label = _server_label(server)
    ev = resolve_cascading_value(
        'ssl_ciphers', 'HIGH:!aNULL:!MD5',
        http_directives=http_directives, server_directives=server.directives,
    )
    if ev.value is None:
        return 'UNKNOWN', f'{label}: ssl_ciphers effective value could not be determined'
    if ev.has_variable:
        return 'UNKNOWN', f'{label}: ssl_ciphers "{ev.value}" contains an nginx variable'

    tokens = ev.value.split(':')

    forbidden = {'enull', 'null', 'anull', 'export', 'rc4', 'des', '3des', 'md5', 'krsa'}
    for tok in tokens:
        raw = tok.strip()
        if not raw or raw[0] in '!-':
            continue
        if raw.lower() in forbidden:
            return 'FAIL', f'{label}: ssl_ciphers "{ev.value}" explicitly includes forbidden class {raw!r}'

    seclevel = None
    for tok in tokens:
        raw = tok.strip()
        if raw.upper().startswith('@SECLEVEL='):
            try:
                seclevel = int(raw.split('=', 1)[1])
            except ValueError:
                seclevel = None
    if seclevel is not None and seclevel >= 2:
        return 'PASS', f'{label}: ssl_ciphers "{ev.value}" sets @SECLEVEL={seclevel} with no later forbidden inclusion'

    return 'UNKNOWN', f'{label}: ssl_ciphers "{ev.value}" (source={ev.source}) is not a recognized-safe profile'


def _c_tls_004_ciphers(cfg_v2: NginxConfigV2) -> Component:
    # NGX-TLS-004 - weak cipher policy, weight 0.12 (section 8.3)
    verdicts = [_verdict_tls_004_ciphers(s, cfg_v2.http_directives) for s in cfg_v2.servers]
    verdict, evidence = _aggregate_server_verdicts(verdicts)

    if verdict == 'N/A':
        return Component(name='tls_004_ciphers', weight=0.12, score=0, max=100,
                          applicable=False, reason=evidence, finding_id=None)
    if verdict == 'UNKNOWN':
        return Component(name='tls_004_ciphers', weight=0.12, score=0, max=100,
                          applicable=False, reason=evidence, finding_id=None)
    score = 100 if verdict == 'PASS' else 0
    return Component(name='tls_004_ciphers', weight=0.12, score=score, max=100,
                      finding_id=None if verdict == 'PASS' else 'NGX-TLS-004',
                      reason=evidence if verdict == 'FAIL' else None)


def _build_tier2_components(cfg_v2: NginxConfigV2) -> list[Component]:
    """The 6 currently-implemented Tier-2 controls (NGX-CONF-004 is
    BLOCKED, see docs/checks/nginx_hardening.md section 7 - not part of
    this list). Extended incrementally as each control lands; only
    NGX-TLS-004 exists as of this commit - see this module's git history
    / docs/checks/nginx_hardening.md section 9 for the implementation
    checklist tracking the rest.
    """
    return [
        _c_tls_004_ciphers(cfg_v2),
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
