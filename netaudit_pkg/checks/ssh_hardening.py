"""
sshd hardening score: authentication, authentication limits, forwarding, and
cryptography, scored 0-100 per docs/checks/ssh_hardening.md.

Two-layer API, mirroring nginx_hardening.py's established pattern:

    audit_ssh_hardening_score(ssh)   <- internal, reusable: takes an already-
                                         connected SSHExecutor, does no I/O
                                         setup/teardown itself.
    check_ssh_hardening(...)         <- registry entrypoint: opens its own SSH
                                         session when run standalone, then
                                         delegates to audit_ssh_hardening_score().

Named audit_ssh_hardening_score (not audit_ssh_hardening) specifically to
avoid colliding with the pre-existing audit_ssh_hardening() findings function
in server_security.py - both exist side by side, both independently consume
collect_ssh_config()/SSHConfig, neither calls the other (same reasoning as
nginx_hardening.py's relationship to audit_nginx() - see this module's
_build_findings() docstring for the specific division of finding coverage
between the two).

Every control's PASS/FAIL/N/A condition and weight below is a direct
transcription of docs/checks/ssh_hardening.md sections 6 and 8 - this module
is the implementation of that spec, not a fresh design. In particular:

- SSH-AUTH-001 (permit_root_login) was deliberately revised mid-spec from
  "PermitRootLogin == 'no'" to "root password/keyboard-interactive auth
  disabled" (PASS on 'no', 'prohibit-password', 'without-password', or
  'forced-commands-only'; FAIL only on 'yes') - see section 6.1's note for
  the sshd_config(5) citation this rests on. Do not "simplify" this back to
  an exact-match-on-'no'' check; that was the bug the spec's own synthetic
  validation caught before this code was written.
- The three crypto controls use substring/family matching against a
  deny-list (section 6.4.1), not an exact-name allow-list - this is a
  deliberate policy choice (an OpenSSH maintainer's own guidance against
  positive allow-lists), not an implementation shortcut. Do not replace the
  substring checks with a fixed set of exact algorithm names.
- Severity-weighted per-control weights (section 8.1) are transcribed as
  literal float constants below, not recomputed from a severity table at
  runtime - this mirrors nginx_hardening.py's approach (weights are a fixed
  policy decision, not a dynamic parameter) and keeps this module's only
  dependency on scoring.py the same Component/weighted_score() contract
  nginx_hardening.py already uses.
"""

from __future__ import annotations

from ..registry import register
from ..findings import finding as _finding
from ..scoring import Component, weighted_score
from ..ssh import SSHExecutor, HostKeyMismatchError
from ..ssh_config import SSHConfig, collect_ssh_config

try:
    import paramiko
except ImportError:
    paramiko = None

# ===========================================================================
# Weak-algorithm policy (docs/checks/ssh_hardening.md section 6.4.1)
# ===========================================================================
#
# Deny-list, not allow-list: substring/family matching against algorithm
# *names*, deliberately not exact-string comparison. An OpenSSH maintainer's
# explicit guidance against positive allow-lists is the reason (a new,
# stronger algorithm OpenSSH introduces in the future would otherwise be
# silently treated as FAIL just for not being on a hardcoded list). See the
# spec section 6.4.1 for the full citation trail (RHEL, F5, EnterpriseDT,
# IBM, kifarunix cross-referenced) behind each substring below.

_WEAK_CIPHER_SUBSTRINGS = ('-cbc', 'arcfour')
_WEAK_MAC_SUBSTRINGS = ('md5', 'sha1', 'ripemd', '-96', 'umac-64')
_WEAK_KEX_SUBSTRINGS = ('group1-sha1', 'group14-sha1', 'group-exchange-sha1')


def _has_weak_algorithm(algorithms: list[str], weak_substrings: tuple[str, ...]) -> bool:
    """True if any algorithm name in the list contains any weak substring.
    Deliberately substring-based (see module docstring) - e.g. this must
    catch both 'hmac-sha1' and 'hmac-sha1-etm@openssh.com' via the same
    'sha1' rule, not require them to be listed as two separate exact names.
    """
    return any(any(weak in algo for weak in weak_substrings) for algo in algorithms)


# ===========================================================================
# Per-control weights (docs/checks/ssh_hardening.md section 8.1)
# ===========================================================================
#
# Severity multiplier (critical=2.0, high=1.5, medium=1.0, low=0.5),
# normalized within each group, transcribed here as literal per-control
# weights - the arithmetic that produced these is documented in the spec,
# not re-derived at runtime. Sum of all 14 must equal 1.0 (verified by
# test_ssh_hardening_components.py, not just asserted here).

_W_PERMIT_ROOT_LOGIN = 0.0900              # high
_W_PASSWORD_AUTHENTICATION = 0.0600        # medium
_W_PERMIT_EMPTY_PASSWORDS = 0.1200         # critical
_W_PUBKEY_AUTHENTICATION = 0.0900          # high
_W_KBD_INTERACTIVE_AUTHENTICATION = 0.0600  # medium
_W_HOSTBASED_AUTHENTICATION = 0.0300       # low

_W_MAX_AUTH_TRIES = 0.0500                 # low
_W_LOGIN_GRACE_TIME = 0.0500               # low

_W_X11_FORWARDING = 0.0400                 # low
_W_ALLOW_TCP_FORWARDING = 0.0800           # medium
_W_ALLOW_AGENT_FORWARDING = 0.0800         # medium

_W_CIPHERS = 0.09375                       # high
_W_MACS = 0.0625                           # medium
_W_KEX_ALGORITHMS = 0.09375                # high


# ===========================================================================
# Component builders — one per control, in docs/checks/ssh_hardening.md
# section 6 order (6.1 Authentication, 6.2 Authentication limits,
# 6.3 Forwarding, 6.4 Cryptography). None of these controls has a
# genuine N/A condition (section 4.1: the only N/A case is the whole
# SSHConfig being unreadable, handled one level up, before any of these
# are ever called) except the three crypto controls, whose N/A condition
# is "the field SSHConfig collected is empty" (section 6.4).
# ===========================================================================


def _c_permit_root_login(cfg: SSHConfig) -> Component:
    # SSH-AUTH-001 - Root password/keyboard-interactive auth disabled,
    # weight 0.0900, severity high. PASS on 'no', 'prohibit-password',
    # 'without-password' (deprecated alias), or 'forced-commands-only' -
    # all four eliminate root password-guessing per sshd_config(5). FAIL
    # only on 'yes'. See this module's docstring - do not narrow this back
    # to exact-match-on-'no'.
    passing_values = ('no', 'prohibit-password', 'without-password', 'forced-commands-only')
    passed = cfg.permit_root_login in passing_values
    score = 100 if passed else 0
    return Component(name='permit_root_login', weight=_W_PERMIT_ROOT_LOGIN, score=score, max=100,
                      finding_id=None if passed else 'SSH-AUTH-001')


def _c_password_authentication(cfg: SSHConfig) -> Component:
    # SSH-AUTH-002 - PasswordAuthentication disabled, weight 0.0600, severity medium
    passed = cfg.password_authentication is False
    score = 100 if passed else 0
    return Component(name='password_authentication', weight=_W_PASSWORD_AUTHENTICATION, score=score, max=100,
                      finding_id=None if passed else 'SSH-AUTH-002')


def _c_permit_empty_passwords(cfg: SSHConfig) -> Component:
    # SSH-AUTH-003 - PermitEmptyPasswords disabled, weight 0.1200, severity
    # critical (the highest in this catalogue - see spec 6.1: empty
    # passwords + password auth enabled is a direct auth bypass, not just
    # weakened defense-in-depth like every other control here).
    passed = cfg.permit_empty_passwords is False
    score = 100 if passed else 0
    return Component(name='permit_empty_passwords', weight=_W_PERMIT_EMPTY_PASSWORDS, score=score, max=100,
                      finding_id=None if passed else 'SSH-AUTH-003')


def _c_pubkey_authentication(cfg: SSHConfig) -> Component:
    # SSH-AUTH-004 - PubkeyAuthentication enabled, weight 0.0900, severity high
    passed = cfg.pubkey_authentication is True
    score = 100 if passed else 0
    return Component(name='pubkey_authentication', weight=_W_PUBKEY_AUTHENTICATION, score=score, max=100,
                      finding_id=None if passed else 'SSH-AUTH-004')


def _c_kbd_interactive_authentication(cfg: SSHConfig) -> Component:
    # SSH-AUTH-005 - KbdInteractiveAuthentication disabled, weight 0.0600,
    # severity medium. Distinct control from SSH-AUTH-002 because
    # PAM-backed keyboard-interactive auth is an independently-exploitable
    # password-equivalent path (spec 6.1) - not folded into password_auth.
    passed = cfg.kbd_interactive_authentication is False
    score = 100 if passed else 0
    return Component(name='kbd_interactive_authentication', weight=_W_KBD_INTERACTIVE_AUTHENTICATION,
                      score=score, max=100, finding_id=None if passed else 'SSH-AUTH-005')


def _c_hostbased_authentication(cfg: SSHConfig) -> Component:
    # SSH-AUTH-006 - HostbasedAuthentication disabled, weight 0.0300, severity low
    passed = cfg.hostbased_authentication is False
    score = 100 if passed else 0
    return Component(name='hostbased_authentication', weight=_W_HOSTBASED_AUTHENTICATION, score=score, max=100,
                      finding_id=None if passed else 'SSH-AUTH-006')


def _c_max_auth_tries(cfg: SSHConfig) -> Component:
    # SSH-AUTH-007 - MaxAuthTries bounded, weight 0.0500, severity low.
    # PASS <= 4 (spec 6.2: conservative CIS-style threshold, sshd's own
    # default of 6 is FAIL). None (directive somehow unreadable while the
    # rest of SSHConfig is readable) is defensively treated as FAIL, not
    # N/A - see spec section 4: no per-control N/A exists for this
    # catalogue outside the three crypto controls.
    passed = cfg.max_auth_tries is not None and cfg.max_auth_tries <= 4
    score = 100 if passed else 0
    return Component(name='max_auth_tries', weight=_W_MAX_AUTH_TRIES, score=score, max=100,
                      finding_id=None if passed else 'SSH-AUTH-007')


def _c_login_grace_time(cfg: SSHConfig) -> Component:
    # SSH-AUTH-008 - LoginGraceTime bounded, weight 0.0500, severity low.
    # PASS <= 60 seconds (spec 6.2: half of sshd's default 120s).
    passed = cfg.login_grace_time is not None and cfg.login_grace_time <= 60
    score = 100 if passed else 0
    return Component(name='login_grace_time', weight=_W_LOGIN_GRACE_TIME, score=score, max=100,
                      finding_id=None if passed else 'SSH-AUTH-008')


def _c_x11_forwarding(cfg: SSHConfig) -> Component:
    # SSH-FWD-001 - X11Forwarding disabled, weight 0.0400, severity low
    passed = cfg.x11_forwarding is False
    score = 100 if passed else 0
    return Component(name='x11_forwarding', weight=_W_X11_FORWARDING, score=score, max=100,
                      finding_id=None if passed else 'SSH-FWD-001')


def _c_allow_tcp_forwarding(cfg: SSHConfig) -> Component:
    # SSH-FWD-002 - AllowTcpForwarding disabled, weight 0.0800, severity
    # medium. Strict PASS on 'no' only - 'local'/'remote' partial-forwarding
    # modes are FAIL too (spec 6.3: no citable ranking between them and
    # 'yes' was found, so both are treated the same as full forwarding
    # rather than inventing an unsupported WARN tier).
    passed = cfg.allow_tcp_forwarding == 'no'
    score = 100 if passed else 0
    return Component(name='allow_tcp_forwarding', weight=_W_ALLOW_TCP_FORWARDING, score=score, max=100,
                      finding_id=None if passed else 'SSH-FWD-002')


def _c_allow_agent_forwarding(cfg: SSHConfig) -> Component:
    # SSH-FWD-003 - AllowAgentForwarding disabled, weight 0.0800, severity medium
    passed = cfg.allow_agent_forwarding is False
    score = 100 if passed else 0
    return Component(name='allow_agent_forwarding', weight=_W_ALLOW_AGENT_FORWARDING, score=score, max=100,
                      finding_id=None if passed else 'SSH-FWD-003')


def _c_ciphers(cfg: SSHConfig) -> Component:
    # SSH-CRYPTO-001 - No weak ciphers, weight 0.0938, severity high. N/A
    # when SSHConfig.ciphers is empty (spec 6.4: an empty list is either an
    # upstream collection problem or a defensive case this module has no
    # evidence to score as FAIL - see nginx_hardening's identical reasoning
    # for its own crypto N/A conditions).
    if not cfg.ciphers:
        return Component(name='ciphers', weight=_W_CIPHERS, score=0, max=100,
                          applicable=False, reason='ciphers empty — nothing to evaluate',
                          finding_id='SSH-CRYPTO-001')
    passed = not _has_weak_algorithm(cfg.ciphers, _WEAK_CIPHER_SUBSTRINGS)
    score = 100 if passed else 0
    return Component(name='ciphers', weight=_W_CIPHERS, score=score, max=100,
                      finding_id=None if passed else 'SSH-CRYPTO-001')


def _c_macs(cfg: SSHConfig) -> Component:
    # SSH-CRYPTO-002 - No weak MACs, weight 0.0625, severity medium
    if not cfg.macs:
        return Component(name='macs', weight=_W_MACS, score=0, max=100,
                          applicable=False, reason='macs empty — nothing to evaluate',
                          finding_id='SSH-CRYPTO-002')
    passed = not _has_weak_algorithm(cfg.macs, _WEAK_MAC_SUBSTRINGS)
    score = 100 if passed else 0
    return Component(name='macs', weight=_W_MACS, score=score, max=100,
                      finding_id=None if passed else 'SSH-CRYPTO-002')


def _c_kex_algorithms(cfg: SSHConfig) -> Component:
    # SSH-CRYPTO-003 - No weak KEX, weight 0.0938, severity high
    if not cfg.kex_algorithms:
        return Component(name='kex_algorithms', weight=_W_KEX_ALGORITHMS, score=0, max=100,
                          applicable=False, reason='kex_algorithms empty — nothing to evaluate',
                          finding_id='SSH-CRYPTO-003')
    passed = not _has_weak_algorithm(cfg.kex_algorithms, _WEAK_KEX_SUBSTRINGS)
    score = 100 if passed else 0
    return Component(name='kex_algorithms', weight=_W_KEX_ALGORITHMS, score=score, max=100,
                      finding_id=None if passed else 'SSH-CRYPTO-003')


def _build_components(cfg: SSHConfig) -> list[Component]:
    """All 14 Tier-1 controls, in docs/checks/ssh_hardening.md section 6
    order. Individual builders decide their own applicability; this
    function does not add any group-level N/A logic itself - the
    SSHConfig.readable == False case (section 4.1's group-level N/A) is
    the caller's responsibility (mirrors nginx_hardening._build_components,
    which has the identical division of responsibility for the same
    reason: there's no meaningful cfg data to build components from at all
    when the whole collection failed)."""
    return [
        _c_permit_root_login(cfg),
        _c_password_authentication(cfg),
        _c_permit_empty_passwords(cfg),
        _c_pubkey_authentication(cfg),
        _c_kbd_interactive_authentication(cfg),
        _c_hostbased_authentication(cfg),
        _c_max_auth_tries(cfg),
        _c_login_grace_time(cfg),
        _c_x11_forwarding(cfg),
        _c_allow_tcp_forwarding(cfg),
        _c_allow_agent_forwarding(cfg),
        _c_ciphers(cfg),
        _c_macs(cfg),
        _c_kex_algorithms(cfg),
    ]


# ===========================================================================
# Finding builders — self-generated findings for the 11 of 14 controls that
# have no counterpart in the pre-existing audit_ssh_hardening() (findings-
# only check, server_security.py). Only SSH-AUTH-001/002/003 are covered
# there; every other control's finding is generated here, same division of
# labor as nginx_hardening.py's _build_findings() (see that module's
# docstring for the general pattern this follows). None of these duplicate
# an existing finding - a caller wanting the full finding set for this
# server's SSH posture combines this module's findings with
# audit_ssh_hardening()'s, linked via Component.finding_id, not by one
# function calling the other.
# ===========================================================================

def _f_pubkey_authentication(cfg: SSHConfig) -> dict | None:
    if cfg.pubkey_authentication is True:
        return None
    return _finding('high', 'PubkeyAuthentication disabled',
                    'public-key authentication is not enabled — this removes the strongest '
                    'available authentication method, leaving only weaker alternatives',
                    id='SSH-AUTH-004')


def _f_kbd_interactive_authentication(cfg: SSHConfig) -> dict | None:
    if cfg.kbd_interactive_authentication is False:
        return None
    return _finding('medium', 'KbdInteractiveAuthentication enabled',
                    'PAM-backed keyboard-interactive authentication can prompt for a password '
                    'exactly like PasswordAuthentication — disabling only the latter does not '
                    'remove this password-equivalent path',
                    id='SSH-AUTH-005')


def _f_hostbased_authentication(cfg: SSHConfig) -> dict | None:
    if cfg.hostbased_authentication is False:
        return None
    return _finding('low', 'HostbasedAuthentication enabled',
                    'host-based trust authentication is enabled — this trusts client-presented '
                    'host identity rather than per-user credentials',
                    id='SSH-AUTH-006')


def _f_max_auth_tries(cfg: SSHConfig) -> dict | None:
    if cfg.max_auth_tries is not None and cfg.max_auth_tries <= 4:
        return None
    value = cfg.max_auth_tries if cfg.max_auth_tries is not None else 'unresolved'
    return _finding('low', 'MaxAuthTries above recommended threshold',
                    f'MaxAuthTries is {value} — 4 or fewer limits brute-force attempts per connection',
                    id='SSH-AUTH-007')


def _f_login_grace_time(cfg: SSHConfig) -> dict | None:
    if cfg.login_grace_time is not None and cfg.login_grace_time <= 60:
        return None
    value = cfg.login_grace_time if cfg.login_grace_time is not None else 'unresolved'
    return _finding('low', 'LoginGraceTime above recommended threshold',
                    f'LoginGraceTime is {value}s — 60s or less reduces the window an '
                    'unauthenticated connection can hold a slot open',
                    id='SSH-AUTH-008')


def _f_x11_forwarding(cfg: SSHConfig) -> dict | None:
    if cfg.x11_forwarding is False:
        return None
    return _finding('low', 'X11Forwarding enabled',
                    'X11 forwarding is enabled — an unused attack surface on most servers',
                    id='SSH-FWD-001')


def _f_allow_tcp_forwarding(cfg: SSHConfig) -> dict | None:
    if cfg.allow_tcp_forwarding == 'no':
        return None
    value = cfg.allow_tcp_forwarding if cfg.allow_tcp_forwarding is not None else 'unresolved'
    return _finding('medium', 'AllowTcpForwarding not disabled',
                    f'AllowTcpForwarding is {value!r} — TCP forwarding/tunneling is available '
                    '(including partial modes like local/remote, which still enable a real '
                    'tunneling capability)',
                    id='SSH-FWD-002')


def _f_allow_agent_forwarding(cfg: SSHConfig) -> dict | None:
    if cfg.allow_agent_forwarding is False:
        return None
    return _finding('medium', 'AllowAgentForwarding enabled',
                    'SSH agent forwarding is enabled — a compromised server can potentially '
                    'use the client-side agent to authenticate elsewhere',
                    id='SSH-FWD-003')


def _f_ciphers(cfg: SSHConfig) -> dict | None:
    if not cfg.ciphers:
        return None  # N/A — no finding for "nothing to evaluate"
    if not _has_weak_algorithm(cfg.ciphers, _WEAK_CIPHER_SUBSTRINGS):
        return None
    return _finding('high', 'weak cipher enabled',
                    'ciphers includes a deny-listed algorithm (CBC-mode or RC4/arcfour family) — '
                    'see docs/checks/ssh_hardening.md section 6.4.1 for the full policy',
                    id='SSH-CRYPTO-001')


def _f_macs(cfg: SSHConfig) -> dict | None:
    if not cfg.macs:
        return None
    if not _has_weak_algorithm(cfg.macs, _WEAK_MAC_SUBSTRINGS):
        return None
    return _finding('medium', 'weak MAC enabled',
                    'macs includes a deny-listed algorithm (MD5, SHA-1, RIPEMD, or a truncated '
                    '96-bit variant) — see docs/checks/ssh_hardening.md section 6.4.1',
                    id='SSH-CRYPTO-002')


def _f_kex_algorithms(cfg: SSHConfig) -> dict | None:
    if not cfg.kex_algorithms:
        return None
    if not _has_weak_algorithm(cfg.kex_algorithms, _WEAK_KEX_SUBSTRINGS):
        return None
    return _finding('high', 'weak key exchange algorithm enabled',
                    'kex_algorithms includes a deny-listed SHA-1-based group — '
                    'see docs/checks/ssh_hardening.md section 6.4.1',
                    id='SSH-CRYPTO-003')


def _build_findings(cfg: SSHConfig) -> list[dict]:
    """The 11 self-generated findings this module produces on its own
    (everything except SSH-AUTH-001/002/003, which audit_ssh_hardening()
    already covers and this module references via Component.finding_id
    instead of re-deriving). Returns only the findings for controls that
    are currently FAILing (or, for the three crypto controls, N/A produces
    no finding either — nothing to flag when there's nothing to evaluate)."""
    findings = [
        _f_pubkey_authentication(cfg),
        _f_kbd_interactive_authentication(cfg),
        _f_hostbased_authentication(cfg),
        _f_max_auth_tries(cfg),
        _f_login_grace_time(cfg),
        _f_x11_forwarding(cfg),
        _f_allow_tcp_forwarding(cfg),
        _f_allow_agent_forwarding(cfg),
        _f_ciphers(cfg),
        _f_macs(cfg),
        _f_kex_algorithms(cfg),
    ]
    return [f for f in findings if f is not None]


# ===========================================================================
# Internal reusable API
# ===========================================================================

def audit_ssh_hardening_score(ssh: SSHExecutor) -> dict:
    """Scores sshd's own hardening (authentication, auth limits, forwarding,
    cryptography) from an already-connected SSHExecutor. Does NOT open or
    close the SSH session itself - see this module's docstring for the
    two-layer API rationale (mirrors nginx_hardening's
    audit_nginx_hardening()).

    Deliberately does not call audit_ssh_hardening() (server_security.py) -
    both are independent consumers of collect_ssh_config(); the link
    between them is Component.finding_id referencing audit_ssh_hardening()'s
    finding ids for SSH-AUTH-001/002/003, not a function call.
    """
    cfg = collect_ssh_config(ssh)
    if not cfg.readable:
        if not cfg.version:
            # sshd isn't installed at all - which sshd found nothing, so
            # collect_ssh_config() never even attempted sshd -T.
            return {'installed': False}
        # sshd is installed but sshd -T came back empty - the group-level
        # N/A case (spec section 4.1): sudo lacked access to a restricted
        # Include file, so nothing was resolved and no control has a
        # legitimate opinion. No hardening score at all, matching
        # nginx_hardening's identical handling of the same shape of failure.
        return {'installed': True, 'version': cfg.version,
                'error': 'sshd -T requires root — no read access to the effective configuration'}

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
    id='ssh_hardening', label='SSH server hardening (SSH)', category='hardening',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Host', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'User', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH port', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Key path', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Password (if not using a key)', 'default': ''},
    ],
    required_tools=[],
    description='Scores sshd authentication, authentication limits, forwarding and '
                'cryptography against docs/checks/ssh_hardening.md (14 controls, 0-100 '
                'hardening score). Read-only.',
)
def check_ssh_hardening(host='', user='root', port=22, key_path='', password='') -> dict:  # nosec B107 - empty default is a CLI/API parameter, not a hardcoded credential
    """Public registry entrypoint - opens its own SSH session when run
    standalone, then delegates to audit_ssh_hardening_score(). Callers that
    already hold an open SSHExecutor should call audit_ssh_hardening_score(ssh)
    directly instead, to avoid a second SSH connection to the same host."""
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
        return audit_ssh_hardening_score(ssh)
    finally:
        ssh.close()
