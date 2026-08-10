"""
sshd effective-configuration collection and parsing: the single place that
runs `sshd -T` over SSH and turns its output into a structured SSHConfig.

Unlike nginx_config.py (which has to parse raw `nginx -T` text - comments,
Include ordering, directive precedence, all handled by regex), sshd already
does that work itself: `sshd -T` prints the fully-resolved *effective*
configuration - every directive on its own `key value` line, no comments,
Include files already merged with the correct precedence applied. This was
confirmed empirically on a live VM before writing this module (not assumed
by analogy with nginx): the VM's /etc/ssh/sshd_config.d/50-cloud-init.conf
overrides a value the main sshd_config leaves commented-out, and `sshd -T`
correctly reflects the override - a naive regex/substring parse of the raw
config files would have gotten this wrong (whichever file's text happened
to be matched first, not whichever file OpenSSH actually gives precedence
to). So this collector deliberately does NOT read /etc/ssh/sshd_config or
sshd_config.d/*.conf at all - only `sshd -T`'s output.

`sshd -T` requires root: confirmed empirically (not assumed) - on the same
VM, `ssh.run('sshd -T')` failed with "Permission denied" reading a 600-mode
Include file and returned zero directives, while `ssh.sudo('sshd -T')`
returned the full 103-directive effective config. This collector always
uses ssh.sudo(), matching the same lesson nginx_config.py had to learn
after shipping without it (see that module's docstring).

Deliberately data-only, same split as nginx_config.py: SSHConfig holds
facts (what's effectively configured), never judgments (no "auth_score"
field here). The existing audit_ssh_hardening() (Findings) and the future
ssh_hardening (scoring Components) are both independent consumers of this
module - collect once, judge twice, in two different ways, from the same
facts.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .ssh import SSHExecutor


@dataclass
class SSHConfig:
    """Structured facts extracted from `sshd -T` (effective configuration).
    Data only - no severity, no score, no opinion about whether a value is
    good or bad. That judgment belongs to the consumer (audit_ssh_hardening
    for Findings, ssh_hardening for scoring), not to this parser.

    Field types deliberately follow what `sshd -T` actually prints, not a
    simplified yes/no model:
      - permit_root_login and allow_tcp_forwarding are `str`, not `bool` -
        both have more than two effective values (e.g. permit_root_login
        can be 'yes'/'no'/'without-password'/'prohibit-password'/
        'forced-commands-only'; allow_tcp_forwarding can be 'yes'/'no'/
        'local'/'remote'). Collapsing either to a bool would silently lose
        the distinction a hardening control needs to make (e.g.
        'prohibit-password' is meaningfully different from both 'yes' and
        'no', not just "some third thing").
      - max_auth_tries / login_grace_time are `int` - sshd -T always prints
        a plain integer for both.
      - ciphers / macs / kex_algorithms are `list[str]` - sshd -T prints
        these as one comma-separated line each.
      - allow_users / allow_groups / deny_users / deny_groups are
        `list[str]`, defaulting to empty - confirmed empirically that
        sshd -T only prints these directives when they're actually set
        (verified via `sshd -T -o AllowUsers=testuser`, which produced an
        `allowusers testuser` line that's otherwise entirely absent from
        the output). An empty list here is a real fact ("no restriction
        configured"), not a parsing failure - collected for completeness
        even though ssh_hardening v1 doesn't score them (see
        docs/checks/ssh_hardening.md for why: "AllowUsers absent" is not
        inherently a hardening defect the way, say, PasswordAuthentication
        'yes' is, so scoring it needs a policy decision this collector
        shouldn't be making).
    """

    readable: bool = False
    version: str = ''

    # Legacy informational field — not a scoring input for any Tier-1
    # control (docs/checks/ssh_hardening.md section 6.6: changing the SSH
    # port is a weak, non-scored hardening measure), collected purely so
    # audit_ssh_hardening() (server_security.py) can keep returning it in
    # its output after being refactored onto this collector. Do not wire
    # this into _build_components() in checks/ssh_hardening.py.
    port: str | None = None

    # Authentication
    permit_root_login: str | None = None
    password_authentication: bool | None = None
    permit_empty_passwords: bool | None = None
    pubkey_authentication: bool | None = None
    kbd_interactive_authentication: bool | None = None
    hostbased_authentication: bool | None = None

    # Authentication limits
    max_auth_tries: int | None = None
    login_grace_time: int | None = None

    # Forwarding
    x11_forwarding: bool | None = None
    allow_tcp_forwarding: str | None = None
    allow_agent_forwarding: bool | None = None

    # Cryptography
    ciphers: list[str] = field(default_factory=list)
    macs: list[str] = field(default_factory=list)
    kex_algorithms: list[str] = field(default_factory=list)

    # Access restrictions - collected, not scored in ssh_hardening v1
    allow_users: list[str] = field(default_factory=list)
    allow_groups: list[str] = field(default_factory=list)
    deny_users: list[str] = field(default_factory=list)
    deny_groups: list[str] = field(default_factory=list)


def collect_ssh_config(ssh: SSHExecutor) -> SSHConfig:
    """Run `sshd -V` / `sshd -T` over the given (already-connected) SSH
    session and parse the effective configuration into an SSHConfig.
    Read-only - sshd -T only prints the resolved configuration, it doesn't
    change anything on the target.

    `sshd -T` runs via ssh.sudo(), not ssh.run() - see this module's
    docstring for the empirical VM finding that makes this mandatory, not
    optional (a non-root sshd -T fails outright with Permission denied
    reading a restricted Include file, returning zero directives - there
    is no partial-but-usable non-root result to fall back to).
    """
    which_out, _ = ssh.run('which sshd || echo NONE')
    if 'NONE' in which_out:
        return SSHConfig(readable=False)

    ver_out, ver_err = ssh.run('sshd -V 2>&1')
    version = (ver_out or ver_err).strip().splitlines()[0] if (ver_out or ver_err) else ''

    out, err = ssh.sudo('sshd -T')
    if not out.strip():
        return SSHConfig(readable=False, version=version)

    return _parse_sshd_t(out, version=version)


def _parse_sshd_t(output: str, version: str = '') -> SSHConfig:
    """Pure parsing, no I/O - split out from collect_ssh_config() so it can
    be unit-tested against fixture text without an SSH mock.

    `sshd -T` output is one directive per line, lowercase key followed by
    its value(s), no comments, no Include markers - a plain generic
    `key, value = line.split(None, 1)` dict build covers every directive
    uniformly. There is deliberately no per-directive regex here (contrast
    nginx_config.py, which has to regex because raw nginx -T output mixes
    directives with comments and braces) - sshd -T has already done the
    equivalent of nginx's directive-resolution work, so this parser's only
    job is generic key/value extraction plus type normalization for the
    specific fields SSHConfig cares about.
    """
    effective: dict[str, str] = {}
    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        key = parts[0].lower()
        value = parts[1] if len(parts) > 1 else ''
        # sshd -T repeats some directives on multiple lines (e.g. multiple
        # `hostkey` or `listenaddress` entries) - first occurrence wins,
        # matching sshd's own "first value takes precedence" semantics for
        # directives that aren't inherently multi-valued. None of the
        # fields SSHConfig extracts below are of this repeating kind, so
        # this only matters for robustness against directives we don't use.
        effective.setdefault(key, value)

    def _yes_no(key: str) -> bool | None:
        v = effective.get(key)
        if v == 'yes':
            return True
        if v == 'no':
            return False
        return None

    def _int(key: str) -> int | None:
        v = effective.get(key)
        try:
            return int(v) if v is not None else None
        except ValueError:
            return None

    def _csv(key: str) -> list[str]:
        v = effective.get(key)
        return v.split(',') if v else []

    def _space_list(key: str) -> list[str]:
        v = effective.get(key)
        return v.split() if v else []

    return SSHConfig(
        readable=True,
        version=version,
        port=effective.get('port'),
        permit_root_login=effective.get('permitrootlogin'),
        password_authentication=_yes_no('passwordauthentication'),
        permit_empty_passwords=_yes_no('permitemptypasswords'),
        pubkey_authentication=_yes_no('pubkeyauthentication'),
        kbd_interactive_authentication=_yes_no('kbdinteractiveauthentication'),
        hostbased_authentication=_yes_no('hostbasedauthentication'),
        max_auth_tries=_int('maxauthtries'),
        login_grace_time=_int('logingracetime'),
        x11_forwarding=_yes_no('x11forwarding'),
        allow_tcp_forwarding=effective.get('allowtcpforwarding'),
        allow_agent_forwarding=_yes_no('allowagentforwarding'),
        ciphers=_csv('ciphers'),
        macs=_csv('macs'),
        kex_algorithms=_csv('kexalgorithms'),
        allow_users=_space_list('allowusers'),
        allow_groups=_space_list('allowgroups'),
        deny_users=_space_list('denyusers'),
        deny_groups=_space_list('denygroups'),
    )
