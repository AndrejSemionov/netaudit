"""
Server security audit. Two modes:
  server_audit          — from the inside over SSH: nginx, fail2ban, firewall, SQL, SSH hardening.
  web_security_external — from the outside, no access: headers, TLS versions, version leaks,
                          exposed sensitive paths (.git, .env, wp-config...).

All SSH commands are read-only — nothing on the client's server is ever changed.
Each finding has a severity (high/medium/low/ok) and an explanation.
"""

from __future__ import annotations

import re
import socket
import ssl

from ..registry import register
from ..findings import finding as _finding
from ..utils import run_cmd, tool_available
from ..ssh import SSHExecutor, HostKeyMismatchError
from ..ssh_config import collect_ssh_config
from ..nginx_config import collect_nginx_config

try:
    import paramiko
except ImportError:
    paramiko = None

# ===========================================================================
# Helpers
# ===========================================================================

# ===========================================================================
# nginx
# ===========================================================================

def audit_nginx(ssh: SSHExecutor) -> dict:
    """Findings-producing nginx audit. Thin wrapper: all data collection and
    parsing now lives in nginx_config.collect_nginx_config() (see that
    module's docstring for why) - this function's job is only to decide
    severity from the already-parsed NginxConfig fields. Behavior and return
    shape are unchanged from before this refactor, so every existing caller
    (check_server_audit, tests, the web UI) keeps working without changes.

    Findings that correspond to a control in docs/checks/nginx_hardening.md's
    catalogue carry a stable id= matching that control's ID (e.g.
    'NGX-CONF-001' for server_tokens) - this is what lets the future
    nginx_hardening check set Component.finding_id to reference the exact
    same finding a user already sees here, instead of nginx_hardening
    re-deriving its own separate finding for the same fact (see
    docs/checks/nginx_hardening.md section 5 "Finding <-> Component
    relationship"). Two findings deliberately have no id: the "no access to
    the config" case (not a control - it's the signal that nothing below was
    evaluated at all, handled at the component-group level per section 4.1 of
    the spec) and the "no obvious issues" ok-fallback (an aggregate summary,
    not a specific control's result).
    """
    cfg = collect_nginx_config(ssh)
    if not cfg.installed:
        return {'installed': False}
    if not cfg.readable:
        return {'installed': True, 'version': cfg.version,
                'findings': [_finding('low', 'no access to the config', 'nginx -T requires root')]}

    findings = []

    # server_tokens -> NGX-CONF-001
    if cfg.server_tokens != 'off':
        findings.append(_finding('medium', 'server_tokens is not disabled',
                                 'nginx reveals its version in headers and error pages — add server_tokens off;',
                                 id='NGX-CONF-001'))

    # outdated TLS -> NGX-TLS-001 (legacy protocols present)
    # ssl_protocols not set explicitly -> NGX-TLS-003 (protocols explicitly configured)
    if cfg.ssl_protocols:
        protos_str = ' '.join(cfg.ssl_protocols)
        if 'TLSv1' in cfg.ssl_protocols or 'TLSv1.1' in cfg.ssl_protocols:
            findings.append(_finding('high', 'outdated TLS 1.0/1.1 is enabled', f'ssl_protocols: {protos_str}',
                                     id='NGX-TLS-001'))
    elif cfg.has_ssl_certificate:
        findings.append(_finding('low', 'ssl_protocols is not set explicitly', 'relying on the default',
                                 id='NGX-TLS-003'))

    # security headers in the config -> NGX-HDR-001/002/003
    header_control_ids = {
        'Strict-Transport-Security': 'NGX-HDR-001',
        'X-Frame-Options': 'NGX-HDR-002',
        'X-Content-Type-Options': 'NGX-HDR-003',
    }
    for hdr, sev in [('Strict-Transport-Security', 'medium'), ('X-Frame-Options', 'low'),
                     ('X-Content-Type-Options', 'low')]:
        if hdr.lower() not in cfg.headers_present:
            findings.append(_finding(sev, f'missing header {hdr}', 'no add_header set in the config',
                                     id=header_control_ids[hdr]))

    # dangerous directives -> NGX-CONF-002
    if cfg.autoindex_on:
        findings.append(_finding('medium', 'autoindex on', 'directory listing is enabled — exposes the file structure',
                                 id='NGX-CONF-002'))

    if not findings:
        findings.append(_finding('ok', 'no obvious issues found in the nginx config'))

    return {'installed': True, 'version': cfg.version, 'findings': findings}

# ===========================================================================
# fail2ban
# ===========================================================================

def audit_fail2ban(ssh: SSHExecutor) -> dict:
    out, _ = ssh.run('which fail2ban-client || echo NONE')
    if 'NONE' in out:
        return {'installed': False,
                'findings': [_finding('medium', 'fail2ban is not installed',
                                      'no brute-force protection for SSH/web — recommended to install')]}

    status, err = ssh.run('fail2ban-client status 2>&1')
    if 'Failed' in status or 'ERROR' in status or err.strip():
        return {'installed': True,
                'findings': [_finding('low', 'no access to fail2ban status', 'requires root')]}

    jail_m = re.search(r'Jail list:\s*(.+)', status)
    jails = [j.strip() for j in jail_m.group(1).split(',')] if jail_m else []
    findings = []
    total_banned = 0
    jail_info = []
    for jail in jails:
        if not jail:
            continue
        jstatus, _ = ssh.run(f'fail2ban-client status {jail} 2>/dev/null')
        banned_m = re.search(r'Currently banned:\s*(\d+)', jstatus)
        total_m = re.search(r'Total banned:\s*(\d+)', jstatus)
        banned = int(banned_m.group(1)) if banned_m else 0
        total = int(total_m.group(1)) if total_m else 0
        total_banned += total
        jail_info.append({'jail': jail, 'currently_banned': banned, 'total_banned': total})

    if not jails or jails == ['']:
        findings.append(_finding('medium', 'no active jails', 'fail2ban is running, but isn\'t protecting any services'))
    else:
        if not any('ssh' in j.lower() for j in jails):
            findings.append(_finding('medium', 'no jail for SSH', 'SSH isn\'t protected against brute-force'))
        findings.append(_finding('ok', f'active jails: {len(jails)}', f'total bans: {total_banned}'))

    return {'installed': True, 'jails': jail_info, 'findings': findings}

# ===========================================================================
# firewall
# ===========================================================================

# iptables -A INPUT rule with -j ACCEPT and no preceding match criteria at
# all (no -s/-d/-p/--dport/-i/-m/...) - this is functionally identical to
# an ACCEPT policy with zero rules (accepts everything), just spelled out
# as an explicit rule instead of the chain default. Matches only the
# EXACT unconditional form; any match option before -j ACCEPT means the
# rule is conditional (e.g. '-p tcp --dport 22 -j ACCEPT' is fine) and
# does not match this pattern.
_IPTABLES_UNCONDITIONAL_ACCEPT_RE = re.compile(r'^-A INPUT\s+-j ACCEPT\s*$')


def _ufw_verdict(evidence) -> tuple[str, dict]:
    """Returns (verdict, context) for the UFW backend.

    verdict is one of:
      'NOT_PRESENT' - confirmed absent (command -v exit 127) - not a
                       finding at all, this host simply doesn't have ufw.
      'ACTIVE'      - confirmed 'Status: active'
      'INACTIVE'    - confirmed 'Status: inactive' - HIGH finding
      'UNKNOWN'     - presence or status could not be confirmed; context
                       carries the specific reason (never silently 'ok').

    context is a dict with a 'reason' key for UNKNOWN, used to build the
    finding's detail text - never invented text, always the actual
    evidence (exit code, stdout snippet) that produced the verdict.
    """
    from ..firewall_config import tool_is_present

    present = tool_is_present(evidence.ufw_present)
    if present is None:
        if not evidence.ufw_present.completed:
            return 'UNKNOWN', {'reason': 'could not confirm whether ufw is installed (command did not complete)'}
        return 'UNKNOWN', {'reason': f'unexpected exit code {evidence.ufw_present.exit_code} checking for ufw'}
    if present is False:
        return 'NOT_PRESENT', {}

    status = evidence.ufw_status
    if status is None or not status.completed:
        return 'UNKNOWN', {'reason': 'ufw is installed, but `ufw status` did not complete'}
    if status.exit_code != 0:
        return 'UNKNOWN', {'reason': f'ufw is installed, but `ufw status` failed (exit {status.exit_code})'}
    if 'Status: active' in status.stdout:
        return 'ACTIVE', {}
    if 'Status: inactive' in status.stdout:
        return 'INACTIVE', {}
    return 'UNKNOWN', {'reason': f'ufw is installed, but status output was not recognized: {status.stdout[:120]!r}'}


def _nftables_verdict(evidence) -> tuple[str, dict]:
    """Returns (verdict, context) for the nftables backend.

    verdict is one of:
      'LIVE_ACTIVE'  - confirmed non-empty live ruleset (exit 0, non-empty
                        stdout) - the only way to reach this verdict; a
                        readable config file alone is NEVER sufficient
                        (this is the direct fix for FW-3).
      'LIVE_EMPTY'   - confirmed empty live ruleset (exit 0, empty
                        stdout) - a real, confirmed fact, not a
                        collection failure.
      'LIVE_UNKNOWN' - live ruleset collection did not complete or
                        failed (permission denied, timeout, etc).

    context carries 'config_readable' (bool) and, when true,
    'config_path'/'config_rule_lines' - config-file evidence is ALWAYS
    attached as context, never used to upgrade LIVE_EMPTY or
    LIVE_UNKNOWN into an ACTIVE-shaped verdict. The caller uses
    config_readable to decide whether a LIVE_EMPTY verdict deserves the
    stronger "config says rules exist but the kernel has none" finding.
    """
    cfg = evidence.nftables_config
    config_readable = cfg.completed and cfg.exit_code == 0 and bool(cfg.content.strip())
    context = {'config_readable': config_readable}
    if config_readable:
        context['config_path'] = cfg.path
        context['config_rule_lines'] = len(
            [l for l in cfg.content.splitlines() if l.strip() and not l.strip().startswith('#')])

    live = evidence.nftables_live
    if not live.completed:
        return 'LIVE_UNKNOWN', {**context, 'reason': 'nft list ruleset did not complete'}
    if live.exit_code != 0:
        return 'LIVE_UNKNOWN', {**context, 'reason': f'nft list ruleset failed (exit {live.exit_code})'}
    if live.stdout.strip():
        return 'LIVE_ACTIVE', context
    return 'LIVE_EMPTY', context


def _parse_iptables_input(stdout: str) -> tuple[str | None, list[str]]:
    """Extracts the INPUT chain's policy and its -A INPUT rule lines from
    raw `iptables -S` output. Returns (policy, rule_lines) - policy is
    None if no '-P INPUT ...' line was found at all (shouldn't happen on
    a real host, but this function doesn't assume it)."""
    policy = None
    rules = []
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith('-P INPUT '):
            policy = line.split()[2] if len(line.split()) > 2 else None
        elif line.startswith('-A INPUT'):
            rules.append(line)
    return policy, rules


def _iptables_verdict(evidence) -> tuple[str, dict]:
    """Returns (verdict, context) for the iptables backend.

    verdict is one of:
      'OPEN'     - INPUT policy ACCEPT with either zero -A INPUT rules,
                   or an unconditional '-A INPUT -j ACCEPT' rule among
                   them (functionally identical to zero rules - this is
                   the direct fix for FW-4, which previously only
                   checked rule COUNT, not content).
      'FILTERED' - INPUT policy is not ACCEPT, or ACCEPT with only
                   conditional (match-qualified) rules.
      'UNKNOWN'  - collection did not complete/failed, or no INPUT
                   policy line was found in otherwise-successful output.
    """
    live = evidence.iptables_live
    if not live.completed:
        return 'UNKNOWN', {'reason': 'iptables -S did not complete'}
    if live.exit_code != 0:
        return 'UNKNOWN', {'reason': f'iptables -S failed (exit {live.exit_code})'}

    policy, rules = _parse_iptables_input(live.stdout)
    if policy is None:
        return 'UNKNOWN', {'reason': 'iptables -S succeeded but no INPUT policy line was found',
                            'raw_snippet': live.stdout[:200]}

    unconditional_accept = any(_IPTABLES_UNCONDITIONAL_ACCEPT_RE.match(r) for r in rules)
    if policy == 'ACCEPT' and (not rules or unconditional_accept):
        return 'OPEN', {'policy': policy, 'rule_count': len(rules),
                         'unconditional_accept': unconditional_accept}
    return 'FILTERED', {'policy': policy, 'rule_count': len(rules)}


def audit_firewall(ssh: SSHExecutor) -> dict:
    """Findings-producing firewall audit. Thin wrapper over
    firewall_config.collect_firewall_config() (raw evidence collection)
    and the per-backend verdict functions above (_ufw_verdict/
    _nftables_verdict/_iptables_verdict, pure functions with no I/O -
    the actual interpretation logic, independently unit-testable without
    SSH mocking).

    Each backend produces its own, independent finding(s) - there is
    deliberately NO aggregate "firewall is secure/open" verdict across
    backends (see this function's quality-audit session notes): a host
    can legitimately run more than one of these simultaneously (e.g.
    iptables-nft plus a leftover UFW install), and collapsing three
    independent facts into one verdict would suppress real findings the
    same way the pre-refactor code's single `active` flag did (e.g. an
    active-but-open iptables chain being silently masked by an
    unrelated, correctly-configured nftables ruleset).

    UNKNOWN is never reported as 'ok' - see the individual verdict
    functions' docstrings for exactly what UNKNOWN means for each
    backend and why. This is the direct fix for FW-1 (UFW collection
    failure previously read as "not installed"), FW-3 (a readable
    nftables config file previously counted as proof of an active
    firewall), and FW-4 (iptables rule-count-only open-firewall
    detection previously missed an explicit unconditional ACCEPT rule).
    """
    from ..firewall_config import collect_firewall_config

    evidence = collect_firewall_config(ssh)
    findings = []

    # --- UFW ---
    ufw_verdict, ufw_ctx = _ufw_verdict(evidence)
    if ufw_verdict == 'ACTIVE':
        findings.append(_finding('ok', 'ufw is active'))
    elif ufw_verdict == 'INACTIVE':
        findings.append(_finding('high', 'ufw is installed but disabled'))
    elif ufw_verdict == 'UNKNOWN':
        findings.append(_finding('low', 'could not determine ufw status', ufw_ctx['reason'],
                                  requires_manual_verification=True))
    # NOT_PRESENT produces no finding - ufw simply isn't on this host.

    # --- nftables ---
    nft_verdict, nft_ctx = _nftables_verdict(evidence)
    if nft_verdict == 'LIVE_ACTIVE':
        detail = f'{len(evidence.nftables_live.stdout.splitlines())} lines in the live ruleset'
        findings.append(_finding('ok', 'nftables: active ruleset loaded in the kernel', detail))
    elif nft_verdict == 'LIVE_EMPTY':
        if nft_ctx['config_readable']:
            # The core FW-3 case: declared rules exist, but the kernel
            # confirms none are actually loaded - a real discrepancy,
            # not a guess, and NOT downgraded to 'ok' just because a
            # config file happens to exist.
            findings.append(_finding(
                'high',
                'nftables config file has rules, but the live kernel ruleset is empty',
                f"config: {nft_ctx['config_path']} (~{nft_ctx['config_rule_lines']} rule lines); "
                'the configuration may not have been loaded (service not started/reloaded, '
                'syntax error, or a stale/unused file)',
                requires_manual_verification=True,
            ))
        else:
            findings.append(_finding('low', 'nftables: no rules loaded and no config file found',
                                      'live ruleset is empty and no readable nftables config file was found'))
    else:  # LIVE_UNKNOWN
        detail = nft_ctx['reason']
        if nft_ctx['config_readable']:
            detail += (f" (a readable config file exists at {nft_ctx['config_path']} with "
                       f"~{nft_ctx['config_rule_lines']} rule lines, but this does NOT confirm "
                       'those rules are actually loaded - see live ruleset collection failure above)')
        findings.append(_finding('low', 'could not determine nftables live ruleset state', detail,
                                  requires_manual_verification=True))

    # --- iptables ---
    ipt_verdict, ipt_ctx = _iptables_verdict(evidence)
    if ipt_verdict == 'OPEN':
        reason = ('explicit unconditional ACCEPT rule' if ipt_ctx.get('unconditional_accept')
                  else 'no filtering rules')
        findings.append(_finding('high', 'iptables INPUT is effectively open',
                                 f'policy {ipt_ctx["policy"]}, {reason} — everything is allowed'))
    elif ipt_verdict == 'FILTERED':
        findings.append(_finding('ok', 'iptables: INPUT chain is filtered',
                                 f'policy {ipt_ctx["policy"]}, {ipt_ctx["rule_count"]} rule(s)'))
    else:  # UNKNOWN
        findings.append(_finding('low', 'could not determine iptables status', ipt_ctx['reason'],
                                  requires_manual_verification=True))

    return {'findings': findings}

# ===========================================================================
# SQL (MySQL/MariaDB) — config and exposure, without logging into the DB
# ===========================================================================

def audit_sql(ssh: SSHExecutor) -> dict:
    out, _ = ssh.run('which mysql mariadb 2>/dev/null || echo NONE')
    running, _ = ssh.run('ss -tlnp 2>/dev/null | grep -E ":3306" || echo NOPORT')
    if 'NONE' in out and 'NOPORT' in running:
        return {'installed': False}

    findings = []
    # 3306 exposed externally?
    if 'NOPORT' not in running:
        if re.search(r'0\.0\.0\.0:3306|\*:3306|:::3306', running):
            findings.append(_finding('high', 'MySQL is listening on all interfaces (0.0.0.0:3306)',
                                     'the DB is reachable externally — should be bind-address=127.0.0.1 unless external access is needed'))
        else:
            findings.append(_finding('ok', 'MySQL is listening locally'))

    # bind-address in the config (ignore commented-out lines — the earlier grep
    # also matched '#bind-address = 0.0.0.0', giving a false high on the default,
    # never-activated value from the template config)
    bind, _ = ssh.run("grep -rh '^\\s*bind-address' /etc/mysql/ 2>/dev/null | head -3")
    if bind.strip() and '127.0.0.1' not in bind and '0.0.0.0' in bind:
        findings.append(_finding('high', 'bind-address=0.0.0.0 in the MySQL config', bind.strip()))

    if not findings:
        findings.append(_finding('ok', 'MySQL/MariaDB: no obvious exposure issues found'))

    return {'installed': True, 'findings': findings}

# ===========================================================================
# SSH hardening
# ===========================================================================

def audit_ssh_hardening(ssh: SSHExecutor) -> dict:
    """Findings-producing SSH hardening check - the pre-existing function
    this project has had since before ssh_hardening (the scoring module,
    netaudit_pkg/checks/ssh_hardening.py) existed. Refactored to consume
    collect_ssh_config()/SSHConfig instead of its own raw-text `directive()`
    regex against `cat sshd_config; cat sshd_config.d/*.conf` - two bugs
    that raw-text approach had, both fixed by this refactor:

    1. No sudo: `cat sshd_config.d/*.conf` silently lost any Include file
       without world-read permissions (confirmed on a live VM - see
       docs/checks/ssh_hardening.md section 2 - a 600-mode
       50-cloud-init.conf was invisible to this check before this refactor).
       collect_ssh_config() uses ssh.sudo() for `sshd -T`, fixing this.
    2. Wrong precedence: concatenating main-file + Include text and taking
       the first regex match doesn't reliably reflect which file OpenSSH
       actually gives precedence to (also documented in that same section).
       `sshd -T` resolves this correctly server-side; this function no
       longer does its own precedence reasoning at all.

    External return shape is unchanged from before this refactor (same
    keys: 'port', 'root_login', 'password_auth', 'max_auth_tries',
    'findings'; same finding text/severity for the three checks this
    function has always covered) except for the two fixes above, which
    change VALUES this function returns for the same input in cases where
    the old parsing was wrong - not the shape. Findings now carry stable
    id= values (SSH-AUTH-001/002/003) matching docs/checks/ssh_hardening.md's
    control catalogue, added fresh in this refactor (the pre-refactor
    findings had no id= at all - see test_audit_ssh_hardening_legacy.py,
    written before this refactor to pin exactly what changed).

    Port and MaxAuthTries are still read and returned (unchanged, for any
    caller relying on them) but max_auth_tries no longer produces a
    finding here - see docs/checks/ssh_hardening.md section 6.2: bounding
    MaxAuthTries is SSH-AUTH-007's job (the scoring module), not this
    findings function's; the pre-refactor code never generated a finding
    for it either, only exposed the raw value, so this preserves that.

    Fail-safe defaults for a None SSHConfig field are pinned to match the
    PRE-REFACTOR directive() defaults exactly (root_login->
    'prohibit-password', password_authentication->'yes'), not derived from
    Python truthiness - a naive `'yes' if cfg.password_authentication else
    'no'` was caught and rejected during this refactor because it silently
    flips an unresolved/None value to the SAFE-looking 'no' instead of the
    original code's pessimistic 'yes', which is the wrong failure direction
    for a security report (a None should read as "couldn't confirm this is
    safe," not "assume it's fine"). See
    test_current_behavior_none_field_defaults_fail_safe.
    """
    cfg = collect_ssh_config(ssh)
    if not cfg.readable:
        return {'findings': [_finding('low', 'no access to sshd_config')]}

    findings = []

    # Fail-safe defaults for a None field (readable=True but this specific
    # value somehow didn't resolve - an anomaly on a real sshd -T, which
    # always prints every directive's effective value, but defended against
    # here anyway rather than silently changing this function's risk
    # posture). Each default below matches the PRE-REFACTOR directive()
    # default exactly - not "whatever seems reasonable now" - because
    # audit_ssh_hardening() is a security-facing report and a None here
    # must fail toward "flag it", never toward "assume it's fine",
    # regardless of which collector produced the data. See
    # test_audit_ssh_hardening_legacy.py's
    # test_current_behavior_none_field_defaults_fail_safe for the
    # regression test pinning this.
    root_login = cfg.permit_root_login if cfg.permit_root_login is not None else 'prohibit-password'
    if root_login == 'yes':
        findings.append(_finding('high', 'PermitRootLogin yes',
                                 'root login is allowed — disable it or set prohibit-password',
                                 id='SSH-AUTH-001'))

    # cfg.password_authentication is None -> fail-safe 'yes' (pessimistic:
    # unknown state is treated as the insecure one), NOT the `X if Y else
    # 'no'` shortcut - that shortcut silently flips None to the SAFE-looking
    # 'no', which is backwards for a security report. This was caught before
    # being shipped - see this session's working notes.
    if cfg.password_authentication is None:
        pw_auth = 'yes'
    else:
        pw_auth = 'yes' if cfg.password_authentication else 'no'
    if pw_auth == 'yes':
        findings.append(_finding('medium', 'PasswordAuthentication yes',
                                 'password login is allowed — vulnerable to brute-force, keys-only is better',
                                 id='SSH-AUTH-002'))

    # permit_empty_passwords: pre-refactor default was 'no' (not a finding)
    # - None here already matches that direction via ordinary falsiness, no
    # special-casing needed, unlike password_authentication above.
    if cfg.permit_empty_passwords:
        findings.append(_finding('high', 'PermitEmptyPasswords yes', 'empty passwords are allowed!',
                                 id='SSH-AUTH-003'))

    port = cfg.port if cfg.port is not None else '22'  # legacy default, matches pre-refactor behavior
    max_auth = str(cfg.max_auth_tries) if cfg.max_auth_tries is not None else '6'

    if not findings:
        findings.append(_finding('ok', 'SSH is configured sensibly'))

    return {'port': port, 'root_login': root_login, 'password_auth': pw_auth,
            'max_auth_tries': max_auth, 'findings': findings}

# ===========================================================================
# Combined SSH audit
# ===========================================================================

@register(
    id='server_audit', label='Server security audit (SSH)', category='server',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Host', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'User', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH port', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Key path', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Password (if not using a key)', 'default': ''},
    ],
    required_tools=[],
    description='Full server security audit over SSH: nginx, fail2ban, firewall, MySQL, SSH hardening. Read-only.',
)
def check_server_audit(host='', user='root', port=22, key_path='', password='') -> dict:
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
        sections = {
            'nginx': audit_nginx(ssh),
            'fail2ban': audit_fail2ban(ssh),
            'firewall': audit_firewall(ssh),
            'sql': audit_sql(ssh),
            'ssh': audit_ssh_hardening(ssh),
        }
    finally:
        ssh.close()

    # severity summary
    counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
    for sec in sections.values():
        for f in sec.get('findings', []):
            counts[f['severity']] = counts.get(f['severity'], 0) + 1

    return {'host': host, 'sections': sections, 'summary': counts}

# ===========================================================================
# External web audit (no server access)
# ===========================================================================

SENSITIVE_PATHS = [
    '/.git/config', '/.env', '/wp-config.php.bak', '/wp-config.php~',
    '/.htaccess', '/server-status', '/phpinfo.php', '/.svn/entries',
    '/config.php.bak', '/backup.sql', '/.DS_Store',
    '/.aws/credentials', '/id_rsa', '/composer.json', '/package.json',
    '/api/swagger.json', '/swagger.json', '/swagger-ui.html', '/api-docs',
    '/docker-compose.yml', '/.npmrc',
]

def _check_tls_version(hostname, version_name, ssl_version) -> bool:
    """Tries connecting with a specific TLS version. True if the server accepted it."""
    try:
        ctx = ssl.SSLContext(ssl_version)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return True
    except (ssl.SSLError, socket.error, OSError, ValueError):
        return False

def _parse_set_cookie_headers(head: str) -> list[str]:
    """Extracts all Set-Cookie lines from raw curl -I response headers.
    Headers are case-insensitive, the value may start on a new line after ':'."""
    return re.findall(r'^set-cookie:\s*(.+)$', head, re.IGNORECASE | re.MULTILINE)

def _audit_cookies(cookie_lines: list[str]) -> list[dict]:
    """Checks Secure/HttpOnly/SameSite flags for each cookie found."""
    findings = []
    for line in cookie_lines:
        name = line.split('=', 1)[0].strip()
        lower = line.lower()
        missing = []
        if 'secure' not in lower:
            missing.append('Secure')
        if 'httponly' not in lower:
            missing.append('HttpOnly')
        samesite_m = re.search(r'samesite=(\w+)', lower)
        samesite_val = samesite_m.group(1) if samesite_m else None
        if samesite_val is None:
            missing.append('SameSite')
        elif samesite_val == 'none' and 'secure' not in lower:
            findings.append(_finding('high', f'cookie "{name}": SameSite=None without Secure',
                                      'the cookie is sent in cross-site requests and is accessible over non-HTTPS'))
        if missing:
            sev = 'high' if 'HttpOnly' in missing and 'Secure' in missing else 'medium'
            findings.append(_finding(sev, f'cookie "{name}": missing flag(s) {", ".join(missing)}',
                                      line[:120]))
    return findings

def _audit_cors(base: str) -> list[dict]:
    """Checks CORS headers for the dangerous combination: any Origin allowed + credentials.
    Sends a known-foreign Origin and sees what the server reflects back."""
    findings = []
    if not tool_available('curl'):
        return findings
    fake_origin = 'https://evil-attacker-test.example'
    code, head, _ = run_cmd(['curl', '-s', '-I', '-L', '--max-time', '10',
                              '-H', f'Origin: {fake_origin}', base], timeout=15)
    hl = head.lower()
    acao_m = re.search(r'^access-control-allow-origin:\s*(.+)$', head, re.IGNORECASE | re.MULTILINE)
    acac = 'access-control-allow-credentials: true' in hl
    if acao_m:
        acao_val = acao_m.group(1).strip()
        if acao_val == '*' and acac:
            findings.append(_finding('high', 'CORS: Allow-Origin=* together with Allow-Credentials=true',
                                      'per spec, browsers should reject this, but broken proxies/older clients might let it through — fix the config explicitly'))
        elif acao_val == fake_origin:
            findings.append(_finding('high', 'CORS: the server reflects any Origin back',
                                      f'responded with Allow-Origin: {acao_val} to a fake Origin — any site can read responses as the user'))
    return findings

def _audit_error_page(base: str) -> list[dict]:
    """Requests a known-nonexistent path and looks for signs of a verbose error
    (stack trace, filesystem path, framework version in the response body)."""
    findings = []
    if not tool_available('curl'):
        return findings
    probe_path = '/netaudit-probe-nonexistent-' + str(abs(hash(base)) % 10000)
    code, body, _ = run_cmd(['curl', '-s', '-L', '--max-time', '10', base + probe_path], timeout=15)
    if not body:
        return findings
    lower = body.lower()
    signals = {
        'stack trace': ['traceback (most recent call last)', 'at System.', 'stacktrace',
                         'stack trace:', 'exception in thread'],
        'filesystem path': ['/var/www/', '/home/', 'c:\\inetpub', 'c:\\users\\'],
        'framework/language version in the error': ['php version', 'django version', 'werkzeug', 'debug = true',
                                              'whoops', 'laravel', 'yii2', '<title>fatal error'],
    }
    for label, needles in signals.items():
        if any(n in lower for n in needles):
            findings.append(_finding('medium', f'verbose error page: looks like {label}',
                                      f'the error page at {probe_path} exposes internal details — turn off debug mode in production'))
            break  # one finding is enough, don't duplicate per signal
    return findings

@register(
    id='web_security_external', label='External web audit (no access)', category='site', risk_level='PASSIVE',
    params=[{'name': 'url', 'type': 'text', 'label': 'Site URL', 'default': 'https://example.com'}],
    required_tools=['curl'],
    description='Audits a site from the outside: security headers, outdated TLS, version leaks, exposed '
                '.git/.env/backups, cookie flags (Secure/HttpOnly/SameSite), CORS misconfiguration, '
                'verbose error pages.',
)
def check_web_security_external(url='https://example.com') -> dict:
    from urllib.parse import urlparse
    parsed = urlparse(url if '://' in url else f'https://{url}')
    hostname = parsed.hostname
    if not hostname:
        return {'error': f'could not parse URL: {url}'}
    base = f'https://{hostname}'
    findings = []

    # headers
    if tool_available('curl'):
        code, head, _ = run_cmd(['curl', '-s', '-I', '-L', '--max-time', '10', base], timeout=15)
        hl = head.lower()
        server_m = re.search(r'server:\s*(.+)', head, re.IGNORECASE)
        if server_m and re.search(r'\d+\.\d+', server_m.group(1)):
            findings.append(_finding('low', 'the server discloses its version', f'Server: {server_m.group(1).strip()}'))
        for hdr, sev in [('strict-transport-security', 'medium'), ('x-frame-options', 'low'),
                         ('x-content-type-options', 'low'), ('content-security-policy', 'low')]:
            if hdr not in hl:
                findings.append(_finding(sev, f'missing header {hdr}'))
        for hdr in ('x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'):
            m = re.search(rf'^{hdr}:\s*(.+)$', head, re.IGNORECASE | re.MULTILINE)
            if m:
                findings.append(_finding('low', f'header {hdr} discloses the technology',
                                          m.group(1).strip()))
        findings.extend(_audit_cookies(_parse_set_cookie_headers(head)))
    else:
        head = ''

    findings.extend(_audit_cors(base))
    findings.extend(_audit_error_page(base))

    # outdated TLS
    old_tls = []
    if hasattr(ssl, 'PROTOCOL_TLSv1'):
        if _check_tls_version(hostname, 'TLS 1.0', ssl.PROTOCOL_TLSv1):
            old_tls.append('TLS 1.0')
    if hasattr(ssl, 'PROTOCOL_TLSv1_1'):
        if _check_tls_version(hostname, 'TLS 1.1', ssl.PROTOCOL_TLSv1_1):
            old_tls.append('TLS 1.1')
    if old_tls:
        findings.append(_finding('high', 'outdated TLS versions are supported', ', '.join(old_tls)))

    # sensitive paths
    exposed = []
    if tool_available('curl'):
        for path in SENSITIVE_PATHS:
            code, out, _ = run_cmd(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                                    '--max-time', '6', base + path], timeout=10)
            if out.strip() == '200':
                exposed.append(path)
    if exposed:
        findings.append(_finding('high', 'sensitive paths are exposed', ', '.join(exposed)))

    if not findings:
        findings.append(_finding('ok', 'no external issues found'))

    counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
    for f in findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    return {'url': base, 'findings': findings, 'summary': counts, 'exposed_paths': exposed}
