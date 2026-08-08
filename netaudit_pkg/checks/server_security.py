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
from ..utils import run_cmd, tool_available

try:
    import paramiko
except ImportError:
    paramiko = None


# ===========================================================================
# Helpers
# ===========================================================================

def _ssh_connect(host, user, port, key_path, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {'hostname': host, 'port': int(port), 'username': user, 'timeout': 10,
              'look_for_keys': bool(key_path), 'allow_agent': bool(key_path)}
    if key_path and key_path.strip():
        from pathlib import Path
        kwargs['key_filename'] = str(Path(key_path).expanduser())
    elif password:
        kwargs['password'] = password
    client.connect(**kwargs)
    return client


def _run(client, cmd, timeout=15):
    _, so, se = client.exec_command(cmd, timeout=timeout)
    return so.read().decode(errors='replace'), se.read().decode(errors='replace')


def _finding(severity, title, detail=''):
    return {'severity': severity, 'title': title, 'detail': detail}


# ===========================================================================
# nginx
# ===========================================================================

def audit_nginx(client) -> dict:
    out, _ = _run(client, 'which nginx || echo NONE')
    if 'NONE' in out:
        return {'installed': False}

    ver, _ = _run(client, 'nginx -v 2>&1')
    conf, _ = _run(client, 'nginx -T 2>/dev/null')
    findings = []

    if not conf:
        return {'installed': True, 'version': ver.strip(),
                'findings': [_finding('low', 'no access to the config', 'nginx -T requires root')]}

    # server_tokens
    if 'server_tokens off' not in conf:
        findings.append(_finding('medium', 'server_tokens is not disabled',
                                 'nginx reveals its version in headers and error pages — add server_tokens off;'))

    # outdated TLS
    ssl_proto_m = re.search(r'ssl_protocols\s+([^;]+);', conf)
    if ssl_proto_m:
        protos = ssl_proto_m.group(1)
        if 'TLSv1 ' in protos or 'TLSv1;' in protos or 'TLSv1.1' in protos or protos.strip().endswith('TLSv1'):
            findings.append(_finding('high', 'outdated TLS 1.0/1.1 is enabled', f'ssl_protocols: {protos.strip()}'))
    else:
        if 'ssl_certificate' in conf:
            findings.append(_finding('low', 'ssl_protocols is not set explicitly', 'relying on the default'))

    # security headers in the config
    for hdr, sev in [('Strict-Transport-Security', 'medium'), ('X-Frame-Options', 'low'),
                     ('X-Content-Type-Options', 'low')]:
        if hdr.lower() not in conf.lower():
            findings.append(_finding(sev, f'missing header {hdr}', 'no add_header set in the config'))

    # dangerous directives
    if re.search(r'autoindex\s+on', conf):
        findings.append(_finding('medium', 'autoindex on', 'directory listing is enabled — exposes the file structure'))

    if not findings:
        findings.append(_finding('ok', 'no obvious issues found in the nginx config'))

    return {'installed': True, 'version': ver.strip(), 'findings': findings}


# ===========================================================================
# fail2ban
# ===========================================================================

def audit_fail2ban(client) -> dict:
    out, _ = _run(client, 'which fail2ban-client || echo NONE')
    if 'NONE' in out:
        return {'installed': False,
                'findings': [_finding('medium', 'fail2ban is not installed',
                                      'no brute-force protection for SSH/web — recommended to install')]}

    status, err = _run(client, 'fail2ban-client status 2>&1')
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
        jstatus, _ = _run(client, f'fail2ban-client status {jail} 2>/dev/null')
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

def audit_firewall(client) -> dict:
    findings = []

    # nftables: try reading the config file directly first (doesn't require root
    # if the file has normal read permissions) - this is more reliable than
    # live 'nft list ruleset', which always fails with 'Operation not permitted'
    # without root/CAP_NET_ADMIN and gives a false "firewall not configured"
    # even though one actually exists.
    nft_conf = ''
    nft_conf_path = ''
    for path in ('/etc/nftables.conf', '/etc/nftables/nftables.conf', '/etc/nftables/main.nft'):
        out, _ = _run(client, f'cat {path} 2>/dev/null')
        if out.strip():
            nft_conf = out
            nft_conf_path = path
            break

    # ufw?
    ufw, _ = _run(client, 'which ufw && ufw status 2>/dev/null || echo NOUFW')
    nft, _ = _run(client, 'nft list ruleset 2>/dev/null | head -100 || echo NONFT')
    ipt, _ = _run(client, 'iptables -S 2>/dev/null | head -60 || echo NOIPT')

    active = False
    if 'Status: active' in ufw:
        active = True
        findings.append(_finding('ok', 'ufw is active'))
    elif 'NOUFW' not in ufw and 'Status: inactive' in ufw:
        findings.append(_finding('high', 'ufw is installed but disabled'))

    if nft_conf:
        active = True
        rules = len([l for l in nft_conf.splitlines() if l.strip() and not l.strip().startswith('#')])
        findings.append(_finding('ok', f'nftables: config {nft_conf_path}, ~{rules} rule lines',
                                 'read from the file (without root - live nft list ruleset requires root/CAP_NET_ADMIN)'))
    elif 'NONFT' not in nft and nft.strip():
        rules = len([l for l in nft.splitlines() if l.strip()])
        active = True
        findings.append(_finding('ok', f'nftables: ~{rules} rules'))

    if not active:
        if 'NOIPT' not in ipt and ipt.strip():
            # check the INPUT policy
            if '-P INPUT ACCEPT' in ipt and ipt.count('-A INPUT') == 0:
                findings.append(_finding('high', 'firewall is effectively open',
                                         'iptables INPUT policy ACCEPT with no rules — everything is allowed'))
            else:
                findings.append(_finding('ok', 'iptables: rules are present'))
        else:
            findings.append(_finding('low', 'could not determine firewall status',
                                     'neither ufw, nor nftables (live), nor iptables rules were detected over SSH '
                                     'without root; if nftables is configured via a non-standard config path — check manually'))

    return {'findings': findings}


# ===========================================================================
# SQL (MySQL/MariaDB) — config and exposure, without logging into the DB
# ===========================================================================

def audit_sql(client) -> dict:
    out, _ = _run(client, 'which mysql mariadb 2>/dev/null || echo NONE')
    running, _ = _run(client, 'ss -tlnp 2>/dev/null | grep -E ":3306" || echo NOPORT')
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
    bind, _ = _run(client, "grep -rh '^\\s*bind-address' /etc/mysql/ 2>/dev/null | head -3")
    if bind.strip() and '127.0.0.1' not in bind and '0.0.0.0' in bind:
        findings.append(_finding('high', 'bind-address=0.0.0.0 in the MySQL config', bind.strip()))

    if not findings:
        findings.append(_finding('ok', 'MySQL/MariaDB: no obvious exposure issues found'))

    return {'installed': True, 'findings': findings}


# ===========================================================================
# SSH hardening
# ===========================================================================

def audit_ssh_hardening(client) -> dict:
    conf, _ = _run(client, "cat /etc/ssh/sshd_config 2>/dev/null; cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null")
    if not conf.strip():
        return {'findings': [_finding('low', 'no access to sshd_config')]}

    findings = []

    def directive(name, default=None):
        m = re.search(rf'^\s*{name}\s+(\S+)', conf, re.IGNORECASE | re.MULTILINE)
        return m.group(1).lower() if m else default

    root_login = directive('PermitRootLogin', 'prohibit-password')
    if root_login in ('yes',):
        findings.append(_finding('high', 'PermitRootLogin yes', 'root login is allowed — disable it or set prohibit-password'))

    pw_auth = directive('PasswordAuthentication', 'yes')
    if pw_auth == 'yes':
        findings.append(_finding('medium', 'PasswordAuthentication yes',
                                 'password login is allowed — vulnerable to brute-force, keys-only is better'))

    if directive('PermitEmptyPasswords', 'no') == 'yes':
        findings.append(_finding('high', 'PermitEmptyPasswords yes', 'empty passwords are allowed!'))

    port = directive('Port', '22')
    max_auth = directive('MaxAuthTries', '6')

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
        client = _ssh_connect(host, user, port, key_path, password)
    except Exception as e:
        return {'error': f'could not connect: {e}'}

    try:
        sections = {
            'nginx': audit_nginx(client),
            'fail2ban': audit_fail2ban(client),
            'firewall': audit_firewall(client),
            'sql': audit_sql(client),
            'ssh': audit_ssh_hardening(client),
        }
    finally:
        client.close()

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
    id='web_security_external', label='External web audit (no access)', category='site',
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
