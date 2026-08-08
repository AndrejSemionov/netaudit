"""
Security-аудит сервера. Два режима:
  server_audit          — изнутри по SSH: nginx, fail2ban, firewall, SQL, SSH hardening.
  web_security_external — снаружи без доступа: заголовки, TLS-версии, утечка версий,
                          доступность чувствительных путей (.git, .env, wp-config...).

Все SSH-команды readonly — ничего не меняют на сервере клиента.
Каждая находка имеет severity (high/medium/low/ok) и объяснение.
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
# Вспомогательное
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
                'findings': [_finding('low', 'нет доступа к конфигу', 'nginx -T требует root')]}

    # server_tokens
    if 'server_tokens off' not in conf:
        findings.append(_finding('medium', 'server_tokens не выключен',
                                 'nginx раскрывает свою версию в заголовках и страницах ошибок — добавь server_tokens off;'))

    # устаревшие TLS
    ssl_proto_m = re.search(r'ssl_protocols\s+([^;]+);', conf)
    if ssl_proto_m:
        protos = ssl_proto_m.group(1)
        if 'TLSv1 ' in protos or 'TLSv1;' in protos or 'TLSv1.1' in protos or protos.strip().endswith('TLSv1'):
            findings.append(_finding('high', 'включены устаревшие TLS 1.0/1.1', f'ssl_protocols: {protos.strip()}'))
    else:
        if 'ssl_certificate' in conf:
            findings.append(_finding('low', 'ssl_protocols не задан явно', 'полагается на дефолт'))

    # security-заголовки в конфиге
    for hdr, sev in [('Strict-Transport-Security', 'medium'), ('X-Frame-Options', 'low'),
                     ('X-Content-Type-Options', 'low')]:
        if hdr.lower() not in conf.lower():
            findings.append(_finding(sev, f'нет заголовка {hdr}', 'не задан add_header в конфиге'))

    # опасные директивы
    if re.search(r'autoindex\s+on', conf):
        findings.append(_finding('medium', 'autoindex on', 'листинг директорий включён — раскрывает структуру файлов'))

    if not findings:
        findings.append(_finding('ok', 'явных проблем в конфиге nginx не найдено'))

    return {'installed': True, 'version': ver.strip(), 'findings': findings}


# ===========================================================================
# fail2ban
# ===========================================================================

def audit_fail2ban(client) -> dict:
    out, _ = _run(client, 'which fail2ban-client || echo NONE')
    if 'NONE' in out:
        return {'installed': False,
                'findings': [_finding('medium', 'fail2ban не установлен',
                                      'нет защиты от брутфорса SSH/веб — рекомендуется установить')]}

    status, err = _run(client, 'fail2ban-client status 2>&1')
    if 'Failed' in status or 'ERROR' in status or err.strip():
        return {'installed': True,
                'findings': [_finding('low', 'нет доступа к статусу fail2ban', 'нужен root')]}

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
        findings.append(_finding('medium', 'нет активных jail', 'fail2ban запущен, но не защищает сервисы'))
    else:
        if not any('ssh' in j.lower() for j in jails):
            findings.append(_finding('medium', 'нет jail для SSH', 'SSH не защищён от брутфорса'))
        findings.append(_finding('ok', f'активно jail: {len(jails)}', f'всего банов: {total_banned}'))

    return {'installed': True, 'jails': jail_info, 'findings': findings}


# ===========================================================================
# firewall
# ===========================================================================

def audit_firewall(client) -> dict:
    findings = []

    # nftables: сначала пробуем прочитать конфиг-файл напрямую (не требует root,
    # если у файла обычные права на чтение) — это надёжнее live-'nft list ruleset',
    # которая без root/CAP_NET_ADMIN всегда падает с 'Operation not permitted'
    # и даёт ложный вывод "firewall не настроен", хотя он реально есть.
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
        findings.append(_finding('ok', 'ufw активен'))
    elif 'NOUFW' not in ufw and 'Status: inactive' in ufw:
        findings.append(_finding('high', 'ufw установлен, но выключен'))

    if nft_conf:
        active = True
        rules = len([l for l in nft_conf.splitlines() if l.strip() and not l.strip().startswith('#')])
        findings.append(_finding('ok', f'nftables: конфиг {nft_conf_path}, строк правил ~{rules}',
                                 'прочитано из файла (без root — live nft list ruleset требует root/CAP_NET_ADMIN)'))
    elif 'NONFT' not in nft and nft.strip():
        rules = len([l for l in nft.splitlines() if l.strip()])
        active = True
        findings.append(_finding('ok', f'nftables: правил ~{rules}'))

    if not active:
        if 'NOIPT' not in ipt and ipt.strip():
            # проверим политику INPUT
            if '-P INPUT ACCEPT' in ipt and ipt.count('-A INPUT') == 0:
                findings.append(_finding('high', 'firewall фактически открыт',
                                         'iptables INPUT policy ACCEPT без правил — всё разрешено'))
            else:
                findings.append(_finding('ok', 'iptables: правила присутствуют'))
        else:
            findings.append(_finding('low', 'не удалось определить статус firewall',
                                     'ни ufw, ни nftables (live), ни iptables-правил не обнаружено по SSH без root; '
                                     'если nftables настроен через конфиг не по стандартным путям — проверь вручную'))

    return {'findings': findings}


# ===========================================================================
# SQL (MySQL/MariaDB) — конфиг и экспозиция, без входа в БД
# ===========================================================================

def audit_sql(client) -> dict:
    out, _ = _run(client, 'which mysql mariadb 2>/dev/null || echo NONE')
    running, _ = _run(client, 'ss -tlnp 2>/dev/null | grep -E ":3306" || echo NOPORT')
    if 'NONE' in out and 'NOPORT' in running:
        return {'installed': False}

    findings = []
    # 3306 наружу?
    if 'NOPORT' not in running:
        if re.search(r'0\.0\.0\.0:3306|\*:3306|:::3306', running):
            findings.append(_finding('high', 'MySQL слушает на всех интерфейсах (0.0.0.0:3306)',
                                     'БД доступна извне — должно быть bind-address=127.0.0.1, если не нужен внешний доступ'))
        else:
            findings.append(_finding('ok', 'MySQL слушает локально'))

    # bind-address в конфиге (игнорируем закомментированные строки — grep выше
    # находил и '#bind-address = 0.0.0.0', что давало ложное high на дефолтном,
    # ничем не активированном значении из шаблона конфига)
    bind, _ = _run(client, "grep -rh '^\\s*bind-address' /etc/mysql/ 2>/dev/null | head -3")
    if bind.strip() and '127.0.0.1' not in bind and '0.0.0.0' in bind:
        findings.append(_finding('high', 'bind-address=0.0.0.0 в конфиге MySQL', bind.strip()))

    if not findings:
        findings.append(_finding('ok', 'MySQL/MariaDB: явных проблем экспозиции не найдено'))

    return {'installed': True, 'findings': findings}


# ===========================================================================
# SSH hardening
# ===========================================================================

def audit_ssh_hardening(client) -> dict:
    conf, _ = _run(client, "cat /etc/ssh/sshd_config 2>/dev/null; cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null")
    if not conf.strip():
        return {'findings': [_finding('low', 'нет доступа к sshd_config')]}

    findings = []

    def directive(name, default=None):
        m = re.search(rf'^\s*{name}\s+(\S+)', conf, re.IGNORECASE | re.MULTILINE)
        return m.group(1).lower() if m else default

    root_login = directive('PermitRootLogin', 'prohibit-password')
    if root_login in ('yes',):
        findings.append(_finding('high', 'PermitRootLogin yes', 'вход под root разрешён — отключи или ставь prohibit-password'))

    pw_auth = directive('PasswordAuthentication', 'yes')
    if pw_auth == 'yes':
        findings.append(_finding('medium', 'PasswordAuthentication yes',
                                 'разрешён вход по паролю — уязвим к брутфорсу, лучше только ключи'))

    if directive('PermitEmptyPasswords', 'no') == 'yes':
        findings.append(_finding('high', 'PermitEmptyPasswords yes', 'разрешены пустые пароли!'))

    port = directive('Port', '22')
    max_auth = directive('MaxAuthTries', '6')

    if not findings:
        findings.append(_finding('ok', 'SSH настроен разумно'))

    return {'port': port, 'root_login': root_login, 'password_auth': pw_auth,
            'max_auth_tries': max_auth, 'findings': findings}


# ===========================================================================
# Комбинированный SSH-аудит
# ===========================================================================

@register(
    id='server_audit', label='Security-аудит сервера (SSH)', category='server',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Хост', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'Пользователь', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH-порт', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Путь к ключу', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Пароль (если без ключа)', 'default': ''},
    ],
    required_tools=[],
    description='Полный security-аудит сервера по SSH: nginx, fail2ban, firewall, MySQL, SSH hardening. Readonly.',
)
def check_server_audit(host='', user='root', port=22, key_path='', password='') -> dict:
    if paramiko is None:
        return {'error': 'paramiko не установлен'}
    if not host:
        return {'error': 'не указан host'}
    try:
        client = _ssh_connect(host, user, port, key_path, password)
    except Exception as e:
        return {'error': f'не подключиться: {e}'}

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

    # сводка по severity
    counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
    for sec in sections.values():
        for f in sec.get('findings', []):
            counts[f['severity']] = counts.get(f['severity'], 0) + 1

    return {'host': host, 'sections': sections, 'summary': counts}


# ===========================================================================
# Внешний web-аудит (без доступа к серверу)
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
    """Пытается подключиться конкретной версией TLS. True если сервер её принял."""
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
    """Извлекает все строки Set-Cookie из сырых заголовков ответа curl -I.
    Заголовки регистронезависимы, значение может начинаться с новой строки после ':'."""
    return re.findall(r'^set-cookie:\s*(.+)$', head, re.IGNORECASE | re.MULTILINE)


def _audit_cookies(cookie_lines: list[str]) -> list[dict]:
    """Проверяет флаги Secure/HttpOnly/SameSite для каждой найденной cookie."""
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
            findings.append(_finding('high', f'cookie "{name}": SameSite=None без Secure',
                                      'кука отправляется в кросс-сайтовых запросах и доступна не по HTTPS'))
        if missing:
            sev = 'high' if 'HttpOnly' in missing and 'Secure' in missing else 'medium'
            findings.append(_finding(sev, f'cookie "{name}": нет флага(ов) {", ".join(missing)}',
                                      line[:120]))
    return findings


def _audit_cors(base: str) -> list[dict]:
    """Проверяет CORS-заголовки на опасную комбинацию: разрешён любой Origin + credentials.
    Отправляет заведомо чужой Origin и смотрит, что сервер отражает в ответ."""
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
            findings.append(_finding('high', 'CORS: Allow-Origin=* вместе с Allow-Credentials=true',
                                      'по спецификации браузеры должны такое отклонять, но неверные прокси/старые клиенты могут пропустить — исправь конфиг явно'))
        elif acao_val == fake_origin:
            findings.append(_finding('high', 'CORS: сервер отражает любой Origin обратно',
                                      f'ответил Allow-Origin: {acao_val} на подставной Origin — любой сайт может читать ответы от имени пользователя'))
    return findings


def _audit_error_page(base: str) -> list[dict]:
    """Запрашивает заведомо несуществующий путь и ищет признаки verbose error
    (stack trace, путь на диске, версия фреймворка в теле ответа)."""
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
        'путь на диске': ['/var/www/', '/home/', 'c:\\inetpub', 'c:\\users\\'],
        'версия фреймворка/языка в ошибке': ['php version', 'django version', 'werkzeug', 'debug = true',
                                              'whoops', 'laravel', 'yii2', '<title>fatal error'],
    }
    for label, needles in signals.items():
        if any(n in lower for n in needles):
            findings.append(_finding('medium', f'verbose error page: похоже на {label}',
                                      f'страница ошибки на {probe_path} раскрывает внутренние детали — выключи debug-режим на проде'))
            break  # одной находки достаточно, не дублируем по каждому сигналу
    return findings


@register(
    id='web_security_external', label='Внешний web-аудит (без доступа)', category='site',
    params=[{'name': 'url', 'type': 'text', 'label': 'URL сайта', 'default': 'https://example.com'}],
    required_tools=['curl'],
    description='Аудит сайта снаружи: security-заголовки, устаревшие TLS, утечка версий, доступность '
                '.git/.env/бэкапов, флаги cookie (Secure/HttpOnly/SameSite), CORS-misconfiguration, '
                'verbose error pages.',
)
def check_web_security_external(url='https://example.com') -> dict:
    from urllib.parse import urlparse
    parsed = urlparse(url if '://' in url else f'https://{url}')
    hostname = parsed.hostname
    if not hostname:
        return {'error': f'не распарсить URL: {url}'}
    base = f'https://{hostname}'
    findings = []

    # заголовки
    if tool_available('curl'):
        code, head, _ = run_cmd(['curl', '-s', '-I', '-L', '--max-time', '10', base], timeout=15)
        hl = head.lower()
        server_m = re.search(r'server:\s*(.+)', head, re.IGNORECASE)
        if server_m and re.search(r'\d+\.\d+', server_m.group(1)):
            findings.append(_finding('low', 'сервер раскрывает версию', f'Server: {server_m.group(1).strip()}'))
        for hdr, sev in [('strict-transport-security', 'medium'), ('x-frame-options', 'low'),
                         ('x-content-type-options', 'low'), ('content-security-policy', 'low')]:
            if hdr not in hl:
                findings.append(_finding(sev, f'нет заголовка {hdr}'))
        for hdr in ('x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'):
            m = re.search(rf'^{hdr}:\s*(.+)$', head, re.IGNORECASE | re.MULTILINE)
            if m:
                findings.append(_finding('low', f'заголовок {hdr} раскрывает технологию',
                                          m.group(1).strip()))
        findings.extend(_audit_cookies(_parse_set_cookie_headers(head)))
    else:
        head = ''

    findings.extend(_audit_cors(base))
    findings.extend(_audit_error_page(base))

    # устаревшие TLS
    old_tls = []
    if hasattr(ssl, 'PROTOCOL_TLSv1'):
        if _check_tls_version(hostname, 'TLS 1.0', ssl.PROTOCOL_TLSv1):
            old_tls.append('TLS 1.0')
    if hasattr(ssl, 'PROTOCOL_TLSv1_1'):
        if _check_tls_version(hostname, 'TLS 1.1', ssl.PROTOCOL_TLSv1_1):
            old_tls.append('TLS 1.1')
    if old_tls:
        findings.append(_finding('high', 'поддерживаются устаревшие TLS', ', '.join(old_tls)))

    # чувствительные пути
    exposed = []
    if tool_available('curl'):
        for path in SENSITIVE_PATHS:
            code, out, _ = run_cmd(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                                    '--max-time', '6', base + path], timeout=10)
            if out.strip() == '200':
                exposed.append(path)
    if exposed:
        findings.append(_finding('high', 'доступны чувствительные пути', ', '.join(exposed)))

    if not findings:
        findings.append(_finding('ok', 'внешних проблем не обнаружено'))

    counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
    for f in findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    return {'url': base, 'findings': findings, 'summary': counts, 'exposed_paths': exposed}
