"""Локальные проверки (порты, firewall, CPU/RAM/диск), SSH-аудит, iperf3 — как плагины."""

from __future__ import annotations

import json as _json
import socket
from datetime import datetime, timezone

from ..registry import register
from ..utils import run_cmd, tool_available

try:
    import psutil
except ImportError:
    psutil = None

try:
    import paramiko
except ImportError:
    paramiko = None


@register(
    id='ports', label='Открытые порты', category='security',
    required_tools=['ss'],
    description='Слушающие TCP/UDP порты (ss).',
)
def check_ports() -> dict:
    if not tool_available('ss'):
        return {'error': 'ss не найден'}
    code, out, err = run_cmd(['ss', '-tulnp'])
    if code != 0:
        code, out, err = run_cmd(['ss', '-tuln'])
        if code != 0:
            return {'error': err.strip()}
    ports = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            ports.append({'proto': parts[0], 'local_address': parts[4]})
    return {'open_ports': ports}


@register(
    id='firewall', label='Firewall', category='security',
    description='Статус ufw / количество правил nftables.',
)
def check_firewall() -> dict:
    result = {}
    if tool_available('ufw'):
        code, out, _ = run_cmd(['ufw', 'status'])
        result['ufw'] = out.strip().splitlines()[0] if out.strip() else 'нет данных'
    if tool_available('nft'):
        code, out, _ = run_cmd(['nft', 'list', 'ruleset'])
        result['nftables_rules_count'] = len(out.strip().splitlines()) if code == 0 else 'нет доступа (root)'
    return result or {'note': 'ufw/nft не найдены'}


@register(
    id='performance', label='CPU / RAM / диск', category='performance',
    description='Использование ресурсов системы (psutil).',
)
def check_performance() -> dict:
    if psutil is None:
        return {'error': 'psutil не установлен (pip install psutil --break-system-packages)'}
    disks = []
    for part in psutil.disk_partitions(all=False):
        try:
            u = psutil.disk_usage(part.mountpoint)
            disks.append({'mountpoint': part.mountpoint, 'total_gb': round(u.total / 1e9, 1), 'used_pct': u.percent})
        except PermissionError:
            continue
    mem = psutil.virtual_memory()
    return {'cpu_pct': psutil.cpu_percent(interval=1), 'cpu_cores': psutil.cpu_count(),
            'ram_total_gb': round(mem.total / 1e9, 1), 'ram_used_pct': mem.percent, 'disks': disks,
            'boot_time': datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc).isoformat()}


REMOTE_CHECKS = {
    'os_release': 'cat /etc/os-release 2>/dev/null | head -5',
    'uptime': 'uptime',
    'disk_usage': 'df -h --output=target,size,pcent -x tmpfs -x devtmpfs',
    'memory': 'free -h',
    'open_ports': 'ss -tulnp 2>/dev/null || ss -tuln',
    'firewall_ufw': 'ufw status 2>/dev/null || echo "нет доступа"',
    'firewall_nft': 'nft list ruleset 2>/dev/null | head -50 || echo "нет доступа (root)"',
    'failed_ssh_logins': 'journalctl -u ssh -u sshd --since "-24 hours" 2>/dev/null | grep -i "failed\\|invalid" | tail -20 || echo "journalctl недоступен"',
    'fail2ban_status': 'fail2ban-client status 2>/dev/null || echo "fail2ban не установлен"',
    'unattended_upgrades': 'systemctl is-enabled unattended-upgrades 2>/dev/null || echo "не найден"',
    'sshd_config': "grep -E '^(PermitRootLogin|PasswordAuthentication|Port)' /etc/ssh/sshd_config 2>/dev/null || echo 'нет доступа'",
    'load_average': 'cat /proc/loadavg',
}


@register(
    id='ssh_audit', label='SSH-аудит сервера', category='server',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Хост', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'Пользователь', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'Порт', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Путь к ключу', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Пароль (если без ключа)', 'default': ''},
    ],
    required_tools=[],
    description='Readonly-аудит удалённого сервера: порты, firewall, fail2ban, логи логинов.',
)
def check_ssh_audit(host: str = '', user: str = 'root', port: int = 22,
                    key_path: str = '', password: str = '') -> dict:
    if paramiko is None:
        return {'error': 'paramiko не установлен (pip install paramiko --break-system-packages)'}
    if not host:
        return {'error': 'не указан host'}
    from pathlib import Path
    port = int(port)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        kwargs = {'hostname': host, 'port': port, 'username': user, 'timeout': 10}
        if key_path and key_path.strip():
            kwargs['key_filename'] = str(Path(key_path).expanduser())
        elif password:
            kwargs['password'] = password
        client.connect(**kwargs)
    except (paramiko.AuthenticationException, paramiko.SSHException, socket.error, OSError) as e:
        return {'error': f'не подключиться: {e}'}
    results = {}
    try:
        for name, cmd in REMOTE_CHECKS.items():
            try:
                _, so, se = client.exec_command(cmd, timeout=15)
                results[name] = so.read().decode(errors='replace').strip() or se.read().decode(errors='replace').strip() or '(пусто)'
            except (paramiko.SSHException, socket.timeout) as e:
                results[name] = f'ошибка: {e}'
    finally:
        client.close()
    return {'host': host, 'user': user, 'checks': results}


@register(
    id='iperf', label='iperf3 пропускная способность', category='performance',
    params=[
        {'name': 'server', 'type': 'text', 'label': 'iperf3-сервер', 'default': ''},
        {'name': 'port', 'type': 'number', 'label': 'Порт', 'default': 5201},
        {'name': 'duration', 'type': 'number', 'label': 'Секунд', 'default': 10},
    ],
    required_tools=['iperf3'],
    description='Реальная скорость upload/download (нужен `iperf3 -s` на другом конце).',
)
def check_iperf(server: str = '', port: int = 5201, duration: int = 10) -> dict:
    if not tool_available('iperf3'):
        return {'error': 'iperf3 не установлен (apt install iperf3)'}
    if not server:
        return {'error': 'не указан server'}
    port, duration = int(port), int(duration)

    def one(reverse):
        cmd = ['iperf3', '-c', server, '-p', str(port), '-t', str(duration), '-J']
        if reverse: cmd.append('-R')
        code, out, err = run_cmd(cmd, timeout=duration + 15)
        if code != 0:
            return {'error': err.strip() or f'iperf3 код {code}. Запущен ли `iperf3 -s` на {server}?'}
        try:
            data = _json.loads(out)
            s = data.get('end', {}).get('sum_received') or data.get('end', {}).get('sum_sent') or {}
            return {'mbps': round(s.get('bits_per_second', 0) / 1e6, 1),
                    'retransmits': data.get('end', {}).get('sum_sent', {}).get('retransmits')}
        except (_json.JSONDecodeError, KeyError) as e:
            return {'error': f'парсинг iperf3: {e}'}

    return {'server': server, 'upload': one(False), 'download': one(True)}
