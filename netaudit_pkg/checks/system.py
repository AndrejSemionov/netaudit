"""Local checks (ports, firewall, CPU/RAM/disk), SSH audit, iperf3 - as plugins."""

from __future__ import annotations

import json as _json
import socket
from datetime import datetime, timezone

from ..registry import register
from ..utils import run_cmd, tool_available
from ..ssh import SSHExecutor, HostKeyMismatchError

try:
    import psutil
except ImportError:
    psutil = None

try:
    import paramiko
except ImportError:
    paramiko = None


@register(
    id='ports', label='Open ports', category='security', risk_level='PASSIVE',
    required_tools=['ss'],
    description='Listening TCP/UDP ports (ss).',
)
def check_ports() -> dict:
    if not tool_available('ss'):
        return {'error': 'ss not found'}
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
    id='firewall', label='Firewall', category='security', risk_level='PASSIVE',
    description='ufw status / nftables rule count.',
)
def check_firewall() -> dict:
    result = {}
    if tool_available('ufw'):
        code, out, _ = run_cmd(['ufw', 'status'])
        result['ufw'] = out.strip().splitlines()[0] if out.strip() else 'no data'
    if tool_available('nft'):
        code, out, _ = run_cmd(['nft', 'list', 'ruleset'])
        result['nftables_rules_count'] = len(out.strip().splitlines()) if code == 0 else 'no access (root)'
    return result or {'note': 'ufw/nft not found'}


@register(
    id='performance', label='CPU / RAM / disk', category='performance', risk_level='PASSIVE',
    description='System resource usage (psutil).',
)
def check_performance() -> dict:
    if psutil is None:
        return {'error': 'psutil not installed (pip install psutil --break-system-packages)'}
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
    'firewall_ufw': 'ufw status 2>/dev/null || echo "no access"',
    'firewall_nft': 'nft list ruleset 2>/dev/null | head -50 || echo "no access (root)"',
    'failed_ssh_logins': 'journalctl -u ssh -u sshd --since "-24 hours" 2>/dev/null | grep -i "failed\\|invalid" | tail -20 || echo "journalctl unavailable"',
    'fail2ban_status': 'fail2ban-client status 2>/dev/null || echo "fail2ban not installed"',
    'unattended_upgrades': 'systemctl is-enabled unattended-upgrades 2>/dev/null || echo "not found"',
    'sshd_config': "grep -E '^(PermitRootLogin|PasswordAuthentication|Port)' /etc/ssh/sshd_config 2>/dev/null || echo 'no access'",
    'load_average': 'cat /proc/loadavg',
}


@register(
    id='ssh_audit', label='Server SSH audit', category='server',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Host', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'User', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'Port', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Key path', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Password (if not using a key)', 'default': ''},
    ],
    required_tools=[],
    description='Read-only audit of a remote server: ports, firewall, fail2ban, login logs.',
)
def check_ssh_audit(host: str = '', user: str = 'root', port: int = 22,
                    key_path: str = '', password: str = '') -> dict:
    if paramiko is None:
        return {'error': 'paramiko not installed (pip install paramiko --break-system-packages)'}
    if not host:
        return {'error': 'host not specified'}
    try:
        ssh = SSHExecutor(host, user, port, key_path, password).connect()
    except HostKeyMismatchError as e:
        return {'error': str(e)}
    except Exception as e:
        return {'error': f'could not connect: {e}'}
    results = {}
    try:
        for name, cmd in REMOTE_CHECKS.items():
            try:
                out, err = ssh.run(cmd, timeout=15)
                results[name] = out.strip() or err.strip() or '(empty)'
            except (paramiko.SSHException, socket.timeout) as e:
                results[name] = f'error: {e}'
    finally:
        ssh.close()
    return {'host': host, 'user': user, 'checks': results}


@register(
    id='iperf', label='iperf3 throughput', category='performance', risk_level='ACTIVE',
    params=[
        {'name': 'server', 'type': 'text', 'label': 'iperf3 server', 'default': ''},
        {'name': 'port', 'type': 'number', 'label': 'Port', 'default': 5201},
        {'name': 'duration', 'type': 'number', 'label': 'Seconds', 'default': 10},
    ],
    required_tools=['iperf3'],
    description='Real upload/download speed (needs `iperf3 -s` running on the other end).',
)
def check_iperf(server: str = '', port: int = 5201, duration: int = 10) -> dict:
    if not tool_available('iperf3'):
        return {'error': 'iperf3 not installed (apt install iperf3)'}
    if not server:
        return {'error': 'server not specified'}
    port, duration = int(port), int(duration)

    def one(reverse):
        cmd = ['iperf3', '-c', server, '-p', str(port), '-t', str(duration), '-J']
        if reverse: cmd.append('-R')
        code, out, err = run_cmd(cmd, timeout=duration + 15)
        if code != 0:
            return {'error': err.strip() or f'iperf3 exit code {code}. Is `iperf3 -s` running on {server}?'}
        try:
            data = _json.loads(out)
            s = data.get('end', {}).get('sum_received') or data.get('end', {}).get('sum_sent') or {}
            return {'mbps': round(s.get('bits_per_second', 0) / 1e6, 1),
                    'retransmits': data.get('end', {}).get('sum_sent', {}).get('retransmits')}
        except (_json.JSONDecodeError, KeyError) as e:
            return {'error': f'iperf3 parsing: {e}'}

    return {'server': server, 'upload': one(False), 'download': one(True)}
