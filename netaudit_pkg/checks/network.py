"""Network check plugins: mtr, tcptraceroute, ping, dig, arping."""

from __future__ import annotations

import json
import re
import socket
import time

from ..registry import register
from ..utils import run_cmd, tool_available


@register(
    id='mtr', label='MTR (ICMP traceroute)', category='network',
    params=[
        {'name': 'target', 'type': 'text', 'label': 'Target (IP/host)', 'default': '8.8.8.8'},
        {'name': 'duration_sec', 'type': 'number', 'label': 'Duration, sec', 'default': 15},
    ],
    required_tools=['mtr'],
    description='Loss and latency per hop. Set the run time in seconds directly: '
                '45 = 45 sec, 300 = 5 min, 3600 = 1 hour, 7200 = 2 hours.',
)
def check_mtr(target: str = '8.8.8.8', duration_sec: float = 15) -> dict:
    if not tool_available('mtr'):
        return {'target': target, 'error': 'mtr is not installed (apt install mtr-tiny)'}
    duration_sec = float(duration_sec)
    if duration_sec < 1:
        return {'target': target, 'error': 'duration must be ≥ 1 sec'}

    # Break the duration into count*interval for mtr. Don't go below a 1s interval
    # (that's mtr's default and a reasonable minimum for ICMP), and increase the
    # interval for longer periods to avoid flooding the network with thousands of
    # useless packets - once every 1..30 sec is plenty for tracking degradation
    # over a long window.
    if duration_sec <= 60:
        interval = 1.0
    elif duration_sec <= 600:
        interval = 5.0
    elif duration_sec <= 3600:
        interval = 15.0
    else:
        interval = 30.0
    count = max(1, round(duration_sec / interval))

    # Text output (-j is buggy on some 0.95 builds: doesn't give valid JSON and is slow).
    # -r report mode, -w wide, -b show name+IP, -i interval between packets.
    # Process timeout has generous headroom over the requested duration, so a long
    # monitoring run doesn't get cut off early (real mtr can take longer than the
    # nominal estimate on silent/unstable networks).
    timeout = max(90, int(duration_sec * 1.5) + 60)
    code, out, err = run_cmd(
        ['mtr', '-r', '-w', '-b', '-c', str(count), '-i', str(interval), target],
        timeout=timeout,

    )
    if code != 0:
        return {'target': target, 'error': f'mtr error: {err.strip() or out.strip()[-300:]}'}
    if not out.strip():
        return {'target': target, 'error': 'mtr returned no output (empty)'}

    hops = []
    for line in out.splitlines():
        # format: "  1.|-- _gateway (192.168.88.1)    0.0%    15    5.0   5.6   1.5  23.3   6.6"
        m = re.match(
            r'\s*(\d+)\.\|--\s+(\S+)(?:\s+\(([\d.:a-fA-F]+)\))?\s+'
            r'([\d.]+)%\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)',
            line
        )
        if not m:
            continue
        hop_num, host, ip, loss, snt, last, avg, best, wrst, stdev = m.groups()
        display_host = host if host != '???' else (ip or '???')
        if ip and host != ip:
            display_host = f'{host} ({ip})'
        hops.append({
            'hop': int(hop_num), 'host': display_host,
            'loss_pct': float(loss), 'avg_ms': float(avg), 'worst_ms': float(wrst),
        })

    if not hops:
        return {'target': target, 'error': f'failed to parse mtr output: {out.strip()[-300:]}'}

    return {'target': target, 'hops': hops, 'duration_sec': round(duration_sec, 1)}


@register(
    id='tcptraceroute', label='TCP traceroute', category='network',
    params=[
        {'name': 'target', 'type': 'text', 'label': 'Target (IP/host)', 'default': '8.8.8.8'},
        {'name': 'port', 'type': 'number', 'label': 'Port', 'default': 80},
        {'name': 'max_hops', 'type': 'number', 'label': 'Max hops', 'default': 8},
    ],
    required_tools=['tcptraceroute'],
    description='TCP SYN instead of ICMP — refutes the ISP excuse "ICMP is just deprioritized". Default 8 hops: usually enough to catch the provider, and beyond that internet nodes often stay silent to TCP traceroute and only waste time.',
)
def check_tcptraceroute(target: str = '8.8.8.8', port: int = 80, max_hops: int = 8) -> dict:
    if not tool_available('tcptraceroute'):
        return {'error': 'tcptraceroute is not installed (apt install tcptraceroute)'}
    port = int(port)
    max_hops = int(max_hops)
    # -m caps the number of hops, -w wait timeout for a response per hop (sec).
    # On silent hops (a common situation — transit nodes don't reply with a
    # TTL-exceeded to a TCP SYN, even though ICMP works fine for mtr), tcptraceroute
    # can retry several times, actually taking noticeably longer than hops*wait.
    # The process timeout gets generous headroom.
    per_hop_wait = 2
    timeout = max_hops * per_hop_wait * 3 + 20
    code, out, err = run_cmd(
        ['tcptraceroute', '-n', '-m', str(max_hops), '-w', str(per_hop_wait), target, str(port)],
        timeout=timeout,
    )
    if code not in (0, 1):
        return {'error': err.strip() or out.strip()[-300:] or 'no response'}
    hops = []
    for line in out.splitlines():
        m = re.match(r'\s*(\d+)\s+(\S+)\s+([\d.]+)\s*ms', line)
        if m:
            hops.append({'hop': int(m.group(1)), 'host': m.group(2), 'ms': float(m.group(3))})
        elif re.match(r'\s*\d+\s+\*', line):
            hop_m = re.match(r'\s*(\d+)\s+\*', line)
            if hop_m:
                hops.append({'hop': int(hop_m.group(1)), 'host': '* (no response)', 'ms': None})
    if not hops:
        return {'target': target, 'port': port, 'error': f'failed to parse output: {out.strip()[-300:]}'}
    return {'target': target, 'port': port, 'hops': hops, 'raw': out.strip()}


@register(
    id='ping', label='Ping', category='network',
    params=[
        {'name': 'target', 'type': 'text', 'label': 'Target', 'default': '8.8.8.8'},
        {'name': 'count', 'type': 'number', 'label': 'Packets', 'default': 10},
    ],
    required_tools=['ping'],
    description='Basic loss and RTT check.',
)
def check_ping(target: str = '8.8.8.8', count: int = 10) -> dict:
    if not tool_available('ping'):
        return {'target': target, 'error': 'ping not found'}
    count = int(count)
    code, out, err = run_cmd(['ping', '-c', str(count), '-i', '0.3', target], timeout=count + 10)
    if code not in (0, 1):
        return {'target': target, 'error': err.strip() or 'no response'}
    loss = re.search(r'(\d+)% packet loss', out)
    rtt = re.search(r'= ([\d.]+)/([\d.]+)/([\d.]+)', out)
    return {
        'target': target,
        'loss_pct': float(loss.group(1)) if loss else None,
        'avg_ms': float(rtt.group(2)) if rtt else None,
        'worst_ms': float(rtt.group(3)) if rtt else None,
    }


@register(
    id='dig', label='DNS (dig)', category='network',
    params=[
        {'name': 'hostname', 'type': 'text', 'label': 'Domain', 'default': 'google.com'},
        {'name': 'record_type', 'type': 'text', 'label': 'Record type', 'default': 'A'},
    ],
    required_tools=['dig'],
    description='Detailed DNS: server, TTL, query time.',
)
def check_dig(hostname: str = 'google.com', record_type: str = 'A') -> dict:
    if not tool_available('dig'):
        return {'error': 'dig is not installed (apt install dnsutils)'}
    code, out, err = run_cmd(['dig', '+noall', '+answer', '+stats', record_type, hostname], timeout=10)
    if code != 0:
        return {'error': err.strip() or 'dig error'}
    answers, query_time, server = [], None, None
    for line in out.splitlines():
        if line.startswith(';;'):
            if 'Query time' in line:
                m = re.search(r'Query time:\s*(\d+)\s*msec', line)
                if m: query_time = int(m.group(1))
            elif 'SERVER' in line:
                m = re.search(r'SERVER:\s*(\S+)', line)
                if m: server = m.group(1)
        elif line.strip():
            parts = line.split()
            if len(parts) >= 5:
                answers.append({'name': parts[0], 'ttl': parts[1], 'type': parts[3], 'value': parts[4]})
    return {'hostname': hostname, 'record_type': record_type, 'answers': answers,
            'query_time_ms': query_time, 'dns_server': server}


@register(
    id='arping', label='ARPing (L2, local network)', category='network',
    params=[
        {'name': 'target', 'type': 'text', 'label': 'IP on the local subnet', 'default': '192.168.88.1'},
        {'name': 'count', 'type': 'number', 'label': 'Packets', 'default': 5},
    ],
    required_tools=['arping'],
    description='L2 check within the local subnet (not over the internet).',
)
def check_arping(target: str = '192.168.88.1', count: int = 5) -> dict:
    if not tool_available('arping'):
        return {'error': 'arping is not installed (apt install iputils-arping)'}
    count = int(count)
    code, out, err = run_cmd(['arping', '-c', str(count), target], timeout=count + 10)
    if code != 0:
        return {'error': err.strip() or 'no response (target not on the local subnet?)'}

    # Modern iputils-arping prints "Sent N probes ..." / "Received N response(s)"
    # (no explicit "% unanswered", that's only in older versions). We compute loss ourselves.
    sent_m = re.search(r'Sent (\d+) probe', out)
    recv_m = re.search(r'Received (\d+) response', out)
    loss_pct = None
    if sent_m and recv_m:
        sent, recv = int(sent_m.group(1)), int(recv_m.group(1))
        loss_pct = round((1 - recv / sent) * 100, 1) if sent else None
    else:
        # fallback to the old format in case of a different arping version
        loss_m = re.search(r'(\d+)% unanswered', out)
        loss_pct = float(loss_m.group(1)) if loss_m else None

    times = [float(m) for m in re.findall(r'(\d+\.\d+)ms', out)]
    avg_ms = round(sum(times) / len(times), 2) if times else None
    mac_m = re.search(r'\[([0-9A-Fa-f:]{17})\]', out)

    return {
        'target': target, 'loss_pct': loss_pct, 'avg_ms': avg_ms,
        'mac': mac_m.group(1) if mac_m else None,
        'sent': int(sent_m.group(1)) if sent_m else None,
        'received': int(recv_m.group(1)) if recv_m else None,
        'raw': out.strip(),
    }
