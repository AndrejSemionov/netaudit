"""
Traffic capture/analysis plugins:
  tshark_capture   — passive capture on the machine's own interface (Wireshark engine).
                     Only sees traffic physically passing through this machine.
  mikrotik_sniffer — a specific device's (phone's) traffic via a MikroTik router over SSH.
                     Sees ALL of the device's traffic, since the router is its point of transit.

Both return a unified format: top destinations by volume + a protocol breakdown,
so the dashboard can render them the same way.

TLS is not decrypted: WHERE (IP/domain) and HOW MUCH is visible, but not the content.

NOTE: the 'analyze_threats' select values ('да' / 'да+whois' / 'нет') are kept
in Russian intentionally, matching the default preset seeded in storage.py's
_seed_presets() — changing them here without updating that seed data would
break both new installs and any preset already stored in an existing DB.
"""

from __future__ import annotations

import re
import socket
from collections import defaultdict

from ..registry import register
from ..utils import run_cmd, tool_available
from .. import threat
from ..ssh import SSHExecutor, HostKeyMismatchError

try:
    import paramiko
except ImportError:
    paramiko = None


def _reverse_dns(ip: str) -> str | None:
    """Reverse DNS for enrichment: 142.250.1.1 -> *.1e100.net. Best-effort, with a timeout."""
    try:
        socket.setdefaulttimeout(1.5)
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None


def _enrich_top(dests: list[dict], limit: int = 15) -> list[dict]:
    """Adds reverse DNS to the top N destinations (top only, to avoid slowing things down)."""
    for d in dests[:limit]:
        d['host'] = _reverse_dns(d['ip'])
    return dests


@register(
    id='tshark_capture', label='Traffic capture (tshark)', category='capture',
    params=[
        {'name': 'interface', 'type': 'text', 'label': 'Interface', 'default': 'any'},
        {'name': 'duration', 'type': 'number', 'label': 'Duration, sec', 'default': 15},
        {'name': 'bpf_filter', 'type': 'text', 'label': 'BPF filter (e.g. host 192.168.88.55)', 'default': ''},
        {'name': 'analyze_threats', 'type': 'select', 'label': 'Threat analysis',
         'options': ['да', 'да+whois', 'нет'], 'default': 'да'},
    ],
    required_tools=['tshark'],
    description='Passive capture via the Wireshark engine + destination suspiciousness scoring. Requires root.',
)
def check_tshark_capture(interface: str = 'any', duration: int = 15, bpf_filter: str = '',
                         analyze_threats: str = 'да') -> dict:
    if not tool_available('tshark'):
        return {'error': 'tshark is not installed (apt install tshark). Capture requires root.'}
    duration = int(duration)

    cmd = ['tshark', '-i', interface, '-a', f'duration:{duration}', '-n', '-l',
           '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'frame.len',
           '-e', '_ws.col.Protocol', '-E', 'separator=|']
    if bpf_filter.strip():
        cmd += ['-f', bpf_filter.strip()]

    code, out, err = run_cmd(cmd, timeout=duration + 20)
    if code != 0:
        low = err.lower()
        if 'permission' in low or 'are you root' in low or 'couldn\'t run' in low:
            return {'error': 'no capture permission — run as root/sudo, or grant tshark CAP_NET_RAW'}
        return {'error': err.strip()[-400:] or f'tshark exit code {code}'}

    by_dst = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'protocols': set()})
    total_packets = total_bytes = 0
    for line in out.splitlines():
        parts = line.split('|')
        if len(parts) < 4:
            continue
        _src, dst, length, proto = parts[0], parts[1], parts[2], parts[3]
        if not dst:
            continue
        try:
            blen = int(length) if length else 0
        except ValueError:
            blen = 0
        by_dst[dst]['packets'] += 1
        by_dst[dst]['bytes'] += blen
        if proto:
            by_dst[dst]['protocols'].add(proto)
        total_packets += 1
        total_bytes += blen

    dests = [{'ip': dst, 'packets': v['packets'], 'bytes': v['bytes'],
              'protocols': sorted(v['protocols'])}
             for dst, v in by_dst.items()]
    dests.sort(key=lambda x: x['bytes'], reverse=True)
    dests = _enrich_top(dests)

    result = {
        'interface': interface, 'duration': duration, 'filter': bpf_filter or None,
        'total_packets': total_packets, 'total_bytes': total_bytes,
        'destinations': dests,
    }
    if analyze_threats != 'нет':
        scored = threat.score_destinations(dests, do_whois=(analyze_threats == 'да+whois'))
        result['destinations'] = scored['scored']
        result['threat_summary'] = scored['summary']
    return result


# CAUTION: arp_capture (ARP-spoofing MITM) is NOT registered as a web check.
# Reason: it requires root, but the netaudit service runs as an unprivileged
# user. Granting it sudo NOPASSWD on arpspoof/tshark would mean any vulnerability
# in the web service itself (e.g. command injection) automatically converts
# into root + the ability to MITM the entire local network without a password —
# far too broad a privilege to expose behind a button in a browser.
#
# check_arp_capture() below is kept as a working, tested function —
# use it manually only, entering the sudo password explicitly each time:
#
#   sudo python3 -c "
#   from netaudit_pkg.checks.capture import check_arp_capture
#   import json
#   print(json.dumps(check_arp_capture(
#       target_ip='192.168.88.3', gateway_ip='192.168.88.1',
#       interface='enp0s3', duration=30), indent=2, ensure_ascii=False))
#   "
#
# (run from the netaudit/ project root, under sudo — same as you've already
# done manually with arpspoof+tshark, and it worked)
def check_arp_capture(target_ip: str = '', gateway_ip: str = '', interface: str = 'eth0',
                      duration: int = 30, analyze_threats: str = 'да') -> dict:
    if not tool_available('tshark'):
        return {'error': 'tshark is not installed (apt install tshark)'}
    if not tool_available('arpspoof'):
        return {'error': 'arpspoof is not installed (apt install dsniff)'}
    if not target_ip:
        return {'error': 'provide the device IP (target_ip) whose traffic to intercept'}
    if not gateway_ip:
        return {'error': 'provide the router IP (gateway_ip) — usually the network gateway'}
    duration = int(duration)

    # enable IP forwarding — without this the device loses internet during the
    # capture instead of a transparent MITM (packets would reach us but go no further)
    _, ip_fwd_before, _ = run_cmd(['cat', '/proc/sys/net/ipv4/ip_forward'], timeout=5)
    run_cmd(['sysctl', '-w', 'net.ipv4.ip_forward=1'], timeout=5)

    # two arpspoof processes: the phone thinks we're the router, the router
    # thinks we're the phone — that's the MITM; without both, only half the
    # traffic would reach us
    proc_to_target = None
    proc_to_gateway = None
    try:
        import subprocess
        proc_to_target = subprocess.Popen(
            ['arpspoof', '-i', interface, '-t', target_ip, gateway_ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc_to_gateway = subprocess.Popen(
            ['arpspoof', '-i', interface, '-t', gateway_ip, target_ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # tshark only listens to the target device's traffic while spoofing is active
        cmd = ['tshark', '-i', interface, '-a', f'duration:{duration}', '-n', '-l',
               '-f', f'host {target_ip}',
               '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'frame.len',
               '-e', '_ws.col.Protocol', '-E', 'separator=|']
        code, out, err = run_cmd(cmd, timeout=duration + 20)
    finally:
        # restoration — CRITICAL: without this the device would be left without
        # internet (or worse — traffic keeps flowing through us uncaptured) after exit
        for proc in (proc_to_target, proc_to_gateway):
            if proc:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    proc.kill()
        # arpspoof without -r usually doesn't send corrective packets itself on
        # an explicit terminate, so we manually restore the real ARP entries both ways
        run_cmd(['arping', '-c', '3', '-A', '-I', interface, target_ip], timeout=10)
        run_cmd(['arping', '-c', '3', '-A', '-I', interface, gateway_ip], timeout=10)
        if ip_fwd_before.strip() != '1':
            run_cmd(['sysctl', '-w', 'net.ipv4.ip_forward=0'], timeout=5)

    if code != 0:
        low = err.lower()
        if 'permission' in low or 'are you root' in low:
            return {'error': 'no permission — arpspoof and tshark require root'}
        return {'error': err.strip()[-400:] or f'tshark exit code {code}'}

    by_dst = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'protocols': set()})
    total_packets = total_bytes = 0
    for line in out.splitlines():
        parts = line.split('|')
        if len(parts) < 4:
            continue
        src_field, dst_field, length, proto = parts[0], parts[1], parts[2], parts[3]
        if not dst_field or not src_field:
            continue
        # in MITM mode tshark sometimes collapses multiple addresses in one frame,
        # comma-separated (e.g. '192.168.88.20,192.168.88.3' - the VM forwards the
        # phone's packet onward) - take all parts and check whether our target is involved
        srcs = src_field.split(',')
        dsts = dst_field.split(',')
        if target_ip not in srcs:
            continue
        # destination — the first dst that isn't the device itself and isn't the VM
        dst = next((d for d in dsts if d not in (target_ip,)), dsts[-1])
        try:
            blen = int(length) if length else 0
        except ValueError:
            blen = 0
        by_dst[dst]['packets'] += 1
        by_dst[dst]['bytes'] += blen
        if proto:
            by_dst[dst]['protocols'].add(proto)
        total_packets += 1
        total_bytes += blen

    dests = [{'ip': dst, 'packets': v['packets'], 'bytes': v['bytes'],
              'protocols': sorted(v['protocols'])}
             for dst, v in by_dst.items()]
    dests.sort(key=lambda x: x['bytes'], reverse=True)
    dests = _enrich_top(dests)

    result = {
        'target_ip': target_ip, 'gateway_ip': gateway_ip, 'duration': duration,
        'total_packets': total_packets, 'total_bytes': total_bytes,
        'destinations': dests,
        'note': 'ARP-spoofing MITM — works with any router regardless of vendor. '
                'ARP tables restored after capture.',
    }
    if analyze_threats != 'нет':
        scored = threat.score_destinations(dests, do_whois=(analyze_threats == 'да+whois'))
        result['destinations'] = scored['scored']
        result['threat_summary'] = scored['summary']
    return result


@register(
    id='mikrotik_sniffer', label='Device traffic via MikroTik', category='capture',
    params=[
        {'name': 'router', 'type': 'text', 'label': 'Router IP', 'default': '192.168.88.1'},
        {'name': 'user', 'type': 'text', 'label': 'User', 'default': 'admin'},
        {'name': 'password', 'type': 'password', 'label': 'Password', 'default': ''},
        {'name': 'target_ip', 'type': 'text', 'label': 'Device IP (phone)', 'default': ''},
        {'name': 'port', 'type': 'number', 'label': 'SSH port', 'default': 22},
        {'name': 'analyze_threats', 'type': 'select', 'label': 'Threat analysis',
         'options': ['да', 'да+whois', 'нет'], 'default': 'да'},
    ],
    required_tools=[],
    description='Where a device\'s traffic goes via the router + destination suspiciousness scoring. Sees ALL of the device\'s traffic.',
)
def check_mikrotik_sniffer(router: str = '192.168.88.1', user: str = 'admin',
                           password: str = '', target_ip: str = '', port: int = 22,
                           analyze_threats: str = 'да') -> dict:
    if paramiko is None:
        return {'error': 'paramiko not installed (pip install paramiko --break-system-packages)'}
    if not target_ip:
        return {'error': 'provide the device IP (target_ip) whose traffic to view'}
    port = int(port)

    try:
        ssh = SSHExecutor(router, user, port, key_path='', password=password).connect()
    except HostKeyMismatchError as e:
        return {'error': str(e)}
    except (paramiko.AuthenticationException, paramiko.SSHException, socket.error, OSError) as e:
        return {'error': f'could not connect to the router: {e}'}

    # terse — one line per record, easy to parse.
    # connection tracking shows the device's active connections: where and over which protocol.
    cmd = f'/ip firewall connection print terse where src-address~"{target_ip}"'
    try:
        out, err = ssh.run(cmd, timeout=20)
    except (paramiko.SSHException, socket.timeout) as e:
        ssh.close()
        return {'error': f'error running the command on the router: {e}'}
    finally:
        ssh.close()

    if err.strip():
        return {'error': f'the router returned an error: {err.strip()[:300]}'}

    # parse dst-address=IP:port and protocol=
    by_dst = defaultdict(lambda: {'connections': 0, 'protocols': set(), 'ports': set()})
    for line in out.splitlines():
        dst_m = re.search(r'dst-address=([\d.]+):?(\d+)?', line)
        proto_m = re.search(r'protocol=(\S+)', line)
        if not dst_m:
            continue
        dst_ip = dst_m.group(1)
        dst_port = dst_m.group(2)
        by_dst[dst_ip]['connections'] += 1
        if proto_m:
            by_dst[dst_ip]['protocols'].add(proto_m.group(1))
        if dst_port:
            by_dst[dst_ip]['ports'].add(dst_port)

    dests = [{'ip': ip, 'connections': v['connections'],
              'protocols': sorted(v['protocols']), 'ports': sorted(v['ports'])}
             for ip, v in by_dst.items()]
    dests.sort(key=lambda x: x['connections'], reverse=True)
    dests = _enrich_top(dests)

    result = {
        'router': router, 'target_ip': target_ip,
        'total_destinations': len(dests),
        'destinations': dests,
        'note': 'A snapshot of active connections. TLS content isn\'t visible — only destination addresses.',
    }
    if analyze_threats != 'нет':
        scored = threat.score_destinations(dests, do_whois=(analyze_threats == 'да+whois'))
        result['destinations'] = scored['scored']
        result['threat_summary'] = scored['summary']
    return result
