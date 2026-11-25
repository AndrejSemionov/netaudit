"""
What the network audit learns about the segment it is plugged into
(docs/research/network_audit.md §3-4, contract N1-N2, PR 1 notes §12).

Everything here runs without root, as the NetAudit service does:

- vantage(): this machine's interface, address, subnet, gateway (and the
  gateway's MAC from the kernel neighbour table), DNS servers and search
  domain - read from `ip -j` and resolv.conf, no packet sent.
- scan_range(): the subnet to scan - private only (RFC 1918), a subnet
  bigger than MAX_SUBNET cut to the /24 around this machine.
- the nmap commands: TCP connect only (no raw sockets), gentle timing,
  scripts named one by one - never a category, so an nmap update cannot add
  one - and no user-supplied nmap option.
- parse_nmap_xml(): nmap's XML, with any DOCTYPE other than nmap's own
  refused before parsing (no entity is ever expanded).
- neighbours(): devices that answered ARP while nmap probed them - a PC
  whose firewall drops every TCP probe still answers ARP (§3.3).
- listen(): MikroTik's MNDP announcements and LLMNR name queries, heard on
  UDP 5678 and 5355. NetAudit only listens; it never answers a query
  (answering is the name-poisoning attack, §3.4).
"""

from __future__ import annotations

import ipaddress
import json
import re
import select
import socket
import struct
import time
import xml.etree.ElementTree as ET  # nosec B405 - parses our own nmap's output; DOCTYPE/ENTITY refused first (parse_nmap_xml)

from .utils import run_cmd

PRIVATE = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
MAX_SUBNET = 22            # a bigger subnet is cut to the /24 around this machine
RESOLV_PATHS = ('/run/systemd/resolve/resolv.conf', '/etc/resolv.conf')
MAC_PREFIXES = '/usr/share/nmap/nmap-mac-prefixes'

# a device that drops 80/443 often answers on one of these (Windows 135/445,
# printers 9100/631, iPhones 62078, MikroTik 8291)
DISCOVERY_PORTS = (21, 22, 23, 53, 80, 135, 139, 443, 445, 515, 548, 554, 631, 3389, 5000, 5357, 8080, 8291,
                   9100, 62078)
SCAN_PORTS = (21, 22, 23, 25, 53, 80, 81, 110, 135, 139, 143, 389, 443, 445, 515, 548, 554, 631, 636, 873, 1433,
              1521, 1883, 2000, 2049, 2375, 3306, 3389, 5000, 5001, 5432, 5900, 5985, 6379, 8000, 8080, 8081,
              8291, 8443, 8728, 8729, 8888, 9000, 9100, 9200, 10000, 11211, 27017, 62078)
# level 1: what any client sees when it connects (research §7.1)
LEVEL1_SCRIPTS = ('smb-protocols', 'smb2-security-mode', 'rdp-enum-encryption', 'vnc-info', 'http-title',
                  'ssl-cert', 'ssh2-enum-algos')
# level 2, its own confirmation: anonymous access and vulnerability probes nmap marks safe
LEVEL2_SCRIPTS = ('smb-vuln-ms17-010', 'ftp-anon', 'redis-info')
BROADCAST_SCRIPTS = ('broadcast-dns-service-discovery', 'broadcast-upnp-info', 'broadcast-wsdd-discover')
MAX_RATE = '100'           # packets per second, a busy office network never notices
HOST_TIMEOUT = '180s'

MNDP_PORT = 5678
LLMNR_PORT = 5355
LLMNR_GROUP = '224.0.0.252'
LISTEN_SECONDS = 40


class LanError(Exception):
    """The audit cannot start or a step failed; the message says why."""


def _json(run, cmd: list[str]):
    code, out, err = run(cmd, timeout=15)
    if code != 0:
        raise LanError(f'{" ".join(cmd[:4])} failed: {(err or out).strip()[:200] or f"exit code {code}"}')
    try:
        return json.loads(out or '[]')
    except ValueError as e:
        raise LanError(f'{" ".join(cmd[:4])}: unreadable output') from e


def _resolv(paths) -> tuple[list[str], list[str]]:
    """DNS servers and search domains; the systemd stub (127.0.0.53) is not
    the client's DNS, the next file is read instead."""
    for path in paths:
        try:
            with open(path, encoding='utf-8', errors='replace') as f:
                text = f.read()
        except OSError:
            continue
        dns, search = [], []
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == 'nameserver':
                dns.append(parts[1])
            elif len(parts) >= 2 and parts[0] in ('search', 'domain'):
                search = parts[1:]
        real = [d for d in dns if not d.startswith('127.')]
        if real:
            return real, search
    return [], []


def vantage(interface: str = '', *, run=None, resolv_paths=None) -> dict:
    """Where this machine is: research §3.1. Raises LanError."""
    run = run or run_cmd
    routes = _json(run, ['ip', '-j', 'route', 'show', 'default'])
    default = next((r for r in routes if isinstance(r, dict) and r.get('dev')), None)
    if not interface:
        if default is None:
            raise LanError('no default route: this machine is not connected to a network')
        interface = default['dev']
    links = _json(run, ['ip', '-j', '-4', 'addr', 'show'])
    link = next((x for x in links if isinstance(x, dict) and x.get('ifname') == interface), None)
    info = next((a for a in (link or {}).get('addr_info', []) if a.get('family') == 'inet' and a.get('local')), None)
    if info is None:
        raise LanError(f'{interface} has no IPv4 address')
    iface = ipaddress.ip_interface(f"{info['local']}/{info.get('prefixlen', 32)}")
    gateway = default.get('gateway') if default and default.get('dev') == interface else None
    gateway_mac = None
    if gateway:
        try:
            gateway_mac = neighbours(interface, run=run).get(gateway, {}).get('mac')
        except LanError:
            gateway_mac = None
    dns, search = _resolv(RESOLV_PATHS if resolv_paths is None else resolv_paths)
    return {'interface': interface, 'address': str(iface.ip), 'prefix': iface.network.prefixlen,
            'subnet': str(iface.network), 'gateway': gateway, 'gateway_mac': gateway_mac,
            # wl* is how udev names Wi-Fi interfaces (wlan0, wlp1s0)
            'wireless': interface.startswith('wl'), 'dns': dns, 'search': search}


def scan_range(subnet: str, address: str) -> tuple[str, str | None]:
    """The range to scan and, when the subnet was cut, a note saying so.
    Raises LanError for anything but RFC 1918 (§6)."""
    net = ipaddress.ip_network(subnet, strict=False)
    if not any(net.subnet_of(p) for p in PRIVATE if net.version == p.version):
        raise LanError(f'{net} is not a private network (10/8, 172.16/12, 192.168/16): it is not scanned')
    if net.prefixlen >= MAX_SUBNET:
        return str(net), None
    cut = ipaddress.ip_network(f'{address}/24', strict=False)
    return str(cut), f'{net} is larger than /{MAX_SUBNET}: only {cut} around this machine was scanned'


def discovery_command(target: str, interface: str) -> list[str]:
    return ['nmap', '-sn', '-n', '-T3', '--max-rate', MAX_RATE, '-e', interface,
            '-PS' + ','.join(map(str, DISCOVERY_PORTS)), '-oX', '-', target]


def ports_command(hosts: list[str], interface: str, level2: bool) -> list[str]:
    scripts = LEVEL1_SCRIPTS + (LEVEL2_SCRIPTS if level2 else ())
    # no -n: nmap asks the client's DNS for each device's name (PTR)
    return ['nmap', '-sT', '-Pn', '-sV', '--version-light', '-T3', '--max-rate', MAX_RATE,
            '--host-timeout', HOST_TIMEOUT, '-e', interface, '-p', ','.join(map(str, SCAN_PORTS)),
            '--script', ','.join(scripts), '-oX', '-', *hosts]


def broadcast_command(interface: str) -> list[str]:
    return ['nmap', '-sn', '-n', '-e', interface, '--script', ','.join(BROADCAST_SCRIPTS), '-oX', '-']


def _struct(el):
    """A <script>/<table> body: keyed children -> dict, unkeyed -> list."""
    keyed, items = {}, []
    for child in el:
        if child.tag not in ('elem', 'table'):
            continue
        value = (child.text or '') if child.tag == 'elem' else _struct(child)
        if child.get('key') is not None:
            keyed[child.get('key')] = value
        else:
            items.append(value)
    if keyed:
        if items:
            keyed['_'] = items
        return keyed
    return items


def _scripts(parent) -> dict:
    out = {}
    if parent is None:
        return out
    for s in parent.findall('script'):
        out[s.get('id', '')] = {'output': s.get('output', ''), 'data': _struct(s)}
    return out


_NMAP_DOCTYPE = '<!DOCTYPE nmaprun>'


def parse_nmap_xml(text: str) -> dict:
    """{'hosts': [...], 'prescripts': {id: {'output', 'data'}}, 'error': str|None}.
    Broken or cut output is an error, never an empty network."""
    empty = {'hosts': [], 'prescripts': {}, 'error': None}
    body = (text or '').replace(_NMAP_DOCTYPE, '', 1)
    if '<!DOCTYPE' in body or '<!ENTITY' in body:
        return {**empty, 'error': 'nmap output carries a DOCTYPE or ENTITY: refused'}
    try:
        root = ET.fromstring(body)  # nosec B314 - DOCTYPE/ENTITY refused above, nothing is expanded
    except ET.ParseError as e:
        return {**empty, 'error': f'nmap output is not complete XML ({e})'}
    if root.tag != 'nmaprun':
        return {**empty, 'error': 'not nmap XML output'}
    hosts = []
    for h in root.findall('host'):
        status = h.find('status')
        rec = {'ip': None, 'mac': None, 'mac_vendor': None, 'state': status.get('state') if status is not None else None,
               'reason': status.get('reason') if status is not None else None, 'hostnames': [], 'ports': [],
               'hostscripts': _scripts(h.find('hostscript'))}
        for a in h.findall('address'):
            if a.get('addrtype') == 'ipv4':
                rec['ip'] = a.get('addr')
            elif a.get('addrtype') == 'mac':
                rec['mac'] = (a.get('addr') or '').lower() or None
                rec['mac_vendor'] = a.get('vendor')
        rec['hostnames'] = [n.get('name') for n in h.findall('hostnames/hostname') if n.get('name')]
        for p in h.findall('ports/port'):
            state = p.find('state')
            if state is None or state.get('state') != 'open':
                continue
            svc = p.find('service')
            s = svc.attrib if svc is not None else {}
            try:
                conf = int(s.get('conf', '0'))
            except ValueError:
                conf = 0
            rec['ports'].append({
                'port': int(p.get('portid', '0')), 'proto': p.get('protocol', 'tcp'), 'state': 'open',
                'service': s.get('name', ''), 'product': s.get('product', ''), 'version': s.get('version', ''),
                'extrainfo': s.get('extrainfo', ''), 'devicetype': s.get('devicetype', ''),
                'tunnel': s.get('tunnel', ''), 'method': s.get('method', ''), 'conf': conf,
                'cpe': [c.text for c in (svc.findall('cpe') if svc is not None else []) if c.text],
                'scripts': _scripts(p)})
        if rec['ip']:
            hosts.append(rec)
    finished = root.find('runstats/finished')
    error = None
    if finished is not None and finished.get('exit') == 'error':
        error = f"nmap: {finished.get('errormsg') or 'exit error'}"
    return {'hosts': hosts, 'prescripts': _scripts(root.find('prescript')), 'error': error}


_ANSWERED = {'REACHABLE', 'STALE', 'DELAY', 'PROBE', 'PERMANENT', 'NOARP'}


def neighbours(interface: str, *, run=None) -> dict:
    """{ip: {'mac', 'state'}} of the devices that answered ARP on `interface`."""
    entries = _json(run or run_cmd, ['ip', '-j', 'neigh', 'show', 'dev', interface])
    out = {}
    for e in entries:
        if not isinstance(e, dict) or not e.get('lladdr') or ':' in (e.get('dst') or ':'):
            continue
        states = set(e.get('state') or [])
        if states & _ANSWERED:
            out[e['dst']] = {'mac': e['lladdr'].lower(), 'state': min(states & _ANSWERED)}
    return out


def load_vendors(path: str = MAC_PREFIXES) -> dict:
    """{'aa:bb:cc': vendor} from nmap's own OUI list (read where nmap put it;
    nothing is bundled). Missing file -> {}."""
    vendors = {}
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                m = re.match(r'([0-9A-Fa-f]{6})\s+(.+)', line)
                if m:
                    p = m.group(1).lower()
                    vendors[f'{p[0:2]}:{p[2:4]}:{p[4:6]}'] = m.group(2).strip()
    except OSError:
        return {}
    return vendors


def mac_vendor(mac: str | None, vendors: dict) -> str | None:
    return vendors.get(mac.lower()[:8]) if mac else None


def is_random_mac(mac: str | None) -> bool:
    """The locally administered bit: a phone's or laptop's private Wi-Fi
    address, not a vendor's (IEEE 802)."""
    try:
        return bool(int(mac.split(':')[0], 16) & 0x02) if mac else False
    except ValueError:
        return False


# ---- what devices announce (research §3.4) ---------------------------------

def _blocks(output: str) -> dict[str, list[str]]:
    """'  1.2.3.4' lines start a block; the lines under it belong to it."""
    blocks, current = {}, None
    for line in (output or '').splitlines():
        text = line.strip()
        if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', text):
            current = blocks.setdefault(text, [])
        elif current is not None and text:
            current.append(text)
    return blocks


_UPNP_KEYS = {'Name': 'name', 'Manufacturer': 'manufacturer', 'Model Name': 'model'}


def broadcast_devices(prescripts: dict) -> dict:
    """{ip: {'upnp': {...}, 'mdns': [...], 'wsdd': [...]}} from the three
    broadcast scripts' text output."""
    found: dict[str, dict] = {}
    upnp = prescripts.get('broadcast-upnp-info', {}).get('output', '')
    for ip, lines in _blocks(upnp).items():
        info = {}
        for i, line in enumerate(lines):
            key, _, value = line.partition(':')
            if key in _UPNP_KEYS and value.strip():
                info[_UPNP_KEYS[key]] = value.strip()
            elif i == 0 and ':' not in line.split('/')[0]:
                info['server'] = line
        found.setdefault(ip, {})['upnp'] = info
    mdns = prescripts.get('broadcast-dns-service-discovery', {}).get('output', '')
    for ip, lines in _blocks(mdns).items():
        services = [x for x in lines if re.match(r'\d+/(tcp|udp) ', x) or x.startswith('_')]
        found.setdefault(ip, {})['mdns'] = services
    wsdd = prescripts.get('broadcast-wsdd-discover', {}).get('output', '')
    for ip, lines in _blocks(wsdd).items():
        types = [x.split(':', 1)[1].strip() for x in lines if x.startswith('Type:')]
        found.setdefault(ip, {})['wsdd'] = types
    return found


_MNDP_FIELDS = {5: 'identity', 7: 'version', 8: 'platform', 12: 'board'}


def parse_mndp(payload: bytes) -> dict | None:
    """MikroTik Neighbor Discovery: a 4-byte header, then type(2) length(2)
    value TLVs (1 MAC, 5 identity, 7 version, 8 platform, 12 board, 17 IPv4).
    Anything malformed -> None."""
    if len(payload) < 8:
        return None
    out, i = {}, 4
    while i < len(payload):
        if i + 4 > len(payload):
            return None
        kind, length = struct.unpack('>HH', payload[i:i + 4])
        value = payload[i + 4:i + 4 + length]
        if len(value) != length:
            return None
        if kind == 1 and length == 6:
            out['mac'] = ':'.join(f'{b:02x}' for b in value)
        elif kind == 17 and length == 4:
            out['ipv4'] = str(ipaddress.IPv4Address(value))
        elif kind in _MNDP_FIELDS:
            text = value.decode('utf-8', errors='replace').strip()
            if text:
                out[_MNDP_FIELDS[kind]] = text[:100]
        i += 4 + length
    return out or None


def parse_llmnr(payload: bytes) -> str | None:
    """The name a LLMNR query asks for; a response (QR bit set) -> None."""
    if len(payload) < 13:
        return None
    flags, qdcount = struct.unpack('>HH', payload[2:6])
    if flags & 0x8000 or qdcount < 1:
        return None
    labels, i = [], 12
    while i < len(payload):
        n = payload[i]
        if n == 0:
            return '.'.join(labels)[:255] if labels else None
        if n > 63 or i + 1 + n > len(payload):
            return None
        labels.append(payload[i + 1:i + 1 + n].decode('utf-8', errors='replace'))
        i += 1 + n
    return None


def _udp_socket(port: int, group: str | None = None) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', port))  # nosec B104 - a listener for broadcasts/multicast on the audited segment
    if group:
        mreq = socket.inet_aton(group) + struct.pack('=I', socket.INADDR_ANY)  # any interface joins
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    s.setblocking(False)
    return s


def listen(seconds: int = LISTEN_SECONDS) -> dict:
    """Listen for MNDP and LLMNR for `seconds`; never send anything.
    {'mndp': [{'ip', ...}], 'llmnr': [{'ip', 'name'}], 'gaps': {what: why},
    'seconds': n}. A port that cannot be opened is a gap with its reason."""
    out = {'mndp': [], 'llmnr': [], 'gaps': {}, 'seconds': seconds}
    socks = {}
    for name, port, group in (('mndp', MNDP_PORT, None), ('llmnr', LLMNR_PORT, LLMNR_GROUP)):
        try:
            socks[name] = _udp_socket(port, group)
        except OSError as e:
            out['gaps'][name] = f'UDP {port} could not be opened: {e.strerror or e}'
    seen = set()
    deadline = time.monotonic() + seconds
    try:
        while socks and time.monotonic() < deadline:
            ready, _, _ = select.select(list(socks.values()), [], [], max(0.0, min(1.0, deadline - time.monotonic())))
            for s in ready:
                try:
                    data, (ip, _port) = s.recvfrom(2048)
                except OSError:
                    continue
                if s is socks.get('mndp'):
                    info = parse_mndp(data)
                    if info and ('mndp', ip) not in seen:
                        seen.add(('mndp', ip))
                        out['mndp'].append({'ip': ip, **info})
                elif s is socks.get('llmnr'):
                    name = parse_llmnr(data)
                    if name and ('llmnr', ip, name) not in seen and len(out['llmnr']) < 200:
                        seen.add(('llmnr', ip, name))
                        out['llmnr'].append({'ip': ip, 'name': name})
    finally:
        for s in socks.values():
            s.close()
    return out
