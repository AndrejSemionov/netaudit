"""
Network audit of the segment NetAudit is plugged into (docs/research/
network_audit.md, contract N1-N4, PR 1 notes §12).

The scenario: an auditor invited into a client's network plugs in and
starts one audit. With no password and no prior knowledge NetAudit finds
where it is, the devices of this segment, the router and its model, the
services every device offers and the misconfigurations they show - then
says what a next step with the owner's credentials would add.

Nothing is sent before the auditor confirms the owner's written permission.
TCP connect only (no root), scripts named one by one (lan.py), no login is
ever tried at level 1; level 2 (anonymous access and vulnerability probes
nmap marks safe) has a confirmation of its own.

Two kinds of "not checked" (§12): gaps - a step that should have run and
could not - make the verdict "incomplete"; limits - what this kind of run
never covers - are always listed and never change the verdict. A device
that did not answer is "no answer", never "no device".
"""

from __future__ import annotations

import ipaddress
import re
import threading
from datetime import UTC, date, datetime

from .. import lan, lan_policy, lan_vulns, laravel_data, webprobe
from ..findings import finding as _finding
from ..findings import subject_id
from ..registry import register
from ..utils import run_cmd, tool_available

AUTH_CONFIRM = 'yes — the network owner gave me written permission'
LEVEL2_CONFIRM = 'yes — also try anonymous access and vulnerability probes'
ROUTEROS_EOL_URL = 'https://endoflife.date/api/routeros.json'
TOOL_PACKAGES = {'nmap': 'nmap', 'ip': 'iproute2'}
DISCOVERY_TIMEOUT = 600
SUBNET_TIMEOUT = 600
BROADCAST_TIMEOUT = 90
PORTS_TIMEOUT = 1800
LIMITS = ('udp', 'os_detection', 'other_subnets', 'known_vulns')   # with a subnet search: traceroute, not other_subnets
DB_PORTS = {1433: 'SQL Server', 1521: 'Oracle', 3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis',
            9200: 'Elasticsearch', 11211: 'memcached', 27017: 'MongoDB'}
# port -> (nmap service names, product words) that prove the database answered
DB_PROTOCOLS = {1433: (('ms-sql-s',), ('sql server',)), 1521: (('oracle-tns', 'oracle'), ('oracle',)),
                3306: (('mysql',), ('mysql', 'mariadb')), 5432: (('postgresql',), ('postgresql',)),
                6379: (('redis',), ('redis',)), 9200: (('elasticsearch',), ('elasticsearch',)),
                11211: (('memcached',), ('memcached',)), 27017: (('mongodb', 'mongod'), ('mongodb',))}
SEVERITY_ORDER = ('critical', 'high', 'medium', 'low')

# seams for the tests: nothing here runs a tool or opens a socket directly
_run = run_cmd
_listen = lan.listen
_tool = tool_available


def routeros_support(version: str, today: date | None = None) -> dict:
    """endoflife.date's RouterOS release lines (MIT): the same reading as
    Laravel's (laravel_data.support)."""
    return laravel_data.support(version, today, url=ROUTEROS_EOL_URL)


_support = routeros_support
_vulns = lan_vulns.lookup


def _labels(client: str) -> dict:
    """The auditor's names and sensitive marks for this client's segments
    (storage.lan_segment_labels); an unreadable database is no labels."""
    from .. import storage
    try:
        return storage.lan_segment_labels(client)
    except Exception:  # noqa: BLE001 - labels only name segments; the audit goes on without them
        return {}


def _policy(client: str) -> dict:
    """The client's current access rules (storage.lan_policy_get). Unlike
    labels, unreadable rules are a gap, never "no rules": a forbidden path
    would go unjudged (docs/research/network_access_policy.md §4.2)."""
    from .. import storage
    try:
        current = storage.lan_policy_get(client)
        rules = lan_policy.validate(current['rules'])
    except Exception as e:  # noqa: BLE001 - any failure to read the rules is reported as a gap
        return {'revision': None, 'rules': [], 'error': f'the access rules could not be read ({type(e).__name__})'}
    return {'revision': current['revision'], 'rules': rules, 'error': None}


# ---- devices ----------------------------------------------------------------

def _ip_key(ip: str):
    return ipaddress.ip_address(ip)


def _texts(value) -> list[str]:
    """Every string inside a parsed script body."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [t for v in value.values() for t in _texts(v)]
    if isinstance(value, list):
        return [t for v in value for t in _texts(v)]
    return []


def _kind(dev: dict, vantage: dict, routers: set, controllers: set) -> str:
    if dev['ip'] == vantage['address']:
        return 'this_machine'
    if dev['ip'] in routers:
        # only the vantage gateway: the route table says it routes. The .1/.254
        # that answered in a found subnet proves only that it answered - it is
        # judged as any device (review #66 R1)
        return 'router'
    if dev['ip'] in controllers:
        return 'domain_controller'
    ports = {p['port'] for p in dev['_ports']}
    words = ' '.join(f"{p['product']} {p['devicetype']} {p['service']}" for p in dev['_ports']).lower()
    announced = dev.get('announced', {})
    upnp = ' '.join(announced.get('upnp', {}).values()).lower()
    vendor = f"{dev.get('vendor') or ''} {upnp}".lower()
    wsdd = ' '.join(announced.get('wsdd', [])).lower()
    mdns = ' '.join(announced.get('mdns', [])).lower()
    if (ports & {9100, 515} or 'printer' in words or 'printdevice' in wsdd or ' ipp' in f' {mdns}'
            or any(w in upnp for w in ('printer', 'laserjet', 'officejet'))):
        return 'printer'
    if 554 in ports or 'webcam' in words or 'camera' in words or any(v in vendor for v in ('hikvision', 'dahua',
                                                                                             'axis comm')):
        return 'camera'
    if any(v in vendor for v in ('synology', 'qnap', 'western digital', 'buffalo')) or 'storage' in words:
        return 'nas'
    if any(t in words for t in ('router', 'switch', ' wap', 'firewall', 'bridge')):
        return 'network'
    if ports & {135, 3389} or 'windows' in words or 'pub:computer' in wsdd:
        return 'windows'
    if 62078 in ports or (dev['random_mac'] and not ports):
        return 'phone'
    if ports:
        return 'server'
    return 'unknown'


def _in(net, ip) -> bool:
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def _net_of(nets: list, ip: str):
    return next((n for n in nets if _in(n, ip)), None)


def _devices(vantage, nets, discovery, neighbours, ports, broadcast, heard, vendors, controllers) -> list[dict]:
    answered = {h['ip'] for h in discovery['hosts'] if h.get('state') == 'up'}
    scanned = {h['ip']: h for h in ports['hosts']}
    announced = lan.broadcast_devices(broadcast.get('prescripts', {}))
    mndp = {m['ip']: m for m in heard.get('mndp', []) if m.get('ip')}
    # a device seen only by its announcement is a device too (review #65 P3);
    # a domain controller known from the domain's DNS records too (§13)
    ips = {ip for ip in answered | set(neighbours) | set(scanned) | set(announced) | set(mndp) | set(controllers)
           if _net_of(nets, ip) is not None}
    devices = []
    for ip in sorted(ips, key=_ip_key):
        host = scanned.get(ip) or next((h for h in discovery['hosts'] if h['ip'] == ip), None) or {}
        mac = host.get('mac') or neighbours.get(ip, {}).get('mac')
        names = [{'name': n, 'source': 'dns'} for n in host.get('hostnames', [])]
        if ip in controllers:
            names.append({'name': controllers[ip], 'source': 'ad dns'})
        info = announced.get(ip, {})
        if info.get('upnp', {}).get('name'):
            names.append({'name': info['upnp']['name'], 'source': 'upnp'})
        if mndp.get(ip, {}).get('identity'):
            names.append({'name': mndp[ip]['identity'], 'source': 'mndp'})
        devices.append({
            'ip': ip, 'mac': mac, 'mac_source': 'nmap' if host.get('mac') else ('neighbour' if mac else None),
            'vendor': host.get('mac_vendor') or lan.mac_vendor(mac, vendors),
            'random_mac': lan.is_random_mac(mac), 'names': names,
            # -Pn reports every target as up: only the discovery answer or an
            # open port means the device answered TCP
            'answered': ('tcp' if ip in answered or scanned.get(ip, {}).get('ports')
                         else 'neighbour' if ip in neighbours else 'dns' if ip in controllers else 'announced'),
            'announced': info, 'segment': str(_net_of(nets, ip)),
            '_ports': host.get('ports', []), '_hostscripts': host.get('hostscripts', {}),
            '_closed': scanned.get(ip, {}).get('closed', []), '_filtered': scanned.get(ip, {}).get('filtered', []),
            '_scanned': ip in scanned, '_timedout': bool(scanned.get(ip, {}).get('timedout')),
        })
    return devices


# ---- the router (research §4) -------------------------------------------------

def _routeros_version(text: str) -> str | None:
    m = re.search(r'(\d+\.\d+(?:\.\d+)?)', text or '')
    return m.group(1) if m else None


def identify_router(gateway: str | None, dev: dict | None, heard: dict) -> dict | None:
    if not gateway:
        return None
    dev = dev or {'ip': gateway, 'mac': None, 'vendor': None, '_ports': [], 'announced': {}}
    sources, vendor, os_name, version, version_source, model = [], None, None, None, None, None
    mac_vendor = dev.get('vendor') or ''
    if mac_vendor:
        sources.append('mac vendor')
        vendor = 'MikroTik' if re.search(r'routerboard|mikrotik', mac_vendor, re.IGNORECASE) else mac_vendor
    for p in dev['_ports']:
        said = f"{p['product']} {p['version']}"
        if not (re.search('mikrotik', said, re.IGNORECASE) or p['service'] == 'winbox'):
            continue
        vendor, os_name = 'MikroTik', 'RouterOS'
        source = f"{p['service'] or p['port']} banner"
        if source not in sources:
            sources.append(source)
        if p['service'] == 'ftp' and _routeros_version(p['version']) and version_source != 'ftp banner':
            version, version_source = _routeros_version(p['version']), 'ftp banner'
        m = re.search(r'mikrotik ([\d.]+)', p['version'], re.IGNORECASE)
        if m and version is None:
            version, version_source = m.group(1).rstrip('.'), f"{p['service']} banner"
    upnp = dev.get('announced', {}).get('upnp', {})
    if upnp:
        sources.append('upnp')
        vendor = vendor or upnp.get('manufacturer')
        model = upnp.get('model') or model
        if re.search('mikrotik', upnp.get('manufacturer', ''), re.IGNORECASE):
            vendor, os_name = 'MikroTik', 'RouterOS'
    m = next((x for x in heard.get('mndp', []) if x.get('ip') == gateway
              or (dev.get('mac') and x.get('mac') == dev.get('mac'))), None)
    if m:
        sources.append('mndp')
        vendor, os_name = 'MikroTik', 'RouterOS'
        model = m.get('board') or model
        if version is None and _routeros_version(m.get('version', '')):
            version, version_source = _routeros_version(m['version']), 'mndp'
    if vendor == 'MikroTik':
        os_name = 'RouterOS'
    return {'ip': gateway, 'mac': dev.get('mac'), 'vendor': vendor, 'os': os_name, 'model': model,
            'version': version, 'version_source': version_source, 'sources': sources,
            'services': [{'port': p['port'], 'service': p['service'], 'product': p['product']}
                         for p in dev['_ports']]}


UNIDENTIFIED = ('', 'unknown', 'tcpwrapped')
CLEAR_TEXT = ('telnet', 'ftp', 'api')        # router services judged for their clear text


def _protocol(p: dict, names: tuple, products: tuple = ()) -> str:
    """What a port is known to speak (review #65 P5): 'confirmed' - nmap read
    the service's own answer and it is this one; 'other' - it answered as
    another service, so the port number proves nothing; 'possible' - nmap only
    guessed from the port number."""
    said = f"{p['product']} {p['version']}".lower()
    if p['method'] == 'probed' and p['service'] not in UNIDENTIFIED:
        if p['service'] in names or any(x in said for x in products):
            return 'confirmed'
        return 'other'
    return 'possible'


def _certainty(state: str, port: int) -> dict:
    """Finding fields for a confirmed or a possible service."""
    if state == 'confirmed':
        return {'confidence': 'high', 'requires_manual_verification': False, 'note': ''}
    return {'confidence': 'low', 'requires_manual_verification': True,
            'note': f'; port {port}: nmap did not identify the service from its answer - '
                    'a guess by the port number, check it'}


# management services of a router seen from this segment:
# port -> (name, severity, why, service names, product words)
ROUTER_SERVICES = {
    23: ('telnet', 'high', 'Telnet sends the admin password in clear text', ('telnet',), ()),
    21: ('ftp', 'medium', 'FTP sends passwords in clear text', ('ftp',), ()),
    8728: ('api', 'medium', 'the router API without TLS', ('mikrotik-routeros-api',), ('mikrotik',)),
    2000: ('btest', 'medium', 'the bandwidth-test server (a known-exploited RouterOS service in 2026)',
           ('bandwidth-test',), ('bandwidth-test',)),
    8291: ('winbox', 'low', 'WinBox management is open to this segment', ('winbox',), ('winbox',)),
    8729: ('api-ssl', 'low', 'the router API is open to this segment', ('mikrotik-routeros-api',), ('mikrotik',)),
}


def _http_without_tls(p: dict) -> bool | None:
    """True: a plain-HTTP page that does not move to HTTPS; None: unknown."""
    if p['tunnel'] == 'ssl' or p['service'] in ('https', 'https-alt') or not p['service'].startswith('http'):
        return False
    title = p['scripts'].get('http-title')
    if title is None:
        return None
    data = title['data'] if isinstance(title['data'], dict) else {}
    target = data.get('redirect_url') or ''
    return not (target.startswith('https://') or 'redirect to https://' in title['output'])


def _router_findings(router: dict, dev: dict | None, broadcast_info: dict, findings: list):
    start = len(findings)
    for p in (dev or {}).get('_ports', []):
        if p['port'] in ROUTER_SERVICES:
            name, sev, why, names, products = ROUTER_SERVICES[p['port']]
            state = _protocol(p, names, products)
            # Telnet, FTP and the plain API are findings for their clear text:
            # not over a TLS tunnel nmap saw (review #65 pass 2, R2-2)
            if state == 'other' or (name in CLEAR_TEXT and p['tunnel'] == 'ssl'):
                continue
            c = _certainty(state, p['port'])
            title = f'router management over {name} is reachable from this segment'
            if sev == 'high':
                findings.append(_finding('high', title, why + c['note'], c['confidence'],
                                         id=subject_id('RTR-SVC-001', name), extra={'device': router['ip']},
                                         requires_manual_verification=c['requires_manual_verification']))
            elif sev == 'medium':
                findings.append(_finding('medium', title, why + c['note'], c['confidence'],
                                         id=subject_id('RTR-SVC-001', name), extra={'device': router['ip']},
                                         requires_manual_verification=c['requires_manual_verification']))
            else:
                findings.append(_finding('low', title, why + c['note'], c['confidence'],
                                         id=subject_id('RTR-SVC-001', name), extra={'device': router['ip']},
                                         requires_manual_verification=c['requires_manual_verification']))
        elif p['service'].startswith('http') and _http_without_tls(p):
            findings.append(_finding('medium', 'the router admin page is plain HTTP, reachable from this segment',
                                     f'port {p["port"]}: the admin password crosses the network unencrypted',
                                     id=subject_id('RTR-SVC-001', 'http'), extra={'device': router['ip']}))
    # one finding per service (WebFig on 80 and 8080 is one problem)
    seen, kept = set(), []
    for f in findings[start:]:
        if f['id'] not in seen:
            seen.add(f['id'])
            kept.append(f)
    findings[start:] = kept
    if broadcast_info.get('upnp'):
        findings.append(_finding('medium', 'the router answers UPnP',
                                 'any device inside can ask the router to open a port to the internet',
                                 id='RTR-UPNP-001', extra={'device': router['ip']}))


# ---- devices' findings (research §7.1) ------------------------------------------

_WEAK_SSH = re.compile(r'(diffie-hellman-group1-sha1|-cbc$|^arcfour|^3des|hmac-md5|-96$|^ssh-dss$)')


def _cert_dates(data) -> tuple[datetime | None, bool]:
    if not isinstance(data, dict):
        return None, False
    after = (data.get('validity') or {}).get('notAfter') if isinstance(data.get('validity'), dict) else None
    ends = None
    if after:
        try:
            ends = datetime.fromisoformat(after)
            if ends.tzinfo is None:
                ends = ends.replace(tzinfo=UTC)
        except ValueError:
            ends = None
    self_signed = bool(data.get('subject')) and data.get('subject') == data.get('issuer')
    return ends, self_signed


def _device_findings(dev: dict, level2: bool, findings: list):
    ip, ports, hs = dev['ip'], {p['port']: p for p in dev['_ports']}, dev['_hostscripts']
    smb = hs.get('smb-protocols')
    if smb and any('SMBv1' in t or 'NT LM 0.12' in t for t in _texts(smb['data']) + [smb['output']]):
        findings.append(_finding('high', 'SMBv1 is enabled', 'the protocol WannaCry spread through',
                                 id=subject_id('NET-SMB-001', ip), extra={'device': ip}))
    signing = hs.get('smb2-security-mode')
    if signing and any('not required' in t.lower() for t in _texts(signing['data']) + [signing['output']]):
        findings.append(_finding('medium', 'SMB message signing is not required',
                                 'an attacker inside can relay a login to this computer',
                                 id=subject_id('NET-SMB-002', ip), extra={'device': ip}))
    if level2 and _ms17(hs)[0] == 'vulnerable':
        findings.append(_finding('critical', 'MS17-010 is not patched (EternalBlue)',
                                 'remote code execution over SMBv1, used by WannaCry',
                                 id=subject_id('NET-SMB-003', ip), extra={'device': ip}))
    # a TLS tunnel nmap saw on the port is not a clear-text login (review #65 pass 2, R2-2)
    state = _protocol(ports[23], ('telnet',)) if 23 in ports else 'other'
    if state != 'other' and ports[23]['tunnel'] != 'ssl':
        c = _certainty(state, 23)
        findings.append(_finding('high', 'Telnet is open', 'logins cross the network in clear text' + c['note'],
                                 c['confidence'], id=subject_id('NET-TEL-001', ip), extra={'device': ip},
                                 requires_manual_verification=c['requires_manual_verification']))
    state = _protocol(ports[21], ('ftp',), ('ftpd', 'ftp server')) if 21 in ports else 'other'
    if state != 'other':
        if ports[21]['tunnel'] != 'ssl':
            c = _certainty(state, 21)
            findings.append(_finding('medium', 'FTP is open',
                                     'logins and files cross the network in clear text' + c['note'],
                                     c['confidence'], id=subject_id('NET-FTP-001', ip), extra={'device': ip},
                                     requires_manual_verification=c['requires_manual_verification']))
        # an anonymous login is a finding over TLS too
        anon = ports[21]['scripts'].get('ftp-anon')
        if level2 and anon and anon['output'].startswith('Anonymous FTP login allowed'):
            findings.append(_finding('high', 'anonymous FTP login is allowed', 'anyone here can read the files',
                                     id=subject_id('NET-FTP-002', ip), extra={'device': ip}))
    state = (_protocol(ports[3389], ('ms-wbt-server',), ('terminal services', 'remote desktop', 'xrdp'))
             if 3389 in ports else 'other')
    if state != 'other':
        c = _certainty(state, 3389)
        findings.append(_finding('low', 'RDP is reachable from this segment',
                                 'remote desktop is a common way in for ransomware' + c['note'], c['confidence'],
                                 id=subject_id('NET-RDP-001', ip), extra={'device': ip},
                                 requires_manual_verification=c['requires_manual_verification']))
        rdp = ports[3389]['scripts'].get('rdp-enum-encryption')
        if rdp and re.search(r'(Native RDP|SSL):\s*SUCCESS', rdp['output']):
            findings.append(_finding('medium', 'RDP accepts connections without NLA',
                                     'the login screen is reached before any authentication',
                                     id=subject_id('NET-RDP-002', ip), extra={'device': ip}))
    for number, p in sorted(ports.items()):
        vnc = p['scripts'].get('vnc-info')
        if vnc and isinstance(vnc['data'], dict):
            types = vnc['data'].get('Security types') or []
            if any(isinstance(t, dict) and (t.get('type') == '1' or t.get('name') == 'None') for t in types):
                findings.append(_finding('high', 'VNC accepts connections without a password',
                                         f'port {number}: anyone here can see and control this screen',
                                         id=subject_id('NET-VNC-001', ip, number), extra={'device': ip}))
        state = _protocol(p, *DB_PROTOCOLS[number]) if number in DB_PORTS else 'other'
        if state != 'other':
            c = _certainty(state, number)
            findings.append(_finding('medium', f'{DB_PORTS[number]} is reachable from this segment',
                                     f'port {number}: a database should answer only the servers that need it'
                                     + c['note'], c['confidence'], id=subject_id('NET-DB-001', ip, number),
                                     extra={'device': ip},
                                     requires_manual_verification=c['requires_manual_verification']))
            redis = p['scripts'].get('redis-info')
            if level2 and redis and 'Version' in redis['output'] and 'ERROR' not in redis['output']:
                findings.append(_finding('high', 'Redis answers without a password',
                                         f'port {number}: anyone here can read and change its data',
                                         id=subject_id('NET-DB-002', ip, number), extra={'device': ip}))
        if dev['kind'] in ('printer', 'camera', 'nas', 'network') and _http_without_tls(p):
            findings.append(_finding('low', "the device's web interface is plain HTTP",
                                     f'port {number}: its admin password crosses the network unencrypted',
                                     id=subject_id('NET-WEB-001', ip, number), extra={'device': ip}))
        cert = p['scripts'].get('ssl-cert')
        if cert:
            ends, self_signed = _cert_dates(cert['data'])
            if ends is not None and ends < datetime.now(UTC):
                findings.append(_finding('medium', 'the certificate has expired',
                                         f'port {number}: valid until {ends.date().isoformat()}'
                                         + ('; self-signed' if self_signed else ''),
                                         id=subject_id('NET-TLS-001', ip, number), extra={'device': ip}))
            elif self_signed:
                findings.append(_finding('low', 'the certificate is self-signed',
                                         f'port {number}: browsers cannot tell this device from an impostor',
                                         id=subject_id('NET-TLS-001', ip, number), extra={'device': ip}))
        algos = p['scripts'].get('ssh2-enum-algos')
        if algos and isinstance(algos['data'], dict):
            weak = sorted({a for a in _texts(algos['data']) if _WEAK_SSH.search(a)})
            if weak:
                findings.append(_finding('low', 'SSH offers weak algorithms',
                                         f'port {number}: {", ".join(weak[:8])}',
                                         id=subject_id('NET-SSH-001', ip, number), extra={'device': ip}))


# ---- what could not be checked (review #65 P1) ------------------------------------

def _failed(result: dict | None) -> str | None:
    """Why a script gave no usable answer, or None when it answered."""
    if result is None:
        return 'no result'
    out = (result.get('output') or '').strip()
    if out.startswith('ERROR'):
        return out[:160]
    return None


def _ms17(hs: dict) -> tuple[str, str]:
    """('vulnerable'|'patched'|'unknown', why). Run with vulns.showall:
    NOT VULNERABLE is said for a patched system and for a failed check alike,
    only check_results tells them apart (smb-vuln-ms17-010.nse)."""
    s = hs.get('smb-vuln-ms17-010')
    why = _failed(s)
    if why:
        return 'unknown', why
    entries = [v for v in (s['data'].values() if isinstance(s['data'], dict) else [])
               if isinstance(v, dict) and 'state' in v]
    if any(re.match(r'(LIKELY )?VULNERABLE', str(v['state'])) for v in entries):
        return 'vulnerable', ''
    results = [r for v in entries for r in _texts(v.get('check_results', []))]
    if any('patched' in r.lower() for r in results):
        return 'patched', ''
    return 'unknown', '; '.join(results)[:160] or 'NOT VULNERABLE without a reason: the check may not have run'


def _script_gaps(dev: dict, level2: bool) -> tuple[list[str], list[str]]:
    """(level-1 gaps, level-2 gaps) of one device: an applicable script that
    failed or said nothing never reads as a clean answer."""
    one, two = [], []
    ports, hs = {p['port']: p for p in dev['_ports']}, dev['_hostscripts']
    router = dev['kind'] == 'router'
    smb = [n for n in (445, 139) if n in ports]
    if smb and not router:
        for sid in ('smb-protocols', 'smb2-security-mode'):
            why = _failed(hs.get(sid))
            if why:
                one.append(f'{sid} (SMB {smb[0]}): {why}')
        if level2:
            state, why = _ms17(hs)
            if state == 'unknown':
                two.append(f'smb-vuln-ms17-010 (SMB {smb[0]}): {why}')
    for number, p in sorted(ports.items()):
        wanted = []
        if router:
            if p['service'].startswith('http') and p['tunnel'] != 'ssl':
                wanted.append('http-title')
        else:
            if p['service'] == 'ssh' or (number == 22 and _protocol(p, ('ssh',)) != 'other'):
                wanted.append('ssh2-enum-algos')
            if p['tunnel'] == 'ssl' or p['service'] in ('https', 'https-alt'):
                wanted.append('ssl-cert')
            if number == 3389 or p['service'] == 'ms-wbt-server':
                wanted.append('rdp-enum-encryption')
            if p['service'] == 'vnc':
                wanted.append('vnc-info')
            if (dev['kind'] in ('printer', 'camera', 'nas', 'network') and p['service'].startswith('http')
                    and p['tunnel'] != 'ssl' and p['service'] not in ('https', 'https-alt')):
                wanted.append('http-title')
        for sid in wanted:
            why = _failed(p['scripts'].get(sid))
            if why:
                one.append(f'{sid} (port {number}): {why}')
        if level2 and not router:
            if (number == 21 or p['service'] == 'ftp') and _protocol(p, ('ftp',), ('ftpd',)) != 'other':
                anon = p['scripts'].get('ftp-anon')
                if anon is None:
                    two.append(f'ftp-anon (port {number}): no answer - nmap is silent both for a refused '
                               'login and for a lost connection')
                elif not anon['output'].startswith('Anonymous FTP login allowed'):
                    two.append(f'ftp-anon (port {number}): {anon["output"].strip()[:120]}')
            if number == 6379 and _protocol(p, ('redis',), ('redis',)) != 'other':
                redis = p['scripts'].get('redis-info')
                why = _failed(redis)
                if redis is not None and 'Authentication required' in redis['output']:
                    why = None
                if why:
                    two.append(f'redis-info (port {number}): {why}')
    return one, two


def _listed(entries: list[str], limit: int = 12) -> str:
    return '; '.join(entries[:limit]) + (f' … (+{len(entries) - limit})' if len(entries) > limit else '')


# ---- segments and isolation (research §5.4-5.5, §13) ------------------------------

# services that should not answer across segments: port -> (label, service names, product words)
SENSITIVE_SERVICES = {
    139: ('SMB', ('netbios-ssn', 'microsoft-ds'), ('samba', 'smb')),
    445: ('SMB', ('microsoft-ds', 'netbios-ssn'), ('samba', 'smb')),
    3389: ('RDP', ('ms-wbt-server',), ('terminal services', 'remote desktop', 'xrdp')),
    5985: ('WinRM', ('wsman',), ('microsoft httpapi',)),
    5900: ('VNC', ('vnc',), ('vnc',)),
    22: ('SSH', ('ssh',), ('openssh', 'dropbear')),
    2049: ('NFS', ('nfs',), ('nfs',)),
    873: ('rsync', ('rsync',), ('rsync',)),
    **{n: (DB_PORTS[n], *DB_PROTOCOLS[n]) for n in DB_PORTS},
}
_TOKENS = {'accounting': ('buh', 'bux', 'buch', 'acc', 'account', 'fin', 'kassa', 'ledger'),
           'servers': ('srv', 'server', 'dc', 'sql', 'file', 'nas'),
           'printers': ('prn', 'print', 'printer', 'mfp')}


def _suggest(devs: list[dict]) -> str | None:
    """A name for a segment from what is inside: device names first, then kinds."""
    tokens = {tok for d in devs for n in d['names'] for tok in re.split(r'[^a-z]+', n['name'].lower()) if tok}
    for key, words in _TOKENS.items():
        if any(tok.startswith(w) for tok in tokens for w in words):
            return key
    kinds = [d['kind'] for d in devs if d['kind'] not in ('router', 'this_machine')]
    if not kinds:
        return None
    if all(k == 'phone' for k in kinds):
        return 'guests'
    top = max(sorted(set(kinds)), key=kinds.count)
    if kinds.count(top) * 2 <= len(kinds):
        return None                     # no kind is the majority: no guess
    return {'printer': 'printers', 'server': 'servers', 'nas': 'servers', 'domain_controller': 'servers',
            'windows': 'staff'}.get(top)


def _segments(scanned: str, vantage: dict, search: dict | None, devices: list[dict], labels: dict) -> list[dict]:
    found = (search or {}).get('found', [])
    cut = set((search or {}).get('cut', []))
    segs = [{'cidr': scanned, 'own': True, 'gateway': vantage.get('gateway'), 'scanned': True, 'source': 'vantage'}]
    segs += [{'cidr': f['cidr'], 'own': False, 'gateway': f.get('gateway'), 'scanned': f['cidr'] not in cut,
              'source': f.get('source', 'probe')} for f in found]
    for s in segs:
        members = [d for d in devices if d['segment'] == s['cidr']]
        label = labels.get(s['cidr']) or {}
        s.update(devices=[d['ip'] for d in members], name=label.get('name') or None,
                 labelled=bool(label.get('name')), sensitive=bool(label.get('sensitive')),
                 # the address that answered the probe says nothing of what the segment is for
                 suggestion=_suggest([d for d in members if s['own'] or d['ip'] != s['gateway']]))
    return segs


def _isolation(segments: list[dict], devices: list[dict], findings: list, judged: frozenset = frozenset()):
    """NET-SEG-001: a sensitive service of another segment answers from the
    vantage segment - one finding per (segment, port), the devices listed.
    A (device, port) an access rule decides is judged by the rule instead
    (`judged`, docs/research/network_access_policy.md §3.4)."""
    own = next(s for s in segments if s['own'])
    by_ip = {d['ip']: d for d in devices}
    for s in segments:
        if s['own'] or not s['scanned']:
            continue
        reach: dict = {}
        for ip in s['devices']:
            d = by_ip[ip]
            if d['kind'] in ('router', 'this_machine'):
                continue                # router management is the router's own finding
            for p in d['_ports']:
                if (ip, p['port']) in judged:
                    continue
                if p['port'] in SENSITIVE_SERVICES and _protocol(p, *SENSITIVE_SERVICES[p['port']][1:]) != 'other':
                    reach.setdefault(p['port'], []).append(ip)
        where = f"{s['name']} ({s['cidr']})" if s['name'] else s['cidr']
        for number, ips in sorted(reach.items()):
            label = SENSITIVE_SERVICES[number][0]
            detail = (f"from {own['cidr']} (where this machine is) to {where}: {label} port {number} answers on "
                      f"{', '.join(ips[:10])}{' …' if len(ips) > 10 else ''} - the segments are not separated "
                      'for this service')
            fid = subject_id('NET-SEG-001', own['cidr'], s['cidr'], number)
            if s['sensitive']:
                findings.append(_finding('high', f'{label} of a sensitive segment answers from another segment',
                                         detail, id=fid, extra={'segment': s['cidr']}))
            else:
                findings.append(_finding('medium', f'{label} of another segment answers from this one', detail,
                                         id=fid, extra={'segment': s['cidr']}))


def _flat_network(search: dict | None, devices: list[dict], scanned: str, findings: list):
    """NET-SEG-002: no other subnet answered, and workstations or servers
    share the segment with phones or printers."""
    if not search or search.get('error') or search.get('found'):
        return
    kinds = {d['kind'] for d in devices if d['segment'] == scanned}
    work = kinds & {'windows', 'server', 'nas', 'domain_controller'}
    loose = kinds & {'phone', 'printer', 'camera'}
    if work and loose:
        findings.append(_finding('medium', 'one flat network: no separate segments',
                                 f"no other subnet answered through the router; {', '.join(sorted(work))} share "
                                 f"{scanned} with {', '.join(sorted(loose))} - one infected device reaches all "
                                 'of them (other subnets may exist but be filtered)',
                                 'medium', id='NET-SEG-002'))


# ---- the owner's access rules (docs/research/network_access_policy.md §3-4) ----

_EMPTY_PROBE = {'ports': [], 'open': [], 'closed': [], 'filtered': [], 'complete': False}


def _probe(d: dict, ports_error: str | None, extra: dict) -> dict:
    """What the port scan covered on one device (§4.3): the ports probed, how
    each answered, and whether the probe of this device is complete."""
    if d['kind'] == 'this_machine' or not d['_scanned']:
        return dict(_EMPTY_PROBE)
    failed = d['ip'] in extra.get('failed', ())
    probed = set(lan.SCAN_PORTS) | (set() if failed else set(extra.get('hosts', {}).get(d['ip'], ())))
    return {'ports': sorted(probed), 'open': sorted({p['port'] for p in d['_ports']} & probed),
            'closed': sorted(set(d['_closed']) & probed), 'filtered': sorted(set(d['_filtered']) & probed),
            'complete': not ports_error and not d['_timedout'] and not failed}


def _why_incomplete(d: dict, ports_error: str | None, extra: dict) -> str:
    if not d['_scanned']:
        return 'not port-scanned (it answered only by ARP, DNS or its announcement)'
    if ports_error:
        return f'the port scan failed: {ports_error}'
    if d['_timedout']:
        return 'the port scan timed out on it'
    return f"the probe of the rules' extra ports failed: {extra.get('error') or 'no answer'}"


def _policy_check(policy: dict | None, vantage: dict, devices: list[dict], segments: list[dict],
                  ports_error: str | None, extra: dict, findings: list, checked: list,
                  limits: list, scope: dict) -> tuple[dict | None, frozenset]:
    """Judge every open port of every device by the rules that apply from
    this machine's address: NET-POL-001 (forbidden, it answers), NET-POL-002
    (equal rules disagree). Returns the result's 'policy' block and the
    (device, port) pairs a rule decided."""
    if policy is None:
        limits.append('access_policy')
        return None, frozenset()
    source = vantage['address']
    block = {'revision': policy.get('revision'), 'source': source, 'rules': list(policy.get('rules') or []),
             'applicable': [], 'paths': [], 'gaps': [], 'not_observed': {}}
    if policy.get('error'):
        block['gaps'] = [policy['error']]
        checked.append({'item': 'access_policy', 'status': 'not_checked', 'detail': policy['error']})
        return block, frozenset()
    if not block['rules']:
        limits.append('access_policy')
        return block, frozenset()
    applicable = [r for r in block['rules'] if lan_policy.applies_from(r, source)]
    block['applicable'] = [r['id'] for r in applicable]
    if not applicable:
        limits.append('access_policy_here')
        return block, frozenset()

    by_id = {r['id']: r for r in applicable}
    sensitive_segments = {s['cidr'] for s in segments if s.get('sensitive')}
    own = next(s for s in segments if s['own'])
    judged, problems = set(), 0
    for d in devices:
        if d['kind'] == 'this_machine':
            continue
        for p in sorted(d['_ports'], key=lambda x: x['port']):
            number = p['port']
            verdict = lan_policy.evaluate(applicable, source, d['ip'], number)
            label = SENSITIVE_SERVICES[number][0] if number in SENSITIVE_SERVICES else f'TCP {number}'
            evidence = (_protocol(p, *SENSITIVE_SERVICES[number][1:]) if number in SENSITIVE_SERVICES else 'open')
            block['paths'].append({'source': source, 'from': own['cidr'], 'destination': d['ip'], 'port': number,
                                   'service': label, 'decision': verdict['decision'], 'rules': verdict['rules'],
                                   'evidence': evidence, 'segment': d['segment']})
            if verdict['decision'] == 'unknown':
                continue
            judged.add((d['ip'], number))
            where = f"{d['ip']} ({d['segment']})"
            if verdict['decision'] == 'conflict':
                problems += 1
                said = ', '.join(f"{rid} ({by_id[rid]['decision']})" for rid in verdict['rules'])
                findings.append(_finding(
                    'medium', 'two access rules disagree about a service that answers',
                    f'from {source} to {where}: {label} port {number} answers, and rules {said} are equally '
                    'specific and disagree - make one of them more specific or remove one',
                    id=subject_id('NET-POL-002', source, d['ip'], number),
                    extra={'device': d['ip'], 'segment': d['segment'], 'from': own['cidr'],
                           'rules': verdict['rules'], 'policy_revision': block['revision']}))
                continue
            if verdict['decision'] != 'forbid':
                continue
            problems += 1
            rule = by_id[verdict['rules'][0]]
            note = ''
            if evidence == 'possible':
                note = f' nmap did not identify the service on port {number} from its answer - to verify.'
            elif evidence == 'other':
                note = f' The port answers, but not as {label} - check what listens there.'
            detail = (f"from {source} ({own['cidr']}, where this machine is) to {where}: {label} port {number} "
                      f"answers; rule {rule['id']} forbids {rule['source']} -> {rule['destination']} "
                      f"{rule['service']}. This shows access to the service, not a login.{note}")
            fid = subject_id('NET-POL-001', source, d['ip'], number)
            fields = {'device': d['ip'], 'segment': d['segment'], 'from': own['cidr'], 'rule': rule['id'],
                      'policy_revision': block['revision']}
            manual = evidence in ('possible', 'other')
            confidence = 'medium' if manual else 'high'
            title = f'{label} answers from here although the access rules forbid it'
            if number in SENSITIVE_SERVICES or d['segment'] in sensitive_segments:
                findings.append(_finding('high', title, detail, confidence, id=fid, extra=fields,
                                         requires_manual_verification=manual))
            else:
                findings.append(_finding('medium', title, detail, confidence, id=fid, extra=fields,
                                         requires_manual_verification=manual))

    # what the forbid rules could not see (§4.2): a gap names it
    gaps: list[str] = []
    judged_on: list[str] = []
    cut = set(extra.get('cut', ()))
    for rule in applicable:
        if rule['decision'] != 'forbid':
            continue
        # the destination's parts this run skipped or could not search (review PR A, A2): a device
        # answering elsewhere in it proves nothing about them
        gaps += [f"rule {rule['id']}: {why}" for why in _scope_gaps(rule, scope)]
        judged_on += [n for n in scope['scanned'] if lan_policy.destination_overlaps(rule, n) and n not in judged_on]
        inside = [d for d in devices if d['kind'] != 'this_machine' and lan_policy.destination_contains(rule, d['ip'])]
        if not inside:
            gaps.append(f"rule {rule['id']}: no device of {rule['destination']} answered - nothing there was probed")
            continue
        wanted = lan_policy.rule_ports(rule)
        over = sorted(set(wanted or ()) & cut)
        if over:
            gaps.append(f"rule {rule['id']}: port {', '.join(map(str, over))} not probed "
                        f'(at most {lan_policy.MAX_EXTRA_PORTS} extra ports a run)')
        silent = 0
        for d in inside:
            probe = d['probe']
            if not probe['complete']:
                gaps.append(f"rule {rule['id']}: {d['ip']}: {_why_incomplete(d, ports_error, extra)}")
                continue
            missing = [n for n in (wanted or ()) if n not in probe['ports'] and n not in cut]
            if missing:
                gaps.append(f"rule {rule['id']}: {d['ip']}: port {', '.join(map(str, missing))} not probed")
            silent += len([n for n in (wanted or probe['ports']) if n in probe['ports'] and n not in probe['open']])
        block['not_observed'][rule['id']] = silent
    block['gaps'] = gaps
    if gaps:
        checked.append({'item': 'access_policy', 'status': 'not_checked', 'detail': _listed(gaps)})
    elif problems:
        checked.append({'item': 'access_policy', 'status': 'problem',
                        'detail': f'{problems} answering services break the {len(applicable)} rules that apply '
                                  f'from {source}'})
    else:
        checked.append({'item': 'access_policy', 'status': 'ok',
                        'detail': f"{len(applicable)} rules judged from {source} on {', '.join(judged_on) or '-'}: "
                                  'no forbidden service answered '
                                  f"({sum(block['not_observed'].values())} forbidden ports probed, no answer)"})
    return block, frozenset(judged)


def _scope_gaps(rule: dict, scope: dict) -> list[str]:
    """Why part of a forbid rule's destination was not covered by this
    run: a found subnet over the sweep cap, a failed or missing subnet
    search, the part of this subnet cut from the scan. A destination
    nothing answered in stays its own gap (no device there)."""
    whys = []
    over = [c for c in scope['cut'] if lan_policy.destination_overlaps(rule, c)]
    if over:
        whys.append(f"{', '.join(over)} in {rule['destination']} was found but not scanned "
                    f'(at most {lan.MAX_SUBNETS} subnets a run)')
    if not lan_policy.destination_within(rule, scope['own_scanned']):
        if not scope['searched']:
            whys.append(f"{rule['destination']}: other subnets were not searched in this run")
        elif scope['search_error']:
            whys.append(f"{rule['destination']}: the search for other subnets failed: {scope['search_error']}")
        if scope['own_subnet'] != scope['own_scanned'] and lan_policy.destination_overlaps(rule, scope['own_subnet']):
            whys.append(f"{rule['destination']}: only {scope['own_scanned']} of {scope['own_subnet']} was scanned")
    return whys


# ---- known vulnerabilities by version (research §7.2, §14) ------------------------

MAX_NVD_FINDINGS = 10      # per service; the rest are counted


def _vuln_severity(severity: str | None, in_kev: bool) -> str:
    base = severity if severity in SEVERITY_ORDER else 'medium'
    if in_kev:
        return 'critical' if base == 'critical' else 'high'
    return base


def _kev_text(entry: dict | None) -> str:
    if not entry:
        return ''
    text = f" - listed by CISA as exploited in the wild (since {entry.get('added') or '?'})"
    return text + ('; used in ransomware campaigns' if entry.get('ransomware') else '')


def _known_vulns(devices: list[dict], router: dict | None, lookup, findings: list, checked: list):
    services, versionless = [], []
    for d in devices:
        if d['kind'] in ('router', 'this_machine') or not d['_scanned']:
            continue
        for p in d['_ports']:
            src = lan_vulns.version_source(p)
            if src:
                services.append({'ip': d['ip'], 'port': p['port'], **src})
            else:
                versionless.append(f"{d['ip']}:{p['port']}")
    router_version = router['version'] if router and router.get('os') == 'RouterOS' else None
    result = lookup(services, router_version)
    kev = result.get('kev') or {}
    problems, more = [], 0
    nvd_count = osv_count = fixed_count = unfixed_count = 0
    for s in result.get('services', []):
        where = f"{s['ip']}:{s['port']}"
        if s.get('error'):
            problems.append(f"{where}: {s['error']}")
            continue
        if s['kind'] == 'nvd':
            nvd_count += 1
            cves = sorted(s.get('cves') or [], key=lambda c: (c.get('score') or 0), reverse=True)
            more += max(0, len(cves) - MAX_NVD_FINDINGS)
            for c in cves[:MAX_NVD_FINDINGS]:
                entry = kev.get(c['id'])
                severity = _vuln_severity(c.get('severity'), bool(entry))
                findings.append(_finding(severity, f"possible {c['id']} in the service on port {s['port']}"
                                         + (' - exploited in the wild' if entry else ''),
                                         f"{c.get('summary') or ''} (CVSS {c.get('score') or '?'}); matched by the "
                                         f"version nmap read ({s['cpe']}) - check the device: a vendor may fix "
                                         f"without a new version{_kev_text(entry)}", 'low',
                                         id=subject_id('NET-VULN-001', s['ip'], s['port'], c['id']),
                                         requires_manual_verification=True, extra={'device': s['ip']}))
        elif s['kind'] == 'osv':
            osv_count += 1
            fixed, unfixed = s.get('fixed') or [], s.get('unfixed') or []
            fixed_count, unfixed_count = fixed_count + len(fixed), unfixed_count + len(unfixed)
            if fixed:
                hot = [c for c in fixed if c in kev]
                detail = (f"{len(fixed)} vulnerabilities of the Debian package {s['package']} {s['version']} "
                          f"({s['ecosystem']}) are fixed in newer revisions: {', '.join(fixed[:15])}"
                          f"{' …' if len(fixed) > 15 else ''} - update the package (apt upgrade)"
                          + (f"; exploited in the wild (CISA KEV): {', '.join(hot)}" if hot else ''))
                fid = subject_id('NET-VULN-002', s['ip'], s['port'])
                if hot:
                    findings.append(_finding('high', f"{s['package']} needs security updates", detail, 'medium',
                                             id=fid, extra={'device': s['ip']}))
                else:
                    findings.append(_finding('medium', f"{s['package']} needs security updates", detail, 'medium',
                                             id=fid, extra={'device': s['ip']}))
            if unfixed:
                # affected, and no Debian revision fixes it yet: never silent, never
                # gated on a fixable one (review #67 R1)
                hot = [c for c in unfixed if c in kev]
                detail = (f"{len(unfixed)} vulnerabilities affect the Debian package {s['package']} {s['version']} "
                          f"({s['ecosystem']}) and no revision fixes them yet: {', '.join(unfixed[:15])}"
                          f"{' …' if len(unfixed) > 15 else ''} - an update does not help; check each in Debian's "
                          "security tracker (many are minor or need a setting) and limit who reaches the service"
                          + (f"; exploited in the wild (CISA KEV): {', '.join(hot)}" if hot else ''))
                fid = subject_id('NET-VULN-003', s['ip'], s['port'])
                if hot:
                    findings.append(_finding('high', f"{s['package']} has an exploited vulnerability with no fix yet",
                                             detail, 'medium', id=fid, requires_manual_verification=True,
                                             extra={'device': s['ip']}))
                else:
                    findings.append(_finding('low', f"{s['package']} has vulnerabilities with no fix yet", detail,
                                             'medium', id=fid, requires_manual_verification=True,
                                             extra={'device': s['ip']}))
    r = result.get('router')
    if r and router:
        if r.get('error'):
            problems.append(f"router RouterOS {r['version']}: {r['error']}")
        else:
            for c in sorted(r.get('cves') or [], key=lambda c: (c.get('score') or 0),
                            reverse=True)[:MAX_NVD_FINDINGS]:
                entry = kev.get(c['id'])
                findings.append(_finding(_vuln_severity(c.get('severity'), bool(entry)),
                                         f"possible {c['id']} in RouterOS {r['version']}"
                                         + (' - exploited in the wild' if entry else ''),
                                         f"{c.get('summary') or ''} (CVSS {c.get('score') or '?'}); matched by the "
                                         f"RouterOS version - check MikroTik's changelog{_kev_text(entry)}", 'low',
                                         id=subject_id('RTR-VULN-001', c['id']), requires_manual_verification=True,
                                         extra={'device': router['ip']}))
    problems += [f'{where}: over the lookup limit' for where in result.get('cut', [])]
    if result.get('kev_error'):
        problems.append(result['kev_error'])
    # a service whose version was not looked up is not covered: a gap that
    # names it, never "ok" (review #67 R2)
    problems += result.get('skipped', [])
    if versionless:
        problems.append(f"no product version to look up: {', '.join(versionless[:12])}"
                        f"{f' … (+{len(versionless) - 12})' if len(versionless) > 12 else ''}")
    done = (f"{nvd_count} versions looked up in NVD (possible matches), {osv_count} Debian packages in OSV "
            f"({fixed_count} vulnerabilities with a fix, {unfixed_count} without a fix), CISA KEV marks"
            + (f"; {more} more possible matches not listed" if more else ''))
    if problems:
        checked.append({'item': 'known_vulns', 'status': 'not_checked', 'detail': f'{_listed(problems)}; {done}'})
    else:
        checked.append({'item': 'known_vulns', 'status': 'ok', 'detail': done})


# ---- the result -------------------------------------------------------------------

def _worst(severities) -> str | None:
    return next((s for s in SEVERITY_ORDER if s in severities), None)


def build_result(*, client: str, vantage: dict, scanned: str, note: str | None, discovery: dict,
                 neighbours: dict, ports: dict, broadcast: dict, heard: dict, level2: bool, support,
                 vendors: dict, neighbour_error: str | None = None, subnet_search: dict | None = None,
                 remote_discovery: dict | None = None, labels: dict | None = None,
                 dcs: dict | None = None, vulns=None, policy: dict | None = None,
                 extra: dict | None = None) -> dict:
    net = ipaddress.ip_network(scanned)
    found = (subnet_search or {}).get('found', [])
    nets = [net] + [ipaddress.ip_network(f['cidr']) for f in found]
    # only what came from the scanned range is this network's (review #65 P4)
    heard = {**heard, 'mndp': [m for m in heard.get('mndp', []) if _in(net, m.get('ip', ''))],
             'llmnr': [x for x in heard.get('llmnr', []) if _in(net, x.get('ip', ''))]}
    remote = remote_discovery or {'hosts': [], 'prescripts': {}, 'error': None}
    controllers = {c['ip']: c['name'] for c in (dcs or {}).get('found', []) if _net_of(nets, c['ip']) is not None}
    devices = _devices(vantage, nets, {**discovery, 'hosts': discovery['hosts'] + remote['hosts']}, neighbours,
                       ports, broadcast, heard, vendors, controllers)
    gateway = vantage.get('gateway')
    routers = {gateway} if gateway else set()
    for d in devices:
        d['kind'] = _kind(d, vantage, routers, set(controllers))
    by_ip = {d['ip']: d for d in devices}
    findings: list = []
    checked: list = []

    # the range and discovery
    if note:
        checked.append({'item': 'range', 'status': 'not_checked', 'detail': note})
    else:
        checked.append({'item': 'range', 'status': 'ok', 'detail': f'{scanned}: the whole subnet'})
    others = [d for d in devices if d['kind'] != 'this_machine']
    addresses = max(net.num_addresses - 2, 1) if net.prefixlen < 31 else net.num_addresses
    if discovery.get('error'):
        checked.append({'item': 'discovery', 'status': 'not_checked', 'detail': discovery['error']})
    elif not others:
        checked.append({'item': 'discovery', 'status': 'not_checked',
                        'detail': 'no device answered: a device that drops every probe is not seen, '
                                  'so this is not an empty network'})
    else:
        checked.append({'item': 'discovery', 'status': 'ok',
                        'detail': f'{len(others)} devices answered of {addresses} addresses'})
    if neighbour_error:
        checked.append({'item': 'neighbours', 'status': 'not_checked', 'detail': neighbour_error})
    else:
        quiet = sum(1 for d in devices if d['answered'] == 'neighbour')
        checked.append({'item': 'neighbours', 'status': 'ok',
                        'detail': f'{quiet} devices answered only ARP (their TCP ports are filtered)'})
    for d in devices:
        d['gaps'] = []
    if ports.get('error'):
        # nothing about these devices' ports is known (review #65 pass 2, R2-1)
        for d in others:
            d['gaps'].append(f"the port scan failed: {ports['error']}")
        checked.append({'item': 'services', 'status': 'not_checked', 'detail': ports['error']})
    elif others:
        missing = []
        for d in others:
            if not d['_scanned']:
                why = ('found only by its announcement; the port scan has no result for it'
                       if d['answered'] == 'announced' else 'the port scan returned nothing for it')
                d['gaps'].append(why)
                missing.append(f"{d['ip']}: {why}")
            elif d['_timedout']:
                d['gaps'].append('the port scan timed out on it: its ports may be incomplete')
                missing.append(f"{d['ip']}: timed out")
        if missing:
            checked.append({'item': 'services', 'status': 'not_checked', 'detail': _listed(missing)})
        else:
            checked.append({'item': 'services', 'status': 'ok',
                            'detail': f'{len(others)} devices: {len(lan.SCAN_PORTS)} TCP ports, services, '
                                      f'{len(lan.LEVEL1_SCRIPTS)} read-only scripts'})
    if broadcast.get('error'):
        checked.append({'item': 'broadcast', 'status': 'not_checked', 'detail': broadcast['error']})
    else:
        count = len(lan.broadcast_devices(broadcast.get('prescripts', {})))
        checked.append({'item': 'broadcast', 'status': 'ok',
                        'detail': f'{count} devices announced themselves (mDNS, UPnP, WS-Discovery)'})
    gaps, seconds = heard.get('gaps', {}), heard.get('seconds', lan.LISTEN_SECONDS)
    if 'mndp' in gaps:
        checked.append({'item': 'mndp', 'status': 'not_checked', 'detail': gaps['mndp']})
    else:
        checked.append({'item': 'mndp', 'status': 'ok',
                        'detail': f"{len(heard.get('mndp', []))} MikroTik announcements in {seconds} s"})
    asked = [x for x in heard.get('llmnr', []) if x.get('ip') != vantage['address']]
    if 'llmnr' in gaps:
        checked.append({'item': 'llmnr', 'status': 'not_checked', 'detail': gaps['llmnr']})
    elif asked:
        shown = '; '.join(f"{x['ip']} asked for {x['name']!r}" for x in asked[:10])
        findings.append(_finding('medium', 'computers on this network ask names by LLMNR',
                                 f'{shown}{" …" if len(asked) > 10 else ""} - an attacker inside can answer '
                                 'and collect their password hashes', id='NET-NAME-001'))
        checked.append({'item': 'llmnr', 'status': 'problem', 'detail': f'{len(asked)} queries heard'})
    else:
        checked.append({'item': 'llmnr', 'status': 'ok',
                        'detail': f'none heard in {seconds} s - computers may still use it'})

    # other subnets (§13)
    if subnet_search is not None:
        cut = subnet_search.get('cut') or []
        if subnet_search.get('error'):
            checked.append({'item': 'subnets', 'status': 'not_checked', 'detail': subnet_search['error']})
        elif remote.get('error'):
            checked.append({'item': 'subnets', 'status': 'not_checked',
                            'detail': f"{len(found)} found, their sweep failed: {remote['error']}"})
        elif cut:
            checked.append({'item': 'subnets', 'status': 'not_checked',
                            'detail': f"{len(found)} other subnets found, {len(found) - len(cut)} checked; "
                                      f"not checked: {', '.join(cut)}"})
        else:
            checked.append({'item': 'subnets', 'status': 'ok',
                            'detail': f"{subnet_search.get('candidates', 0)} candidate gateways probed, "
                                      f"{len(found)} other subnets found - a subnet the router filters is "
                                      'not seen'})
    if dcs is not None:
        if dcs.get('error'):
            checked.append({'item': 'dcs', 'status': 'not_checked', 'detail': dcs['error']})
        else:
            checked.append({'item': 'dcs', 'status': 'ok',
                            'detail': f"{len(controllers)} domain controllers in the domain's DNS records"})

    # the router
    gw_dev = by_ip.get(gateway) if gateway else None
    placeholder = None
    if gateway and gw_dev is None:
        mac = vantage.get('gateway_mac')
        placeholder = {'ip': gateway, 'mac': mac, 'vendor': lan.mac_vendor(mac, vendors), '_ports': [],
                       'announced': lan.broadcast_devices(broadcast.get('prescripts', {})).get(gateway, {})}
    router = identify_router(gateway, gw_dev or placeholder, heard)
    if router is None:
        checked.append({'item': 'router', 'status': 'not_checked', 'detail': 'no gateway on this interface'})
    elif not router['vendor']:
        checked.append({'item': 'router', 'status': 'not_checked',
                        'detail': f"{gateway}: the vendor could not be told from its MAC, banners or announcements"})
    else:
        said = ' '.join(x for x in (router['vendor'], router['os'], router['version']) if x)
        checked.append({'item': 'router', 'status': 'ok',
                        'detail': f"{gateway}: {said} ({', '.join(router['sources'])})"})
    if router is not None:
        _router_findings(router, gw_dev, (gw_dev or {}).get('announced', {}), findings)
        if router['os'] == 'RouterOS':
            if router['version']:
                s = support(router['version'])
                router['support'] = s
                if s['status'] == 'ended':
                    findings.append(_finding('high', "the router's firmware no longer gets fixes",
                                             f"RouterOS {router['version']}: the {s['cycle']} line ended"
                                             + (f" on {s['eol']}" if s.get('eol') else '')
                                             + (f"; latest {s['latest']}" if s.get('latest') else ''),
                                             id='RTR-VER-001', extra={'device': router['ip']}))
                    checked.append({'item': 'router_support', 'status': 'problem', 'detail': s['cycle'] or ''})
                elif s['status'] == 'supported':
                    checked.append({'item': 'router_support', 'status': 'ok',
                                    'detail': f"RouterOS {s['cycle']} still gets fixes"
                                              + (f"; latest {s['latest']}" if s.get('latest') else '')})
                else:
                    checked.append({'item': 'router_support', 'status': 'not_checked',
                                    'detail': s.get('error') or f"endoflife.date does not list {router['version']}"})
            else:
                checked.append({'item': 'router_support', 'status': 'not_checked',
                                'detail': 'the RouterOS version is not visible from here'})

    # every other device
    for d in devices:
        if d['kind'] in ('this_machine', 'router'):
            continue
        _device_findings(d, level2, findings)
    script_gaps, level2_gaps = [], []
    for d in devices:
        if d['kind'] == 'this_machine' or not d['_scanned']:
            continue
        one, two = _script_gaps(d, level2)
        d['gaps'] += one + two
        script_gaps += [f"{d['ip']} {g}" for g in one]
        level2_gaps += [f"{d['ip']} {g}" for g in two]
    if ports.get('error'):
        # no script ran anywhere: never "every script answered" (R2-1)
        reason = f"the port scan failed: {ports['error']}"
        checked.append({'item': 'scripts', 'status': 'not_checked', 'detail': reason})
        if level2:
            checked.append({'item': 'level2', 'status': 'not_checked', 'detail': reason})
    else:
        uncovered = [d['ip'] for d in others if not d['_scanned']]
        script_gaps += [f'{ip}: not port-scanned, no script ran on it' for ip in uncovered]
        level2_gaps += [f'{ip}: not port-scanned, level 2 did not run on it' for ip in uncovered]
        # a timed-out host's ports are not fully known: which scripts apply to
        # it, and whether they ran, is not known either (review #65 pass 3, R3-1)
        timed_out = [d['ip'] for d in others if d['_scanned'] and d['_timedout']]
        script_gaps += [f'{ip}: the port scan timed out on it, its scripts may not have run' for ip in timed_out]
        level2_gaps += [f'{ip}: the port scan timed out on it, level 2 may not have run' for ip in timed_out]
        if script_gaps:
            checked.append({'item': 'scripts', 'status': 'not_checked', 'detail': _listed(script_gaps)})
        elif others:
            checked.append({'item': 'scripts', 'status': 'ok', 'detail': 'every applicable script answered'})
        if level2:
            checked.append({'item': 'level2', 'status': 'not_checked', 'detail': _listed(level2_gaps)}
                           if level2_gaps else
                           {'item': 'level2', 'status': 'ok', 'detail': ', '.join(lan.LEVEL2_SCRIPTS)})

    if vulns is not None:
        _known_vulns(devices, router, vulns, findings, checked)
    segments = _segments(scanned, vantage, subnet_search, devices, labels or {})
    extra = dict(extra or {'ports': [], 'cut': [], 'error': None})
    if 'hosts' not in extra:
        extra['hosts'] = lan_policy.extra_targets((policy or {}).get('rules') or [], vantage['address'],
                                                  [d['ip'] for d in devices], extra.get('ports', ()))
    for d in devices:
        d['probe'] = _probe(d, ports.get('error'), extra)
    policy_limits: list = []
    cut_subnets = list((subnet_search or {}).get('cut') or [])
    scope = {'own_subnet': str(ipaddress.ip_network(vantage.get('subnet') or scanned, strict=False)),
             'own_scanned': scanned, 'cut': cut_subnets, 'searched': subnet_search is not None,
             'search_error': (subnet_search or {}).get('error') or remote.get('error'),
             'scanned': [scanned] + [f['cidr'] for f in found if f['cidr'] not in cut_subnets]}
    policy_block, judged = _policy_check(policy, vantage, devices, segments, ports.get('error'), extra, findings,
                                         checked, policy_limits, scope)
    _isolation(segments, devices, findings, judged)
    _flat_network(subnet_search, devices, scanned, findings)

    for d in devices:
        d['worst'] = _worst({f['severity'] for f in findings if f.get('device') == d['ip']})
        d['ports'] = [{'port': p['port'], 'service': p['service'], 'product': p['product'],
                       'version': p['version'], 'tunnel': p['tunnel'], 'guessed': p['method'] == 'table'}
                      for p in sorted(d.pop('_ports'), key=lambda p: p['port'])]
        for key in ('_hostscripts', '_scanned', '_timedout', '_closed', '_filtered'):
            d.pop(key)

    next_steps = []
    if router and router['vendor'] == 'MikroTik':
        next_steps.append({'id': 'router_ssh', 'host': router['ip']})
    ssh_hosts = [d['ip'] for d in devices if d['kind'] not in ('router', 'this_machine')
                 and any(p['port'] == 22 for p in d['ports'])]
    if ssh_hosts:
        next_steps.append({'id': 'saved_hosts', 'hosts': ssh_hosts})
    if not level2:
        next_steps.append({'id': 'level2'})
    next_steps.append({'id': 'other_vantage'})

    return {
        'client': client, 'level': 2 if level2 else 1, 'vantage': vantage, 'scanned': scanned, 'scan_note': note,
        'router': router, 'devices': devices, 'segments': segments,
        'stats': {'addresses': addresses, 'devices': len(devices),
                  'neighbour_only': sum(1 for d in devices if d['answered'] == 'neighbour')},
        'heard': {'llmnr': asked, 'mndp': heard['mndp']},
        'findings': findings, 'checked': checked,
        'limits': [x for x in (([y for y in LIMITS if y != 'other_subnets'] + ['traceroute'])
                               if subnet_search is not None else list(LIMITS))
                   if not (x == 'known_vulns' and vulns is not None)]
                  # looked up: what matching by version cannot see stays a limit (review #67 R2)
                  + (['vuln_versions'] if vulns is not None else []) + ([] if level2 else ['level2'])
                  + policy_limits,
        'policy': policy_block,
        'notices': lan_vulns.NOTICES if vulns is not None else [],
        'score': webprobe.score(findings, checked), 'verdict': webprobe.verdict(findings, checked),
        'summary': webprobe.summary(findings), 'next_steps': next_steps,
    }


def _probe_extra(ports: dict, extra: dict, interface: str) -> None:
    """Probe each host on its rules' extra ports, one nmap run per set of
    ports, and fold the answers into the main port scan's hosts."""
    groups: dict[tuple, list[str]] = {}
    for ip, numbers in extra['hosts'].items():
        groups.setdefault(tuple(numbers), []).append(ip)
    main = {h['ip']: h for h in ports['hosts']}
    for numbers, hosts in groups.items():
        got = _nmap(lan.extra_ports_command(hosts, list(numbers), interface), PORTS_TIMEOUT)
        if got.get('error'):
            extra['error'] = got['error']
            extra['failed'] += hosts
            continue
        for rec in got['hosts']:
            if rec['ip'] not in hosts:
                continue
            into = main.get(rec['ip'])
            if into is None:
                ports['hosts'].append(rec)
                continue
            into['ports'] += rec['ports']
            into['closed'] = sorted(set(into.get('closed', [])) | set(rec['closed']))
            into['filtered'] = sorted(set(into.get('filtered', [])) | set(rec['filtered']))
            into['timedout'] = into.get('timedout') or rec.get('timedout')
        answered = {rec['ip'] for rec in got['hosts']}
        extra['failed'] += [ip for ip in hosts if ip not in answered]


def _nmap(cmd: list[str], timeout: int) -> dict:
    code, out, err = _run(cmd, timeout=timeout)
    if code != 0:
        return {'hosts': [], 'prescripts': {}, 'error': f'nmap exit code {code}: {(err or out).strip()[:300]}'}
    return lan.parse_nmap_xml(out)


@register(
    id='lan_audit', label='Network audit (this segment)', category='lan', risk_level='ACTIVE',
    params=[
        {'name': 'client', 'type': 'text', 'label': 'Client / network name', 'default': ''},
        {'name': 'authorization', 'type': 'select', 'label': "Network owner's permission",
         'options': ['no', AUTH_CONFIRM], 'default': 'no'},
        {'name': 'level2', 'type': 'select', 'label': 'Level 2: anonymous access and vulnerability probes',
         'options': ['no', LEVEL2_CONFIRM], 'default': 'no'},
        {'name': 'interface', 'type': 'text', 'label': 'Interface (empty = the default route)', 'default': '',
         'format': 'interface'},
        {'name': 'share_with_ai', 'type': 'select', 'label': 'Allow AI analysis of this network',
         'options': ['no', 'yes'], 'default': 'no'},
        {'name': 'vuln_lookup', 'type': 'select',
         'label': 'Look up known vulnerabilities (NVD, OSV, CISA KEV: products and versions only)',
         'options': ['yes', 'no'], 'default': 'yes'},
    ],
    required_tools=['nmap', 'ip'],
    description='Audit of the network segment this machine is plugged into: finds the devices (TCP probes and '
                'ARP), identifies the router and its firmware without passwords, scans the common TCP ports and '
                'services and reports misconfigurations (SMBv1, SMB signing, Telnet, FTP, RDP, VNC, open '
                'databases, plain-HTTP admin pages, certificates, weak SSH). Listens for MikroTik and LLMNR '
                'announcements. Runs only with the owner\'s permission confirmed; no root, no login attempts.',
)
def check_lan_audit(client: str = '', authorization: str = 'no', level2: str = 'no', interface: str = '',
                    share_with_ai: str = 'no', vuln_lookup: str = 'yes') -> dict:
    client = str(client or '')[:120]   # a label for the report, shown escaped; never an argument
    if authorization != AUTH_CONFIRM:
        return {'client': client, 'verdict': 'not_started',
                'error': 'not started: confirm that the network owner gave you written permission for this audit'}
    for tool, package in TOOL_PACKAGES.items():
        if not _tool(tool):
            return {'client': client, 'verdict': 'not_started',
                    'error': f'{tool} is not installed (apt install {package})'}
    try:
        vantage = lan.vantage(interface, run=_run)
        scanned, note = lan.scan_range(vantage['subnet'], vantage['address'])
    except lan.LanError as e:
        return {'client': client, 'verdict': 'not_started', 'error': str(e)}

    level2_on = level2 == LEVEL2_CONFIRM
    heard: dict = {}
    listener = threading.Thread(target=lambda: heard.update(_listen(
        lan.LISTEN_SECONDS, interface=vantage['interface'], network=scanned, address=vantage['address'])),
        daemon=True)
    listener.start()
    # the neighbour table is watched the whole time: the kernel drops stale
    # entries once a /24 of probes has filled it (lan.NeighbourWatch)
    watch = lan.NeighbourWatch(vantage['interface'], run=_run).start()
    discovery = _nmap(lan.discovery_command(scanned, vantage['interface']), DISCOVERY_TIMEOUT)
    watch.read()
    broadcast = _nmap(lan.broadcast_command(vantage['interface']), BROADCAST_TIMEOUT)
    seen = watch.read()
    net = ipaddress.ip_network(scanned)
    announced = lan.broadcast_devices(broadcast.get('prescripts', {}))
    found = {h['ip'] for h in discovery['hosts'] if h.get('state') == 'up'} | set(seen) | set(announced)
    targets = sorted((ip for ip in found if _in(net, ip) and ip != vantage['address']), key=_ip_key)

    # other subnets through the router, and the domain's controllers (§13)
    dcs = None
    if vantage.get('search') and _tool('dig'):
        controllers, dc_error = lan.domain_controllers(vantage['search'][0], run=_run)
        dcs = {'found': controllers, 'error': dc_error}
    candidates = lan.candidate_gateways(vantage, extra=[c['ip'] for c in (dcs or {}).get('found', [])])
    probe = _nmap(lan.subnet_probe_command(candidates, vantage['interface']), SUBNET_TIMEOUT)
    subnets = [] if probe['error'] else lan.found_subnets(probe, scanned)
    swept = subnets[:lan.MAX_SUBNETS]
    subnet_search = {'ran': True, 'candidates': len(candidates), 'error': probe['error'], 'found': subnets,
                     'cut': [s['cidr'] for s in subnets[lan.MAX_SUBNETS:]]}
    remote = (_nmap(lan.discovery_command([s['cidr'] for s in swept], vantage['interface']), DISCOVERY_TIMEOUT)
              if swept else {'hosts': [], 'prescripts': {}, 'error': None})
    swept_nets = [ipaddress.ip_network(s['cidr']) for s in swept]
    remote_up = ({h['ip'] for h in remote['hosts'] if h.get('state') == 'up'}
                 | {s['gateway'] for s in swept if s.get('gateway')}
                 | {c['ip'] for c in (dcs or {}).get('found', [])})
    targets += sorted((ip for ip in remote_up if _net_of(swept_nets, ip) is not None), key=_ip_key)
    ports = (_nmap(lan.ports_command(targets, vantage['interface'], level2_on), PORTS_TIMEOUT) if targets
             else {'hosts': [], 'prescripts': {}, 'error': None})
    # the ports a forbid rule names that SCAN_PORTS lacks, on that rule's
    # destinations only (docs/research/network_access_policy.md §3.5)
    policy = _policy(client)
    extra_list, extra_cut = lan_policy.extra_ports(policy['rules'], vantage['address'], lan.SCAN_PORTS)
    extra = {'ports': extra_list, 'cut': extra_cut, 'error': None, 'failed': [],
             'hosts': lan_policy.extra_targets(policy['rules'], vantage['address'], targets, extra_list)}
    if not ports.get('error'):
        _probe_extra(ports, extra, vantage['interface'])
    neighbours, neighbour_error = watch.stop()
    listener.join(timeout=lan.LISTEN_SECONDS + 10)
    if not heard:
        heard = {'mndp': [], 'llmnr': [], 'seconds': lan.LISTEN_SECONDS,
                 'gaps': {'mndp': 'the listener did not finish', 'llmnr': 'the listener did not finish'}}
    return build_result(client=client, vantage=vantage, scanned=scanned, note=note, discovery=discovery,
                        neighbours=neighbours, ports=ports, broadcast=broadcast, heard=heard, level2=level2_on,
                        support=_support, vendors=lan.load_vendors(), neighbour_error=neighbour_error,
                        subnet_search=subnet_search, remote_discovery=remote, labels=_labels(client), dcs=dcs,
                        vulns=_vulns if vuln_lookup == 'yes' else None, policy=policy, extra=extra)
