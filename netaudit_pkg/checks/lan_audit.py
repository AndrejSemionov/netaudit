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

from .. import lan, laravel_data, webprobe
from ..findings import finding as _finding
from ..findings import subject_id
from ..registry import register
from ..utils import run_cmd, tool_available

AUTH_CONFIRM = 'yes — the network owner gave me written permission'
LEVEL2_CONFIRM = 'yes — also try anonymous access and vulnerability probes'
ROUTEROS_EOL_URL = 'https://endoflife.date/api/routeros.json'
TOOL_PACKAGES = {'nmap': 'nmap', 'ip': 'iproute2'}
DISCOVERY_TIMEOUT = 600
BROADCAST_TIMEOUT = 90
PORTS_TIMEOUT = 1800
LIMITS = ('udp', 'os_detection', 'other_subnets', 'known_vulns')
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


def _kind(dev: dict, vantage: dict, gateway: str | None) -> str:
    if dev['ip'] == vantage['address']:
        return 'this_machine'
    if dev['ip'] == gateway:
        return 'router'
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


def _devices(vantage, net, discovery, neighbours, ports, broadcast, heard, vendors) -> list[dict]:
    answered = {h['ip'] for h in discovery['hosts'] if h.get('state') == 'up'}
    scanned = {h['ip']: h for h in ports['hosts']}
    announced = lan.broadcast_devices(broadcast.get('prescripts', {}))
    mndp = {m['ip']: m for m in heard.get('mndp', []) if m.get('ip')}
    # a device seen only by its announcement is a device too (review #65 P3)
    ips = {ip for ip in answered | set(neighbours) | set(scanned) | set(announced) | set(mndp) if _in(net, ip)}
    devices = []
    for ip in sorted(ips, key=_ip_key):
        host = scanned.get(ip) or next((h for h in discovery['hosts'] if h['ip'] == ip), None) or {}
        mac = host.get('mac') or neighbours.get(ip, {}).get('mac')
        names = [{'name': n, 'source': 'dns'} for n in host.get('hostnames', [])]
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
                         else 'neighbour' if ip in neighbours else 'announced'),
            'announced': info,
            '_ports': host.get('ports', []), '_hostscripts': host.get('hostscripts', {}),
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


# ---- the result -------------------------------------------------------------------

def _worst(severities) -> str | None:
    return next((s for s in SEVERITY_ORDER if s in severities), None)


def build_result(*, client: str, vantage: dict, scanned: str, note: str | None, discovery: dict,
                 neighbours: dict, ports: dict, broadcast: dict, heard: dict, level2: bool, support,
                 vendors: dict, neighbour_error: str | None = None) -> dict:
    net = ipaddress.ip_network(scanned)
    # only what came from the scanned range is this network's (review #65 P4)
    heard = {**heard, 'mndp': [m for m in heard.get('mndp', []) if _in(net, m.get('ip', ''))],
             'llmnr': [x for x in heard.get('llmnr', []) if _in(net, x.get('ip', ''))]}
    devices = _devices(vantage, net, discovery, neighbours, ports, broadcast, heard, vendors)
    gateway = vantage.get('gateway')
    for d in devices:
        d['kind'] = _kind(d, vantage, gateway)
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
        if script_gaps:
            checked.append({'item': 'scripts', 'status': 'not_checked', 'detail': _listed(script_gaps)})
        elif others:
            checked.append({'item': 'scripts', 'status': 'ok', 'detail': 'every applicable script answered'})
        if level2:
            checked.append({'item': 'level2', 'status': 'not_checked', 'detail': _listed(level2_gaps)}
                           if level2_gaps else
                           {'item': 'level2', 'status': 'ok', 'detail': ', '.join(lan.LEVEL2_SCRIPTS)})

    for d in devices:
        d['worst'] = _worst({f['severity'] for f in findings if f.get('device') == d['ip']})
        d['ports'] = [{'port': p['port'], 'service': p['service'], 'product': p['product'],
                       'version': p['version'], 'tunnel': p['tunnel'], 'guessed': p['method'] == 'table'}
                      for p in sorted(d.pop('_ports'), key=lambda p: p['port'])]
        for key in ('_hostscripts', '_scanned', '_timedout'):
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
        'router': router, 'devices': devices,
        'stats': {'addresses': addresses, 'devices': len(devices),
                  'neighbour_only': sum(1 for d in devices if d['answered'] == 'neighbour')},
        'heard': {'llmnr': asked, 'mndp': heard['mndp']},
        'findings': findings, 'checked': checked,
        'limits': list(LIMITS) + ([] if level2 else ['level2']),
        'score': webprobe.score(findings, checked), 'verdict': webprobe.verdict(findings, checked),
        'summary': webprobe.summary(findings), 'next_steps': next_steps,
    }


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
    ],
    required_tools=['nmap', 'ip'],
    description='Audit of the network segment this machine is plugged into: finds the devices (TCP probes and '
                'ARP), identifies the router and its firmware without passwords, scans the common TCP ports and '
                'services and reports misconfigurations (SMBv1, SMB signing, Telnet, FTP, RDP, VNC, open '
                'databases, plain-HTTP admin pages, certificates, weak SSH). Listens for MikroTik and LLMNR '
                'announcements. Runs only with the owner\'s permission confirmed; no root, no login attempts.',
)
def check_lan_audit(client: str = '', authorization: str = 'no', level2: str = 'no', interface: str = '',
                    share_with_ai: str = 'no') -> dict:
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
    ports = (_nmap(lan.ports_command(targets, vantage['interface'], level2_on), PORTS_TIMEOUT) if targets
             else {'hosts': [], 'prescripts': {}, 'error': None})
    neighbours, neighbour_error = watch.stop()
    listener.join(timeout=lan.LISTEN_SECONDS + 10)
    if not heard:
        heard = {'mndp': [], 'llmnr': [], 'seconds': lan.LISTEN_SECONDS,
                 'gaps': {'mndp': 'the listener did not finish', 'llmnr': 'the listener did not finish'}}
    return build_result(client=client, vantage=vantage, scanned=scanned, note=note, discovery=discovery,
                        neighbours=neighbours, ports=ports, broadcast=broadcast, heard=heard, level2=level2_on,
                        support=_support, vendors=lan.load_vendors(), neighbour_error=neighbour_error)
