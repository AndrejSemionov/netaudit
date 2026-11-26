"""
Network audit of the segment NetAudit is plugged into (docs/research/
network_audit.md, contract N1-N4, PR 1 notes in §12). No network: `ip`,
nmap and the listeners are replaced by fixtures shaped like their real
output (nmap's own @output/@xmloutput examples in /usr/share/nmap/scripts).
"""

from __future__ import annotations

import json
import struct
from datetime import date

import pytest

from netaudit_pkg import lan
from netaudit_pkg.checks import lan_audit
from netaudit_pkg.registry import registry

# ---------------------------------------------------------------------------
# fixtures: `ip -j` output and nmap XML
# ---------------------------------------------------------------------------

ROUTE = [{'dst': 'default', 'gateway': '192.168.88.1', 'dev': 'eth0', 'protocol': 'dhcp',
          'prefsrc': '192.168.88.10', 'metric': 100, 'flags': []}]
ADDR = [
    {'ifindex': 1, 'ifname': 'lo', 'addr_info': [{'family': 'inet', 'local': '127.0.0.1', 'prefixlen': 8}]},
    {'ifindex': 2, 'ifname': 'eth0', 'addr_info': [{'family': 'inet', 'local': '192.168.88.10', 'prefixlen': 24}]},
    {'ifindex': 3, 'ifname': 'wlp1s0', 'addr_info': [{'family': 'inet', 'local': '10.20.0.5', 'prefixlen': 16}]},
]
NEIGH = [
    {'dst': '192.168.88.1', 'dev': 'eth0', 'lladdr': '4c:5e:0c:11:22:33', 'state': ['REACHABLE']},
    {'dst': '192.168.88.30', 'dev': 'eth0', 'lladdr': '00:11:32:aa:bb:cc', 'state': ['STALE']},
    {'dst': '192.168.88.77', 'dev': 'eth0', 'state': ['FAILED']},
    {'dst': '192.168.88.78', 'dev': 'eth0', 'state': ['INCOMPLETE']},
    {'dst': '192.168.88.40', 'dev': 'eth0', 'lladdr': '9a:12:34:56:78:9a', 'state': ['DELAY']},
]
RESOLV = 'nameserver 192.168.88.1\nsearch office.example\noptions edns0\n'


def fake_ip(route=ROUTE, addr=ADDR, neigh=NEIGH):
    calls = []

    def run(cmd, timeout=30):
        calls.append(cmd)
        if cmd[:4] == ['ip', '-j', 'route', 'show']:
            return 0, json.dumps(route), ''
        if cmd[:4] == ['ip', '-j', '-4', 'addr']:
            return 0, json.dumps(addr), ''
        if cmd[:3] == ['ip', '-j', 'neigh']:
            return 0, json.dumps(neigh), ''
        return 127, '', f'unexpected {cmd}'
    run.calls = calls
    return run


def _esc(text: str) -> str:
    return (text.replace('&', '&amp;').replace('"', '&quot;').replace('<', '&lt;')
            .replace('>', '&gt;').replace('\n', '&#xa;'))


def script(sid: str, output: str, inner: str = '') -> str:
    return f'<script id="{sid}" output="{_esc(output)}">{inner}</script>'


def port(portid: int, name: str, *, product='', version='', method='probed', conf=10, devicetype='',
         tunnel='', scripts='', cpe='') -> str:
    attrs = f'name="{name}"'
    for key, value in (('product', product), ('version', version), ('tunnel', tunnel),
                       ('devicetype', devicetype)):
        if value:
            attrs += f' {key}="{_esc(value)}"'
    attrs += f' method="{method}" conf="{conf}"'
    cpe_xml = f'<cpe>{cpe}</cpe>' if cpe else ''
    return (f'<port protocol="tcp" portid="{portid}"><state state="open" reason="syn-ack" reason_ttl="0"/>'
            f'<service {attrs}>{cpe_xml}</service>{scripts}</port>')


def host(ip: str, ports: str = '', *, hostscripts: str = '', mac: str | None = None,
         vendor: str | None = None, names: tuple = (), timedout: bool = False) -> str:
    mac_xml = ''
    if mac:
        mac_xml = f'<address addr="{mac.upper()}" addrtype="mac"' + (f' vendor="{vendor}"' if vendor else '') + '/>'
    names_xml = ''.join(f'<hostname name="{n}" type="PTR"/>' for n in names)
    hs = f'<hostscript>{hostscripts}</hostscript>' if hostscripts else ''
    attrs = ' timedout="true"' if timedout else ''
    return (f'<host{attrs}><status state="up" reason="syn-ack" reason_ttl="0"/><address addr="{ip}" addrtype="ipv4"/>'
            f'{mac_xml}<hostnames>{names_xml}</hostnames><ports>{ports}</ports>{hs}</host>')


def nmap_xml(*hosts: str, prescripts: str = '') -> str:
    pre = f'<prescript>{prescripts}</prescript>' if prescripts else ''
    return ('<?xml version="1.0" encoding="UTF-8"?><nmaprun scanner="nmap" args="nmap" version="7.94SVN">'
            f'{pre}{"".join(hosts)}<runstats><finished time="1" elapsed="1.00" exit="success"/>'
            f'<hosts up="{len(hosts)}" down="0" total="{len(hosts)}"/></runstats></nmaprun>')


SMB_V1 = script('smb-protocols', '\n  dialects: \n    NT LM 0.12 (SMBv1) [dangerous, but default]\n    2.0.2\n    3.1.1',
                '<table key="dialects"><elem>NT LM 0.12 (SMBv1) [dangerous, but default]</elem>'
                '<elem>2.0.2</elem><elem>3.1.1</elem></table>')
SMB_V2_ONLY = script('smb-protocols', '\n  dialects: \n    2.0.2\n    3.1.1',
                     '<table key="dialects"><elem>2.0.2</elem><elem>3.1.1</elem></table>')
SIGNING_OPTIONAL = script('smb2-security-mode', '\n  3.1.1: \n    Message signing enabled but not required',
                          '<table key="3.1.1"><elem>Message signing enabled but not required</elem></table>')
SIGNING_REQUIRED = script('smb2-security-mode', '\n  3.1.1: \n    Message signing enabled and required',
                          '<table key="3.1.1"><elem>Message signing enabled and required</elem></table>')
MS17_VULN = script('smb-vuln-ms17-010', 'VULNERABLE', '<table key="CVE-2017-0143">'
                   '<elem key="title">Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)</elem>'
                   '<elem key="state">VULNERABLE</elem></table>')
MS17_NOT = script('smb-vuln-ms17-010', 'NOT VULNERABLE', '<table key="CVE-2017-0143">'
                  '<elem key="state">NOT VULNERABLE</elem></table>')
RDP_NO_NLA = script('rdp-enum-encryption', '\n  Security layer\n    CredSSP (NLA): SUCCESS\n'
                    '    Native RDP: SUCCESS\n    SSL: SUCCESS\n')
RDP_NLA_ONLY = script('rdp-enum-encryption', '\n  Security layer\n    CredSSP (NLA): SUCCESS\n'
                      '    CredSSP with Early User Auth: SUCCESS\n')
VNC_NONE = script('vnc-info', '\n  Protocol version: 3.8\n  Security types: \n    None (1)',
                  '<elem key="Protocol version">3.8</elem><table key="Security types">'
                  '<table><elem key="name">None</elem><elem key="type">1</elem></table></table>')
VNC_AUTH = script('vnc-info', '\n  Protocol version: 3.8\n  Security types: \n    VNC Authentication (2)',
                  '<elem key="Protocol version">3.8</elem><table key="Security types">'
                  '<table><elem key="name">VNC Authentication</elem><elem key="type">2</elem></table></table>')
TITLE_PRINTER = script('http-title', 'HP LaserJet - Home', '<elem key="title">HP LaserJet - Home</elem>')
TITLE_TO_HTTPS = script('http-title', 'Did not follow redirect to https://192.168.88.31/',
                        '<elem key="redirect_url">https://192.168.88.31/</elem>')
SSH_WEAK = script('ssh2-enum-algos', '\n  kex_algorithms: (2)',
                  '<table key="kex_algorithms"><elem>curve25519-sha256</elem><elem>diffie-hellman-group1-sha1</elem>'
                  '</table><table key="encryption_algorithms"><elem>aes128-ctr</elem><elem>3des-cbc</elem></table>'
                  '<table key="mac_algorithms"><elem>hmac-sha2-256</elem></table>')
SSH_GOOD = script('ssh2-enum-algos', '\n  kex_algorithms: (1)',
                  '<table key="kex_algorithms"><elem>curve25519-sha256</elem></table>'
                  '<table key="encryption_algorithms"><elem>chacha20-poly1305@openssh.com</elem></table>'
                  '<table key="mac_algorithms"><elem>hmac-sha2-256-etm@openssh.com</elem></table>')


def cert(not_after: str, *, self_signed: bool) -> str:
    issuer = 'printer.local' if self_signed else 'Office CA'
    return script('ssl-cert', f'Subject: commonName=printer.local\nNot valid after:  {not_after}',
                  '<table key="subject"><elem key="commonName">printer.local</elem></table>'
                  f'<table key="issuer"><elem key="commonName">{issuer}</elem></table>'
                  f'<table key="validity"><elem key="notBefore">2020-01-01T00:00:00</elem>'
                  f'<elem key="notAfter">{not_after}</elem></table>')


FTP_ANON = script('ftp-anon', 'Anonymous FTP login allowed (FTP code 230)\n-rw-r--r--   1 0  0  31 Mar 28  2001 .banner')
REDIS_OPEN = script('redis-info', '\n  Version: 7.2.4\n  Operating System: Linux',
                    '<elem key="Version">7.2.4</elem><elem key="Operating System">Linux</elem>')
REDIS_AUTH = script('redis-info', 'ERROR: Authentication required')

GATEWAY = host('192.168.88.1', port(21, 'ftp', product='MikroTik router ftpd', version='6.49.7', devicetype='router')
               + port(23, 'telnet', product='MikroTik router telnetd', devicetype='router')
               + port(80, 'http', product='MikroTik router config httpd', devicetype='router',
                      scripts=script('http-title', 'RouterOS router configuration page',
                                     '<elem key="title">RouterOS router configuration page</elem>'))
               + port(2000, 'bandwidth-test', product='MikroTik bandwidth-test server', devicetype='router')
               + port(8291, 'winbox', product='MikroTik WinBox', devicetype='router'))
LEGACY = host('192.168.88.20', port(21, 'ftp', product='vsftpd', version='3.0.3')
              + port(23, 'telnet', product='Linux telnetd') + port(445, 'microsoft-ds', product='Samba smbd')
              + port(6379, 'redis', product='Redis key-value store', version='7.2.4'),
              hostscripts=SMB_V1 + SIGNING_OPTIONAL)
WINDOWS = host('192.168.88.21', port(135, 'msrpc', product='Microsoft Windows RPC')
               + port(445, 'microsoft-ds', method='table', conf=3)
               + port(3389, 'ms-wbt-server', product='Microsoft Terminal Services', scripts=RDP_NO_NLA),
               hostscripts=SMB_V2_ONLY + SIGNING_REQUIRED, names=('BUH-PC1.office.example',))
PRINTER = host('192.168.88.31', port(80, 'http', product='HP Embedded Web Server', scripts=TITLE_PRINTER)
               + port(443, 'https', tunnel='ssl', product='HP Embedded Web Server',
                      scripts=cert('2023-01-01T00:00:00', self_signed=True))
               + port(9100, 'jetdirect', method='table', conf=3))
SERVER = host('192.168.88.40', port(22, 'ssh', product='OpenSSH', version='9.2p1 Debian 2+deb12u3', scripts=SSH_WEAK)
              + port(5900, 'vnc', product='VNC', scripts=VNC_NONE))
SELF = host('192.168.88.10', port(8000, 'http-alt', product='uvicorn'))

DISCOVERY = nmap_xml(*(host(ip) for ip in ('192.168.88.1', '192.168.88.10', '192.168.88.20', '192.168.88.21',
                                           '192.168.88.31', '192.168.88.40')))
PORTS = nmap_xml(GATEWAY, SELF, LEGACY, WINDOWS, PRINTER, SERVER)
BROADCAST = nmap_xml(prescripts=script(
    'broadcast-upnp-info',
    '\n  192.168.88.1\n      MikroTik UPnP/1.0\n      Location:  http://192.168.88.1:2828/gateway.xml\n'
    '      Name: MikroTik Router\n      Manufacturer: MikroTik\n      Model Name: router\n'
    '  192.168.88.31\n      HP HTTP Server\n      Manufacturer: HP\n      Model Name: LaserJet Pro M404\n')
    + script('broadcast-dns-service-discovery', '\n  192.168.88.31\n    631/tcp ipp\n      ty=HP LaserJet Pro M404\n')
    + script('broadcast-wsdd-discover', '\n  Devices\n    192.168.88.21\n        Type: Device pub:Computer\n'))

VANTAGE = {'interface': 'eth0', 'address': '192.168.88.10', 'prefix': 24, 'subnet': '192.168.88.0/24',
           'gateway': '192.168.88.1', 'gateway_mac': '4c:5e:0c:11:22:33', 'wireless': False,
           'dns': ['192.168.88.1'], 'search': ['office.example']}
NEIGHBOURS = {'192.168.88.1': {'mac': '4c:5e:0c:11:22:33', 'state': 'REACHABLE'},
              '192.168.88.30': {'mac': '00:11:32:aa:bb:cc', 'state': 'STALE'},
              '192.168.88.40': {'mac': '9a:12:34:56:78:9a', 'state': 'DELAY'}}
HEARD_NOTHING = {'mndp': [], 'llmnr': [], 'gaps': {}, 'seconds': 40}


def supported(version):
    return {'status': 'supported', 'cycle': '6.49', 'eol': None, 'latest': '6.49.18', 'error': None}


def build(**over):
    kwargs = {'client': 'Example Ltd', 'vantage': VANTAGE, 'scanned': '192.168.88.0/24', 'note': None,
              'discovery': lan.parse_nmap_xml(DISCOVERY), 'neighbours': NEIGHBOURS,
              'ports': lan.parse_nmap_xml(PORTS), 'broadcast': lan.parse_nmap_xml(BROADCAST),
              'heard': HEARD_NOTHING, 'level2': False, 'support': supported,
              'vendors': {'4c:5e:0c': 'Routerboard.com', '00:11:32': 'Synology Incorporated'}}
    kwargs.update(over)
    return lan_audit.build_result(**kwargs)


def ids(result) -> set[str]:
    return {f['id'] for f in result['findings'] if 'id' in f}


def device(result, ip):
    return next(d for d in result['devices'] if d['ip'] == ip)


# ---------------------------------------------------------------------------
# N1: where NetAudit is
# ---------------------------------------------------------------------------

def test_vantage_takes_the_default_route_interface(tmp_path):
    resolv = tmp_path / 'resolv.conf'
    resolv.write_text(RESOLV)
    v = lan.vantage(run=fake_ip(), resolv_paths=(str(resolv),))
    assert v == {'interface': 'eth0', 'address': '192.168.88.10', 'prefix': 24, 'subnet': '192.168.88.0/24',
                 'gateway': '192.168.88.1', 'gateway_mac': '4c:5e:0c:11:22:33', 'wireless': False,
                 'dns': ['192.168.88.1'], 'search': ['office.example']}


def test_vantage_on_a_named_interface_and_wifi(tmp_path):
    v = lan.vantage('wlp1s0', run=fake_ip(), resolv_paths=(str(tmp_path / 'missing'),))
    assert (v['interface'], v['address'], v['subnet'], v['wireless']) == ('wlp1s0', '10.20.0.5', '10.20.0.0/16', True)
    assert v['gateway'] is None            # the default route is on eth0
    assert v['dns'] == [] and v['search'] == []


def test_vantage_without_a_default_route_or_address_is_an_error(tmp_path):
    with pytest.raises(lan.LanError, match='no default route'):
        lan.vantage(run=fake_ip(route=[]), resolv_paths=())
    with pytest.raises(lan.LanError, match='no IPv4 address'):
        lan.vantage('eth9', run=fake_ip(), resolv_paths=())


def test_systemd_stub_resolver_is_skipped_for_the_real_one(tmp_path):
    stub = tmp_path / 'stub'
    stub.write_text('nameserver 127.0.0.53\nsearch office.example\n')
    real = tmp_path / 'real'
    real.write_text('nameserver 192.168.88.1\nsearch office.example\n')
    v = lan.vantage(run=fake_ip(), resolv_paths=(str(real), str(stub)))
    assert v['dns'] == ['192.168.88.1']


@pytest.mark.parametrize('subnet, address, expected, cut', [
    ('192.168.88.0/24', '192.168.88.10', '192.168.88.0/24', False),
    ('10.1.0.0/22', '10.1.2.3', '10.1.0.0/22', False),
    ('10.20.0.0/16', '10.20.7.5', '10.20.7.0/24', True),
    ('172.16.0.0/12', '172.20.1.1', '172.20.1.0/24', True),
])
def test_scan_range_caps_a_big_subnet(subnet, address, expected, cut):
    scanned, note = lan.scan_range(subnet, address)
    assert scanned == expected
    assert (note is not None) is cut


@pytest.mark.parametrize('subnet, address', [('8.8.8.0/24', '8.8.8.8'), ('100.64.0.0/24', '100.64.0.5'),
                                             ('169.254.0.0/16', '169.254.3.3')])
def test_a_public_or_non_office_subnet_is_refused(subnet, address):
    with pytest.raises(lan.LanError, match='not a private'):
        lan.scan_range(subnet, address)


# ---------------------------------------------------------------------------
# N2: devices of this segment
# ---------------------------------------------------------------------------

def test_neighbours_keep_only_answered_entries():
    assert lan.neighbours('eth0', run=fake_ip()) == {
        '192.168.88.1': {'mac': '4c:5e:0c:11:22:33', 'state': 'REACHABLE'},
        '192.168.88.30': {'mac': '00:11:32:aa:bb:cc', 'state': 'STALE'},
        '192.168.88.40': {'mac': '9a:12:34:56:78:9a', 'state': 'DELAY'},
    }


def test_neighbours_failure_raises():
    def run(cmd, timeout=30):
        return 1, '', 'boom'
    with pytest.raises(lan.LanError):
        lan.neighbours('eth0', run=run)


def _neigh_reads(*tables):
    """`ip -j neigh` that answers with the given tables in turn, then the
    last one again - the kernel dropping entries as the scan goes on."""
    calls = []

    def run(cmd, timeout=30):
        calls.append(cmd)
        table = tables[min(len(calls), len(tables)) - 1]
        if isinstance(table, str):
            return 1, '', table
        return 0, json.dumps(table), ''
    run.calls = calls
    return run


QUIET_ONLY = [{'dst': '192.168.88.30', 'dev': 'eth0', 'lladdr': '00:11:32:aa:bb:cc', 'state': ['STALE']}]


def test_neighbour_watch_keeps_what_the_kernel_dropped():
    """CI e2e-lan run 45893044669: after 254 probes the neighbour table holds
    more than gc_thresh1 (128) entries and the kernel drops stale ones before
    a single late read - MACs went missing, a device seen only by ARP could too."""
    run = _neigh_reads(QUIET_ONLY, [])
    watch = lan.NeighbourWatch('eth0', run=run, every=0.01)
    watch.start()
    found, error = watch.stop()
    assert error is None
    assert found == {'192.168.88.30': {'mac': '00:11:32:aa:bb:cc', 'state': 'STALE'}}
    assert len(run.calls) >= 2                                  # a read at start and one at stop


def test_neighbour_watch_error_only_when_no_read_worked():
    found, error = lan.NeighbourWatch('eth0', run=_neigh_reads('boom'), every=0.01).start().stop()
    assert found == {} and 'boom' in error
    found, error = lan.NeighbourWatch('eth0', run=_neigh_reads('boom', QUIET_ONLY), every=0.01).start().stop()
    assert '192.168.88.30' in found and error is None


def test_mac_vendor_and_random_mac(tmp_path):
    prefixes = tmp_path / 'nmap-mac-prefixes'
    prefixes.write_text('# comment\n4C5E0C Routerboard.com\n001132 Synology Incorporated\n')
    vendors = lan.load_vendors(str(prefixes))
    assert lan.mac_vendor('4c:5e:0c:11:22:33', vendors) == 'Routerboard.com'
    assert lan.mac_vendor('aa:bb:cc:00:00:00', vendors) is None
    assert lan.is_random_mac('9a:12:34:56:78:9a') is True      # locally administered bit
    assert lan.is_random_mac('4c:5e:0c:11:22:33') is False
    assert lan.load_vendors(str(tmp_path / 'missing')) == {}


def test_parse_nmap_xml_reads_hosts_ports_services_and_scripts():
    parsed = lan.parse_nmap_xml(PORTS)
    assert parsed['error'] is None
    hosts = {h['ip']: h for h in parsed['hosts']}
    gw = hosts['192.168.88.1']
    ftp = next(p for p in gw['ports'] if p['port'] == 21)
    assert (ftp['service'], ftp['product'], ftp['version'], ftp['devicetype'], ftp['method'], ftp['conf']) == \
        ('ftp', 'MikroTik router ftpd', '6.49.7', 'router', 'probed', 10)
    win = hosts['192.168.88.21']
    assert win['hostnames'] == ['BUH-PC1.office.example']
    assert win['hostscripts']['smb2-security-mode']['data'] == {'3.1.1': ['Message signing enabled and required']}
    smb = next(p for p in win['ports'] if p['port'] == 445)
    assert (smb['method'], smb['conf']) == ('table', 3)
    vnc = next(p for p in hosts['192.168.88.40']['ports'] if p['port'] == 5900)
    assert vnc['scripts']['vnc-info']['data']['Security types'] == [{'name': 'None', 'type': '1'}]


def test_parse_nmap_xml_reads_mac_and_prescripts():
    xml = nmap_xml(host('192.168.88.5', mac='00:11:32:aa:bb:cc', vendor='Synology Incorporated'),
                   prescripts=script('broadcast-upnp-info', 'x'))
    parsed = lan.parse_nmap_xml(xml)
    assert parsed['hosts'][0]['mac'] == '00:11:32:aa:bb:cc'
    assert parsed['hosts'][0]['mac_vendor'] == 'Synology Incorporated'
    assert parsed['prescripts']['broadcast-upnp-info']['output'] == 'x'


@pytest.mark.parametrize('text', ['', 'not xml', '<?xml version="1.0"?><nmaprun><host>'])
def test_parse_nmap_xml_broken_output_is_an_error_not_an_empty_network(text):
    parsed = lan.parse_nmap_xml(text)
    assert parsed['error'] and parsed['hosts'] == []


def test_parse_nmap_xml_does_not_resolve_entities():
    evil = ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
            '<nmaprun><host><address addr="&e;" addrtype="ipv4"/></host></nmaprun>')
    parsed = lan.parse_nmap_xml(evil)
    assert parsed['error'] and parsed['hosts'] == []


def test_broadcast_devices_from_upnp_mdns_and_wsdd():
    found = lan.broadcast_devices(lan.parse_nmap_xml(BROADCAST)['prescripts'])
    assert found['192.168.88.1']['upnp'] == {'server': 'MikroTik UPnP/1.0', 'name': 'MikroTik Router',
                                             'manufacturer': 'MikroTik', 'model': 'router'}
    assert found['192.168.88.31']['upnp']['model'] == 'LaserJet Pro M404'
    assert found['192.168.88.31']['mdns'] == ['631/tcp ipp']
    assert found['192.168.88.21']['wsdd'] == ['Device pub:Computer']


def _mndp(*tlvs) -> bytes:
    body = b''.join(struct.pack('>HH', t, len(v)) + v for t, v in tlvs)
    return b'\x00\x00\x00\x01' + body


def test_parse_mndp_reads_identity_version_board():
    payload = _mndp((1, bytes.fromhex('4c5e0c112233')), (5, b'office-gw'), (7, b'7.15.3 (stable)'),
                    (8, b'MikroTik'), (12, b'RB4011iGS+'), (17, bytes([192, 168, 88, 1])))
    assert lan.parse_mndp(payload) == {'mac': '4c:5e:0c:11:22:33', 'identity': 'office-gw',
                                       'version': '7.15.3 (stable)', 'platform': 'MikroTik',
                                       'board': 'RB4011iGS+', 'ipv4': '192.168.88.1'}


@pytest.mark.parametrize('payload', [b'', b'\x00\x00', b'\x00\x00\x00\x01\x00\x05\x00\x40short', b'\xff' * 3])
def test_parse_mndp_garbage_is_none(payload):
    assert lan.parse_mndp(payload) is None


def _dns_query(name: str, flags: int = 0x0000) -> bytes:
    qname = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\x00'
    return struct.pack('>HHHHHH', 0x1234, flags, 1, 0, 0, 0) + qname + struct.pack('>HH', 1, 1)


def test_parse_llmnr_query_and_ignore_answers():
    assert lan.parse_llmnr(_dns_query('fileserver')) == 'fileserver'
    assert lan.parse_llmnr(_dns_query('fileserver', flags=0x8000)) is None     # a response
    assert lan.parse_llmnr(b'\x00\x01') is None


# ---------------------------------------------------------------------------
# what is sent: commands
# ---------------------------------------------------------------------------

FORBIDDEN = {'-sS', '-sU', '-O', '-A', '--privileged', '-sC', '--script-args'}


def test_discovery_command_is_unprivileged_and_gentle():
    cmd = lan.discovery_command('192.168.88.0/24', 'eth0')
    assert cmd[0] == 'nmap' and '-sn' in cmd and '-n' in cmd and cmd[-1] == '192.168.88.0/24'
    assert any(a.startswith('-PS') and '445' in a and '3389' in a for a in cmd)
    assert '--max-rate' in cmd and '-T3' in cmd and ['-oX', '-'] == cmd[cmd.index('-oX'):cmd.index('-oX') + 2]
    assert not FORBIDDEN & set(cmd)


def test_ports_command_names_scripts_one_by_one():
    one = lan.ports_command(['192.168.88.20', '192.168.88.21'], 'eth0', level2=False)
    two = lan.ports_command(['192.168.88.20'], 'eth0', level2=True)
    for cmd in (one, two):
        assert {'-sT', '-sV', '--version-light', '-Pn', '--host-timeout'} <= set(cmd)
        assert not (FORBIDDEN - {'--script-args'}) & set(cmd)
    # a silent smb-vuln-ms17-010 is "not vulnerable" and "the check failed" alike;
    # vulns.showall makes it say which (review #65 pass 1, P1) - fixed in code, never from a user
    assert '--script-args' not in one
    assert two[two.index('--script-args') + 1] == 'vulns.showall'
    def scripts(cmd):
        return set(cmd[cmd.index('--script') + 1].split(','))
    assert scripts(one) == set(lan.LEVEL1_SCRIPTS)
    assert scripts(two) == set(lan.LEVEL1_SCRIPTS) | set(lan.LEVEL2_SCRIPTS)
    assert not scripts(two) & {'default', 'safe', 'vuln', 'intrusive', 'all', 'auth', 'brute', 'exploit', 'dos'}
    assert one[-2:] == ['192.168.88.20', '192.168.88.21']


def test_broadcast_command_runs_only_the_three_discovery_scripts():
    cmd = lan.broadcast_command('eth0')
    assert cmd[cmd.index('--script') + 1].split(',') == list(lan.BROADCAST_SCRIPTS)
    assert ['-e', 'eth0'] == cmd[cmd.index('-e'):cmd.index('-e') + 2]


def test_script_lists_hold_no_intrusive_script():
    """nmap's own categories, read from the installed scripts when nmap is here."""
    import pathlib
    base = pathlib.Path('/usr/share/nmap/scripts')
    if not base.is_dir():
        pytest.skip('nmap is not installed here')
    bad = {'intrusive', 'brute', 'exploit', 'dos', 'external', 'malware', 'fuzzer'}
    for name in lan.LEVEL1_SCRIPTS + lan.LEVEL2_SCRIPTS + lan.BROADCAST_SCRIPTS:
        text = (base / f'{name}.nse').read_text(errors='replace')
        line = next(line for line in text.splitlines() if line.startswith('categories'))
        assert not {c for c in bad if f'"{c}"' in line}, (name, line)


# ---------------------------------------------------------------------------
# N3: the router, without passwords
# ---------------------------------------------------------------------------

def test_router_is_identified_with_its_version_and_sources():
    r = build()['router']
    assert (r['ip'], r['vendor'], r['os'], r['version']) == ('192.168.88.1', 'MikroTik', 'RouterOS', '6.49.7')
    assert r['version_source'] == 'ftp banner'
    assert {'mac vendor', 'ftp banner', 'upnp'} <= set(r['sources'])
    assert r['support']['status'] == 'supported'


def test_router_version_from_a_v7_ssh_banner():
    gw = host('192.168.88.1', port(22, 'ssh', product='OpenSSH', version='8.0 mikrotik 7.15.3', devicetype='router'))
    r = build(ports=lan.parse_nmap_xml(nmap_xml(gw)))['router']
    assert (r['vendor'], r['version'], r['version_source']) == ('MikroTik', '7.15.3', 'ssh banner')


def test_router_version_from_mndp_when_banners_hide_it():
    gw = host('192.168.88.1', port(8291, 'winbox', product='MikroTik WinBox', devicetype='router'))
    heard = {**HEARD_NOTHING, 'mndp': [{'ip': '192.168.88.1', 'version': '7.16 (stable)', 'board': 'hEX'}]}
    r = build(ports=lan.parse_nmap_xml(nmap_xml(gw)), heard=heard)['router']
    assert (r['version'], r['version_source'], r['model']) == ('7.16', 'mndp', 'hEX')


def test_unknown_router_is_said_so_and_is_a_gap():
    gw = host('192.168.88.1', port(53, 'domain', product='dnsmasq', version='2.89'))
    res = build(ports=lan.parse_nmap_xml(nmap_xml(gw)), vendors={}, broadcast=lan.parse_nmap_xml(nmap_xml()))
    assert res['router']['vendor'] is None
    item = next(c for c in res['checked'] if c['item'] == 'router')
    assert item['status'] == 'not_checked'


def test_router_management_findings_and_no_duplicate_device_findings():
    res = build()
    found = ids(res)
    assert {'RTR-SVC-001:telnet', 'RTR-SVC-001:ftp', 'RTR-SVC-001:http', 'RTR-SVC-001:winbox',
            'RTR-SVC-001:btest', 'RTR-UPNP-001'} <= found
    sev = {f['id']: f['severity'] for f in res['findings'] if 'id' in f}
    assert sev['RTR-SVC-001:telnet'] == 'high' and sev['RTR-SVC-001:winbox'] == 'low'
    assert not {i for i in found if i.endswith(':192.168.88.1') or ':192.168.88.1:' in i}


def test_router_firmware_out_of_support():
    def ended(version):
        return {'status': 'ended', 'cycle': '6.49', 'eol': '2024-01-01', 'latest': '6.49.18', 'error': None}
    res = build(support=ended)
    f = next(f for f in res['findings'] if f.get('id') == 'RTR-VER-001')
    assert f['severity'] == 'high' and '6.49' in f['detail']


def test_router_support_lookup_failure_is_a_gap_not_ok():
    def broken(version):
        return {'status': 'error', 'cycle': None, 'eol': None, 'latest': None, 'error': 'endoflife.date: HTTP 503'}
    res = build(support=broken)
    item = next(c for c in res['checked'] if c['item'] == 'router_support')
    assert item['status'] == 'not_checked' and '503' in item['detail']
    assert res['verdict'] != 'ok'


# ---------------------------------------------------------------------------
# N4: services and misconfigurations
# ---------------------------------------------------------------------------

def test_level1_findings_on_the_example_network():
    found = ids(build())
    assert {'NET-SMB-001:192.168.88.20', 'NET-SMB-002:192.168.88.20', 'NET-TEL-001:192.168.88.20',
            'NET-FTP-001:192.168.88.20', 'NET-DB-001:192.168.88.20:6379',
            'NET-RDP-001:192.168.88.21', 'NET-RDP-002:192.168.88.21',
            'NET-WEB-001:192.168.88.31:80', 'NET-TLS-001:192.168.88.31:443',
            'NET-SSH-001:192.168.88.40:22', 'NET-VNC-001:192.168.88.40:5900'} <= found
    # signing required and SMBv2 only: nothing on the Windows PC's SMB
    assert not {i for i in found if i.startswith(('NET-SMB-001:192.168.88.21', 'NET-SMB-002:192.168.88.21'))}
    # level 2 was not run
    assert not {i for i in found if i.startswith(('NET-SMB-003', 'NET-FTP-002', 'NET-DB-002'))}


def test_expired_self_signed_certificate_is_one_medium_finding():
    f = next(f for f in build()['findings'] if f.get('id') == 'NET-TLS-001:192.168.88.31:443')
    assert f['severity'] == 'medium' and 'expired' in f['title']


def test_self_signed_but_valid_certificate_is_low():
    printer = host('192.168.88.31', port(443, 'https', tunnel='ssl', scripts=cert('2099-01-01T00:00:00',
                                                                                  self_signed=True)))
    f = next(f for f in build(ports=lan.parse_nmap_xml(nmap_xml(printer)))['findings']
             if f.get('id') == 'NET-TLS-001:192.168.88.31:443')
    assert f['severity'] == 'low'


def test_http_that_moves_to_https_is_not_a_finding():
    printer = host('192.168.88.31', port(80, 'http', scripts=TITLE_TO_HTTPS) + port(9100, 'jetdirect'))
    assert 'NET-WEB-001:192.168.88.31:80' not in ids(build(ports=lan.parse_nmap_xml(nmap_xml(printer))))


def test_vnc_with_a_password_and_rdp_with_nla_only_are_fine():
    pc = host('192.168.88.50', port(5900, 'vnc', scripts=VNC_AUTH) + port(3389, 'ms-wbt-server', scripts=RDP_NLA_ONLY)
              + port(22, 'ssh', scripts=SSH_GOOD))
    found = ids(build(ports=lan.parse_nmap_xml(nmap_xml(pc))))
    assert 'NET-VNC-001:192.168.88.50:5900' not in found
    assert 'NET-RDP-002:192.168.88.50' not in found
    assert 'NET-RDP-001:192.168.88.50' in found
    assert 'NET-SSH-001:192.168.88.50:22' not in found


def test_level2_findings():
    legacy = host('192.168.88.20', port(21, 'ftp', scripts=FTP_ANON) + port(445, 'microsoft-ds')
                  + port(6379, 'redis', scripts=REDIS_OPEN), hostscripts=SMB_V1 + MS17_VULN)
    found = ids(build(ports=lan.parse_nmap_xml(nmap_xml(legacy)), level2=True))
    assert {'NET-SMB-003:192.168.88.20', 'NET-FTP-002:192.168.88.20', 'NET-DB-002:192.168.88.20:6379'} <= found
    sev = {f['id']: f['severity'] for f in build(ports=lan.parse_nmap_xml(nmap_xml(legacy)), level2=True)['findings']
           if 'id' in f}
    assert sev['NET-SMB-003:192.168.88.20'] == 'critical'


def test_level2_negative_answers_are_not_findings():
    legacy = host('192.168.88.20', port(445, 'microsoft-ds') + port(6379, 'redis', scripts=REDIS_AUTH),
                  hostscripts=SMB_V2_ONLY + MS17_NOT)
    found = ids(build(ports=lan.parse_nmap_xml(nmap_xml(legacy)), level2=True))
    assert not {i for i in found if i.startswith(('NET-SMB-003', 'NET-DB-002'))}


def test_llmnr_heard_is_a_finding_and_names_the_askers():
    heard = {**HEARD_NOTHING, 'llmnr': [{'ip': '192.168.88.21', 'name': 'fileserver'},
                                        {'ip': '192.168.88.10', 'name': 'self'}]}
    res = build(heard=heard)
    f = next(f for f in res['findings'] if f.get('id') == 'NET-NAME-001')
    assert f['severity'] == 'medium' and '192.168.88.21' in f['detail']
    assert '192.168.88.10' not in f['detail']          # NetAudit's own machine is not counted


def test_llmnr_not_heard_is_ok_with_its_caveat_and_a_busy_port_is_a_gap():
    item = next(c for c in build()['checked'] if c['item'] == 'llmnr')
    assert item['status'] == 'ok' and '40' in item['detail']
    res = build(heard={**HEARD_NOTHING, 'gaps': {'llmnr': 'UDP 5355 is in use (systemd-resolved?)'}})
    item = next(c for c in res['checked'] if c['item'] == 'llmnr')
    assert item['status'] == 'not_checked' and '5355' in item['detail']


# ---------------------------------------------------------------------------
# devices, the model, and no false clean
# ---------------------------------------------------------------------------

def test_devices_merge_nmap_and_the_neighbour_table():
    res = build()
    nas = device(res, '192.168.88.30')                     # answered ARP only
    assert (nas['answered'], nas['mac'], nas['vendor'], nas['ports']) == \
        ('neighbour', '00:11:32:aa:bb:cc', 'Synology Incorporated', [])
    srv = device(res, '192.168.88.40')
    assert srv['random_mac'] is True and srv['answered'] == 'tcp'
    assert device(res, '192.168.88.10')['kind'] == 'this_machine'
    assert device(res, '192.168.88.1')['kind'] == 'router'
    assert device(res, '192.168.88.31')['kind'] == 'printer'
    assert device(res, '192.168.88.21')['kind'] == 'windows'
    assert {'name': 'BUH-PC1.office.example', 'source': 'dns'} in device(res, '192.168.88.21')['names']
    assert res['stats'] == {'addresses': 254, 'devices': 7, 'neighbour_only': 1}


def test_the_pn_scan_does_not_make_an_arp_only_device_a_tcp_one():
    """-Pn reports every target as up; only the discovery answer or an open
    port means the device answered TCP (CI e2e-lan run 45892042011: the host
    that drops every probe read as 'tcp')."""
    quiet = host('192.168.88.30')                               # in the -Pn scan, no open port
    printer = host('192.168.88.31', port(9100, 'jetdirect'))    # missed by discovery, a port answered
    res = build(discovery=lan.parse_nmap_xml(nmap_xml(host('192.168.88.1'))),
                ports=lan.parse_nmap_xml(nmap_xml(quiet, printer)),
                neighbours={**NEIGHBOURS, '192.168.88.31': {'mac': '00:11:22:33:44:55', 'state': 'STALE'}})
    assert device(res, '192.168.88.30')['answered'] == 'neighbour'
    assert device(res, '192.168.88.31')['answered'] == 'tcp'
    # .30 and .40: in the neighbour table, not in discovery, no open port
    assert device(res, '192.168.88.40')['answered'] == 'neighbour'
    assert res['stats']['neighbour_only'] == 2


def test_a_service_guessed_from_the_port_is_marked():
    smb = next(p for p in device(build(), '192.168.88.21')['ports'] if p['port'] == 445)
    assert smb['guessed'] is True


def test_findings_point_at_their_device_and_devices_carry_the_worst():
    res = build()
    assert all(f.get('device') for f in res['findings'] if f.get('id', '').startswith('NET-')
               and f['id'] != 'NET-NAME-001')
    assert device(res, '192.168.88.20')['worst'] == 'high'
    assert device(res, '192.168.88.30')['worst'] is None


def test_verdict_score_limits_and_next_steps():
    res = build()
    assert res['verdict'] == 'danger'
    assert 0 <= res['score']['value'] < 100
    assert set(res['limits']) >= {'udp', 'os_detection', 'other_subnets', 'known_vulns', 'level2'}
    steps = {s['id'] for s in res['next_steps']}
    assert {'router_ssh', 'saved_hosts', 'level2', 'other_vantage'} <= steps
    assert next(s for s in res['next_steps'] if s['id'] == 'saved_hosts')['hosts'] == ['192.168.88.40']


def test_nothing_answered_is_never_a_clean_network():
    empty = lan.parse_nmap_xml(nmap_xml())
    res = build(discovery=empty, ports=empty, neighbours={}, broadcast=empty)
    assert res['verdict'] == 'incomplete'
    item = next(c for c in res['checked'] if c['item'] == 'discovery')
    assert item['status'] == 'not_checked'


def test_a_failed_port_scan_is_a_gap():
    res = build(ports={'hosts': [], 'prescripts': {}, 'error': 'nmap exit code 1: boom'})
    item = next(c for c in res['checked'] if c['item'] == 'services')
    assert item['status'] == 'not_checked' and 'boom' in item['detail']
    assert res['verdict'] in ('incomplete', 'danger', 'warn')


def test_a_cut_range_is_a_gap():
    res = build(scanned='10.20.7.0/24', note='10.20.0.0/16 is larger than /22: only 10.20.7.0/24 was scanned')
    item = next(c for c in res['checked'] if c['item'] == 'range')
    assert item['status'] == 'not_checked'


def test_level2_on_is_not_a_limit():
    assert 'level2' not in build(level2=True)['limits']


# ---------------------------------------------------------------------------
# review #65 pass 1: no false "complete", announcements, the listener's scope,
# the protocol a port really speaks
# ---------------------------------------------------------------------------

SMB_ERROR = script('smb-protocols', 'ERROR: Script execution failed (use -d to debug)')


def _gap_items(result):
    return {c['item']: c['detail'] for c in result['checked'] if c['status'] == 'not_checked'}


def test_a_target_missing_from_the_port_scan_is_a_gap():
    """P1: discovery saw .20, the port-scan XML holds only the gateway."""
    res = build(discovery=lan.parse_nmap_xml(nmap_xml(host('192.168.88.1'), host('192.168.88.20'))),
                ports=lan.parse_nmap_xml(nmap_xml(GATEWAY)), neighbours={})
    gaps = _gap_items(res)
    assert 'services' in gaps and '192.168.88.20' in gaps['services']
    assert device(res, '192.168.88.20')['gaps']
    assert res['verdict'] != 'ok' and res['score']['complete'] is False


def test_a_timed_out_host_is_a_gap():
    timed = host('192.168.88.20', port(445, 'microsoft-ds'), timedout=True)
    res = build(ports=lan.parse_nmap_xml(nmap_xml(GATEWAY, timed)), neighbours={})
    assert '192.168.88.20' in _gap_items(res)['services']
    assert any('timed out' in g for g in device(res, '192.168.88.20')['gaps'])


def test_a_failed_script_is_a_gap_not_a_clean_answer():
    """P1: 445 open, smb-protocols failed, smb2-security-mode silent - SMB was not checked."""
    pc = host('192.168.88.20', port(445, 'microsoft-ds', product='Samba smbd'), hostscripts=SMB_ERROR)
    res = build(discovery=lan.parse_nmap_xml(nmap_xml(host('192.168.88.1'), host('192.168.88.20'))),
                ports=lan.parse_nmap_xml(nmap_xml(host('192.168.88.1'), pc)), neighbours={},
                broadcast=lan.parse_nmap_xml(nmap_xml()))
    gaps = _gap_items(res)
    assert 'scripts' in gaps and 'smb-protocols' in gaps['scripts'] and 'smb2-security-mode' in gaps['scripts']
    assert res['verdict'] == 'incomplete' and res['score']['complete'] is False


def test_every_applicable_script_must_answer():
    srv = host('192.168.88.40', port(22, 'ssh', product='OpenSSH') + port(443, 'https', tunnel='ssl')
               + port(3389, 'ms-wbt-server') + port(5900, 'vnc'))
    gaps = _gap_items(build(ports=lan.parse_nmap_xml(nmap_xml(GATEWAY, srv))))['scripts']
    for name in ('ssh2-enum-algos', 'ssl-cert', 'rdp-enum-encryption', 'vnc-info'):
        assert name in gaps, name


def test_level2_answers_and_silences():
    patched = script('smb-vuln-ms17-010', 'NOT VULNERABLE', '<table key="CVE-2017-0143">'
                     '<elem key="state">NOT VULNERABLE</elem><table key="check_results">'
                     '<elem>This system is patched.</elem></table></table>')
    failed = script('smb-vuln-ms17-010', 'NOT VULNERABLE', '<table key="CVE-2017-0143">'
                    "<elem key=\"state\">NOT VULNERABLE</elem><table key=\"check_results\">"
                    "<elem>Could not connect to 'IPC$'</elem></table></table>")
    clean = host('192.168.88.20', port(445, 'microsoft-ds') + port(6379, 'redis', scripts=REDIS_AUTH),
                 hostscripts=SMB_V2_ONLY + SIGNING_REQUIRED + patched)
    res = build(ports=lan.parse_nmap_xml(nmap_xml(GATEWAY, clean)), level2=True)
    assert 'level2' not in _gap_items(res)
    broken = host('192.168.88.20', port(21, 'ftp', product='vsftpd') + port(445, 'microsoft-ds'),
                  hostscripts=SMB_V2_ONLY + SIGNING_REQUIRED + failed)
    gaps = _gap_items(build(ports=lan.parse_nmap_xml(nmap_xml(GATEWAY, broken)), level2=True))
    # ms17-010 could not check; ftp-anon is silent for a refusal and for a lost connection alike
    assert 'smb-vuln-ms17-010' in gaps['level2'] and 'ftp-anon' in gaps['level2']


def test_devices_seen_only_by_announcements_are_kept():
    """P3: broadcast announced .1, .31 and .21; TCP and ARP saw only .1."""
    res = build(discovery=lan.parse_nmap_xml(nmap_xml(host('192.168.88.1'))), neighbours={},
                ports=lan.parse_nmap_xml(nmap_xml(GATEWAY)))
    for ip in ('192.168.88.21', '192.168.88.31'):
        d = device(res, ip)
        assert d is not None and d['answered'] == 'announced' and d['gaps'], ip
    assert device(res, '192.168.88.31')['kind'] == 'printer'


def test_mndp_only_device_and_foreign_announcements():
    heard = {**HEARD_NOTHING, 'mndp': [{'ip': '192.168.88.2', 'identity': 'ap-2', 'board': 'cAP'},
                                       {'ip': '10.99.0.4', 'identity': 'other-site'}],
             'llmnr': [{'ip': '10.99.0.4', 'name': 'OTHER-NETWORK'}]}
    res = build(heard=heard)
    assert device(res, '192.168.88.2')['answered'] == 'announced'
    assert all(d['ip'] != '10.99.0.4' for d in res['devices'])
    # P4: a query from outside the scanned range is not this network's problem
    assert 'NET-NAME-001' not in ids(res)
    assert all(x['ip'] != '10.99.0.4' for x in res['heard']['mndp'] + res['heard']['llmnr'])


def test_announced_devices_are_port_scanned(monkeypatch, tmp_path):
    ip = fake_ip(neigh=[])
    scanned = []

    def run(cmd, timeout=30):
        if cmd[0] == 'ip':
            return ip(cmd, timeout)
        if '-sn' in cmd and '--script' not in cmd:
            return 0, nmap_xml(host('192.168.88.1')), ''
        if '--version-light' in cmd:
            scanned.append(cmd)
            return 0, nmap_xml(GATEWAY, PRINTER), ''
        return 0, BROADCAST, ''
    monkeypatch.setattr(lan_audit, '_run', run)
    monkeypatch.setattr(lan_audit, '_listen', lambda seconds, **kw: HEARD_NOTHING)
    monkeypatch.setattr(lan_audit, '_tool', lambda name: True)
    monkeypatch.setattr(lan_audit, '_support', supported)
    monkeypatch.setattr(lan, 'RESOLV_PATHS', (str(tmp_path / 'none'),))
    lan_audit.check_lan_audit(authorization=lan_audit.AUTH_CONFIRM)
    assert '192.168.88.31' in scanned[0] and '192.168.88.21' in scanned[0]


def test_the_listener_is_scoped_to_the_interface_and_the_range():
    """P4, with real sockets on loopback and free ports."""
    import socket
    import threading
    import time

    def free_port():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]

    payload = _mndp((5, b'gw'), (7, b'7.16'))

    def heard(**scope):
        ports = {'mndp': free_port(), 'llmnr': free_port()}
        box = {}
        th = threading.Thread(target=lambda: box.update(lan.listen(1, ports=ports, **scope)))
        th.start()
        time.sleep(0.3)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(payload, ('127.0.0.1', ports['mndp']))
        th.join()
        return box['mndp']

    assert [m['identity'] for m in heard(interface='lo', network='127.0.0.0/8')] == ['gw']
    assert heard(interface='lo', network='192.168.88.0/24') == []
    loopback = socket.if_nameindex()
    other = next((name for _, name in loopback if name != 'lo'), None)
    if other:
        assert heard(interface=other, network='127.0.0.0/8') == []


def test_a_port_number_alone_does_not_prove_the_protocol():
    """P5: port 23 answered as HTTP is not Telnet; a port nmap only guessed is
    a possible service, not a proven one."""
    web23 = host('192.168.88.20', port(23, 'http', product='nginx') + port(3306, 'http', product='nginx'))
    found = ids(build(ports=lan.parse_nmap_xml(nmap_xml(GATEWAY, web23))))
    assert 'NET-TEL-001:192.168.88.20' not in found and 'NET-DB-001:192.168.88.20:3306' not in found
    guess = host('192.168.88.20', port(23, 'telnet', method='table', conf=3))
    f = next(f for f in build(ports=lan.parse_nmap_xml(nmap_xml(GATEWAY, guess)))['findings']
             if f.get('id') == 'NET-TEL-001:192.168.88.20')
    assert f['confidence'] == 'low' and f['requires_manual_verification'] is True
    sure = next(f for f in build()['findings'] if f.get('id') == 'NET-TEL-001:192.168.88.20')
    assert sure['confidence'] == 'high' and 'requires_manual_verification' not in sure


def test_the_router_port_number_alone_does_not_prove_the_service():
    gw = host('192.168.88.1', port(21, 'ftp', product='MikroTik router ftpd', version='6.49.7', devicetype='router')
              + port(23, 'http', product='lighttpd'))
    assert 'RTR-SVC-001:telnet' not in ids(build(ports=lan.parse_nmap_xml(nmap_xml(gw))))


def test_a_failed_port_scan_leaves_no_device_and_no_level2_looking_checked():
    """Review #65 pass 2, R2-1: the whole port scan failed - every device it
    should have covered has a gap (a ring on the map), and level 2 and the
    scripts are "not checked", never ok."""
    res = build(discovery=lan.parse_nmap_xml(nmap_xml(host('192.168.88.1'), host('192.168.88.20'))),
                neighbours={}, broadcast=lan.parse_nmap_xml(nmap_xml()), vendors={},
                ports={'hosts': [], 'prescripts': {}, 'error': 'nmap exit code -1: timeout'}, level2=True)
    for ip in ('192.168.88.1', '192.168.88.20'):
        assert any('timeout' in g for g in device(res, ip)['gaps']), ip
    gaps = _gap_items(res)
    assert {'services', 'scripts', 'level2'} <= set(gaps)
    assert 'timeout' in gaps['level2']


def test_level2_names_devices_the_port_scan_did_not_cover():
    res = build(discovery=lan.parse_nmap_xml(nmap_xml(host('192.168.88.1'), host('192.168.88.20'))),
                ports=lan.parse_nmap_xml(nmap_xml(GATEWAY)), neighbours={},
                broadcast=lan.parse_nmap_xml(nmap_xml()), level2=True)
    assert '192.168.88.20' in _gap_items(res)['level2']


def test_ftp_and_telnet_over_tls_are_not_clear_text():
    """R2-2: a TLS tunnel nmap saw on the port is not a clear-text login; an
    anonymous login it allows is still a finding."""
    tls = host('192.168.88.20', port(21, 'ftp', product='vsftpd', tunnel='ssl', scripts=FTP_ANON)
               + port(23, 'telnet', tunnel='ssl'))
    found = ids(build(ports=lan.parse_nmap_xml(nmap_xml(GATEWAY, tls)), level2=True))
    assert 'NET-FTP-001:192.168.88.20' not in found and 'NET-TEL-001:192.168.88.20' not in found
    assert 'NET-FTP-002:192.168.88.20' in found
    plain = host('192.168.88.20', port(21, 'ftp', product='vsftpd') + port(23, 'telnet'))
    found = ids(build(ports=lan.parse_nmap_xml(nmap_xml(GATEWAY, plain))))
    assert {'NET-FTP-001:192.168.88.20', 'NET-TEL-001:192.168.88.20'} <= found


def test_router_management_over_tls_is_not_clear_text():
    gw = host('192.168.88.1', port(21, 'ftp', product='MikroTik router ftpd', version='6.49.7', tunnel='ssl',
                                   devicetype='router')
              + port(8728, 'mikrotik-routeros-api', tunnel='ssl', product='MikroTik RouterOS API'))
    found = ids(build(ports=lan.parse_nmap_xml(nmap_xml(gw))))
    assert 'RTR-SVC-001:ftp' not in found and 'RTR-SVC-001:api' not in found


# ---------------------------------------------------------------------------
# the check: permission first, then the steps
# ---------------------------------------------------------------------------

def test_registered_as_an_active_lan_check():
    spec = registry.get('lan_audit')
    assert spec is not None and spec.category == 'lan' and spec.risk_level == 'ACTIVE'
    params = {p['name']: p for p in spec.params}
    assert params['authorization']['options'] == ['no', lan_audit.AUTH_CONFIRM]
    assert params['authorization']['default'] == 'no'
    assert params['level2']['options'] == ['no', lan_audit.LEVEL2_CONFIRM]
    assert params['interface']['format'] == 'interface' and params['interface']['default'] == ''
    assert params['share_with_ai']['default'] == 'no'
    assert set(spec.required_tools) == {'nmap', 'ip'}


@pytest.fixture
def no_network(monkeypatch):
    calls = []

    def run(cmd, timeout=30):
        calls.append(cmd)
        return 127, '', 'should not run'
    monkeypatch.setattr(lan_audit, '_run', run)
    monkeypatch.setattr(lan_audit, '_listen', lambda seconds, **kw: calls.append('listen') or HEARD_NOTHING)
    monkeypatch.setattr(lan_audit, '_tool', lambda name: True)
    return calls


def test_nothing_is_sent_without_the_owner_permission(no_network):
    res = lan_audit.check_lan_audit(client='X', authorization='no')
    assert res['verdict'] == 'not_started' and 'permission' in res['error']
    assert no_network == []


def test_missing_nmap_is_said(monkeypatch, no_network):
    monkeypatch.setattr(lan_audit, '_tool', lambda name: name != 'nmap')
    res = lan_audit.check_lan_audit(authorization=lan_audit.AUTH_CONFIRM)
    assert res['verdict'] == 'not_started' and 'nmap' in res['error']
    assert no_network == []


def test_a_public_network_is_refused_before_any_probe(monkeypatch, no_network):
    route = [{'dst': 'default', 'gateway': '203.0.113.1', 'dev': 'eth0'}]
    addr = [{'ifname': 'eth0', 'addr_info': [{'family': 'inet', 'local': '203.0.113.5', 'prefixlen': 24}]}]
    ip = fake_ip(route=route, addr=addr)
    monkeypatch.setattr(lan_audit, '_run', ip)
    res = lan_audit.check_lan_audit(authorization=lan_audit.AUTH_CONFIRM)
    assert res['verdict'] == 'not_started' and 'not a private' in res['error']
    assert not [c for c in ip.calls if c[0] == 'nmap']


def test_full_run_with_fake_tools(monkeypatch, tmp_path):
    ip = fake_ip()
    outputs = {'-sn': DISCOVERY, '--version-light': PORTS, 'broadcast': BROADCAST}
    seen = []

    def run(cmd, timeout=30):
        if cmd[0] == 'ip':
            return ip(cmd, timeout)
        seen.append(cmd)
        if '-sn' in cmd and '--script' not in cmd:
            return 0, outputs['-sn'], ''
        if '--version-light' in cmd:
            return 0, outputs['--version-light'], ''
        return 0, outputs['broadcast'], ''
    monkeypatch.setattr(lan_audit, '_run', run)
    monkeypatch.setattr(lan_audit, '_listen', lambda seconds, **kw: HEARD_NOTHING)
    monkeypatch.setattr(lan_audit, '_tool', lambda name: True)
    monkeypatch.setattr(lan_audit, '_support', supported)
    monkeypatch.setattr(lan, 'RESOLV_PATHS', (str(tmp_path / 'none'),))
    res = lan_audit.check_lan_audit(client='Example Ltd', authorization=lan_audit.AUTH_CONFIRM)
    assert res['verdict'] == 'danger' and res['client'] == 'Example Ltd'
    assert res['scanned'] == '192.168.88.0/24'
    assert len(seen) == 3
    port_scan = next(c for c in seen if '--version-light' in c)
    # every device found is scanned, the neighbour-only one too; this machine is not
    assert '192.168.88.30' in port_scan and '192.168.88.10' not in port_scan
    assert res['router']['vendor'] == 'MikroTik'


def test_a_device_seen_only_while_discovery_ran_is_kept(monkeypatch, tmp_path):
    """The neighbour table is watched during the scan, not read once after it."""
    ip = fake_ip()
    state = {'phase': 'before'}        # the entry exists from discovery until the kernel drops it
    scanned = []

    def run(cmd, timeout=30):
        if cmd[:3] == ['ip', '-j', 'neigh']:
            return 0, json.dumps(QUIET_ONLY if state['phase'] == 'seen' else []), ''
        if cmd[0] == 'ip':
            return ip(cmd, timeout)
        if '-sn' in cmd and '--script' not in cmd:
            state['phase'] = 'seen'
            return 0, nmap_xml(host('192.168.88.1')), ''
        state['phase'] = 'dropped'      # broadcast or port scan: later reads no longer see it
        if '--version-light' in cmd:
            scanned.append(cmd)
            return 0, nmap_xml(host('192.168.88.30')), ''
        return 0, nmap_xml(), ''
    monkeypatch.setattr(lan_audit, '_run', run)
    monkeypatch.setattr(lan_audit, '_listen', lambda seconds, **kw: HEARD_NOTHING)
    monkeypatch.setattr(lan_audit, '_tool', lambda name: True)
    monkeypatch.setattr(lan_audit, '_support', supported)
    monkeypatch.setattr(lan, 'RESOLV_PATHS', (str(tmp_path / 'none'),))
    res = lan_audit.check_lan_audit(authorization=lan_audit.AUTH_CONFIRM)
    assert scanned and '192.168.88.30' in scanned[0]
    d = device(res, '192.168.88.30')
    assert d is not None and d['answered'] == 'neighbour' and d['mac'] == '00:11:32:aa:bb:cc'


def test_nmap_timeout_is_a_gap(monkeypatch, tmp_path):
    ip = fake_ip()

    def run(cmd, timeout=30):
        if cmd[0] == 'ip':
            return ip(cmd, timeout)
        if '-sn' in cmd and '--script' not in cmd:
            return 0, DISCOVERY, ''
        if '--version-light' in cmd:
            return -1, '', 'timeout after 900s'
        return 0, nmap_xml(), ''
    monkeypatch.setattr(lan_audit, '_run', run)
    monkeypatch.setattr(lan_audit, '_listen', lambda seconds, **kw: HEARD_NOTHING)
    monkeypatch.setattr(lan_audit, '_tool', lambda name: True)
    monkeypatch.setattr(lan_audit, '_support', supported)
    monkeypatch.setattr(lan, 'RESOLV_PATHS', (str(tmp_path / 'none'),))
    res = lan_audit.check_lan_audit(authorization=lan_audit.AUTH_CONFIRM)
    item = next(c for c in res['checked'] if c['item'] == 'services')
    assert item['status'] == 'not_checked' and 'timeout' in item['detail']
    assert res['verdict'] != 'ok'


def test_routeros_support_uses_endoflife_routeros(monkeypatch):
    from netaudit_pkg import laravel_data
    asked = []

    def fake(url):
        asked.append(url)
        return 200, [{'cycle': '7.20', 'eol': '2026-01-12', 'latest': '7.20.8'},
                     {'cycle': '7.25', 'eol': False, 'latest': '7.25.2'}]
    monkeypatch.setattr(laravel_data, '_ask', fake)
    out = lan_audit.routeros_support('7.20.4', today=date(2026, 11, 25))
    assert asked == ['https://endoflife.date/api/routeros.json']
    assert (out['status'], out['cycle'], out['latest']) == ('ended', '7.20', '7.20.8')
    assert lan_audit.routeros_support('7.25.1', today=date(2026, 11, 25))['status'] == 'supported'


# ---------------------------------------------------------------------------
# AI: the client's network stays here unless the run allowed it
# ---------------------------------------------------------------------------

def _report(share='no'):
    return {'timestamp': '2026-11-25 22:00:00', 'checks': ['lan_audit', 'ping'],
            'execution_context': {'lan_audit': {'client': 'Example Ltd', 'share_with_ai': share}},
            'results': {'lan_audit': build(), 'ping': {'target': '8.8.8.8', 'loss_pct': 0}}}


def test_ai_does_not_get_the_network_by_default():
    from netaudit_pkg import history
    out = history.withhold_local_only(_report())
    assert '192.168.88' not in json.dumps(out['results']['lan_audit'])
    assert out['results']['lan_audit']['withheld']
    assert out['results']['ping'] == {'target': '8.8.8.8', 'loss_pct': 0}


def test_ai_gets_the_network_when_the_run_allowed_it():
    from netaudit_pkg import history
    report = _report(share='yes')
    assert history.withhold_local_only(report)['results']['lan_audit'] == report['results']['lan_audit']


def test_ai_prompt_has_no_device_address(monkeypatch):
    from netaudit_pkg import history
    sent = {}

    class Resp:
        status_code = 200

        @staticmethod
        def raise_for_status():
            return None

        @staticmethod
        def json():
            return {'content': [{'type': 'text', 'text': '{"summary": "x", "problems": []}'}]}

    def post(url, **kw):
        sent['prompt'] = kw['json']['messages'][0]['content']
        return Resp()
    import httpx
    monkeypatch.setattr(httpx, 'post', post)
    history.ai_analyze(_report(), api_key='test-key')
    assert 'prompt' in sent and '192.168.88.' not in sent['prompt']
