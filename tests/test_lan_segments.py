"""
Network audit PR 2 (docs/research/network_audit.md §13, contract N5 + N6):
other subnets found through the router, domain controllers from the
client's DNS, segments with the auditor's labels, isolation between
segments, one flat network, and audits from several places merged. No
network: nmap, dig and the database are fakes or a temporary database.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from netaudit_pkg import lan, lan_merge, storage
from netaudit_pkg.checks import lan_audit
from tests.test_lan_audit import (
    GATEWAY,
    HEARD_NOTHING,
    VANTAGE,
    build,
    device,
    fake_ip,
    host,
    ids,
    nmap_xml,
    port,
    supported,
)

OWN = '192.168.88.0/24'
BUH = '192.168.30.0/24'
SRV = '192.168.40.0/24'


def _gap_items(result):
    return {c['item']: c['detail'] for c in result['checked'] if c['status'] == 'not_checked'}


# ---------------------------------------------------------------------------
# N5: candidate gateways and found subnets
# ---------------------------------------------------------------------------

def test_candidates_cover_the_own_16_and_192_168():
    v = {**VANTAGE, 'address': '10.20.7.5', 'subnet': '10.20.7.0/24', 'dns': []}
    got = lan.candidate_gateways(v)
    assert {'10.20.0.1', '10.20.0.254', '10.20.255.1', '192.168.0.1', '192.168.255.254'} <= set(got)
    assert '10.20.7.1' not in got and '10.20.7.254' not in got        # the own /24
    assert len(got) == (255 + 256) * 2
    own_192 = lan.candidate_gateways(VANTAGE)                          # already inside 192.168/16
    assert len(own_192) == 255 * 2 and not [a for a in own_192 if not a.startswith('192.168.')]


def test_dns_servers_and_controllers_in_other_private_ranges_are_candidates():
    v = {**VANTAGE, 'dns': ['10.50.0.2', '8.8.8.8', '192.168.88.1']}
    got = lan.candidate_gateways(v, extra=['172.20.5.10', '1.1.1.1'])
    assert {'10.50.0.1', '10.50.0.254', '172.20.5.1', '172.20.5.254'} <= set(got)
    assert not [a for a in got if a.startswith(('8.', '1.1.'))]


def test_subnet_probe_is_unprivileged_and_gentle():
    cmd = lan.subnet_probe_command(['192.168.30.1', '192.168.30.254'], 'eth0')
    assert cmd[:3] == ['nmap', '-sn', '-n'] and '-PS22,53,80,443,8291' in cmd
    assert '--max-rate' in cmd and cmd[-2:] == ['192.168.30.1', '192.168.30.254']
    assert not {'-sS', '-sU', '-O', '--privileged', '--script', '--script-args'} & set(cmd)


def test_found_subnets_from_answering_gateways():
    probe = lan.parse_nmap_xml(nmap_xml(host('192.168.30.1'), host('192.168.30.254'), host('192.168.40.254'),
                                        host('192.168.88.1')))
    assert lan.found_subnets(probe, OWN) == [{'cidr': BUH, 'gateway': '192.168.30.1'},
                                             {'cidr': SRV, 'gateway': '192.168.40.254'}]


def test_discovery_command_takes_several_subnets():
    cmd = lan.discovery_command([BUH, SRV], 'eth0')
    assert cmd[-2:] == [BUH, SRV]


# ---------------------------------------------------------------------------
# domain controllers from the client's DNS (research §5.2)
# ---------------------------------------------------------------------------

def _dig(answers):
    calls = []

    def run(cmd, timeout=30):
        calls.append(cmd)
        return 0, answers.get(cmd[-1], ''), ''
    run.calls = calls
    return run


def test_domain_controllers_from_srv_records():
    run = _dig({'_ldap._tcp.dc._msdcs.office.example': '0 100 389 dc1.office.example.\n0 100 389 dc2.office.example.\n',
                'dc1.office.example.': '192.168.40.5\n', 'dc2.office.example.': '203.0.113.9\n'})
    found, error = lan.domain_controllers('office.example', run=run)
    assert error is None and found == [{'name': 'dc1.office.example', 'ip': '192.168.40.5'}]
    assert all(c[0] == 'dig' and '+short' in c for c in run.calls)


@pytest.mark.parametrize('domain', ['-f/etc/passwd', 'a b', 'x' * 300, ''])
def test_a_strange_domain_is_never_asked(domain):
    run = _dig({})
    found, error = lan.domain_controllers(domain, run=run)
    assert found == [] and error and run.calls == []


# ---------------------------------------------------------------------------
# N6: segments, labels, isolation, one flat network
# ---------------------------------------------------------------------------

BUH_PC = host('192.168.30.5', port(445, 'microsoft-ds', product='Microsoft Windows SMB')
              + port(3389, 'ms-wbt-server', product='Microsoft Terminal Services')
              + port(80, 'http', product='Microsoft IIS'),
              names=('BUH-PC3.office.example',))
BUH_GW = host('192.168.30.1', port(22, 'ssh', product='MikroTik RouterOS sshd', devicetype='router'))
SEARCH = {'ran': True, 'candidates': 510, 'error': None, 'cut': [],
          'found': [{'cidr': BUH, 'gateway': '192.168.30.1', 'source': 'probe'},
                    {'cidr': SRV, 'gateway': '192.168.40.254', 'source': 'probe'}]}


def build2(**over):
    remote = lan.parse_nmap_xml(nmap_xml(host('192.168.30.1'), host('192.168.30.5'), host('192.168.40.254')))
    kwargs = {'subnet_search': SEARCH, 'remote_discovery': remote, 'labels': {}, 'dcs': None,
              'ports': lan.parse_nmap_xml(nmap_xml(GATEWAY, BUH_PC, BUH_GW, host('192.168.40.254')))}
    kwargs.update(over)
    return build(**kwargs)


def segment(result, cidr):
    return next(s for s in result['segments'] if s['cidr'] == cidr)


def test_segments_one_per_subnet_with_devices():
    res = build2()
    assert [s['cidr'] for s in res['segments']] == [OWN, BUH, SRV]
    own = segment(res, OWN)
    assert own['own'] is True and own['gateway'] == '192.168.88.1'
    buh = segment(res, BUH)
    assert buh['own'] is False and buh['gateway'] == '192.168.30.1'
    assert set(buh['devices']) == {'192.168.30.1', '192.168.30.5'}
    assert device(res, '192.168.30.5')['segment'] == BUH
    assert device(res, '192.168.88.20')['segment'] == OWN


def test_a_segment_name_is_suggested_from_what_is_inside():
    assert segment(build2(), BUH)['suggestion'] == 'accounting'      # BUH-PC3


def test_the_auditor_label_wins_and_marks_sensitive():
    res = build2(labels={BUH: {'name': 'Бухгалтерия', 'sensitive': True}})
    buh = segment(res, BUH)
    assert (buh['name'], buh['sensitive'], buh['labelled']) == ('Бухгалтерия', True, True)


def test_a_found_subnet_gateway_is_a_router_interface():
    res = build2()
    gw = device(res, '192.168.30.1')
    assert gw['kind'] == 'router'
    assert not [f for f in res['findings'] if f.get('device') == '192.168.30.1']


def test_isolation_findings_from_the_vantage_segment():
    res = build2()
    found = ids(res)
    assert {f'NET-SEG-001:{_q(OWN)}:{_q(BUH)}:445', f'NET-SEG-001:{_q(OWN)}:{_q(BUH)}:3389'} <= found
    assert not [i for i in found if i.startswith('NET-SEG-001') and i.endswith(':80')]   # not a sensitive service
    f = next(f for f in res['findings'] if f.get('id', '').endswith(':445') and f['id'].startswith('NET-SEG'))
    assert f['severity'] == 'medium' and '192.168.30.5' in f['detail']
    # the device's own findings are judged as everywhere (RDP reachable)
    assert 'NET-RDP-001:192.168.30.5' in found


def test_isolation_into_a_sensitive_segment_is_high():
    res = build2(labels={BUH: {'name': 'Бухгалтерия', 'sensitive': True}})
    f = next(f for f in res['findings'] if f.get('id') == f'NET-SEG-001:{_q(OWN)}:{_q(BUH)}:445')
    assert f['severity'] == 'high' and 'Бухгалтерия' in f['detail']


def _q(cidr):
    from urllib.parse import quote
    return quote(cidr, safe='')


def test_one_flat_network_is_a_finding():
    search = {**SEARCH, 'found': []}
    res = build(subnet_search=search, remote_discovery=lan.parse_nmap_xml(nmap_xml()), labels={}, dcs=None)
    f = next(f for f in res['findings'] if f.get('id') == 'NET-SEG-002')
    assert f['severity'] == 'medium' and f['confidence'] == 'medium'


def test_no_flat_network_claim_when_the_search_failed_or_other_subnets_answer():
    failed = {**SEARCH, 'found': [], 'error': 'nmap exit code -1: timeout'}
    res = build(subnet_search=failed, remote_discovery=lan.parse_nmap_xml(nmap_xml()), labels={}, dcs=None)
    assert 'NET-SEG-002' not in ids(res) and 'timeout' in _gap_items(res)['subnets']
    assert 'NET-SEG-002' not in ids(build2())


def test_subnets_beyond_the_cap_are_a_gap_and_the_search_is_no_longer_a_limit():
    res = build2(subnet_search={**SEARCH, 'cut': ['192.168.50.0/24', '192.168.60.0/24']})
    assert '192.168.50.0/24' in _gap_items(res)['subnets']
    assert 'other_subnets' not in res['limits'] and 'traceroute' in res['limits']
    ok = next(c for c in build2()['checked'] if c['item'] == 'subnets')
    assert ok['status'] == 'ok' and '2' in ok['detail']


def test_without_a_search_other_subnets_stay_a_limit():
    res = build()
    assert 'other_subnets' in res['limits'] and len(res['segments']) == 1


def test_domain_controllers_are_devices():
    dcs = {'found': [{'name': 'dc1.office.example', 'ip': '192.168.40.5'}], 'error': None}
    res = build2(dcs=dcs)
    d = device(res, '192.168.40.5')
    assert d['kind'] == 'domain_controller' and {'name': 'dc1.office.example', 'source': 'ad dns'} in d['names']


# ---------------------------------------------------------------------------
# the check: the steps in order
# ---------------------------------------------------------------------------

def test_full_run_finds_and_scans_another_subnet(monkeypatch, tmp_path):
    ip = fake_ip()
    seen = []

    def run(cmd, timeout=30):
        if cmd[0] == 'ip':
            return ip(cmd, timeout)
        seen.append(cmd)
        if '-PS22,53,80,443,8291' in cmd:
            return 0, nmap_xml(host('192.168.30.1')), ''
        if '-sn' in cmd and '--script' not in cmd and BUH in cmd:
            return 0, nmap_xml(host('192.168.30.1'), host('192.168.30.5')), ''
        if '-sn' in cmd and '--script' not in cmd:
            return 0, nmap_xml(host('192.168.88.1'), host('192.168.88.20')), ''
        if '--version-light' in cmd:
            return 0, nmap_xml(GATEWAY, BUH_PC, BUH_GW, host('192.168.88.20', port(22, 'ssh'))), ''
        return 0, nmap_xml(), ''
    monkeypatch.setattr(lan_audit, '_run', run)
    monkeypatch.setattr(lan_audit, '_listen', lambda seconds, **kw: HEARD_NOTHING)
    monkeypatch.setattr(lan_audit, '_tool', lambda name: True)
    monkeypatch.setattr(lan_audit, '_support', supported)
    monkeypatch.setattr(lan_audit, '_labels', lambda client: {BUH: {'name': 'Бухгалтерия', 'sensitive': True}})
    monkeypatch.setattr(lan, 'RESOLV_PATHS', (str(tmp_path / 'none'),))
    res = lan_audit.check_lan_audit(client='Example Ltd', authorization=lan_audit.AUTH_CONFIRM)
    probe = next(c for c in seen if '-PS22,53,80,443,8291' in c)
    assert '192.168.30.1' in probe and '192.168.88.1' not in probe
    ports = next(c for c in seen if '--version-light' in c)
    assert {'192.168.30.5', '192.168.30.1', '192.168.88.20'} <= set(ports)
    assert segment(res, BUH)['name'] == 'Бухгалтерия'
    assert f'NET-SEG-001:{_q(OWN)}:{_q(BUH)}:445' in ids(res)


# ---------------------------------------------------------------------------
# labels: storage and API
# ---------------------------------------------------------------------------

def test_labels_round_trip(isolated_db):
    storage.lan_segment_label_set('Example Ltd', BUH, 'Бухгалтерия', True)
    storage.lan_segment_label_set('Example Ltd', SRV, 'Серверы', False)
    storage.lan_segment_label_set('Other', BUH, 'x', False)
    assert storage.lan_segment_labels('Example Ltd') == {BUH: {'name': 'Бухгалтерия', 'sensitive': True},
                                                         SRV: {'name': 'Серверы', 'sensitive': False}}
    storage.lan_segment_label_set('Example Ltd', BUH, 'Бухгалтерия 2', False)
    assert storage.lan_segment_labels('Example Ltd')[BUH] == {'name': 'Бухгалтерия 2', 'sensitive': False}
    assert storage._conn().execute('PRAGMA user_version').fetchone()[0] == len(storage.MIGRATIONS)


@pytest.mark.parametrize('cidr, name', [('8.8.8.0/24', 'x'), ('not a net', 'x'), (BUH, 'x' * 61)])
def test_labels_refuse_bad_values(isolated_db, cidr, name):
    with pytest.raises(ValueError):
        storage.lan_segment_label_set('Example Ltd', cidr, name, False)


def test_labels_api(isolated_db):
    client = TestClient(__import__('web.app', fromlist=['app']).app)
    r = client.put('/api/lan/segments', json={'client': 'Example Ltd', 'cidr': BUH, 'name': 'Бухгалтерия',
                                              'sensitive': True})
    assert r.status_code == 200
    assert client.get('/api/lan/segments', params={'client': 'Example Ltd'}).json() == \
        {BUH: {'name': 'Бухгалтерия', 'sensitive': True}}
    bad = client.put('/api/lan/segments', json={'client': 'Example Ltd', 'cidr': '8.8.8.0/24', 'name': 'x',
                                                'sensitive': False})
    assert bad.status_code == 400


# ---------------------------------------------------------------------------
# a second vantage point: audits of one client merged
# ---------------------------------------------------------------------------

def _result_from(vantage_subnet, address, extra_findings=()):
    v = {**VANTAGE, 'address': address, 'subnet': vantage_subnet}
    res = build2(vantage=v, scanned=vantage_subnet) if vantage_subnet == OWN else build(
        vantage=v, scanned=vantage_subnet, discovery=lan.parse_nmap_xml(nmap_xml(host('192.168.30.5'))),
        ports=lan.parse_nmap_xml(nmap_xml(BUH_PC)), neighbours={}, broadcast=lan.parse_nmap_xml(nmap_xml()),
        subnet_search={**SEARCH, 'found': []}, remote_discovery=lan.parse_nmap_xml(nmap_xml()), labels={},
        dcs=None)
    res['findings'] += list(extra_findings)
    return res


def test_merge_two_vantage_points():
    first = {'timestamp': '2026-11-27 10:00:00', 'results': {'lan_audit': _result_from(OWN, '192.168.88.10')}}
    second = {'timestamp': '2026-11-27 11:00:00', 'results': {'lan_audit': _result_from(BUH, '192.168.30.9')}}
    merged = lan_merge.merge([first, second])
    assert merged['merged'] is True
    assert [v['subnet'] for v in merged['vantages']] == [OWN, BUH]
    buh = next(s for s in merged['segments'] if s['cidr'] == BUH)
    assert set(buh['seen_from']) == {OWN, BUH}
    assert len({f['id'] for f in merged['findings'] if 'id' in f}) == len([f for f in merged['findings'] if 'id' in f])
    assert merged['verdict'] in ('danger', 'warn', 'incomplete', 'ok')


def test_merge_keeps_the_latest_audit_per_vantage():
    old = {'timestamp': '2026-11-26 10:00:00', 'results': {'lan_audit': _result_from(OWN, '192.168.88.10')}}
    new = {'timestamp': '2026-11-27 10:00:00', 'results': {'lan_audit': _result_from(OWN, '192.168.88.11')}}
    merged = lan_merge.merge([new, old])
    assert [v['address'] for v in merged['vantages']] == ['192.168.88.11']


def test_merged_api_reads_the_client_audits(isolated_db):
    for stamp, subnet, addr in (('2026-11-27 10:00:00', OWN, '192.168.88.10'),
                                ('2026-11-27 11:00:00', BUH, '192.168.30.9')):
        storage.save_report({'timestamp': stamp, 'checks': ['lan_audit'],
                             'execution_context': {'lan_audit': {'client': 'Example Ltd'}},
                             'results': {'lan_audit': _result_from(subnet, addr)}})
    other = _result_from(OWN, '192.168.88.99')
    other['client'] = 'Someone else'
    storage.save_report({'timestamp': '2026-11-27 12:00:00', 'checks': ['lan_audit'],
                         'execution_context': {'lan_audit': {'client': 'Someone else'}},
                         'results': {'lan_audit': other}})
    client = TestClient(__import__('web.app', fromlist=['app']).app)
    body = client.get('/api/lan/merged', params={'client': 'Example Ltd'}).json()
    assert [v['address'] for v in body['vantages']] == ['192.168.88.10', '192.168.30.9']
    assert json.dumps(body).count('192.168.88.99') == 0


def test_merged_view_shows_the_current_labels(isolated_db):
    """Browser check of PR 2: a later audit made before the segment was named
    must not hide the name - the merged view shows the client's labels now."""
    first = _result_from(OWN, '192.168.88.10')
    second = _result_from(BUH, '192.168.30.9')
    for stamp, r in (('2026-11-27 10:00:00', first), ('2026-11-27 11:00:00', second)):
        storage.save_report({'timestamp': stamp, 'checks': ['lan_audit'], 'results': {'lan_audit': r}})
    storage.lan_segment_label_set('Example Ltd', BUH, 'Бухгалтерия', True)
    client = TestClient(__import__('web.app', fromlist=['app']).app)
    body = client.get('/api/lan/merged', params={'client': 'Example Ltd'}).json()
    buh = next(s for s in body['segments'] if s['cidr'] == BUH)
    assert (buh['name'], buh['sensitive'], buh['labelled']) == ('Бухгалтерия', True, True)


def test_merge_keeps_a_label_over_an_unlabelled_later_view():
    labelled = _result_from(OWN, '192.168.88.10')
    for s in labelled['segments']:
        if s['cidr'] == BUH:
            s.update(name='Бухгалтерия', labelled=True, sensitive=True)
    merged = lan_merge.merge([{'timestamp': '2026-11-27 10:00:00', 'results': {'lan_audit': labelled}},
                              {'timestamp': '2026-11-27 11:00:00',
                               'results': {'lan_audit': _result_from(BUH, '192.168.30.9')}}])
    buh = next(s for s in merged['segments'] if s['cidr'] == BUH)
    assert (buh['name'], buh['sensitive']) == ('Бухгалтерия', True)


def test_a_mixed_segment_gets_no_kind_based_name():
    """Browser check of PR 2: one device of each kind is not "Printers"."""
    assert lan_audit._suggest([{'names': [], 'kind': k} for k in ('printer', 'windows', 'phone', 'nas')]) is None
    assert lan_audit._suggest([{'names': [], 'kind': k} for k in ('printer', 'printer', 'windows')]) == 'printers'

