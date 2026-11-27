"""
Network access policy, PR A (docs/research/network_access_policy.md §3-4,
§7-8, contract P1-P3 and P6): the owner's access rules per client, how one
observation is judged by them (most specific rule wins, a tie is a conflict,
no rule is unknown, a sensitive mark is not a rule), the evidence a probe
keeps, NET-POL-001/002, and the rules' storage, API and CLI. No network:
nmap is a fake, the database is a temporary one.
"""

from __future__ import annotations

import json
from argparse import Namespace

import pytest
from fastapi.testclient import TestClient

import netaudit
from netaudit_pkg import lan, lan_policy, storage
from netaudit_pkg.checks import lan_audit
from netaudit_pkg.findings import subject_id
from tests.test_lan_audit import GATEWAY as GATEWAY_XML
from tests.test_lan_audit import (
    HEARD_NOTHING,
    VANTAGE,
    device,
    fake_ip,
    host,
    ids,
    nmap_xml,
    port,
    supported,
)
from tests.test_lan_segments import BUH, BUH_GW, BUH_PC, OWN, build2

ME = VANTAGE['address']                                    # 192.168.88.10, in OWN


def R(rid, source, destination, service, decision, note=''):
    return {'id': rid, 'source': source, 'destination': destination, 'service': service,
            'decision': decision, 'note': note}


def policy(*rules, revision=1, error=None):
    return {'revision': revision, 'rules': lan_policy.validate(list(rules)), 'error': error}


def pol(fid_port, ip='192.168.30.5', source=ME):
    return subject_id('NET-POL-001', source, ip, fid_port)


def seg(port_number):
    return subject_id('NET-SEG-001', OWN, BUH, port_number)


def finding(res, fid):
    return next(f for f in res['findings'] if f.get('id') == fid)


def item(res, name):
    return next((c for c in res['checked'] if c['item'] == name), None)


FORBID_GUESTS = R('r1', OWN, BUH, 'any', 'forbid')
ALLOW_ADMIN = R('r2', ME, BUH, 'SMB', 'allow', '1C administration')
ALLOW_ADMIN_RDP = R('r3', ME, BUH, 'RDP', 'allow', '1C administration')


# ---------------------------------------------------------------------------
# P1: a rule, its validation
# ---------------------------------------------------------------------------

def test_validate_normalizes_a_rule():
    got = lan_policy.validate([{'source': '192.168.88.10/32', 'destination': '192.168.30.7/24',
                                'service': 'smb', 'decision': 'Forbid', 'note': '  why  '}])
    assert got == [{'source': '192.168.88.10', 'destination': BUH, 'service': 'SMB',
                    'decision': 'forbid', 'note': 'why'}]


@pytest.mark.parametrize('service, normal', [('any', 'any'), ('TCP/8443', 'tcp/8443'), ('rdp', 'RDP'),
                                             ('postgresql', 'PostgreSQL'), ('tcp/22', 'tcp/22')])
def test_validate_knows_the_services(service, normal):
    assert lan_policy.validate([R('r1', 'any', BUH, service, 'forbid')])[0]['service'] == normal


@pytest.mark.parametrize('bad', [
    {'source': '8.8.8.8', 'destination': BUH, 'service': 'any', 'decision': 'forbid'},
    {'source': OWN, 'destination': '1.1.1.0/24', 'service': 'any', 'decision': 'forbid'},
    {'source': 'not an address', 'destination': BUH, 'service': 'any', 'decision': 'forbid'},
    {'source': OWN, 'destination': BUH, 'service': 'telnetz', 'decision': 'forbid'},
    {'source': OWN, 'destination': BUH, 'service': 'tcp/0', 'decision': 'forbid'},
    {'source': OWN, 'destination': BUH, 'service': 'tcp/70000', 'decision': 'forbid'},
    {'source': OWN, 'destination': BUH, 'service': 'any', 'decision': 'maybe'},
    {'source': OWN, 'destination': BUH, 'service': 'any', 'decision': 'forbid', 'note': 'x' * 201},
    {'source': OWN, 'destination': BUH, 'service': 'any', 'decision': 'forbid', 'id': 'r1; drop'},
    {'source': ['x'], 'destination': BUH, 'service': 'any', 'decision': 'forbid'},
    'not a rule',
])
def test_validate_refuses_a_bad_rule(bad):
    with pytest.raises(ValueError):
        lan_policy.validate([bad])


def test_validate_refuses_too_many_rules():
    many = [R(f'r{i}', OWN, f'192.168.30.{i}', 'any', 'forbid') for i in range(1, 202)]
    with pytest.raises(ValueError, match='200'):
        lan_policy.validate(many)


def test_an_exception_must_say_why():
    """§3.1: an allow more specific than a forbid it sits inside is an
    exception - without a note it is refused."""
    with pytest.raises(ValueError, match='note'):
        lan_policy.validate([FORBID_GUESTS, {**ALLOW_ADMIN, 'note': ''}])
    assert len(lan_policy.validate([FORBID_GUESTS, ALLOW_ADMIN])) == 2
    # a forbid inside a broader allow is no exception
    assert lan_policy.validate([R('r1', OWN, BUH, 'any', 'allow'), R('r2', OWN, '192.168.30.5', 'SMB', 'forbid')])


def test_the_named_services_are_the_isolation_services():
    for number, (label, _names, _products) in lan_audit.SENSITIVE_SERVICES.items():
        assert number in lan_policy.SERVICES[label], (number, label)


# ---------------------------------------------------------------------------
# P1: one observation judged by the rules (§3.2-3.3)
# ---------------------------------------------------------------------------

def judge(rules, source, destination, number):
    return lan_policy.evaluate(lan_policy.validate(rules), source, destination, number)


def test_a_forbid_rule_matches():
    assert judge([FORBID_GUESTS], ME, '192.168.30.5', 445) == {'decision': 'forbid', 'rules': ['r1']}


def test_no_rule_is_unknown_never_forbidden():
    assert judge([], ME, '192.168.30.5', 445) == {'decision': 'unknown', 'rules': []}
    assert judge([R('r1', OWN, '192.168.40.0/24', 'any', 'forbid')], ME, '192.168.30.5', 445)['decision'] == 'unknown'


def test_the_admin_exception_wins_over_the_segment_rule():
    assert judge([FORBID_GUESTS, ALLOW_ADMIN], ME, '192.168.30.5', 445) == {'decision': 'allow', 'rules': ['r2']}
    assert judge([FORBID_GUESTS, ALLOW_ADMIN], ME, '192.168.30.5', 3389)['decision'] == 'forbid'


def test_a_host_source_rule_matches_only_from_that_address():
    """§3.2: the source of every observation is NetAudit's own address."""
    assert judge([FORBID_GUESTS, ALLOW_ADMIN], '192.168.88.77', '192.168.30.5', 445)['decision'] == 'forbid'


def test_the_destination_counts_first():
    rules = [R('r1', ME, BUH, 'any', 'allow'), R('r2', OWN, '192.168.30.5', 'any', 'forbid')]
    assert judge(rules, ME, '192.168.30.5', 445) == {'decision': 'forbid', 'rules': ['r2']}


def test_a_longer_prefix_is_more_specific():
    rules = [R('r1', OWN, '192.168.0.0/16', 'any', 'forbid'), R('r2', OWN, BUH, 'any', 'allow')]
    assert judge(rules, ME, '192.168.30.5', 445)['decision'] == 'allow'


def test_the_port_rule_wins_over_any():
    rules = [R('r1', OWN, BUH, 'any', 'allow'), R('r2', OWN, BUH, 'tcp/8443', 'forbid')]
    assert judge(rules, ME, '192.168.30.5', 8443) == {'decision': 'forbid', 'rules': ['r2']}
    assert judge(rules, ME, '192.168.30.5', 443)['decision'] == 'allow'


def test_a_named_service_wins_over_any_and_loses_to_a_port():
    rules = [R('r1', OWN, BUH, 'any', 'forbid'), R('r2', OWN, BUH, 'SMB', 'allow', 'file server'),
             R('r3', OWN, BUH, 'tcp/445', 'forbid')]
    assert judge(rules, ME, '192.168.30.5', 139)['decision'] == 'allow'
    assert judge(rules, ME, '192.168.30.5', 445) == {'decision': 'forbid', 'rules': ['r3']}


def test_a_tie_is_a_conflict():
    rules = [R('r1', OWN, BUH, 'SMB', 'forbid'), R('r2', OWN, BUH, 'SMB', 'allow', 'shared folder')]
    assert judge(rules, ME, '192.168.30.5', 445) == {'decision': 'conflict', 'rules': ['r1', 'r2']}


def test_two_rules_of_one_decision_are_no_conflict():
    rules = [R('r1', OWN, BUH, 'SMB', 'forbid'), R('r2', OWN, BUH, 'SMB', 'forbid')]
    assert judge(rules, ME, '192.168.30.5', 445) == {'decision': 'forbid', 'rules': ['r1', 'r2']}


def test_extra_ports_come_from_forbid_rules_for_this_place():
    rules = lan_policy.validate([R('r1', OWN, BUH, 'tcp/9999', 'forbid'), R('r2', OWN, BUH, 'tcp/22', 'forbid'),
                                 R('r3', OWN, BUH, 'tcp/7777', 'allow'),
                                 R('r4', '192.168.50.0/24', BUH, 'tcp/6666', 'forbid')])
    assert lan_policy.extra_ports(rules, ME, lan.SCAN_PORTS) == ([9999], [])


def test_extra_ports_are_capped():
    rules = lan_policy.validate([R(f'r{i}', OWN, BUH, f'tcp/{30000 + i}', 'forbid') for i in range(1, 26)])
    probed, cut = lan_policy.extra_ports(rules, ME, lan.SCAN_PORTS)
    assert len(probed) == lan_policy.MAX_EXTRA_PORTS == 20 and len(cut) == 5
    assert probed == sorted(probed) and set(probed).isdisjoint(cut)


# ---------------------------------------------------------------------------
# storage: revisions per client (§7)
# ---------------------------------------------------------------------------

def test_no_policy_yet(isolated_db):
    assert storage.lan_policy_get('Example Ltd') == {'client': 'Example Ltd', 'revision': 0, 'rules': [],
                                                     'saved_at': None}


def test_saving_makes_revisions_with_stable_ids(isolated_db):
    first = storage.lan_policy_save('Example Ltd', [
        {'source': OWN, 'destination': BUH, 'service': 'any', 'decision': 'forbid'}])
    assert first['revision'] == 1 and [r['id'] for r in first['rules']] == ['r1']
    second = storage.lan_policy_save('Example Ltd', first['rules'] + [
        {'source': ME, 'destination': BUH, 'service': 'SMB', 'decision': 'allow', 'note': 'admin'}])
    assert second['revision'] == 2 and [r['id'] for r in second['rules']] == ['r1', 'r2']
    # r1 removed, a new rule added: r1 is never reused
    third = storage.lan_policy_save('Example Ltd', [second['rules'][1], {
        'source': OWN, 'destination': BUH, 'service': 'RDP', 'decision': 'forbid'}])
    assert [r['id'] for r in third['rules']] == ['r2', 'r3']
    assert storage.lan_policy_get('Example Ltd')['revision'] == 3
    assert storage._conn().execute('PRAGMA user_version').fetchone()[0] == len(storage.MIGRATIONS)


def test_saving_the_same_rules_is_no_new_revision(isolated_db):
    saved = storage.lan_policy_save('Example Ltd', [FORBID_GUESTS])
    again = storage.lan_policy_save('Example Ltd', saved['rules'])
    assert again['revision'] == saved['revision'] == 1


def test_an_unknown_id_is_a_new_rule(isolated_db):
    saved = storage.lan_policy_save('Example Ltd', [{**FORBID_GUESTS, 'id': 'r7'}])
    assert [r['id'] for r in saved['rules']] == ['r1']


def test_clients_never_share_rules(isolated_db):
    storage.lan_policy_save('Example Ltd', [FORBID_GUESTS])
    assert storage.lan_policy_get('Other')['rules'] == []


def test_a_bad_policy_is_not_saved(isolated_db):
    with pytest.raises(ValueError):
        storage.lan_policy_save('Example Ltd', [{'source': '8.8.8.8', 'destination': BUH, 'service': 'any',
                                                 'decision': 'forbid'}])
    with pytest.raises(ValueError):
        storage.lan_policy_save('x' * 121, [])
    assert storage.lan_policy_get('Example Ltd')['revision'] == 0


# ---------------------------------------------------------------------------
# P3: what a probe keeps (§4.3)
# ---------------------------------------------------------------------------

CLOSED_LISTED = ('<port protocol="tcp" portid="22"><state state="closed" reason="conn-refused" reason_ttl="0"/>'
                 '<service name="ssh" method="table" conf="3"/></port>'
                 '<port protocol="tcp" portid="23"><state state="filtered" reason="no-response" reason_ttl="0"/>'
                 '<service name="telnet" method="table" conf="3"/></port>')
EXTRAPORTS = ('<extraports state="closed" count="3"><extrareasons reason="conn-refused" count="3" proto="tcp" '
              'ports="135,139,3389"/></extraports>'
              '<extraports state="filtered" count="2"><extrareasons reason="no-response" count="2" proto="tcp" '
              'ports="1433-1434"/></extraports>')


def test_closed_and_filtered_ports_are_kept_beside_the_open_ones():
    xml = nmap_xml(host('192.168.30.5', EXTRAPORTS + CLOSED_LISTED + port(445, 'microsoft-ds')))
    h = lan.parse_nmap_xml(xml)['hosts'][0]
    assert [p['port'] for p in h['ports']] == [445]                   # open only, as before
    assert h['closed'] == [22, 135, 139, 3389] and h['filtered'] == [23, 1433, 1434]


def test_extra_ports_command_is_the_same_gentle_scan():
    cmd = lan.extra_ports_command(['192.168.30.5'], [9999, 8443], 'eth0')
    assert cmd[:2] == ['nmap', '-sT'] and '-Pn' in cmd and '--max-rate' in cmd
    assert cmd[cmd.index('-p') + 1] == '8443,9999' and cmd[-1] == '192.168.30.5'
    assert not {'-sS', '-sU', '-O', '--privileged', '--script'} & set(cmd)


def test_every_device_says_what_its_probe_covered():
    res = build2()
    d = device(res, '192.168.30.5')
    assert d['probe']['complete'] is True
    assert d['probe']['ports'] == sorted(lan.SCAN_PORTS)
    assert d['probe']['open'] == [80, 445, 3389]
    timed = build2(ports=lan.parse_nmap_xml(nmap_xml(
        GATEWAY_XML, host('192.168.30.5', port(445, 'microsoft-ds'), timedout=True), BUH_GW)))
    assert device(timed, '192.168.30.5')['probe']['complete'] is False
    assert device(timed, '192.168.40.254')['probe'] == {'ports': [], 'open': [], 'closed': [], 'filtered': [],
                                                        'complete': False}


# ---------------------------------------------------------------------------
# P2: the audit judged by the rules (§3.4, §4)
# ---------------------------------------------------------------------------

def test_a_forbidden_service_that_answers_is_a_violation():
    res = build2(policy=policy(FORBID_GUESTS))
    f = finding(res, pol(445))
    assert f['severity'] == 'high' and f['confidence'] == 'high'
    assert f['device'] == '192.168.30.5' and f['rule'] == 'r1' and f['policy_revision'] == 1
    assert f['segment'] == BUH and f['from'] == OWN
    assert 'not a login' in f['detail'] and ME in f['detail']
    assert finding(res, pol(3389))['severity'] == 'high'
    assert finding(res, pol(80))['severity'] == 'medium'              # plain web, not a sensitive segment


def test_a_violation_into_a_sensitive_segment_is_high():
    res = build2(policy=policy(FORBID_GUESTS), labels={BUH: {'name': 'Бухгалтерия', 'sensitive': True}})
    assert finding(res, pol(80))['severity'] == 'high'


def test_a_path_the_policy_judges_leaves_the_isolation_finding():
    """§3.4: NET-SEG-001 is the observation for paths without the owner's
    intent; a path a rule decides is judged by the rule instead."""
    res = build2(policy=policy(FORBID_GUESTS, ALLOW_ADMIN))
    found = ids(res)
    assert seg(445) not in found and seg(3389) not in found
    assert pol(445) not in found and pol(3389) in found


def test_an_allowed_path_is_listed_not_reported():
    res = build2(policy=policy(FORBID_GUESTS, ALLOW_ADMIN, ALLOW_ADMIN_RDP))
    allowed = {(p['destination'], p['port']) for p in res['policy']['paths'] if p['decision'] == 'allow'}
    assert {('192.168.30.5', 445), ('192.168.30.5', 3389)} <= allowed
    assert not {pol(445), pol(3389), seg(445), seg(3389)} & ids(res)
    assert pol(80) in ids(res)


def test_from_another_staff_address_the_segment_rule_applies():
    v = {**VANTAGE, 'address': '192.168.88.77'}
    res = build2(vantage=v, policy=policy(FORBID_GUESTS, ALLOW_ADMIN))
    assert subject_id('NET-POL-001', '192.168.88.77', '192.168.30.5', 445) in ids(res)


def test_without_rules_nothing_changes():
    res = build2()
    assert 'access_policy' in res['limits'] and item(res, 'access_policy') is None
    assert seg(445) in ids(res) and not [i for i in ids(res) if i.startswith('NET-POL')]


def test_a_sensitive_mark_is_not_a_rule():
    res = build2(labels={BUH: {'name': 'Бухгалтерия', 'sensitive': True}}, policy=policy())
    assert finding(res, seg(445))['severity'] == 'high'
    assert not [i for i in ids(res) if i.startswith('NET-POL')]


def test_an_unknown_path_stays_an_isolation_finding():
    res = build2(policy=policy(R('r1', OWN, '192.168.40.0/24', 'any', 'forbid')))
    assert seg(445) in ids(res)
    assert {'destination': '192.168.30.5', 'port': 445} in [
        {'destination': p['destination'], 'port': p['port']} for p in res['policy']['paths']
        if p['decision'] == 'unknown']


def test_a_conflict_is_neither_violation_nor_allowed():
    res = build2(policy=policy(R('r1', OWN, BUH, 'SMB', 'forbid'), R('r2', OWN, BUH, 'SMB', 'allow', 'share')))
    f = finding(res, subject_id('NET-POL-002', ME, '192.168.30.5', 445))
    assert f['severity'] == 'medium' and 'r1' in f['detail'] and 'r2' in f['detail']
    assert pol(445) not in ids(res) and seg(445) not in ids(res)


def test_rules_for_other_places_are_not_judged_here():
    res = build2(policy=policy(R('r1', '192.168.50.0/24', BUH, 'any', 'forbid')))
    assert 'access_policy_here' in res['limits'] and item(res, 'access_policy') is None
    assert seg(445) in ids(res) and res['policy']['applicable'] == []


def test_a_guessed_service_is_a_violation_to_verify():
    guessed = host('192.168.30.5', port(445, 'microsoft-ds', method='table', conf=3))
    res = build2(policy=policy(FORBID_GUESTS), ports=lan.parse_nmap_xml(nmap_xml(GATEWAY_XML, guessed, BUH_GW)))
    f = finding(res, pol(445))
    assert f['confidence'] == 'medium' and f['requires_manual_verification'] is True


def test_the_policy_item_is_ok_only_when_every_forbid_rule_was_probed():
    clean = build2(policy=policy(R('r1', OWN, BUH, 'tcp/9999', 'forbid')),
                   extra={'ports': [9999], 'cut': [], 'error': None})
    assert item(clean, 'access_policy')['status'] == 'ok'
    bad = build2(policy=policy(FORBID_GUESTS))
    assert item(bad, 'access_policy')['status'] == 'problem'


def test_a_timed_out_destination_is_a_gap():
    timed = lan.parse_nmap_xml(nmap_xml(GATEWAY_XML, host('192.168.30.5', port(80, 'http'), timedout=True), BUH_GW))
    res = build2(policy=policy(R('r1', OWN, BUH, 'RDP', 'forbid')), ports=timed)
    c = item(res, 'access_policy')
    assert c['status'] == 'not_checked' and '192.168.30.5' in c['detail']


def test_a_destination_where_nothing_answered_is_a_gap():
    res = build2(policy=policy(R('r1', OWN, '192.168.60.0/24', 'any', 'forbid')))
    c = item(res, 'access_policy')
    assert c['status'] == 'not_checked' and '192.168.60.0/24' in c['detail']


def test_ports_over_the_cap_are_a_gap():
    rules = policy(*[R(f'r{i}', OWN, BUH, f'tcp/{30000 + i}', 'forbid') for i in range(1, 23)])
    res = build2(policy=rules, extra={'ports': list(range(30001, 30021)), 'cut': [30021, 30022], 'error': None})
    c = item(res, 'access_policy')
    assert c['status'] == 'not_checked' and '30021' in c['detail'] and '30022' in c['detail']


def test_unreadable_rules_are_a_gap_not_no_rules():
    res = build2(policy={'revision': None, 'rules': [], 'error': 'database is locked'})
    c = item(res, 'access_policy')
    assert c['status'] == 'not_checked' and 'database is locked' in c['detail']


def test_the_result_keeps_what_it_was_judged_by():
    res = build2(policy=policy(FORBID_GUESTS, ALLOW_ADMIN, revision=4))
    p = res['policy']
    assert p['revision'] == 4 and p['source'] == ME and [r['id'] for r in p['rules']] == ['r1', 'r2']
    assert p['applicable'] == ['r1', 'r2']
    smb = next(x for x in p['paths'] if x['destination'] == '192.168.30.5' and x['port'] == 445)
    assert smb['decision'] == 'allow' and smb['rules'] == ['r2'] and smb['evidence'] == 'confirmed'
    assert smb['segment'] == BUH and smb['service'] == 'SMB'


def test_the_router_is_a_destination_too():
    res = build2(policy=policy(R('r1', OWN, VANTAGE['gateway'], 'tcp/8291', 'forbid')))
    assert subject_id('NET-POL-001', ME, VANTAGE['gateway'], 8291) in ids(res)


def test_this_machine_is_never_a_destination():
    res = build2(policy=policy(R('r1', OWN, ME, 'any', 'forbid')))
    assert not [i for i in ids(res) if i.startswith('NET-POL-001')]


# ---------------------------------------------------------------------------
# the check: rules read per client, extra ports probed
# ---------------------------------------------------------------------------

def _full_run(monkeypatch, tmp_path, client, extra_answer=''):
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
        if '--version-light' in cmd and '--script' in cmd:
            return 0, nmap_xml(GATEWAY_XML, BUH_PC, BUH_GW, host('192.168.88.20', port(22, 'ssh'))), ''
        if '--version-light' in cmd:
            return 0, nmap_xml(host('192.168.30.5', extra_answer)), ''
        return 0, nmap_xml(), ''
    monkeypatch.setattr(lan_audit, '_run', run)
    monkeypatch.setattr(lan_audit, '_listen', lambda seconds, **kw: HEARD_NOTHING)
    monkeypatch.setattr(lan_audit, '_tool', lambda name: True)
    monkeypatch.setattr(lan_audit, '_support', supported)
    monkeypatch.setattr(lan_audit, '_labels', lambda c: {})
    monkeypatch.setattr(lan, 'RESOLV_PATHS', (str(tmp_path / 'none'),))
    res = lan_audit.check_lan_audit(client=client, authorization=lan_audit.AUTH_CONFIRM, vuln_lookup='no')
    return res, seen


def test_the_check_reads_the_rules_of_its_client(isolated_db, monkeypatch, tmp_path):
    storage.lan_policy_save('Example Ltd', [FORBID_GUESTS])
    res, _seen = _full_run(monkeypatch, tmp_path, 'Example Ltd')
    assert pol(445) in ids(res) and res['policy']['revision'] == 1
    other, _ = _full_run(monkeypatch, tmp_path, 'Other')
    assert not [i for i in ids(other) if i.startswith('NET-POL')] and 'access_policy' in other['limits']


def test_extra_ports_are_probed_on_the_rule_destination_only(isolated_db, monkeypatch, tmp_path):
    storage.lan_policy_save('Example Ltd', [R('r1', OWN, '192.168.30.5', 'tcp/9999', 'forbid')])
    res, seen = _full_run(monkeypatch, tmp_path, 'Example Ltd', extra_answer=port(9999, 'abyss'))
    extra = [c for c in seen if '--version-light' in c and '--script' not in c]
    assert len(extra) == 1 and extra[0][extra[0].index('-p') + 1] == '9999' and extra[0][-1] == '192.168.30.5'
    assert 9999 in device(res, '192.168.30.5')['probe']['ports']
    assert pol(9999) in ids(res)


def test_no_extra_probe_without_extra_ports(isolated_db, monkeypatch, tmp_path):
    storage.lan_policy_save('Example Ltd', [FORBID_GUESTS])
    _res, seen = _full_run(monkeypatch, tmp_path, 'Example Ltd')
    assert not [c for c in seen if '--version-light' in c and '--script' not in c]


# ---------------------------------------------------------------------------
# P6: API and CLI
# ---------------------------------------------------------------------------

def _api():
    return TestClient(__import__('web.app', fromlist=['app']).app)


def test_policy_api_round_trip(isolated_db):
    api = _api()
    assert api.get('/api/lan/policy', params={'client': 'Example Ltd'}).json()['revision'] == 0
    r = api.put('/api/lan/policy', json={'client': 'Example Ltd', 'rules': [
        {'source': OWN, 'destination': BUH, 'service': 'any', 'decision': 'forbid'}]})
    assert r.status_code == 200 and r.json()['revision'] == 1
    got = api.get('/api/lan/policy', params={'client': 'Example Ltd'}).json()
    assert got['revision'] == 1 and got['rules'][0]['id'] == 'r1'


@pytest.mark.parametrize('body', [
    {'client': 'Example Ltd', 'rules': [{'source': '8.8.8.8', 'destination': BUH, 'service': 'any',
                                         'decision': 'forbid'}]},
    {'client': 'Example Ltd', 'rules': 'r1'},
    {'client': 5, 'rules': []},
    ['not', 'an', 'object'],
])
def test_policy_api_refuses_bad_input(isolated_db, body):
    r = _api().put('/api/lan/policy', json=body)
    assert r.status_code == 400
    assert storage.lan_policy_get('Example Ltd')['revision'] == 0


def test_policy_api_refuses_a_body_that_is_not_json(isolated_db):
    r = _api().put('/api/lan/policy', content=b'{', headers={'Content-Type': 'application/json'})
    assert r.status_code == 400


def _cli(action, client='Example Ltd', file=None, as_json=False):
    return Namespace(action=action, client=client, file=file, json=as_json)


def test_cli_shows_no_rules(isolated_db, capsys):
    netaudit.cmd_lan_policy(_cli('show'))
    assert 'no access rules' in capsys.readouterr().out.lower()


def test_cli_sets_and_shows_rules(isolated_db, capsys, tmp_path):
    path = tmp_path / 'rules.json'
    path.write_text(json.dumps([FORBID_GUESTS, ALLOW_ADMIN]), encoding='utf-8')
    netaudit.cmd_lan_policy(_cli('set', file=str(path)))
    out = capsys.readouterr().out
    assert 'revision 1' in out and 'r1' in out and 'r2' in out
    netaudit.cmd_lan_policy(_cli('show', as_json=True))
    shown = json.loads(capsys.readouterr().out)
    assert shown['revision'] == 1 and [r['id'] for r in shown['rules']] == ['r1', 'r2']


@pytest.mark.parametrize('content', ['{not json', json.dumps([{'source': '8.8.8.8', 'destination': BUH,
                                                                'service': 'any', 'decision': 'forbid'}])])
def test_cli_refuses_a_bad_file(isolated_db, capsys, tmp_path, content):
    path = tmp_path / 'rules.json'
    path.write_text(content, encoding='utf-8')
    with pytest.raises(SystemExit) as e:
        netaudit.cmd_lan_policy(_cli('set', file=str(path)))
    assert e.value.code == 2
    assert storage.lan_policy_get('Example Ltd')['revision'] == 0


def test_cli_parser_knows_lan_policy():
    args = netaudit.build_parser().parse_args(['lan-policy', 'set', '--client', 'Example Ltd', '--file', 'r.json'])
    assert (args.action, args.client, args.file) == ('set', 'Example Ltd', 'r.json')
    assert args.func is netaudit.cmd_lan_policy
