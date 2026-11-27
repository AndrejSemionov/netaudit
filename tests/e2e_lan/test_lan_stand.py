"""
Network audit on the CI stand (docs/research/network_audit.md §10, contract
N9): the ground truth for lan_audit. tests/e2e_lan/setup.sh builds one
segment with a fake MikroTik gateway, an old server, a host that answers ARP
only and a clean SSH host, and runs the audit there as an unprivileged user.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

DIR = os.environ.get('NETAUDIT_E2E_LAN_DIR')
pytestmark = pytest.mark.skipif(not DIR, reason='the network stand runs in CI (job e2e-lan)')

SCANNER, GW, LEGACY, QUIET, CLEAN = '172.30.10.10', '172.30.10.254', '172.30.10.20', '172.30.10.40', '172.30.10.50'
SEG_A, SEG_B, BUH = '172.30.10.0/24', '172.30.20.0/24', '172.30.20.20'


def _load(level: int) -> dict:
    return json.loads((Path(DIR) / f'level{level}.json').read_text())


@pytest.fixture(scope='module')
def one():
    return _load(1)


@pytest.fixture(scope='module')
def two():
    return _load(2)


def ids(result) -> set[str]:
    return {f['id'] for f in result['findings'] if 'id' in f}


def device(result, ip):
    return next((d for d in result['devices'] if d['ip'] == ip), None)


def test_ran_unprivileged_on_the_stand_segment(one):
    assert one['_euid'] != 0
    assert one['scanned'] == '172.30.10.0/24'
    assert (one['vantage']['address'], one['vantage']['gateway']) == (SCANNER, GW)
    assert one['verdict'] == 'danger'


def test_router_is_identified_from_its_banners(one):
    r = one['router']
    assert (r['ip'], r['vendor'], r['os'], r['version'], r['version_source']) == \
        (GW, 'MikroTik', 'RouterOS', '6.49.7', 'ftp banner')
    assert {'RTR-SVC-001:telnet', 'RTR-SVC-001:ftp', 'RTR-SVC-001:winbox', 'RTR-SVC-001:btest'} <= ids(one)
    assert device(one, GW)['kind'] == 'router' and device(one, GW)['mac']


def test_old_server_findings(one):
    assert {f'NET-SMB-001:{LEGACY}', f'NET-SMB-002:{LEGACY}', f'NET-TEL-001:{LEGACY}',
            f'NET-FTP-001:{LEGACY}', f'NET-DB-001:{LEGACY}:6379'} <= ids(one)
    # level 2 was not run
    assert not {i for i in ids(one) if i.startswith(('NET-FTP-002', 'NET-DB-002', 'NET-SMB-003'))}


def test_a_host_that_drops_every_probe_is_found_by_arp(one):
    """Research §3.3: a connect() makes the kernel ARP first; the answer is in
    the neighbour table even when every TCP probe is dropped."""
    d = device(one, QUIET)
    assert d is not None, 'the firewalled host was not found'
    assert d['answered'] == 'neighbour' and d['mac'] and d['ports'] == []


def test_clean_host_has_no_findings(one):
    d = device(one, CLEAN)
    assert d is not None and [p['port'] for p in d['ports']] == [22]
    assert not [f for f in one['findings'] if f.get('device') == CLEAN]


def test_the_scanner_itself_is_not_judged(one):
    assert device(one, SCANNER)['kind'] == 'this_machine'
    assert not [f for f in one['findings'] if f.get('device') == SCANNER]


def test_level2_finds_anonymous_access_and_no_false_ms17_010(two):
    assert {f'NET-FTP-002:{LEGACY}', f'NET-DB-002:{LEGACY}:6379'} <= ids(two)
    assert f'NET-SMB-003:{LEGACY}' not in ids(two)          # Samba is not affected by MS17-010
    assert 'level2' not in two['limits']


def _q(cidr):
    from urllib.parse import quote
    return quote(cidr, safe='')


def test_segment_b_is_found_through_the_router(one):
    """PR 2 (research §13): the probe through the gateway finds segment B, its
    sweep finds the accounting server, and its SMB answering from segment A
    is an isolation finding."""
    segments = {s['cidr']: s for s in one['segments']}
    assert segments[SEG_A]['own'] is True and SEG_B in segments
    assert BUH in segments[SEG_B]['devices']
    assert device(one, BUH)['segment'] == SEG_B and device(one, BUH)['mac'] is None   # behind the router: no MAC
    assert f'NET-SEG-001:{_q(SEG_A)}:{_q(SEG_B)}:445' in ids(one)
    assert 'NET-SEG-002' not in ids(one)
    item = next(c for c in one['checked'] if c['item'] == 'subnets')
    assert item['status'] == 'ok'
    assert 'traceroute' in one['limits'] and 'other_subnets' not in one['limits']


def test_the_device_rules_apply_in_segment_b_too(one):
    assert {f'NET-SMB-001:{BUH}', f'NET-DB-001:{BUH}:6379'} <= ids(one)

