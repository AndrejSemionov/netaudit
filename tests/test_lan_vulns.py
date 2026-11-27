"""
Network audit PR 3 (docs/research/network_audit.md §14, contract N7): known
vulnerabilities by version - NVD by CPE as "possible", OSV for Debian
package revisions, CISA KEV marks, the router's RouterOS version. No network:
every HTTP call is a fake; caches go to a temporary database.
"""

from __future__ import annotations

import json

import pytest

from netaudit_pkg import lan, lan_vulns
from netaudit_pkg.checks import lan_audit
from tests.test_lan_audit import (
    GATEWAY,
    HEARD_NOTHING,
    build,
    fake_ip,
    host,
    nmap_xml,
    port,
    supported,
)

SSH_DEBIAN = {'port': 22, 'service': 'ssh', 'product': 'OpenSSH', 'version': '9.2p1 Debian 2+deb12u3',
              'method': 'probed', 'cpe': ['cpe:/a:openbsd:openssh:9.2p1', 'cpe:/o:linux:linux_kernel'],
              'tunnel': '', 'devicetype': '', 'extrainfo': '', 'conf': 10, 'scripts': {}}
SSH_UBUNTU = {**SSH_DEBIAN, 'version': '8.9p1 Ubuntu 3ubuntu0.6', 'cpe': ['cpe:/a:openbsd:openssh:8.9p1']}
CUPS = {**SSH_DEBIAN, 'port': 631, 'service': 'ipp', 'product': 'CUPS', 'version': '2.4', 'cpe': ['cpe:/a:apple:cups:2.4']}
NOVER = {**SSH_DEBIAN, 'port': 80, 'service': 'http', 'product': 'nginx', 'version': '', 'cpe': ['cpe:/a:igor_sysoev:nginx']}


# ---------------------------------------------------------------------------
# where a version comes from
# ---------------------------------------------------------------------------

def test_a_debian_banner_goes_to_osv_for_that_release():
    assert lan_vulns.version_source(SSH_DEBIAN) == {'kind': 'osv', 'ecosystem': 'Debian:12', 'package': 'openssh',
                                                   'version': '1:9.2p1-2+deb12u3'}


def test_an_ubuntu_banner_is_named_not_looked_up():
    src = lan_vulns.version_source(SSH_UBUNTU)
    assert src['kind'] == 'skip' and 'Ubuntu' in src['reason']


def test_a_cpe_with_a_version_goes_to_nvd():
    assert lan_vulns.version_source(CUPS) == {'kind': 'nvd', 'cpe': 'cpe:2.3:a:apple:cups:2.4:*:*:*:*:*:*:*'}
    assert lan_vulns.version_source(NOVER) is None


@pytest.mark.parametrize('uri', ['cpe:/a:apple:cups', 'cpe:/a:apple:cups:2.4&x=1', 'not a cpe', 'cpe:/a:a b:c:1'])
def test_a_cpe_without_a_clean_version_is_not_used(uri):
    assert lan_vulns.cpe23(uri) is None


# ---------------------------------------------------------------------------
# the sources
# ---------------------------------------------------------------------------

NVD_ANSWER = {'totalResults': 2, 'vulnerabilities': [
    {'cve': {'id': 'CVE-2024-47176', 'metrics': {'cvssMetricV31': [{'cvssData': {'baseScore': 8.3,
                                                                                  'baseSeverity': 'HIGH'}}]},
             'descriptions': [{'lang': 'en', 'value': 'cups-browsed binds on UDP 631'}]}},
    {'cve': {'id': 'CVE-2023-4504', 'metrics': {'cvssMetricV31': [{'cvssData': {'baseScore': 7.8,
                                                                                 'baseSeverity': 'HIGH'}}]},
             'descriptions': [{'lang': 'en', 'value': 'heap overflow'}]}}]}


def test_nvd_answer_is_read_and_cached(isolated_db, monkeypatch):
    calls = []

    def get(url, params):
        calls.append(params)
        return 200, NVD_ANSWER
    monkeypatch.setattr(lan_vulns, '_get', get)
    cves, error = lan_vulns.nvd_cves('cpe:2.3:a:apple:cups:2.4:*:*:*:*:*:*:*')
    assert error is None and [c['id'] for c in cves] == ['CVE-2024-47176', 'CVE-2023-4504']
    assert cves[0] == {'id': 'CVE-2024-47176', 'score': 8.3, 'severity': 'high',
                       'summary': 'cups-browsed binds on UDP 631'}
    assert calls[0]['virtualMatchString'] == 'cpe:2.3:a:apple:cups:2.4:*:*:*:*:*:*:*'
    again, _ = lan_vulns.nvd_cves('cpe:2.3:a:apple:cups:2.4:*:*:*:*:*:*:*')
    assert again == cves and len(calls) == 1


@pytest.mark.parametrize('answer', [(403, {'message': 'rate limit'}), (200, None), (200, {'vulnerabilities': 'x'})])
def test_nvd_failure_is_an_error_not_no_vulnerabilities(isolated_db, monkeypatch, answer):
    monkeypatch.setattr(lan_vulns, '_get', lambda url, params: answer)
    cves, error = lan_vulns.nvd_cves('cpe:2.3:a:apple:cups:2.4:*:*:*:*:*:*:*')
    assert cves is None and error


def test_kev_is_downloaded_once_a_day_and_a_failure_keeps_the_old_copy(isolated_db, monkeypatch):
    calls = []
    catalog = {'catalogVersion': '2026.11.27', 'vulnerabilities': [
        {'cveID': 'CVE-2024-47176', 'dateAdded': '2024-10-01', 'knownRansomwareCampaignUse': 'Unknown'}]}

    def get(url, params):
        calls.append(url)
        return 200, catalog
    monkeypatch.setattr(lan_vulns, '_get', get)
    kev, error = lan_vulns.kev()
    assert error is None and kev == {'CVE-2024-47176': {'added': '2024-10-01', 'ransomware': False}}
    lan_vulns.kev()
    assert len(calls) == 1
    monkeypatch.setattr(lan_vulns, 'KEV_MAX_AGE_HOURS', -1)          # stale: try again, and fail
    monkeypatch.setattr(lan_vulns, '_get', lambda url, params: (503, None))
    kev2, error2 = lan_vulns.kev()
    assert kev2 == kev and error2 and 'previous' in error2


OSV_ANSWER = {'vulns': [
    {'id': 'DEBIAN-CVE-2023-51385', 'aliases': ['CVE-2023-51385'], 'affected': [
        {'package': {'ecosystem': 'Debian:12', 'name': 'openssh'},
         'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '1:9.2p1-2+deb12u2'}]}]}]},
    {'id': 'DEBIAN-CVE-2007-2243', 'affected': [
        {'package': {'ecosystem': 'Debian:12', 'name': 'openssh'},
         'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}]}]}]}]}


def test_osv_debian_counts_what_a_newer_revision_fixes(isolated_db, monkeypatch):
    sent = []
    monkeypatch.setattr(lan_vulns, '_post', lambda url, body: sent.append(body) or (200, OSV_ANSWER))
    out, error = lan_vulns.osv_debian('Debian:12', 'openssh', '1:9.2p1-2+deb12u3')
    assert error is None
    assert out == {'fixed': ['CVE-2023-51385'], 'open': 1}
    assert sent[0] == {'package': {'ecosystem': 'Debian:12', 'name': 'openssh'}, 'version': '1:9.2p1-2+deb12u3'}


def test_lookup_paces_nvd_and_caps_it(isolated_db, monkeypatch):
    slept = []
    monkeypatch.setattr(lan_vulns, '_sleep', slept.append)
    monkeypatch.setattr(lan_vulns, '_get', lambda url, params: (200, {'vulnerabilities': [], 'catalogVersion': 'x'}))
    monkeypatch.setattr(lan_vulns, 'MAX_CPES', 2)
    services = [{'ip': f'192.168.88.{i}', 'port': 631, 'kind': 'nvd',
                 'cpe': f'cpe:2.3:a:apple:cups:2.{i}:*:*:*:*:*:*:*'} for i in range(1, 5)]
    out = lan_vulns.lookup(services, router_version=None)
    assert [s['ip'] for s in out['services'] if s['error'] is None] == ['192.168.88.1', '192.168.88.2']
    assert out['cut'] == ['192.168.88.3:631', '192.168.88.4:631']
    assert slept == [lan_vulns.NVD_PAUSE]          # one pause between the two NVD requests


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------

def _vulns_fake(result):
    def run(services, router_version):
        run.asked = (services, router_version)
        return result
    return run


def _ports_with(*extra):
    return lan.parse_nmap_xml(nmap_xml(GATEWAY, *extra))


CUPS_HOST = host('192.168.88.31', port(631, 'ipp', product='CUPS', version='2.4', cpe='cpe:/a:apple:cups:2.4')
                 + port(9100, 'jetdirect'))
SSH_HOST = host('192.168.88.40', port(22, 'ssh', product='OpenSSH', version='9.2p1 Debian 2+deb12u3',
                                      cpe='cpe:/a:openbsd:openssh:9.2p1'))
LOOKED_UP = {
    'services': [
        {'ip': '192.168.88.31', 'port': 631, 'kind': 'nvd', 'cpe': 'cpe:2.3:a:apple:cups:2.4:*:*:*:*:*:*:*',
         'cves': [{'id': 'CVE-2024-47176', 'score': 8.3, 'severity': 'high', 'summary': 's'},
                  {'id': 'CVE-2023-4504', 'score': 7.8, 'severity': 'high', 'summary': 's'},
                  {'id': 'CVE-2022-0001', 'score': 4.0, 'severity': 'medium', 'summary': 's'}], 'error': None},
        {'ip': '192.168.88.40', 'port': 22, 'kind': 'osv', 'ecosystem': 'Debian:12', 'package': 'openssh',
         'version': '1:9.2p1-2+deb12u3', 'fixed': ['CVE-2023-51385'], 'open': 1, 'error': None}],
    'router': {'version': '6.49.7', 'cves': [{'id': 'CVE-2023-30799', 'score': 9.1, 'severity': 'critical',
                                              'summary': 'admin to super-admin'}], 'error': None},
    'kev': {'CVE-2024-47176': {'added': '2024-10-01', 'ransomware': False},
            'CVE-2023-30799': {'added': '2023-07-01', 'ransomware': True}},
    'kev_error': None, 'cut': [], 'skipped': [],
}


def test_services_and_the_router_version_are_asked():
    fake = _vulns_fake(LOOKED_UP)
    build(ports=_ports_with(CUPS_HOST, SSH_HOST), vulns=fake)
    services, router_version = fake.asked
    asked = {(s['ip'], s['port'], s['kind']) for s in services}
    assert {('192.168.88.31', 631, 'nvd'), ('192.168.88.40', 22, 'osv')} <= asked
    assert not [s for s in services if s['ip'] == '192.168.88.1']       # the router's services are not devices
    assert router_version == '6.49.7'


def test_findings_from_the_lookups():
    res = build(ports=_ports_with(CUPS_HOST, SSH_HOST), vulns=_vulns_fake(LOOKED_UP))
    by_id = {f['id']: f for f in res['findings'] if 'id' in f}
    kev = by_id['NET-VULN-001:192.168.88.31:631:CVE-2024-47176']
    assert kev['severity'] == 'high' and kev['confidence'] == 'low' and kev['requires_manual_verification']
    assert 'CISA' in kev['detail']
    assert by_id['NET-VULN-001:192.168.88.31:631:CVE-2022-0001']['severity'] == 'medium'
    deb = by_id['NET-VULN-002:192.168.88.40:22']
    assert deb['severity'] == 'medium' and 'CVE-2023-51385' in deb['detail'] and 'Debian:12' in deb['detail']
    rtr = by_id['RTR-VULN-001:CVE-2023-30799']
    assert rtr['severity'] == 'critical' and 'ransomware' in rtr['detail']
    assert 'known_vulns' not in res['limits']
    item = next(c for c in res['checked'] if c['item'] == 'known_vulns')
    # the audit counts the services nmap read no version of (here 9100 on the printer)
    assert item['status'] == 'ok' and '1 services without a version' in item['detail']
    assert any('NVD' in n['notice'] for n in res['notices'])


def test_at_most_ten_nvd_findings_per_service():
    many = {**LOOKED_UP, 'services': [{**LOOKED_UP['services'][0], 'cves': [
        {'id': f'CVE-2020-{1000 + i}', 'score': 5.0 + i / 10, 'severity': 'medium', 'summary': ''} for i in range(14)]}]}
    res = build(ports=_ports_with(CUPS_HOST), vulns=_vulns_fake(many))
    vuln = [f for f in res['findings'] if f.get('id', '').startswith('NET-VULN-001:192.168.88.31')]
    assert len(vuln) == 10 and 'CVE-2020-1013' in {f['id'].rsplit(':', 1)[1] for f in vuln}   # the highest scores
    assert '4' in next(c for c in res['checked'] if c['item'] == 'known_vulns')['detail']


def test_failed_lookups_and_cut_services_are_gaps():
    failed = {**LOOKED_UP, 'services': [{**LOOKED_UP['services'][0], 'cves': None, 'error': 'NVD: HTTP 403'}],
              'cut': ['192.168.88.50:443'], 'kev_error': 'KEV: HTTP 503, no previous copy'}
    res = build(ports=_ports_with(CUPS_HOST), vulns=_vulns_fake(failed))
    item = next(c for c in res['checked'] if c['item'] == 'known_vulns')
    assert item['status'] == 'not_checked'
    for part in ('403', '192.168.88.50:443', 'KEV'):
        assert part in item['detail']
    assert not [f for f in res['findings'] if f.get('id', '').startswith('NET-VULN-001')]


def test_without_lookups_known_vulnerabilities_stay_a_limit():
    res = build()
    assert 'known_vulns' in res['limits']
    assert not [c for c in res['checked'] if c['item'] == 'known_vulns']


def test_the_check_can_turn_the_lookups_off(monkeypatch, tmp_path):
    ip = fake_ip()
    asked = []

    def run(cmd, timeout=30):
        if cmd[0] == 'ip':
            return ip(cmd, timeout)
        if '--version-light' in cmd:
            return 0, nmap_xml(GATEWAY, CUPS_HOST), ''
        return 0, nmap_xml(host('192.168.88.1'), host('192.168.88.31')), ''
    monkeypatch.setattr(lan_audit, '_run', run)
    monkeypatch.setattr(lan_audit, '_listen', lambda seconds, **kw: HEARD_NOTHING)
    monkeypatch.setattr(lan_audit, '_tool', lambda name: True)
    monkeypatch.setattr(lan_audit, '_support', supported)
    monkeypatch.setattr(lan_audit, '_labels', lambda client: {})
    monkeypatch.setattr(lan_audit, '_vulns', lambda services, router_version: asked.append(1) or LOOKED_UP)
    monkeypatch.setattr(lan, 'RESOLV_PATHS', (str(tmp_path / 'none'),))
    off = lan_audit.check_lan_audit(authorization=lan_audit.AUTH_CONFIRM, vuln_lookup='no')
    assert asked == [] and 'known_vulns' in off['limits']
    on = lan_audit.check_lan_audit(authorization=lan_audit.AUTH_CONFIRM)
    assert asked == [1] and 'known_vulns' not in on['limits']


def test_the_param_is_registered_with_lookups_on_by_default():
    from netaudit_pkg.registry import registry
    params = {p['name']: p for p in registry.get('lan_audit').params}
    assert params['vuln_lookup']['options'] == ['yes', 'no'] and params['vuln_lookup']['default'] == 'yes'


def test_what_leaves_the_network_is_products_and_versions_only(isolated_db, monkeypatch):
    sent = []
    monkeypatch.setattr(lan_vulns, '_get', lambda url, params: sent.append((url, params)) or (200, {'vulnerabilities': []}))
    monkeypatch.setattr(lan_vulns, '_post', lambda url, body: sent.append((url, body)) or (200, {'vulns': []}))
    monkeypatch.setattr(lan_vulns, '_sleep', lambda s: None)
    lan_vulns.lookup([{'ip': '192.168.88.31', 'port': 631, 'kind': 'nvd',
                       'cpe': 'cpe:2.3:a:apple:cups:2.4:*:*:*:*:*:*:*'},
                      {'ip': '192.168.88.40', 'port': 22, 'kind': 'osv', 'ecosystem': 'Debian:12',
                       'package': 'openssh', 'version': '1:9.2p1-2+deb12u3'}], router_version='6.49.7')
    assert sent and '192.168.88' not in json.dumps(sent)
