"""
Trend layer v1.2 (roadmap 2a) - docs/research/trend_layer_v1_2_web_ai.md:
server_audit is trended from its sections; findings that require manual
verification are counted per scope; an id that disappeared from a scope the
latest run could not fully evaluate is `not_evaluated`, never `resolved`.
"""

from __future__ import annotations

from netaudit_pkg.checks.server_security import audit_nginx, audit_ssh_hardening
from netaudit_pkg.trends import compute_trend, snapshots_from_report
from tests.conftest import FakeSSHExecutor


def _f(severity, fid=None, unverified=False):
    d = {'severity': severity, 'title': 't', 'detail': '', 'confidence': 'high'}
    if fid:
        d['id'] = fid
    if unverified:
        d['requires_manual_verification'] = True
    return d


def _report(ts, check_id, result, host='10.0.0.1'):
    return {'timestamp': ts, 'results': {check_id: result}, 'timing': {}, 'meta': {},
            'execution_context': {check_id: {'host': host}}, 'total_time': 0}


def _server_audit(**sections):
    return {'host': '10.0.0.1', 'summary': {}, 'sections': sections}


def _trend(*reports):
    snaps = []
    for r in reports:
        snaps.extend(snapshots_from_report(r))
    return compute_trend(snaps)


# --- server_audit sections -------------------------------------------------

def test_server_audit_snapshot_sums_sections_and_collects_ids():
    [snap] = snapshots_from_report(_report('t1', 'server_audit', _server_audit(
        nginx={'installed': True, 'findings': [_f('high', 'NGX-CONF-001')]},
        firewall={'findings': [_f('medium', 'FW-UFW-001'), _f('ok')]},
        ssh={'findings': [_f('low')]},
    )))
    assert snap['error'] is None
    assert snap['counts'] == {'critical': 0, 'high': 1, 'medium': 1, 'low': 1}
    assert snap['finding_ids'] == {'NGX-CONF-001': 'high', 'FW-UFW-001': 'medium'}
    assert snap['unverified'] == 0


def test_top_level_findings_win_over_sections():
    [snap] = snapshots_from_report(_report('t1', 'x_check', {
        'findings': [_f('high', 'A')],
        'sections': {'s': {'findings': [_f('low', 'B')]}},
    }))
    assert snap['finding_ids'] == {'A': 'high'}
    assert snap['counts']['low'] == 0


def test_unreadable_nginx_moves_its_ids_to_not_evaluated_not_resolved():
    trend = _trend(
        _report('t1', 'server_audit', _server_audit(
            nginx={'installed': True, 'findings': [_f('high', 'NGX-CONF-001')]},
            firewall={'findings': [_f('medium', 'FW-UFW-001')]})),
        _report('t2', 'server_audit', _server_audit(
            nginx={'installed': True, 'findings': [_f('low', unverified=True)]},
            firewall={'findings': []})),
    )
    ch = trend['latest_change']
    assert ch['not_evaluated'] == ['NGX-CONF-001']
    assert ch['resolved'] == ['FW-UFW-001']  # firewall was fully evaluated
    assert trend['points'][-1]['unverified'] == 1


def test_section_missing_from_latest_result_is_not_evaluated():
    trend = _trend(
        _report('t1', 'server_audit', _server_audit(
            sql={'installed': True, 'findings': [_f('high', 'SQL-NET-001')]})),
        _report('t2', 'server_audit', _server_audit(nginx={'installed': False})),
    )
    assert trend['latest_change']['not_evaluated'] == ['SQL-NET-001']
    assert trend['latest_change']['resolved'] == []


def test_uninstalled_section_is_evaluated_so_its_ids_resolve():
    trend = _trend(
        _report('t1', 'server_audit', _server_audit(
            nginx={'installed': True, 'findings': [_f('high', 'NGX-CONF-001')]})),
        _report('t2', 'server_audit', _server_audit(nginx={'installed': False})),
    )
    assert trend['latest_change']['resolved'] == ['NGX-CONF-001']
    assert trend['latest_change']['not_evaluated'] == []


# --- flat checks -------------------------------------------------------------

def test_flat_check_with_unverified_finding_moves_all_missing_ids_to_not_evaluated():
    trend = _trend(
        _report('t1', 'docker_audit', {'findings': [_f('high', 'A'), _f('medium', 'B'), _f('low', 'C')]}),
        _report('t2', 'docker_audit', {'findings': [_f('low', 'C'), _f('low', 'D', unverified=True)]}),
    )
    ch = trend['latest_change']
    assert ch['resolved'] == []
    assert ch['not_evaluated'] == ['A', 'B']
    assert ch['new'] == ['D']
    assert ch['persisting'] == ['C']


def test_check_without_unverified_findings_keeps_v1_1_values():
    trend = _trend(
        _report('t1', 'ssh_hardening', {'findings': [_f('high', 'A'), _f('high', 'B'), _f('medium', 'C')],
                                        'hardening': {'score': 60}}),
        _report('t2', 'ssh_hardening', {'findings': [_f('high', 'B'), _f('medium', 'C'), _f('low', 'D')],
                                        'hardening': {'score': 70}}),
    )
    ch = trend['latest_change']
    assert ch['counts_delta'] == {'critical': 0, 'high': -1, 'medium': 0, 'low': 1}
    assert ch['total_delta'] == 0
    assert ch['score_delta'] == 10
    assert (ch['new'], ch['resolved'], ch['persisting']) == (['D'], ['A'], ['B', 'C'])
    assert ch['not_evaluated'] == []
    assert set(ch) == {'from', 'to', 'counts_delta', 'total_delta', 'score_delta',
                       'new', 'resolved', 'persisting', 'not_evaluated'}


def test_points_carry_unverified_and_error_points_have_none():
    trend = _trend(
        _report('t1', 'docker_audit', {'findings': [_f('low', unverified=True), _f('low', unverified=True)]}),
        _report('t2', 'docker_audit', {'error': 'could not connect'}),
    )
    assert [p['unverified'] for p in trend['points']] == [2, None]
    assert set(trend['points'][0]) == {'timestamp', 'error', 'counts', 'total',
                                       'hardening_score', 'unverified'}


def test_instances_differing_only_in_unverified_are_ambiguous():
    report = {'timestamp': 't1', 'timing': {}, 'meta': {}, 'total_time': 0,
              'execution_context': {'docker_audit': {'h': {'host': 'x'}, 'h#2': {'host': 'x'}}},
              'results': {'docker_audit': {'_multi_host': True, 'by_host': {
                  'h': {'findings': [_f('low')]},
                  'h#2': {'findings': [_f('low', unverified=True)]}}}}}
    [snap] = snapshots_from_report(report)
    assert snap['error'].startswith('ambiguous: ')
    assert snap['unverified'] is None


# --- server_audit "could not read" findings ------------------------------------

def test_unreadable_nginx_config_finding_requires_manual_verification():
    ssh = FakeSSHExecutor(responses={
        'command -v nginx': ('/usr/sbin/nginx', ''),
        'nginx -v': ('nginx version: nginx/1.24.0', ''),
        'nginx -T': ('', ''),
    })
    [f] = audit_nginx(ssh)['findings']
    assert f['requires_manual_verification'] is True
    assert (f['severity'], 'id' in f) == ('low', False)


def test_unreadable_sshd_config_finding_requires_manual_verification():
    ssh = FakeSSHExecutor(responses={'cat /etc/ssh/sshd_config': ('', '')})
    [f] = audit_ssh_hardening(ssh)['findings']
    assert f['requires_manual_verification'] is True
    assert (f['severity'], f['title'], 'id' in f) == ('low', 'no access to sshd_config', False)
