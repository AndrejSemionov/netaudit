"""Contract 2d: bounded log slices are observations, not state changes."""

from argparse import Namespace

import netaudit
from netaudit_pkg import trends


def _report(check_id, result, ts='2026-01-01 00:00:00', **params):
    return {
        'timestamp': ts,
        'results': {check_id: result},
        'execution_context': {check_id: {'host': 's', **params}},
    }


def _point(check_id, result, **params):
    snapshots = trends.snapshots_from_report(_report(check_id, result, **params))
    return trends.compute_trend(snapshots)['points'][0] if snapshots else None


def _finding(severity='high', fid=None):
    item = {'severity': severity, 'title': 'observed signal'}
    if fid:
        item['id'] = fid
    return item


def test_ssh_two_slices_never_claim_resolved_and_keep_source_metadata():
    check = 'ssh_auth_audit'
    first = trends.snapshots_from_report(_report(check, {
        'findings': [_finding(fid='EVENT-1')],
        'meta': {'selected_source': 'file', 'events_parsed': 4, 'coverage_uncertain': True},
    }, lines=100, window_hours=24))[0]
    second = trends.snapshots_from_report(_report(check, {
        'findings': [],
        'meta': {'selected_source': 'journal', 'events_parsed': 0, 'coverage_uncertain': False},
    }, ts='2026-01-02 00:00:00', lines=200, window_hours=12))[0]

    trend = trends.compute_trend([first, second])

    assert trend['kind'] == 'event_observation'
    assert trend['latest_change'] is None
    assert [p['total'] for p in trend['points']] == [1, 0]
    assert trend['points'][0]['observation']['source'] == 'file'
    assert trend['points'][0]['observation']['tail_limit_reached'] is True
    assert trend['points'][0]['observation']['requested_lines'] == 100
    assert trend['points'][1]['observation']['window_hours'] == 12


def test_single_source_failure_is_unknown_not_zero_and_old_metadata_is_visible():
    for check in ('fail2ban_logs_audit', 'kern_log_audit'):
        failed = _point(check, {'findings': [], 'meta': {'coverage': 'failed'}})
        unknown = _point(check, {'findings': [], 'meta': {'coverage': 'unknown'}})
        old = _point(check, {'findings': [_finding()], 'meta': {}})
        partial = _point(check, {'findings': [_finding()],
                                 'meta': {'coverage': 'partial', 'events_parsed': 2, 'events_total': 4}})
        empty = _point(check, {'findings': [], 'meta': {'coverage': 'empty'}})

        assert failed['counts'] is None and failed['total'] is None
        assert unknown['counts'] is None and unknown['total'] is None
        assert old['total'] == 1 and old['observation']['label'] == 'coverage unknown'
        assert partial['total'] == 1 and partial['observation']['label'] == 'partial, lower bound'
        assert partial['observation']['events_parsed'] == 2
        assert empty['total'] == 0 and empty['observation']['label'] == 'empty log'


def test_nginx_coverage_keeps_both_contours_and_failure_is_unknown():
    partial = _point('nginx_logs_audit', {
        'installed': True, 'findings': [_finding()],
        'meta': {'access': {'coverage': 'complete', 'events_total': 5},
                 'error': {'coverage': 'failed', 'events_total': 0}},
    }, lines=50)
    failed = _point('nginx_logs_audit', {
        'installed': True, 'findings': [],
        'meta': {'access': {'coverage': 'failed'}, 'error': {'coverage': 'unknown'}},
    })
    not_installed = _point('nginx_logs_audit', {'installed': False})
    errored = _point('nginx_logs_audit', {'installed': True, 'error': 'config unreadable'})

    assert partial['total'] == 1
    assert partial['observation']['access_coverage'] == 'complete'
    assert partial['observation']['error_coverage'] == 'failed'
    assert partial['observation']['label'] == 'partial, lower bound'
    assert partial['observation']['events_total'] == 5
    assert failed['counts'] is None and failed['total'] is None
    assert not_installed is None
    assert errored['error'] == 'config unreadable' and errored['counts'] is None


def test_ssh_no_source_never_reports_zero_and_old_report_keeps_observed_finding():
    no_source = _point('ssh_auth_audit', {'findings': [], 'meta': {'selected_source': 'none'}})
    old = _point('ssh_auth_audit', {'findings': [_finding()], 'meta': {}})

    assert no_source['counts'] is None
    assert old['total'] == 1 and old['observation']['label'] == 'coverage unknown'


def test_state_check_retains_latest_change_and_kind():
    first = trends.snapshots_from_report(_report('ssh_hardening', {'findings': [_finding(fid='A')]}))[0]
    second = trends.snapshots_from_report(_report('ssh_hardening', {'findings': []},
                                                 ts='2026-01-02 00:00:00'))[0]
    trend = trends.compute_trend([first, second])

    assert trend['kind'] == 'state'
    assert trend['latest_change']['resolved'] == ['A']
    assert trend['latest_change']['not_evaluated'] == []


def test_list_units_and_cli_label_log_observations(isolated_db, capsys):
    for ts, findings in [('2026-01-01 00:00:00', [_finding()]),
                         ('2026-01-02 00:00:00', [])]:
        isolated_db.save_report(_report('ssh_auth_audit', {
            'findings': findings, 'meta': {'selected_source': 'file', 'events_parsed': 1},
        }, ts=ts))

    [unit] = trends.list_units()
    assert unit['kind'] == 'event_observation'
    assert unit['runs'] == 2

    netaudit.cmd_trend(Namespace(check_id='ssh_auth_audit', value='s', key='host', json=False))
    output = capsys.readouterr().out.lower()
    assert 'log observations' in output
    assert 'resolved' not in output
    assert 'improved' not in output
    assert 'latest change' not in output
