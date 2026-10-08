"""
Tests for netaudit_pkg.trends - Trend Layer Contract v1.

Contract (frozen before these tests were written):
docs/research/trend_layer_research_summary.md, "Contract v1 - precise shapes".
Finding-level diff is by explicit `id` only; findings without `id` count
toward severity totals but never appear in new/resolved/persisting.
"""

from __future__ import annotations

from netaudit_pkg.trends import (
    PROBLEM_SEVERITIES,
    compute_trend,
    snapshots_from_report,
)


def _f(severity, fid=None, title='t'):
    d = {'severity': severity, 'title': title, 'detail': '', 'confidence': 'high'}
    if fid:
        d['id'] = fid
    return d


def _report(ts, results, ctx):
    return {'timestamp': ts, 'results': results, 'timing': {}, 'meta': {},
            'execution_context': ctx, 'total_time': 0}


def _snap(ts, counts=None, score=None, ids=None, error=None):
    """Hand-built snapshot for compute_trend() tests."""
    return {
        'check_id': 'ssh_hardening', 'key': 'host', 'value': '10.0.0.1',
        'timestamp': ts, 'error': error,
        'counts': None if error else {s: (counts or {}).get(s, 0) for s in PROBLEM_SEVERITIES},
        'hardening_score': score,
        'finding_ids': {} if error else (ids or {}),
    }


# ===========================================================================
# snapshots_from_report()
# ===========================================================================

def test_problem_severities_exclude_ok_and_info():
    assert PROBLEM_SEVERITIES == ('critical', 'high', 'medium', 'low')


def test_flat_context_single_snapshot_counts_and_ids():
    report = _report('2026-01-01 00:00:00', {
        'ssh_hardening': {
            'hardening': {'score': 72, 'max': 100, 'components': []},
            'findings': [_f('high', 'SSH-001'), _f('medium'), _f('ok', 'SSH-002'), _f('info')],
        },
    }, {'ssh_hardening': {'host': '10.0.0.1', 'port': 22}})

    snaps = snapshots_from_report(report)

    assert len(snaps) == 1
    s = snaps[0]
    assert (s['check_id'], s['key'], s['value']) == ('ssh_hardening', 'host', '10.0.0.1')
    assert s['timestamp'] == '2026-01-01 00:00:00'
    assert s['error'] is None
    assert s['counts'] == {'critical': 0, 'high': 1, 'medium': 1, 'low': 0}
    assert s['hardening_score'] == 72
    # ok-severity finding with an id is not a problem -> not tracked
    assert s['finding_ids'] == {'SSH-001': 'high'}


def test_multi_host_context_one_snapshot_per_host():
    report = _report('2026-01-01 00:00:00', {
        'ssh_hardening': {'_multi_host': True, 'by_host': {
            '10.0.0.1': {'findings': [_f('high', 'A')]},
            '10.0.0.2': {'findings': []},
        }},
    }, {'ssh_hardening': {
        '10.0.0.1': {'host': '10.0.0.1'},
        '10.0.0.2': {'host': '10.0.0.2'},
    }})

    snaps = {s['value']: s for s in snapshots_from_report(report)}

    assert set(snaps) == {'10.0.0.1', '10.0.0.2'}
    assert snaps['10.0.0.1']['counts']['high'] == 1
    assert snaps['10.0.0.2']['counts']['high'] == 0


# ---------------------------------------------------------------------------
# Contract v1.1: repeated unit within one report (REVIEW pass 1, defect 1).
# At most one snapshot per unit per report; identical instances collapse,
# differing instances become one non-comparable "ambiguous:" snapshot.
# ---------------------------------------------------------------------------

def _dup_report(first, second, ts='2026-01-01 00:00:00'):
    return _report(ts, {
        'ssh_hardening': {'_multi_host': True, 'by_host': {'h': first, 'h#2': second}},
    }, {'ssh_hardening': {'h': {'host': 'h'}, 'h#2': {'host': 'h'}}})


def _assert_ambiguous(snap, n=2):
    assert snap['error'] == f'ambiguous: {n} instances of this unit with different results in one report'
    assert snap['counts'] is None
    assert snap['hardening_score'] is None
    assert snap['finding_ids'] == {}


def test_repeated_unit_identical_instances_collapse_to_one_snapshot():
    snaps = snapshots_from_report(_dup_report({'findings': [_f('high', 'A')]},
                                              {'findings': [_f('high', 'A')]}))

    (s,) = snaps
    assert s['error'] is None
    assert s['counts']['high'] == 1
    assert s['finding_ids'] == {'A': 'high'}


def test_repeated_unit_empty_then_finding_is_ambiguous():
    (s,) = snapshots_from_report(_dup_report({'findings': []}, {'findings': [_f('high', 'A')]}))

    _assert_ambiguous(s)


def test_repeated_unit_finding_then_empty_is_ambiguous():
    (s,) = snapshots_from_report(_dup_report({'findings': [_f('high', 'A')]}, {'findings': []}))

    _assert_ambiguous(s)


def test_repeated_unit_error_and_success_is_ambiguous():
    (s,) = snapshots_from_report(_dup_report({'error': 'timeout'}, {'findings': [_f('high', 'A')]}))

    _assert_ambiguous(s)


def test_repeated_unit_identical_errors_collapse_to_one_error_snapshot():
    (s,) = snapshots_from_report(_dup_report({'error': 'timeout'}, {'error': 'timeout'}))

    assert s['error'] == 'timeout'


def test_repeated_unit_differing_score_only_is_ambiguous():
    (s,) = snapshots_from_report(_dup_report(
        {'findings': [], 'hardening': {'score': 60, 'max': 100, 'components': []}},
        {'findings': [], 'hardening': {'score': 80, 'max': 100, 'components': []}},
    ))

    _assert_ambiguous(s)


def test_repeated_unit_counts_all_instances_in_message():
    report = _report('2026-01-01 00:00:00', {
        'ssh_hardening': {'_multi_host': True, 'by_host': {
            'h': {'findings': []}, 'h#2': {'findings': []}, 'h#3': {'findings': [_f('low')]},
        }},
    }, {'ssh_hardening': {'h': {'host': 'h'}, 'h#2': {'host': 'h'}, 'h#3': {'host': 'h'}}})

    (s,) = snapshots_from_report(report)

    _assert_ambiguous(s, n=3)


def test_repeated_unit_does_not_affect_other_hosts_in_same_report():
    report = _report('2026-01-01 00:00:00', {
        'ssh_hardening': {'_multi_host': True, 'by_host': {
            'h': {'findings': []}, 'h#2': {'findings': [_f('low')]}, 'g': {'findings': [_f('high')]},
        }},
    }, {'ssh_hardening': {'h': {'host': 'h'}, 'h#2': {'host': 'h'}, 'g': {'host': 'g'}}})

    snaps = {s['value']: s for s in snapshots_from_report(report)}

    assert set(snaps) == {'h', 'g'}
    _assert_ambiguous(snaps['h'])
    assert snaps['g']['counts']['high'] == 1


def test_repeated_unit_never_compared_within_one_report():
    """The original defect: h/h#2 in one report gave latest_change with
    from == to and a false 'resolved'."""
    trend = compute_trend(snapshots_from_report(
        _dup_report({'findings': [_f('high', 'A')]}, {'findings': []})))

    assert len(trend['points']) == 1
    assert trend['latest_change'] is None


def test_ambiguous_point_is_skipped_by_latest_change_like_an_error():
    snaps = []
    snaps += snapshots_from_report(_dup_report({'findings': [_f('high', 'A')]},
                                               {'findings': [_f('high', 'A')]}, ts='t1'))
    snaps += snapshots_from_report(_dup_report({'findings': []}, {'findings': [_f('high', 'A')]}, ts='t2'))
    snaps += snapshots_from_report(_dup_report({'findings': []}, {'findings': []}, ts='t3'))

    trend = compute_trend(snaps)

    assert [p['timestamp'] for p in trend['points']] == ['t1', 't2', 't3']
    assert trend['points'][1]['error'].startswith('ambiguous:')
    assert trend['points'][1]['total'] is None
    ch = trend['latest_change']
    assert (ch['from'], ch['to']) == ('t1', 't3')
    assert ch['resolved'] == ['A']


def test_error_result_is_error_snapshot_not_zero_problems():
    report = _report('2026-01-01 00:00:00', {
        'ssh_hardening': {'error': 'connection refused'},
    }, {'ssh_hardening': {'host': '10.0.0.1'}})

    (s,) = snapshots_from_report(report)

    assert s['error'] == 'connection refused'
    assert s['counts'] is None
    assert s['hardening_score'] is None
    assert s['finding_ids'] == {}


def test_metric_only_result_is_not_trendable():
    """ping/mtr-style results have neither findings nor a hardening score."""
    report = _report('2026-01-01 00:00:00', {
        'ping': {'loss_pct': 0, 'avg_ms': 12.3},
    }, {'ping': {'target': '8.8.8.8', 'count': 3}})

    assert snapshots_from_report(report) == []


def test_no_identity_key_produces_no_snapshot():
    report = _report('2026-01-01 00:00:00', {
        'firewall': {'findings': [_f('high')]},
    }, {'firewall': {}})

    assert snapshots_from_report(report) == []


def test_several_identity_keys_one_snapshot_per_pair():
    report = _report('2026-01-01 00:00:00', {
        'x': {'findings': [_f('low')]},
    }, {'x': {'host': 'h1', 'domain': 'example.com'}})

    pairs = sorted((s['key'], s['value']) for s in snapshots_from_report(report))

    assert pairs == [('domain', 'example.com'), ('host', 'h1')]


def test_result_missing_for_context_entry_is_skipped():
    """Context says a check ran, but its result is absent (e.g. interrupted
    run) - nothing to snapshot, and no crash."""
    report = _report('2026-01-01 00:00:00', {}, {'ssh_hardening': {'host': '10.0.0.1'}})

    assert snapshots_from_report(report) == []


def test_report_without_execution_context_returns_empty():
    """Reports saved before execution_context existed."""
    report = {'timestamp': '2026-01-01 00:00:00',
              'results': {'ssh_hardening': {'findings': [_f('high')]}}}

    assert snapshots_from_report(report) == []


# ===========================================================================
# compute_trend()
# ===========================================================================

def test_compute_trend_points_in_given_order_with_totals():
    trend = compute_trend([
        _snap('t1', counts={'high': 2, 'low': 1}, score=60),
        _snap('t2', counts={'high': 1}, score=75),
    ])

    assert (trend['check_id'], trend['key'], trend['value']) == ('ssh_hardening', 'host', '10.0.0.1')
    assert [p['timestamp'] for p in trend['points']] == ['t1', 't2']
    assert [p['total'] for p in trend['points']] == [3, 1]
    assert [p['hardening_score'] for p in trend['points']] == [60, 75]
    # Contract v1.2 added 'unverified' (docs/research/trend_layer_v1_2_web_ai.md, 2a.2)
    assert set(trend['points'][0]) == {'timestamp', 'error', 'counts', 'total', 'hardening_score', 'unverified'}


def test_compute_trend_latest_change_deltas_and_id_diff():
    trend = compute_trend([
        _snap('t1', counts={'high': 2, 'medium': 1}, score=60,
              ids={'A': 'high', 'B': 'high', 'C': 'medium'}),
        _snap('t2', counts={'high': 1, 'medium': 1, 'low': 1}, score=70,
              ids={'B': 'high', 'C': 'medium', 'D': 'low'}),
    ])

    ch = trend['latest_change']
    assert (ch['from'], ch['to']) == ('t1', 't2')
    assert ch['counts_delta'] == {'critical': 0, 'high': -1, 'medium': 0, 'low': 1}
    assert ch['total_delta'] == 0
    assert ch['score_delta'] == 10
    assert ch['new'] == ['D']
    assert ch['resolved'] == ['A']
    assert ch['persisting'] == ['B', 'C']


def test_compute_trend_findings_without_id_only_affect_counts():
    """Contract v1: no title matching - a count change with no ids yields
    empty id lists, not guessed new/resolved entries."""
    trend = compute_trend([
        _snap('t1', counts={'high': 3}),
        _snap('t2', counts={'high': 1}),
    ])

    ch = trend['latest_change']
    assert ch['total_delta'] == -2
    assert ch['new'] == ch['resolved'] == ch['persisting'] == []


def test_compute_trend_latest_change_skips_error_snapshots():
    trend = compute_trend([
        _snap('t1', counts={'high': 2}, ids={'A': 'high'}),
        _snap('t2', counts={'high': 1}),
        _snap('t3', error='timeout'),
    ])

    assert len(trend['points']) == 3
    assert trend['points'][2]['error'] == 'timeout'
    assert trend['points'][2]['total'] is None
    ch = trend['latest_change']
    assert (ch['from'], ch['to']) == ('t1', 't2')
    assert ch['resolved'] == ['A']


def test_compute_trend_score_delta_none_when_either_side_has_no_score():
    trend = compute_trend([_snap('t1', score=None), _snap('t2', score=80)])

    assert trend['latest_change']['score_delta'] is None


def test_compute_trend_no_latest_change_with_fewer_than_two_good_snapshots():
    assert compute_trend([_snap('t1')])['latest_change'] is None
    assert compute_trend([_snap('t1'), _snap('t2', error='x')])['latest_change'] is None


# ===========================================================================
# trend_for() / list_units() - storage-backed
# ===========================================================================

from netaudit_pkg.trends import list_units, trend_for


def _ssh_report(ts, host, findings, score=None):
    result = {'findings': findings}
    if score is not None:
        result['hardening'] = {'score': score, 'max': 100, 'components': []}
    return _report(ts, {'ssh_hardening': result}, {'ssh_hardening': {'host': host}})


def test_trend_for_collects_unit_chronologically(isolated_db):
    isolated_db.save_report(_ssh_report('2026-01-02 00:00:00', '10.0.0.1', [], score=90))
    isolated_db.save_report(_ssh_report('2026-01-01 00:00:00', '10.0.0.1', [_f('high', 'A')], score=60))
    isolated_db.save_report(_ssh_report('2026-01-03 00:00:00', '10.0.0.9', [_f('high', 'Z')]))

    trend = trend_for('ssh_hardening', 'host', '10.0.0.1')

    assert [p['timestamp'] for p in trend['points']] == ['2026-01-01 00:00:00', '2026-01-02 00:00:00']
    assert trend['latest_change']['resolved'] == ['A']
    assert trend['latest_change']['score_delta'] == 30


def test_trend_for_unknown_unit_returns_none(isolated_db):
    isolated_db.save_report(_ssh_report('2026-01-01 00:00:00', '10.0.0.1', []))

    assert trend_for('ssh_hardening', 'host', '10.9.9.9') is None
    assert trend_for('nginx_hardening', 'host', '10.0.0.1') is None


def test_trend_for_respects_window(isolated_db):
    for day in range(1, 5):
        isolated_db.save_report(_ssh_report(f'2026-01-0{day} 00:00:00', '10.0.0.1', []))

    trend = trend_for('ssh_hardening', 'host', '10.0.0.1', window=2)

    assert [p['timestamp'] for p in trend['points']] == ['2026-01-03 00:00:00', '2026-01-04 00:00:00']


def test_trend_for_includes_multi_host_reports(isolated_db):
    isolated_db.save_report(_report('2026-01-01 00:00:00', {
        'ssh_hardening': {'_multi_host': True, 'by_host': {
            '10.0.0.1': {'findings': [_f('high', 'A')]},
            '10.0.0.2': {'findings': []},
        }},
    }, {'ssh_hardening': {'10.0.0.1': {'host': '10.0.0.1'}, '10.0.0.2': {'host': '10.0.0.2'}}}))
    isolated_db.save_report(_ssh_report('2026-01-02 00:00:00', '10.0.0.1', []))

    trend = trend_for('ssh_hardening', 'host', '10.0.0.1')

    assert len(trend['points']) == 2
    assert trend['latest_change']['resolved'] == ['A']


def test_list_units_runs_and_last_timestamp_most_recent_first(isolated_db):
    isolated_db.save_report(_ssh_report('2026-01-01 00:00:00', '10.0.0.1', []))
    isolated_db.save_report(_ssh_report('2026-01-02 00:00:00', '10.0.0.1', []))
    isolated_db.save_report(_ssh_report('2026-01-05 00:00:00', '10.0.0.2', []))
    isolated_db.save_report(_report('2026-01-06 00:00:00', {'ping': {'loss_pct': 0}},
                                    {'ping': {'target': '8.8.8.8'}}))

    units = list_units()

    assert units == [
        {'check_id': 'ssh_hardening', 'key': 'host', 'value': '10.0.0.2',
         'runs': 1, 'last_timestamp': '2026-01-05 00:00:00', 'kind': 'state'},
        {'check_id': 'ssh_hardening', 'key': 'host', 'value': '10.0.0.1',
         'runs': 2, 'last_timestamp': '2026-01-02 00:00:00', 'kind': 'state'},
    ]


def test_list_units_empty_db(isolated_db):
    assert list_units() == []


def test_trend_for_repeated_host_in_one_report_gives_no_false_change(isolated_db):
    isolated_db.save_report(_report('2026-01-01 00:00:00', {
        'ssh_hardening': {'_multi_host': True, 'by_host': {
            '10.0.0.1': {'findings': [_f('high', 'A')]},
            '10.0.0.1#2': {'findings': []},
        }},
    }, {'ssh_hardening': {'10.0.0.1': {'host': '10.0.0.1'}, '10.0.0.1#2': {'host': '10.0.0.1'}}}))

    trend = trend_for('ssh_hardening', 'host', '10.0.0.1')

    assert len(trend['points']) == 1
    assert trend['latest_change'] is None
    assert list_units()[0]['runs'] == 1
