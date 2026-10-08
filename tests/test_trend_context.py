"""
Roadmap 2b, part 2 - trends.trend_context() (docs/research/trend_layer_v1_2_web_ai.md,
2b.3): deterministic changes since the previous run of each object, for the AI
prompt. History is strictly before the analyzed run (storage.report_data_before),
the analyzed run is the `to` side, event-log units never appear.
"""

from __future__ import annotations

import json

from netaudit_pkg.trends import trend_context


def _f(severity, fid=None):
    d = {'severity': severity, 'title': 't'}
    if fid:
        d['id'] = fid
    return d


def _report(ts, findings=None, check='ssh_hardening', host='10.0.0.1', error=None, password=None):
    params = {'host': host}
    if password:
        params['password'] = password
    result = {'error': error} if error else {'findings': findings or []}
    return {'timestamp': ts, 'timing': {}, 'meta': {}, 'total_time': 0,
            'execution_context': {check: params}, 'results': {check: result}}


def test_change_from_previous_run_to_the_analyzed_one(isolated_db):
    isolated_db.save_report(_report('2026-05-01 00:00:00', [_f('high', 'A'), _f('high', 'B')]))
    r = _report('2026-05-02 00:00:00', [_f('high', 'B')], password='FAKE-CTX-PW')
    rid = isolated_db.save_report(r)
    [item] = trend_context(r, report_id=rid)
    assert set(item) == {'check_id', 'key', 'value', 'latest_change'}
    assert (item['check_id'], item['key'], item['value']) == ('ssh_hardening', 'host', '10.0.0.1')
    ch = item['latest_change']
    assert (ch['from'], ch['to']) == ('2026-05-01 00:00:00', '2026-05-02 00:00:00')
    assert ch['resolved'] == ['A'] and ch['persisting'] == ['B']
    assert 'FAKE-CTX-PW' not in json.dumps(item)


def test_older_run_is_compared_with_its_predecessor_not_a_later_run(isolated_db):
    isolated_db.save_report(_report('2026-05-01 00:00:00', [_f('high', 'A')]))
    b = isolated_db.save_report(_report('2026-05-02 00:00:00', [_f('high', 'B')]))
    isolated_db.save_report(_report('2026-05-03 00:00:00', [_f('high', 'C')]))
    [item] = trend_context(isolated_db.load_report(b), report_id=b)
    ch = item['latest_change']
    assert (ch['from'], ch['to']) == ('2026-05-01 00:00:00', '2026-05-02 00:00:00')
    assert (ch['new'], ch['resolved']) == (['B'], ['A'])


def test_inline_report_without_id_uses_earlier_runs(isolated_db):
    isolated_db.save_report(_report('2026-05-01 00:00:00', [_f('high', 'A')]))
    [item] = trend_context(_report('2026-05-09 00:00:00', []))
    assert item['latest_change']['resolved'] == ['A']


def test_errored_analyzed_run_first_run_and_event_units_are_left_out(isolated_db):
    isolated_db.save_report(_report('2026-05-01 00:00:00', [_f('high', 'A')]))
    assert trend_context(_report('2026-05-02 00:00:00', error='could not connect')) == []
    assert trend_context(_report('2026-05-02 00:00:00', host='never-seen')) == []
    isolated_db.save_report(_report('2026-05-01 00:00:00', [_f('high', 'A')], check='ssh_auth_audit'))
    assert trend_context(_report('2026-05-02 00:00:00', [], check='ssh_auth_audit')) == []


def test_caps_on_units_and_ids_with_omitted_counts(isolated_db):
    many = [_f('high', f'ID-{i}') for i in range(5)]
    isolated_db.save_report(_report('2026-05-01 00:00:00', many))
    isolated_db.save_report(_report('2026-05-01 00:00:00', many, host='10.0.0.2'))
    current = _report('2026-05-02 00:00:00', [])
    current['execution_context']['ssh_hardening'] = {'h1': {'host': '10.0.0.1'}, 'h2': {'host': '10.0.0.2'}}
    current['results']['ssh_hardening'] = {'_multi_host': True, 'by_host': {
        'h1': {'findings': []}, 'h2': {'findings': []}}}
    items = trend_context(current, max_units=1, max_ids=2)
    assert len(items) == 1
    ch = items[0]['latest_change']
    assert ch['resolved'] == ['ID-0', 'ID-1']
    assert ch['resolved_omitted'] == 3
    assert 'new_omitted' not in ch
