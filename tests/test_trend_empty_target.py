"""
An empty target is not an object of trends or of the AI history
(docs/research/trend_empty_target.md): `netaudit trend` on a real database
listed `systemd_hardening host= 1 run`.
"""

from __future__ import annotations

import pytest

from netaudit_pkg import notify, storage, trends
from netaudit_pkg.history import save_report


def _report(ts, host, result=None):
    result = result or {'error': 'host not specified'}
    return {'timestamp': ts, 'results': {'systemd_hardening': result}, 'timing': {}, 'meta': {},
            'execution_context': {'systemd_hardening': {'host': host}}, 'total_time': 0}


OK = {'host': '10.0.0.5', 'findings': [], 'units': []}


@pytest.mark.parametrize('host', ['', '  ', None])
def test_a_run_without_a_target_makes_no_snapshot(host):
    assert trends.snapshots_from_report(_report('2026-10-09 15:03:33', host)) == []


def test_a_run_with_a_target_still_makes_one():
    assert len(trends.snapshots_from_report(_report('2026-10-09 15:03:33', '10.0.0.5', OK))) == 1


def test_the_trend_list_leaves_out_the_empty_target(isolated_db):
    save_report(_report('2026-10-09 15:03:33', ''))
    save_report(_report('2026-10-09 15:04:00', '10.0.0.5', OK))
    assert [(u['check_id'], u['value']) for u in trends.list_units()] == [('systemd_hardening', '10.0.0.5')]


def test_an_empty_target_is_not_an_identity_pair():
    assert storage.identity_pairs({'systemd_hardening': {'host': ''}}) == set()
    assert storage.identity_pairs({'dns_audit': {'domain': ' '}, 'ssl': {'url': 'https://h.example'}}) \
        == {('url', 'https://h.example')}


def test_two_runs_without_a_target_are_not_each_others_history(isolated_db):
    save_report(_report('2026-10-09 15:03:33', ''))
    later = _report('2026-10-10 15:03:33', '')
    rid = save_report(later)
    assert storage.find_related_reports(later, report_id=rid) == []


def test_notify_still_reports_the_failed_run(isolated_db):
    report = _report('2026-10-09 15:03:33', '')
    rid = save_report(report)
    changes = notify.collect_changes(report, rid)
    assert [p['status'] for p in changes['problems']] == ['error']
    assert changes['units'] == []
