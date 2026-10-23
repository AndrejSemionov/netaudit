"""
A4.6 (docs/research/a4_6_job_baseline.md): a scheduled job (`--job`) compares
with its own last run, so a manual or Web run in between no longer cancels
the alert for what it found.
"""

from __future__ import annotations

from argparse import Namespace

import pytest

import netaudit
from netaudit_pkg import notify, storage
from netaudit_pkg.history import load_report, save_report

HIGH = {'severity': 'high', 'title': 'web: running with --privileged', 'detail': '',
        'confidence': 'high', 'id': 'DCK-PRIV-001:web'}


def _report(ts, by_host, job=None):
    """by_host: {host: findings} for docker_audit."""
    results, ctx = {}, {}
    if len(by_host) == 1:
        [(host, findings)] = by_host.items()
        results['docker_audit'] = {'host': host, 'findings': findings}
        ctx['docker_audit'] = {'host': host}
    else:
        results['docker_audit'] = {'_multi_host': True,
                                   'by_host': {h: {'host': h, 'findings': f} for h, f in by_host.items()}}
        ctx['docker_audit'] = {h: {'host': h} for h in by_host}
    report = {'timestamp': ts, 'results': results, 'timing': {}, 'meta': {}, 'execution_context': ctx,
              'total_time': 0}
    if job:
        report['job'] = job
    return report


def _save(report):
    return report, save_report(report)


def _changes(saved):
    report, rid = saved
    return notify.collect_changes(report, rid)


def _new_ids(changes):
    return [f['id'] for u in changes['units'] for f in u.get('new', [])]


def test_a_manual_run_in_between_no_longer_cancels_the_alert(isolated_db):
    _save(_report('2026-10-22 03:00:00', {'192.0.2.10': []}, job='nightly'))
    _save(_report('2026-10-22 15:00:00', {'192.0.2.10': [HIGH]}))              # manual
    changes = _changes(_save(_report('2026-10-23 03:00:00', {'192.0.2.10': [HIGH]}, job='nightly')))
    assert notify.decide(changes)
    assert _new_ids(changes) == ['DCK-PRIV-001:web']


def test_the_first_run_of_a_job_falls_back_to_any_earlier_run(isolated_db):
    _save(_report('2026-10-22 15:00:00', {'192.0.2.10': [HIGH]}))              # manual
    changes = _changes(_save(_report('2026-10-23 03:00:00', {'192.0.2.10': [HIGH]}, job='nightly')))
    assert not notify.decide(changes)
    assert not any(u.get('baseline') for u in changes['units'])


def test_a_host_the_job_never_saw_falls_back_to_any_earlier_run(isolated_db):
    _save(_report('2026-10-22 03:00:00', {'192.0.2.10': []}, job='nightly'))
    _save(_report('2026-10-22 15:00:00', {'192.0.2.11': [HIGH]}))              # manual, host B
    changes = _changes(_save(_report('2026-10-23 03:00:00',
                                     {'192.0.2.10': [], '192.0.2.11': [HIGH]}, job='nightly')))
    assert not notify.decide(changes)
    [b] = [u for u in changes['units'] if u['target'] == '192.0.2.11']
    assert not b.get('baseline') and b['new'] == []


def test_a_unit_the_job_saw_only_with_an_error_does_not_take_a_manual_run(isolated_db):
    errored = _report('2026-10-22 03:00:00', {'192.0.2.10': []}, job='nightly')
    errored['results']['docker_audit'] = {'host': '192.0.2.10', 'error': 'could not connect'}
    _save(errored)
    _save(_report('2026-10-22 15:00:00', {'192.0.2.10': [HIGH]}))              # manual, good
    changes = _changes(_save(_report('2026-10-23 03:00:00', {'192.0.2.10': [HIGH]}, job='nightly')))
    [unit] = changes['units']
    assert unit.get('baseline') is True


def test_a_notify_run_without_a_job_is_unchanged(isolated_db):
    _save(_report('2026-10-22 03:00:00', {'192.0.2.10': []}))
    _save(_report('2026-10-22 15:00:00', {'192.0.2.10': [HIGH]}))
    changes = _changes(_save(_report('2026-10-23 03:00:00', {'192.0.2.10': [HIGH]})))
    assert not notify.decide(changes)


# --- the CLI stores the job --------------------------------------------------

@pytest.fixture
def telegram(isolated_db, monkeypatch):
    storage.setting_set('telegram_token', '123456:FAKE')
    storage.setting_set('telegram_chat', '-100')
    monkeypatch.setattr(notify, 'send_telegram', lambda *a, **k: None)
    monkeypatch.setattr(netaudit, 'run_checks', lambda selected: _report('2026-10-23 03:00:00',
                                                                        {'192.0.2.10': []}))


def _run(rest, notify_flag):
    netaudit.cmd_run(Namespace(checks=['docker_audit'], ai=False, quick=False, rest=rest, notify=notify_flag))
    return load_report(storage.list_reports(limit=1)[0]['id'])


def test_cli_stores_the_job_of_a_scheduled_run(telegram):
    assert _run(['--host', '192.0.2.10', '--job', 'nightly'], True)['job'] == 'nightly'


@pytest.mark.parametrize('rest, notify_flag', [(['--host', '192.0.2.10'], True), (['--host', '192.0.2.10'], False)])
def test_cli_stores_no_job_without_one(telegram, rest, notify_flag):
    assert 'job' not in _run(rest, notify_flag)
