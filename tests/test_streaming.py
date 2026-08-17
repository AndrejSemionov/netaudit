"""
Tests for netaudit_pkg.streaming.run_stream(): legacy single-host behavior
(regression - no dedicated test file existed for this module before) and the
new multi-host path added in Step 3B.

Multi-host is only wired up for regular (non-streaming) checks - mtr/ping/
tcptraceroute keep their single-host live-stream (Popen) path unchanged and
are explicitly out of scope here (see is_multi_host in run_stream()).
"""

from __future__ import annotations

import time
import queue

import pytest

from netaudit_pkg.streaming import StreamTask, run_stream
from netaudit_pkg.registry import registry, CheckSpec


@pytest.fixture
def temp_check():
    """Registers a throwaway check with a 'host' param and cleans it up."""
    registered_ids = []

    def _register(check_id, func, required_tools=None):
        registry.register(CheckSpec(
            id=check_id, label=f'Test {check_id}', category='test', func=func,
            required_tools=required_tools or [],
            params=[{'name': 'host', 'type': 'text', 'label': 'Host'}],
        ))
        registered_ids.append(check_id)
        return check_id

    yield _register

    for cid in registered_ids:
        registry._checks.pop(cid, None)


def _drain(task: StreamTask) -> list[dict]:
    """Collects every event a completed task has emitted, in order."""
    events = []
    while True:
        try:
            events.append(task.q.get_nowait())
        except queue.Empty:
            break
    return events


def _run_and_drain(selected: list[dict]) -> list[dict]:
    task = StreamTask('test-task', selected)
    run_stream(task)
    return _drain(task)


# ===========================================================================
# Legacy single-host behavior (regression - must stay exactly as before)
# ===========================================================================

def test_single_host_params_form_unchanged(temp_check, isolated_db):
    """A check with the old flat 'params' form (no 'instances' at all)
    behaves exactly as before Step 3B."""
    temp_check('__test_st_legacy__', lambda host='': {'seen': host})
    events = _run_and_drain([{'id': '__test_st_legacy__', 'params': {'host': 'a'}}])

    starts = [e for e in events if e['type'] == 'check_start']
    dones = [e for e in events if e['type'] == 'check_done']
    assert len(starts) == 1
    assert starts[0]['streaming'] is False
    assert 'multi_host' not in starts[0]
    assert len(dones) == 1
    assert dones[0]['result'] == {'seen': 'a'}
    assert 'host' not in dones[0]  # legacy check_done has no per-host key
    assert not any(e['type'] == 'check_group_done' for e in events)


def test_single_instance_in_instances_form_behaves_like_legacy(temp_check, isolated_db):
    """A check with exactly ONE entry in 'instances' also takes the legacy
    path (not the multi-host/run_instances path) - same as run_checks_multi()'s
    own single-instance rule."""
    temp_check('__test_st_one_inst__', lambda host='': {'seen': host})
    events = _run_and_drain([
        {'id': '__test_st_one_inst__', 'instances': [{'host': 'solo'}]},
    ])
    dones = [e for e in events if e['type'] == 'check_done']
    assert len(dones) == 1
    assert dones[0]['result'] == {'seen': 'solo'}
    assert not any(e['type'] == 'check_group_done' for e in events)


def test_unknown_check_id_reports_error(isolated_db):
    events = _run_and_drain([{'id': '__nonexistent_stream_check__', 'params': {}}])
    all_done = next(e for e in events if e['type'] == 'all_done')
    assert 'error' in all_done['report']['results']['__nonexistent_stream_check__']


def test_streaming_ids_never_take_multi_host_path_even_with_instances(isolated_db, monkeypatch):
    """mtr/ping/tcptraceroute must stay on the legacy path even if a caller
    somehow sends 'instances' with 2+ entries for them - confirms
    run_instances() is never invoked for STREAMING_IDS."""
    import netaudit_pkg.streaming as streaming_mod
    calls = []
    monkeypatch.setattr(streaming_mod, 'run_instances',
                         lambda *a, **k: calls.append(a) or ({}, {}))
    monkeypatch.setattr('shutil.which', lambda name: None)  # force "not installed" quickly

    events = _run_and_drain([
        {'id': 'ping', 'instances': [{'host': 'a'}, {'host': 'b'}]},
    ])
    assert calls == []  # run_instances never called for a STREAMING_IDS check
    starts = [e for e in events if e['type'] == 'check_start']
    assert starts[0]['streaming'] is True
    assert 'multi_host' not in starts[0]


# ===========================================================================
# New: multi-host path for regular (non-streaming) checks
# ===========================================================================

def test_multi_host_emits_check_done_per_host(temp_check, isolated_db):
    temp_check('__test_st_multi__', lambda host='': {'seen': host})
    events = _run_and_drain([
        {'id': '__test_st_multi__', 'instances': [
            {'host': '1.1.1.1'}, {'host': '2.2.2.2'},
        ]},
    ])
    dones = [e for e in events if e['type'] == 'check_done' and e['id'] == '__test_st_multi__']
    assert len(dones) == 2
    hosts_seen = {d['host'] for d in dones}
    assert hosts_seen == {'1.1.1.1', '2.2.2.2'}
    for d in dones:
        assert d['result'] == {'seen': d['host']}
        assert isinstance(d['elapsed'], float)


def test_multi_host_check_start_flags_multi_host(temp_check, isolated_db):
    temp_check('__test_st_start_flag__', lambda host='': {'ok': True})
    events = _run_and_drain([
        {'id': '__test_st_start_flag__', 'instances': [{'host': 'a'}, {'host': 'b'}]},
    ])
    start = next(e for e in events if e['type'] == 'check_start')
    assert start['multi_host'] is True
    assert start['streaming'] is False


def test_multi_host_emits_check_group_done_with_by_host_result(temp_check, isolated_db):
    temp_check('__test_st_group__', lambda host='': {'seen': host})
    events = _run_and_drain([
        {'id': '__test_st_group__', 'instances': [{'host': 'a'}, {'host': 'b'}]},
    ])
    group_done = next(e for e in events if e['type'] == 'check_group_done')
    assert group_done['result']['_multi_host'] is True
    assert group_done['result']['by_host'] == {'a': {'seen': 'a'}, 'b': {'seen': 'b'}}


def test_multi_host_final_report_has_by_host_shape(temp_check, isolated_db):
    temp_check('__test_st_report__', lambda host='': {'seen': host})
    events = _run_and_drain([
        {'id': '__test_st_report__', 'instances': [{'host': 'a'}, {'host': 'b'}]},
    ])
    all_done = next(e for e in events if e['type'] == 'all_done')
    result = all_done['report']['results']['__test_st_report__']
    assert result['_multi_host'] is True
    assert result['by_host'] == {'a': {'seen': 'a'}, 'b': {'seen': 'b'}}
    timing_entry = all_done['report']['timing']['__test_st_report__']
    assert set(timing_entry.keys()) == {'a', 'b'}


def test_multi_host_actually_runs_in_parallel(temp_check, isolated_db):
    def slow(host=''):
        time.sleep(0.3)
        return {'ok': True}

    temp_check('__test_st_parallel__', slow)
    start = time.monotonic()
    _run_and_drain([
        {'id': '__test_st_parallel__', 'instances': [{'host': 'a'}, {'host': 'b'}]},
    ])
    elapsed = time.monotonic() - start
    # sequential would be ~0.6s, parallel ~0.3s - generous margin for CI jitter
    assert elapsed < 0.5, f'expected ~0.3s parallel execution, took {elapsed:.2f}s'


def test_multi_host_one_failing_host_does_not_block_others(temp_check, isolated_db):
    def maybe_fail(host=''):
        if host == 'bad':
            raise ValueError('boom')
        return {'ok': True}

    temp_check('__test_st_partial__', maybe_fail)
    events = _run_and_drain([
        {'id': '__test_st_partial__', 'instances': [
            {'host': 'good1'}, {'host': 'bad'}, {'host': 'good2'},
        ]},
    ])
    dones = {e['host']: e['result'] for e in events
             if e['type'] == 'check_done' and e['id'] == '__test_st_partial__'}
    assert dones['good1'] == {'ok': True}
    assert dones['good2'] == {'ok': True}
    assert 'error' in dones['bad']

    group_done = next(e for e in events if e['type'] == 'check_group_done')
    assert 'error' in group_done['result']['by_host']['bad']
    assert group_done['result']['by_host']['good1'] == {'ok': True}


def test_multi_host_duplicate_hosts_get_suffixed_keys(temp_check, isolated_db):
    temp_check('__test_st_dup__', lambda host='': {'ok': True})
    events = _run_and_drain([
        {'id': '__test_st_dup__', 'instances': [{'host': 'x'}, {'host': 'x'}]},
    ])
    dones = [e for e in events if e['type'] == 'check_done' and e['id'] == '__test_st_dup__']
    assert {d['host'] for d in dones} == {'x', 'x#2'}


def test_multi_host_total_time_uses_max_not_sum(temp_check, isolated_db):
    def check_a(host='', sleep=0.0):
        time.sleep(sleep)
        return {'ok': True}

    temp_check('__test_st_total__', check_a)
    events = _run_and_drain([
        {'id': '__test_st_total__', 'instances': [
            {'host': 'x', 'sleep': 0.1}, {'host': 'y', 'sleep': 0.3},
        ]},
    ])
    all_done = next(e for e in events if e['type'] == 'all_done')
    # max(0.1, 0.3) ~= 0.3, vs the sequential-sum alternative 0.1+0.3=0.4 -
    # threshold sits with generous margin below that floor for CI jitter
    assert all_done['report']['total_time'] < 0.37


def test_multi_host_records_timing_via_run_instances(temp_check, isolated_db, monkeypatch):
    """timing.record() should be called exactly once per instance (through
    run_instances(), not double-recorded by run_stream() itself)."""
    recorded = []
    monkeypatch.setattr('netaudit_pkg.engine.timing.record',
                         lambda check_id, params, elapsed: recorded.append(params.get('host')))

    temp_check('__test_st_timing__', lambda host='': {'ok': True})
    _run_and_drain([
        {'id': '__test_st_timing__', 'instances': [{'host': 'a'}, {'host': 'b'}]},
    ])
    assert sorted(recorded) == ['a', 'b']
