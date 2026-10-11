"""B2.1 contract: bounded execution and validation before side effects."""

from __future__ import annotations

import threading
import time

import pytest

from netaudit_pkg import engine, timing
from netaudit_pkg.registry import CheckSpec, registry


@pytest.fixture
def slow_check():
    lock = threading.Lock()
    state = {'active': 0, 'peak': 0, 'called': []}

    def check(host=''):
        with lock:
            state['active'] += 1
            state['peak'] = max(state['peak'], state['active'])
            state['called'].append(host)
        time.sleep(0.02)
        with lock:
            state['active'] -= 1
        return {'host': host}

    cid = '__b2_slow__'
    registry.register(CheckSpec(id=cid, label=cid, category='test', func=check,
                                required_tools=[], params=[], risk_level='READ_ONLY'))
    yield cid, registry.get(cid), state
    registry._checks.pop(cid, None)


@pytest.mark.parametrize(('limit', 'expected'), [(None, 4), (2, 2), (16, 16)])
def test_run_instances_bounded(slow_check, isolated_db, limit, expected):
    cid, spec, state = slow_check
    instances = [{'host': str(i)} for i in range(20)]
    kw = {} if limit is None else {'max_parallel': limit}
    results, _timing = engine.run_instances(cid, spec, instances, **kw)
    assert state['peak'] == expected
    assert list(results) == [str(i) for i in range(20)]


def test_run_checks_multi_rejects_limits_before_first_check(slow_check, isolated_db):
    cid, _spec, state = slow_check
    for selected, cap in [
        ([{'id': cid, 'instances': [{'host': str(i)} for i in range(65)]}], 4),
        ([{'id': cid, 'instances': [{'host': 'a'}]}] * 257, 4),
        ([{'id': cid, 'params': {'host': 'a'}}], 0),
        ([{'id': cid, 'params': {'host': 'a'}}], 17),
    ]:
        with pytest.raises(ValueError):
            engine.run_checks_multi(selected, max_parallel=cap)
    assert state['called'] == []


def test_estimate_uses_bounded_batches(monkeypatch):
    monkeypatch.setattr(timing, 'estimate', lambda _cid, params: params['n'])
    item = {'id': 'x', 'instances': [{'n': n} for n in [1, 5, 2, 3, 4, 6]]}
    assert timing.estimate_item(item, max_parallel=2) == 14  # 5 + 3 + 6
    assert timing.decide_mode([item], threshold=10, max_parallel=2) == ('async', 14)


def test_shared_web_process_cap(slow_check, isolated_db):
    cid, _spec, state = slow_check
    barrier = threading.Barrier(3)
    reports = []

    def run(prefix):
        barrier.wait()
        reports.append(engine.run_checks_multi([
            {'id': cid, 'instances': [{'host': f'{prefix}{i}'} for i in range(16)]},
        ], max_parallel=16, shared_pool=True))

    threads = [threading.Thread(target=run, args=(p,)) for p in ('a', 'b')]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert len(reports) == 2
    assert 1 < state['peak'] <= engine.PROCESS_MAX_PARALLEL
    assert len(state['called']) == 32


def test_shared_queue_gives_other_run_next_slot(monkeypatch):
    monkeypatch.setattr(engine, 'PROCESS_MAX_PARALLEL', 1)
    slots = engine._ProcessSlots()
    first_entered = threading.Event()
    release_first = threading.Event()
    order = []
    run_a, run_b = object(), object()

    def first():
        with slots.slot(run_a):
            first_entered.set()
            assert release_first.wait(2)

    def queued(token, label):
        with slots.slot(token):
            order.append(label)

    def wait_queued(token):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            with slots.cv:
                if token in slots.waiting:
                    return
            time.sleep(0.001)
        pytest.fail('worker did not queue')

    t1 = threading.Thread(target=first)
    t1.start()
    assert first_entered.wait(2)
    t2 = threading.Thread(target=queued, args=(run_b, 'b'))
    t2.start()
    wait_queued(run_b)
    t3 = threading.Thread(target=queued, args=(run_a, 'a'))
    t3.start()
    wait_queued(run_a)
    release_first.set()
    for thread in (t1, t2, t3):
        thread.join(timeout=2)
        assert not thread.is_alive()
    assert order == ['b', 'a']


def test_web_rejects_oversized_request_before_start(slow_check, isolated_db):
    from fastapi import HTTPException

    from web.app import CheckItem, RunRequest, api_estimate, api_run, api_stream_start

    cid, _spec, state = slow_check
    req = RunRequest(checks=[CheckItem(id=cid, instances=[{'host': str(i)} for i in range(65)])])
    for endpoint in (api_estimate, api_run, api_stream_start):
        with pytest.raises(HTTPException) as error:
            endpoint(req)
        assert error.value.status_code == 400
    assert state['called'] == []


def test_streaming_uses_same_bounded_dispatcher(slow_check, isolated_db):
    from netaudit_pkg.streaming import StreamTask, run_stream

    cid, _spec, state = slow_check
    task = StreamTask('b2-bounded-stream', [
        {'id': cid, 'instances': [{'host': str(i)} for i in range(9)]},
    ], max_parallel=2)
    run_stream(task)
    events = list(task.q.queue)
    dones = [event for event in events if event['type'] == 'check_done']
    assert state['peak'] == 2
    assert len(dones) == 9
    report = next(event['report'] for event in events if event['type'] == 'all_done')
    assert list(report['results'][cid]['by_host']) == [str(i) for i in range(9)]
