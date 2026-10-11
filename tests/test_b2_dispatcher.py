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
