"""
Tests for web/app.py: CheckItem.instances, /api/estimate, /api/run, and
presets round-tripping multi-instance checks.

No test file existed for web/app.py before this - these use FastAPI's
TestClient against the real `app` object. NETAUDIT_WEB_HOST is left unset so
web_auth treats the host as localhost (127.0.0.1 default) and no Basic Auth
is required, matching how the test suite runs elsewhere without a live server.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from web.app import app
from netaudit_pkg.registry import registry, CheckSpec


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def temp_check():
    """Registers a throwaway check with a 'host' param (so it's detectable
    as multi-host-capable) and cleans it up afterward."""
    registered_ids = []

    def _register(check_id, func, required_tools=None, risk_level='READ_ONLY'):
        registry.register(CheckSpec(
            id=check_id, label=f'Test {check_id}', category='test', func=func,
            required_tools=required_tools or [],
            params=[{'name': 'host', 'type': 'text', 'label': 'Host'}],
            risk_level=risk_level,
        ))
        registered_ids.append(check_id)
        return check_id

    yield _register

    for cid in registered_ids:
        registry._checks.pop(cid, None)


# ===========================================================================
# /api/estimate
# ===========================================================================

def test_estimate_legacy_params_still_works(client, temp_check, isolated_db):
    temp_check('__test_web_est_legacy__', lambda host='': {'ok': True})
    resp = client.post('/api/estimate', json={
        'checks': [{'id': '__test_web_est_legacy__', 'params': {'host': 'a'}}],
    })
    assert resp.status_code == 200
    body = resp.json()
    assert '__test_web_est_legacy__' in body['per_check']
    assert isinstance(body['per_check']['__test_web_est_legacy__'], float)


def test_estimate_instances_per_check_is_max_not_flat_zero(client, temp_check, isolated_db):
    """Before the fix, per_check for an 'instances' item would silently
    compute estimate(id, {}) instead of the true per-instance max."""
    temp_check('__test_web_est_multi__', lambda host='': {'ok': True})
    resp = client.post('/api/estimate', json={
        'checks': [{'id': '__test_web_est_multi__', 'instances': [
            {'host': 'a'}, {'host': 'b'},
        ]}],
    })
    assert resp.status_code == 200
    body = resp.json()
    assert '__test_web_est_multi__' in body['per_check']
    assert isinstance(body['per_check']['__test_web_est_multi__'], float)
    assert body['per_check']['__test_web_est_multi__'] > 0


def test_estimate_total_matches_decide_mode_semantics(client, temp_check, isolated_db):
    """Total across a multi-instance check should not be inflated by summing
    every instance (that would break sync/async thresholds)."""
    temp_check('__test_web_est_total__', lambda host='': {'ok': True})
    resp_single = client.post('/api/estimate', json={
        'checks': [{'id': '__test_web_est_total__', 'params': {'host': 'a'}}],
    })
    resp_multi = client.post('/api/estimate', json={
        'checks': [{'id': '__test_web_est_total__', 'instances': [
            {'host': 'a'}, {'host': 'b'}, {'host': 'c'},
        ]}],
    })
    # same check/seed -> per-instance estimates are equal -> max == single estimate
    assert resp_multi.json()['estimate'] == resp_single.json()['estimate']


# ===========================================================================
# /api/run (sync path)
# ===========================================================================

def test_run_rejects_empty_checks(client, isolated_db):
    resp = client.post('/api/run', json={'checks': []})
    assert resp.status_code == 400


def test_run_single_instance_gives_flat_result(client, temp_check, isolated_db):
    isolated_db.setting_set('sync_threshold_sec', '100')
    temp_check('__test_web_run_single__', lambda host='': {'summary': 'ok'})
    resp = client.post('/api/run', json={
        'checks': [{'id': '__test_web_run_single__', 'instances': [{'host': 'a'}]}],
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body['mode'] == 'sync'
    result = body['report']['results']['__test_web_run_single__']
    assert result == {'summary': 'ok'}
    assert '_multi_host' not in result


def test_run_multi_instance_gives_by_host_result(client, temp_check, isolated_db):
    isolated_db.setting_set('sync_threshold_sec', '100')
    temp_check('__test_web_run_multi__', lambda host='': {'seen': host})
    resp = client.post('/api/run', json={
        'checks': [{'id': '__test_web_run_multi__', 'instances': [
            {'host': '1.1.1.1'}, {'host': '2.2.2.2'},
        ]}],
    })
    assert resp.status_code == 200
    body = resp.json()
    result = body['report']['results']['__test_web_run_multi__']
    assert result['_multi_host'] is True
    assert result['by_host']['1.1.1.1'] == {'seen': '1.1.1.1'}
    assert result['by_host']['2.2.2.2'] == {'seen': '2.2.2.2'}


def test_run_legacy_params_only_request_unaffected(client, temp_check, isolated_db):
    """A request using only the old 'params' form (no 'instances' at all)
    behaves exactly as before the multi-host change."""
    isolated_db.setting_set('sync_threshold_sec', '100')
    temp_check('__test_web_run_legacy__', lambda host='': {'ok': True})
    resp = client.post('/api/run', json={
        'checks': [{'id': '__test_web_run_legacy__', 'params': {'host': 'x'}}],
    })
    assert resp.status_code == 200
    result = resp.json()['report']['results']['__test_web_run_legacy__']
    assert result == {'ok': True}


# ===========================================================================
# /api/stream/start (the actual endpoint the "Запустить" button uses)
# ===========================================================================

def test_stream_start_forwards_instances_not_just_flat_params(client, temp_check, isolated_db):
    """Regression test: /api/stream/start previously built its `selected` list
    with the old flat {'id', 'params'} shape unconditionally, silently
    dropping CheckItem.instances. Single-host requests happened to still
    work (instances is None or has 1 entry -> falls back to params), which
    is why this wasn't caught by hand-testing one host at a time - adding a
    SECOND host silently ran the check with an empty params dict instead.
    """
    from web.app import _stream_tasks

    temp_check('__test_stream_multi__', lambda host='': {'seen': host})
    resp = client.post('/api/stream/start', json={
        'checks': [{'id': '__test_stream_multi__', 'instances': [
            {'host': '1.1.1.1'}, {'host': '2.2.2.2'},
        ]}],
    })
    assert resp.status_code == 200
    task_id = resp.json()['task_id']

    task = _stream_tasks.get(task_id)
    assert task is not None, 'stream task should still be registered right after start'
    item = task.selected[0]
    assert 'instances' in item, (
        "api_stream_start() dropped 'instances' and fell back to flat "
        "'params' - this is the multi-host-in-the-UI bug"
    )
    assert item['instances'] == [{'host': '1.1.1.1'}, {'host': '2.2.2.2'}]

    task.stop()  # don't leave a background thread running past the test


def test_stream_start_legacy_single_instance_still_uses_flat_params(client, temp_check, isolated_db):
    """A single-instance / no-instances request keeps going through the
    legacy flat 'params' path unchanged, exactly as before."""
    from web.app import _stream_tasks

    temp_check('__test_stream_single__', lambda host='': {'seen': host})
    resp = client.post('/api/stream/start', json={
        'checks': [{'id': '__test_stream_single__', 'params': {'host': 'x'}}],
    })
    assert resp.status_code == 200
    task_id = resp.json()['task_id']

    task = _stream_tasks.get(task_id)
    assert task is not None
    item = task.selected[0]
    assert 'instances' not in item
    assert item['params'] == {'host': 'x'}

    task.stop()


def test_stream_start_actually_runs_multi_host_end_to_end(client, temp_check, isolated_db):
    """Full round trip: POST /api/stream/start with 2 instances, wait for the
    task to finish, confirm the task's underlying report really has the
    _multi_host/by_host shape - not just that 'instances' reached the
    StreamTask object (belt-and-suspenders on top of the unit-level check
    above, exercising the real run_stream() thread)."""
    import time as _time
    from web.app import _stream_tasks

    temp_check('__test_stream_e2e__', lambda host='': {'seen': host})
    resp = client.post('/api/stream/start', json={
        'checks': [{'id': '__test_stream_e2e__', 'instances': [
            {'host': 'aaa'}, {'host': 'bbb'},
        ]}],
    })
    task_id = resp.json()['task_id']

    task = None
    for _ in range(50):
        candidate = _stream_tasks.get(task_id)
        if candidate is not None and candidate.status != 'running':
            task = candidate
            break
        _time.sleep(0.05)
    assert task is not None, 'stream task did not finish in time'
    assert task.status == 'done'

    import queue as _queue
    report = None
    while True:
        try:
            ev = task.q.get_nowait()
        except _queue.Empty:
            break
        if ev.get('type') == 'all_done':
            report = ev['report']
    assert report is not None
    result = report['results']['__test_stream_e2e__']
    assert result['_multi_host'] is True
    assert result['by_host'] == {'aaa': {'seen': 'aaa'}, 'bbb': {'seen': 'bbb'}}


# ===========================================================================
# Presets round-trip instances
# ===========================================================================

def test_preset_round_trips_instances(client, isolated_db):
    resp = client.post('/api/presets', json={
        'name': 'multi-host-preset',
        'checks': [{'id': 'cve', 'instances': [
            {'host': '1.1.1.1'}, {'host': '2.2.2.2'},
        ]}],
    })
    assert resp.status_code == 200

    listed = client.get('/api/presets').json()
    saved = next(p for p in listed if p['name'] == 'multi-host-preset')
    assert saved['checks'][0]['instances'] == [
        {'host': '1.1.1.1'}, {'host': '2.2.2.2'},
    ]


def test_preset_round_trips_legacy_params(client, isolated_db):
    """A preset saved with only 'params' (no instances) still round-trips
    unchanged - old presets aren't broken by the schema addition."""
    resp = client.post('/api/presets', json={
        'name': 'legacy-preset',
        'checks': [{'id': 'mtr', 'params': {'target': '8.8.8.8'}}],
    })
    assert resp.status_code == 200

    listed = client.get('/api/presets').json()
    saved = next(p for p in listed if p['name'] == 'legacy-preset')
    assert saved['checks'][0]['params'] == {'target': '8.8.8.8'}
