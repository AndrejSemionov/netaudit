"""
Tests for netaudit_pkg.engine: run_checks(), run_checks_multi(), and list_available().

These register throwaway checks into the REAL global registry (registry.py's
module-level `registry` singleton) rather than a fresh one, because
run_checks() and list_available() both read from that singleton directly and
aren't parameterized to accept an alternate registry. Every test cleans up
its own registered check(s) in a `finally` block so nothing leaks into other
tests or into the real check list.
"""

from __future__ import annotations

import threading
import time

import pytest

from netaudit_pkg.engine import (
    list_available,
    run_checks,
    run_checks_multi,
    run_instances,
)
from netaudit_pkg.registry import CheckSpec, registry


@pytest.fixture
def temp_check():
    """Registers a single throwaway check and cleans it up afterward. Yields
    a function to configure the check's behavior (what it returns / raises)."""
    registered_ids = []

    def _register(check_id, func, required_tools=None, risk_level='READ_ONLY'):
        registry.register(CheckSpec(
            id=check_id, label=f'Test {check_id}', category='test', func=func,
            required_tools=required_tools or [], risk_level=risk_level,
        ))
        registered_ids.append(check_id)
        return check_id

    yield _register

    for cid in registered_ids:
        registry._checks.pop(cid, None)


def test_run_checks_unknown_id_reports_error():
    result = run_checks([{'id': '__nonexistent_check_xyz__', 'params': {}}])
    assert 'error' in result['results']['__nonexistent_check_xyz__']
    assert 'not found' in result['results']['__nonexistent_check_xyz__']['error']


def test_run_checks_missing_required_tool(temp_check, isolated_db):
    temp_check('__test_missing_tool__', lambda: {'ok': True},
               required_tools=['__definitely_not_a_real_binary_xyz__'])
    result = run_checks([{'id': '__test_missing_tool__', 'params': {}}])
    entry = result['results']['__test_missing_tool__']
    assert 'error' in entry
    assert 'missing tools' in entry['error']
    assert result['timing']['__test_missing_tool__'] == 0.0


def test_run_checks_successful_execution(temp_check, isolated_db):
    temp_check('__test_ok__', lambda: {'summary': {'ok': 1}})
    result = run_checks([{'id': '__test_ok__', 'params': {}}])
    assert result['results']['__test_ok__'] == {'summary': {'ok': 1}}
    assert '__test_ok__' in result['timing']
    assert result['meta']['__test_ok__']['category'] == 'test'


def test_run_checks_passes_params_to_check_func(temp_check, isolated_db):
    captured = {}

    def check_with_params(target='', count=1):
        captured['target'] = target
        captured['count'] = count
        return {'ok': True}

    temp_check('__test_params__', check_with_params)
    run_checks([{'id': '__test_params__', 'params': {'target': '8.8.8.8', 'count': 5}}])
    assert captured == {'target': '8.8.8.8', 'count': 5}


def test_run_checks_catches_exceptions_from_check_func(temp_check, isolated_db):
    def failing_check():
        raise ValueError('something went wrong')

    temp_check('__test_fails__', failing_check)
    result = run_checks([{'id': '__test_fails__', 'params': {}}])
    entry = result['results']['__test_fails__']
    assert 'error' in entry
    assert 'ValueError' in entry['error']
    assert 'something went wrong' in entry['error']


def test_run_checks_total_time_sums_individual_timings(temp_check, isolated_db):
    temp_check('__test_a__', lambda: {'ok': True})
    temp_check('__test_b__', lambda: {'ok': True})
    result = run_checks([
        {'id': '__test_a__', 'params': {}},
        {'id': '__test_b__', 'params': {}},
    ])
    expected_total = round(sum(result['timing'].values()), 2)
    assert result['total_time'] == expected_total


def test_run_checks_report_has_timestamp():
    result = run_checks([])
    assert 'timestamp' in result
    assert result['results'] == {}
    assert result['total_time'] == 0.0


def test_run_checks_error_result_does_not_feed_timing(temp_check, isolated_db, monkeypatch):
    """A failed check's elapsed time shouldn't be recorded into the adaptive
    timing estimator - otherwise a fast failure could skew future sync/async
    decisions for a check that normally takes much longer to actually run."""
    recorded = []
    monkeypatch.setattr('netaudit_pkg.engine.timing.record',
                         lambda check_id, params, elapsed: recorded.append(check_id))

    temp_check('__test_fails_no_record__', lambda: (_ for _ in ()).throw(ValueError('boom')))
    run_checks([{'id': '__test_fails_no_record__', 'params': {}}])
    assert '__test_fails_no_record__' not in recorded


def test_run_checks_success_does_feed_timing(temp_check, isolated_db, monkeypatch):
    recorded = []
    monkeypatch.setattr('netaudit_pkg.engine.timing.record',
                         lambda check_id, params, elapsed: recorded.append(check_id))

    temp_check('__test_records__', lambda: {'ok': True})
    run_checks([{'id': '__test_records__', 'params': {}}])
    assert '__test_records__' in recorded


# ===========================================================================
# run_checks_multi
# ===========================================================================

def test_multi_unknown_id_reports_error():
    result = run_checks_multi([{'id': '__nonexistent_check_xyz__', 'instances': [{}]}])
    assert 'error' in result['results']['__nonexistent_check_xyz__']
    assert 'not found' in result['results']['__nonexistent_check_xyz__']['error']


def test_multi_missing_required_tool(temp_check, isolated_db):
    temp_check('__test_multi_missing_tool__', lambda host='': {'ok': True},
               required_tools=['__definitely_not_a_real_binary_xyz__'])
    result = run_checks_multi([
        {'id': '__test_multi_missing_tool__', 'instances': [{'host': 'a'}]},
    ])
    entry = result['results']['__test_multi_missing_tool__']
    assert 'error' in entry
    assert 'missing tools' in entry['error']


def test_multi_single_instance_is_flat_like_run_checks(temp_check, isolated_db):
    """1 instance -> same flat shape as run_checks(), for backward compatibility."""
    temp_check('__test_multi_single__', lambda host='': {'summary': {'ok': 1}})
    result = run_checks_multi([
        {'id': '__test_multi_single__', 'instances': [{'host': '1.2.3.4'}]},
    ])
    assert result['results']['__test_multi_single__'] == {'summary': {'ok': 1}}
    assert isinstance(result['timing']['__test_multi_single__'], float)
    assert '_multi_host' not in result['results']['__test_multi_single__']


# ===========================================================================
# Regression (2026-08-20): run_checks_multi() previously read only
# 'instances' via item.get('instances', [{}]) — the legacy single-instance
# 'params' form (identical shape to what run_checks() and web/app.py's
# _to_selected_item() both use/emit) was silently discarded, always
# producing one instance with EMPTY params regardless of what 'params'
# actually contained. Caught via web API smoke-testing nginx_logs_audit:
# POST /api/run with {'params': {'host': '...'}} produced "host not
# specified" even though the check function's own default is host=''.
# ===========================================================================

def test_multi_params_form_reaches_the_check_function(temp_check, isolated_db):
    """The legacy {'id': ..., 'params': {...}} form (no 'instances' key at
    all) must resolve to one instance carrying those exact params — not an
    empty dict. This is the API-layer's actual request shape
    (web/app.py's _to_selected_item() emits 'params', never 'instances',
    unless the caller explicitly used multi-host)."""
    def check_with_host(host=''):
        return {'host_seen': host}

    temp_check('__test_multi_params_form__', check_with_host)
    result = run_checks_multi([
        {'id': '__test_multi_params_form__', 'params': {'host': '9.9.9.9'}},
    ])
    assert result['results']['__test_multi_params_form__'] == {'host_seen': '9.9.9.9'}
    assert '_multi_host' not in result['results']['__test_multi_params_form__']


def test_multi_params_form_is_flat_like_instances_form(temp_check, isolated_db):
    """The 'params' form and the single-element 'instances' form must
    produce identically-shaped results — same flat report, same absence of
    '_multi_host' — since they represent the same single-instance run."""
    temp_check('__test_multi_params_flat__', lambda host='': {'summary': {'ok': 1}})
    via_params = run_checks_multi([
        {'id': '__test_multi_params_flat__', 'params': {'host': 'a'}},
    ])
    via_instances = run_checks_multi([
        {'id': '__test_multi_params_flat__', 'instances': [{'host': 'a'}]},
    ])
    assert via_params['results']['__test_multi_params_flat__'] == \
        via_instances['results']['__test_multi_params_flat__']


def test_multi_no_params_or_instances_key_defaults_to_empty_params(temp_check, isolated_db):
    """Neither key present at all -> one instance with {} params, matching
    run_checks()'s own item.get('params', {}) default — not an error, and
    not silently different behavior from the pre-fix code's [{}] default
    (this specific no-keys-at-all case behaved correctly before the fix
    too; this test documents that the fix preserves it)."""
    temp_check('__test_multi_no_keys__', lambda host='default': {'host_seen': host})
    result = run_checks_multi([{'id': '__test_multi_no_keys__'}])
    assert result['results']['__test_multi_no_keys__'] == {'host_seen': 'default'}


def test_multi_empty_instances_list_is_not_overridden_by_params(temp_check, isolated_db):
    """An explicit empty 'instances': [] is a deliberate 'no hosts' request
    and must NOT fall back to 'params', even if 'params' is also present —
    'instances' takes precedence whenever the key exists at all, regardless
    of its contents. (Matches the module docstring's stated precedence
    rule.)"""
    calls = []
    temp_check('__test_multi_empty_instances__', lambda host='': calls.append(host) or {'ok': True})
    result = run_checks_multi([
        {'id': '__test_multi_empty_instances__', 'instances': [], 'params': {'host': 'should-not-run'}},
    ])
    assert calls == []
    assert result['results']['__test_multi_empty_instances__'] == \
        {'_multi_host': True, 'by_host': {}}


def test_multi_two_instances_different_hosts(temp_check, isolated_db):
    def check_with_host(host=''):
        return {'host_seen': host}

    temp_check('__test_multi_two__', check_with_host)
    result = run_checks_multi([
        {'id': '__test_multi_two__', 'instances': [
            {'host': '1.1.1.1'}, {'host': '2.2.2.2'},
        ]},
    ])
    entry = result['results']['__test_multi_two__']
    assert entry['_multi_host'] is True
    assert entry['by_host']['1.1.1.1'] == {'host_seen': '1.1.1.1'}
    assert entry['by_host']['2.2.2.2'] == {'host_seen': '2.2.2.2'}

    timing_entry = result['timing']['__test_multi_two__']
    assert isinstance(timing_entry, dict)
    assert set(timing_entry.keys()) == {'1.1.1.1', '2.2.2.2'}


def test_multi_duplicate_host_gets_suffixed_key(temp_check, isolated_db):
    calls = []

    def check_with_host(host=''):
        calls.append(host)
        return {'call_num': len(calls)}

    temp_check('__test_multi_dup__', check_with_host)
    result = run_checks_multi([
        {'id': '__test_multi_dup__', 'instances': [
            {'host': '1.1.1.1'}, {'host': '1.1.1.1'}, {'host': '1.1.1.1'},
        ]},
    ])
    by_host = result['results']['__test_multi_dup__']['by_host']
    assert set(by_host.keys()) == {'1.1.1.1', '1.1.1.1#2', '1.1.1.1#3'}
    assert set(result['timing']['__test_multi_dup__'].keys()) == {'1.1.1.1', '1.1.1.1#2', '1.1.1.1#3'}


def test_multi_one_instance_failing_does_not_block_others(temp_check, isolated_db):
    def maybe_fail(host=''):
        if host == 'bad':
            raise ValueError('boom')
        return {'ok': True}

    temp_check('__test_multi_partial_fail__', maybe_fail)
    result = run_checks_multi([
        {'id': '__test_multi_partial_fail__', 'instances': [
            {'host': 'good1'}, {'host': 'bad'}, {'host': 'good2'},
        ]},
    ])
    by_host = result['results']['__test_multi_partial_fail__']['by_host']
    assert by_host['good1'] == {'ok': True}
    assert by_host['good2'] == {'ok': True}
    assert 'error' in by_host['bad']
    assert 'ValueError' in by_host['bad']['error']


def test_multi_instances_run_in_parallel_not_sequentially(temp_check, isolated_db):
    """Two instances of the same check must have their actual execution
    windows (spec.func() call, not the surrounding worker/bookkeeping code)
    overlap in time - proving they run concurrently rather than via a plain
    sequential for-loop.

    Measures start/end timestamps INSIDE the check function itself, via a
    thread-safe shared list, rather than timing run_checks_multi() as a
    black box from the outside. This is deliberately immune to overhead
    from anything other than the check's own execution - including
    timing.record()'s SQLite write, which runs AFTER a thread's elapsed
    time is captured but BEFORE the thread actually finishes (join()
    waits for it too). That distinction matters: a real VM run showed
    wall-clock time significantly exceeding even the sequential-sum of
    the two checks' own elapsed times, which turned out to be occasional
    slow SQLite writes inside timing.record() padding the outer
    wall-clock measurement without changing the checks' own timing at
    all - a black-box wall-clock assertion conflates "did the checks run
    in parallel" with "was every side-effect around them also fast,"
    which is a different (and unrelated) question this test isn't meant
    to answer.
    """
    lock = threading.Lock()
    windows = []  # list of (start, end) tuples, one per instance

    def slow_check(host=''):
        t0 = time.monotonic()
        time.sleep(0.2)
        t1 = time.monotonic()
        with lock:
            windows.append((t0, t1))
        return {'ok': True}

    temp_check('__test_multi_parallel__', slow_check)
    run_checks_multi([
        {'id': '__test_multi_parallel__', 'instances': [{'host': 'a'}, {'host': 'b'}]},
    ])

    assert len(windows) == 2, 'both instances should have recorded a window'
    (start_a, end_a), (start_b, end_b) = windows

    # true parallel execution means the two [start, end] windows overlap -
    # sequential execution would have one window's start be >= the other's end
    overlap = min(end_a, end_b) - max(start_a, start_b)
    assert overlap > 0, (
        f'expected the two instances\' execution windows to overlap '
        f'(window a: {start_a:.3f}-{end_a:.3f}, window b: {start_b:.3f}-{end_b:.3f}) - '
        f'looks like they ran sequentially instead of in parallel'
    )


def test_multi_timing_record_called_once_per_instance(temp_check, isolated_db, monkeypatch):
    recorded = []
    monkeypatch.setattr('netaudit_pkg.engine.timing.record',
                         lambda check_id, params, elapsed: recorded.append((check_id, params)))

    temp_check('__test_multi_record__', lambda host='': {'ok': True})
    run_checks_multi([
        {'id': '__test_multi_record__', 'instances': [
            {'host': 'a'}, {'host': 'b'}, {'host': 'c'},
        ]},
    ])
    assert len(recorded) == 3
    hosts_recorded = {params.get('host') for _, params in recorded}
    assert hosts_recorded == {'a', 'b', 'c'}


def test_multi_total_time_is_max_per_check_summed_across_checks(temp_check, isolated_db):
    """Within one check, instances run in parallel -> total_time contribution is
    the max elapsed among its instances. Across different checks -> summed.

    Asserts the SHAPE of the relationship (parallel max, not sequential sum)
    rather than an absolute wall-clock threshold - a fixed-seconds threshold
    is fundamentally unreliable under full-suite load (observed on a real VM:
    an isolated run of this test easily clears any reasonable margin, but the
    same test under full-suite thread/scheduling pressure can occasionally
    take 3x+ longer in absolute terms even though the parallel-vs-sequential
    RATIO stays correct). Comparing against report['timing'] (the actual
    measured elapsed per instance) rather than the nominal sleep= values
    keeps this correct even when the underlying sleeps ran much slower than
    requested.
    """
    def check_a(host='', sleep=0.0):
        time.sleep(sleep)
        return {'ok': True}

    temp_check('__test_multi_total_a__', check_a)
    temp_check('__test_multi_total_b__', check_a)

    result = run_checks_multi([
        {'id': '__test_multi_total_a__', 'instances': [
            {'host': 'x', 'sleep': 0.1}, {'host': 'y', 'sleep': 0.3},
        ]},
        {'id': '__test_multi_total_b__', 'instances': [
            {'host': 'z', 'sleep': 0.1},
        ]},
    ])

    timing_a = result['timing']['__test_multi_total_a__']  # {'x': elapsed, 'y': elapsed}
    timing_b = result['timing']['__test_multi_total_b__']  # flat float (1 instance)
    expected_total = round(max(timing_a.values()) + timing_b, 2)
    sequential_alternative = round(sum(timing_a.values()) + timing_b, 2)

    # total_time must match the max-per-check/sum-across-checks formula
    # exactly (this is the actual logic under test, independent of how slow
    # the machine happened to be)
    assert result['total_time'] == expected_total
    # and it must be meaningfully below the naive sequential-sum alternative,
    # proving the two instances of check 'a' really ran in parallel rather
    # than back-to-back (guards against a regression to a plain for-loop)
    assert result['total_time'] < sequential_alternative


# ===========================================================================
# run_instances (shared execution core used by run_checks_multi and streaming)
# ===========================================================================

def test_run_instances_returns_results_and_timing_by_key(temp_check, isolated_db):
    temp_check('__test_ri_basic__', lambda host='': {'seen': host})
    spec = registry.get('__test_ri_basic__')
    results, timings = run_instances('__test_ri_basic__', spec, [
        {'host': 'a'}, {'host': 'b'},
    ])
    assert results == {'a': {'seen': 'a'}, 'b': {'seen': 'b'}}
    assert set(timings.keys()) == {'a', 'b'}
    assert all(isinstance(v, float) for v in timings.values())


def test_run_instances_dedupes_repeated_host(temp_check, isolated_db):
    temp_check('__test_ri_dup__', lambda host='': {'ok': True})
    spec = registry.get('__test_ri_dup__')
    results, timings = run_instances('__test_ri_dup__', spec, [
        {'host': 'x'}, {'host': 'x'},
    ])
    assert set(results.keys()) == {'x', 'x#2'}
    assert set(timings.keys()) == {'x', 'x#2'}


def test_run_instances_isolates_failures(temp_check, isolated_db):
    def maybe_fail(host=''):
        if host == 'bad':
            raise ValueError('boom')
        return {'ok': True}

    temp_check('__test_ri_fail__', maybe_fail)
    spec = registry.get('__test_ri_fail__')
    results, _ = run_instances('__test_ri_fail__', spec, [
        {'host': 'good'}, {'host': 'bad'},
    ])
    assert results['good'] == {'ok': True}
    assert 'error' in results['bad']


def test_run_instances_calls_callback_per_instance(temp_check, isolated_db):
    temp_check('__test_ri_cb__', lambda host='': {'ok': True})
    spec = registry.get('__test_ri_cb__')
    seen = []
    lock = threading.Lock()

    def on_done(key, result, elapsed):
        with lock:
            seen.append((key, result, elapsed))

    run_instances('__test_ri_cb__', spec, [
        {'host': 'a'}, {'host': 'b'}, {'host': 'c'},
    ], on_instance_done=on_done)

    assert len(seen) == 3
    keys = {k for k, _, _ in seen}
    assert keys == {'a', 'b', 'c'}
    assert all(r == {'ok': True} for _, r, _ in seen)


def test_run_instances_no_callback_does_not_error(temp_check, isolated_db):
    """on_instance_done is optional - omitting it must not raise."""
    temp_check('__test_ri_nocb__', lambda host='': {'ok': True})
    spec = registry.get('__test_ri_nocb__')
    results, timings = run_instances('__test_ri_nocb__', spec, [{'host': 'a'}])
    assert results == {'a': {'ok': True}}


def test_run_instances_records_timing_per_instance(temp_check, isolated_db, monkeypatch):
    recorded = []
    monkeypatch.setattr('netaudit_pkg.engine.timing.record',
                         lambda check_id, params, elapsed: recorded.append(params.get('host')))

    temp_check('__test_ri_timing__', lambda host='': {'ok': True})
    spec = registry.get('__test_ri_timing__')
    run_instances('__test_ri_timing__', spec, [{'host': 'a'}, {'host': 'b'}])

    assert set(recorded) == {'a', 'b'}


def test_run_checks_multi_uses_run_instances_for_multi_case(temp_check, isolated_db, monkeypatch):
    """Confirms run_checks_multi() is actually delegating to run_instances()
    (not a separate parallel copy of the same logic) by monkeypatching it."""
    calls = []
    import netaudit_pkg.engine as engine_mod
    real_run_instances = engine_mod.run_instances

    def spy(check_id, spec, instances, on_instance_done=None):
        calls.append((check_id, len(instances)))
        return real_run_instances(check_id, spec, instances, on_instance_done)

    monkeypatch.setattr(engine_mod, 'run_instances', spy)
    temp_check('__test_rcm_delegates__', lambda host='': {'ok': True})
    run_checks_multi([
        {'id': '__test_rcm_delegates__', 'instances': [{'host': 'a'}, {'host': 'b'}]},
    ])
    assert calls == [('__test_rcm_delegates__', 2)]


def test_run_instances_callback_exception_does_not_lose_other_instances(temp_check, isolated_db):
    """If on_instance_done raises for one instance, results/timing for ALL
    instances (including that one) must still be recorded correctly - a
    misbehaving callback must not silently drop a worker thread's outcome."""
    temp_check('__test_ri_cb_raises__', lambda host='': {'ok': True})
    spec = registry.get('__test_ri_cb_raises__')

    def flaky_callback(key, result, elapsed):
        if key == 'b':
            raise RuntimeError('simulated callback failure')

    results, timings = run_instances('__test_ri_cb_raises__', spec, [
        {'host': 'a'}, {'host': 'b'}, {'host': 'c'},
    ], on_instance_done=flaky_callback)

    # results/timing must be complete for all 3 instances regardless of the
    # callback exception on 'b'
    assert set(results.keys()) == {'a', 'b', 'c'}
    assert set(timings.keys()) == {'a', 'b', 'c'}
    assert results['b'] == {'ok': True}


def test_run_instances_timing_record_failure_does_not_lose_instance_result(temp_check, isolated_db, monkeypatch):
    """If timing.record() raises (e.g. a rare SQLite lock under concurrent
    writes), the instance's own result/timing must still be recorded - this
    mirrors run_checks()'s and streaming.py's legacy single-host protection,
    which _run_one_instance() must not silently lose for the multi-host path."""
    def flaky_record(check_id, params, elapsed):
        if params.get('host') == 'b':
            raise RuntimeError('simulated database is locked')

    monkeypatch.setattr('netaudit_pkg.engine.timing.record', flaky_record)

    temp_check('__test_ri_record_fails__', lambda host='': {'ok': True})
    spec = registry.get('__test_ri_record_fails__')
    results, timings = run_instances('__test_ri_record_fails__', spec, [
        {'host': 'a'}, {'host': 'b'}, {'host': 'c'},
    ])

    assert set(results.keys()) == {'a', 'b', 'c'}
    assert set(timings.keys()) == {'a', 'b', 'c'}
    assert results['b'] == {'ok': True}


# ===========================================================================
# list_available
# ===========================================================================

def test_list_available_includes_registered_check(temp_check):
    temp_check('__test_listed__', dict, risk_level='PASSIVE')
    listed = {c['id']: c for c in list_available()}
    assert '__test_listed__' in listed
    assert listed['__test_listed__']['risk_level'] == 'PASSIVE'


def test_list_available_reports_missing_tools(temp_check):
    temp_check('__test_missing_reported__', dict,
               required_tools=['__definitely_not_a_real_binary_xyz__'])
    listed = {c['id']: c for c in list_available()}
    entry = listed['__test_missing_reported__']
    assert '__definitely_not_a_real_binary_xyz__' in entry['missing_tools']


def test_list_available_returns_all_real_checks():
    """Sanity check against the actual project state: at the time of writing
    there are 27 registered checks. This isn't meant to be a hardcoded trap -
    if it fails after adding/removing a check, update the number, but a
    sudden large drop is worth investigating (a check failing to import silently)."""
    listed = list_available()
    assert len(listed) >= 27


# ===========================================================================
# execution_context (Report Identity / Execution Context Contract v1)
#
# run_checks()/run_checks_multi() must record the actual params a check was
# invoked with, alongside results/timing/meta - a new report['execution_context']
# entry. This is deliberately NOT identity/subject extraction (no attempt to
# decide which param is "the host" vs "the target" vs "the URL") - it stores
# exactly what was passed to spec.func(**params), unmodified, regardless of
# which family of check this is. That interpretation is future work.
#
# Contract v1 (frozen before these tests were written):
#   spec is None (unknown check id)   -> no execution_context entry
#   required tool missing             -> no execution_context entry
#   spec.func(**params) is invoked    -> execution_context entry present
#       - successful call             -> execution_context + result + timing
#       - call raises an exception    -> execution_context + result={'error': ...} + timing
#   multi-host (run_checks_multi, N>1 instances):
#       execution_context[check_id][instance_key] = params  (parallel to by_host,
#       same dedup keying _dedupe_key() already produces)
# ===========================================================================

def test_run_checks_unknown_id_has_no_execution_context():
    result = run_checks([{'id': '__nonexistent_check_xyz__', 'params': {'target': '8.8.8.8'}}])
    assert '__nonexistent_check_xyz__' not in result.get('execution_context', {})


def test_run_checks_missing_tool_has_no_execution_context(temp_check, isolated_db):
    temp_check('__test_ec_missing_tool__', lambda target='': {'ok': True},
               required_tools=['__definitely_not_a_real_binary_xyz__'])
    result = run_checks([{'id': '__test_ec_missing_tool__', 'params': {'target': '8.8.8.8'}}])
    assert '__test_ec_missing_tool__' not in result.get('execution_context', {})


def test_run_checks_successful_call_records_execution_context(temp_check, isolated_db):
    temp_check('__test_ec_ok__', lambda target='', count=1: {'ok': True})
    result = run_checks([
        {'id': '__test_ec_ok__', 'params': {'target': '8.8.8.8', 'count': 5}},
    ])
    assert result['execution_context']['__test_ec_ok__'] == {'target': '8.8.8.8', 'count': 5}
    # result/timing/meta are unaffected - this is an additive contract
    assert result['results']['__test_ec_ok__'] == {'ok': True}
    assert '__test_ec_ok__' in result['timing']


def test_run_checks_exception_still_records_execution_context(temp_check, isolated_db):
    """Params were passed and the call was attempted - that fact doesn't
    disappear just because the check itself failed. execution_context
    records the *attempt*, not the outcome."""
    def failing_check(target=''):
        raise ValueError('boom')

    temp_check('__test_ec_fails__', failing_check)
    result = run_checks([
        {'id': '__test_ec_fails__', 'params': {'target': '8.8.8.8'}},
    ])
    assert result['execution_context']['__test_ec_fails__'] == {'target': '8.8.8.8'}
    assert 'error' in result['results']['__test_ec_fails__']
    assert '__test_ec_fails__' in result['timing']


def test_run_checks_empty_params_records_empty_dict(temp_check, isolated_db):
    """A check with no identity params at all (speedtest, performance,
    firewall, ports) still gets an execution_context entry - an empty dict,
    not a missing key. The entry marks 'this check ran', regardless of
    whether it had any params to record."""
    temp_check('__test_ec_no_params__', lambda: {'ok': True})
    result = run_checks([{'id': '__test_ec_no_params__', 'params': {}}])
    assert result['execution_context']['__test_ec_no_params__'] == {}


def test_run_checks_execution_context_reflects_actual_params_not_defaults(temp_check, isolated_db):
    """execution_context stores what was PASSED IN, not what the check
    function's own defaults would produce internally - these can differ
    when only some params are supplied."""
    temp_check('__test_ec_partial__', lambda target='', count=10: {'ok': True})
    result = run_checks([
        {'id': '__test_ec_partial__', 'params': {'target': '1.1.1.1'}},
    ])
    # count was never in the passed params dict, even though the check
    # function has a default for it
    assert result['execution_context']['__test_ec_partial__'] == {'target': '1.1.1.1'}


def test_multi_unknown_id_has_no_execution_context():
    result = run_checks_multi([{'id': '__nonexistent_check_xyz__', 'instances': [{}]}])
    assert '__nonexistent_check_xyz__' not in result.get('execution_context', {})


def test_multi_missing_tool_has_no_execution_context(temp_check, isolated_db):
    temp_check('__test_ec_multi_missing_tool__', lambda host='': {'ok': True},
               required_tools=['__definitely_not_a_real_binary_xyz__'])
    result = run_checks_multi([
        {'id': '__test_ec_multi_missing_tool__', 'instances': [{'host': 'a'}]},
    ])
    assert '__test_ec_multi_missing_tool__' not in result.get('execution_context', {})


def test_multi_single_instance_execution_context_is_flat(temp_check, isolated_db):
    """1 instance -> flat execution_context entry (just the params dict),
    matching run_checks()'s shape - not the {key: params} multi-host form.
    Mirrors how results/timing are flat for a single instance."""
    temp_check('__test_ec_multi_single__', lambda host='': {'ok': True})
    result = run_checks_multi([
        {'id': '__test_ec_multi_single__', 'instances': [{'host': '1.2.3.4'}]},
    ])
    assert result['execution_context']['__test_ec_multi_single__'] == {'host': '1.2.3.4'}


def test_multi_single_instance_via_legacy_params_form(temp_check, isolated_db):
    """The legacy {'id': ..., 'params': {...}} form (no 'instances' key)
    must also produce a flat execution_context entry with those exact
    params - same as the explicit single-element 'instances' form."""
    temp_check('__test_ec_multi_legacy__', lambda host='': {'ok': True})
    result = run_checks_multi([
        {'id': '__test_ec_multi_legacy__', 'params': {'host': '9.9.9.9'}},
    ])
    assert result['execution_context']['__test_ec_multi_legacy__'] == {'host': '9.9.9.9'}


def test_multi_single_instance_exception_still_records_execution_context(temp_check, isolated_db):
    def failing_check(host=''):
        raise RuntimeError('boom')

    temp_check('__test_ec_multi_fails__', failing_check)
    result = run_checks_multi([
        {'id': '__test_ec_multi_fails__', 'instances': [{'host': 'a'}]},
    ])
    assert result['execution_context']['__test_ec_multi_fails__'] == {'host': 'a'}
    assert 'error' in result['results']['__test_ec_multi_fails__']


def test_multi_two_instances_execution_context_keyed_like_by_host(temp_check, isolated_db):
    """N>1 instances -> execution_context[check_id] is a {key: params} dict,
    with the SAME keys run_instances() already produces for by_host (host
    value, deduped via the same _dedupe_key() the results/timing dicts use)
    - not a separate keying scheme."""
    temp_check('__test_ec_multi_two__', lambda host='': {'host_seen': host})
    result = run_checks_multi([
        {'id': '__test_ec_multi_two__', 'instances': [
            {'host': '1.1.1.1'}, {'host': '2.2.2.2'},
        ]},
    ])
    ec = result['execution_context']['__test_ec_multi_two__']
    by_host = result['results']['__test_ec_multi_two__']['by_host']
    assert set(ec.keys()) == set(by_host.keys()) == {'1.1.1.1', '2.2.2.2'}
    assert ec['1.1.1.1'] == {'host': '1.1.1.1'}
    assert ec['2.2.2.2'] == {'host': '2.2.2.2'}


def test_multi_duplicate_host_execution_context_uses_suffixed_keys(temp_check, isolated_db):
    """Duplicate host values get the same '#2'/'#3' suffixed keys in
    execution_context as they already get in by_host/timing - one
    consistent keying scheme across all three dicts, not a second one."""
    temp_check('__test_ec_multi_dup__', lambda host='': {'ok': True})
    result = run_checks_multi([
        {'id': '__test_ec_multi_dup__', 'instances': [
            {'host': '1.1.1.1'}, {'host': '1.1.1.1'},
        ]},
    ])
    ec = result['execution_context']['__test_ec_multi_dup__']
    by_host = result['results']['__test_ec_multi_dup__']['by_host']
    assert set(ec.keys()) == set(by_host.keys()) == {'1.1.1.1', '1.1.1.1#2'}


def test_multi_one_instance_fails_others_still_have_execution_context(temp_check, isolated_db):
    """A failing instance doesn't block execution_context for the others -
    same isolation guarantee run_instances() already provides for
    results/timing."""
    def maybe_fail(host=''):
        if host == 'bad':
            raise ValueError('boom')
        return {'ok': True}

    temp_check('__test_ec_multi_partial_fail__', maybe_fail)
    result = run_checks_multi([
        {'id': '__test_ec_multi_partial_fail__', 'instances': [
            {'host': 'good'}, {'host': 'bad'},
        ]},
    ])
    ec = result['execution_context']['__test_ec_multi_partial_fail__']
    assert ec == {'good': {'host': 'good'}, 'bad': {'host': 'bad'}}
    assert 'error' in result['results']['__test_ec_multi_partial_fail__']['by_host']['bad']
