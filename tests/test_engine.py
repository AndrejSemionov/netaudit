"""
Tests for netaudit_pkg.engine: run_checks() and list_available().

These register throwaway checks into the REAL global registry (registry.py's
module-level `registry` singleton) rather than a fresh one, because
run_checks() and list_available() both read from that singleton directly and
aren't parameterized to accept an alternate registry. Every test cleans up
its own registered check(s) in a `finally` block so nothing leaks into other
tests or into the real check list.
"""

from __future__ import annotations

import pytest

from netaudit_pkg.engine import run_checks, list_available
from netaudit_pkg.registry import registry, CheckSpec


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
# list_available
# ===========================================================================

def test_list_available_includes_registered_check(temp_check):
    temp_check('__test_listed__', lambda: {}, risk_level='PASSIVE')
    listed = {c['id']: c for c in list_available()}
    assert '__test_listed__' in listed
    assert listed['__test_listed__']['risk_level'] == 'PASSIVE'


def test_list_available_reports_missing_tools(temp_check):
    temp_check('__test_missing_reported__', lambda: {},
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
