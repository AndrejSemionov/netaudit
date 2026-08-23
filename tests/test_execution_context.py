"""
RED tests for execution_context: run_checks()/run_checks_multi() must record
the actual params a check was invoked with, alongside results/timing/meta.

Contract v1 (frozen before this file was written):
    spec is None (unknown check id)          -> no execution_context entry
    required tool missing                    -> no execution_context entry
    spec.func(**params) is invoked           -> execution_context entry present
        - successful call                    -> execution_context + result + timing
        - call raises an exception            -> execution_context + result={'error': ...} + timing
    multi-host (run_checks_multi, N>1 instances):
        execution_context[check_id][instance_key] = params  (parallel to by_host)

execution_context is deliberately NOT identity/subject extraction - it stores
exactly what was passed to spec.func(**params), unmodified, no matter which
family of check this is (host/target/url/domain/emails/no-params-at-all).
That interpretation is future work, out of scope here.

Uses the same temp_check/isolated_db fixtures and registry-based testing
style as tests/test_engine.py (see that file's module docstring for why:
run_checks()/list_available() read the real global registry singleton
directly, not a fresh one, so throwaway checks are registered into it and
cleaned up in a fixture finally block).
"""

from __future__ import annotations

from netaudit_pkg.engine import run_checks, run_checks_multi


# ===========================================================================
# run_checks() - single-instance CLI path
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


# ===========================================================================
# run_checks_multi() - single instance (flat, backward-compatible shape)
# ===========================================================================

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


# ===========================================================================
# run_checks_multi() - multi-instance (parallel to by_host)
# ===========================================================================

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
