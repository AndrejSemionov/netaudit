"""Engine: runs the selected checks with their params, times each one."""

from __future__ import annotations

import threading
import time
from datetime import datetime

# importing registers all the checks
from . import (
    checks,  # noqa: F401
    timing,
)
from .registry import registry
from .utils import log, missing_tools


def run_checks(selected: list[dict]) -> dict:
    """
    selected: list of {'id': 'mtr', 'params': {'target': '8.8.8.8', 'count': 15}}
    Returns a report with the elapsed time of each check.
    """
    report = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'results': {},
        'timing': {},
        'meta': {},
    }

    for item in selected:
        check_id = item['id']
        params = item.get('params', {})
        spec = registry.get(check_id)
        if spec is None:
            report['results'][check_id] = {'error': f'check {check_id} not found'}
            continue

        missing = missing_tools(spec.required_tools)
        if missing:
            report['results'][check_id] = {'error': f'missing tools: {", ".join(missing)}'}
            report['timing'][check_id] = 0.0
            continue

        log.info(f'Running: {spec.label} ({check_id})...')
        start = time.monotonic()
        try:
            result = spec.func(**params)
        except Exception as e:
            result = {'error': f'exception: {type(e).__name__}: {e}'}
        elapsed = round(time.monotonic() - start, 2)

        # feed the adaptive timing system with real elapsed time (successful runs
        # only, so a tool error doesn't skew the estimate)
        if not (isinstance(result, dict) and result.get('error')):
            timing.record(check_id, params, elapsed)

        report['results'][check_id] = result
        report['timing'][check_id] = elapsed
        report['meta'][check_id] = {'label': spec.label, 'category': spec.category}

    report['total_time'] = round(sum(report['timing'].values()), 2)
    return report


def _run_one_instance(check_id: str, spec, params: dict) -> tuple[dict, float]:
    """Runs a single check instance, returns (result, elapsed). Mirrors the
    try/except + timing.record() behavior of run_checks()'s inner loop."""
    log.info(f'Running: {spec.label} ({check_id})...')
    start = time.monotonic()
    try:
        result = spec.func(**params)
    except Exception as e:
        result = {'error': f'exception: {type(e).__name__}: {e}'}
    elapsed = round(time.monotonic() - start, 2)

    if not (isinstance(result, dict) and result.get('error')):
        try:
            timing.record(check_id, params, elapsed)
        except Exception:
            # Best-effort: a timing-store hiccup (e.g. a rare SQLite lock
            # under concurrent multi-host writes) must never cost this
            # instance its actual result - the check itself already
            # succeeded above, only the adaptive-timing side record failed.
            log.error(f'{check_id}: timing.record() failed', exc_info=True)

    return result, elapsed


def _dedupe_key(host_value, seen_counts: dict) -> str:
    """host_value -> display key, suffixing repeats within the same check as
    '#2', '#3', ... so duplicate hosts don't overwrite each other in by_host."""
    key = str(host_value)
    seen_counts[key] = seen_counts.get(key, 0) + 1
    n = seen_counts[key]
    return key if n == 1 else f'{key}#{n}'


def run_instances(check_id: str, spec, instances: list[dict],
                   on_instance_done=None) -> tuple[dict, dict]:
    """
    Runs N instances of ONE check, in parallel (threading), and returns
    (results_by_key, timing_by_key).

    This is the shared execution core behind both run_checks_multi() (plain
    report building) and streaming.run_stream() (adds SSE progress events on
    top via on_instance_done) - the parallel dispatch, per-instance isolation,
    timing, and host-key dedup logic lives here exactly once.

    - `key` is instance['host'] (stringified), suffixed with '#2', '#3', ...
      on repeats within this call so duplicate hosts don't collide.
    - A single instance still goes through the same threading path (a thread
      of one), kept simple rather than special-cased, since the cost is
      negligible and it guarantees identical behavior between the 1- and
      N-instance cases.
    - A failing instance (exception in spec.func) does not block the others -
      each instance is isolated in its own try/except (see _run_one_instance).
    - timing.record() is called once per instance via _run_one_instance,
      with that instance's own params/elapsed.
    - on_instance_done(key, result, elapsed), if given, is called once per
      instance as soon as it completes (from that instance's worker thread) -
      used by streaming.run_stream() to emit a per-host SSE event without
      run_instances() itself knowing anything about SSE/queues.
    """
    results: dict = {}
    timings: dict = {}
    lock = threading.Lock()
    seen_counts: dict = {}
    threads = []

    def _worker(cid, sp, params, key, out_results, out_timing, out_lock, cb):
        result, elapsed = _run_one_instance(cid, sp, params)
        with out_lock:
            out_results[key] = result
            out_timing[key] = elapsed
        if cb is not None:
            try:
                cb(key, result, elapsed)
            except Exception:
                # A misbehaving callback (e.g. streaming's SSE emit) must not
                # take down this worker thread silently - results/timing for
                # this instance are already recorded above regardless, but an
                # uncaught exception here would otherwise propagate out of
                # the thread target and be swallowed by threading's default
                # excepthook, dropping the caller's per-instance notification
                # (e.g. streaming.run_stream()'s per-host check_done event)
                # without any visible error.
                log.error(f'{cid}: on_instance_done callback failed for {key!r}', exc_info=True)

    for instance_params in instances:
        key = _dedupe_key(instance_params.get('host', ''), seen_counts)
        t = threading.Thread(
            target=_worker,
            args=(check_id, spec, instance_params, key, results, timings, lock, on_instance_done),
            daemon=True,
        )
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    return results, timings


def run_checks_multi(selected: list[dict]) -> dict:
    """
    selected: list of {'id': 'cve', 'instances': [{'host': ..., ...}, {'host': ..., ...}]}
    or the legacy single-instance form {'id': 'cve', 'params': {'host': ..., ...}}
    (same shape run_checks() accepts — see 'instances' vs 'params' resolution
    below, fixed 2026-08-20: this function previously read only 'instances'
    and silently discarded 'params' via item.get('instances', [{}]), which
    made every check launched through web/app.py's api_run()/api_estimate()
    (built via _to_selected_item(), which emits the legacy 'params' form
    whenever the caller didn't specify 'instances') always receive params={},
    with no error raised — the underlying check function's own empty-host
    default ('host not specified') was the only visible symptom. Confirmed
    via a direct run_checks_multi() call bypassing HTTP/threading entirely,
    matching CLI's run_checks(), which already resolved 'params' first via
    item.get('params', {})).

    One instance for a check -> report['results'][check_id] / report['timing'][check_id]
    are flat, identical in shape to run_checks() (backward compatible).

    Multiple instances for a check -> executed via run_instances() (parallel):
        report['results'][check_id] = {'_multi_host': True, 'by_host': {key: result, ...}}
        report['timing'][check_id]  = {key: elapsed, ...}

    A failing instance (missing tools, exception) does not block the others -
    each instance is isolated the same way run_checks() isolates each check.

    report['total_time'] is a wall-clock approximation: for each check, the
    max elapsed among its instances (since they ran in parallel), summed
    across checks (since different checks still run one after another).
    """
    report = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'results': {},
        'timing': {},
        'meta': {},
    }

    check_max_elapsed = []  # per-check max elapsed, for total_time

    for item in selected:
        check_id = item['id']
        # 'instances' (multi-host) takes precedence when present, even if
        # empty — an explicit empty list is a deliberate "no hosts" request,
        # not a signal to fall back to 'params'. Only when 'instances' is
        # absent entirely do we resolve the legacy single-instance 'params'
        # form (or {} if neither key is present, matching run_checks()'s own
        # item.get('params', {}) default) into a one-item instances list.
        if 'instances' in item:
            instances = item['instances']
        else:
            instances = [item.get('params', {})]

        spec = registry.get(check_id)

        if spec is None:
            report['results'][check_id] = {'error': f'check {check_id} not found'}
            continue

        missing = missing_tools(spec.required_tools)
        if missing:
            report['results'][check_id] = {'error': f'missing tools: {", ".join(missing)}'}
            report['timing'][check_id] = 0.0
            continue

        report['meta'][check_id] = {'label': spec.label, 'category': spec.category}

        if len(instances) == 1:
            result, elapsed = _run_one_instance(check_id, spec, instances[0])
            report['results'][check_id] = result
            report['timing'][check_id] = elapsed
            check_max_elapsed.append(elapsed)
            continue

        by_host, by_host_timing = run_instances(check_id, spec, instances)
        report['results'][check_id] = {'_multi_host': True, 'by_host': by_host}
        report['timing'][check_id] = by_host_timing
        if by_host_timing:
            check_max_elapsed.append(max(by_host_timing.values()))

    report['total_time'] = round(sum(check_max_elapsed), 2)
    return report


def list_available() -> list[dict]:
    """List of all checks for the UI/CLI: id, label, category, params, tool availability."""
    out = []
    for spec in registry.all():
        out.append({
            'id': spec.id, 'label': spec.label, 'category': spec.category,
            'description': spec.description, 'params': spec.params,
            'required_tools': spec.required_tools,
            'missing_tools': missing_tools(spec.required_tools),
            'risk_level': spec.risk_level,
        })
    return out
