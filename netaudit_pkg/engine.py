"""Engine: runs the selected checks with their params, times each one."""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager, nullcontext
from datetime import datetime

# importing registers all the checks
from . import (
    checks,  # noqa: F401
    timing,
)
from .redaction import redact_params
from .registry import registry
from .utils import log, missing_tools

DEFAULT_MAX_PARALLEL = 4
MAX_PARALLEL_LIMIT = 16
PROCESS_MAX_PARALLEL = 8
MAX_INSTANCES_PER_CHECK = 64
MAX_INSTANCES_PER_REQUEST = 256
NOT_STARTED_ERROR = 'not started: the run was stopped'


class _CancelledBeforeStart(Exception):
    """A waiting Web worker was stopped before its check started."""


def validate_multi_request(selected: list[dict], max_parallel: int = DEFAULT_MAX_PARALLEL) -> None:
    """Reject oversized requests before any check has side effects."""
    if type(max_parallel) is not int or not 1 <= max_parallel <= MAX_PARALLEL_LIMIT:
        raise ValueError(f'max_parallel must be an integer from 1 to {MAX_PARALLEL_LIMIT}')
    total = 0
    for item in selected:
        instances = item['instances'] if 'instances' in item else [item.get('params', {})]
        if len(instances) > MAX_INSTANCES_PER_CHECK:
            raise ValueError(f'too many instances for {item["id"]}: limit {MAX_INSTANCES_PER_CHECK}')
        total += len(instances)
        if total > MAX_INSTANCES_PER_REQUEST:
            raise ValueError(f'too many instances in request: limit {MAX_INSTANCES_PER_REQUEST}')


class _ProcessSlots:
    """Round-robin Web slots: one waiting worker per run gets each free slot."""

    def __init__(self):
        self.cv = threading.Condition()
        self.active = 0
        self.queue = []
        self.waiting = {}
        self.grants = {}

    def _dispatch(self):
        while self.active < PROCESS_MAX_PARALLEL and self.queue:
            run = self.queue.pop(0)
            self.waiting[run] -= 1
            self.grants[run] = self.grants.get(run, 0) + 1
            self.active += 1
            if self.waiting[run]:
                self.queue.append(run)
            else:
                del self.waiting[run]
        self.cv.notify_all()

    @contextmanager
    def slot(self, run, cancelled: threading.Event | None = None):
        with self.cv:
            if cancelled is not None and cancelled.is_set():
                raise _CancelledBeforeStart
            if run not in self.waiting:
                self.waiting[run] = 0
                self.queue.append(run)
            self.waiting[run] += 1
            self._dispatch()
            while not self.grants.get(run):
                if cancelled is not None and cancelled.is_set():
                    self.waiting[run] -= 1
                    if not self.waiting[run]:
                        del self.waiting[run]
                        self.queue.remove(run)
                    self._dispatch()
                    raise _CancelledBeforeStart
                self.cv.wait(0.05 if cancelled is not None else None)
            self.grants[run] -= 1
            if not self.grants[run]:
                del self.grants[run]
            if cancelled is not None and cancelled.is_set():
                self.active -= 1
                self._dispatch()
                raise _CancelledBeforeStart
        try:
            yield
        finally:
            with self.cv:
                self.active -= 1
                self._dispatch()


_process_slots = _ProcessSlots()


def execution_slot(run, cancelled: threading.Event | None = None):
    """Shared Web process slot around one active check instance."""
    return _process_slots.slot(run, cancelled)


def run_checks(selected: list[dict]) -> dict:
    """
    selected: list of {'id': 'mtr', 'params': {'target': '8.8.8.8', 'count': 15}}
    Returns a report with the elapsed time of each check.
    """
    report = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),  # noqa: DTZ005 - report history uses local naive timestamps for ordering
        'results': {},
        'timing': {},
        'meta': {},
        'execution_context': {},
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
        except Exception as e:  # noqa: BLE001 - isolate arbitrary registered check failures
            result = {'error': f'exception: {type(e).__name__}: {e}'}
        elapsed = round(time.monotonic() - start, 2)

        # feed the adaptive timing system with real elapsed time (successful runs
        # only, so a tool error doesn't skew the estimate)
        if not (isinstance(result, dict) and result.get('error')):
            timing.record(check_id, params, elapsed)

        report['results'][check_id] = result
        report['timing'][check_id] = elapsed
        report['meta'][check_id] = {'label': spec.label, 'category': spec.category}
        # execution_context records the fact of the attempt (params actually
        # passed to spec.func), independent of whether the call succeeded -
        # a check that raised still had its params recorded here, matching
        # the frozen Report Identity / Execution Context Contract v1 (see
        # docs/research/ai_analysis_17_research_summary.md for why this
        # exists: params were previously discarded after spec.func() consumed
        # them, making history/trend features across reports impossible).
        # secret params (password) are passed to the check but never recorded
        report['execution_context'][check_id] = redact_params(params)

    report['total_time'] = round(sum(report['timing'].values()), 2)
    return report


def _run_one_instance(check_id: str, spec, params: dict) -> tuple[dict, float]:
    """Runs a single check instance, returns (result, elapsed). Mirrors the
    try/except + timing.record() behavior of run_checks()'s inner loop."""
    log.info(f'Running: {spec.label} ({check_id})...')
    start = time.monotonic()
    try:
        result = spec.func(**params)
    except Exception as e:  # noqa: BLE001 - isolate arbitrary registered check failures
        result = {'error': f'exception: {type(e).__name__}: {e}'}
    elapsed = round(time.monotonic() - start, 2)

    if not (isinstance(result, dict) and result.get('error')):
        try:
            timing.record(check_id, params, elapsed)
        except Exception:  # noqa: BLE001 - timing is best-effort after a successful check
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
                   on_instance_done=None, *, max_parallel: int = DEFAULT_MAX_PARALLEL,
                   shared_pool: bool = False, run_token=None,
                   cancelled: threading.Event | None = None) -> tuple[dict, dict]:
    """
    Runs N instances of ONE check with at most max_parallel workers, and returns
    (results_by_key, timing_by_key).

    This is the shared execution core behind both run_checks_multi() (plain
    report building) and streaming.run_stream() (adds SSE progress events on
    top via on_instance_done) - the parallel dispatch, per-instance isolation,
    timing, and host-key dedup logic lives here exactly once.

    - `key` is instance['host'] (stringified), suffixed with '#2', '#3', ...
      on repeats within this call so duplicate hosts don't collide.
    - Waiting instances remain in the input list; they do not create threads.
      Web workers also acquire one of the shared process slots.
    - A failing instance (exception in spec.func) does not block the others -
      each instance is isolated in its own try/except (see _run_one_instance).
    - timing.record() is called once per instance via _run_one_instance,
      with that instance's own params/elapsed.
    - on_instance_done(key, result, elapsed), if given, is called once per
      instance as soon as it completes (from that instance's worker thread) -
      used by streaming.run_stream() to emit a per-host SSE event without
      run_instances() itself knowing anything about SSE/queues.
    """
    validate_multi_request([{'id': check_id, 'instances': instances}], max_parallel)
    seen_counts: dict = {}
    keys = [_dedupe_key(p.get('host', ''), seen_counts) for p in instances]
    pending = object()
    results_by_index: list = [pending] * len(instances)
    timings_by_index: list = [pending] * len(instances)
    next_index = 0
    lock = threading.Lock()
    threads = []
    token = run_token if run_token is not None else object()

    def _worker():
        nonlocal next_index
        while True:
            with lock:
                if next_index == len(instances) or (cancelled is not None and cancelled.is_set()):
                    return
                index = next_index
                next_index += 1
            slot = execution_slot(token, cancelled) if shared_pool else nullcontext()
            try:
                with slot:
                    if cancelled is not None and cancelled.is_set():
                        return
                    result, elapsed = _run_one_instance(check_id, spec, instances[index])
            except _CancelledBeforeStart:
                return
            results_by_index[index] = result
            timings_by_index[index] = elapsed
            if on_instance_done is not None:
                try:
                    on_instance_done(keys[index], result, elapsed)
                except Exception:  # noqa: BLE001 - callback failure must not hide check results
                    log.error('%s: on_instance_done callback failed for %r',
                              check_id, keys[index], exc_info=True)

    worker_count = min(len(instances), max_parallel,
                       PROCESS_MAX_PARALLEL if shared_pool else max_parallel)
    for _ in range(worker_count):
        t = threading.Thread(target=_worker, daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    for index, result in enumerate(results_by_index):
        if result is pending:
            if cancelled is None or not cancelled.is_set():
                raise RuntimeError(f'{check_id}: worker did not return instance {index}')
            skipped = {'error': NOT_STARTED_ERROR}
            results_by_index[index] = skipped
            timings_by_index[index] = 0.0
            if on_instance_done is not None:
                try:
                    on_instance_done(keys[index], skipped, 0.0)
                except Exception:  # noqa: BLE001 - callback failure must not hide skipped hosts
                    log.error('%s: on_instance_done callback failed for %r',
                              check_id, keys[index], exc_info=True)

    return (dict(zip(keys, results_by_index, strict=True)),
            dict(zip(keys, timings_by_index, strict=True)))


def run_checks_multi(selected: list[dict], *, max_parallel: int = DEFAULT_MAX_PARALLEL,
                     shared_pool: bool = False) -> dict:
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

    report['total_time'] approximates elapsed time from bounded groups of
    instances, summed across sequential checks. Per-instance timings exclude
    queue wait and timing-store overhead.
    """
    validate_multi_request(selected, max_parallel)
    run_token = object()
    report = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),  # noqa: DTZ005 - report history uses local naive timestamps for ordering
        'results': {},
        'timing': {},
        'meta': {},
        'execution_context': {},
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
            slot = execution_slot(run_token) if shared_pool else nullcontext()
            with slot:
                result, elapsed = _run_one_instance(check_id, spec, instances[0])
            report['results'][check_id] = result
            report['timing'][check_id] = elapsed
            # Flat shape, matching run_checks() - single instance means
            # execution_context[check_id] is the params dict directly, not
            # a {key: params} map (see Contract v1 docstring above).
            report['execution_context'][check_id] = redact_params(instances[0])
            check_max_elapsed.append(elapsed)
            continue

        if max_parallel == DEFAULT_MAX_PARALLEL and not shared_pool:
            # Keep the original positional call for existing callers that
            # wrap run_instances(); CLI's default behavior is otherwise the
            # same as passing both defaults explicitly.
            by_host, by_host_timing = run_instances(check_id, spec, instances)
        else:
            by_host, by_host_timing = run_instances(
                check_id, spec, instances, max_parallel=max_parallel,
                shared_pool=shared_pool, run_token=run_token)
        report['results'][check_id] = {'_multi_host': True, 'by_host': by_host}
        report['timing'][check_id] = by_host_timing
        # execution_context uses the SAME dedup keying run_instances() uses
        # internally for by_host (host value, '#2'/'#3' suffixed on repeats)
        # - computed independently here via the same _dedupe_key() helper,
        # in the same instances-list order, so keys line up 1:1 with by_host
        # without depending on dict ordering across the two calls.
        seen_counts: dict = {}
        report['execution_context'][check_id] = {
            _dedupe_key(inst.get('host', ''), seen_counts): redact_params(inst) for inst in instances
        }
        if by_host_timing:
            values = list(by_host_timing.values())
            width = min(max_parallel, PROCESS_MAX_PARALLEL) if shared_pool else max_parallel
            check_max_elapsed.append(sum(
                max(values[i:i + width]) for i in range(0, len(values), width)))

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
