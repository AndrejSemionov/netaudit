"""
Adaptive timing: learns from real elapsed times and decides sync/async.
Stats storage is via storage (SQLite). Thresholds are configurable via settings.
"""

from __future__ import annotations

from . import storage

# Defaults (overridden by settings in the DB)
DEFAULT_SYNC_THRESHOLD_SEC = 2.5
DEFAULT_EMA_ALPHA = 0.4

SEED_ESTIMATES = {
    'mtr': 20.0, 'tcptraceroute': 15.0, 'ping': 4.0, 'dig': 0.5, 'arping': 6.0,
    'ssl': 1.5, 'http': 2.0, 'security_headers': 1.5, 'ports': 0.5, 'firewall': 0.3,
    'performance': 1.2, 'ssh_audit': 12.0, 'iperf': 25.0,
    'tshark_capture': 18.0, 'mikrotik_sniffer': 8.0,
    'server_audit': 15.0, 'web_security_external': 12.0, 'sql_injection': 30.0,
}
DEFAULT_SEED = 5.0
TARGET_PARAM_KEYS = ('target', 'url', 'hostname', 'host', 'server')

# Checks where duration is explicitly derivable from params (count*interval, duration, etc).
# If the explicit calc gives noticeably more time than history/seed - trust the explicit
# calc: otherwise a short history for the same target could wrongly push a long run into
# sync, and it'd hit the HTTP request timeout before it actually finishes.
def _explicit_duration(check_id: str, params: dict) -> float | None:
    if check_id == 'mtr':
        try:
            return float(params.get('duration_sec', 15))
        except (TypeError, ValueError):
            return None
    if check_id == 'mikrotik_sniffer':
        try:
            return float(params.get('duration_sec')) if params.get('duration_sec') else None
        except (TypeError, ValueError):
            return None
    if check_id == 'iperf':
        try:
            return float(params.get('duration', 10)) * 2  # upload+download
        except (TypeError, ValueError):
            return None
    if check_id == 'tshark_capture':
        try:
            return float(params.get('duration', 15))
        except (TypeError, ValueError):
            return None
    return None


def _sync_threshold() -> float:
    v = storage.setting_get('sync_threshold_sec')
    try:
        return float(v) if v is not None else DEFAULT_SYNC_THRESHOLD_SEC
    except (ValueError, TypeError):
        return DEFAULT_SYNC_THRESHOLD_SEC


def _ema_alpha() -> float:
    v = storage.setting_get('ema_alpha')
    try:
        return float(v) if v is not None else DEFAULT_EMA_ALPHA
    except (ValueError, TypeError):
        return DEFAULT_EMA_ALPHA


def _target_of(params: dict):
    for k in TARGET_PARAM_KEYS:
        if params.get(k):
            return str(params[k])
    return None


def _key(check_id: str, params: dict) -> str:
    t = _target_of(params)
    return f'{check_id}::{t}' if t else check_id


def estimate(check_id: str, params: dict) -> float:
    seed = SEED_ESTIMATES.get(check_id, DEFAULT_SEED)

    # Explicit calc from params (mtr count*interval, iperf duration, etc) - if it's
    # noticeably bigger than seed/history, trust it: the user explicitly asked for a long run.
    explicit = _explicit_duration(check_id, params)

    specific = storage.timing_get(_key(check_id, params))
    if specific is not None:
        base = specific['ema']
    else:
        per_check = storage.timing_all_for_check(check_id)
        if per_check:
            hist_avg = sum(per_check) / len(per_check)
            n = len(per_check)
            hist_weight = min(0.7, 0.25 * n)
            blended = hist_weight * hist_avg + (1 - hist_weight) * seed
            base = round(max(blended, min(seed, hist_avg)), 3)
        else:
            base = seed

    if explicit is not None:
        return max(base, explicit)
    return base


def record(check_id: str, params: dict, elapsed: float) -> None:
    key = _key(check_id, params)
    entry = storage.timing_get(key)
    alpha = _ema_alpha()
    if entry is None:
        storage.timing_upsert(key, elapsed, 1, elapsed)
    else:
        new_ema = round(alpha * elapsed + (1 - alpha) * entry['ema'], 3)
        storage.timing_upsert(key, new_ema, entry['count'] + 1, elapsed)


def decide_mode(selected: list[dict], force_async: bool = False, threshold: float | None = None):
    """
    selected items may be either:
      - {'id': ..., 'params': {...}}                  legacy, single-instance
      - {'id': ..., 'instances': [{...}, {...}, ...]}  multi-instance

    Per-check contribution to the total:
      - 'params' form   -> estimate(id, params)                       (unchanged)
      - 'instances' form -> max(estimate(id, inst) for inst in instances),
        since same-check instances run in parallel, bounded by the
        slowest one. An empty instances list contributes 0.

    total = sum of per-check contributions, since different checks in one
    request still run sequentially relative to each other.
    """
    total = 0.0
    for item in selected:
        check_id = item['id']
        if 'instances' in item:
            instance_estimates = [estimate(check_id, inst) for inst in item['instances']]
            total += max(instance_estimates) if instance_estimates else 0.0
        else:
            total += estimate(check_id, item.get('params', {}))

    if force_async:
        return 'async', round(total, 2)
    thr = threshold if threshold is not None else _sync_threshold()
    return ('sync' if total <= thr else 'async'), round(total, 2)


def stats_snapshot() -> dict:
    return storage.timing_snapshot()
