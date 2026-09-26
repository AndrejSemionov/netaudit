"""
Deterministic trend layer: how the state of one audited object changed
across saved reports - without an LLM.

Full rationale and the frozen contract: docs/research/trend_layer_research_summary.md.

A trend unit is (check_id, identity key, identity value), taken from the
report's execution_context (flat or multi-host shape, same identity keys as
storage.find_related_reports()). Each report contributes one snapshot per
unit; compute_trend() turns a unit's snapshots into points plus the change
between the last two successful runs.

Finding-level diff (new / resolved / persisting) is by explicit finding `id`
only. Many checks build titles with volatile values ("files changed: 5"),
so title matching would report "resolved + new" every time a number moves -
findings without an `id` count toward severity totals and nothing else.
"""

from __future__ import annotations

from . import storage

# 'ok' (checked, no issue) and 'info' (neutral observation) are not problems -
# counting them would make a run where more checks passed look worse.
PROBLEM_SEVERITIES = ('critical', 'high', 'medium', 'low')


def _result_param_pairs(check_id: str, ctx: dict, results: dict) -> list[tuple[dict, dict]]:
    """(params, result) for each instance of one check, for both
    execution_context shapes (see storage.identity_pairs())."""
    result = results.get(check_id)
    if not isinstance(result, dict) or not isinstance(ctx, dict):
        return []
    if result.get('_multi_host'):
        by_host = result.get('by_host') or {}
        return [(params, by_host[host_key]) for host_key, params in ctx.items()
                if isinstance(params, dict) and isinstance(by_host.get(host_key), dict)]
    return [(ctx, result)]


def _snapshot(check_id: str, key: str, value, timestamp: str, result: dict) -> dict | None:
    base = {'check_id': check_id, 'key': key, 'value': value, 'timestamp': timestamp}
    if result.get('error'):
        return {**base, 'error': result['error'], 'counts': None,
                'hardening_score': None, 'finding_ids': {}}

    findings = result.get('findings')
    hardening = result.get('hardening')
    score = hardening.get('score') if isinstance(hardening, dict) else None
    if not isinstance(findings, list) and score is None:
        return None  # metric-style result (ping, mtr, ...) - out of scope for v1

    counts = dict.fromkeys(PROBLEM_SEVERITIES, 0)
    finding_ids = {}
    for f in findings or []:
        if not isinstance(f, dict) or f.get('severity') not in PROBLEM_SEVERITIES:
            continue
        counts[f['severity']] += 1
        if f.get('id'):
            finding_ids[f['id']] = f['severity']
    return {**base, 'error': None, 'counts': counts,
            'hardening_score': score, 'finding_ids': finding_ids}


def snapshots_from_report(report: dict) -> list[dict]:
    """One snapshot per (check_id, identity pair) present in `report`."""
    results = report.get('results') or {}
    timestamp = report.get('timestamp')
    out = []
    for check_id, ctx in (report.get('execution_context') or {}).items():
        for params, result in _result_param_pairs(check_id, ctx, results):
            for key, value in params.items():
                if key not in storage.IDENTITY_PARAM_KEYS:
                    continue
                snap = _snapshot(check_id, key, value, timestamp, result)
                if snap:
                    out.append(snap)
    return out


def _point(snap: dict) -> dict:
    counts = snap['counts']
    return {
        'timestamp': snap['timestamp'],
        'error': snap['error'],
        'counts': counts,
        'total': sum(counts.values()) if counts is not None else None,
        'hardening_score': snap['hardening_score'],
    }


def _change(prev: dict, cur: dict) -> dict:
    prev_ids, cur_ids = set(prev['finding_ids']), set(cur['finding_ids'])
    counts_delta = {s: cur['counts'][s] - prev['counts'][s] for s in PROBLEM_SEVERITIES}
    score_delta = None
    if prev['hardening_score'] is not None and cur['hardening_score'] is not None:
        score_delta = cur['hardening_score'] - prev['hardening_score']
    return {
        'from': prev['timestamp'],
        'to': cur['timestamp'],
        'counts_delta': counts_delta,
        'total_delta': sum(counts_delta.values()),
        'score_delta': score_delta,
        'new': sorted(cur_ids - prev_ids),
        'resolved': sorted(prev_ids - cur_ids),
        'persisting': sorted(prev_ids & cur_ids),
    }


def compute_trend(snapshots: list[dict]) -> dict:
    """Trend of ONE unit from its snapshots, oldest first.

    latest_change compares the last two non-error snapshots (an errored run
    says nothing about the object's state); None when there are fewer than two.
    """
    first = snapshots[0]
    good = [s for s in snapshots if s['error'] is None]
    return {
        'check_id': first['check_id'],
        'key': first['key'],
        'value': first['value'],
        'points': [_point(s) for s in snapshots],
        'latest_change': _change(good[-2], good[-1]) if len(good) >= 2 else None,
    }
