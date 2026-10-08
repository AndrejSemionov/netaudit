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
EVENT_CHECK_IDS = frozenset({
    'ssh_auth_audit', 'nginx_logs_audit', 'kern_log_audit', 'fail2ban_logs_audit',
})
_USABLE_COVERAGE = frozenset({'complete', 'partial', 'empty'})


def _kind(check_id: str) -> str:
    return 'event_observation' if check_id in EVENT_CHECK_IDS else 'state'


def _observation(check_id: str, result: dict, params: dict) -> tuple[dict, bool]:
    """Safe collection summary, without raw log lines or subject identifiers.

    The boolean says whether observed counts are meaningful. Missing metadata
    in old reports is different from an explicit failed collection: preserve
    the former's findings, but never turn the latter into a false zero.
    """
    meta = result.get('meta')
    meta = meta if isinstance(meta, dict) else {}
    obs = {
        'source': None, 'coverage': None, 'access_coverage': None,
        'error_coverage': None, 'events_parsed': None, 'events_total': None,
        'requested_lines': params.get('lines'),
        'window_hours': params.get('window_hours'),
        'tail_limit_reached': None, 'label': 'coverage unknown',
    }

    if check_id == 'ssh_auth_audit':
        source = meta.get('selected_source')
        obs['source'] = source if source in ('file', 'journal', 'none') else None
        obs['events_parsed'] = meta.get('events_parsed')
        obs['tail_limit_reached'] = meta.get('coverage_uncertain')
        if source == 'none' or ('selected_source' in meta and source not in ('file', 'journal')):
            obs['label'] = 'no usable source'
            return obs, False
        if source in ('file', 'journal'):
            obs['label'] = 'bounded tail, limit reached' if meta.get('coverage_uncertain') else 'bounded tail'
        return obs, True

    if check_id == 'nginx_logs_audit':
        access = meta.get('access') if isinstance(meta.get('access'), dict) else {}
        error = meta.get('error') if isinstance(meta.get('error'), dict) else {}
        statuses = tuple(v if isinstance(v, str) else None
                         for v in (access.get('coverage'), error.get('coverage')))
        obs['source'] = 'nginx access/error logs'
        obs['access_coverage'], obs['error_coverage'] = statuses
        for field in ('events_parsed', 'events_total'):
            values = (access.get(field), error.get(field))
            numbers = [v for v in values if type(v) is int]
            obs[field] = sum(numbers) if numbers else None
        if 'access' not in meta and 'error' not in meta:
            return obs, True  # older report, coverage was not recorded
        if not any(status in _USABLE_COVERAGE for status in statuses):
            obs['label'] = 'neither contour usable'
            return obs, False
        obs['label'] = ('partial, lower bound' if any(status not in ('complete', 'empty')
                                               for status in statuses)
                        else 'complete for collected slices')
        return obs, True

    raw_coverage = meta.get('coverage')
    coverage = raw_coverage if isinstance(raw_coverage, str) else None
    obs['source'] = 'fail2ban.log' if check_id == 'fail2ban_logs_audit' else 'kern.log'
    obs['coverage'] = coverage
    obs['events_parsed'] = meta.get('events_parsed')
    obs['events_total'] = meta.get('events_total')
    if coverage is None and 'coverage' not in meta:
        return obs, True  # old reports may have valid findings without metadata
    obs['label'] = {
        'complete': 'complete for collected slice',
        'partial': 'partial, lower bound',
        'empty': 'empty log',
        'failed': 'collection failed',
        'unknown': 'collection unknown',
    }.get(coverage, 'collection unknown')
    return obs, coverage in _USABLE_COVERAGE and meta.get('detection_succeeded') is not False


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


def _scoped_findings(result: dict) -> dict[str, list] | None:
    """Findings grouped by scope: '' for a flat result, the section name for a
    sectioned one (server_audit: {'sections': {name: {'findings': [...]}}}).
    Top-level findings win - a result is never counted twice. None when the
    result has neither shape."""
    findings = result.get('findings')
    if isinstance(findings, list):
        return {'': findings}
    sections = result.get('sections')
    if isinstance(sections, dict) and sections and all(isinstance(s, dict) for s in sections.values()):
        return {name: s['findings'] if isinstance(s.get('findings'), list) else []
                for name, s in sections.items()}
    return None


def _snapshot(check_id: str, key: str, value, timestamp: str, result: dict,
              params: dict | None = None) -> dict | None:
    base = {'check_id': check_id, 'key': key, 'value': value, 'timestamp': timestamp}
    event = check_id in EVENT_CHECK_IDS
    observation, usable = _observation(check_id, result, params or {}) if event else (None, True)
    if result.get('error'):
        return {**base, 'error': result['error'], 'counts': None,
                'hardening_score': None, 'finding_ids': {}, 'scopes': {},
                'unverified': None, 'observation': observation}

    scoped = _scoped_findings(result)
    hardening = result.get('hardening')
    score = hardening.get('score') if isinstance(hardening, dict) else None
    if scoped is None and score is None:
        return None  # metric-style result (ping, mtr, ...) - out of scope for v1
    if scoped is None:
        scoped = {'': []}

    counts = dict.fromkeys(PROBLEM_SEVERITIES, 0)
    finding_ids = {}
    # per scope: its ids and how many problems it could not verify - a
    # "could not determine / no access" finding means that scope's missing
    # ids were not evaluated, not fixed (Contract v1.2)
    scopes = {name: {'ids': [], 'unverified': 0} for name in scoped}
    for name, findings in scoped.items():
        for f in findings:
            if not isinstance(f, dict) or f.get('severity') not in PROBLEM_SEVERITIES:
                continue
            counts[f['severity']] += 1
            if f.get('requires_manual_verification'):
                scopes[name]['unverified'] += 1
            if f.get('id'):
                finding_ids[f['id']] = f['severity']
                scopes[name]['ids'].append(f['id'])
    return {**base, 'error': None, 'counts': counts if usable else None, 'hardening_score': score,
            'finding_ids': finding_ids, 'scopes': scopes,
            'unverified': sum(s['unverified'] for s in scopes.values()),
            'observation': observation}


_COMPARED_FIELDS = ('error', 'counts', 'hardening_score', 'finding_ids', 'scopes', 'unverified', 'observation')


def _one_per_unit(instances: list[dict]) -> dict:
    """Collapse several instances of one unit from the SAME report (a host
    listed twice, or one host audited on two ports) into one snapshot.

    Identical instances -> that snapshot. Differing ones -> an "ambiguous:"
    snapshot with no counts/score/ids: picking one instance would hide the
    other's result, and merging counts of findings without an id cannot be
    done honestly. Like an errored run it is shown but never compared
    (Contract v1.1)."""
    first = instances[0]
    if all(all(i[f] == first[f] for f in _COMPARED_FIELDS) for i in instances[1:]):
        return first
    return {**first,
            'error': f'ambiguous: {len(instances)} instances of this unit '
                     f'with different results in one report',
            'counts': None, 'hardening_score': None, 'finding_ids': {},
            'scopes': {}, 'unverified': None, 'observation': None}


def snapshots_from_report(report: dict) -> list[dict]:
    """At most one snapshot per (check_id, identity pair) in `report`."""
    results = report.get('results') or {}
    timestamp = report.get('timestamp')
    by_unit: dict[tuple, list[dict]] = {}
    for check_id, ctx in (report.get('execution_context') or {}).items():
        for params, result in _result_param_pairs(check_id, ctx, results):
            for key, value in params.items():
                if key not in storage.IDENTITY_PARAM_KEYS:
                    continue
                snap = _snapshot(check_id, key, value, timestamp, result, params)
                if snap:
                    by_unit.setdefault((check_id, key, value), []).append(snap)
    return [_one_per_unit(instances) for instances in by_unit.values()]


def _point(snap: dict) -> dict:
    counts = snap['counts']
    point = {
        'timestamp': snap['timestamp'],
        'error': snap['error'],
        'counts': counts,
        'total': sum(counts.values()) if counts is not None else None,
        'hardening_score': snap['hardening_score'],
        'unverified': snap.get('unverified'),
    }
    if snap['check_id'] in EVENT_CHECK_IDS:
        point['observation'] = snap.get('observation')
    return point


def _was_evaluated(fid: str, prev: dict, cur: dict) -> bool:
    """True if `cur` fully evaluated the scope `fid` belonged to in `prev`:
    that scope is present in `cur` and has no finding requiring manual
    verification. Snapshots without scope data (hand-built, pre-v1.2 shape)
    count as one fully evaluated scope."""
    prev_scope = next((name for name, s in (prev.get('scopes') or {}).items()
                       if fid in s['ids']), '')
    cur_scopes = cur.get('scopes')
    if cur_scopes is None:
        return True
    scope = cur_scopes.get(prev_scope)
    return scope is not None and scope['unverified'] == 0


def _change(prev: dict, cur: dict) -> dict:
    prev_ids, cur_ids = set(prev['finding_ids']), set(cur['finding_ids'])
    counts_delta = {s: cur['counts'][s] - prev['counts'][s] for s in PROBLEM_SEVERITIES}
    score_delta = None
    if prev['hardening_score'] is not None and cur['hardening_score'] is not None:
        score_delta = cur['hardening_score'] - prev['hardening_score']
    gone = prev_ids - cur_ids
    # a missing id is "resolved" only where the latest run could actually
    # look; otherwise it was not evaluated (Contract v1.2, tri-state)
    not_evaluated = {fid for fid in gone if not _was_evaluated(fid, prev, cur)}
    return {
        'from': prev['timestamp'],
        'to': cur['timestamp'],
        'counts_delta': counts_delta,
        'total_delta': sum(counts_delta.values()),
        'score_delta': score_delta,
        'new': sorted(cur_ids - prev_ids),
        'resolved': sorted(gone - not_evaluated),
        'persisting': sorted(prev_ids & cur_ids),
        'not_evaluated': sorted(not_evaluated),
    }


def compute_trend(snapshots: list[dict]) -> dict:
    """Trend of ONE unit from its snapshots, oldest first.

    State checks compare the last two successful snapshots; event-log checks
    only show bounded observations and never infer state changes.
    """
    first = snapshots[0]
    kind = _kind(first['check_id'])
    good = [s for s in snapshots if s['error'] is None and s['counts'] is not None]
    return {
        'check_id': first['check_id'],
        'key': first['key'],
        'value': first['value'],
        'kind': kind,
        'points': [_point(s) for s in snapshots],
        'latest_change': _change(good[-2], good[-1]) if kind == 'state' and len(good) >= 2 else None,
    }


def _all_snapshots(window: int) -> list[dict]:
    """Snapshots from the latest `window` reports, oldest first."""
    snaps = []
    for report in reversed(storage.recent_report_data(window)):
        snaps.extend(snapshots_from_report(report))
    return snaps


def trend_for(check_id: str, key: str, value, window: int = storage.RELATED_REPORTS_SEARCH_WINDOW) -> dict | None:
    """Trend of one unit over the latest `window` reports; None if the unit
    has no snapshots in that window."""
    snaps = [s for s in _all_snapshots(window)
             if (s['check_id'], s['key'], s['value']) == (check_id, key, value)]
    return compute_trend(snaps) if snaps else None


def list_units(window: int = storage.RELATED_REPORTS_SEARCH_WINDOW) -> list[dict]:
    """Every trend unit seen in the latest `window` reports, with its run
    count and last run timestamp - most recently run first."""
    units: dict[tuple, dict] = {}
    for s in _all_snapshots(window):
        unit = units.setdefault((s['check_id'], s['key'], s['value']), {
            'check_id': s['check_id'], 'key': s['key'], 'value': s['value'], 'runs': 0,
            'kind': _kind(s['check_id']),
        })
        unit['runs'] += 1
        unit['last_timestamp'] = s['timestamp']
    return sorted(units.values(), key=lambda u: u['last_timestamp'] or '', reverse=True)


_CHANGE_ID_LISTS = ('new', 'resolved', 'persisting', 'not_evaluated')


def trend_context(report: dict, report_id: int | None = None,
                  window: int = storage.RELATED_REPORTS_SEARCH_WINDOW,
                  max_units: int = 20, max_ids: int = 20) -> list[dict]:
    """Deterministic change since the previous run of each object in `report`,
    for the AI prompt (Contract v1.2, 2b.3).

    History is only what was saved strictly before `report` (exact
    `report_id` when known - storage.report_data_before()), and `report`'s own
    snapshot is the `to` side. An object is included only when that gives a
    previous -> this-run latest_change: an errored run, a first run and
    event-log observations (latest_change is always None) are left out.
    Id lists longer than `max_ids` are cut, with `<list>_omitted` counts."""
    current = [s for s in snapshots_from_report(report) if s['error'] is None]
    if not current or max_units <= 0:
        return []
    history = []
    for past in reversed(storage.report_data_before(report, report_id, window)):
        history.extend(snapshots_from_report(past))

    items = []
    for snap in current:
        unit = (snap['check_id'], snap['key'], snap['value'])
        change = compute_trend([s for s in history if (s['check_id'], s['key'], s['value']) == unit]
                               + [snap])['latest_change']
        if change is None:
            continue
        for name in _CHANGE_ID_LISTS:
            if len(change[name]) > max_ids:
                change[f'{name}_omitted'] = len(change[name]) - max_ids
                change[name] = change[name][:max_ids]
        items.append({'check_id': unit[0], 'key': unit[1], 'value': unit[2], 'latest_change': change})
        if len(items) >= max_units:
            break
    return items
