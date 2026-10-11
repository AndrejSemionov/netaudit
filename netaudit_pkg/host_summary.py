"""Read-only summary of hosts in one saved report (B2.4)."""

from __future__ import annotations

from . import trends


def _instances(report: dict, check_id: str):
    """Yield (instance_key, safe host name, result) in execution order."""
    contexts = report.get('execution_context') or {}
    results = report.get('results') or {}
    ctx = contexts.get(check_id)
    result = results.get(check_id)
    if not isinstance(ctx, dict):
        return
    multi_context = 'host' not in ctx and bool(ctx) and all(isinstance(p, dict) for p in ctx.values())
    if multi_context:
        by_host = result.get('by_host') if isinstance(result, dict) else None
        if not isinstance(by_host, dict):
            by_host = {}
        for instance_key, params in ctx.items():
            if isinstance(params, dict) and isinstance(params.get('host'), str) and params['host']:
                yield instance_key, params['host'], by_host.get(instance_key)
    elif isinstance(ctx.get('host'), str) and ctx['host']:
        yield None, ctx['host'], result


def _check_row(check_id: str, instance_key, host: str, result) -> dict:
    counts = None
    if not isinstance(result, dict):
        status = 'unknown'
    elif result.get('error'):
        status = 'error'
    else:
        scoped = trends._scoped_findings(result)
        if scoped is None:
            status = 'incomplete' if result.get('warnings') else 'unknown'
        else:
            counts = dict.fromkeys(trends.PROBLEM_SEVERITIES, 0)
            manual = False
            for findings in scoped.values():
                for finding in findings:
                    if not isinstance(finding, dict):
                        continue
                    severity = finding.get('severity')
                    if severity in counts:
                        counts[severity] += 1
                    manual |= bool(finding.get('requires_manual_verification'))
            status = 'incomplete' if manual or bool(result.get('warnings')) else 'complete'
    return {'check_id': check_id, 'instance_key': instance_key, 'host': host,
            'status': status, 'observed_counts': counts}


def compare_hosts(report: dict, check_id: str) -> dict:
    """Rows for one check only; never infer a cross-check finding delta."""
    return {'check_id': check_id,
            'hosts': [_check_row(check_id, key, host, result)
                      for key, host, result in _instances(report, check_id)]}


def host_summary(report: dict) -> dict:
    """One row per real host, with observed counts and collection gaps."""
    by_host = {}
    for check_id in (report.get('execution_context') or {}):
        for row in compare_hosts(report, check_id)['hosts']:
            by_host.setdefault(row['host'], []).append(row)

    hosts = []
    for host, checks in by_host.items():
        occurrences = {}
        for check in checks:
            cid = check['check_id']
            occurrences[cid] = occurrences.get(cid, 0) + 1
        duplicates = list(dict.fromkeys(
            check['check_id'] for check in checks if occurrences[check['check_id']] > 1))
        unique = [check for check in checks if occurrences[check['check_id']] == 1]
        comparable = [check['observed_counts'] for check in unique
                      if check['observed_counts'] is not None]
        counts = ({severity: sum(c[severity] for c in comparable)
                   for severity in trends.PROBLEM_SEVERITIES} if comparable else None)
        errors = list(dict.fromkeys(c['check_id'] for c in checks if c['status'] == 'error'))
        incomplete = list(dict.fromkeys(c['check_id'] for c in checks if c['status'] == 'incomplete'))
        unknown = list(dict.fromkeys(c['check_id'] for c in checks if c['status'] == 'unknown'))
        hosts.append({
            'host': host,
            'completed_checks': sum(c['status'] in ('complete', 'incomplete') for c in unique),
            'errored_checks': len(errors),
            'observed_counts': counts,
            'error_checks': errors,
            'incomplete_checks': incomplete,
            'unknown_checks': unknown,
            'duplicate_checks': duplicates,
            'checks': checks,
        })
    return {'hosts': hosts}
