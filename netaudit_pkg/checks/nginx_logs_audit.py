"""
Nginx Logs Audit (@register orchestration): wires Discovery -> Resolver ->
Matching -> Collection -> Parser -> Detection -> Findings into one real,
SSH-connected check, for both access.log and error.log independently.

This module contains NO new security logic — every decision (thresholds,
severity, signal taxonomy, cascade rules) already lives in its own layer,
tested there (nginx_log_resolver.py, nginx_log_matching.py,
nginx_log_collection.py, nginx_access_parser.py / nginx_error_parser.py,
nginx_access_detection.py / nginx_error_detection.py, nginx_findings.py).
This file's only job is to call each layer in order, per server block,
and to close the one gap no other layer owns: turning collection evidence
into a CoverageStatus. See "Coverage resolution" below — this is the only
new logic this module adds, and it is intentionally minimal.

Why per-directive-type, not per-server-block
------------------------------------------------------------------
nginx_access_detection.detect_access_signals() / nginx_error_detection.
detect_error_signals() are each built around ONE combined event slice and
ONE CoverageStatus for the whole run (see their own docstrings: "this
function does not re-derive coverage itself — that's the caller's
responsibility"). A host can have multiple server{} blocks, each with its
own (possibly identical, possibly distinct) access_log/error_log
directive. Per session decision, this check does NOT call Detection once
per server block — it resolves every server block's access_log
destinations first, matches + dedupes them into a set of LogSource
candidates, collects all of them, and only THEN aggregates into one
combined event list + one CoverageStatus before calling Detection once.
Same, independently, for error_log. This mirrors ssh_auth_audit.py's
"exactly one selected source" principle in spirit (Detection must not
know how many underlying sources fed it), but generalizes it to "one
AGGREGATED source" rather than "one ALTERNATIVE source", since
access_log/error_log across server blocks are not alternatives the way
auth.log/journal are — they are legitimately independent, coexisting
destinations that must all be accounted for.

Coverage resolution (the one new piece of logic this module adds)
------------------------------------------------------------------
No existing layer computes CoverageStatus from a CollectionResult — every
Detection module's docstring says so explicitly ("derived by the caller
from collection/discovery evidence"). This is that adapter, kept
deliberately minimal: it implements exactly the 5-value table already
frozen in nginx_access_detection.py's and nginx_error_detection.py's own
docstrings, nothing more.

Per-source (one NginxLogCollectionResult):
    error is not None                                  -> UNKNOWN
    result.completed is False or result.exit_code != 0  -> FAILED
    completed=True, exit_code=0, line_count == 0         -> EMPTY
    completed=True, exit_code=0, line_count > 0           -> COMPLETE
PARTIAL is not reachable from a single source — collect_file()/
CollectionResult does not track enough information to distinguish "the
whole (short) file" from "a truncated tail" (see log_collection.py's own
docstring on why `truncated` is deliberately not part of its contract).

Aggregation (N per-source statuses -> one CoverageStatus), decided this
session:
    []                          -> UNKNOWN   (nothing to collect at all)
    all sources the same status -> that status
    only COMPLETE + EMPTY mixed -> COMPLETE  (every source that returned
                                    something is fully accounted for;
                                    an empty log among several non-empty
                                    ones is not degraded coverage)
    anything else (any FAILED and/or UNKNOWN present alongside a
    different status)           -> PARTIAL   (coverage semantics, not
                                    severity semantics: PARTIAL means
                                    "part of the expected coverage was
                                    not obtained", regardless of whether
                                    the failure mode was a definite
                                    FAILED or an indeterminate UNKNOWN)

detection_succeeded semantics
------------------------------------------------------------------
Never computed independently here — it is exactly what
detect_access_signals()/detect_error_signals() already derive from the
coverage this module hands them (COMPLETE/PARTIAL/EMPTY -> True,
FAILED/UNKNOWN -> False). This module does not duplicate that table.
"""

from __future__ import annotations

from ..log_discovery import collect_log_discovery
from ..nginx_access_detection import CoverageStatus as AccessCoverageStatus
from ..nginx_access_detection import detect_access_signals
from ..nginx_access_parser import NginxAccessEventType, parse_nginx_access_line
from ..nginx_config_v2 import collect_nginx_config_v2
from ..nginx_error_detection import CoverageStatus as ErrorCoverageStatus
from ..nginx_error_detection import detect_error_signals
from ..nginx_error_parser import NginxErrorEventType, parse_nginx_error_line
from ..nginx_findings import build_access_findings, build_error_findings
from ..nginx_log_collection import NginxLogCollectionResult, collect_nginx_logs
from ..nginx_log_matching import dedupe_matches, match_log_directive
from ..nginx_log_resolver import resolve_access_log, resolve_error_log
from ..registry import register
from ..ssh import HostKeyMismatchError, SSHExecutor
from .log_discovery_audit import build_report

try:
    import paramiko
except ImportError:
    paramiko = None

DEFAULT_TAIL_LINES = 200


# ===========================================================================
# Coverage resolution — see module docstring for the frozen rule
# ===========================================================================

def _source_coverage(collected: NginxLogCollectionResult) -> str:
    """Per-source status, as one of 'complete'/'empty'/'failed'/'unknown'
    (plain strings, not either CoverageStatus enum, since this is shared
    logic feeding both the access and the error aggregation). See module
    docstring — PARTIAL is not reachable here by construction."""
    if collected.error is not None:
        return 'unknown'
    result = collected.result
    if result is None or not result.result.completed or result.result.exit_code != 0:
        return 'failed'
    if result.line_count == 0:
        return 'empty'
    return 'complete'


def _aggregate_coverage_str(statuses: list[str]) -> str:
    """N per-source statuses -> one aggregate status string. See module
    docstring for the frozen aggregation table."""
    if not statuses:
        return 'unknown'
    unique = set(statuses)
    if len(unique) == 1:
        return next(iter(unique))
    if unique == {'complete', 'empty'}:
        return 'complete'
    return 'partial'


def _resolve_access_coverage(statuses: list[str]) -> AccessCoverageStatus:
    return AccessCoverageStatus(_aggregate_coverage_str(statuses))


def _resolve_error_coverage(statuses: list[str]) -> ErrorCoverageStatus:
    return ErrorCoverageStatus(_aggregate_coverage_str(statuses))


# ===========================================================================
# Internal, reusable: takes an already-connected SSHExecutor
# ===========================================================================

def audit_nginx_logs(ssh: SSHExecutor, lines: int = DEFAULT_TAIL_LINES) -> dict:
    """Runs the full Nginx Logs Audit pipeline (access + error,
    independently) from an already-connected SSHExecutor. Does NOT open
    or close the SSH session itself — mirrors audit_nginx_hardening()'s
    two-layer API (nginx_hardening.py)."""
    cfg = collect_nginx_config_v2(ssh)
    if not cfg.installed:
        return {'installed': False}
    if not cfg.readable:
        return {'installed': True, 'error': 'nginx -T requires root — no read access to the config'}

    discovery_evidence = collect_log_discovery(ssh)
    discovery_report = build_report(discovery_evidence)
    discovered_nginx_sources = discovery_report.nginx_sources

    # --- Resolve + match + dedupe access_log and error_log destinations,
    # independently, across every server block. See module docstring,
    # "Why per-directive-type, not per-server-block".
    access_matches = [
        match_log_directive(resolve_access_log(cfg, server), discovered_nginx_sources)
        for server in cfg.servers
    ]
    error_matches = [
        match_log_directive(resolve_error_log(cfg, server), discovered_nginx_sources)
        for server in cfg.servers
    ]
    access_sources = dedupe_matches(access_matches)
    error_sources = dedupe_matches(error_matches)

    # --- Collect every deduped source, independently per directive type ---
    access_collected = collect_nginx_logs(ssh, access_sources, lines=lines)
    error_collected = collect_nginx_logs(ssh, error_sources, lines=lines)

    # --- Aggregate N sources -> one event list + one CoverageStatus, per
    # directive type. See module docstring, "Coverage resolution".
    access_events = []
    access_statuses = []
    for collected in access_collected:
        access_statuses.append(_source_coverage(collected))
        if collected.result is not None:
            for line in collected.result.result.stdout.splitlines():
                if line.strip():
                    access_events.append(parse_nginx_access_line(line))
    access_coverage = _resolve_access_coverage(access_statuses)

    error_events = []
    error_statuses = []
    for collected in error_collected:
        error_statuses.append(_source_coverage(collected))
        if collected.result is not None:
            for line in collected.result.result.stdout.splitlines():
                if line.strip():
                    error_events.append(parse_nginx_error_line(line))
    error_coverage = _resolve_error_coverage(error_statuses)

    # --- Detection + Findings, independently per directive type ---
    access_result = detect_access_signals(access_events, access_coverage)
    error_result = detect_error_signals(error_events, error_coverage)
    findings = build_access_findings(access_result) + build_error_findings(error_result)

    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'ok': 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    parsed_access_events = sum(1 for e in access_events if e.event_type == NginxAccessEventType.PARSED)
    parsed_error_events = sum(1 for e in error_events if e.event_type == NginxErrorEventType.PARSED)

    return {
        'installed': True,
        'findings': [
            {
                'finding_type': f.finding_type, 'severity': f.severity, 'confidence': f.confidence,
                'detail': f.detail, 'recommendation': f.recommendation, 'event_count': f.event_count,
            }
            for f in findings
        ],
        'summary': counts,
        'meta': {
            'access': {
                'sources_matched': len(access_sources),
                'coverage': access_coverage.value,
                'detection_succeeded': access_result.detection_succeeded,
                'events_parsed': parsed_access_events,
                'events_total': len(access_events),
            },
            'error': {
                'sources_matched': len(error_sources),
                'coverage': error_coverage.value,
                'detection_succeeded': error_result.detection_succeeded,
                'events_parsed': parsed_error_events,
                'events_total': len(error_events),
            },
        },
    }


# ===========================================================================
# Registry entrypoint
# ===========================================================================

@register(
    id='nginx_logs_audit', label='Nginx Logs Audit (SSH)', category='server',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Host', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'User', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH port', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Key path', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Password (if not using a key)', 'default': ''},
        {'name': 'lines', 'type': 'number', 'label': 'Lines to collect per source', 'default': DEFAULT_TAIL_LINES},
    ],
    required_tools=[],
    risk_level='READ_ONLY',
    description='Analyzes nginx access.log and error.log activity (rate anomalies, path scanning, '
                'request bursts, parse-failure rate, high error rate, critical errors, repeated errors) '
                'across every server block\'s resolved, deduped log destinations. Read-only — collects a '
                'bounded tail of recent log content per source, never full files.',
)
def check_nginx_logs_audit(host='', user='root', port=22, key_path='', password='',  # nosec B107 - empty default is a CLI/API parameter, not a hardcoded credential
                            lines=DEFAULT_TAIL_LINES) -> dict:
    """Public registry entrypoint — opens its own SSH session when run
    standalone, then delegates to audit_nginx_logs(). Callers that already
    hold an open SSHExecutor should call audit_nginx_logs(ssh) directly
    instead, to avoid a second SSH connection to the same host."""
    if paramiko is None:
        return {'error': 'paramiko not installed'}
    if not host:
        return {'error': 'host not specified'}

    try:
        ssh = SSHExecutor(host, user, port, key_path, password).connect()
    except HostKeyMismatchError as e:
        return {'error': str(e)}
    except Exception as e:
        return {'error': f'could not connect: {e}'}

    try:
        return audit_nginx_logs(ssh, lines=lines)
    finally:
        ssh.close()
