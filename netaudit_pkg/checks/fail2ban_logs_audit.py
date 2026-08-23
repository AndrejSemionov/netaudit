"""
Fail2Ban Logs Audit (@register orchestration): wires Discovery ->
Collection -> Parser -> Detection -> Findings into one real,
SSH-connected check for /var/log/fail2ban.log.

This module contains NO new security logic — every decision (event
grammar, signal taxonomy, severity, recommendation) already lives in its
own layer, tested there (fail2ban_parser.py, fail2ban_detection.py,
fail2ban_findings.py). This file's only job is to call each layer in
order and close the one gap no other layer owns: turning collection
evidence into a CoverageStatus.

NOT to be confused with checks/server_security.py's audit_fail2ban()
------------------------------------------------------------------
audit_fail2ban() (in server_security.py, part of check_server_audit())
is a DIFFERENT, pre-existing check — it queries fail2ban-client / a
status-only wrapper for CURRENT JAIL STATUS (is fail2ban running, which
jails are configured, how many IPs currently banned). This module is
about LOG CONTENT — what fail2ban actually did over time, per
fail2ban.log. Same relationship as nginx_hardening.py (config quality)
vs nginx_logs_audit.py (log content) — two independent contours, never
merged, never sharing a finding namespace.

Why this is architecturally simpler than nginx_logs_audit.py
------------------------------------------------------------------
fail2ban.log has exactly ONE fixed path (/var/log/fail2ban.log) — no
per-server-block resolution, no Matching/dedup step (those exist for
nginx because access_log/error_log destinations are configurable and
can appear in multiple server blocks; fail2ban.log has neither
property). It also has no alternative source the way ssh_auth_audit.py
has auth.log-vs-journal — there is nothing to fall back to if the file
is unavailable. This means: probe the one fixed path -> collect it ->
derive coverage -> parse -> detect -> find. No aggregation across
multiple sources is needed at any step.

Discovery: probe_log_file() + file_verdict(), not a full
collect_log_discovery() call — same performance rationale already
established in ssh_auth_audit.py's docstring (a full Discovery run also
globs every nginx log file, checks journal state, logrotate.d configs,
etc., none of which this check needs just to learn fail2ban.log's
availability).

Coverage resolution (the one new piece of logic this module adds)
------------------------------------------------------------------
No existing layer computes CoverageStatus from a CollectionResult —
fail2ban_detection.py's own docstring says so explicitly ("derived by
the caller from collection/discovery evidence"). This adapter is a
deliberately independent copy of the same reasoning already used in
nginx_logs_audit.py's _source_coverage() — not shared code (same
"wait for a second/third real case before generalizing" principle
already applied throughout this project) — but simplified further,
since there is exactly one source here, never several to aggregate:

    result is None (collect_file() returned nothing — source.available
                     was False)                       -> UNKNOWN
    result.completed is False or exit_code != 0        -> FAILED
    completed=True, exit_code=0, line_count == 0        -> EMPTY
    completed=True, exit_code=0, line_count > 0          -> COMPLETE

PARTIAL is not reachable here at all — unlike nginx_logs_audit.py, there
is no multi-source aggregation step that could ever produce it. This
check has only ever ONE fixed source, so the aggregation table nginx
needs (several statuses -> one) does not apply; this adapter maps
directly from one CollectionResult (or its absence) to one
CoverageStatus, with only 4 of the 5 possible enum values ever actually
produced.

detection_succeeded semantics
------------------------------------------------------------------
Never computed independently here — it is exactly what
detect_fail2ban_signals() already derives from the coverage this module
hands it (COMPLETE/PARTIAL/EMPTY -> True, FAILED/UNKNOWN -> False; see
fail2ban_detection.py's own docstring). This module does not duplicate
that table, and in practice PARTIAL never occurs per the point above.

sudo handling
------------------------------------------------------------------
This module does NOT decide when to use sudo. LogSource.readable /
requires_sudo (set by Discovery/probe_log_file) and collect_file()'s
existing branching on those fields already handle it — fail2ban.log is
mode 640 root:adm (confirmed empirically on the writer host, see
project session notes), so collect_file() will route through the sudo
path automatically. Nothing fail2ban-specific is added at this layer.
"""

from __future__ import annotations

from ..fail2ban_detection import CoverageStatus, detect_fail2ban_signals
from ..fail2ban_findings import build_fail2ban_findings
from ..fail2ban_parser import Fail2BanEventType, parse_fail2ban_line
from ..log_collection import collect_file
from ..log_discovery import probe_log_file
from ..registry import register
from ..ssh import HostKeyMismatchError, SSHExecutor
from .log_discovery_audit import SourceType, file_verdict

try:
    import paramiko
except ImportError:
    paramiko = None

FAIL2BAN_LOG_PATH = '/var/log/fail2ban.log'
DEFAULT_TAIL_LINES = 200


# ===========================================================================
# Coverage resolution — see module docstring for the frozen rule
# ===========================================================================

def _source_coverage(collected) -> CoverageStatus:
    """Maps a single collect_file() CollectionResult (or None, if the
    source was never even attempted — source.available was False) to a
    CoverageStatus. See module docstring — PARTIAL is not reachable here
    by construction."""
    if collected is None:
        return CoverageStatus.UNKNOWN
    result = collected.result
    if not result.completed or result.exit_code != 0:
        return CoverageStatus.FAILED
    if collected.line_count == 0:
        return CoverageStatus.EMPTY
    return CoverageStatus.COMPLETE


# ===========================================================================
# Internal, reusable: takes an already-connected SSHExecutor
# ===========================================================================

def audit_fail2ban_logs(ssh: SSHExecutor, lines: int = DEFAULT_TAIL_LINES) -> dict:
    """Runs the full Fail2Ban Logs Audit pipeline from an already-
    connected SSHExecutor. Does NOT open or close the SSH session itself
    — mirrors audit_nginx_logs()'s two-layer API."""
    evidence = probe_log_file(ssh, FAIL2BAN_LOG_PATH)
    source = file_verdict(evidence, SourceType.FAIL2BAN_LOG)

    collected = None
    if source.available:
        collected = collect_file(ssh, source, lines=lines)

    coverage = _source_coverage(collected)

    events = []
    if collected is not None:
        for line in collected.result.stdout.splitlines():
            if line.strip():
                events.append(parse_fail2ban_line(line))

    detection_result = detect_fail2ban_signals(events, coverage)
    findings = build_fail2ban_findings(detection_result)

    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'ok': 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    parsed_events = sum(1 for e in events if e.event_type not in (
        Fail2BanEventType.UNKNOWN, Fail2BanEventType.UNKNOWN_MESSAGE,
    ))

    return {
        'available': source.available,
        'findings': [
            {
                'finding_type': f.finding_type, 'severity': f.severity, 'confidence': f.confidence,
                'detail': f.detail, 'recommendation': f.recommendation, 'event_count': f.event_count,
            }
            for f in findings
        ],
        'summary': counts,
        'meta': {
            'coverage': coverage.value,
            'detection_succeeded': detection_result.detection_succeeded,
            'events_parsed': parsed_events,
            'events_total': len(events),
        },
    }


# ===========================================================================
# Registry entrypoint
# ===========================================================================

@register(
    id='fail2ban_logs_audit', label='Fail2Ban Logs Audit (SSH)', category='server',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Host', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'User', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH port', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Key path', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Password (if not using a key)', 'default': ''},
        {'name': 'lines', 'type': 'number', 'label': 'Lines to collect', 'default': DEFAULT_TAIL_LINES},
    ],
    required_tools=[],
    risk_level='READ_ONLY',
    description='Analyzes fail2ban.log for ban activity (which IPs were actually banned, in which jail). '
                'Read-only — collects a bounded tail of recent log content, never the full file. Distinct '
                'from the fail2ban jail-status check (current configuration/state) — this check is about '
                'what fail2ban has actually done, per its own log.',
)
def check_fail2ban_logs_audit(host='', user='root', port=22, key_path='', password='',  # nosec B107 - empty default is a CLI/API parameter, not a hardcoded credential
                               lines=DEFAULT_TAIL_LINES) -> dict:
    """Public registry entrypoint — opens its own SSH session when run
    standalone, then delegates to audit_fail2ban_logs(). Callers that
    already hold an open SSHExecutor should call audit_fail2ban_logs(ssh)
    directly instead, to avoid a second SSH connection to the same host."""
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
        return audit_fail2ban_logs(ssh, lines=lines)
    finally:
        ssh.close()
