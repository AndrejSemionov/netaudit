"""
Kern Log Audit (@register orchestration): wires Discovery -> Collection ->
Parser -> Detection -> Findings into one real, SSH-connected check for
/var/log/kern.log.

This module contains NO new security logic — every decision (event
grammar, signal taxonomy, thresholds, severity, recommendation) already
lives in its own layer, tested there (kern_log_parser.py,
kern_log_detection.py, kern_log_findings.py). This file's only job is
to call each layer in order and close the one gap no other layer owns:
turning collection evidence into a CoverageStatus.

Architecturally identical in shape to checks/fail2ban_logs_audit.py
------------------------------------------------------------------
kern.log has exactly ONE fixed path (/var/log/kern.log) — no per-
server-block resolution, no Matching/dedup step, no alternative source
to fall back to. Same pipeline shape as fail2ban_logs_audit.py: probe
the one fixed path -> collect it -> derive coverage -> parse -> detect
-> find. The coverage adapter below is a DELIBERATE, INDEPENDENT COPY
of fail2ban_logs_audit.py's _source_coverage() — not shared code (same
"wait for a second/third real case before generalizing" principle
already applied throughout this project), and not imported from there.

Discovery: probe_log_file() + file_verdict(), not a full
collect_log_discovery() call — same performance rationale already
established in ssh_auth_audit.py's and fail2ban_logs_audit.py's
docstrings.

Coverage resolution (the one new piece of logic this module adds):
    collected is None (source.available was False)      -> UNKNOWN
    result.completed is False or exit_code != 0           -> FAILED
    completed=True, exit_code=0, line_count == 0            -> EMPTY
    completed=True, exit_code=0, line_count > 0               -> COMPLETE
PARTIAL is not reachable here — same reasoning as fail2ban_logs_audit.py:
exactly one fixed source, never several to aggregate.

detection_succeeded semantics: never computed independently here — it
is exactly what detect_kern_log_signals() already derives from the
coverage this module hands it (see kern_log_detection.py's own
docstring).

sudo handling: this module does NOT decide when to use sudo.
LogSource.readable/requires_sudo (set by Discovery/probe_log_file) and
collect_file()'s existing branching on those fields already handle it
— kern.log is mode 640 syslog:adm on both real hosts checked (writer
46.62.147.41 and sysadmin.courses 157.180.66.90), so collect_file()
will route through the sudo path automatically on both. Nothing
kern_log-specific is added at this layer.

Two-signal-type distinction (the one structural difference from
fail2ban_logs_audit.py, which has only one finding_type): Detection can
emit BOTH a HIGH_DROP_RATE and a PORT_SCAN signal for the same src_ip in
the same collected slice — this module does not special-case that, it
simply passes every event through Detection once and every resulting
signal through Findings once, exactly as kern_log_detection.py and
kern_log_findings.py's own contracts already specify (no merging, no
deduplication across signal types).
"""

from __future__ import annotations

from ..kern_log_detection import CoverageStatus, detect_kern_log_signals
from ..kern_log_findings import build_kern_log_findings
from ..kern_log_parser import KernLogEventType, parse_kern_log_line
from ..log_collection import collect_file
from ..log_discovery import probe_log_file
from ..registry import register
from ..ssh import HostKeyMismatchError, SSHExecutor
from .log_discovery_audit import SourceType, file_verdict

try:
    import paramiko
except ImportError:
    paramiko = None

KERN_LOG_PATH = '/var/log/kern.log'
DEFAULT_TAIL_LINES = 200


# ===========================================================================
# Coverage resolution — see module docstring for the frozen rule
# ===========================================================================

def _source_coverage(collected) -> CoverageStatus:
    """Maps a single collect_file() CollectionResult (or None, if the
    source was never even attempted — source.available was False) to a
    CoverageStatus. See module docstring — PARTIAL is not reachable here
    by construction. Deliberately independent from
    fail2ban_logs_audit.py's _source_coverage() — not shared code."""
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

def audit_kern_log(ssh: SSHExecutor, lines: int = DEFAULT_TAIL_LINES) -> dict:
    """Runs the full Kern Log Audit pipeline from an already-connected
    SSHExecutor. Does NOT open or close the SSH session itself — mirrors
    audit_fail2ban_logs()'s two-layer API."""
    evidence = probe_log_file(ssh, KERN_LOG_PATH)
    source = file_verdict(evidence, SourceType.KERN_LOG)

    collected = None
    if source.available:
        collected = collect_file(ssh, source, lines=lines)

    coverage = _source_coverage(collected)

    events = []
    if collected is not None:
        for line in collected.result.stdout.splitlines():
            if line.strip():
                events.append(parse_kern_log_line(line))

    detection_result = detect_kern_log_signals(events, coverage)
    findings = build_kern_log_findings(detection_result)

    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'ok': 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    parsed_events = sum(1 for e in events if e.event_type == KernLogEventType.NFT_DROPPED)

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
    id='kern_log_audit', label='Kernel Log Audit (SSH)', category='server',
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
    description='Analyzes kern.log for nftables packet-drop patterns (high drop rate or port-scan '
                'behavior from a single source IP). Read-only — collects a bounded tail of recent log '
                'content, never the full file.',
)
def check_kern_log_audit(host='', user='root', port=22, key_path='', password='',
                          lines=DEFAULT_TAIL_LINES) -> dict:
    """Public registry entrypoint — opens its own SSH session when run
    standalone, then delegates to audit_kern_log(). Callers that already
    hold an open SSHExecutor should call audit_kern_log(ssh) directly
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
        return audit_kern_log(ssh, lines=lines)
    finally:
        ssh.close()
