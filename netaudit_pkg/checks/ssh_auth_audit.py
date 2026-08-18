"""
Logs Audit — SSH Authentication Audit (@register orchestration): wires
Discovery -> Collection -> Parser -> Detection -> Findings into one
real, SSH-connected check. This module contains NO new security logic —
every decision (severity, thresholds, event classification, sudo vs
run, window semantics) already lives in its own layer, tested there.
This file's only job is to call each layer in order and pass its output
to the next one honestly.

Why this exists (see project session notes, Iteration 4 E2E decision)
------------------------------------------------------------------
ssh_auth_parser.py / ssh_auth_detection.py / ssh_auth_findings.py /
log_collection.py were all built and tested against mocks. That proves
each layer's internal logic is correct, but not that the orchestration
between them is wired correctly against a REAL SSH connection — the
project has a known history of Web != CLI / wiring-layer bugs that unit
tests on individual modules cannot catch. This check is that missing
integration boundary, verified live against both real project hosts
before Iteration 4 is considered fully closed.

detection_succeeded semantics
------------------------------------------------------------------
detection_succeeded (passed to ssh_auth_findings.build_findings(), see
that function's own docstring on why it must never be inferred from an
empty DetectionResult) is True here iff at least one of auth.log or the
journal produced a CONFIRMED collection result (CollectionResult.result
.completed is True) — regardless of whether that source had zero
matching lines. If auth.log is unavailable (Discovery says
available=False) AND the journal collection itself never completes
(SSH failure, timeout), there is nothing to analyze and
detection_succeeded is False — an empty result in that case must not
read as "no suspicious activity", it must read as "we could not check".

reference_year
------------------------------------------------------------------
datetime.now().year is used ONLY here, at the single legitimate "what
time is it right now" boundary for this whole pipeline — see
ssh_auth_parser.py's docstring on why reference_year is never guessed
inside the parser itself, and ssh_auth_detection.py's docstring on why
reference_time is never taken from datetime.now() inside Detection.
This check is the caller both of those functions require to supply
that value explicitly.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .log_discovery_audit import build_report
from ..log_collection import collect_file, collect_journal
from ..log_discovery import collect_log_discovery
from ..registry import register
from ..ssh import HostKeyMismatchError, SSHExecutor
from ..ssh_auth_detection import DetectionContext, apply_window, detect
from ..ssh_auth_findings import DEFAULT_POLICY, build_findings
from ..ssh_auth_parser import parse_ssh_auth_line

try:
    import paramiko
except ImportError:
    paramiko = None

JOURNAL_UNIT = 'ssh'
DEFAULT_TAIL_LINES = 200
DEFAULT_WINDOW_HOURS = 24


@register(
    id='ssh_auth_audit', label='SSH Authentication Audit (SSH)', category='server',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Host', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'User', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH port', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Key path', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Password (if not using a key)', 'default': ''},
        {'name': 'lines', 'type': 'number', 'label': 'Lines to collect per source', 'default': DEFAULT_TAIL_LINES},
        {'name': 'window_hours', 'type': 'number', 'label': 'Detection window (hours)', 'default': DEFAULT_WINDOW_HOURS},
    ],
    required_tools=[],
    risk_level='READ_ONLY',
    description='Analyzes SSH authentication activity (auth.log + journal) for repeated failures, '
                'invalid-user enumeration, distributed-source attempts, and successful logins following '
                'failures. Read-only — collects a bounded tail of recent log content, never the full file.',
)
def check_ssh_auth_audit(host='', user='root', port=22, key_path='', password='',
                          lines=DEFAULT_TAIL_LINES, window_hours=DEFAULT_WINDOW_HOURS) -> dict:
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
        # --- Discovery: find auth.log's current available/readable state ---
        discovery_evidence = collect_log_discovery(ssh)
        report = build_report(discovery_evidence)
        auth_source = next(s for s in report.fixed_sources if s.source_type.value == 'auth_log')

        # --- Collection: bounded tail from both sources, independently ---
        file_result = collect_file(ssh, auth_source, lines=lines)
        journal_result = collect_journal(ssh, JOURNAL_UNIT, lines=lines)

        file_ok = file_result is not None and file_result.result.completed
        journal_ok = journal_result.result.completed
        detection_succeeded = file_ok or journal_ok

        reference_year = datetime.now(timezone.utc).year

        # --- Parser: raw lines from whichever source(s) actually returned data ---
        events = []
        if file_ok:
            for line in file_result.result.stdout.splitlines():
                if line.strip():
                    events.append(parse_ssh_auth_line(line, reference_year=reference_year))
        if journal_ok:
            for line in journal_result.result.stdout.splitlines():
                if line.strip():
                    events.append(parse_ssh_auth_line(line, reference_year=reference_year))

        # --- Detection: window + aggregate + signal ---
        context = DetectionContext(
            reference_time=datetime.now(timezone.utc), window=timedelta(hours=window_hours),
            collection_limit=lines,
        )
        windowed = apply_window(events, context)
        detection_result = detect(windowed)

        # --- Findings: interpret facts into severity/confidence/evidence ---
        findings = build_findings(detection_result, detection_succeeded=detection_succeeded, policy=DEFAULT_POLICY)

    finally:
        ssh.close()

    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'ok': 0}
    for f in findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    return {
        'host': host,
        'findings': findings,
        'summary': counts,
        'meta': {
            'auth_log_collected': file_ok,
            'journal_collected': journal_ok,
            'events_parsed': len(events),
            'undated_event_count': detection_result.undated_event_count,
            'coverage_uncertain': detection_result.coverage_uncertain,
        },
    }
