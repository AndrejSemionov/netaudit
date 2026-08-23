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
empty DetectionResult) is True iff a source was actually selected (see
"Source selection" below) and its collection completed. If neither
auth.log nor the journal produces a usable result, there is nothing to
analyze and detection_succeeded is False — an empty result in that case
must not read as "no suspicious activity", it must read as "we could
not check".

Source selection (fixed after a real E2E bug — see project session
notes, 2026-08-18)
------------------------------------------------------------------
auth.log and journalctl -u ssh are ALTERNATIVES, never concatenated.
Earlier versions of this check collected both sources independently and
parsed all their lines into one combined event stream — on
192.168.88.20, where journald forwards the exact same sshd events
already present in auth.log, this double-counted every real event (a
single "Failed password" line was seen once via auth.log and once via
journalctl, producing failed_password_count=2 for one actual failure).

Per Analysis Contract v3 (auth.log is the primary source for SSH
authentication analysis when it exists and contains events; journal is
optional/best-effort), this check now selects exactly ONE source per
run:
  1. If Discovery reports auth.log as available, try collect_file() on
     it. If that collection completes, auth.log IS the selected source
     — journal is never also collected in this case.
  2. Only if auth.log is unavailable, or its collection did not
     complete, is journalctl -u ssh attempted as a fallback.
  3. If neither produces a completed result, no source is selected and
     detection_succeeded is False.

This is deliberately NOT deduplication — merging two sources' events by
matching timestamp/pid/content was considered and rejected (see project
session notes): it would require inventing an identity-matching
contract with real risk of silently discarding genuinely distinct
events, for a problem source selection already solves more safely.
Cross-source correlation/deduplication remains a possible future
mechanism, but is explicitly out of scope for this check.

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

from .log_discovery_audit import SourceType, file_verdict
from ..log_collection import collect_file, collect_journal
from ..log_discovery import probe_log_file
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
AUTH_LOG_PATH = '/var/log/auth.log'
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
    description='Analyzes SSH authentication activity (auth.log, with journal as fallback when auth.log is '
                'unavailable) for repeated failures, invalid-user enumeration, distributed-source attempts, '
                'and successful logins following failures. Read-only — collects a bounded tail of recent log '
                'content, never the full file. Sources are alternatives, never combined.',
)
def check_ssh_auth_audit(host='', user='root', port=22, key_path='', password='',  # nosec B107 - empty default is a CLI/API parameter, not a hardcoded credential
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
        # Single reference point for the whole pipeline — see this
        # module's docstring, "reference_year": every time-dependent
        # value downstream (parser's reference_year, Detection's
        # reference_time) must derive from ONE now() call taken here,
        # not be independently re-queried at each step. Two separate
        # datetime.now() calls could in principle disagree (however
        # unlikely in practice) and would violate the same
        # caller-determines-it-once principle already enforced for
        # reference_year in ssh_auth_parser.py and reference_time in
        # ssh_auth_detection.py.
        reference_time = datetime.now(timezone.utc)
        reference_year = reference_time.year

        # --- Discovery: targeted probe of auth.log ONLY — not full-host
        # discovery. See log_discovery.probe_log_file()'s docstring: this
        # check previously called collect_log_discovery() (which also
        # globs every nginx log file, checks journal state, logrotate.d
        # configs, and five other fixed sources this check never uses)
        # just to learn auth.log's availability. Confirmed wasteful in
        # practice — the nginx glob alone accounted for most of a ~45s
        # run on 46.62.147.41. probe_log_file() + file_verdict() give
        # the exact same LogSource verdict for auth.log without any of
        # that unrelated work.
        auth_log_evidence = probe_log_file(ssh, AUTH_LOG_PATH)
        auth_source = file_verdict(auth_log_evidence, SourceType.AUTH_LOG)

        # --- Collection: try the primary FILE source first, journal only as fallback ---
        # Sources are ALTERNATIVES, not additive evidence — see this
        # module's docstring on the real E2E bug (project session notes)
        # this fixed: 192.168.88.20's journal duplicates auth.log content
        # (same sshd events, forwarded to journald), so concatenating both
        # streams double-counted every failure. auth.log is preferred
        # per Analysis Contract v3 (it's the primary source for SSH
        # authentication analysis when it exists and contains events);
        # journalctl -u ssh is used ONLY when the primary file source is
        # unavailable, never alongside it.
        file_result = None
        journal_result = None
        selected_source = 'none'
        fallback_used = False

        if auth_source.available:
            file_result = collect_file(ssh, auth_source, lines=lines)
            if file_result is not None and file_result.result.completed:
                selected_source = 'file'

        if selected_source == 'none':
            journal_result = collect_journal(ssh, JOURNAL_UNIT, lines=lines)
            if journal_result.result.completed:
                selected_source = 'journal'
                fallback_used = auth_source.available  # only a "fallback" if file was tried and failed

        file_ok = selected_source == 'file'
        journal_ok = selected_source == 'journal'
        detection_succeeded = file_ok or journal_ok

        # --- Parser: raw lines from the single selected source ---
        events = []
        source_stdout = None
        if file_ok:
            source_stdout = file_result.result.stdout
        elif journal_ok:
            source_stdout = journal_result.result.stdout

        if source_stdout is not None:
            for line in source_stdout.splitlines():
                if line.strip():
                    events.append(parse_ssh_auth_line(line, reference_year=reference_year))

        # --- Detection: window + aggregate + signal ---
        context = DetectionContext(
            reference_time=reference_time, window=timedelta(hours=window_hours),
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

    if selected_source == 'file':
        selection_reason = 'primary file source (auth.log) available'
    elif selected_source == 'journal' and fallback_used:
        selection_reason = 'primary file source (auth.log) unavailable or failed to collect; journal fallback used'
    elif selected_source == 'journal':
        selection_reason = 'journal source used (auth.log was not reported available by Discovery)'
    else:
        selection_reason = 'no usable SSH authentication source (auth.log unavailable and journal collection failed)'

    return {
        'host': host,
        'findings': findings,
        'summary': counts,
        'meta': {
            'selected_source': selected_source,
            'fallback_used': fallback_used,
            'selection_reason': selection_reason,
            'events_parsed': len(events),
            'undated_event_count': detection_result.undated_event_count,
            'coverage_uncertain': detection_result.coverage_uncertain,
        },
    }
