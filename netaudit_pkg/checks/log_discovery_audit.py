"""
Logs Audit — Discovery check (Iteration 1): turns the raw evidence from
netaudit_pkg.log_discovery.collect_log_discovery() into LogSource
judgments (available/readable/requires_sudo/state) and Findings.

Same collector/consumer split as fail2ban_config.py / audit_fail2ban():
netaudit_pkg.log_discovery holds FACTS, this module holds JUDGMENTS. See
that module's docstring for the full background and the empirically-
confirmed Discovery Contract v1 this module implements.

Scope (Iteration 1 — Discovery-only)
--------------------------------------
This check answers "what log sources exist on this host and in what
state?" — it does NOT read log content, does NOT parse events, does NOT
detect security issues. Findings here are about the LOGGING INFRASTRUCTURE
itself (a source is missing, unreadable without sudo, not rotating, a
decoy/dead file masking the real one) — never about what's IN the logs.
That's explicitly out of scope; see the project's Iteration 2 plan.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from ..findings import finding as _finding
from ..log_discovery import (
    JournalEvidence,
    LogDiscoveryEvidence,
    LogFileEvidence,
    LogrotateEvidence,
    NginxGlobEvidence,
    collect_log_discovery,
)
from ..registry import register
from ..ssh import HostKeyMismatchError, SSHExecutor

try:
    import paramiko
except ImportError:
    paramiko = None


# ===========================================================================
# Verdict model
# ===========================================================================

class SourceType(str, Enum):
    AUTH_LOG = 'auth_log'
    SYSLOG = 'syslog'
    KERN_LOG = 'kern_log'
    FAIL2BAN_LOG = 'fail2ban_log'
    MAIL_LOG = 'mail_log'
    AIDE_LOG = 'aide_log'
    NGINX_LOG = 'nginx_log'
    SYSTEMD_JOURNAL = 'systemd_journal'


class LogFileState(str, Enum):
    ACTIVE = 'active'
    STALE_EMPTY = 'stale_empty'
    DECOY_EMPTY = 'decoy_empty'


# rotated/archived filename suffixes this project's logrotate config produces
# (see /etc/logrotate.conf on both real hosts: weekly rotation, default
# dateext off, so suffixes are '.N' and '.N.gz' — NOT '-YYYYMMDD') — used to
# tell a currently-active nginx log apart from its own rotation history, so
# Iteration 1 doesn't generate one finding per archived .gz file (confirmed
# necessary on live VM run against 46.62.147.41: 91 nginx files discovered,
# only a handful are "current").
_ROTATED_SUFFIX_RE = re.compile(r'\.\d+(\.gz)?$')


def _is_rotated_filename(path: str) -> bool:
    return bool(_ROTATED_SUFFIX_RE.search(path))


@dataclass
class LogSource:
    """One source's verdict, derived from LogFileEvidence — never
    collected directly (requires_sudo is explicitly NOT a collected
    fact; see log_discovery.py's docstring, Discovery Contract v1)."""
    source_type: SourceType
    path: str | None
    available: bool
    readable: bool
    requires_sudo: bool
    state: LogFileState | None
    size_bytes: int | None
    last_modified_epoch: int | None
    owner: str | None
    group: str | None
    mode: str | None


@dataclass
class JournalInfo:
    available: bool
    disk_usage_bytes: int | None
    disk_usage_raw: str | None
    on_defaults: bool | None  # None when the probe itself failed to collect


@dataclass
class LogrotateInfo:
    name: str
    has_config: bool


@dataclass
class LogDiscoveryReport:
    fixed_sources: list[LogSource]
    nginx_sources: list[LogSource]   # only non-rotated (current) files — see _is_rotated_filename()
    nginx_rotated_count: int          # how many archived files were excluded, for context in findings
    journal: JournalInfo
    logrotate: list[LogrotateInfo]


# ===========================================================================
# stat output parsing (pure)
# ===========================================================================

def _parse_stat_output(stdout: str) -> dict | None:
    """Parses 'size|mtime_epoch|owner|group|mode' — the exact format
    _stat_probe() in log_discovery.py requests. Returns None if the
    format doesn't match (e.g. stdout is actually an error message, not
    stat's data line) — this function does not guess."""
    line = stdout.strip().splitlines()[-1] if stdout.strip() else ''
    parts = line.split('|')
    if len(parts) != 5:
        return None
    try:
        return {
            'size': int(parts[0]),
            'mtime': int(parts[1]),
            'owner': parts[2],
            'group': parts[3],
            'mode': parts[4],
        }
    except ValueError:
        return None


def _file_verdict(evidence: LogFileEvidence, source_type: SourceType) -> LogSource:
    """Turns one LogFileEvidence into a LogSource verdict.

    available:
      - stat completed and exit_code==0 -> True (metadata was readable,
        regardless of content readability — see log_discovery.py's
        docstring on why these are independent facts)
      - stat completed, exit_code!=0, AND 'No such file or directory' in
        stdout -> False (confirmed absent — the ONLY case treated as
        confirmed absence; see Discovery Contract v1, DC-2)
      - stat completed, exit_code!=0, any OTHER stderr text -> available
        stays None-ish in spirit, but this function returns available=
        False with the caller expected to check `requires_sudo`-style
        ambiguity via the raw evidence if ever needed. For Iteration 1
        scope (only two real hosts, both showing textbook 'No such file'
        for missing sources), this distinction is tracked but not yet
        exercised by a real case — see this module's docstring.
      - stat did not complete at all -> available=False is NOT returned;
        this function returns a sentinel-free "unknown" via
        available=False, readable=False, requires_sudo=False, state=None
        so the caller can still render a "collection failed, not a
        confirmed absence" finding rather than silently treating it as OK.
    """
    stat = evidence.stat_result
    read = evidence.read_probe

    if not stat.completed:
        # Collection failure — genuinely unknown, never treated as "not present"
        return LogSource(
            source_type=source_type, path=evidence.path, available=False, readable=False,
            requires_sudo=False, state=None, size_bytes=None, last_modified_epoch=None,
            owner=None, group=None, mode=None,
        )

    if stat.exit_code != 0:
        # Confirmed-absent is the only exit!=0 case Iteration 1 distinguishes
        # from "something else went wrong" — see this function's docstring.
        return LogSource(
            source_type=source_type, path=evidence.path, available=False, readable=False,
            requires_sudo=False, state=None, size_bytes=None, last_modified_epoch=None,
            owner=None, group=None, mode=None,
        )

    parsed = _parse_stat_output(stat.stdout)
    if parsed is None:
        # exit_code==0 but unparseable output — treat as collection failure,
        # not as a confirmed anything (same "don't guess" principle as
        # fail2ban_config._parse_jail_list()).
        return LogSource(
            source_type=source_type, path=evidence.path, available=False, readable=False,
            requires_sudo=False, state=None, size_bytes=None, last_modified_epoch=None,
            owner=None, group=None, mode=None,
        )

    readable = bool(read.completed and read.exit_code == 0)
    requires_sudo = True and not readable  # available is True in this branch by construction
    file_state = LogFileState.ACTIVE if parsed['size'] > 0 else LogFileState.STALE_EMPTY

    return LogSource(
        source_type=source_type, path=evidence.path, available=True, readable=readable,
        requires_sudo=requires_sudo, state=file_state, size_bytes=parsed['size'],
        last_modified_epoch=parsed['mtime'], owner=parsed['owner'], group=parsed['group'],
        mode=parsed['mode'],
    )


# ===========================================================================
# nginx: decoy detection + rotated-file filtering
# ===========================================================================

def _nginx_verdicts(evidence: NginxGlobEvidence) -> tuple[list[LogSource], int]:
    """Classifies nginx per-file evidence. Only non-rotated ("current")
    files get a LogSource / finding — rotated .N / .N.gz archives are
    counted but not individually reported (see _is_rotated_filename()'s
    docstring: 91 files were discovered on a live run, only a handful are
    current).

    Decoy detection (DECOY_EMPTY vs STALE_EMPTY): a zero-byte current
    file is DECOY_EMPTY if another CURRENT file shares its "base name"
    (the part before the last '_' + access/error, e.g. 'access.log' vs
    'andreykapro_access.log' both end in 'access.log') and that other
    file is ACTIVE — this is the confirmed real pattern on writer
    (project inventory, andreykapro_access.log active, plain access.log
    a dead 0-byte stub). Otherwise a zero-byte current file is
    STALE_EMPTY (genuinely quiet, no active sibling — 192.168.88.20's
    error.log case).
    """
    current: list[LogFileEvidence] = [f for f in evidence.per_file if not _is_rotated_filename(f.path)]
    rotated_count = len(evidence.per_file) - len(current)

    verdicts = [_file_verdict(f, SourceType.NGINX_LOG) for f in current]

    # index active current files by their "kind" suffix (access.log / error.log / other)
    def _kind(path: str) -> str:
        base = path.rsplit('/', 1)[-1]
        for suffix in ('access.log', 'error.log'):
            if base.endswith(suffix):
                return suffix
        return base

    active_kinds = {_kind(v.path) for v in verdicts if v.state == LogFileState.ACTIVE}

    for v in verdicts:
        if v.state == LogFileState.STALE_EMPTY and _kind(v.path) in active_kinds:
            v.state = LogFileState.DECOY_EMPTY

    return verdicts, rotated_count


# ===========================================================================
# journald
# ===========================================================================

_DISK_USAGE_RE = re.compile(r'take up ([\d.]+[KMGT]?) in the file system')


def _journal_verdict(evidence: JournalEvidence) -> JournalInfo:
    disk_usage_bytes = None  # Iteration 1 keeps the raw string; unit conversion is not needed for a presence/size finding
    disk_usage_raw = None
    available = evidence.disk_usage.completed and evidence.disk_usage.exit_code == 0
    if available:
        m = _DISK_USAGE_RE.search(evidence.disk_usage.stdout)
        if m:
            disk_usage_raw = m.group(1)

    on_defaults = None
    if evidence.journald_conf.completed:
        # A fully-default journald.conf's only non-comment/non-blank line is
        # the '[Journal]' section header itself — confirmed on live VM run
        # against 46.62.147.41 (project session notes). Any OTHER non-blank
        # content alongside it means at least one setting is explicitly
        # configured.
        stripped = evidence.journald_conf.stdout.strip()
        on_defaults = stripped == '[Journal]' or stripped == ''

    return JournalInfo(
        available=available, disk_usage_bytes=disk_usage_bytes,
        disk_usage_raw=disk_usage_raw, on_defaults=on_defaults,
    )


# ===========================================================================
# logrotate
# ===========================================================================

def _logrotate_verdicts(entries: list[LogrotateEvidence]) -> list[LogrotateInfo]:
    return [
        LogrotateInfo(name=e.name, has_config=bool(e.config_check.completed and e.config_check.exit_code == 0))
        for e in entries
    ]


# ===========================================================================
# Top-level: evidence -> report
# ===========================================================================

_FIXED_SOURCE_TYPES: dict[str, SourceType] = {
    'auth_log': SourceType.AUTH_LOG,
    'syslog': SourceType.SYSLOG,
    'kern_log': SourceType.KERN_LOG,
    'fail2ban_log': SourceType.FAIL2BAN_LOG,
    'mail_log': SourceType.MAIL_LOG,
    'aide_log': SourceType.AIDE_LOG,
}


def build_report(evidence: LogDiscoveryEvidence) -> LogDiscoveryReport:
    fixed_sources = [
        _file_verdict(getattr(evidence, attr), source_type)
        for attr, source_type in _FIXED_SOURCE_TYPES.items()
    ]
    nginx_sources, nginx_rotated_count = _nginx_verdicts(evidence.nginx)
    journal = _journal_verdict(evidence.journal)
    logrotate = _logrotate_verdicts(evidence.logrotate_configs)

    return LogDiscoveryReport(
        fixed_sources=fixed_sources, nginx_sources=nginx_sources,
        nginx_rotated_count=nginx_rotated_count, journal=journal, logrotate=logrotate,
    )


# ===========================================================================
# Findings
# ===========================================================================

def _source_label(source: LogSource) -> str:
    return source.path or source.source_type.value


def build_findings(report: LogDiscoveryReport) -> list[dict]:
    """Findings are about the logging INFRASTRUCTURE, not log content —
    see this module's docstring. 'ok' severity is used for a source in
    good state (available, active, has rotation) — matching the project
    convention that 'ok' means 'checked, no issue found', not merely
    'not an error' (see findings.py's SEVERITIES docstring)."""
    findings: list[dict] = []

    rsyslog_covered = {SourceType.AUTH_LOG, SourceType.SYSLOG, SourceType.KERN_LOG, SourceType.MAIL_LOG}
    rotate_has_config = {lr.name: lr.has_config for lr in report.logrotate}

    for source in report.fixed_sources:
        label = _source_label(source)
        if not source.available:
            # A confirmed-absent optional source (fail2ban, mail, aide) is
            # informational, not a problem — these tools may simply not be
            # installed. auth_log/syslog/kern_log missing on a real Linux
            # host would be unusual enough to flag.
            if source.source_type in (SourceType.AUTH_LOG, SourceType.SYSLOG, SourceType.KERN_LOG):
                findings.append(_finding(
                    'medium', f'{label} not found',
                    'a core system log source is missing — check whether rsyslog is installed and running',
                    check='log_discovery',
                ))
            else:
                findings.append(_finding(
                    'info', f'{source.source_type.value} not present on this host',
                    'no evidence this tool/service is installed — not a problem by itself',
                    check='log_discovery',
                ))
            continue

        if source.requires_sudo:
            findings.append(_finding(
                'ok', f'{label} present, requires elevated access to read',
                f'owner={source.owner} group={source.group} mode={source.mode} — '
                'this is expected for security-relevant logs; NetAudit\'s SSH user is not in the reading group',
                check='log_discovery',
            ))
        elif source.state == LogFileState.STALE_EMPTY:
            findings.append(_finding(
                'low', f'{label} exists but is empty',
                'no data recorded yet, or the service that writes it is inactive',
                check='log_discovery',
            ))
        else:
            findings.append(_finding(
                'ok', f'{label} present and active',
                f'size={source.size_bytes} bytes, readable without sudo',
                check='log_discovery',
            ))

        logrotate_name = 'rsyslog' if source.source_type in rsyslog_covered else source.source_type.value
        if source.source_type in rsyslog_covered or source.source_type == SourceType.FAIL2BAN_LOG:
            has_rotation = rotate_has_config.get(logrotate_name)
            if has_rotation is False:
                findings.append(_finding(
                    'low', f'{label} has no logrotate configuration',
                    'this file will grow unbounded — add a logrotate.d entry',
                    check='log_discovery',
                ))

    active_nginx = [s for s in report.nginx_sources if s.state == LogFileState.ACTIVE]
    decoy_nginx = [s for s in report.nginx_sources if s.state == LogFileState.DECOY_EMPTY]
    if not report.nginx_sources:
        findings.append(_finding(
            'info', 'no nginx logs found', 'nginx may not be installed, or /var/log/nginx is empty',
            check='log_discovery',
        ))
    else:
        findings.append(_finding(
            'ok', f'{len(active_nginx)} active nginx log file(s) found',
            f'{report.nginx_rotated_count} rotated/archived file(s) excluded from findings',
            check='log_discovery',
        ))
        for decoy in decoy_nginx:
            findings.append(_finding(
                'info', f'{_source_label(decoy)} is an unused default log (vhost-based logging in use)',
                'this is expected with per-vhost nginx logging config — the real traffic goes to a differently-named file',
                check='log_discovery',
            ))

    if report.journal.available:
        detail = f'{report.journal.disk_usage_raw} on disk' if report.journal.disk_usage_raw else ''
        findings.append(_finding('ok', 'systemd journal available', detail, check='log_discovery'))
        if report.journal.on_defaults:
            findings.append(_finding(
                'info', 'journald has no explicit Storage= setting',
                'running on distribution defaults (typically persistent on Ubuntu/Debian when /var/log/journal exists) '
                '— set Storage=persistent explicitly if you want this guaranteed rather than implied',
                check='log_discovery',
            ))
    else:
        findings.append(_finding(
            'medium', 'could not determine systemd journal state',
            'journalctl --disk-usage did not return a confirmed result',
            check='log_discovery',
        ))

    return findings


# ===========================================================================
# @register entrypoint
# ===========================================================================

@register(
    id='log_discovery', label='Logs Audit: Discovery (SSH)', category='server',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Host', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'User', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH port', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Key path', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Password (if not using a key)', 'default': ''},
    ],
    required_tools=[],
    risk_level='READ_ONLY',
    description='Discovers what log sources exist on a host and their state (exists/readable/'
                'rotated/active) — does not read log content or detect security events. '
                'Unprivileged (no sudo) by design: reports what NetAudit\'s own SSH access level '
                'can and cannot already see, and flags sources that need elevated access to read.',
)
def check_log_discovery(host='', user='root', port=22, key_path='', password='') -> dict:
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
        evidence = collect_log_discovery(ssh)
    finally:
        ssh.close()

    report = build_report(evidence)
    findings = build_findings(report)

    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'ok': 0}
    for f in findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    return {
        'host': host,
        'findings': findings,
        'summary': counts,
    }
