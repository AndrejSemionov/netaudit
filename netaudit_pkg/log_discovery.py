"""
Logs Audit — Discovery collector: the single place that runs `stat` and
`test -r` (and journal/logrotate probes) over SSH for every known log
source on a host, returning structured, uninterpreted evidence.

Deliberately data-only, same split as firewall_config.py/sql_config.py/
fail2ban_config.py: this module holds FACTS (what a command's stdout/exit
code actually were), never judgments (no available/readable/requires_sudo
verdict here). That judgment belongs to the consumer
(checks/log_discovery_audit.py) — collect once, interpret separately,
from the same evidence.

Scope (Iteration 1 — Discovery-only, see project session notes)
------------------------------------------------------------------
This module answers "what log sources exist on this host and in what
state?" — it does NOT read log content, does NOT parse events, does NOT
detect anything security-relevant. That is explicitly out of scope for
this iteration; see Iteration 2 (collection + one parser + one detection
group) in the project's session notes.

Why two separate probes per file (stat + test -r)
------------------------------------------------------
Empirically confirmed on two real hosts (46.62.147.41 as `andreykapro`,
192.168.88.20 as `netaudit`; neither user is in the `adm` group; project
session notes, 2026-08-18): `stat -c '%s|%Y|%U|%G|%a' /var/log/auth.log`
returns exit_code=0 with full metadata even though the file is `640
syslog:adm` and neither user can read its CONTENT. This is because stat
only needs execute (traversal) permission on the parent directory
(/var/log is 755 on both hosts) — it does not need read permission on
the file's own data. So "can I see this file's metadata" and "can I read
this file's content" are two independent facts, not one derived from the
other. `available` (does the file exist, what does stat say about it) and
`readable` (can THIS user read its content, via `test -r`) are therefore
collected as two separate CommandResults per file — see LogFileEvidence.
`requires_sudo` is NOT collected as a fact; it's a derived semantic field
(available and not readable) computed by the consumer, not by this module
— see checks/log_discovery_audit.py.

A `stat` exit_code != 0 must NOT be assumed to mean "file does not
exist" — that's only true for the specific case of "No such file or
directory" in stderr. A permission-denied *on the parent directory
itself* would also produce a nonzero exit code with different stderr
text, and collapsing both into the same available=False verdict would be
wrong. This module collects stderr alongside exit_code precisely so the
consumer can make that distinction instead of guessing from the exit
code alone — see CommandResult.

Reused vs local primitives
-----------------------------
netaudit_pkg.ssh_utils.run_command_with_exit_code() (shared with
cve_audit.py, firewall_config.py, sql_config.py, fail2ban_config.py) is
reused directly for every probe in this module — none of them need sudo
(discovery is deliberately unprivileged; that's the whole point of
separately tracking `readable`).

CommandResult is intentionally NOT imported from fail2ban_config.py /
firewall_config.py / sql_config.py, and not hoisted into a shared module
— same reasoning as those three modules give for each other: the
extraction is a separate, later architectural change, not something to
mix into this collector's own contract/tests/implementation pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .ssh import SSHExecutor
from .ssh_utils import run_command_with_exit_code

# ===========================================================================
# Evidence data model
# ===========================================================================


@dataclass
class CommandResult:
    """Uninterpreted evidence from running one command with exit-code
    recovery. Same completed/exit_code/stdout contract as
    fail2ban_config.CommandResult/firewall_config.CommandResult/
    sql_config.CommandResult — see any of those for the full semantics.
    completed=False means the command's completion could not be confirmed
    at all (SSH channel drop, timeout, truncated output before the
    completion marker was written) — exit_code is always None in that
    case, and stdout/stderr must NOT be treated as a confirmed result of
    any kind. completed=True means the command ran to completion and
    reported an exit code through the normal channel.

    stderr is collected (unlike the other *_config.py collectors' minimal
    CommandResult) specifically so the consumer can distinguish "No such
    file or directory" (genuinely absent) from other nonzero-exit
    failure text (e.g. a permission problem on the parent directory) —
    see this module's docstring, "A `stat` exit_code != 0 must NOT be
    assumed to mean file does not exist".
    """
    completed: bool
    exit_code: int | None
    stdout: str
    stderr: str
    command: str


@dataclass
class LogFileEvidence:
    """Raw stat + readability evidence for one candidate log file path.
    Both probes are collected unconditionally and independently — see
    this module's docstring for why stat succeeding says nothing about
    read_probe, and vice versa. Neither probe uses sudo; see
    checks/log_discovery_audit.py for how the semantic layer turns this
    into available/readable/requires_sudo."""
    path: str
    stat_result: CommandResult
    read_probe: CommandResult


@dataclass
class NginxGlobEvidence:
    """Result of globbing /var/log/nginx for *.log* files, plus raw
    per-file evidence for each match. The glob itself is collected as a
    CommandResult (not just a parsed list) so a collection failure on the
    glob (e.g. /var/log/nginx doesn't exist at all) is visible as its own
    fact, distinct from "nginx directory exists but is empty". Whether
    each matched file is 'active' vs a 'decoy' (see project session notes
    — writer's vhost-split access.log stub vs andreykapro_access.log) is
    a semantic-layer judgment, not decided here — this module only
    reports what find(1) returned and what stat/test -r said about each
    result."""
    glob_result: CommandResult
    per_file: list[LogFileEvidence] = field(default_factory=list)


@dataclass
class JournalEvidence:
    """Raw systemd-journald evidence: disk usage (parses to a size) and
    the journald.conf contents (to check for an explicit Storage=
    setting — absence means "on defaults", not "not persistent"; see
    project session notes on writer's journald.conf having zero active
    settings while still being persistent by default on Ubuntu)."""
    disk_usage: CommandResult
    journald_conf: CommandResult


@dataclass
class LogrotateEvidence:
    """Raw evidence of whether a given source has a logrotate.d config
    file. has_config is collected as a simple presence probe
    (test -f .../logrotate.d/<name>) — this module does not parse the
    config's contents."""
    name: str
    config_check: CommandResult


@dataclass
class LogDiscoveryEvidence:
    """All raw discovery facts collected from one host. The consumer
    (checks/log_discovery_audit.py) is solely responsible for turning
    this into LogSource objects with available/readable/requires_sudo/
    state judgments and findings — same collector/consumer split as
    fail2ban_config.Fail2banEvidence / audit_fail2ban()."""
    auth_log: LogFileEvidence
    syslog: LogFileEvidence
    kern_log: LogFileEvidence
    fail2ban_log: LogFileEvidence
    mail_log: LogFileEvidence
    aide_log: LogFileEvidence
    nginx: NginxGlobEvidence
    journal: JournalEvidence
    logrotate_configs: list[LogrotateEvidence] = field(default_factory=list)


# ===========================================================================
# Fixed file-source paths (Iteration 1 scope — see this module's docstring)
# ===========================================================================

# name -> (path, logrotate.d config filename or None if not applicable)
_FIXED_FILE_SOURCES: dict[str, tuple[str, str | None]] = {
    'auth_log': ('/var/log/auth.log', 'rsyslog'),  # covered by the rsyslog logrotate config, not its own
    'syslog': ('/var/log/syslog', 'rsyslog'),
    'kern_log': ('/var/log/kern.log', 'rsyslog'),
    'fail2ban_log': ('/var/log/fail2ban.log', 'fail2ban'),
    'mail_log': ('/var/log/mail.log', 'rsyslog'),
    'aide_log': ('/var/log/aide/aide.log', None),  # confirmed no dedicated logrotate.d/aide entry on either real host
}

NGINX_LOG_DIR = '/var/log/nginx'


# ===========================================================================
# Low-level probes (pure command construction + exit-code recovery)
# ===========================================================================

def _run(ssh: SSHExecutor, cmd: str, timeout: int) -> CommandResult:
    """Runs `cmd` unprivileged via run_command_with_exit_code() and wraps
    the result as a CommandResult. stderr is not separately recoverable
    through run_command_with_exit_code()'s stdout-only marker scheme, so
    stderr is always '' here — this is a known, deliberate limitation
    (see the module docstring on ssh_utils.py: SSHExecutor.run() itself
    only returns (stdout, stderr), but the exit-code wrapper folds stderr
    handling into the caller's own command construction instead, e.g.
    `cmd 2>&1`). Callers that need stderr text folded into what they can
    inspect append `2>&1` to `cmd` themselves — see _stat_probe() and
    _read_probe() below.
    """
    stdout, code = run_command_with_exit_code(ssh, cmd, timeout=timeout)
    return CommandResult(completed=code is not None, exit_code=code, stdout=stdout, stderr='', command=cmd)


def _stat_probe(ssh: SSHExecutor, path: str, timeout: int) -> CommandResult:
    """`stat -c '%s|%Y|%U|%G|%a' <path> 2>&1` — no sudo (see module
    docstring: metadata visibility only needs traversal permission on the
    parent directory, not read permission on the file itself). `2>&1` so
    a "No such file or directory" / "Permission denied" message lands in
    stdout where run_command_with_exit_code()'s wrapper can recover it —
    this collector's CommandResult.stderr field stays '' for this probe;
    the error text (when exit_code != 0) is in stdout instead."""
    import shlex
    cmd = f'stat -c {shlex.quote("%s|%Y|%U|%G|%a")} {shlex.quote(path)} 2>&1'
    return _run(ssh, cmd, timeout)


def _read_probe(ssh: SSHExecutor, path: str, timeout: int) -> CommandResult:
    """`test -r <path>` — no sudo, no content read. exit_code==0 means
    the connecting user can read the file's content; exit_code==1 means
    they cannot (this is test(1)'s own documented convention — no
    ambiguous third case to worry about here, unlike `command -v`)."""
    import shlex
    cmd = f'test -r {shlex.quote(path)}'
    return _run(ssh, cmd, timeout)


def _collect_log_file(ssh: SSHExecutor, path: str, timeout: int) -> LogFileEvidence:
    stat_result = _stat_probe(ssh, path, timeout)
    read_probe = _read_probe(ssh, path, timeout)
    return LogFileEvidence(path=path, stat_result=stat_result, read_probe=read_probe)


def probe_log_file(ssh: SSHExecutor, path: str, timeout: int = 20) -> LogFileEvidence:
    """Public, targeted Discovery primitive: probes exactly ONE file
    path (stat + test -r, same as every fixed source inside
    collect_log_discovery()) without running the rest of full-host
    discovery (the other five fixed sources, the nginx glob, journal,
    logrotate.d checks).

    Exists because collect_log_discovery() is deliberately "collect
    everything" — appropriate for a full Logs Audit Discovery pass, but
    wasteful for a caller (e.g. checks/ssh_auth_audit.py) that only
    needs one specific file's state. Confirmed wasteful in practice: an
    SSH auth audit calling collect_log_discovery() just to learn
    auth.log's availability was also paying for a 94-file nginx glob on
    46.62.147.41 (~45s of a ~45s total run) it never used.

    This is a thin public wrapper around the same _collect_log_file()
    used internally by collect_log_discovery() for each fixed source —
    not a second, parallel implementation of stat/readability probing.
    Both call the same _stat_probe()/_read_probe() primitives."""
    return _collect_log_file(ssh, path, timeout)


def _collect_logrotate_config(ssh: SSHExecutor, name: str, timeout: int) -> LogrotateEvidence:
    import shlex
    path = f'/etc/logrotate.d/{name}'
    cmd = f'test -f {shlex.quote(path)}'
    return LogrotateEvidence(name=name, config_check=_run(ssh, cmd, timeout))


def _collect_nginx(ssh: SSHExecutor, timeout: int) -> NginxGlobEvidence:
    """find(1) rather than a shell glob — a glob that matches nothing
    expands to a literal (unmatched) pattern string in some shells,
    which would then get passed to nothing meaningful; find with
    -maxdepth 1 -name '*.log*' -type f prints one path per line and
    exits 0 even with zero matches (empty stdout is a valid, confirmed
    result, not a collection failure) — same 'empty stdout is not the
    same as absence-of-attempt' principle as fail2ban_config.py's binary
    check.
    """
    glob_cmd = f"find {NGINX_LOG_DIR} -maxdepth 1 -name '*.log*' -type f 2>&1"
    glob_result = _run(ssh, glob_cmd, timeout)

    per_file: list[LogFileEvidence] = []
    if glob_result.completed and glob_result.exit_code == 0:
        paths = [line.strip() for line in glob_result.stdout.splitlines() if line.strip()]
        for path in paths:
            per_file.append(_collect_log_file(ssh, path, timeout))

    return NginxGlobEvidence(glob_result=glob_result, per_file=per_file)


def _collect_journal(ssh: SSHExecutor, timeout: int) -> JournalEvidence:
    """`-q` suppresses journalctl's "you are not seeing messages from
    other users" hint banner — empirically confirmed on 46.62.147.41
    (project session notes, live VM verification) that without -q this
    hint is printed to STDOUT (not stderr) ahead of the actual "Archived
    and active journals take up X in the file system." line, which would
    otherwise corrupt a naive regex/last-line parse in the consumer."""
    disk_usage = _run(ssh, 'journalctl --disk-usage -q 2>&1', timeout)
    journald_conf = _run(ssh, "grep -v '^#\\|^$' /etc/systemd/journald.conf 2>&1", timeout)
    return JournalEvidence(disk_usage=disk_usage, journald_conf=journald_conf)


# ===========================================================================
# Top-level collector
# ===========================================================================

def collect_log_discovery(ssh: SSHExecutor, timeout: int = 20) -> LogDiscoveryEvidence:
    """Collects all Iteration-1 discovery evidence from one host: fixed
    file sources (auth.log, syslog, kern.log, fail2ban.log, mail.log,
    aide.log), a glob-discovered set of nginx log files, systemd-journal
    state, and logrotate.d config presence for each fixed source that has
    one. Every probe is unprivileged (no sudo anywhere in this module —
    see this module's docstring on why `readable` is collected instead
    of assumed).
    """
    file_evidence: dict[str, LogFileEvidence] = {}
    logrotate_evidence: list[LogrotateEvidence] = []
    seen_logrotate_names: set[str] = set()

    for name, (path, logrotate_name) in _FIXED_FILE_SOURCES.items():
        file_evidence[name] = _collect_log_file(ssh, path, timeout)
        if logrotate_name and logrotate_name not in seen_logrotate_names:
            logrotate_evidence.append(_collect_logrotate_config(ssh, logrotate_name, timeout))
            seen_logrotate_names.add(logrotate_name)

    nginx = _collect_nginx(ssh, timeout)
    journal = _collect_journal(ssh, timeout)

    return LogDiscoveryEvidence(
        auth_log=file_evidence['auth_log'],
        syslog=file_evidence['syslog'],
        kern_log=file_evidence['kern_log'],
        fail2ban_log=file_evidence['fail2ban_log'],
        mail_log=file_evidence['mail_log'],
        aide_log=file_evidence['aide_log'],
        nginx=nginx,
        journal=journal,
        logrotate_configs=logrotate_evidence,
    )
