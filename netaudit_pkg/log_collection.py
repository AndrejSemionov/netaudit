"""
Logs Audit — Collection (Iteration 2): reads a bounded amount of log
CONTENT from a source already discovered in Iteration 1, using the
access decision (readable/requires_sudo) that Discovery already made.
This module does not decide whether sudo is needed — it only executes
the read using whatever LogSource.readable/requires_sudo already says.

Scope (Iteration 2 — Collection, per Collection Contract v2 freeze)
------------------------------------------------------------------
- TAIL mode only (`tail -n N` for files, `journalctl -n N` for journal
  units). FULL and WINDOW are reserved enum members, not implemented.
- Line-based limiting (`-n`, not `-c`) — log lines are the unit of
  meaning for any downstream parser; a byte-cut can corrupt the first
  line of the window, a line-cut cannot.
- FILE sources use LogSource.readable/requires_sudo exactly as Discovery
  already determined it — this module does not re-derive or second-guess
  that decision. FILE + available=False is never collected at all (no
  CollectionResult is produced for it).
- JOURNAL sources are NOT assumed to require sudo, and are NOT assumed
  to work without it either — "journalctl -u <unit> works via run()
  without sudo" is an empirically-confirmed fact on this project's two
  real hosts (see system.py's existing failed_ssh_logins REMOTE_CHECKS
  entry), not a universal property of journalctl this module bakes in
  as policy. JOURNAL collection always goes through run() (never sudo())
  in Iteration 2; a real access-denied case surfaces as a nonzero exit
  code via run_command_with_exit_code(), not as an automatic escalation
  to sudo — any future sudo-for-journal policy is a deliberate, separate
  decision for a later iteration, not something this module infers.
- `truncated` is deliberately NOT part of this contract. Whether a `tail
  -n N` result represents "the whole file, which happened to be short"
  or "the file was longer and got cut" cannot be determined from the
  tail result alone without an extra `wc -l` round-trip per source, and
  that cost isn't justified for what Iteration 2's detection layer
  actually needs. line_count is provided (a plain count of returned
  lines) without implying anything about what was cut, if anything.
"""

from __future__ import annotations

import shlex
import uuid
from dataclasses import dataclass
from enum import Enum

from .checks.log_discovery_audit import LogSource
from .ssh import SSHExecutor
from .ssh_utils import run_command_with_exit_code


class CollectionMode(str, Enum):
    TAIL = 'tail'
    FULL = 'full'      # reserved — not implemented in Iteration 2
    WINDOW = 'window'   # reserved — not implemented in Iteration 2


class SourceKind(str, Enum):
    FILE = 'file'
    JOURNAL = 'journal'


@dataclass
class CommandResult:
    """Same completed/exit_code/stdout/stderr/command shape as
    log_discovery.CommandResult — intentionally local to this module for
    the same reason fail2ban_config.py/firewall_config.py/sql_config.py/
    log_discovery.py each keep their own: extraction to a shared type is
    a separate architectural decision, not something to fold into a
    Collection-Contract pass."""
    completed: bool
    exit_code: int | None
    stdout: str
    stderr: str
    command: str


@dataclass
class CollectionResult:
    source_kind: SourceKind
    source_path: str | None    # None for JOURNAL — see unit_name instead
    unit_name: str | None       # only set for JOURNAL
    result: CommandResult
    line_count: int | None      # count of lines actually returned; says
                                 # nothing about whether more existed — see
                                 # this module's docstring on `truncated`


DEFAULT_TAIL_LINES = 200


def _to_command_result(stdout: str, exit_code: int | None, command: str) -> CommandResult:
    """run_command_with_exit_code() returns (stdout, exit_code) — exit_code
    is None exactly when completion could not be confirmed at all (see
    that function's own docstring: SSH channel drop, timeout, or a
    truncated result before the completion marker was written). This
    wrapper folds that into the same completed/exit_code/stdout/stderr
    shape used everywhere else in Logs Audit (log_discovery.CommandResult)
    — stderr stays '' here for the same reason it does in log_discovery.py:
    run_command_with_exit_code() itself only recovers stdout+exit_code,
    not a separate stderr channel."""
    return CommandResult(completed=exit_code is not None, exit_code=exit_code, stdout=stdout,
                          stderr='', command=command)


def _run_sudo_with_exit_code(ssh: SSHExecutor, cmd: str, timeout: int = 20) -> CommandResult:
    """Runs `cmd` via SSHExecutor.sudo() and recovers its exit code.
    Identical approach to fail2ban_config._run_sudo_with_exit_code() /
    firewall_config._run_sudo_with_exit_code() — see either for the full
    rationale on why ssh_utils.run_command_with_exit_code()'s shell-group
    marker wrapping can't be handed to sudo directly, and why the
    completion marker is instead routed through `sh -c <script>`.

    Kept local to this module rather than extracted to a shared helper —
    same "wait for a third independent case" principle already applied
    to fail2ban_config.py/firewall_config.py's own local copies of this
    exact function.

    Known limitation (see project session notes on
    _run_sudo_with_exit_code() and scoped sudoers): the `sh -c` wrapping
    means sudoers authorizes the literal `sh` binary, not the real
    command inside it — this breaks a no-password scoped NOPASSWD rule
    limited to one specific executable. Not a practical blocker for
    collect_file(): a LogSource with requires_sudo=True only reaches
    this function when a sudo password is available (SSHExecutor.sudo()
    with a password uses `sudo -S` directly, unaffected by this
    limitation) — the no-password+scoped-NOPASSWD combination remains
    the same pre-existing, deliberately-deferred architectural item as
    for fail2ban/firewall, not something introduced by this module.
    """
    marker = f'__NETAUDIT_RC_{uuid.uuid4().hex}__'
    script = f"{cmd}; rc=$?; printf '%s:%s\\n' {shlex.quote(marker)} \"$rc\""
    sudo_cmd = f'sh -c {shlex.quote(script)}'
    out, _ = ssh.sudo(sudo_cmd, timeout=timeout)

    if marker not in out:
        return CommandResult(completed=False, exit_code=None, stdout=out, stderr='', command=cmd)

    body, _, tail = out.rpartition(marker)
    code_str = tail.lstrip(':').strip()
    try:
        code = int(code_str)
    except ValueError:
        return CommandResult(completed=False, exit_code=None, stdout=body, stderr='', command=cmd)
    return CommandResult(completed=True, exit_code=code, stdout=body.rstrip('\n'), stderr='', command=cmd)


def _count_lines(result: CommandResult) -> int | None:
    """None when the command's completion couldn't be confirmed at all —
    a collection failure must never report a line_count of 0, which
    would be visually identical to a confirmed-empty result (see this
    module's docstring and test_line_count_is_none_on_collection_failure).
    An empty-but-confirmed stdout ('') is 0 lines, not 1 — splitlines()
    on '' already returns [], so no special-casing is needed there."""
    if not result.completed:
        return None
    return len(result.stdout.splitlines())


def collect_file(ssh: SSHExecutor, source: LogSource, mode: CollectionMode = CollectionMode.TAIL,
                  lines: int = DEFAULT_TAIL_LINES, timeout: int = 20) -> CollectionResult | None:
    """Collects content from a FILE LogSource, using exactly the
    access decision Discovery already made (source.readable /
    source.requires_sudo) — this function does not re-derive that.

    Returns None (no CollectionResult at all) when source.available is
    False — an unavailable source has nothing to collect, and producing
    a CollectionResult with some sentinel failure state for it would
    blur the line between "we tried to read this and it failed" and "we
    never had anything to read in the first place" (the same distinction
    Discovery's LogFileEvidence/LogSource split was built to preserve).

    Only CollectionMode.TAIL is implemented; any other mode raises
    NotImplementedError rather than silently falling back to TAIL or to
    an unbounded read — see this module's docstring on FULL/WINDOW being
    reserved, not implemented. The mode check happens before any SSH
    call is made, so an unimplemented mode never issues a command.
    """
    if mode != CollectionMode.TAIL:
        raise NotImplementedError(f'CollectionMode.{mode.name} is reserved, not implemented in Iteration 2')

    if not source.available:
        return None

    cmd = f'tail -n {lines} {shlex.quote(source.path)}'

    if source.readable:
        stdout, exit_code = run_command_with_exit_code(ssh, cmd, timeout=timeout)
        result = _to_command_result(stdout, exit_code, cmd)
    else:
        # requires_sudo=True is the only other reachable state here —
        # source.available=True and source.readable=False together mean
        # Discovery already determined sudo is the correct path; this
        # function does not re-check requires_sudo itself, since
        # available+not readable has no other meaning in the frozen
        # Discovery Contract v1 LogSource model.
        result = _run_sudo_with_exit_code(ssh, cmd, timeout=timeout)

    return CollectionResult(
        source_kind=SourceKind.FILE, source_path=source.path, unit_name=None,
        result=result, line_count=_count_lines(result),
    )


def collect_journal(ssh: SSHExecutor, unit_name: str, mode: CollectionMode = CollectionMode.TAIL,
                     lines: int = DEFAULT_TAIL_LINES, timeout: int = 20) -> CollectionResult:
    """Collects content from a systemd-journal unit via `journalctl -u
    <unit> -n <lines> --no-pager`, always through ssh.run() — never
    ssh.sudo() — per Collection Contract v2: journal access working
    without sudo is an empirically-confirmed fact on this project's real
    hosts, not a universal property this module assumes or a policy it
    enforces. A real permission failure surfaces as a nonzero exit code
    (via run_command_with_exit_code(), which distinguishes that from a
    confirmed-empty exit=0/empty-stdout result) — this function does not
    retry with sudo on that outcome.
    """
    if mode != CollectionMode.TAIL:
        raise NotImplementedError(f'CollectionMode.{mode.name} is reserved, not implemented in Iteration 2')

    cmd = f'journalctl -u {shlex.quote(unit_name)} -n {lines} --no-pager'
    stdout, exit_code = run_command_with_exit_code(ssh, cmd, timeout=timeout)
    result = _to_command_result(stdout, exit_code, cmd)

    return CollectionResult(
        source_kind=SourceKind.JOURNAL, source_path=None, unit_name=unit_name,
        result=result, line_count=_count_lines(result),
    )
