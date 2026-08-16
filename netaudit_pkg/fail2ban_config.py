"""
Fail2ban evidence collection: the single place that runs `command -v
fail2ban-client`, `fail2ban-client status` (unprivileged and via sudo),
and `fail2ban-client status <jail>` per jail over SSH, returning
structured, uninterpreted evidence.

Deliberately data-only, same split as firewall_config.py/sql_config.py/
nginx_config.py/ssh_config.py/kernel_config.py: this module holds FACTS
(what a command's stdout/exit code actually were), never judgments (no
ACTIVE/CONFIRMED_NO_JAILS/ACCESS_DENIED verdict here). That judgment
belongs to the consumer (audit_fail2ban() in server_security.py) -
collect once, interpret separately, from the same evidence.

Why this collector exists (quality-audit background)
------------------------------------------------------
The pre-existing audit_fail2ban() in server_security.py ran `which
fail2ban-client || echo NONE`, then `fail2ban-client status 2>&1` with
text-sniffing for 'Failed'/'ERROR', then a per-jail loop with
`fail2ban-client status {jail} 2>/dev/null`, none of it going through
sudo and none of it recovering a real exit code anywhere. Read-only
semantic audit of that code (this module's session notes, FB-1 through
FB-7) found several real problems this collector is designed to close:

  - `which fail2ban-client || echo NONE` collapses "not installed" and
    "the `which` command itself failed to execute" into the same NONE
    string - the same which-collapse bug already fixed for UFW
    (firewall_config.py) and mysql/mariadb (sql_config.py).
  - `fail2ban-client status 2>&1` merges stderr into stdout and then
    text-sniffs three literal substrings instead of checking a real
    exit code - `err.strip()` in the pre-existing code was always ''
    (nothing left in stderr after the merge), making that half of the
    condition permanently dead.
  - No sudo was ever attempted. Empirically confirmed on a real host
    (46.62.147.41, this module's session notes) that unprivileged
    `fail2ban-client status` reports `exit_code=0` with stdout
    containing `ERROR Permission denied to socket ... (you must be
    root)` - i.e. fail2ban-client's own internal error does NOT
    propagate as a nonzero shell exit code for this command. This is
    the single most important empirical fact behind this collector's
    design: exit_code==0 is NOT sufficient evidence of a successful
    `fail2ban-client status` call. sudo is required to get an
    authoritative result at all on a host configured this way.
  - The per-jail loop used `2>/dev/null` (stderr discarded) with no
    sudo and no exit code - any per-jail query failure (jail deleted
    concurrently, daemon restarting mid-loop, socket busy) was silently
    indistinguishable from "genuinely 0 currently/total banned", which
    could corrupt the aggregate ok-finding's ban count with unconfirmed
    zeros.
  - The jail-list regex (`Jail list:\\s*(.+)`) failing to match for any
    reason (version/locale drift, or a not-yet-detected access-denied
    message falling through the text-sniff above) silently produced
    `jails = []`, identical to a confirmed-empty jail list.

Privilege model
----------------
Empirically confirmed (this module's session notes) that unprivileged
`fail2ban-client status` cannot be trusted as authoritative - it may
report `exit_code=0` while its own stdout says permission was denied.
Per the established project pattern (ssh.sudo() unconditionally for
commands that need root - firewall_config.py's nft/iptables/ufw,
ssh_config.py's `sshd -T`, kernel_config.py's `sysctl -a`), this
collector always attempts sudo for the status call AND for every
per-jail status call - using the SAME privilege context for both is
deliberate: an inconsistent unpriv/sudo mix between the top-level
status call and the per-jail calls would let this collector accidentally
manufacture its own partial-collection failures purely from a privilege
mismatch, not a real one.

The unprivileged status call is still collected and retained in
Fail2banEvidence.status_unpriv - NOT for use as a verdict, but as
diagnostic evidence (e.g. to let the semantic layer note "unprivileged
access was also denied" in a finding's detail text). This collector
does not decide what an ERROR string in status_unpriv.stdout means -
see this module's session notes: "collector does not decide, 'ERROR
means ACCESS_DENIED' is a semantic-layer judgment, not a collection
fact."

`command -v fail2ban-client` needs no privilege - no sudo there.

Recovering an exit code through sudo
--------------------------------------
Uses the same `_run_sudo_with_exit_code()` approach firewall_config.py
established: ssh_utils.run_command_with_exit_code()'s shell-group
wrapping (`{ cmd; rc=$?; printf ...; }`) cannot be handed to sudo
directly (sudo execve()s its argument; `{ }` is a shell reserved word,
not something sudo can invoke on its own), so the marker script is
routed through `sh -c <script>` instead, safely quoted via
shlex.quote().

Reused vs local primitives
-----------------------------
netaudit_pkg.ssh_utils.run_command_with_exit_code() (shared with
cve_audit.py, firewall_config.py, sql_config.py) is reused directly for
the unprivileged status call and the binary-presence check.

CommandResult and the sudo-exit-code-recovery helper are intentionally
NOT imported from firewall_config.py and NOT hoisted into a shared
module, even though this is now the THIRD independent collector with
this exact shape (firewall_config.py, sql_config.py, and this one).
Per the quality-audit session's stated principle, the extraction itself
is deliberately being treated as a separate, later change so as not to
mix it with this collector's own contract/tests/implementation pass -
see the project session notes for the follow-up ssh_utils.py
generalization decision.
"""

from __future__ import annotations

import re
import shlex
import uuid
from dataclasses import dataclass, field

from .ssh import SSHExecutor
from .ssh_utils import run_command_with_exit_code

# ===========================================================================
# Evidence data model
# ===========================================================================

@dataclass
class CommandResult:
    """Uninterpreted evidence from running one command (directly or via
    sudo) with exit-code recovery. Same completed/exit_code/stdout
    contract as firewall_config.CommandResult/sql_config.CommandResult -
    see either for the full semantics. completed=False means the
    command's completion could not be confirmed at all (SSH channel
    drop, timeout, truncated output before the completion marker was
    written) - exit_code is always None in that case, and stdout must
    NOT be treated as a confirmed result of any kind. completed=True
    means the command ran to completion and reported an exit code
    through the normal channel.
    """
    completed: bool
    exit_code: int | None
    stdout: str
    command: str


@dataclass
class JailEvidence:
    """One jail's own `fail2ban-client status <jail>` evidence, always
    collected via sudo (see this module's docstring, "Privilege model" -
    per-jail queries use the SAME privilege context as the top-level
    status call, deliberately, to avoid manufacturing an artificial
    partial-collection failure purely from an unpriv/sudo mismatch).

    `name` is exactly the jail name as parsed from the top-level status
    output's "Jail list:" line - this collector does not validate or
    normalize it further.
    """
    name: str
    status: CommandResult


@dataclass
class Fail2banEvidence:
    """All fail2ban-related evidence collected from one host, one field
    per independent source. No aggregation, no verdict - see this
    module's docstring. audit_fail2ban() in server_security.py is the
    sole consumer responsible for turning this into PRESENT/NOT_PRESENT/
    UNKNOWN, SUCCESS/PARSE_FAILURE/ACCESS_DENIED/COMMAND_ERROR, and
    CONFIRMED/UNKNOWN per-jail judgments and findings.

    status_sudo is None only when binary_check already confirms
    NOT_PRESENT (no point attempting a privileged status call - or any
    per-jail calls - against a binary that's confirmed absent). In every
    other case (PRESENT, or UNKNOWN at the binary check) status_sudo is
    attempted and populated with whatever CommandResult results,
    including a completed=False collection failure.

    jails is always a list (never None), but an empty list here does
    NOT by itself mean "confirmed zero jails" - see status_sudo's own
    verdict first (this collector does not encode that judgment; the
    semantic layer must check status_sudo's completed/exit_code/parse
    outcome before treating an empty jails list as CONFIRMED_NO_JAILS
    versus UNKNOWN). jails is only ever populated when status_sudo
    reported exit_code==0 and its "Jail list:" line was parseable.
    """
    binary_check: CommandResult
    status_unpriv: CommandResult
    status_sudo: CommandResult | None
    jails: list[JailEvidence] = field(default_factory=list)


# ===========================================================================
# Exit-code recovery over ssh.sudo()
# ===========================================================================

def _run_sudo_with_exit_code(ssh: SSHExecutor, cmd: str, timeout: int = 20) -> CommandResult:
    """Runs `cmd` via SSHExecutor.sudo() and recovers its exit code.

    Identical approach to firewall_config._run_sudo_with_exit_code() -
    see that function's docstring for why ssh_utils.
    run_command_with_exit_code()'s `{ cmd; rc=$?; ...; }` shell-group
    wrapping can't be handed to sudo directly, and why the completion
    marker is instead routed through `sh -c <script>`.

    Kept local to this module rather than shared with firewall_config.py
    - see this module's docstring, "Reused vs local primitives", for why
    the extraction is deliberately deferred to a separate change.
    """
    marker = f'__NETAUDIT_RC_{uuid.uuid4().hex}__'
    script = f"{cmd}; rc=$?; printf '%s:%s\\n' {shlex.quote(marker)} \"$rc\""
    sudo_cmd = f'sh -c {shlex.quote(script)}'
    out, _ = ssh.sudo(sudo_cmd, timeout=timeout)

    if marker not in out:
        return CommandResult(completed=False, exit_code=None, stdout=out, command=cmd)

    body, _, tail = out.rpartition(marker)
    code_str = tail.lstrip(':').strip()
    try:
        code = int(code_str)
    except ValueError:
        return CommandResult(completed=False, exit_code=None, stdout=body, command=cmd)

    return CommandResult(completed=True, exit_code=code, stdout=body.rstrip('\n'), command=cmd)


# ===========================================================================
# Binary presence
# ===========================================================================

def _binary_check(ssh: SSHExecutor, timeout: int = 20) -> CommandResult:
    """Checks whether fail2ban-client is on PATH via `command -v` (POSIX
    shell builtin, not `which` - see firewall_config._tool_is_present()'s
    docstring for why `which` isn't used). No sudo - PATH lookup needs
    no privilege.

    Returns a CommandResult whose exit_code follows `command -v`'s own
    documented convention: exit_code=0 with the binary's path in stdout
    means present; exit_code=127 with empty stdout means genuinely not
    on PATH (valid evidence of absence, NOT a collection failure). See
    binary_verdict() below for how a caller interprets this, including
    why any OTHER confirmed exit code is UNKNOWN, not NOT_PRESENT -
    only 127 is `command -v`'s documented "not found" convention; a
    different nonzero code means something else went wrong and this
    collector refuses to guess at what.
    """
    cmd = 'command -v fail2ban-client'
    stdout, code = run_command_with_exit_code(ssh, cmd, timeout=timeout)
    return CommandResult(completed=code is not None, exit_code=code, stdout=stdout, command=cmd)


def binary_verdict(result: CommandResult) -> str:
    """Interprets a _binary_check() CommandResult using `command -v`'s
    documented exit-code convention. Returns one of 'PRESENT',
    'NOT_PRESENT' (confirmed absent, exit_code==127 exactly - not "any
    nonzero code"), or 'UNKNOWN' (collection failure - completed=False -
    or a confirmed exit code that's neither 0 nor 127, which
    `command -v` isn't documented to produce and which this function
    still refuses to treat as either presence or absence)."""
    if not result.completed:
        return 'UNKNOWN'
    if result.exit_code == 0:
        return 'PRESENT'
    if result.exit_code == 127:
        return 'NOT_PRESENT'
    return 'UNKNOWN'


# ===========================================================================
# Jail list parsing (pure - no I/O)
# ===========================================================================

_JAIL_LIST_RE = re.compile(r'Jail list:\s*(.*)')


def _parse_jail_list(stdout: str) -> list[str] | None:
    """Parses the `Jail list:` line out of a successful `fail2ban-client
    status` stdout. Returns a list of jail names (possibly empty - a
    genuinely empty "Jail list:" line is a valid parse result, not a
    parse failure), or None if no "Jail list:" line was found at all
    (PARSE_FAILURE - the caller must not treat this the same as an
    empty list; see this module's docstring and Fail2banEvidence's
    jails field for why "parsed successfully and got zero jails" and
    "couldn't parse at all" must never be collapsed into the same
    `jails = []` shape without also checking which case this was).

    This function does not care about exit_code or completed - it is a
    pure string parser. Callers are responsible for only calling it on
    stdout that's already been confirmed to come from a successful
    (exit_code==0, completed=True) status call; see audit_fail2ban()'s
    semantic layer.
    """
    m = _JAIL_LIST_RE.search(stdout)
    if m is None:
        return None
    raw = m.group(1).strip()
    if not raw:
        return []
    return [j.strip() for j in raw.split(',') if j.strip()]


# ===========================================================================
# Top-level collector
# ===========================================================================

def collect_fail2ban_config(ssh: SSHExecutor, timeout: int = 20) -> Fail2banEvidence:
    """Collects all fail2ban evidence from one host: binary presence,
    unprivileged status (diagnostic only), sudo status (authoritative),
    and per-jail sudo status for every jail successfully parsed out of
    the sudo status output.

    Short-circuits (status_unpriv is still collected for diagnostic
    value, but status_sudo stays None and no per-jail calls are made)
    when binary_verdict() confirms NOT_PRESENT - there is no reason to
    attempt a privileged round trip, possibly prompting for a sudo
    password, against a binary that's confirmed absent from PATH. This
    mirrors firewall_config.collect_ufw()'s same short-circuit pattern
    for a NOT_PRESENT backend.

    When binary_verdict() is UNKNOWN (collection failure on the
    presence check itself), status_sudo IS still attempted - a failed
    `command -v` doesn't tell us anything about whether fail2ban-client
    actually exists, so it would be wrong to skip the one check that
    might still succeed and give a real answer.
    """
    binary_check = _binary_check(ssh, timeout=timeout)

    unpriv_cmd = 'fail2ban-client status'
    unpriv_stdout, unpriv_code = run_command_with_exit_code(ssh, unpriv_cmd, timeout=timeout)
    status_unpriv = CommandResult(completed=unpriv_code is not None, exit_code=unpriv_code,
                                   stdout=unpriv_stdout, command=unpriv_cmd)

    if binary_verdict(binary_check) == 'NOT_PRESENT':
        return Fail2banEvidence(binary_check=binary_check, status_unpriv=status_unpriv,
                                 status_sudo=None, jails=[])

    status_sudo = _run_sudo_with_exit_code(ssh, 'fail2ban-client status', timeout=timeout)

    jails: list[JailEvidence] = []
    if status_sudo.completed and status_sudo.exit_code == 0:
        jail_names = _parse_jail_list(status_sudo.stdout)
        if jail_names:
            for name in jail_names:
                jail_cmd = f'fail2ban-client status {shlex.quote(name)}'
                jail_status = _run_sudo_with_exit_code(ssh, jail_cmd, timeout=timeout)
                jails.append(JailEvidence(name=name, status=jail_status))

    return Fail2banEvidence(binary_check=binary_check, status_unpriv=status_unpriv,
                             status_sudo=status_sudo, jails=jails)
