"""
Firewall evidence collection: the single place that runs `ufw status`,
`nft list ruleset`, `iptables -S`, and reads nftables config files over
SSH, returning structured, uninterpreted evidence.

Deliberately data-only, same split as nginx_config.py/ssh_config.py/
kernel_config.py: this module holds FACTS (what a command's stdout/exit
code actually were), never judgments (no "firewall is active" verdict
here). That judgment belongs to the consumer (audit_firewall() in
server_security.py) - collect once, interpret separately, from the same
evidence.

Why this collector exists (quality-audit background)
------------------------------------------------------
The pre-existing audit_firewall() in server_security.py ran these same
four commands directly with plain ssh.run() and stdout-only text-marker
heuristics ('NOUFW'/'NONFT'/'NOIPT' via `cmd || echo MARKER`). Read-only
semantic audit of that code found several real problems this collector
is designed to close:

  - `A | head -N || echo MARKER` never actually triggers MARKER in
    standard bash: the pipeline's exit status is head's, not the first
    command's, so a permission-denied nft/iptables call and a genuinely
    empty (but successful) result were indistinguishable by stdout alone.
  - `which ufw && ufw status || echo NOUFW` collapses "ufw not installed"
    and "ufw status failed without root" into the same NOUFW string -
    a real collection failure silently read as "not installed", which
    could suppress a legitimate 'ufw is installed but disabled' finding.
  - Presence of a readable /etc/nftables.conf file was treated as proof
    the firewall is ACTIVE - but a config file existing is not the same
    fact as nftables having actually loaded it into the kernel (the
    service could be down, the file could reference a broken include,
    or an admin could have edited it without reloading). This collector
    keeps "config file is readable" and "live ruleset is non-empty" as
    two separate, independently-reported facts - it is the CALLER's job
    to decide what to make of a config-present/live-unconfirmed
    combination, not this collector's.

Privilege model
----------------
`nft list ruleset` and `iptables -S` require root/CAP_NET_ADMIN to see
anything at all - confirmed by the exact same class of problem
kernel_config.py's `sysctl -a` and ssh_config.py's `sshd -T` already ran
into (see those modules' docstrings): without sudo, the command either
returns nothing or errors out, and a naive "empty output" read is
indistinguishable from "the firewall genuinely has zero rules loaded".
Per that established project pattern (ssh.sudo() unconditionally, never
"try without sudo first, hope it's enough"), this collector always uses
sudo for `nft list ruleset` and `iptables -S`.

`ufw status` also typically requires root, so it goes through sudo too.
`cat` on the nftables config file path does NOT go through sudo - a
config file's own filesystem permissions are the actual, meaningful
signal here (if it's world-readable, that's a legitimate fact; if it
isn't, that's PERMISSION_DENIED evidence, not a reason to force root
just for symmetry with the other three collectors).

Recovering an exit code through sudo
--------------------------------------
netaudit_pkg.ssh_utils.run_command_with_exit_code() (shared with
cve_audit.py) wraps a command in a bash `{ cmd; rc=$?; printf ...; }`
group and passes the WHOLE wrapped string to SSHExecutor.run(). That
exact wrapping cannot be handed to SSHExecutor.sudo() unmodified: sudo
execve()s its argument directly rather than invoking a shell to parse
it, and `{ ... }` is a shell reserved word, not something sudo (or any
non-shell exec) can interpret positioned as an argument - confirmed by
testing this directly (see this module's PR/session notes): `sudo {
cmd; }` fails to parse. The fix used here is to route the exit-code
recovery script through `sh -c <script>`, with the whole script quoted
via shlex.quote() (never hand-built string concatenation, which risks
reintroducing exactly the kind of quoting bug this is meant to avoid) -
see _run_sudo_with_exit_code() below. A base64-encode/decode pipeline
was considered and rejected: it works, but makes the actual remote
command opaque in audit/debug logs for no correctness benefit over
shlex.quote(), which keeps the command human-readable while still being
provably correctly escaped.

sudo() prerequisite note
--------------------------
SSHExecutor.sudo() silently writes an empty string to stdin if no sudo
password was configured and passwordless sudo isn't available - it does
NOT raise or otherwise signal "no password was available" itself; that
signal only shows up as a nonzero sudo exit code once decoded via
_run_sudo_with_exit_code(). This collector deliberately does NOT call
SSHExecutor.needs_sudo_password() as an upfront gate before attempting
each command - each backend's collection is attempted independently and
reports its own UNKNOWN/reason if sudo authentication fails for it,
rather than a single needs_sudo_password() check preemptively marking
all three backends UNKNOWN before even trying. This matters in practice:
a host might have passwordless sudo configured for some commands via
sudoers NOPASSWD rules scoped to specific binaries, so "sudo needs a
password in general" is not always the same fact as "sudo will fail for
this specific command" - though in the common case (blanket sudo
access) they usually agree.
"""

from __future__ import annotations

import shlex
import uuid
from dataclasses import dataclass

from .ssh import SSHExecutor

# ===========================================================================
# Evidence data model
# ===========================================================================

@dataclass
class CommandResult:
    """Uninterpreted evidence from running one command (directly or via
    sudo) with exit-code recovery.

    completed=False means the command's completion could not be
    confirmed at all (SSH channel drop, timeout, truncated output before
    the completion marker was written) - a genuine unknown. exit_code is
    always None when completed=False, and stdout is whatever raw output
    (if any) was captured before the marker went missing - it must NOT
    be treated as a confirmed result of any kind by a caller.

    completed=True means the command ran to completion and reported an
    exit code through the normal channel - exit_code=0 is a confirmed
    success (stdout may still legitimately be empty, e.g. `nft list
    ruleset` on a host with zero configured tables), and any nonzero
    exit_code is a confirmed failure (e.g. permission denied, sudo
    authentication failure, command not found via the shell's own "127"
    exit convention).
    """
    completed: bool
    exit_code: int | None
    stdout: str
    command: str  # the original (unwrapped) command, for error messages/debugging


@dataclass
class FileResult:
    """Uninterpreted evidence from reading one file's contents via `cat`
    (no sudo - see this module's docstring for why). Same completed/
    exit_code contract as CommandResult; `path` is the exact path that
    was read (or attempted)."""
    completed: bool
    exit_code: int | None
    content: str
    path: str


@dataclass
class FirewallEvidence:
    """All firewall-related evidence collected from one host, one field
    per independent source. No aggregation, no verdict - see this
    module's docstring. audit_firewall() in server_security.py is the
    sole consumer responsible for turning this into ACTIVE/INACTIVE/
    UNKNOWN judgments and findings.
    """
    ufw_present: CommandResult  # `command -v ufw` - see collect_ufw()
    ufw_status: CommandResult | None  # `sudo ufw status` - None if ufw_present says NOT_PRESENT
    nftables_live: CommandResult
    nftables_config: FileResult
    iptables_live: CommandResult


# Same three candidate paths the pre-existing audit_firewall() checked,
# in the same priority order - preserved rather than re-derived, since
# this ordering (main config path first, then the two common alternate
# layouts) isn't this collector's decision to revisit; see
# server_security.py's audit_firewall() for how the result is used.
NFTABLES_CONFIG_PATHS = (
    '/etc/nftables.conf',
    '/etc/nftables/nftables.conf',
    '/etc/nftables/main.nft',
)


# ===========================================================================
# Exit-code recovery over ssh.sudo()
# ===========================================================================

def _run_sudo_with_exit_code(ssh: SSHExecutor, cmd: str, timeout: int = 20) -> CommandResult:
    """Runs `cmd` via SSHExecutor.sudo() and recovers its exit code.

    See this module's docstring ("Recovering an exit code through sudo")
    for why this can't reuse ssh_utils.run_command_with_exit_code()
    as-is: that helper's `{ cmd; rc=$?; printf ...; }` shell-group
    wrapping cannot be handed to sudo directly (sudo execve()s its
    argument rather than invoking a shell to parse `{ }`). This routes
    the same completion-marker approach through `sh -c <script>`
    instead, with the whole script safely quoted via shlex.quote().

    Kept local to this module rather than added to ssh_utils.py: only
    one collector needs a sudo-flavored variant so far (see the
    quality-audit session notes on not generalizing on a single call
    site) - ssh_utils.py stays focused on the plain ssh.run() case,
    which cve_audit.py also needs.
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


def _cat_file(ssh: SSHExecutor, path: str, timeout: int = 20) -> FileResult:
    """Reads a file's content via plain `cat` (no sudo - see this
    module's docstring for why config-file reads are deliberately NOT
    privilege-escalated). Uses the same completion-marker exit-code
    recovery as _run_sudo_with_exit_code(), but over plain ssh.run() -
    this is exactly ssh_utils.run_command_with_exit_code()'s job, reused
    directly rather than reimplemented, since `cat` needs no sudo
    wrapping."""
    from .ssh_utils import run_command_with_exit_code

    stdout, code = run_command_with_exit_code(ssh, f'cat {shlex.quote(path)}', timeout=timeout)
    return FileResult(completed=code is not None, exit_code=code, content=stdout, path=path)


def _tool_is_present(ssh: SSHExecutor, tool: str, timeout: int = 20) -> CommandResult:
    """Checks whether `tool` is on PATH via `command -v` (POSIX shell
    builtin - not `which`, which isn't guaranteed to exist as a separate
    binary on every distro/minimal image). No sudo - PATH lookup needs no
    privilege.

    Returns a CommandResult whose exit_code follows `command -v`'s own
    documented convention (confirmed empirically - see this module's
    session notes): exit_code=0 with the tool's path in stdout means
    present; exit_code=127 with empty stdout means genuinely not on
    PATH - this is NOT a collection failure, it's valid evidence a
    backend is absent. Any OTHER confirmed exit code, or completed=False
    (marker missing entirely - SSH channel drop, timeout), is a real
    collection failure and must not be read as either "present" or
    "not present" - see tool_is_present() below for how callers
    interpret this.
    """
    from .ssh_utils import run_command_with_exit_code

    stdout, code = run_command_with_exit_code(ssh, f'command -v {shlex.quote(tool)}', timeout=timeout)
    return CommandResult(completed=code is not None, exit_code=code, stdout=stdout,
                          command=f'command -v {tool}')


def tool_is_present(result: CommandResult) -> bool | None:
    """Interprets a _tool_is_present() CommandResult using `command -v`'s
    documented exit-code convention. Returns True (found), False
    (confirmed absent, exit_code==127), or None (collection failure -
    completion unconfirmed, or an exit code that's neither 0 nor 127,
    which `command -v` isn't documented to produce but which this
    function still refuses to guess at rather than silently treating as
    either presence or absence)."""
    if not result.completed:
        return None
    if result.exit_code == 0:
        return True
    if result.exit_code == 127:
        return False
    return None


# ===========================================================================
# Per-backend collectors
# ===========================================================================

def collect_ufw(ssh: SSHExecutor, timeout: int = 20) -> tuple[CommandResult, CommandResult | None]:
    """Checks whether ufw is present via `command -v`, and if so, runs
    `ufw status` via sudo. Returns (presence_result, status_result) -
    status_result is None if ufw is confirmed NOT present (exit_code==127
    on the presence check - see tool_is_present()), since there is no
    point attempting a privileged status call for a binary that doesn't
    exist. If presence itself is UNKNOWN (collection failure on the
    `command -v` step), status_result is also None - a caller must not
    assume ufw is absent just because a privileged follow-up wasn't
    attempted; it must read presence_result's own completed/exit_code to
    tell "confirmed absent" apart from "couldn't even check".

    Does NOT interpret 'Status: active'/'Status: inactive' text in
    status_result - that belongs to the semantic layer
    (server_security.py).
    """
    presence = _tool_is_present(ssh, 'ufw', timeout=timeout)
    if tool_is_present(presence) is not True:
        return presence, None
    return presence, _run_sudo_with_exit_code(ssh, 'ufw status', timeout=timeout)


def collect_nftables_live(ssh: SSHExecutor, timeout: int = 20) -> CommandResult:
    """Runs `nft list ruleset` via sudo and returns raw evidence -
    reflects the actual kernel-loaded ruleset right now, unlike
    collect_nftables_config() below (declared/file evidence only)."""
    return _run_sudo_with_exit_code(ssh, 'nft list ruleset', timeout=timeout)


def collect_nftables_config(ssh: SSHExecutor, timeout: int = 20) -> FileResult:
    """Reads the first readable nftables config file among
    NFTABLES_CONFIG_PATHS (no sudo - see this module's docstring). This
    is DECLARED evidence only - a readable, non-empty file here does NOT
    mean the ruleset it describes is actually loaded; see
    collect_nftables_live() for the corresponding live-state fact, and
    server_security.py's audit_firewall() for how the two are combined.

    Tries each candidate path in NFTABLES_CONFIG_PATHS order and returns
    the FIRST one with non-empty content. If a path is unreadable
    (permission denied) or the command's completion can't be confirmed,
    that specific FileResult's completed/exit_code reflects it - but
    this function still moves on to try the next candidate path (a
    permission-denied /etc/nftables.conf shouldn't prevent checking
    whether /etc/nftables/nftables.conf might be readable instead). If
    none of the three paths yields a non-empty, confirmed read, the
    LAST attempted path's FileResult is returned (so the caller still
    sees a real command/exit_code/completed combination to reason about,
    not a synthetic empty placeholder).
    """
    last_result: FileResult | None = None
    for path in NFTABLES_CONFIG_PATHS:
        result = _cat_file(ssh, path, timeout=timeout)
        last_result = result
        if result.completed and result.exit_code == 0 and result.content.strip():
            return result
    return last_result


def collect_iptables_live(ssh: SSHExecutor, timeout: int = 20) -> CommandResult:
    """Runs `iptables -S` via sudo and returns raw evidence - the
    INPUT/FORWARD/OUTPUT chain policies and every rule, in the exact
    syntax iptables itself uses (needed for server_security.py's
    unconditional-ACCEPT-rule detection, not just chain policy)."""
    return _run_sudo_with_exit_code(ssh, 'iptables -S', timeout=timeout)


def collect_firewall_config(ssh: SSHExecutor, timeout: int = 20) -> FirewallEvidence:
    """Collects all firewall evidence from one host in one call - the
    single entry point audit_firewall() (server_security.py) uses."""
    ufw_present, ufw_status = collect_ufw(ssh, timeout=timeout)
    return FirewallEvidence(
        ufw_present=ufw_present,
        ufw_status=ufw_status,
        nftables_live=collect_nftables_live(ssh, timeout=timeout),
        nftables_config=collect_nftables_config(ssh, timeout=timeout),
        iptables_live=collect_iptables_live(ssh, timeout=timeout),
    )
