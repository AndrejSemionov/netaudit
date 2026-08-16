"""
MySQL/MariaDB evidence collection: the single place that runs `command -v
mysql`/`command -v mariadb`, `ss -tlnp`, and reads MySQL config files for
a bind-address directive over SSH, returning structured, uninterpreted
evidence.

Deliberately data-only, same split as firewall_config.py/nginx_config.py/
ssh_config.py/kernel_config.py: this module holds FACTS (what a command's
stdout/exit code actually were), never judgments (no "MySQL is exposed"
verdict here). That judgment belongs to the consumer (audit_sql() in
server_security.py) - collect once, interpret separately, from the same
evidence.

Why this collector exists (quality-audit background)
------------------------------------------------------
The pre-existing audit_sql() in server_security.py ran these commands
directly with plain ssh.run() and text-marker/pipe-exit-code heuristics.
Read-only semantic audit of that code found several real problems this
collector is designed to close:

  - `which mysql mariadb 2>/dev/null || echo NONE` collapses "neither
    binary is installed" and "the `which` command itself failed to
    execute" into the same NONE string - a real collection failure
    silently read as confirmed absence.
  - `ss -tlnp 2>/dev/null | grep -E ":3306" || echo NOPORT` has its
    fallback driven by `grep`'s OWN exit code (1 = no match), which is
    identical whether `ss` succeeded with no 3306 listener, or `ss`
    itself failed and grep matched nothing in the resulting empty input.
    These are two different facts colliding on one exit code.
  - `if 'NONE' in out and 'NOPORT' in running: return {'installed': False}`
    - a compound collection failure across BOTH checks produces the
    exact same shape as "MySQL genuinely isn't installed anywhere on
    this host", with no findings key at all in that return value.
  - `grep -rh '^\\s*bind-address' /etc/mysql/ 2>/dev/null | head -3`
    with no sudo - a permission-denied read is indistinguishable from
    "no such directive exists", silently skipping the HIGH-severity
    exposed-bind-address check with zero signal that it didn't run.
  - The cumulative effect: if `ss` and the bind-address grep BOTH fail
    to produce a result (for any reason - permission, timeout, transient
    SSH issue), `findings` stays empty through the whole function, and
    an unconditional `if not findings: append('ok', ...)` reports a
    confident "no obvious exposure issues found" with zero actual
    evidence behind it - the most severe finding of this audit (see the
    quality-audit session notes' SQL-5).

Design principles carried over from firewall_config.py
----------------------------------------------------------
  - Two independent `command -v` presence checks (mysql, mariadb) rather
    than one combined `which mysql mariadb` - gives the semantic layer
    "mysql present, mariadb absent" instead of a blurred "some SQL
    binary exists", and each can independently be PRESENT/NOT_PRESENT/
    UNKNOWN rather than collapsing collection failure into absence.
  - `ss -tlnp` is collected RAW here, with NO remote-side `grep` at all -
    this is deliberate, not an oversight: piping through a remote grep
    reintroduces exactly the exit-code collision this collector exists
    to eliminate (grep's own "no match" exit code vs a genuine ss
    failure). The full listening-socket table is returned as-is; finding
    the :3306 line and classifying its bind address (loopback vs
    non-loopback) is server_security.py's job, done in Python against
    the raw text - see that module's session notes on why classifying a
    non-loopback bind as "EXTERNAL" is NOT the same claim as "reachable
    from the Internet" (firewall/routing/NAT are separate, already-
    covered concerns).
  - bind-address config reads do NOT use sudo - same reasoning as
    firewall_config.py's nftables config file read: a config file's own
    filesystem permissions are the meaningful signal (world-readable is
    a legitimate fact; permission-denied is PERMISSION_DENIED evidence,
    not a reason to force root for symmetry with the presence checks).

Reused vs local primitives
-----------------------------
netaudit_pkg.ssh_utils.run_command_with_exit_code() (shared with
cve_audit.py and firewall_config.py) is reused directly - no new SSH
execution mechanism introduced here.

CommandResult is intentionally NOT imported from firewall_config.py and
NOT hoisted into a shared module, even though the two are currently
structurally identical. Per the quality-audit session's stated
principle (don't generalize until a genuinely repeated, stable pattern
is confirmed across more than one prior case), one repeat isn't yet
enough evidence to commit to a shared public data-shape contract - this
local copy can be reconciled with firewall_config.py's later, once a
third independent collector confirms the shape is actually stable.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass

from .ssh import SSHExecutor
from .ssh_utils import run_command_with_exit_code

# ===========================================================================
# Evidence data model
# ===========================================================================

@dataclass
class CommandResult:
    """Uninterpreted evidence from running one command with exit-code
    recovery. See firewall_config.CommandResult for the full contract
    docstring (completed/exit_code/stdout semantics) - identical shape,
    kept as a separate local type here deliberately (see this module's
    docstring, "Reused vs local primitives").
    """
    completed: bool
    exit_code: int | None
    stdout: str
    command: str


@dataclass
class SQLEvidence:
    """All MySQL/MariaDB-related evidence collected from one host, one
    field per independent source. No aggregation, no verdict - see this
    module's docstring. audit_sql() in server_security.py is the sole
    consumer responsible for turning this into PRESENT/NOT_PRESENT/
    UNKNOWN and LOCAL/EXTERNAL/NOT_LISTENING judgments and findings.
    """
    mysql_present: CommandResult
    mariadb_present: CommandResult
    listener: CommandResult  # raw `ss -tlnp` output - ALL listening sockets, not just 3306
    bind_address_config: CommandResult


# The three config paths this collector reads bind-address from, checked
# with plain `grep -r` (no sudo) - preserved from the pre-existing
# audit_sql()'s single /etc/mysql/ recursive grep rather than re-derived,
# since revisiting which paths are worth checking isn't this collector's
# decision; see server_security.py's audit_sql() for how the result is
# used.
MYSQL_CONFIG_DIR = '/etc/mysql/'


# ===========================================================================
# Per-source collectors
# ===========================================================================

def collect_mysql_present(ssh: SSHExecutor, timeout: int = 20) -> CommandResult:
    """Checks whether `mysql` is on PATH via `command -v` (POSIX shell
    builtin, not `which` - see firewall_config.py's _tool_is_present()
    for why). No sudo - PATH lookup needs no privilege.

    Does NOT classify the result into PRESENT/NOT_PRESENT/UNKNOWN here -
    exit_code follows `command -v`'s own convention (0=found,
    127=confirmed absent), but interpreting that is the semantic layer's
    job (server_security.py), same split as firewall_config.py's
    tool_is_present() helper.
    """
    stdout, code = run_command_with_exit_code(ssh, 'command -v mysql', timeout=timeout)
    return CommandResult(completed=code is not None, exit_code=code, stdout=stdout,
                          command='command -v mysql')


def collect_mariadb_present(ssh: SSHExecutor, timeout: int = 20) -> CommandResult:
    """Same as collect_mysql_present() but for `mariadb` - a separate,
    independent check (not a combined `which mysql mariadb`) so the
    semantic layer can distinguish which of the two is actually present,
    rather than a blurred "some SQL binary exists"."""
    stdout, code = run_command_with_exit_code(ssh, 'command -v mariadb', timeout=timeout)
    return CommandResult(completed=code is not None, exit_code=code, stdout=stdout,
                          command='command -v mariadb')


def collect_listener(ssh: SSHExecutor, timeout: int = 20) -> CommandResult:
    """Runs `ss -tlnp` and returns the RAW, unfiltered output - every
    listening TCP socket on the host, not just port 3306. Deliberately
    no remote-side `grep` (see this module's docstring for why): finding
    the 3306 line and classifying its bind address is server_security.py's
    job, done in Python against this raw text, so a remote pipeline's own
    exit-code quirks never leak into the presence/absence signal.

    No sudo - this collector does not assume `ss -tlnp` requires root
    (per the quality-audit review: don't presume a privilege requirement
    without confirming it; if it turns out `-p` process-name resolution
    needs root on some systems, that shows up as a confirmed nonzero
    exit code or missing process names in stdout, not as an assumption
    baked into this collector).
    """
    stdout, code = run_command_with_exit_code(ssh, 'ss -tlnp', timeout=timeout)
    return CommandResult(completed=code is not None, exit_code=code, stdout=stdout, command='ss -tlnp')


def collect_bind_address_config(ssh: SSHExecutor, timeout: int = 20) -> CommandResult:
    """Reads every `bind-address` directive under MYSQL_CONFIG_DIR via
    plain `grep -rh` (no sudo - see this module's docstring for why).
    Returns ALL matching lines raw, including commented-out ones -
    filtering out `#`-commented lines is semantic interpretation
    (server_security.py's job), not this collector's - the pre-existing
    audit_sql() code already knew commented-out bind-address lines are
    common in template configs and must not produce a false HIGH; that
    filtering logic is preserved but moved to the semantic layer here.
    """
    stdout, code = run_command_with_exit_code(
        ssh, f"grep -rh '^\\s*bind-address' {shlex.quote(MYSQL_CONFIG_DIR)}", timeout=timeout)
    return CommandResult(completed=code is not None, exit_code=code, stdout=stdout,
                          command=f'grep -rh bind-address {MYSQL_CONFIG_DIR}')


def collect_sql_config(ssh: SSHExecutor, timeout: int = 20) -> SQLEvidence:
    """Collects all MySQL/MariaDB evidence from one host in one call -
    the single entry point audit_sql() (server_security.py) uses."""
    return SQLEvidence(
        mysql_present=collect_mysql_present(ssh, timeout=timeout),
        mariadb_present=collect_mariadb_present(ssh, timeout=timeout),
        listener=collect_listener(ssh, timeout=timeout),
        bind_address_config=collect_bind_address_config(ssh, timeout=timeout),
    )
