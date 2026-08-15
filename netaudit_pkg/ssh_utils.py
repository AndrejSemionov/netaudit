"""
Shared helper for recovering a command's exit code over SSHExecutor.run().

SSHExecutor.run() (see ssh.py) returns only (stdout, stderr) - no exit
code - because it's the shared executor for every SSH-based check module
(server_audit, lynis_audit, rootkit_check, aide_check, backup_check,
cve_audit, ssh_audit, history_capture, mikrotik_sniffer, and now
firewall_config), and most of them never need one. Adding an exit-code
parameter to SSHExecutor.run() itself would be a signature change with a
wide blast radius for a need only a few collectors actually have.

This module exists because that need turned out not to be a one-off:
cve_audit's version-collection commands (dpkg-query, apt-cache show) and
firewall_config's state-collection commands (ufw status, nft list
ruleset, iptables -S, cat on config files) both hit the exact same
problem independently - stdout-only heuristics cannot reliably
distinguish "the command ran and legitimately produced empty output"
from "the command failed to run at all" (permission denied, SSH channel
drop, timeout). Both consumers need the same three-way distinction:

    exit_code == 0     - command completed successfully (stdout may
                          still legitimately be empty - e.g. `nft list
                          ruleset` on a host with zero configured tables)
    exit_code != 0      - command completed but reported failure through
                          the normal exit-status channel (e.g. `ufw
                          status` refusing without root, dpkg-query
                          reporting a package isn't installed)
    exit_code is None  - completion could not be confirmed at all: SSH
                          channel drop, timeout, or truncated output
                          before the completion marker was written. This
                          is a genuine unknown, and callers must never
                          treat it as either a confirmed success or a
                          confirmed failure - see each collector's own
                          usage for what "unknown" means in that
                          context (e.g. cve_audit must not fall back to
                          an unconfirmed version string; firewall_config
                          must not report a backend as INACTIVE or
                          ACTIVE on the strength of an unconfirmed
                          empty result).

First extracted from cve_audit.py's local _run_with_exit_code() once a
second, independent collector (firewall_config.py) needed the exact same
mechanism - see the netaudit quality-audit session notes for the
decision not to generalize on the first occurrence, and to generalize
once a second, unrelated caller confirmed this is a real SSHExecutor gap
rather than a one-off need.
"""

from __future__ import annotations

import uuid

from .ssh import SSHExecutor


def run_command_with_exit_code(ssh: SSHExecutor, cmd: str, timeout: int = 20) -> tuple[str, int | None]:
    """Runs `cmd` and returns (stdout, exit_code).

    The command is wrapped in a shell group so `$?` is captured
    immediately after it runs, before anything else (including the
    `printf` that reports it) can change it:

        { <cmd>; rc=$?; printf '\\n%s:%s\\n' '<marker>' "$rc"; }

    The marker is a fresh random token per call (not a fixed string) -
    generated with uuid4, which is not influenced by (and does not
    depend on knowledge of) `cmd`'s own output, so an arbitrary remote
    command's stdout cannot coincidentally collide with it. If a
    collision somehow still occurred, the output up to the LAST marker
    occurrence is what's returned (via rpartition), and a coincidental
    non-numeric tail after that instance falls back to exit_code=None -
    a false collection-failure-unknown, never a false confirmed-success.
    That's the deliberately safe failure direction: an unnecessary
    "couldn't confirm" is a minor loss of information, while a wrongly
    confirmed exit code could feed a false-PASS security finding
    downstream.

    `cmd` is run as-is inside the shell group - callers remain
    responsible for their own quoting/escaping of `cmd` itself, same as
    a direct SSHExecutor.run() call.
    """
    marker = f'__NETAUDIT_RC_{uuid.uuid4().hex}__'
    wrapped = f"{{ {cmd}; rc=$?; printf '\\n%s:%s\\n' '{marker}' \"$rc\"; }}"
    out, _ = ssh.run(wrapped, timeout=timeout)
    if marker not in out:
        return out, None
    body, _, tail = out.rpartition(marker)
    code_str = tail.lstrip(':').strip()
    try:
        code = int(code_str)
    except ValueError:
        return body, None
    return body.rstrip('\n'), code
