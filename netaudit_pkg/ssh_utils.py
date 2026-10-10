"""
Shared helpers for recovering a command's exit code over SSHExecutor.run():
run_command_with_exit_code() for unprivileged commands and
run_sudo_with_exit_code() for commands under sudo (see its docstring).

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

import shlex
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from .ssh import SSHExecutor


def command_v_verdict(completed: bool, exit_code: int | None, stdout: str) -> str:
    """Classify a `command -v` probe across Bash (absent=1) and dash
    (absent=127). A completed 0 needs a path; failed output is ambiguous."""
    if not completed:
        return 'UNKNOWN'
    if exit_code == 0 and stdout.strip():
        return 'PRESENT'
    if exit_code in (1, 127) and not stdout.strip():
        return 'ABSENT'
    return 'UNKNOWN'


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


@dataclass(frozen=True)
class ToolProbe:
    """A PATH lookup: absent is confirmed, unknown means no safe conclusion."""

    status: Literal['present', 'absent', 'unknown']
    detail: str = ''


def probe_remote_tool(ssh: SSHExecutor, tool: str, *,
                      extra_dirs: Sequence[str] = ('/usr/sbin', '/sbin'),
                      timeout: int = 20) -> ToolProbe:
    """Find a remote binary with a system PATH prefix and an exit marker.

    Non-root SSH users may not have /usr/sbin in PATH. The prefix is used
    only for this unprivileged presence check: callers must never pass the
    path returned by command -v to sudo, where a user-writable PATH entry
    could otherwise select a root-run executable. Bash uses exit 1 for an
    absent command; dash uses 127. A missing completion marker stays unknown.
    """
    if not extra_dirs or any(not path.startswith('/') for path in extra_dirs):
        raise ValueError('extra_dirs must be absolute system directories')
    prefix = shlex.quote(':'.join(extra_dirs))
    command = f'PATH={prefix}:"$PATH" command -v {shlex.quote(tool)}'
    out, code = run_command_with_exit_code(ssh, command, timeout=timeout)
    if code == 0 and out.strip():
        return ToolProbe('present')
    if code in (1, 127) and not out.strip():
        return ToolProbe('absent')
    if code is None:
        return ToolProbe('unknown', f'{tool} presence check did not complete')
    return ToolProbe('unknown', f'{tool} presence check was inconclusive (exit {code})')


# ===========================================================================
# Exit-code recovery through sudo
# ===========================================================================

SUDO_ERROR_MAX_LEN = 200


@dataclass(frozen=True)
class SudoResult:
    """Uninterpreted result of one command run under sudo.

    completed/exit_code follow run_command_with_exit_code(): completed=False
    means the exit status could not be recovered (exit_code is None).
    exit_code is sudo's own status, which is the command's status when sudo
    ran it. sudo_error is the first stderr line starting with `sudo:` when
    the exit code is 1 - sudo itself refused or failed (no password,
    command outside a scoped rule, wrong password, command not found) - or,
    failing that, sudo's unprefixed sudoers denial ("... is not allowed to
    execute ...", "... is not in the sudoers file"). The `sudo:` prefix is the
    program name and is not localized; the denial texts are English. command is shlex.join(argv),
    the unwrapped command for messages; it never contains the password."""
    completed: bool
    exit_code: int | None
    stdout: str
    stderr: str
    sudo_error: str | None
    command: str


def _sudo_secret(ssh) -> str:
    """SSHExecutor.sudo_password (task 10); objects without it (older test
    doubles) fall back to .password, which is what SSHExecutor itself does."""
    secret = getattr(ssh, 'sudo_password', None)
    return secret if secret is not None else ssh.password


def describe_sudo_refusal(ssh, result: SudoResult) -> str:
    """One-line reason for a refused sudo, for check errors (task 10,
    docs/research/sudo_password.md C4). Matches sudo's English messages;
    any other text (a localized sudo, an unknown refusal) is shown as is."""
    message = result.sudo_error or ''
    text = f'{message}\n{result.stderr}'.lower()
    command = result.command
    if 'incorrect password' in text or 'sorry, try again' in text:
        return f'the sudo password was not accepted for {command}'
    if 'not allowed to execute' in text or 'not in the sudoers' in text or 'may not run sudo' in text:
        return f'the SSH user may not run {command} with sudo (sudoers)'
    if not _sudo_secret(ssh) and ('password is required' in text or 'terminal is required' in text):
        return (f'sudo needs a password to run {command}: fill in "Sudo password", '
                f'or allow {command} for this user with a NOPASSWD sudoers rule')
    return f'sudo refused {command}: {message}'


# sudo's sudoers denials carry no "sudo:" prefix: "Sorry, user u is not
# allowed to execute '...' as root on host." / "u is not in the sudoers file."
_SUDOERS_DENIAL_MARKERS = ('is not allowed to execute', 'is not in the sudoers file')


def _sudo_error(exit_code: int | None, stderr: str) -> str | None:
    if exit_code != 1:
        return None
    lines = [ln.strip() for ln in stderr.splitlines()]
    line = next((ln for ln in lines if ln.startswith('sudo:')), None)
    if line is None:
        line = next((ln for ln in lines if any(m in ln for m in _SUDOERS_DENIAL_MARKERS)), None)
    return line[:SUDO_ERROR_MAX_LEN] if line else None


def run_sudo_with_exit_code(ssh: SSHExecutor, argv: Sequence[str], timeout: int = 20) -> SudoResult:
    """Runs argv under sudo and recovers its exit code.

    sudo runs only the real command; the completion-marker group around it
    runs as the SSH user:

        { sudo -n -- <argv>; rc=$?; printf '\\n%s:%s\\n' '<marker>' "$rc"; }

    so a scoped sudoers rule (e.g. NOPASSWD for /usr/sbin/nft only, or a
    fail2ban status wrapper) matches the binary it names. The previous
    per-module helpers ran `sudo sh -c '<cmd>; marker'`, which asks sudoers
    for `sh` and is refused by any such rule.

    With a sudo password (ssh.sudo_password, which falls back to the SSH
    password), `sudo -S -p ''` reads it from stdin, the same rule as
    SSHExecutor.sudo(). It is never part of the command line. sudo skips stdin when no password is needed
    (NOPASSWD or a cached timestamp); the command then inherits the
    password line on its stdin. Commands passed here must not read stdin.

    argv is joined with shlex.join(): every element is one argument, so no
    shell syntax (pipes, `;`, redirections) can reach the remote shell.
    """
    if isinstance(argv, str):
        raise TypeError('argv must be a sequence of arguments, not a command string')
    if not argv:
        raise ValueError('argv must not be empty')
    command = shlex.join(argv)
    marker = f'__NETAUDIT_RC_{uuid.uuid4().hex}__'
    secret = _sudo_secret(ssh)
    if secret:
        sudo = "sudo -S -p ''"
        stdin_data = secret + '\n'
    else:
        sudo = 'sudo -n'
        stdin_data = None
    wrapped = f"{{ {sudo} -- {command}; rc=$?; printf '\\n%s:%s\\n' '{marker}' \"$rc\"; }}"
    if stdin_data is None:
        out, err = ssh.run(wrapped, timeout=timeout)
    else:
        out, err = ssh.run(wrapped, timeout=timeout, stdin_data=stdin_data)

    if marker not in out:
        return SudoResult(completed=False, exit_code=None, stdout=out, stderr=err, sudo_error=None, command=command)
    body, _, tail = out.rpartition(marker)
    try:
        code = int(tail.lstrip(':').strip())
    except ValueError:
        return SudoResult(completed=False, exit_code=None, stdout=body, stderr=err, sudo_error=None, command=command)
    return SudoResult(completed=True, exit_code=code, stdout=body.rstrip('\n'), stderr=err,
                      sudo_error=_sudo_error(code, err), command=command)
