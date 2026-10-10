# Tool presence over SSH sees /usr/sbin (F8)

Status: USER approved as a separate task (2026-10-10: «Да, автономно»).
Implementer: Claude. Reviewer: GPT/Codex. Stacked on A1 (#16) and A3 (#21).

## Evidence

- A3 (run 37981219631, Debian 12 sshd): a non-root SSH user's `PATH` has no
  `/usr/sbin`. A1 fixed this for nginx/sshd with `probe_remote_tool()`
  (system directories in front of `PATH`, exit marker, present / absent /
  unknown).
- `SSHExecutor.is_tool_installed()` (`ssh.py`) still runs a bare
  `command -v <tool>` and returns `exit_code == 0`. On Debian and Ubuntu
  `lynis` and `chkrootkit` live in `/usr/sbin`, so for a non-root user:
  - `lynis_audit` says "lynis is not installed on the server";
  - `rootkit_check` says "chkrootkit is not installed";
  - with `auto_install` confirmed, `ensure_tool_installed()` runs
    `apt-get install` for a package that is already there.
  A failed probe (no completion marker) also reads as "not installed".

## Design

- `SSHExecutor.tool_presence(tool) -> ToolProbe` — `probe_remote_tool()`
  (same rule as A1/F6). `is_tool_installed()` stays a bool for compatibility:
  `True` only for a confirmed `present`.
- `ensure_tool_installed()`: `present` → `(True, None)`; `unknown` →
  `(False, "could not determine whether <tool> is installed: …")` and **no**
  install attempt; `absent` → the existing allowlist + `apt-get` path.
- Callers distinguish the three states: `lynis_audit`, `aide_check`,
  `docker_audit` return an `error` "could not determine whether <tool> is
  installed" for `unknown`; `rootkit_check` reports it per tool instead of
  "not installed". `absent` keeps today's messages and the `auto_install`
  gate. Only the presence lines change (F3 #19 and F4 change other lines of
  the same files).
- sudo is unaffected: commands still pass the literal tool name, and sudo's
  `secure_path` selects the binary.

## Tests (RED first)

1. Unit: `tool_presence()` sends the `/usr/sbin:/sbin` prefix and a marker;
   exit 0 + path → present, exit 1 + empty → absent, no marker → unknown;
   `is_tool_installed()` is `False` for unknown.
2. Unit: `ensure_tool_installed()` with an unknown probe returns the
   "could not determine" error and never runs `apt-get`.
3. Unit: each caller turns an unknown probe into "could not determine …",
   never "not installed" and never an install.
4. E2E (A3 stand, `lynis` and `chkrootkit` added to the image): for a
   non-root user the bare `command -v` does not find them (evidence), while
   `tool_presence()` reports `present` and `is_tool_installed()` is `True`;
   a missing tool is `absent`; `lynis_audit` for a user without sudo fails on
   sudo, not on "not installed".
