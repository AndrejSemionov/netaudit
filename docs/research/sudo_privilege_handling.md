# sudo privilege handling — fix contract proposal (task 7)

Status: **DRAFT rev.1** (2026-10-08). USER chose the task ("Дефекты sudo
(1–4)", MODE: AUTONOMOUS). Implementer: Claude (proposed). Reviewer:
GPT/Codex. USER approves this contract and the open decisions D1–D2 before
RED/GREEN.

## Evidence

All references are to `main` @ `be1decc` (1.0.0).

- **E1. Scoped sudoers never work for four collectors.**
  `_run_sudo_with_exit_code()` exists in four copies
  (`fail2ban_config.py:294`, `firewall_config.py:178`,
  `checks/systemd_hardening.py:66`, `log_collection.py:104`). Each sends
  `sudo -n sh -c '<cmd>; rc=$?; printf <marker>'`. sudoers then authorizes
  `sh`, not the real binary. A rule such as
  `audit ALL=(root) NOPASSWD: /usr/local/bin/fail2ban-status-only` refuses
  the call, the marker never prints, and the result is `completed=False`.
  The project ships an option for exactly this setup:
  `server_audit` → `fail2ban_mode='status-wrapper'`
  (`fail2ban_config.py:250`, `checks/server_security.py:249`). Without a password that option cannot work.
  `ssh.py:150–163` also says sudo must be probed per command *because*
  scoped rules exist. `log_collection.py:117–127` documents the limitation
  as deferred.
- **E2. sudo's own failure is invisible.** The wrappers discard stderr, so
  `sudo: a password is required` never reaches the report. The user gets
  "did not complete" or `F2B-STAT-001` (low, "could not determine fail2ban
  status"). `systemd_hardening.py:229` tells the user to "see the SSH/sudo
  error above". No such error is shown.
- **E3. `SSHExecutor.needs_sudo_password()` is dead code**
  (`ssh.py:192`). Production code never calls it. Its generic
  `sudo -n true` probe contradicts the per-command rule in E1. Callers
  rejected it on purpose (`firewall_config.py:84–95`). It is still part of
  the class, fakes, and 6 test files.
- **E4. AIDE init reports false success.**
  `aide_check.py:142`: `ssh.sudo('aide --config … --init 2>&1')`. When
  sudo refuses, `out` is `sudo: a password is required`. The success test
  is `'error' in out.lower()`, which does not match, so the check returns
  `ok: AIDE database initialized`. The `mv aide.db.new aide.db` result is
  ignored too. The same chain also misleads earlier, in check mode:
  `sudo -n test -f A || test -f B && echo EXISTS || echo MISSING`. Only
  the first `test` runs under sudo. On refusal the second `test` runs
  unprivileged, gets permission denied, and the result is "MISSING". The
  check then tells the user to *run init first*, which is the
  false-success path above. AIDE: "the exit status is 0 if no errors
  occurred", and errors are 14–23 (man aide(1), Debian bookworm).
- **E5. One `password` field, no key passphrase** (`ssh.py:115–118`).
  `password` is the SSH login password when there is no key, and the
  `sudo -S` password in every case. paramiko gets no `passphrase`. An
  encrypted key works only through ssh-agent (`allow_agent=True` when
  `key_path` is set). The 18 checks label the field
  "Password (if not using a key)", which is wrong: with a key it is still
  the sudo password.
- **Local probe** (this machine, sudo 1.9.15p5): `sudo -n -- /usr/bin/true`
  without a cached credential → stderr `sudo: a password is required`,
  exit 1. Message text can be localized. The `sudo:` prefix is the program
  name and is not.

## Design

### S1. One shared sudo helper; sudo wraps only the real command

`ssh_utils.run_sudo_with_exit_code(ssh, argv, timeout=20) -> SudoResult`.

- `argv` is a non-empty sequence of strings. The command line is
  `shlex.join(argv)`, so every element is a single argument. No shell
  operators, pipes or redirections can be passed (they would arrive as
  literal arguments).
- The marker group runs as the SSH user. sudo runs only the real binary:

  ```
  { sudo -n -- <shlex.join(argv)>; rc=$?; printf '\n%s:%s\n' '<marker>' "$rc"; }
  ```

  With a password: `sudo -S -p '' --` in place of `sudo -n --`. The
  password goes to the channel stdin (see S1a). The rule is the same as
  `SSHExecutor.sudo()`: a password means `-S`, no password means `-n`.
- The exit code is recovered the same way as in
  `run_command_with_exit_code()` (random uuid4 marker, `rpartition`,
  `None` when absent or unparsable).
- `SudoResult` (frozen dataclass): `completed`, `exit_code`, `stdout`,
  `stderr`, `sudo_error`, `command` (`shlex.join(argv)`, no secrets).
- `sudo_error`: the first stderr line that starts with `sudo:`, but only
  when `completed and exit_code == 1`. Otherwise `None`. Truncated to 200
  characters. sudo never echoes the password. A false positive (a command
  that prints `sudo:` and exits 1) only changes wording: exit 1 is a
  failure in every consumer either way.

**S1a.** `SSHExecutor.run(cmd, timeout=20, stdin_data=None)`. With
`stdin_data`, it writes the data, flushes, and calls `shutdown_write()`,
the same as `sudo()` today. Existing callers do not change.

Known limit (unchanged from today): with `-S`, sudo skips stdin when no
password is needed (NOPASSWD or a cached timestamp). The command then
inherits the password line on its stdin. None of the commands in scope
read stdin (`fail2ban-client`, the status wrapper, `ufw`, `nft`,
`iptables`, `systemd-analyze`, `tail`, `test`, `aide`, `mv`).

Alternative considered: read `channel.recv_exit_status()` from paramiko
instead of the marker. It is cleaner, but it changes the shared
executor's contract and the marker-based test fakes for every collector.
Rejected for this task.

### S2. The four collectors use S1

The local `_run_sudo_with_exit_code` copies become thin adapters (or are
removed) that call S1 and map to the module's own result type. Call sites
pass argv:

- firewall: `['ufw','status']`, `['nft','list','ruleset']`, `['iptables','-S']`;
- fail2ban: `shlex.split(commands.status())`, `shlex.split(commands.jail_status(name))`
  (the strings are already `shlex.quote`d);
- systemd: `['systemd-analyze','security',unit,'--no-pager','--json=short']`
  and the text call without `--json`. `2>&1` is gone. JSON is parsed
  from stdout only. Error detection and detail (`Unknown…`,
  `not installed`, `command not found`, exit≠0) read stdout+stderr;
- logs: `['tail','-n',str(lines),source.path]`.

Each module result gets `sudo_error: str | None = None`.
`log_discovery.CommandResult.stderr` now carries the real stderr. Today
nothing reads it.

Semantics of a sudo refusal (E2), per consumer:

| Consumer | Today | After |
|---|---|---|
| fail2ban status | `completed=False` → UNKNOWN → `F2B-STAT-001` | `exit_code=1`, `sudo_error` set → **ACCESS_DENIED → `F2B-STAT-003`** (low, same severity). Detail includes `sudo_error` |
| fail2ban jail | UNKNOWN | UNKNOWN (unchanged, the verdict already treats exit≠0 as UNKNOWN) |
| firewall ufw/nft/iptables | UNKNOWN "did not complete" | UNKNOWN; reason `… failed (exit 1): sudo: a password is required` |
| systemd | error "did not complete" | error `sudo refused systemd-analyze: <sudo_error>` + hint (password or a NOPASSWD rule for `systemd-analyze`) |
| logs (`tail` under sudo) | `completed=False` → source unusable | `exit_code=1` → source unusable (2e rule: usable only on exit 0); journal fallback unchanged |

This matches the existing `firewall_config.CommandResult` docstring
("nonzero exit_code is a confirmed failure (e.g. … sudo authentication
failure)"). Today it holds only on paper.

**Trend note:** a host where sudo is refused moves from `F2B-STAT-001` to
`F2B-STAT-003` once. Both are low and both are
`requires_manual_verification`. CHANGELOG records it. A host with
correctly scoped sudoers gets a real fail2ban/firewall result instead of
UNKNOWN. That is the purpose of the fix.

### S3. Remove `needs_sudo_password()` (decision D1)

Proposed: delete `SSHExecutor.needs_sudo_password()` and
`_no_password_sudo` from `ssh.py`. Delete the method and the
`no_password_sudo` argument from `FakeSSHExecutor`. Delete
`test_ssh.py::test_needs_sudo_password` and the four
`*_needs_sudo_password_no_longer_blocks_the_check` tests (aide, docker,
lynis, rootkit). They only prove that a method nobody calls is not
called. The useful signal ("sudo needs a password for *this* command")
is `sudo_error` from S1, per command, which is correct for scoped
sudoers. Alternative: keep it as an upfront gate. The project rejected
that design (E3).

### S4. AIDE without false success

- **init**: `run_sudo_with_exit_code(['aide','--config',AIDE_CONFIG,'--init'], timeout=600)`.
  Success requires `completed and exit_code == 0`. Then activation runs
  as two argv steps: `['mv','/var/lib/aide/aide.db.new','/var/lib/aide/aide.db']`,
  and if that fails, `['mv', '…aide.db.new.gz', '…aide.db.gz']`. `ok:
  initialized` only when the init and one `mv` returned exit 0. Otherwise
  `{'error': …}`: sudo refusal (with `sudo_error`), AIDE error code
  (14–23 → name from the man page table, unknown code → number), or "new
  database not activated". `output_tail` stays.
- **database presence (check mode)**: two argv calls,
  `['test','-f','/var/lib/aide/aide.db']`, then `.gz`, both under sudo.
  MISSING only when both completed with exit 1 and neither has
  `sudo_error`. A sudo refusal or incomplete result →
  `{'error': 'sudo refused …'}`, never "run init first".
- **check**: `aide --check` stays on `ssh.sudo()` and summary parsing
  (out of scope). One addition: if the output starts with a `sudo:` line
  and has no Summary block, return `{'error': 'sudo refused aide --check: …'}`
  instead of "failed to parse".

### S5. Password and key passphrase (decision D2)

- **D2-A (recommended, minimal):** no new secret field.
  (1) If the key is encrypted (`paramiko.PasswordRequiredException`), the
  connect error says: "private key is encrypted; load it into ssh-agent
  (CLI) or use an unencrypted key for the service account". (2) The
  `password` label in the 18 checks (EN + RU) becomes "SSH password (no
  key) / sudo password". (3) README/README.ru get a short "SSH and sudo"
  section: when the password is used, and the exact argv each S2/S4
  collector runs under sudo, for scoped NOPASSWD rules.
- **D2-B:** everything in D2-A plus a `key_passphrase` param (type
  `password`) in all SSH checks → paramiko `passphrase=`;
  `redaction.SECRET_PARAM_NAMES` gets `key_passphrase` (the
  `test_redaction` guard already enforces this). Risk: Web presets
  currently save every param, including secrets, in plain text (FINDINGS
  2026-10-08). A new secret field increases that exposure until presets
  are fixed.
- Rejected: a separate `sudo_password`. sudo asks for the invoking
  user's password by default, which is the same password as SSH login
  without a key.

## Out of scope (recorded in `.ai/FINDINGS.md`)

- About 45 other direct `ssh.sudo('<shell string>')` calls (kernel, ssh,
  nginx, docker, lynis, rootkit, system, `aide --check`). Simple commands
  already reach sudo directly. Pipelines and `||` elevate only the first
  stage. Audit separately.
- `systemd_hardening`: `unit` goes unquoted into
  `ssh.run(f'systemctl status {unit} …')` (unprivileged shell injection
  by the operator). S2 removes it from the **sudo** call, because `unit`
  becomes one argv element. The unprivileged line needs a separate fix.
- Web presets store `password` in plain text and return it from
  `GET /api/presets`.

## Tests (RED first, temporary HOME, no real SSH)

1. S1 command shape: no `sh -c`. `sudo -n -- <args>` inside the marker
   group without a password. `sudo -S -p '' --` and
   `stdin_data == password + '\n'` with one. An argument such as
   `x; echo PWNED` stays one quoted argument.
2. S1 against a real `/bin/sh` (local executor, `subprocess`): a fake
   `sudo` script first in `PATH` emulates a scoped allow-list. It allows
   only listed binaries, needs `-n` or `-S`, and otherwise prints
   `sudo: a password is required` with exit 1. Assertions: an allowed
   `nft` runs and its exit code (0, 3) comes through; a disallowed binary
   gives `completed=True, exit_code=1, sudo_error=…`; the pre-fix
   `sh -c` shape is refused by the same fake (regression evidence); the
   injection argument is not executed.
3. S1a `SSHExecutor.run(stdin_data=…)`: write, flush, `shutdown_write`
   on a mocked paramiko client. Without `stdin_data`, no stdin use.
4. S2 adapters: firewall, fail2ban (refusal → `F2B-STAT-003` with
   `sudo_error` in detail), systemd (refusal → error naming sudo; JSON
   parsed from stdout only), logs (refusal → source unusable, journal
   fallback). Replace `test_run_sudo_with_exit_code_uses_sh_dash_c_wrapping`,
   which asserts the defect, with its inverse.
5. S3: `SSHExecutor` has no `needs_sudo_password`.
6. S4: init refused → error, not ok; init exit 17 → error naming the
   configuration error; init ok but `mv` fails → error; init and `mv` ok
   → ok; presence refused → sudo error, not "run init first"; both tests
   exit 1 → existing "not found" error; `aide --check` refused → sudo
   error.
7. D2 per USER choice (label text, encrypted-key message; for B,
   passphrase passed to paramiko and redacted).

Verification: full pytest including Web, full Ruff, bandit, pip-audit,
`git diff --check`. The fake-sudo shell test is the strongest local
evidence available: this machine has no sshd or container runtime, and
sudoers here must not be changed. A real scoped-sudoers host is a USER
step (the README section from D2-A lists the rules).
