# Sudo password for SSH audits — contract proposal (task 10)

Status: **APPROVED by USER rev.1** (2026-10-09, «Да, AUTONOMOUS»). USER
requested the task with a written spec (items 1–9, constraints,
done-criterion; `.ai/TASK.md`, task 10) and chose a **separate "Sudo
password" field**. Implementer: Claude. Reviewer: GPT/Codex.
Branch: `fix/sudo-password` from `main` @ `d157421` (PR #8 and #9 merged).

## Evidence

- **E1. The errors.** USER screenshots (2026-10-08): `nginx_hardening` →
  "nginx -T requires root — no read access to the config";
  `kernel_hardening` → "sysctl -a requires root — no read access to the
  effective kernel configuration". The SSH user has sudo with a password.
- **E2. A sudo password already works, but nothing says so.**
  `SSHExecutor` uses `password` for SSH login only when there is no
  `key_path`, and always as the `sudo -S` password (stdin, never argv). Before
  PR #8 the field was labelled "Password (if not using a key)", so with key
  login it was left empty; every sudo call was then `sudo -n` and refused.
- **E3. The refusal is invisible.** `nginx_config` and `nginx_config_v2` run
  `ssh.sudo('nginx -T 2>/dev/null')`: sudo's own message goes to
  `/dev/null`, the output is empty, the check says "requires root".
  `kernel_config` (`ssh.sudo('sysctl -a')`) and `ssh_config`
  (`ssh.sudo('sshd -T')`) look only at empty stdout too. No password, a wrong
  password and "not allowed in sudoers" all produce the same text.
- **E4. `sysctl -a` does not need root for this audit.**
  `docs/checks/kernel_hardening.md` §2 records the measurement on the
  project VM: without sudo `sysctl -a` returned every one of the 16 keys the
  audit reads; only 3 `kernel.apparmor_*` keys (not used) were denied. The
  check still refuses to run when sudo fails.

## Design

### C1. Separate `sudo_password` parameter (USER decision)

- New param `{'name': 'sudo_password', 'type': 'password', 'label': 'Sudo
  password (if sudo asks for one)'}` right after `password`, in every SSH
  check that runs something under sudo (server_audit, nginx_hardening,
  kernel_hardening, ssh_hardening, systemd_hardening, lynis_audit,
  rootkit_check, aide_check, docker_audit, ssh_audit and the four log
  checks; the final list is taken from the code during RED). Checks that never
  use sudo (`backup_check`, `cve_audit`, `log_discovery_audit`) do not get it.
- `password` becomes "SSH password (if no key)" (RU «Пароль SSH (если без
  ключа)»); `sudo_password` RU «Пароль sudo (если sudo его спрашивает)».
- `SSHExecutor(host, user, port, key_path, password, timeout=10,
  sudo_password='')`: SSH login is unchanged; the sudo secret is
  `sudo_password` when set, otherwise `password` (today's behaviour, so CLI
  calls with `--password` keep working). `SSHExecutor.sudo()` and
  `ssh_utils.run_sudo_with_exit_code()` both read that one secret.
- The secret only ever goes to sudo's stdin (`sudo -S -p ''`); it is never
  part of a command line. Unchanged, now covered by tests for the new field.

### C2. CLI without the password in argv

For any `type: password` param, the value `-` means "ask": the CLI reads it
with `getpass` (no echo) before the run, once per param name, e.g.
`netaudit run kernel_hardening --host h --key_path k --sudo_password -`.
A literal value still works (scripts), and README warns that it is visible in
`ps` and shell history. Web: the field is an `<input type=password>` like the
existing one (rendered from the param type).

### C3. Never stored or sent

`redaction.SECRET_PARAM_NAMES` gets `sudo_password`. That one change covers
`execution_context` in saved reports, `/api/report`, the AI prompt, Web presets
(PR #9) and `scrub_legacy_secrets`; `tests/test_redaction.py` already fails if
a `type: password` param name is missing from the set. Engine and streaming do
not log params (checked); no new log line prints them.

### C4. Clear sudo diagnostics

`nginx_config`, `nginx_config_v2`, `ssh_config` and `kernel_config` switch to
`run_sudo_with_exit_code(['nginx', '-T'])` / `['sshd', '-T']` /
`['sysctl', '-a']` (PR #8 helper, `sudo_error`). When sudo itself refuses,
the check error says why:

| sudo's answer (English sudo messages; other text is shown as is) | Error |
|---|---|
| a password is required (no secret given) | `sudo needs a password to run <cmd>: fill in "Sudo password", or allow <cmd> for this user with a NOPASSWD sudoers rule` |
| incorrect password attempt | `the sudo password was not accepted for <cmd>` |
| not allowed to execute / not in the sudoers file | `the SSH user may not run <cmd> with sudo (sudoers)` |
| anything else | `sudo refused <cmd>: <sudo message>` |

A non-sudo failure (exit ≠ 0 without `sudo_error`, e.g. a broken nginx
config) reports the command's own stderr, not "requires root". Empty output
after exit 0 keeps today's "nothing readable" wording.

### C5. `sysctl -a` without sudo when sudo is refused

`kernel_config` first tries `sudo sysctl -a`. If sudo refuses, it runs
`sysctl -a` as the SSH user and parses stdout (denied keys are reported on
stderr). If all 16 audited keys are present, the audit runs in full and the
result says `"collected_without_sudo": true` plus the sudo reason from C4. If
some are missing, there is no score (the existing "no partial score" rule) and
the error lists the missing keys together with the sudo reason. `nginx -T` and
`sshd -T` have no such fallback: their unprivileged output is genuinely
incomplete.

### Out of scope

- Changing sudoers, requiring root, `NOPASSWD: ALL` (USER constraints).
- SSH key passphrase (task 7, D2-A).
- `password` as login password together with a different sudo password
  through `targetpw`/`rootpw` sudoers defaults: works (the field is separate),
  no special handling.

## Tests (RED first; temporary HOME; no real SSH)

1. `SSHExecutor`: key + `sudo_password` → `sudo -S`, stdin == sudo password,
   key login unchanged; no `sudo_password` → falls back to `password`; neither →
   `sudo -n`; the password never appears in a sent command.
2. Real `/bin/sh` with a fake sudo that needs a password (task 7 harness):
   right password → `nginx -T` runs; wrong password → "was not accepted"; no
   password → "needs a password … Sudo password"; NOPASSWD rule for the binary
   → works without any password.
3. `kernel_hardening`: sudo refused + unprivileged `sysctl -a` with all 16 keys
   → full score, `collected_without_sudo`; one key missing → error naming it.
4. `nginx_hardening` / `ssh_hardening`: each sudo case from C4 → its message;
   nginx config error → nginx's stderr, not "requires root".
5. Secrets: a run with `sudo_password` → not in the saved report, raw SQLite
   row, `/api/report`, the AI prompt, a saved preset, scrub dry-run counts it.
6. CLI: `--sudo_password -` reads with `getpass` (monkeypatched), passes the
   value to the check, never puts it in the report.
7. Registry: every check whose code uses sudo has `sudo_password` after
   `password`, labels EN/RU as in C1.

Verification: full pytest including Web, full Ruff, bandit, pip-audit;
browser check of the two fields. The done-criterion (both checks pass under a
normal user with password sudo on a real server) is a USER step: there is no
sshd or container runtime here, and sudoers must not be changed.
