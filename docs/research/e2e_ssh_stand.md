# E2E stand: real sshd and sudo in GitHub Actions (stage A3)

Status: stage A, MODE: AUTONOMOUS. USER chose GitHub Actions (2026-10-09).
Implementer: Claude (debugging needs pushes; GPT/Codex's environment cannot
push). Reviewer: GPT/Codex.

## Why

Every SSH test so far runs against fakes; sudo with a password was confirmed
once by hand on USER's server (`.ai/FINDINGS.md`). Not covered: NOPASSWD and
scoped sudoers, a wrong or missing sudo password, a user without sudo, SSH
password login, the non-root `PATH` on Debian (A1 hypothesis), and whether a
real run leaks the password into SQLite, logs or the AI prompt.

## Stand

`tests/e2e/Dockerfile`: Debian 12 with `openssh-server`, `sudo`, `nginx`,
`procps`. Users (all with the same per-run random password):

| User | Login | sudo |
|------|-------|------|
| `pwsudo` | key | group `sudo` — every command, password required |
| `scoped` | key | `NOPASSWD` only for `/usr/sbin/nginx -T`, `/usr/sbin/sshd -T`, `/usr/sbin/sysctl -a` |
| `nosudo` | key | none |
| `pwlogin` | password only | none |

The CI job creates a throwaway ed25519 key and a random password
(`secrets.token_urlsafe`, masked in the log), starts the container on
`127.0.0.1:2222` and runs `pytest tests/e2e`. Nothing is baked into the image:
the entrypoint sets the passwords and `authorized_keys` from the environment
and a read-only mount. Root login is off. The stand exists only inside the CI
job.

`tests/e2e/test_ssh_stand.py` is skipped unless `NETAUDIT_E2E_HOST` is set, so
the normal test job and local runs are unaffected.

## Scenarios

1. The stand's non-root `PATH` (as SSH gives it) lacks `/usr/sbin` — the
   condition of the A1 hypothesis (evidence, not a product assertion).
2. `pwsudo`, key + correct sudo password: `nginx_hardening`, `ssh_hardening`,
   `kernel_hardening` return a hardening score and no error.
3. `pwsudo`, wrong sudo password: error says the password was not accepted.
4. `pwsudo`, no sudo password: error names the "Sudo password" field.
5. `scoped`, no password: `nginx_hardening` and `ssh_hardening` work (narrow
   NOPASSWD rules match the real binaries).
6. `nosudo` with its password as sudo password: error says sudoers does not
   allow it; `kernel_hardening` is either a score marked
   `collected_without_sudo` or an error listing missing keys — never an
   unmarked score.
7. `pwlogin`, password only: the SSH login works (the error, if any, comes
   from sudo, not from the connection).
8. Secrets: a run of `nginx_hardening` for `pwsudo` through
   `engine.run_checks_multi()`, saved with `history.save_report()`: the
   password is not in the SQLite file, not in the log output and not in the
   AI request body (`history.ai_analyze()` with the HTTP call faked).

## Dependencies

Scenarios 2 and 5 for nginx/sshd need A1 (PR #16): on `main` the `which …`
preflight cannot see `/usr/sbin` for a non-root user. The first CI run is made
on `main` on purpose, to record that as evidence; the branch is then stacked
on A1.
