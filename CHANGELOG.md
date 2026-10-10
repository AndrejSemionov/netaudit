# Changelog

## Unreleased

- Rootkit, Lynis and AIDE audits now require a confirmed sudo command result
  before reporting a clean scan. Failed or partial runs are marked incomplete;
  AIDE change bitmasks and rootkit warnings remain visible.

- `deploy.sh` (layout B) backs up the files it changes and the database before
  copying, rolls back by itself when tests, the restart, the smoke test or
  writing the deployment manifest fail, and has `./deploy.sh --rollback`. It
  deploys everything since the last deployed commit (not only the last pull),
  removes files deleted in git, and treats HTTP 401 from the smoke test (Basic
  Auth on) as a warning. Failing to remove an old backup after a finished
  deploy is a warning too.
- In the Russian interface, the SSH fields shared by many checks (host, user,
  port, key, SSH and sudo passwords, log lines) are translated even where the
  check itself has no translation yet.
- `lynis_audit`, `rootkit_check`, `aide_check` and `docker_audit` find tools in
  `/usr/sbin` for a non-root SSH user (lynis and chkrootkit live there on
  Debian); when the presence check itself fails they say so instead of
  "not installed", and `auto_install` never installs over such a result.
- SSH checks that use sudo have a separate **Sudo password** field
  (`sudo_password`). It goes to `sudo -S` on stdin and is never stored; when it
  is empty the SSH password is used, as before. The `password` field is now the
  SSH login password only. CLI: `--sudo_password -` asks for it without echo.
- `sql_injection` no longer reports "no input points found" for a page it
  could not fetch, and `breach_check` reports an address as partially checked
  (summary key `partial`) when one of the selected sources failed.
- A refused sudo is explained (no password, password not accepted, not allowed
  by sudoers) instead of "requires root" for `nginx -T`, `sshd -T` and
  `sysctl -a`; a failing `nginx -T` reports nginx's own error.
  `kernel_hardening` reads `sysctl -a` without sudo when sudo refuses and runs
  in full when every audited key is readable.
- sudo now runs the real command instead of `sh -c '<command>'` for the
  Fail2Ban and firewall parts of `server_audit`, `systemd_hardening`, Logs
  Audit reads of root-only files, and `aide_check`. Narrow `sudoers` rules for
  one binary (including the Fail2Ban `status-wrapper` mode) now work without a
  password. README "SSH and sudo" lists the exact commands.
- Docker, backup and log discovery checks distinguish failed collection from
  confirmed absence. Incomplete container inspection, backup listing or
  integrity checks, and unknown log metadata now surface for manual review.
- When sudo refuses a command, the report shows sudo's own message. A host
  where sudo refuses `fail2ban-client status` now reports `F2B-STAT-003`
  ("status could not be confirmed even with sudo") instead of `F2B-STAT-001`
  ("could not determine fail2ban status"); both are low. Trends show this
  once, as one finding resolved and one new.
- The systemd sandboxing audit now confirms a unit's `LoadState` and requires
  a nonempty directive model before reporting it as hardened.
- `aide_check` no longer reports "AIDE database initialized" when sudo refused
  `aide --init` or the new database was not moved into place, and a refused
  sudo is no longer reported as a missing database.
- UFW, Fail2Ban and MySQL/MariaDB presence checks include system binary
  directories in the SSH PATH lookup. Bash exit 1 and dash exit 127 with
  empty output mean confirmed absence; malformed output remains unknown.
- An encrypted SSH key that ssh-agent does not provide fails with an explicit
  error. The SSH `password` field is labelled as the sudo password too.
- `ssl` reports a failed certificate verification (expired, self-signed,
  wrong host) instead of `ok` when openssl is installed.
  `web_security_external` detects servers that still accept TLS 1.0/1.1 on
  hosts with OpenSSL 3 (it could not before) and says when it could not
  test them; an unreachable site is an error, not a list of missing
  headers; a sensitive path that could not be requested is reported as not
  checked. Security headers are read from the final response of a redirect
  chain.
- Removed the unused `SSHExecutor.needs_sudo_password()`.
- Raw outputs no longer hide failures: `ssh_audit` keeps journalctl's
  permission hint and exit status and no longer prints "no access" for an
  sshd_config without the grepped lines; `dig` reports the DNS status
  (NXDOMAIN, SERVFAIL as an error); the local `firewall` check shows why
  `ufw`/`nft` failed; `ping`/`arping` report unparsable output as an error.
- Web presets no longer store or return SSH passwords; enter the password
  again after applying a preset. Presets saved earlier are stripped when read,
  and `scrub_legacy_secrets` now also removes passwords from the `presets`
  table (dry-run prints `presets=`, `presets_affected=`, `presets_malformed=`).
- Command injection fixes: `cve_audit` quotes paths found on the target
  (WordPress and composer.lock locations, which any user who can write under
  `/var/www` or `/home` controls); `systemd_hardening` accepts only valid unit
  names; `backup_check` accepts only absolute directories and quotes them;
  the MikroTik `target_ip` must be an IP address.
- `cve_audit`: when the OSV vulnerability database cannot be reached (or
  answers with an error or non-JSON), packages are reported as "CVE matching
  could not be completed" instead of "no known CVEs found". A host where
  not even the running kernel was detected is reported as an error.
- `requirements.txt` requires pydantic 2 explicitly (`pydantic>=2.0`); the Web
  settings endpoint for history capture no longer uses the pydantic v1 API.
  Tests use `httpx2`, as starlette's TestClient now expects
  (`requirements-dev.txt`). pytest runs without deprecation warnings.

## 1.0.0 — 2026-10-08

- Add deterministic history for state findings, server audit sections, and
  hardening scores in the CLI and web interface. A missing finding is marked
  **not evaluated** when its area could not be checked.
- Show SSH authentication, Nginx, kernel, and Fail2Ban log results as bounded
  observations without state-style resolved/new claims.
- Add stable IDs to supported findings. Findings without an ID still count
  toward observed severity totals but are not matched across runs.
- Add strictly prior report history and deterministic changes to AI context.
- Save execution context for web runs and redact SSH password parameters on
  report write, read, and AI egress. Add an opt-in legacy SQLite scrub tool;
  no existing database is rewritten automatically.
- Escape saved report, AI, and history data in the web interface to prevent
  stored script execution. Correct SSH log source failure handling and replace
  deprecated FastAPI lifecycle hooks.
- AI analysis of a saved report no longer receives that same report as its own
  "previous" run, and analysing an older report never uses later runs.
- Report one version everywhere: the web API said 2.0 while the CLI said 0.2.0.
- CI lints with the full Ruff rule set of a pinned Ruff version; remaining
  exceptions are point-in-place `noqa` with a reason.

Upgrading an existing server: see [docs/upgrade_to_1_0.md](docs/upgrade_to_1_0.md)
(database backup, checks, optional removal of old SSH passwords, rollback).
