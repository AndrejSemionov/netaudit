# Changelog

## Unreleased

- Security: `dig --hostname -f<file>` (CLI, or the same value in a Web API
  request) made dig read a local file in batch mode, and its lines came back
  in the check's error, in the report and in the AI request. A check's
  target is now checked before anything runs: a host name or an IP address
  that never starts with `-` (`ping`, `mtr`, `tcptraceroute`, `arping`,
  `dig`, `dns_audit`, `cert_transparency`, `iperf`, MikroTik router), an
  `http://` or `https://` URL (`file://` was fetched by `curl`), email
  addresses, a network interface name. `dig` record type is now a list.
  Numbers have ranges: port 1-65535, count 1-1000, durations 1-3600 s,
  lines 1-100000, hops 1-64, window up to 720 h. A wrong value is refused
  (`Wrong value: …`, Web API: 400); the message never shows the value. The
  Web form's values all pass.
- Stable finding ids for the remaining state checks: `aide_check`,
  `cert_transparency`, `cve_audit` (one id per package and vulnerability,
  e.g. `CVE-VULN-001:nginx:CVE-2023-44487`), `log_discovery`, `lynis_audit`
  (by Lynis test id), `rootkit_check` and `sql_injection`. Trends, the AI
  context and Telegram notifications now say which of their problems was
  fixed, appeared or persists, not only that the count changed; titles with
  changing numbers (`files changed: 12`) no longer matter. Only an `id` key
  is added; titles, severities and order are unchanged. The catalogue is
  `docs/checks/finding_ids.md`.
- Firewall audit (`server_audit`): "iptables INPUT is effectively open"
  (FW-IPT-001, high) is no longer reported when the input is filtered by
  nftables. With the nf_tables backend, the Debian and Ubuntu default,
  `iptables -S` shows only the iptables-nft tables, so a host with a native
  nftables or firewalld firewall got a false HIGH. Now it is "ok" and names
  the nftables chain that surely drops a new TCP connection from a public
  address to a port no rule names. A drop for some packets
  (`ct state invalid drop`) or for IPv6 only does not count, and a rule that
  may accept everything (`ip saddr 0.0.0.0/0 accept`, `ct state new accept`,
  a named set) keeps the HIGH. When `iptables -S` warns about unread iptables-legacy tables,
  the result is "could not determine" (FW-IPT-002). The detail names the
  backend (`iptables -V`). If the nftables ruleset cannot be read, the HIGH
  stays and the detail says so.
- Web: every check reads in Russian in the Russian interface. 15 checks
  (`aide_check`, `backup_check`, `breach_check`, `cert_transparency`,
  `docker_audit`, the log audits, `kernel_hardening`, `nginx_hardening`,
  `rootkit_check`, `speedtest`, `ssh_hardening` and others) had their name,
  description and options in English, and the `sql_injection` choices were
  shown in English because their translations were keyed by old values. A
  test now keeps every check, parameter and choice translated. The English
  interface is unchanged.
- Web: the Telegram hint in Settings says what uses the token and chat ID
  (scheduled audits: `run --notify`, `setup-timer`) instead of "for future
  background monitoring".
- Security: a number option could carry a shell command to the audited
  server. `ssh_auth_audit --lines '5; id'` (CLI, or `"lines": "5; id"` in a Web
  API request) ran `journalctl -n 5; id` there, when the check fell back to
  the journal. Number values are now checked (below), and the journal command
  quotes the value, as the file command already did.
- CLI `run` and the Web API check option values against their type before
  anything runs. A yes/no option takes `true`/`false` (also `yes`/`no`,
  `1`/`0`, `on`/`off`); before, the CLI passed the text on, so
  `--auto_install false` or `--use_rkhunter false` worked as "yes". A number
  takes a number, and a choice takes one of its values (`netaudit list` now
  shows them; `aide_check --mode check`/`init` keep working). A wrong value
  is refused before any password prompt (`Wrong value: …`; Web API: 400),
  and the message names the flag and what it takes, never the value. The Web
  form sends the right types and is unchanged. Old CLI reports saved a yes/no
  option as text: trends read them as the check did, so the first run with a
  real "no" shows the setting as changed.
- Trends no longer call a finding "resolved" when the check settings changed
  between the two compared runs: for example a subdomain dropped from the
  `dns_audit` list, a directory dropped from `backup_check`, a relaxed
  threshold, or another `systemd_hardening` unit. Such a run looked at
  something else, so every finding that disappeared is "not evaluated", and
  the change lists the settings (`params_changed`, names only). This applies
  to CLI and Web trends, the AI context and the Telegram notification.
  A missing setting counts at its default, so CLI and Web runs with the same
  values compare equal; how NetAudit connects (`user`, `port`, `key_path`)
  and `auto_install` are not settings. Reports are not changed.
- CLI `run` refuses a site check whose target was not given, when its default
  target is the placeholder `example.com`: `ssl`, `http`, `security_headers`,
  `web_security_external` (`--url`), `dns_audit`, `cert_transparency`
  (`--domain`). Before, `run dns_audit` alone audited `example.com` and the
  report looked like one about your site. The message names each check and
  its flag; nothing runs and no password is asked for. `netaudit list` shows
  these parameters as `required`. `--quick --url` is unchanged. Network
  diagnostics keep their defaults (`ping` → `8.8.8.8`), and the Web form is
  unchanged: it shows the address in the field.
- CLI `run` refuses a flag that none of the selected checks takes, before
  anything runs or asks for a password. Before, it was dropped silently, so
  `run ports firewall --host X` checked this computer, `run dns_audit --url U`
  checked `example.com`, and a typo vanished. The message names the flags (not
  their values) and hints at the right target flag. This also refuses
  `--quick` with both `--url` and `--host` (the site bundle takes no `--host`).
- Docs: a step-by-step guide in English and Russian (`docs/guide.md`,
  `docs/guide.ru.md`), linked from the top of both READMEs: installation,
  opening the Web interface locally, through an SSH tunnel, behind nginx or
  directly with the one-time generated password, SSH access to audited
  servers, several servers, AI and Telegram settings, scheduled audits,
  updating, backups and common errors.
- `/api/settings` no longer returns the MikroTik password or the Web login
  hash and salt; it returns only the settings page's values, with each key
  and token as a set/not-set flag. Saving through it accepts only those keys:
  any other key (the Web login, MikroTik capture, unknown names) is refused
  with 400 before anything is written. The Web login and MikroTik capture
  keep their own endpoints. A script that read or wrote other keys here
  must use those endpoints.
- Scheduled audits with Telegram notifications. `netaudit setup-timer` writes a
  systemd service and timer that run `run … --hosts-file … --notify` (it never
  installs them). `run --notify` sends one plain-text message when a check
  failed or collected only part of its data, or when new problems at or above
  `--notify-min-severity` (default `medium`) appeared since the previous run.
  The message is built from all hosts and findings of the run, the report is
  saved before sending, a failed delivery makes the run exit non-zero, and
  the bot token is kept out of logs and error texts. No message does not mean
  "all fine": see README, "Scheduled audits and Telegram notifications".
- `~/.netaudit` is now `0700` and its database `0600`, also on existing
  installs; the database holds the AI key, the Telegram token and the
  MikroTik password. When the mode cannot be fixed (another owner),
  NetAudit stops with an error naming the file.

- CLI `--quick` now audits only the target you name. The server bundle
  (`--quick --host`) ran `ports` and `firewall` on the machine NetAudit runs
  on, so a report for another server showed NetAudit's own ports and firewall,
  even when SSH failed. They are replaced with `ssh_audit`, which reads the
  target's ports, firewall and fail2ban over SSH. The site bundle
  (`--quick --url`) ran `dns_audit` on `example.com`; it now runs it only with
  `--domain` and otherwise skips it with a hint.

- Saved multi-host reports now have a read-only host summary and same-check
  comparison in the CLI (`summary <report_id> [--check ID]`) and Web report
  view. Collection errors, incomplete log coverage, warnings, unknown result
  formats, and duplicate host instances remain distinct from zero observed findings.
- Web: saved SSH hosts (Settings → "SSH hosts": host, user, port, key path; never passwords)
  and a picker on the audit tab that fills one host block per chosen host in the selected SSH
  checks. `/api/hosts` refuses a password in the payload with 400 and never echoes it back;
  the database has no column that could hold one.
- Multi-host runs use bounded workers (4 by default, configurable 1–16) and
  share at most 8 active instances across one Web process. Web estimates
  account for bounded batches, and oversized requests are rejected before
  running checks (64 instances per check, 256 per request). Stopping a streamed
  run leaves queued hosts unstarted and marks each one explicitly in the report.

- CLI: `netaudit run <checks> --hosts-file hosts.json` audits several servers in one run. The
  file is a JSON array of `{"host", "user", "port", "key_path"}` records without passwords;
  passwords are only asked for (`--password -`). A duplicate host, a secret in the file, a
  check without a `host` parameter or an unreadable key file is refused before anything runs.
  `--max-parallel N` (1–16, default 4) sets how many hosts run at once. A repeated `--host` is
  now an error (use `--hosts-file`); other repeated parameters keep the last value as before,
  except in a group run, where any repeat is an error.

- SSH host keys are no longer lost when NetAudit connects to several new hosts
  at once (Web runs the hosts of a check in parallel). Before, on a fresh
  install only the last host's key was kept, so the others were trusted again
  as "new" on the next run; and a different key for the same host could replace
  the one just saved. `~/.netaudit/known_hosts` is now updated under a lock and
  replaced atomically, and a conflicting key is refused like any host key
  mismatch.

- `docker_audit` now confirms whether its Docker TCP socket configuration
  probe completed. Missing optional config files are allowed; read failures,
  SSH interruptions and inconsistent probe results are reported as collection
  gaps instead of silently appearing clean. Container findings remain visible.

- `dns_audit` appears in trends (`netaudit trend dns_audit <domain>`, Web
  trends, AI trend context). A DNS query that did not resolve marks its
  section as not evaluated: findings from the previous run there are listed
  as `not evaluated`, not `resolved`. The same now holds for other checks
  that report a collection gap as an `info` finding requiring manual
  verification (for example `web_security_external` when it could not test
  old TLS versions).

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
- `requirements.txt` and package metadata require pydantic 2 explicitly
  (`pydantic>=2.0`); the Web
  settings endpoint for history capture no longer uses the pydantic v1 API.
  Tests use `httpx2` via both dev requirement paths, as starlette's TestClient now expects
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
