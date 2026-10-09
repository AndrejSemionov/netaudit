# Result reliability audit (stage A2)

Status: **both halves audited** — outcome model, criteria and split by
Claude; Claude's 23 checks by Claude, GPT/Codex's 14 by GPT/Codex (working
notes `docs/research/a2_codex_half.md` on `codex/a2-result-reliability`,
`1aa0f33`, merged here by Claude). Cross-check: Claude re-ran or re-read
GPT/Codex's FAIL items (section 8); GPT/Codex's cross-check of RA-01…RA-12 is
pending. MODE: AUTONOMOUS (stage A). Fixes are separate tasks (section 7),
not part of this document.

Base: `main` @ `ea68f97`. Host used for the runs: Ubuntu 24.04, Python 3.12,
OpenSSL 3.0.13, temporary empty `HOME`.

## 1. Question

For every registered check (37): when the check cannot see what it needs, does
it say so, or does the report look like "checked, nothing wrong"? A report that
could not collect its data must not read as a clean result (USER plan, stage A2).

## 2. Outcome model

Every result a check returns has to be one of these five. The report format is
**not** changed by A2: the column "today" says how each outcome is already
expressed, so the audit can judge existing checks against it.

| # | Outcome | Meaning | Today |
|---|---------|---------|-------|
| O1 | Problem found | data collected, a rule failed | finding `critical`/`high`/`medium`/`low` with an id |
| O2 | No problem within the check | data collected **and confirmed complete**, every rule passed | finding `ok`, `hardening.score`, control PASS |
| O3 | Not enough data | some sources/keys could not be read; what was read is reported, the gap is named | `info`/`low` + `requires_manual_verification`, log `CoverageStatus`, `collection_error`/`not_supported` counts, `applicable: false` components |
| O4 | Not applicable | confirmed absent (service not installed, no such config) | `{'installed': False}`, N/A component, no finding |
| O5 | Execution error | the check could not run or its collection failed | `{'error': ...}` (no findings, no score) |

Rules the audit checks against:

- **R-a.** O2 only when the collection is confirmed: exit code / completion
  marker / HTTP status, not "the output was empty" or "the text was missing".
- **R-b.** A failed collection is O3 or O5, never O2 and never O1 (a
  "missing X" finding computed from output that was never received is a false
  O1).
- **R-c.** O4 needs confirmed absence. "Could not tell" is O3/O5.
- **R-d.** A partial result says what is missing.

## 3. Criteria per check

| Id | Criterion |
|----|-----------|
| C1 | Every command / request result is judged by its exit code, completion marker or HTTP status before its output is interpreted (no `cmd \|\| echo X` text sniffing, no pipeline whose status hides the first command). |
| C2 | Empty output is not read as "clean" unless C1 confirmed success and emptiness is meaningful. |
| C3 | Tool or service absent (O4) is distinguished from a failed probe (O5). `command -v`: 0 = present, any other code = absent **only** if the probe completed — the code is 127 under dash but **1 under bash** (`FINDINGS.md`, GPT/Codex, confirmed by Claude). |
| C4 | Permission denied / sudo refused is O5 (or O3) with the reason, not O2 and not O4. |
| C5 | Partial data (one of several sources, some keys) is O3 and named, not O2. |
| C6 | Timeout, dropped connection, unreachable target → O5, not a partial O2/O1. |
| C7 | External services (DNS, HTTP sites, OSV, crt.sh, breach APIs): a failed or rate-limited query is O5/O3, not "no record" / "no vulnerability". |
| C8 | The local tool's own limits are not mistaken for the target's state (e.g. a client library that cannot speak an old protocol reports "server does not support it"). |

## 4. Split (proposal)

By module, so each agent reads whole files. Claude's half is mostly local,
network and site checks plus `server_audit`/`cve_audit`; GPT/Codex's half is
the hardening and log-audit modules (A1 touches `nginx_config*.py` /
`ssh_config.py`, which GPT/Codex is changing anyway).

| Agent | Checks (module) |
|-------|-----------------|
| Claude (23) | `server_audit`, `web_security_external` (server_security.py); `cve_audit`; `dns_audit`; `tshark_capture`, `mikrotik_sniffer` (capture.py); `mtr`, `tcptraceroute`, `ping`, `dig`, `arping`, `speedtest` (network.py); `ports`, `firewall`, `performance`, `ssh_audit`, `iperf` (system.py); `ssl`, `http`, `security_headers` (site.py); `sql_injection`; `breach_check`; `cert_transparency` |
| GPT/Codex (14) | `nginx_hardening`, `kernel_hardening`, `ssh_hardening`, `systemd_hardening`, `log_discovery`, `nginx_logs_audit`, `ssh_auth_audit`, `fail2ban_logs_audit`, `kern_log_audit`, `aide_check`, `docker_audit`, `backup_check`, `rootkit_check`, `lynis_audit` |

Each agent spot-checks the other's high/medium items (section 6) before they
become fix tasks.

## 5. Results

### 5.1 Claude's half

| Check | Verdict | Issues |
|-------|---------|--------|
| `ssl` | **FAIL** | RA-01 |
| `cve_audit` | **FAIL** | RA-02, RA-10 |
| `web_security_external` | **FAIL** | RA-03, RA-04 |
| `sql_injection` | **FAIL** | RA-05 |
| `breach_check` | partial | RA-06 |
| `ssh_audit` | partial | RA-07 |
| `dig` | partial | RA-08 |
| `firewall` (local) | partial | RA-09 |
| `security_headers` | partial | RA-11 |
| `server_audit` | depends | RA-12 (A1 and the `command -v` finding) |
| `dns_audit` | OK — reference model: `_dig_query()` returns NOERROR/NXDOMAIN/SERVFAIL/REFUSED/TIMEOUT/TOOL_ERROR; unresolved queries become `info` "collection failure, not evidence of absence" (SPF, DMARC, DKIM per selector, DNSSEC, dangling CNAME) | — |
| `cert_transparency` | OK — crt.sh timeout / HTTP error / non-JSON → `error`; zero certificates → explicit note | — |
| `http` | OK — curl exit code checked, JSON parse errors reported | — |
| `mtr`, `tcptraceroute` | OK — exit codes checked (`tcptraceroute` accepts 1 = no reply, which is a measurement), unparsable output → `error` | — |
| `ping`, `arping` | partial | RA-20 (GPT/Codex cross-check) |
| `speedtest` | OK — exit code and JSON checked; a JSON without the expected keys raises, and `engine` turns any exception into `error` (`engine.py:50`) | — |
| `iperf` | OK — exit code and JSON checked | — |
| `ports`, `performance` | OK — raw data, exit code checked / psutil | — |
| `tshark_capture`, `mikrotik_sniffer` | partial — exit code / router error text → `error`; capture tools, no verdicts | RA-20 (GPT/Codex cross-check) |

### 5.2 GPT/Codex's half (by GPT/Codex, `1aa0f33`; summary translated by Claude)

| Check | Verdict | Issues / evidence (GPT/Codex) |
|-------|---------|-------------------------------|
| `nginx_hardening` | FAIL on `main`, fixed by A1 | `which nginx \|\| echo NONE` → a failed probe or a `PATH` without `/usr/sbin` became `installed=False`. A1 `e1dfe35` adds present/absent/unknown. |
| `ssh_hardening` | FAIL on `main`, fixed by A1 | an empty `sshd -V` was taken as "sshd absent". A1 uses an explicit `installed`. |
| `nginx_logs_audit` | FAIL on `main`, fixed by A1 | same preflight as `nginx_hardening`; per-source coverage after it is correct (complete/empty/failed/unknown). |
| `kernel_hardening` | OK | sudo, then unprivileged retry; no score unless all 16 keys are read. |
| `ssh_auth_audit` | OK | `auth.log` only on `completed && exit_code == 0`, else journal, else `detection_succeeded=False` and no clean finding (`ssh_auth_audit.py:176–188`). |
| `fail2ban_logs_audit`, `kern_log_audit` | OK | `_source_coverage()` uses marker + exit code; UNKNOWN/FAILED never give `detection_succeeded`. |
| `systemd_hardening` | partial | RA-19 |
| `aide_check` | partial | RA-18 |
| `rootkit_check` | **FAIL** | RA-13 |
| `docker_audit` | **FAIL** | RA-14 |
| `lynis_audit` | **FAIL** | RA-15 |
| `backup_check` | **FAIL** | RA-16 |
| `log_discovery` | **FAIL** | RA-17 |

## 6. Issues (Claude's half)

Severity here is about the reliability of the result, not about the target.
Evidence marked **run** was reproduced on the host above; **code** is by
reading `main` @ `ea68f97`.

### RA-01 — HIGH — `ssl`: the default openssl path never checks the certificate

`check_ssl(method='auto')` uses `openssl s_client -brief` when openssl is
installed and returns `ok: True` once the TLS connection is up. Expiry and
issuer come from a second, verifying stdlib connection whose failure is
dropped. An expired, self-signed or wrong-host certificate therefore gives
`ok: True`, `days_left: None`, `issuer: None` — the very cases the check is
for. (C1, C2, R-b)

**run:** `expired.badssl.com`, `self-signed.badssl.com`,
`wrong.host.badssl.com` → openssl path `{'ok': True, ..., 'expires': None,
'days_left': None}`; python path `{'ok': False, 'error': 'certificate verify
failed: ...'}` for all three.

Direction: report the verification result (openssl's `Verification error` /
the stdlib error) as a failure; never `ok: True` without expiry data.

### RA-02 — HIGH — `cve_audit`: OSV unreachable → "no known CVEs found"

`query_osv()` catches `httpx.HTTPError` (connection error, timeout, HTTP 4xx/5xx
via `raise_for_status`) and sets every unqueried package to `[]`.
`check_cve_audit()` maps `[]` to a severity `ok` finding "no known CVEs found".
The module already has the right channel — `collection_errors` → `info`
"CVE matching could not be completed … (this does NOT mean no CVEs were
found)" — but the outage path does not use it. (C7, R-b)

**run:** `httpx.post` patched to raise `ConnectError` →
`query_osv([nginx 1.24.0-2ubuntu7], 'ubuntu', '24.04')` returns
`({'nginx': []}, set())`.

Direction: on a failed batch, put the unqueried packages into
`collection_errors` (not cached).

### RA-03 — HIGH — `web_security_external`: TLS 1.0/1.1 can never be detected here

`_check_tls_version()` opens `ssl.SSLContext(PROTOCOL_TLSv1 / _1_1)`. With
OpenSSL 3 at its default security level (Ubuntu 22.04+, Debian 12+) the client
cannot offer TLS 1.0/1.1 at all, so every attempt fails locally and is read as
"the server does not support it". `WEB-TLS-001` cannot fire on these hosts, and
a connection failure gives the same `False`. (C8, C6)

**run:** `tls-v1-0.badssl.com:1010` with the current code → `SSLError internal
error` (also for TLS 1.2-only `tls-v1-2.badssl.com:1012`); with
`PROTOCOL_TLS_CLIENT`, `set_ciphers('DEFAULT:@SECLEVEL=0')` and
`minimum_version = maximum_version = TLSv1` → `ACCEPTED TLSv1` for the TLS 1.0
server, connection reset by the TLS 1.2-only one. So detection is possible.

Direction: probe with an explicit min/max version at SECLEVEL 0; three results
— accepted / refused by the server / could not test (local or connect error) —
and report "could not test" as O3, not as "not supported".

### RA-04 — MEDIUM — `web_security_external`: unreachable site → "missing header" findings

The `curl -I` exit code is ignored; on failure `head` is empty, so all four
security headers are reported missing (one medium, three low, with stable
ids), and the TLS and sensitive-path probes silently return negative. A
temporary outage produces findings and the next good run "resolves" them in
trends. (C1, C6, R-b)

**run:** `check_web_security_external('https://does-not-exist.invalid')` →
`missing header strict-transport-security` (medium) + 3 low, no `error`.

Direction: a failed fetch of the base URL → `error` (O5); the probes after it
are skipped or reported as not run.

### RA-05 — MEDIUM — `sql_injection`: unreachable site → `ok`

`_fetch_html()` returns `None` on any failure; with no GET parameters in the
URL the check reports `ok` "no input points found — injection is unlikely
here". (C6, R-b)

**run:** `check_sql_injection('https://does-not-exist.invalid/')` →
`[{'severity': 'ok', 'title': 'no input points found', ...}]`.

Direction: page not fetched → `error` or an explicit "page could not be
fetched" instead of `ok`.

### RA-06 — LOW — `breach_check`: one source failed, the other clean → `ok`

With both XposedOrNot and HIBP enabled, an error from one and "not found" from
the other gives `severity: ok`, "not found in known breaches"; the error stays
only inside `sources`. Partial coverage is presented as complete. (C5, C7)

**code:** `check_breach()` — the `else` branch after `any_breach` /
`all sources failed`.

### RA-07 — LOW — `ssh_audit`: raw strings that mislabel failures

The result is raw text (no findings), but it is shown to the user and sent to
the AI analysis:
- `failed_ssh_logins`: `journalctl … 2>/dev/null | grep … | tail -20 || echo
  "journalctl unavailable"` — the pipeline status is `tail`'s, and stderr is
  dropped; a user who cannot read the journal gets `(empty)`, which reads as
  "no failed logins".
- `sshd_config`: `grep -E … || echo 'no access'` — no matching directive also
  prints "no access".
- `unattended_upgrades`: `systemctl is-enabled … || echo "not found"` —
  "disabled" also gets "not found" appended.
(C1, C2) **code:** `system.py` `REMOTE_CHECKS`.

### RA-08 — LOW — `dig`: NXDOMAIN / SERVFAIL look like "no answers"

`dig +noall +answer +stats` exits 0 for NXDOMAIN and SERVFAIL and the status
line is suppressed, so a broken resolver or a non-existent name returns
`answers: []` with no error. `dns_audit._dig_query()` already parses the status
and could be reused. (C1, C7) **code:** `network.py` `check_dig()`.

### RA-09 — LOW — local `firewall`: `ufw status` failure → "no data"

The exit code of `ufw status` is ignored (non-root: `ERROR: You need to be
root`, on stderr) → `'no data'` without the reason; any non-zero `nft` exit is
labelled "no access (root)". Informational output, no verdict. (C1, C4)

### RA-10 — LOW — `cve_audit`: nothing detected → empty result without a note

When no package was detected the result is `packages: []`, all counters 0, no
`error` and no note — an SSH user whose `PATH` lacks the binaries (see the A1
`/usr/sbin` hypothesis: `nginx -v` would print "not found") and a host with
none of the services look the same. (C3, R-d) **code:** `check_cve_audit()`,
`if not packages`.

### RA-11 — LOW — `security_headers`: headers merged across the redirect chain

`curl -s -I -L` prints the headers of every response; the parser keeps the last
value per name, but a header sent only by an intermediate redirect still counts
as present on the final page. (C2) **code:** `site.py`
`check_security_headers()`. Low: the chain is usually same-site.

### RA-12 — INFO — `server_audit` depends on A1 and on the `command -v` finding

- nginx and SSH sections: `collect_nginx_config()` / `collect_ssh_config()`
  start with `which … || echo NONE` (A1, GPT/Codex).
- firewall and SQL sections: `tool_is_present()` / `_sql_binary_verdict()`
  accept only exit 127 as "absent", so on a bash login shell every host
  without ufw / MySQL gets a `low` "could not determine …" finding (FW-UFW-002,
  …) instead of N/A (GPT/Codex finding in `FINDINGS.md`).
- An unreadable nginx or sshd config is a `low` finding with
  `requires_manual_verification` — an O5 counted as an O1 in the severity
  totals. Acceptable as the current convention; listed so the Unified Security
  Model (stage E) can decide.

Otherwise the firewall, Fail2Ban and SQL sections already follow the model
(per-backend verdicts with UNKNOWN never reported as `ok`).

### Issues in GPT/Codex's half

Found by GPT/Codex (`1aa0f33`); "Claude:" is the independent cross-check.

#### RA-13 — HIGH — `rootkit_check`: sudo refused → "no signs of rootkits found"

`_run_rkhunter()` / `_run_chkrootkit()` call `ssh.sudo('<tool> … 2>&1')` and
only test that stdout is non-empty. The `2>&1` also captures sudo's own
"sudo: a password is required", which parses to zero warnings → `ok`.
(C1, C4) GPT/Codex: reproduced with `FakeSSHExecutor`.
**Claude: reproduced independently** — both tools answering
`sudo: a password is required` → `[('ok', 'no signs of rootkits found')]`.

#### RA-14 — MEDIUM — `docker_audit`: `docker ps` failure → "no running containers"

Only "permission denied" / "password is required" are treated as failures; any
other error (daemon unreachable, API error) leaves stdout empty →
`ok` "no running containers found". A `docker inspect` whose JSON does not
parse is skipped silently. (C1, C6) GPT/Codex: reproduced.
**Claude: reproduced independently** — `docker ps -q` → `('', 'error during
connect: … EOF')` → `[('ok', 'no running containers found')]`.

#### RA-15 — MEDIUM — `lynis_audit`: audit result ignored, an old report can be shown as new

`ssh.sudo('lynis audit system …')` is not checked; the check then reads
`/var/log/lynis-report.dat`. When the audit did not run (refused, lock file,
error) but an older report is readable, its hardening index and findings are
reported as the current run. (C1) GPT/Codex: reproduced (refused audit +
`hardening_index=90` report → `ok` "Lynis found no issues", index 90).
Claude: confirmed by code (`lynis_audit.py:138–146`).

#### RA-16 — MEDIUM — `backup_check`: an unreadable directory looks empty

`_find_files()` runs `find … 2>&1` without an exit code; only "No such file or
directory" is recognised. "Permission denied" or a dropped command leaves no
`|` lines → treated as an empty directory → the "no backup files" finding.
(C1, C4) GPT/Codex: code. **Claude: confirmed by code**, and adds: the archive
integrity probes use `<tool> … && echo OK || echo FAIL`, so a missing
`tar`/`gzip`/`unzip` on the target reports the archive as corrupted (C3).

#### RA-17 — MEDIUM — `log_discovery`: unknown `stat` result → "not found"

`_file_verdict()` returns `available=False` for a confirmed absence, for any
other non-zero `stat` and for an uncompleted `stat`; `build_findings()` then
writes "not found" / "not present". Its own docstring calls the distinction
"tracked but not yet exercised". (C3, C6) GPT/Codex: code. Claude: confirmed
by code (`log_discovery_audit.py:146–186`).

#### RA-18 — LOW — `aide_check` check mode: clean judged by text only

`aide --check` runs through `ssh.sudo()` without an exit code; the text "no
differences" / "looks okay" is taken as clean (`aide_check.py:226–241`). The
database and init paths already use exit markers. (C1) GPT/Codex: code.

#### RA-19 — LOW — `systemd_hardening`: unchecked status and an empty model

`systemctl status … | head -1` takes `head`'s status; a successful
`--json=short` with an empty directive list gives `ok` without confirming the
model is complete. Needs a targeted test. (C1, C2) GPT/Codex: code.

#### RA-20 — LOW — `ping`, `arping`, capture tools: unparsed output is not marked

From GPT/Codex's cross-check of Claude's half: `ping`/`arping` with exit 0/1
but no recognisable statistics return `loss_pct: None` etc. without an
`error`; `tshark_capture` / `mikrotik_sniffer` with exit 0 and unparsable
output report zero packets / destinations. Measurement tools with no verdict,
hence low. Claude: agrees.

## 7. Proposed fix tasks

Grouped by module so each PR stays reviewable; HIGH first. Each is its own
RED → GREEN task in stage A (fixing false results is the stage A goal);
roles alternate by half: the agent who audited a module does not fix it alone,
the other reviews.

| Task | Issues | Modules | Proposed implementer / reviewer |
|------|--------|---------|---------------------------------|
| F1 | RA-02, RA-10 | `cve_audit` | Claude / GPT/Codex |
| F2 | RA-01, RA-03, RA-04, RA-11 | `site.py` (`ssl`, `security_headers`), `server_security.py` (`web_security_external`) | Claude / GPT/Codex |
| F3 | RA-13, RA-15, RA-18 | `rootkit_check`, `lynis_audit`, `aide_check` — move to `run_sudo_with_exit_code()` | GPT/Codex / Claude |
| F4 | RA-14, RA-16, RA-17 | `docker_audit`, `backup_check`, `log_discovery` | GPT/Codex / Claude |
| F5 | RA-05, RA-06 | `sql_injection`, `breach_check` | Claude / GPT/Codex |
| F6 | `command -v` 127-only (`FINDINGS.md`) | `firewall_config`, `fail2ban_config`, `server_security` SQL | GPT/Codex / Claude |
| F7 | RA-07, RA-08, RA-09, RA-19, RA-20 | low cleanup | later |

RA-12 is covered by A1 and F6.

## 8. Cross-check status

- Claude → GPT/Codex's half: RA-13 and RA-14 reproduced; RA-15, RA-16, RA-17
  confirmed by code; RA-18, RA-19 not re-checked (low). The A1 rows are
  reviewed in `.ai/REVIEW.md` (A1 pass 1).
- GPT/Codex → Claude's half: preliminary rows 1–20 in its notes agree on
  `breach_check`, `cve_audit` (empty inventory), `dig`, `dns_audit`,
  `cert_transparency`; added RA-20; `speedtest` resolved above (exception →
  `error` in `engine`). Review of RA-01…RA-12 itself: pending.
