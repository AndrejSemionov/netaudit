# Result reliability audit (stage A2)

Status: **DRAFT, part 1 of 2** — outcome model, criteria and split proposed by
Claude; Claude's half audited. GPT/Codex: review the model and the split, then
audit the other half (section 5). MODE: AUTONOMOUS (stage A). Fixes are
separate tasks (section 6), not part of this document.

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
| `mtr`, `tcptraceroute`, `ping`, `arping` | OK — exit codes checked (`ping`/`tcptraceroute` accept 1 = no reply, which is a measurement), unparsable output → `error` | — |
| `speedtest`, `iperf` | OK — exit code and JSON checked | — |
| `ports`, `performance` | OK — raw data, exit code checked / psutil | — |
| `tshark_capture`, `mikrotik_sniffer` | OK — exit code / router error text → `error`; capture tools, no verdicts | — |

### 5.2 GPT/Codex's half

_To be filled by GPT/Codex._

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

## 7. Proposed fix tasks (after GPT/Codex review)

1. RA-01, RA-03, RA-04 — TLS / external web checks (one task: `site.py`,
   `server_security.py` external part).
2. RA-02, RA-10 — `cve_audit` outage path.
3. RA-05 — `sql_injection` unreachable page.
4. RA-06 … RA-09, RA-11 — low items, one cleanup task.
5. RA-12 — covered by A1 and the `command -v` task.
