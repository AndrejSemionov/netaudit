# AI Analysis #17 — Research Phase Summary

Status: **Research CLOSED. Implementation DEFERRED.**
Date: 2026-08-23

## Scope of this research

The original roadmap item #17 ("AI Analysis") bundled four distinct ideas:
history/trend analysis across recent reports, RAG over CVEs tied to the
audited stack, role-based system prompts (network engineer vs security
engineer), and structured output via JSON schema.

Before designing any of that, this research phase asked one prerequisite
question: **does NetAudit currently know which report belongs to which
audited subject (host/target/URL)?** If it doesn't, no trend analysis or
history-aware AI prompt can be built on top of the existing report data,
regardless of which of the four sub-features is attempted first.

## What already exists (production, not part of this gap)

- **Basic AI analysis** (`ai_analyze()` in `netaudit_pkg/history.py`) is
  fully shipped: `--ai` CLI flag, `/api/analyze` web endpoint, a detailed
  bilingual (en/ru) prompt with per-check-type guidance (mtr/tcptraceroute
  disagreement, CVE-to-config correlation, traffic destination risk,
  hardening findings). It is stateless — one report in, one JSON analysis
  out, no history involved.
- **Report storage** (`netaudit_pkg/storage.py`) is mature: a `reports`
  table with 280+ real rows, `save_report()`/`list_reports()`/
  `load_report()`/`query_reports()` all functional.
- **One narrow trend mechanism already exists**: `timeseries_mtr_loss()`
  and `distinct_mtr_targets()` chart mtr packet loss over time for a given
  `target` string. This was the closest existing precedent for "history",
  and this research phase used it as the starting point.

## The core finding

`timeseries_mtr_loss(target)` filters saved reports by `WHERE checks LIKE
'%mtr%'`, then in Python compares `data['results']['mtr']['target']`
against the requested `target` string. This works **only because the mtr
check happens to echo its own `target` parameter back inside its own
result dict** (`return {'target': target, 'hops': hops, ...}` in
`netaudit_pkg/checks/network.py`) — not because of any general mechanism.

Confirmed by inventorying all 37 registered checks' `params`:

| Family | Identity parameter | Semantics |
|---|---|---|
| SSH-based (17 checks: aide, backup, cve_audit, docker, fail2ban_logs, kern_log, kernel_hardening, log_discovery, lynis, nginx_hardening, nginx_logs, rootkit, server_audit, ssh_audit, ssh_auth_audit, ssh_hardening, systemd_hardening) | `host` | Subject being audited over SSH |
| network (mtr, ping, arping, tcptraceroute) | `target` | Destination probed *from* the machine running NetAudit — not the audited subject |
| site (ssl, http, security_headers, web_security_external, sql_injection, dns_audit, cert_transparency) | `url` / `domain` | HTTP(S)/DNS endpoint — a third, separate namespace |
| capture (mikrotik_sniffer, tshark_capture) | `router`+`target_ip` / `interface` | Yet another shape — a monitoring pair or a local interface name |
| performance, firewall, ports, speedtest | *(none)* | Implicitly "this machine, right now" — no identity parameter exists at all |

These are not dialects of one field. `host` names the audit subject;
`target` names a network-path endpoint that is *not* the subject; `url`
names a web endpoint; some checks have no identity concept whatsoever.
Collapsing these into one generic `host` field would misrepresent at
least three of the five families.

Then, tracing the actual execution path confirmed where the identity is
lost:

```
run_checks(selected)
    for item in selected:
        params = item.get('params', {})      # host/target/url/etc. live here
        result = spec.func(**params)          # params consumed, then discarded
        report['results'][check_id] = result  # only the check's own output is kept
```

(`netaudit_pkg/engine.py`, `run_checks()`, confirmed by direct code
reading — not inferred.) `run_checks_multi()` follows the identical
pattern per-instance, with the added twist that a single check can now
run against N different hosts in one report (`_multi_host: True,
by_host: {...}`), which is a fourth shape on top of the five above.

**`params` are transient — the orchestration layer uses them to invoke a
check and then throws them away. `report['results'][check_id]` contains
only what the check function chose to return, which is not guaranteed to
include what it was asked to check.** `mtr` happens to echo `target`
back; the other 36 checks do not reliably do the same.

## Why this blocks all four #17 sub-features, not just "history"

- **History/trends**: cannot group "reports about the same subject"
  without knowing what the subject was.
- **RAG/CVE knowledge**: correlating CVE findings with "this server's
  software stack over time" requires the same subject identity.
- **Roles**: a role-aware prompt would plausibly want to know *what kind*
  of subject is being analyzed (a server vs a network path vs a URL) —
  which is exactly the same missing semantic distinction.
- **Structured output**: orthogonal to this gap, but any schema that
  includes "which host/target this finding is about" runs into the same
  missing data.

## What this research explicitly did NOT do

- Did not add `host`/`target` fields to any of the 37 checks.
- Did not extend `timeseries_mtr_loss()` into a general mechanism.
- Did not touch `report` schema, `storage.py`, or `engine.py`.
- Did not begin any AI #17 implementation.

## Conclusion / roadmap status

```
AI basic analysis (--ai, /api/analyze)     ✅ production, unaffected by this gap
AI Analysis #17 research                    ✅ CLOSED (this document)
AI Analysis #17 implementation               ⏸ DEFERRED

Discovered prerequisite (not yet designed):
    Report Identity / Execution Context Contract
    — what "the subject of a report" means across 5+ different
      parameter shapes (host / target / url / router+target_ip /
      none), and where in the pipeline (run_checks → report →
      storage) it should be captured.
```

Designing that contract — including whether it needs one unified field,
a per-family typed identity, or something else entirely — is separate
follow-up work, not started here. Per project methodology, it should go
through its own contract-freeze → tests → implementation cycle before
any AI #17 code is written, and should be validated against all 37
existing checks (including the multi-host `instances` shape) before
being considered frozen.
