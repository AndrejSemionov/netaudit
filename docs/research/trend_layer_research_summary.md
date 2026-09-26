# Trend Layer — Research Phase Summary

Status: **Research CLOSED. Contract v1 PROPOSED (awaiting approval).**
Date: 2026-09-26

## Goal

Give the operator a deterministic answer to "how has the state of this
object changed over time?" — without an LLM. Today the only consumer of
report history is `ai_analyze(history=...)` (AI Analysis #17 History v1);
if no API key is configured, accumulated history gives the user nothing.
The trend layer must work without AI; AI can enrich it later, not replace it.

## What already exists

- `execution_context` in every report (engine.py, Contract v1) — the
  params actually passed to each check.
- `storage.IDENTITY_PARAM_KEYS` + `find_related_reports()` — object
  identity matching (same key + same value).
- `Finding` model (findings.py) with optional `id`, and severities
  `critical/high/medium/low/info/ok`.
- `weighted_score()` (scoring.py) — the 0-100 `hardening.score` produced by
  ssh_hardening, nginx_hardening, kernel_hardening.
- `timeseries_mtr_loss()` — the one existing narrow, mtr-specific trend.

## Finding 1 — finding identity across reports is weak

To say "finding X was fixed" or "finding Y is new", the same finding must
be recognisable in two different reports.

- **Stable `id` exists only in a minority of checks**: ssh_hardening,
  nginx_hardening, kernel_hardening set ids on (nearly) every finding;
  server_security sets ids on ~9 of ~49 call sites. All other checks
  (docker_audit, backup_check, aide_check, dns_audit, lynis_audit,
  ssh_auth, ...) produce findings with no `id`.
- **Titles are not a safe fallback**: ~25 of ~184 finding call sites build
  the title with an f-string containing volatile values, e.g.
  `files changed: {n}`, `SPF exceeds the DNS-lookup limit ({n}/10)`,
  `active jails: {n}`, `{n} DKIM selector check(s) did not resolve`.
  Exact title matching would report such a finding as "resolved + new"
  every time the number changes — a false signal, which is worse than no
  signal for an operator deciding what to look at.
- Normalising titles (e.g. stripping digits) is not safe either: it would
  merge genuinely different findings (`port 22 open` vs `port 3306 open`).

## Finding 2 — hardening score is a robust numeric signal

`result['hardening']['score']` (0-100, `weighted_score()` contract) is
deterministic, comparable across runs and already validated. It is the
strongest available trend signal for the three hardening checks.

## Finding 3 — `find_related_reports()` ignores multi-host reports (bug)

For a multi-host run, `execution_context[check_id]` is
`{host_key: params, ...}` (engine.py `run_multi_host`), not a flat params
dict. `find_related_reports()` iterates `ctx.items()` as if it were flat,
so it sees keys like `'10.0.0.1'` with dict values — never an identity
key. Result: a multi-host report never matches anything, **not even
itself** (verified in a scratch DB). AI History silently has no history
for any multi-host audit. Both the fix and the trend layer need one shared
helper that extracts identity pairs from either shape.

## Finding 4 — not every severity is a problem

`ok` means "checked, no issue", `info` is a neutral observation. Counting
them as findings would make a trend of "3 → 5 findings" look worse when
two more checks simply passed. Problem counts must use only
`critical/high/medium/low`.

## Proposed Contract v1

1. **Unit of trend**: `(check_id, identity_key, identity_value)`, taken from
   `execution_context` (flat or multi-host shape, via the shared helper
   from Finding 3). For a multi-host report, each `by_host` entry is its
   own snapshot.
2. **Snapshot per unit per report**: `timestamp`, problem counts by
   severity (`critical/high/medium/low` only), `hardening_score` when
   present, `error` when the check failed (an errored run is shown as
   such, never as "0 problems").
3. **Finding-level diff (new / resolved / persisting) only for findings
   with an explicit `id`.** Findings without `id` contribute to counts
   only. No title matching in v1 (Finding 1) — same philosophy as
   `Component.finding_id`: an explicit link, not a naming convention.
4. **Pure computation separated from storage**: `netaudit_pkg/trends.py`
   computes a trend from a list of snapshots (no DB access, trivially
   testable); storage only collects the snapshots.
5. **First consumer: CLI** (`netaudit trend ...`). Web UI and feeding the
   deterministic diff into the AI prompt are later steps, not v1.

## Out of scope for v1

- Title-based finding matching / fuzzy matching.
- Adding `id` to the findings of the other checks (a separate, per-check
  migration — it improves trend quality but is not a prerequisite).
- Web UI charts, correlation, alerting on regressions.
