# Trend Layer — Research Phase Summary

Status: **Research CLOSED. Contract v1 APPROVED (2026-09-26, option: finding diff by `id` only) and IMPLEMENTED (`netaudit_pkg/trends.py`, `netaudit trend`).**
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

## Contract v1 — precise shapes (frozen before RED tests)

`netaudit_pkg/trends.py`:

- `PROBLEM_SEVERITIES = ('critical', 'high', 'medium', 'low')`.
- `snapshots_from_report(report) -> list[dict]` — one snapshot per
  (check_id, identity pair) in the report. Flat context -> result is
  `results[check_id]`; multi-host context -> result is
  `results[check_id]['by_host'][host_key]`. Params with no identity key
  produce no snapshot; params with several identity keys produce one
  snapshot per pair. A result is trendable only if it has a `findings` list
  or a `hardening.score`, or is an error (`{'error': ...}`) — ping/mtr-style
  metric results are out of scope. Snapshot shape:
  `{check_id, key, value, timestamp, error, counts, hardening_score, finding_ids}`
  where `counts` is `{sev: n}` over PROBLEM_SEVERITIES only (None when
  `error`), and `finding_ids` maps `id -> severity` for problem findings
  that carry an `id`.
- `compute_trend(snapshots) -> dict` — snapshots of ONE unit, oldest
  first. Returns `{check_id, key, value, points, latest_change}`;
  `points[i] = {timestamp, error, counts, total, hardening_score}`.
  `latest_change` compares the last two **non-error** snapshots:
  `{from, to, counts_delta, total_delta, score_delta, new, resolved,
  persisting}` (id lists sorted; `score_delta` None unless both sides have a
  score); `None` when fewer than two non-error snapshots exist.
- `trend_for(check_id, key, value, window=200)` and `list_units(window=200)`
  read the latest `window` reports via `storage.recent_report_data()`.

## Contract v1.1 amendment — repeated unit within one report (2026-09-27)

Found in review (pass 1): one report can hold several instances of the same
unit `(check_id, key, value)` — a host listed twice (`h`, `h#2`), or one host
audited on two ports (`h:22`, `h:2222`: two different sshd, one `host`
identity). v1 emitted a snapshot per instance, so `compute_trend()` compared
instances of the SAME report as if they were two runs — a false
"resolved" with `from == to`.

Taking the first instance is not acceptable: it hides a finding or a
successful run of the second instance. Merging instances is not acceptable
either: counts of findings without `id` cannot be combined honestly (sum
double-counts identical duplicates, max under-counts different ports).

Rule (approved by USER, agreed by both agents):

- `snapshots_from_report()` returns **at most one snapshot per unit per
  report**.
- Instances are compared on their normalised snapshot fields: `error`,
  `counts`, `hardening_score`, `finding_ids`.
  - All equal → one ordinary snapshot (the common "host listed twice" case).
  - Any difference → one **ambiguous** snapshot:
    `error = "ambiguous: N instances of this unit with different results in one report"`,
    `counts = None`, `hardening_score = None`, `finding_ids = {}`.
- An ambiguous snapshot is non-comparable, exactly like an errored run: it
  appears in `points` and is excluded from `latest_change`. It does not claim
  the check failed; it states the run cannot be represented as one state.
  Per-instance details stay in the saved report; the trend does not show them.
- Consumers tell ambiguity from a check failure by the `ambiguous:` prefix of
  `error`; no new field in v1.

CLI (same amendment): `netaudit trend <check_id>` without a value is a usage
error — exit status 2; with `--json` it prints
`{"error": "missing_value", "check_id": ...}` instead of text.

## Out of scope for v1

- Title-based finding matching / fuzzy matching.
- Adding `id` to the findings of the other checks (a separate, per-check
  migration — it improves trend quality but is not a prerequisite).
- Web UI charts, correlation, alerting on regressions.
