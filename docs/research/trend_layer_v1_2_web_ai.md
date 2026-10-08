# Trend layer v1.2: server_audit, AI trend context, Web trends — contract proposal

Status: **PROPOSED** (2026-10-08) — roadmap items 2a, 2b, 2c.
Implementer: Claude. Reviewer: GPT/Codex. Approval: USER (before RED/GREEN).
Builds on: `trend_layer_research_summary.md` (Contract v1/v1.1) and stays
compatible with `event_observation_trends.md` (2d, GPT/Codex): this document
reads its `kind` field when present and never computes deltas for event checks.

## Evidence

- **E1.** `server_audit` is never trended. Its result is
  `{'host', 'sections': {nginx, fail2ban, firewall, sql, ssh: {'findings': [...]}}, 'summary'}`,
  and `trends._snapshot()` reads only top-level `findings`/`hardening`, so it returns `None`.
- **E2.** Some findings mean "could not evaluate". `server_audit` reports an
  unreadable nginx config or `sshd_config` as an id-less `low` finding
  (`server_security.py:63`, `:936`). If nginx was readable in run N and not in
  N+1, a naive diff lists every `NGX-*` id as `resolved`. The same class exists
  in other state checks: kind-D findings ("could not determine", stable-ids
  contract, table row D) already carry `requires_manual_verification: true`
  (`findings.py:59`; 16 call sites in 4 check modules).
- **E3. Bug in AI History v1, reproduced on a temporary DB.** The analyzed
  report is returned as its own most recent "past report": `run --ai` saves the
  report and then calls `find_related_reports(report)`; `analyze <id>` and the
  Web analyze of a saved report do the same. `find_related_reports()` never
  excludes the run itself (`storage.py:303-355`, `netaudit.py:111-118,137-138`,
  `web/app.py:256`). One of the three history slots is wasted, and the AI sees
  "previous run identical to this one".
- **E4.** The Web UI has no trend view. Web reports carry `execution_context`
  since task 2, so the data exists.

## 2a — `server_audit` in trends (`trends.py`, `server_security.py`)

1. `_snapshot()`: when a result has no top-level `findings` list and no
   `hardening.score`, but has `sections` (a dict whose values are dicts), the
   snapshot uses the concatenation of each section's `findings` list, sections
   in key order. Matched by shape, not by check id. If top-level `findings`
   exist, they win and sections are ignored (no double counting).
2. A snapshot gains `unverified`: the number of problem-severity findings with
   `requires_manual_verification: true`, with or without `id`, for every check.
   A point gains `unverified` (`None` for error/ambiguous points). `unverified`
   joins the v1.1 fields compared for in-report ambiguity.
3. `latest_change` gains one key, `unverified_in_latest` = `unverified` of its
   `to` point. All existing keys and values are unchanged. Meaning: if it is
   `> 0` and `resolved` is non-empty, a "resolved" id may be one that the latest
   run could not evaluate.
4. In `server_audit`, the two "no access" findings get
   `requires_manual_verification=True`. Severity, title, detail and id
   (none) stay the same. Adding ids to them is out of scope.
5. CLI `netaudit trend <check> <value>`: when `unverified_in_latest > 0` and
   `resolved` is non-empty, print one extra line:
   `note: N finding(s) in the latest run could not be verified - "resolved" may mean "not evaluated"`.
   `--json` carries the field only.

## 2b — deterministic trend in AI analysis; history excludes the run itself

1. `find_related_reports(report, limit)` skips a candidate that is the same
   run: same `timestamp` **and** same canonical `results`
   (`json.dumps(..., sort_keys=True)` after a JSON round trip). The signature
   does not change. Two distinct runs with the same second and identical
   results add nothing as history, so skipping one is harmless.
2. New pure-ish `trends.trend_context(report, window=200, max_units=20, max_ids=20) -> list[dict]`:
   - for each unit of `snapshots_from_report(report)` whose snapshot has no
     error, compute the trend over (snapshots of the latest `window` reports,
     **excluding the same run** by rule 2b.1) + this report's snapshot, oldest
     first;
   - include the unit only if `latest_change` is not `None` **and** its `to`
     point is this report. Errored current runs and first-ever runs are
     excluded; event-observation units (2d: `latest_change=None`) never appear;
   - item: `{check_id, key, value, latest_change}`. `new`/`resolved`/`persisting`
     are each truncated to `max_ids`, and `<list>_omitted: int` is added only when truncated;
   - at most `max_units` items, in the order of `snapshots_from_report`.
3. `ai_analyze(report, language=None, history=None, trends=None)`: with a
   non-empty `trends`, the prompt gains one block after history:
   "Deterministic changes since the previous run of the same object (computed
   by NetAudit, authoritative - do not recompute or contradict). `resolved` =
   the finding id was not reported in the latest run; if
   `unverified_in_latest > 0` it may mean not evaluated, not fixed." + JSON.
   With `None` or `[]` the prompt is byte-for-byte unchanged (same rule as
   `history`).
4. Callers `cmd_run --ai`, `cmd_analyze`, `api_analyze` pass
   `trends=trends.trend_context(report)`.
5. Privacy: items carry check ids, the identity key/value already present in
   the report, finding ids, counts and timestamps; no params. A test asserts
   that a fake password in `execution_context` never reaches the prompt.
6. **Ordering with 2d.** Before 2d lands, the four log checks still get
   state-style `latest_change`. 2b therefore merges **after** 2d, so the AI
   never receives "resolved" for log events.

## 2c — Web trends (`web/app.py`, `web/static/index.html`, `web/static/i18n.js`)

API, read-only, behind the existing auth middleware like every route:
- `GET /api/trends` → `{"units": list_units()}` (+ `kind` per unit once 2d exists).
- `GET /api/trend?check_id=&key=&value=` → `trend_for(...)`. Returns 400 if a
  parameter is missing or `key` is not an identity key, and 404 if the unit has no data.

UI, existing vanilla JS, both languages:
- New **Trends** tab: table of units (check, key=value, runs, last run).
  Selecting a unit shows the points table (time, critical/high/medium/low,
  total, score, unverified, status ok/error/ambiguous) and, for state units,
  the latest-change block (counts and score delta, new/resolved/persisting
  ids, plus the 2a note when `unverified_in_latest > 0`).
- `kind == 'event_observation'` (2d): heading "Log observations", points only,
  no change block and no "resolved/new/improved" wording.
- All data is rendered with `textContent` or escaped. Tested with a unit value `<img src=x onerror=…>`.
- No new JS dependencies, no charts in 1.0 (tables only).

## RED scenarios (before code)

- 2a: `server_audit` snapshot = sum over sections, ids from all sections;
  nginx unreadable in the latest run → `unverified_in_latest == 1`, NGX ids in
  `resolved`; CLI prints the note; a state check without unverified findings
  keeps every v1.1 value plus `unverified_in_latest == 0`; two in-report
  instances differing only in `unverified` → ambiguous; top-level findings win
  over sections.
- 2b: self-exclusion in `run --ai`, `analyze <id>` and Web analyze (saved and
  posted report); `trend_context`: previous→current change, current error
  excluded, first run excluded, caps and `_omitted`; prompt unchanged without
  trends, block present with trends; no fake password in the prompt.
- 2c: `/api/trends` and `/api/trend` 200/400/404 on the isolated DB; rendered
  page contains the Trends tab; hostile unit value is not interpreted as HTML
  (checked in the browser pane with a temporary HOME); event units show no change block.

## Out of scope

Ids for log findings and the interval model (2d/2e); ids for the "no access"
findings; changing the 200-report window; charts; trends for metric checks
(ping, mtr).

## Implementation order (proposal)

2a (Claude) → 2d (GPT/Codex, on top of 2a: both touch `trends.py`) →
2b + 2c (Claude, on top of 2d). While 2d is in progress, Claude can build the
2c API/UI without the `kind` branch and add it after 2d merges.
