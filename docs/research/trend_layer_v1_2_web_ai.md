# Trend layer v1.2: server_audit, AI trend context, Web trends — contract proposal

Status: **PROPOSED rev.2** (2026-10-08) — roadmap items 2a, 2b, 2c. rev.2 answers
GPT/Codex contract review pass 1 (`.ai/REVIEW.md`): exact-id anchor, strictly-before
history, tri-state `not_evaluated`.
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

## 2a — `server_audit` in trends; "not evaluated" is not "resolved" (`trends.py`, `server_security.py`)

1. `_snapshot()`: when a result has no top-level `findings` list and no
   `hardening.score`, but has `sections` (a dict whose values are dicts), the
   snapshot uses each section's `findings` list. Matched by shape, not by check
   id. If top-level `findings` exist, they win and sections are ignored (no
   double counting).
2. **Scope.** Every problem finding belongs to a scope: its section name for a
   sectioned result, otherwise one scope for the whole result. Internally the
   snapshot keeps, per scope present in the result, its ids and the number of
   problem findings with `requires_manual_verification: true` ("unverified",
   with or without `id`). The public point gains `unverified` (total;
   `None` for error/ambiguous points). The per-scope data takes part in the
   v1.1 in-report ambiguity comparison.
3. **Tri-state diff** (rev.2, GPT/Codex review 3). For an id present in the
   previous compared run and absent from the latest one:
   - `resolved` only if its scope is present in the latest result **and** has
     zero unverified findings there;
   - otherwise it goes to a new list **`not_evaluated`** and never into
     `resolved`. For a flat check this is conservative: any unverified finding
     in the latest run moves every missing id to `not_evaluated`.
   `new` and `persisting` are unchanged. A false "new" only draws attention,
   while a false "resolved" claims remediation. `counts_delta`/`total_delta`
   keep their v1 meaning, which is the change in *observed* counts. CLI, Web
   and AI must label them that way and not call them proven improvement.
   `latest_change` = every v1.1 key with identical semantics + `not_evaluated`
   (list). For runs without unverified findings every value is exactly as in v1.1.
4. In `server_audit`, the two "no access" findings (nginx config, `sshd_config`)
   get `requires_manual_verification=True`. Severity, title, detail and id
   (none) stay the same. With rule 3, an unreadable nginx config moves every
   `NGX-*` id of the previous run to `not_evaluated`.
5. CLI `netaudit trend <check> <value>` prints `not evaluated: …` beside
   `resolved: …` and labels counts as observed counts. `--json` carries the list.

## 2b — deterministic trend in AI analysis; history and trend strictly before the analyzed run

1. **Anchor** (rev.2, GPT/Codex review 1–2). "Before report R" uses the same
   total order as the trend layer: `(timestamp, id)`.
   - With R's DB id: candidates are rows with `timestamp < R.timestamp`, or
     the same timestamp and `id < R.id`. This never includes R itself or any
     later run, and it keeps a distinct run saved in the same second before R.
   - Without an id (an inline report posted to `/api/analyze` with no
     `_report_id`): only `timestamp < R.timestamp`. Limitation, documented:
     same-second earlier runs are skipped, since content is not an identity.
   - No timestamp and no id: no history, no trend.
   Ids come from callers: `run --ai` → the id returned by `save_report()`;
   `analyze <id>` → that id; `/api/analyze` → `report_id`, else an integer
   `report['_report_id']` (Web runs have it), else none. 2c makes the Web UI
   keep `_report_id` when it opens a report from history.
2. `find_related_reports(report, limit=3, report_id=None)` applies the anchor.
   AI History v1 thus stops returning R as its own history and never presents
   a later run as "previous".
3. New `trends.trend_context(report, report_id=None, window=200, max_units=20, max_ids=20) -> list[dict]`:
   - history snapshots come from the latest `window` reports **before the
     anchor** (new read helper `storage.report_data_before(...)`, redacted like
     `recent_report_data()`), followed by R's own snapshots;
   - a unit is included only if R's snapshot has no error and `latest_change`
     compares a previous run → R. Errored R, first-ever runs and
     event-observation units (2d: `latest_change=None`) are not included;
   - item: `{check_id, key, value, latest_change}`. `new`/`resolved`/
     `persisting`/`not_evaluated` are each truncated to `max_ids`, and
     `<list>_omitted: int` is added only when truncated. At most `max_units` items.
4. `ai_analyze(report, language=None, history=None, trends=None)`: a non-empty
   `trends` adds one prompt block after history: "Changes since the previous
   run of the same object, computed by NetAudit from saved reports.
   `resolved`: the finding id is no longer reported and its area was fully
   evaluated. `not_evaluated`: no longer reported, but the latest run could not
   evaluate it, so do not treat it as fixed. `counts_delta`: change in observed
   counts." + JSON. With `None`/`[]` the prompt is byte-for-byte unchanged.
5. Callers `run --ai`, `analyze`, `/api/analyze` pass `history` and `trends`
   built with the same anchor.
6. Privacy: items carry check ids, the identity key/value already present in
   the report, finding ids, counts and timestamps; no params. A test asserts
   that a fake password in `execution_context` never reaches the prompt.
7. **Ordering with 2d.** Before 2d lands, the four log checks still get
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
  the latest-change block (observed counts and score delta, new / resolved /
  not evaluated / persisting ids).
- Opening a report from history keeps its `_report_id`, so AI analysis of
  that report uses the exact-id anchor (2b.1).
- `kind == 'event_observation'` (2d): heading "Log observations", points only,
  no change block and no "resolved/new/improved" wording.
- All data is rendered with `textContent` or escaped. Tested with a unit value `<img src=x onerror=…>`.
- No new JS dependencies, no charts in 1.0 (tables only).

## RED scenarios (before code)

- 2a: `server_audit` snapshot = sum over sections, ids from all sections; top-level
  findings win over sections. nginx readable with `NGX-CONF-001` → unreadable
  next run: `NGX-CONF-001` in `not_evaluated`, **not** in `resolved`; another
  section's id that disappeared while that section was fully evaluated is
  `resolved`. A flat check with one unverified finding in the latest run → all
  missing ids `not_evaluated`. A state check without unverified findings keeps
  every v1.1 value, with `not_evaluated == []`. Two in-report instances that
  differ only in unverified/scope → ambiguous. CLI prints `not evaluated`.
- 2b: `find_related_reports` with id anchor excludes R and later runs: A→B→C,
  analyzing B gives history [A] and trend A→B. Two distinct runs in one second
  (B id 2, C id 3, same results): analyzing C keeps B. Inline report without id
  uses strictly earlier timestamps. `run --ai`, `analyze <id>` and
  `/api/analyze` (by `report_id`, by posted `_report_id`, inline) wire the
  anchor. `trend_context` covers: errored R excluded, first run excluded, caps
  and `_omitted`. The prompt is unchanged without trends and has the block with
  them. No fake password in the prompt.
- 2c: `/api/trends` and `/api/trend` 200/400/404 on the isolated DB; rendered
  page contains the Trends tab; a hostile unit value is not interpreted as HTML
  (checked in the browser pane with a temporary HOME); event units show no
  change block; a history-opened report is analyzed with its `_report_id`.

## Out of scope

Ids for log findings and the interval model (2d/2e); ids for the "no access"
findings; changing the 200-report window; charts; trends for metric checks
(ping, mtr).

## Implementation order (proposal)

2a (Claude) → 2d (GPT/Codex, on top of 2a: both touch `trends.py`) →
2b + 2c (Claude, on top of 2d). While 2d is in progress, Claude can build the
2c API/UI without the `kind` branch and add it after 2d merges.
