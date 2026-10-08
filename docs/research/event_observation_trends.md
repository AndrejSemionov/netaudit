# Event-log observations in trends — research and contract proposal

Status: **DRAFT rev.2, not approved for implementation** (2026-10-08).
Owner proposal: GPT/Codex implements; Claude independently reviews the
contract and code. Product decision and contract approval remain with USER.
Claude reviewed rev.1 (`d7ca5ad`) and approved option 3 in principle;
rev.2 incorporates his three pre-RED clarifications. Focused re-review is
pending.

## Problem and evidence

The existing `trends._snapshot()` accepts any result with a `findings`
list. Consequently the four log checks below are already included in
state-style severity counts. A later observation with fewer findings can
produce a negative `latest_change.total_delta`, even though an event may
simply have fallen out of a bounded tail or rolling time window. Most log
findings carry no `id`, so `new` and `resolved` are empty today, but adding
IDs and using the current state diff would create false "resolved" claims.

| Check | Collection / window | Coverage evidence in current result |
|---|---|---|
| `ssh_auth_audit` | bounded `lines` from auth.log or journal fallback, then `window_hours` | `meta.selected_source`, `fallback_used`, `events_parsed`, `coverage_uncertain`; no explicit coverage status |
| `nginx_logs_audit` | bounded `lines` per matched access/error log | `meta.access` and `meta.error`: coverage, detection_succeeded, events_parsed, events_total |
| `fail2ban_logs_audit` | bounded `lines` from fail2ban.log | `meta.coverage`, detection_succeeded, events_parsed, events_total |
| `kern_log_audit` | bounded `lines` from kern.log | same coverage and count fields as fail2ban |

No current report stores a reliable, non-overlapping observation interval
for all four checks. `execution_context` stores the requested parameters,
not what interval of log events was actually covered. A failed or partial
collection must not be presented as zero events. Different `lines`,
sources, or windows also make raw counts hard to compare.

## Options

1. Assign each signal a stable `Finding.id` and reuse state diff.
   Rejected: disappearance from a later log slice does not prove that an
   attack or fault was fixed. Static IDs also collide for multiple subjects
   in one run; subject IDs need separate identity and privacy rules.
2. Exclude the four log checks from trends until interval metadata exists.
   Safe and minimal, but gives no history view for valuable observations.
3. **Recommended for 1.0:** keep their saved reports and list them as
   event observations, but suppress state-style `latest_change`, `new`,
   `resolved`, and `persisting`. Show per-run severity counts and available
   coverage/source metadata. Do not add `Finding.id` to log events in this
   change. A later interval-based model can define event occurrence IDs or
   rule/subject grouping without changing state-finding IDs.

## Proposed contract for option 3

- A fixed `EVENT_CHECK_IDS` set contains exactly the four checks above.
  A single helper derives `kind` from `check_id` inside pure
  `compute_trend()` and `list_units()`; `trend_for()` returns
  `kind='event_observation'` for these checks;
  `latest_change=None` regardless of how many successful snapshots exist.
  The CLI and Web UI label these points "log observations", never
  "improved", "worsened", "resolved", or "new". State checks gain
  `kind='state'` and retain the existing diff and all existing values.
- Event points retain timestamp and severity counts, with optional
  `observation` metadata: source, coverage, events parsed/total, requested
  lines/window. Metadata absent from a historical report is explicitly
  `None`; its known findings can still be counted, labeled "coverage
  unknown". An explicit collection failure with no usable source yields
  `counts=None`, never a false zero. Coverage mapping:

  | Check and collection outcome | Counts | Display label |
  |---|---|---|
  | fail2ban/kern `complete` | observed finding counts | complete for collected slice |
  | fail2ban/kern `partial` | observed finding counts | partial, lower bound |
  | fail2ban/kern `empty` | zero | empty log, not "no attacks" |
  | fail2ban/kern `failed` or `unknown` | `None` | collection failed / unknown |
  | nginx access/error both `failed` or `unknown` | `None` | neither contour usable |
  | nginx at least one usable contour (`complete`, `partial`, or `empty`) | observed finding counts | show **both** coverage values; lower bound if either contour is `partial`, `failed`, or `unknown`; `complete` + `empty` is fully collected for the available slices |
  | SSH `selected_source='none'` | `None` | no usable source |
  | SSH source selected | observed finding counts | bounded tail; `coverage_uncertain` is shown separately as `tail_limit_reached`, never reclassified as a complete time interval |

  These labels describe collection, not a guarantee that all events in the
  requested time span were available. The SSH mapping depends on the 2e
  correction: a nonzero collection exit code cannot select a source.
  `nginx_logs_audit` with `installed=False` has no snapshot; a top-level
  error yields an error point with `counts=None`.
- No historical report is rewritten. Old event reports with missing metadata
  remain visible, labeled "coverage unknown". No AI prompt may describe a
  lower count as remediation without a comparable-interval contract.
- If duplicate instances of one `(check_id,key,value)` appear in one
  report, retain v1.1 ambiguity handling; do not sum counts across ports.
  This composes with the v1.2 `unverified` field proposed by Claude:
  event points may carry it, but `latest_change` remains `None`.
- All output uses the existing redacted read path. Observation metadata
  excludes raw log lines, usernames, client IPs and secrets.

## RED scenarios before implementation

1. Two `ssh_auth_audit` reports, 1 high finding then 0, yield two event
   points but `latest_change=None`; CLI and Web copy contain no "resolved".
2. Explicit failed/unknown collection for the single-source checks yields
   `counts=None`; historical missing metadata with findings keeps the
   observed count but has coverage unknown.
3. A partial nginx run preserves access/error coverage separately and
   keeps counts from usable contours; both failed gives `counts=None`.
   `installed=False` gives no point; top-level error gives an error point.
4. Different `lines` or `window_hours` remain labeled observations; no
   comparative delta is calculated.
5. A state check such as `ssh_hardening` retains the exact existing
   latest_change shape and values; list units and trend both report its
   `kind='state'`.
6. Old log reports without metadata display unknown coverage and do not
   crash; a multi-host duplicate follows v1.1 ambiguity handling.
7. SSH tail limit reached still shows observed findings and a bounded-slice
   warning, never a state-style delta; no-source/exit-nonzero shows no count.

## Open product decision

USER must choose whether option 3 is sufficient for 1.0, or whether
event-interval provenance and a separately scoped occurrence model are
required before release. Claude's independent review should challenge
the coverage mapping and backwards-compatibility claim before approval.
