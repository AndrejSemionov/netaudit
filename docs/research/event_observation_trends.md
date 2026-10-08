# Event-log observations in trends — research and contract proposal

Status: **DRAFT, not approved for implementation** (2026-10-08).
Owner proposal: GPT/Codex implements; Claude independently reviews the
contract and code. Product decision and contract approval remain with USER.

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
  `trend_for()` returns `kind='event_observation'` for them;
  `latest_change=None` regardless of how many successful snapshots exist.
  The CLI and Web UI label these points "log observations", never
  "improved", "worsened", "resolved", or "new". State checks retain their
  current `kind='state'` behavior and existing diff.
- Event points retain timestamp and severity counts, with optional
  `observation` metadata: source, coverage, events parsed/total, requested
  lines/window. Missing metadata is explicitly `None`, never inferred as
  complete. Errors and unknown/failed coverage yield counts `None`, rather
  than a false zero. For nginx access and error, expose each coverage value
  separately; do not collapse partial coverage into complete.
- No historical report is rewritten. Old event reports with missing metadata
  remain visible, labeled "coverage unknown". No AI prompt may describe a
  lower count as remediation without a comparable-interval contract.
- If duplicate instances of one `(check_id,key,value)` appear in one
  report, retain v1.1 ambiguity handling; do not sum counts across ports.
- All output uses the existing redacted read path. Observation metadata
  excludes raw log lines, usernames, client IPs and secrets.

## RED scenarios before implementation

1. Two `ssh_auth_audit` reports, 1 high finding then 0, yield two event
   points but `latest_change=None`; CLI and Web copy contain no "resolved".
2. A failed or unknown coverage run yields a point with `counts=None`.
3. A partial nginx run preserves access/error coverage separately.
4. Different `lines` or `window_hours` remain labeled observations; no
   comparative delta is calculated.
5. A state check such as `ssh_hardening` retains the exact existing
   latest_change shape and values.
6. Old log reports without metadata display unknown coverage and do not
   crash; a multi-host duplicate follows v1.1 ambiguity handling.

## Open product decision

USER must choose whether option 3 is sufficient for 1.0, or whether
event-interval provenance and a separately scoped occurrence model are
required before release. Claude's independent review should challenge
the coverage mapping and backwards-compatibility claim before approval.
