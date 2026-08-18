"""
Logs Audit — Detection (Iteration 4): turns a list of already-parsed
SSHAuthEvent objects into DetectionSignal objects — aggregated,
evidence-carrying observations about repeated failures or successful
logins following failures. This module does NOT assign severity, does
NOT decide what counts as a "problem", and does NOT produce Findings —
see this module's docstring on the event -> signal -> finding chain and
why each layer answers only its own question.

Scope (per Detection Contract, Iteration 4 freeze)
------------------------------------------------------------------
Rule 1 — No severity thresholds here. A signal is produced for any
  count >= 1; deciding whether that count is worth surfacing to a human
  is entirely the Findings layer's job, not this module's. The
  Repeated*Signal names describe an aggregation, not a claim that the
  underlying activity is actually repeated/suspicious.

Rule 2 — source_ip and username aggregation are independent projections
  of the same event list. The same SSHAuthEvent can and does appear as
  evidence in both a RepeatedFailuresFromIPSignal and a
  RepeatedFailuresForUsernameSignal simultaneously — see Rule 5.

Rule 3 — SuccessAfterFailureSignal construction, per (source_ip,
  username) pair, using only events with timestamp is not None, sorted
  by timestamp:
    - the event stream is split into intervals bounded by ACCEPTED
      events (interval = everything after the previous ACCEPTED, up to
      and including the next ACCEPTED)
    - FAILED_PASSWORD events within an interval become that interval's
      evidence
    - a signal is only produced for an interval that contains at least
      one FAILED_PASSWORD before its ACCEPTED
    - a FAILED_PASSWORD is never reused across two different ACCEPTED
      intervals — each failure belongs to exactly one interval

Rule 4 — INVALID_USER never participates in SuccessAfterFailureSignal
  construction (an invalid/nonexistent user logically cannot be the
  same account that later succeeds). INVALID_USER still participates
  normally in source_ip and username aggregation (Rule 2).

Rule 5 — No deduplication between signal types. Overlapping evidence
  across RepeatedFailuresFromIPSignal / RepeatedFailuresForUsernameSignal
  / SuccessAfterFailureSignal is expected and correct — they are
  different projections of the same underlying events, not redundant
  copies of an error.

Rule 6 — Events with timestamp=None ("undated") participate in
  source_ip and username aggregation (order doesn't matter there), but
  never in SuccessAfterFailureSignal construction, which requires a
  total order. Undated events are still counted and surfaced (see
  WindowedEvents.undated / DetectionResult.undated_event_count) — never
  silently dropped.

Rule 7 — coverage_uncertain never affects whether a signal is produced;
  it is carried through from WindowedEvents into DetectionResult purely
  as a transparency flag for the Findings layer ("we may not have seen
  the full window's worth of events, because Collection returned
  exactly its line limit").

Window boundaries are inclusive on both ends:
  reference_time - window <= timestamp <= reference_time  =>  in window
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .ssh_auth_parser import SSHAuthEvent, SSHAuthEventType


@dataclass
class DetectionContext:
    reference_time: datetime
    window: timedelta
    collection_limit: int


@dataclass
class WindowedEvents:
    in_window: list[SSHAuthEvent]
    undated: list[SSHAuthEvent]
    coverage_uncertain: bool


@dataclass
class RepeatedFailuresFromIPSignal:
    source_ip: str
    failed_password_count: int
    invalid_user_count: int
    invalid_usernames: set[str]
    events: list[SSHAuthEvent] = field(default_factory=list)


@dataclass
class RepeatedFailuresForUsernameSignal:
    username: str
    failed_password_count: int
    source_ips: set[str]
    events: list[SSHAuthEvent] = field(default_factory=list)


@dataclass
class SuccessAfterFailureSignal:
    source_ip: str
    username: str
    failed_events: list[SSHAuthEvent]
    accepted_event: SSHAuthEvent


@dataclass
class DetectionResult:
    repeated_failures_by_ip: list[RepeatedFailuresFromIPSignal]
    repeated_failures_by_username: list[RepeatedFailuresForUsernameSignal]
    success_after_failure: list[SuccessAfterFailureSignal]
    undated_event_count: int
    coverage_uncertain: bool


def apply_window(events: list[SSHAuthEvent], context: DetectionContext) -> WindowedEvents:
    """Splits raw events into in_window / undated per DetectionContext.
    coverage_uncertain is True when len(events) == context.collection_limit
    — a signal (not proof) that Collection's tail -n N limit may have
    cut off older events that would otherwise fall inside the window.

    Window boundaries are inclusive on both ends:
        reference_time - window <= timestamp <= reference_time  =>  in_window

    An event with timestamp=None is never in_window — it goes to
    undated instead. An event with a timestamp outside the window is
    excluded from BOTH lists (it's neither "in window" nor "undated" —
    it has a known timestamp that simply falls outside the requested
    range, which is a third, distinct outcome from either list's
    purpose).
    """
    lower_bound = context.reference_time - context.window
    upper_bound = context.reference_time

    in_window: list[SSHAuthEvent] = []
    undated: list[SSHAuthEvent] = []

    for event in events:
        if event.timestamp is None:
            undated.append(event)
        elif lower_bound <= event.timestamp <= upper_bound:
            in_window.append(event)
        # else: dated but outside the window — excluded from both lists

    coverage_uncertain = len(events) == context.collection_limit

    return WindowedEvents(in_window=in_window, undated=undated, coverage_uncertain=coverage_uncertain)


# ===========================================================================
# IP / username aggregation (Rule 2, Rule 6) — source: in_window + undated
# ===========================================================================

def _aggregate_by_ip(events: list[SSHAuthEvent]) -> list[RepeatedFailuresFromIPSignal]:
    """One aggregate per distinct source_ip, built from every
    FAILED_PASSWORD/INVALID_USER event that has a source_ip. Order of
    the returned list follows first-appearance order of each source_ip
    in `events`, for deterministic test assertions."""
    order: list[str] = []
    by_ip: dict[str, RepeatedFailuresFromIPSignal] = {}

    for event in events:
        if event.event_type not in (SSHAuthEventType.FAILED_PASSWORD, SSHAuthEventType.INVALID_USER):
            continue
        if event.source_ip is None:
            continue

        if event.source_ip not in by_ip:
            by_ip[event.source_ip] = RepeatedFailuresFromIPSignal(
                source_ip=event.source_ip, failed_password_count=0, invalid_user_count=0,
                invalid_usernames=set(),
            )
            order.append(event.source_ip)

        signal = by_ip[event.source_ip]
        if event.event_type == SSHAuthEventType.FAILED_PASSWORD:
            signal.failed_password_count += 1
        else:
            signal.invalid_user_count += 1
            if event.username is not None:
                signal.invalid_usernames.add(event.username)
        signal.events.append(event)

    return [by_ip[ip] for ip in order]


def _aggregate_by_username(events: list[SSHAuthEvent]) -> list[RepeatedFailuresForUsernameSignal]:
    """One aggregate per distinct username, built from FAILED_PASSWORD
    events only — INVALID_USER events reference a username that, by
    definition, doesn't correspond to a real account, so they are not
    folded into per-username failure tracking here (they still fully
    participate in _aggregate_by_ip). Order follows first-appearance."""
    order: list[str] = []
    by_username: dict[str, RepeatedFailuresForUsernameSignal] = {}

    for event in events:
        if event.event_type != SSHAuthEventType.FAILED_PASSWORD:
            continue
        if event.username is None:
            continue

        if event.username not in by_username:
            by_username[event.username] = RepeatedFailuresForUsernameSignal(
                username=event.username, failed_password_count=0, source_ips=set(),
            )
            order.append(event.username)

        signal = by_username[event.username]
        signal.failed_password_count += 1
        if event.source_ip is not None:
            signal.source_ips.add(event.source_ip)
        signal.events.append(event)

    return [by_username[u] for u in order]


# ===========================================================================
# Success-after-failure (Rule 3, Rule 4) — source: in_window only
# ===========================================================================

def _success_after_failure(events: list[SSHAuthEvent]) -> list[SuccessAfterFailureSignal]:
    """Per (source_ip, username) pair: sort by timestamp, split into
    intervals bounded by ACCEPTED events, and emit one signal per
    interval that contains at least one FAILED_PASSWORD. INVALID_USER
    never participates here (Rule 4). A FAILED_PASSWORD is consumed by
    at most one interval — the running `pending` list is cleared after
    each ACCEPTED, so it can never leak into a later interval."""
    by_key: dict[tuple[str, str], list[SSHAuthEvent]] = {}

    for event in events:
        if event.timestamp is None:
            continue
        if event.event_type not in (SSHAuthEventType.FAILED_PASSWORD, SSHAuthEventType.ACCEPTED):
            continue
        if event.source_ip is None or event.username is None:
            continue
        by_key.setdefault((event.source_ip, event.username), []).append(event)

    signals: list[SuccessAfterFailureSignal] = []

    for (source_ip, username), key_events in by_key.items():
        key_events.sort(key=lambda e: e.timestamp)
        pending: list[SSHAuthEvent] = []

        for event in key_events:
            if event.event_type == SSHAuthEventType.FAILED_PASSWORD:
                pending.append(event)
            elif event.event_type == SSHAuthEventType.ACCEPTED:
                if pending:
                    signals.append(SuccessAfterFailureSignal(
                        source_ip=source_ip, username=username,
                        failed_events=list(pending), accepted_event=event,
                    ))
                pending = []

    return signals


def detect(windowed: WindowedEvents) -> DetectionResult:
    """Runs all three detection projections per Rules 1-6 above.

    IP and username aggregation (Rule 6) run over
    windowed.in_window + windowed.undated combined — an event with no
    known timestamp still has a known source_ip/username/event_type and
    must not be dropped from simple counting just because its position
    in time is unknown.

    SuccessAfterFailureSignal construction runs ONLY over
    windowed.in_window — it requires a total order between failures and
    an ACCEPTED, which an undated event cannot supply (Rule 6).

    undated_event_count and coverage_uncertain are carried through from
    the WindowedEvents input unchanged (Rule 7)."""
    aggregation_events = windowed.in_window + windowed.undated

    return DetectionResult(
        repeated_failures_by_ip=_aggregate_by_ip(aggregation_events),
        repeated_failures_by_username=_aggregate_by_username(aggregation_events),
        success_after_failure=_success_after_failure(windowed.in_window),
        undated_event_count=len(windowed.undated),
        coverage_uncertain=windowed.coverage_uncertain,
    )
