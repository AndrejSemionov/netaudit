"""Nginx Error Log Detection (v1).

Scope v1 (frozen contract):

Pipeline position: Discovery -> Resolver -> Matching -> Collection ->
Error Parser -> Detection (this module) -> Findings. Detection does NOT
search for files, does NOT re-parse raw lines, and does NOT talk to SSH.
It receives already-structured NginxErrorEvent objects plus a
CoverageStatus (derived by the caller from collection/discovery
evidence), looks for patterns, and emits NginxErrorSignal objects.
Findings (a separate, not-yet-built module) turns a Signal into a
severity-carrying finding — Detection itself never decides severity.

This module answers a different question than nginx_access_detection.py:
not "who is making requests and how often", but "what is happening to
nginx and its upstream/application layer". It is NOT a mechanical copy of
Access Detection — see the per-signal contracts below, each independently
reasoned rather than inherited.

NginxErrorSignalType (3 values — UPSTREAM_FAILURE deliberately deferred):
    HIGH_ERROR_RATE   frequency axis: too many error+ severity events
    CRITICAL_ERROR    severity axis: at least one crit/alert/emerg event
    REPEATED_ERROR    repetition axis: the same normalized message recurring

UPSTREAM_FAILURE ("connect() failed", "upstream timed out", "no live
upstreams", etc.) is explicitly OUT of v1 scope: classifying these as one
semantic category requires message pattern/signature matching, the same
kind of hardcoded-signature decision already rejected for Access
Detection's PATH_SCAN (no known-attack-paths list there either). A future
"Error Signature Engine" (upstream failures, permission denied,
filesystem errors, TLS errors, etc.) is a distinct, not-yet-started layer
on top of Detection — not part of this module.

Severity semantics (orthogonal axes — a single event can trigger both
HIGH_ERROR_RATE and CRITICAL_ERROR; this is two independent observations,
not double-counting one fact):
    debug/info/notice/warn -> neither
    error                   -> HIGH_ERROR_RATE only
    crit/alert/emerg        -> HIGH_ERROR_RATE AND CRITICAL_ERROR

Aggregation (both slice-wide, at most one signal each per collected
slice — HIGH_ERROR_RATE/CRITICAL_ERROR are NOT per-PID/TID, NOT per-IP;
PID/TID identify a worker process, not a meaningful audit key, and
error.log frequently carries no client IP at all):
    HIGH_ERROR_RATE: count(severity in {error,crit,alert,emerg}) >= threshold
                      -> at most 1 signal, event_count = that count
    CRITICAL_ERROR:  count(severity in {crit,alert,emerg}) >= 1
                      -> at most 1 signal, event_count = ALL such events
                         (not the first one, not one signal per event)

REPEATED_ERROR normalization (the most consequential decision in this
contract — deliberately conservative):
    key = message.strip() — ONLY whitespace normalization, NO regex or
          semantic pattern extraction
    PID/TID/connection_id/severity do NOT participate in identity
    client:/server:/request:/upstream:/host: substrings inside message
          are NOT parsed out — they remain part of the exact-match string
          as-is, exactly as the Error Parser Contract v1 left them
    Two messages differing only in an embedded IP/port/path are treated
          as DIFFERENT errors (explicit anti-case) — grouping them would
          require the same signature-parsing this contract avoids.
    One NginxErrorSignal is emitted PER message-key that reaches the
          threshold — a slice can produce zero, one, or several
          independent REPEATED_ERROR signals.
Rationale: a false negative (failing to group two really-similar errors
that differ by client IP) is preferable to a false positive (declaring
two genuinely different problems as one) for this first Detection
contour. This does not violate the Error Parser Contract v1 — the parser
deliberately leaves client:/request:/upstream: unstructured, and
Detection must not silently start parsing them either.

Invariant for every NginxErrorSignal, no exceptions: event_count ==
len(raw_evidence). No truncation happens inside Detection — even 1000
repeats of the same message keep all 1000 events in raw_evidence. Memory
pressure is a Collection slice-size concern (tail -n N), not something
Detection silently works around.

Coverage semantics — full reuse of the Access Detection model, with NO
error-specific extensions:
    CoverageStatus: COMPLETE / PARTIAL / EMPTY / FAILED / UNKNOWN
    detection_succeeded: COMPLETE/PARTIAL/EMPTY -> True, FAILED/UNKNOWN -> False
EMPTY means strictly "0 parsed events in the input" — NOT "no
crit/alert/emerg events found". An error.log slice containing 1000 info
lines and zero error+ lines is coverage=COMPLETE, detection_succeeded=
True, signals=[] — the file was fully analyzed, nothing noteworthy was
found. This is the same coverage-vs-detection-result boundary already
established for Access Detection; no exception is carved out here.

Numeric thresholds v1 (NetAudit engineering policy — NOT nginx or
Fail2Ban standards; no authoritative external source exists for these
specific values. Fail2Ban's error.log-based jails (nginx-http-auth,
nginx-limit-req) use maxretry in the 5-10 range, used here only as a
semantic order-of-magnitude reference for REPEATED_ERROR, not as a claim
that this threshold is "based on Fail2Ban" — Fail2Ban's maxretry is a
ban-policy on regex-matched lines, a different mechanism from this exact-
message-repetition detector):
    HIGH_ERROR_RATE threshold = 10  (chosen for internal consistency with
                                      Access Detection's HIGH_4XX_RATE=10,
                                      not an external source)
    CRITICAL_ERROR threshold  = 1
    REPEATED_ERROR threshold  = 5

Important consequence: HIGH_ERROR_RATE's threshold of 10 does NOT mean
"10 errors within some time period" — Detection operates on whatever
slice Collection handed it (e.g. tail -n 200), it does not introduce its
own time window. 10 means: at least 10 error+ events among the collected
lines, however that slice's timespan happens to be.

This module is independent from nginx_access_detection.py and
ssh_auth_detection.py by design — no shared code assumed until a second
or third real case demonstrates the same abstraction is warranted.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from enum import Enum

from netaudit_pkg.nginx_error_parser import (
    NginxErrorEvent,
    NginxErrorEventType,
    NginxErrorSeverity,
)


class CoverageStatus(Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    EMPTY = "empty"
    FAILED = "failed"
    UNKNOWN = "unknown"


class NginxErrorSignalType(Enum):
    HIGH_ERROR_RATE = "high_error_rate"
    CRITICAL_ERROR = "critical_error"
    REPEATED_ERROR = "repeated_error"


# Numeric thresholds v1 — see module docstring for provenance/rationale.
HIGH_ERROR_RATE_THRESHOLD = 10
CRITICAL_ERROR_THRESHOLD = 1
REPEATED_ERROR_THRESHOLD = 5

# Severity sets used by the two severity-axis signals — see module
# docstring's "Severity semantics" section for why these two sets differ.
_HIGH_ERROR_RATE_SEVERITIES = {
    NginxErrorSeverity.ERROR,
    NginxErrorSeverity.CRIT,
    NginxErrorSeverity.ALERT,
    NginxErrorSeverity.EMERG,
}
_CRITICAL_SEVERITIES = {
    NginxErrorSeverity.CRIT,
    NginxErrorSeverity.ALERT,
    NginxErrorSeverity.EMERG,
}


@dataclass(frozen=True)
class NginxErrorSignal:
    """One detected pattern. Signal is a fact ("this pattern was found"),
    not an interpretation — severity/interpretation belongs to Findings.

    message_key is populated only for REPEATED_ERROR (the normalized
    message that identifies the group); None for HIGH_ERROR_RATE and
    CRITICAL_ERROR, which are not keyed by message.

    raw_evidence contains every event that produced THIS signal — no
    truncation. event_count == len(raw_evidence) always holds.
    """

    signal_type: NginxErrorSignalType
    message_key: str | None
    event_count: int
    raw_evidence: list[NginxErrorEvent]


@dataclass(frozen=True)
class NginxErrorDetectionResult:
    """Top-level Detection output for one collected error-log slice."""

    coverage: CoverageStatus
    detection_succeeded: bool
    signals: list[NginxErrorSignal]


def normalize_message(message: str | None) -> str | None:
    """Normalizes a parsed error message into a REPEATED_ERROR identity
    key. v1 normalization is deliberately minimal: whitespace stripping
    only, no regex/semantic extraction of client:/request:/upstream:
    fields. Returns None when there is no message to key on (e.g. an
    UNKNOWN event), so the caller can treat that event as not
    participating in REPEATED_ERROR aggregation.
    """
    if message is None:
        return None
    return message.strip()


def _high_error_rate_signal(parsed_events: list[NginxErrorEvent]) -> list[NginxErrorSignal]:
    """HIGH_ERROR_RATE: slice-wide count of severity in
    {error, crit, alert, emerg}. At most one aggregate signal."""
    matching = [e for e in parsed_events if e.severity in _HIGH_ERROR_RATE_SEVERITIES]
    if len(matching) >= HIGH_ERROR_RATE_THRESHOLD:
        return [
            NginxErrorSignal(
                signal_type=NginxErrorSignalType.HIGH_ERROR_RATE,
                message_key=None,
                event_count=len(matching),
                raw_evidence=matching,
            )
        ]
    return []


def _critical_error_signal(parsed_events: list[NginxErrorEvent]) -> list[NginxErrorSignal]:
    """CRITICAL_ERROR: slice-wide count of severity in
    {crit, alert, emerg}. At most one aggregate signal, threshold=1."""
    matching = [e for e in parsed_events if e.severity in _CRITICAL_SEVERITIES]
    if len(matching) >= CRITICAL_ERROR_THRESHOLD:
        return [
            NginxErrorSignal(
                signal_type=NginxErrorSignalType.CRITICAL_ERROR,
                message_key=None,
                event_count=len(matching),
                raw_evidence=matching,
            )
        ]
    return []


def _repeated_error_signals(parsed_events: list[NginxErrorEvent]) -> list[NginxErrorSignal]:
    """REPEATED_ERROR: exact-match on normalize_message(), one signal per
    message-key reaching the threshold. Events with no message (or a
    message that normalizes to None) do not participate."""
    by_key: dict[str, list[NginxErrorEvent]] = defaultdict(list)
    for e in parsed_events:
        key = normalize_message(e.message)
        if key is None:
            continue
        by_key[key].append(e)

    signals = []
    for key, matching in by_key.items():
        if len(matching) >= REPEATED_ERROR_THRESHOLD:
            signals.append(
                NginxErrorSignal(
                    signal_type=NginxErrorSignalType.REPEATED_ERROR,
                    message_key=key,
                    event_count=len(matching),
                    raw_evidence=matching,
                )
            )
    return signals


def detect_error_signals(
    events: list[NginxErrorEvent],
    coverage: CoverageStatus,
) -> NginxErrorDetectionResult:
    """Runs all three Error Detection v1 rules over `events`, given the
    already-known `coverage` status from Collection evidence (this
    function does not re-derive coverage itself — that's the caller's
    responsibility, based on CollectionResult/discovery evidence).

    See this module's docstring for the full coverage/detection_succeeded
    interaction table and the per-signal contracts.
    """
    detection_succeeded = coverage in (
        CoverageStatus.COMPLETE,
        CoverageStatus.PARTIAL,
        CoverageStatus.EMPTY,
    )

    if not detection_succeeded:
        return NginxErrorDetectionResult(
            coverage=coverage,
            detection_succeeded=False,
            signals=[],
        )

    parsed_events = [e for e in events if e.event_type == NginxErrorEventType.PARSED]

    signals: list[NginxErrorSignal] = []
    signals.extend(_high_error_rate_signal(parsed_events))
    signals.extend(_critical_error_signal(parsed_events))
    signals.extend(_repeated_error_signals(parsed_events))

    return NginxErrorDetectionResult(
        coverage=coverage,
        detection_succeeded=True,
        signals=signals,
    )
