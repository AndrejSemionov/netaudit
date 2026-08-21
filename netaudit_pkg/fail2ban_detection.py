"""Fail2Ban Log Detection (v1).

Scope v1 (frozen contract, project session notes, 2026-08-21):

Pipeline position: Discovery -> Collection -> Fail2Ban Parser -> Detection
(this module) -> Findings. Detection does NOT search for files, does NOT
re-parse raw lines, does NOT talk to SSH. It receives already-structured
Fail2BanEvent objects plus a CoverageStatus (derived by the caller from
collection/discovery evidence), looks for security-relevant patterns, and
emits Fail2BanSignal objects. Findings (a separate, not-yet-built module)
turns a Signal into a severity-carrying finding — Detection itself never
decides severity.

This module is NOT a mechanical copy of nginx_access_detection.py or
nginx_error_detection.py. fail2ban.log has a fundamentally different
character from nginx logs: fail2ban has ALREADY performed its own
detection (matching a maxretry threshold) before writing a BAN line — the
raw material here is a log of another system's decisions, not raw
request/error traffic that NetAudit must analyze from scratch. This
changes what "signal" even means for this source.

Fail2Ban Detection v1 vs Config/Hardening Audit (explicit scope boundary):
    This module answers "what happened" (Logs Audit question) — did
    fail2ban actually ban anyone. It does NOT answer "is fail2ban
    configured well" (a Hardening/Config Audit question, same split
    already established between Nginx Logs Audit and Nginx Config/
    Hardening Audit as two separate contours in this project).
    JAIL_START_WARNING ("Jail started without 'journalmatch' set...") is
    a performance/config advisory emitted by fail2ban itself, not a
    security event — confirmed via fail2ban community discussion: jails
    without an explicit backend commonly emit this NOTICE as expected
    behavior, not necessarily an operator error, and the warning is
    explicitly about performance, not about missed detections. It is
    OUT OF SCOPE for this module entirely — not even as a low-severity
    signal. If ever addressed, it belongs in a future, separate
    Fail2Ban config/hardening contour, not here.

Fail2BanSignalType v1 (ONE value — deliberately minimal):
    BAN   the only security-relevant, non-reversible fact in fail2ban.log:
          fail2ban itself decided an IP crossed its threshold and blocked it.

Explicitly NOT signals in v1 (each independently reasoned, not a blanket
"everything else is noise" decision):
    FOUND
        fail2ban's own internal pre-ban signal (retry counter towards
        maxretry). If Detection independently counted/rate-tracked FOUND
        events, it would be re-implementing fail2ban's own maxretry logic
        on top of fail2ban — explicitly rejected. FOUND events are still
        parsed and available as raw evidence/data; they simply do not
        drive any v1 Detection signal.
    UNBAN
        expected lifecycle event (ban expired) — not evidence of a new
        problem.
    RESTORE_BAN
        operational lifecycle event (fail2ban restart persistence) — not
        a new attack signal.
    FLUSH
        operational event (fail2ban jail reload/restart) — not about
        attacker behavior.
    JAIL_START_WARNING
        config/performance advisory — see scope boundary above.
    UNKNOWN_MESSAGE
        parser diagnostic only (fail2ban wrote a message type not yet
        recognized) — participates in neither BAN nor any future
        parse-failure-rate signal in v1 (no such signal exists yet for
        this source; unlike nginx Detection's HIGH_PARSE_FAILURE_RATE,
        this is deliberately not yet built here — no case has
        demonstrated it's needed).
    UNKNOWN (envelope-level parse failure)
        same as above — diagnostic only, not a security signal.

BAN signal aggregation (the most consequential decision in this
contract — deliberately the simplest possible model, explicitly NOT
slice-wide aggregation like nginx's CRITICAL_ERROR):
    Each BAN event maps to exactly ONE Fail2BanSignal. There is no
    slice-wide aggregation, no grouping by IP, no time-window counting,
    no rate calculation, no correlation with a preceding FOUND, no
    deduplication of repeat offenders. A slice with 5 independent Ban
    events yields 5 independent Fail2BanSignal objects, not one signal
    with event_count=5 — aggregating would erase which specific IP/jail
    was banned, the single most useful piece of information for the
    person reading a Finding. Repeat-offender detection (the same IP
    banned multiple times in one slice) is an explicitly deferred v2+
    idea, not part of this contract.

Invariant for every Fail2BanSignal, no exceptions: event_count ==
len(raw_evidence) == 1 (always exactly one event, since there is no
aggregation in v1).

Coverage semantics — structurally identical to nginx Detection's model,
but NOT the same shared code/enum (independent module by design, same
"wait for a second/third real case before generalizing" principle
already applied between nginx_access_detection.py and
nginx_error_detection.py):
    CoverageStatus: COMPLETE / PARTIAL / EMPTY / FAILED / UNKNOWN
    detection_succeeded: COMPLETE/PARTIAL/EMPTY -> True, FAILED/UNKNOWN -> False
EMPTY means strictly "0 parsed events in the input" — NOT "no BAN events
found". A slice with 100 FOUND events and zero BAN events is
coverage=COMPLETE, detection_succeeded=True, signals=[] — the file was
fully analyzed, fail2ban never actually banned anyone in this slice.
detection_succeeded=True does NOT mean "a security issue was found"; it
means "Detection ran to completion over the available data".

This module is independent from nginx_access_detection.py,
nginx_error_detection.py, and ssh_auth_detection.py by design — no
shared code assumed until a second/third real case demonstrates the
same abstraction is warranted.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from netaudit_pkg.fail2ban_parser import Fail2BanEvent, Fail2BanEventType


class CoverageStatus(Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    EMPTY = "empty"
    FAILED = "failed"
    UNKNOWN = "unknown"


class Fail2BanSignalType(Enum):
    BAN = "ban"


@dataclass(frozen=True)
class Fail2BanSignal:
    """One detected security-relevant fact. Signal is a fact ("fail2ban
    banned this IP"), not an interpretation — severity/interpretation
    belongs to Findings.

    v1 has exactly one signal per BAN event: event_count is always 1,
    raw_evidence always contains exactly that one Fail2BanEvent.
    """

    signal_type: Fail2BanSignalType
    event_count: int
    raw_evidence: list[Fail2BanEvent]


@dataclass(frozen=True)
class Fail2BanDetectionResult:
    """Top-level Detection output for one collected fail2ban.log slice."""

    coverage: CoverageStatus
    detection_succeeded: bool
    signals: list[Fail2BanSignal]


def detect_fail2ban_signals(
    events: list[Fail2BanEvent],
    coverage: CoverageStatus,
) -> Fail2BanDetectionResult:
    """Runs Fail2Ban Detection v1 over `events`, given the already-known
    `coverage` status from Collection evidence (this function does not
    re-derive coverage itself — that's the caller's responsibility,
    based on CollectionResult/discovery evidence).

    See this module's docstring for the full coverage/detection_succeeded
    interaction table and the BAN-only signal contract.
    """
    detection_succeeded = coverage in (
        CoverageStatus.COMPLETE,
        CoverageStatus.PARTIAL,
        CoverageStatus.EMPTY,
    )

    if not detection_succeeded:
        return Fail2BanDetectionResult(
            coverage=coverage,
            detection_succeeded=False,
            signals=[],
        )

    signals = [
        Fail2BanSignal(
            signal_type=Fail2BanSignalType.BAN,
            event_count=1,
            raw_evidence=[event],
        )
        for event in events
        if event.event_type == Fail2BanEventType.BAN
    ]

    return Fail2BanDetectionResult(
        coverage=coverage,
        detection_succeeded=True,
        signals=signals,
    )
