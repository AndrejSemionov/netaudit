"""Nginx Access Log Detection (v1).

Scope v1 (frozen contract):

Pipeline position: Discovery -> Resolver -> Matching -> Collection ->
Access Parser -> Detection (this module) -> Findings. Detection does NOT
search for files, does NOT understand access_log/error_log inheritance,
does NOT decide the authoritative source, does NOT re-parse raw lines,
and does NOT talk to SSH. It receives already-structured
NginxAccessEvent objects plus a CoverageStatus (derived by the caller
from collection/discovery evidence), looks for patterns, and emits
NginxAccessSignal objects. Findings (a separate, not-yet-built module)
turns a Signal into a severity-carrying finding — Detection itself never
decides severity.

Three independent axes (never conflate):
    Collection coverage  -> CoverageStatus (COMPLETE/PARTIAL/EMPTY/FAILED/UNKNOWN)
    Parser result         -> PARSED/UNKNOWN (NginxAccessEventType, per-line)
    Detection success     -> bool (detection_succeeded)
UNKNOWN parser results do NOT lower Collection coverage — coverage answers
"did we get the data", not "could we parse it". A slice of 200 collected
lines with 150 PARSED + 50 UNKNOWN is still coverage=COMPLETE.

NginxAccessSignalType (5 values):
    HIGH_4XX_RATE            behavioral, per-IP, slice-wide, absolute count
    HIGH_5XX_RATE            behavioral, per-IP, slice-wide, absolute count
    PATH_SCAN                behavioral, per-IP, slice-wide, distinct-path + ratio
    REQUEST_BURST            behavioral, per-IP, windowed (fixed, non-overlapping)
    HIGH_PARSE_FAILURE_RATE  parser-quality, NOT per-IP, slice-wide

UNKNOWN events participate ONLY in HIGH_PARSE_FAILURE_RATE — never in any
of the four behavioral signals (they carry no usable status/ip/path per
the Access Parser Contract: an UNKNOWN NginxAccessEvent has every field
None except event_type and raw_line).

Windowing is a property of the individual rule, not a global Detection
property: HIGH_4XX_RATE/HIGH_5XX_RATE/PATH_SCAN/HIGH_PARSE_FAILURE_RATE
are slice-wide (window_start=window_end=None on their signals);
REQUEST_BURST is the only windowed rule, using a fixed, non-overlapping
window (not sliding — a deliberate v1 simplification for determinism and
testability). One NginxAccessSignal is emitted per qualifying window, not
one aggregated signal for the whole run.

PATH_SCAN path extraction (frozen, lives here in Detection — NOT a Parser
concern, since Parser Contract says "what the line says", Detection says
"how to use the already-parsed `request` field for this rule"):
    request = "METHOD SP REQUEST-TARGET SP HTTP-VERSION"
    path    = second whitespace-separated token, query string (?...) stripped
    method  does NOT participate in path identity: GET /foo and POST /foo
            are the SAME distinct path
    malformed/empty/None request -> path unavailable; extract_path() never
            raises; the event simply does not participate in PATH_SCAN
            aggregation

CoverageStatus v1 (5 values, frozen):
    COMPLETE  collection.completed=True, exit_code=0, events>0
    PARTIAL   partial collection — Detection still runs successfully on
              what's available; coverage stays PARTIAL, never silently
              upgraded to COMPLETE
    EMPTY     collection.completed=True, exit_code=0, events=0 (NOT an
              error — a valid "nothing to analyze" outcome)
    FAILED    collection.completed=False or exit_code!=0
    UNKNOWN   insufficient evidence to classify

detection_succeeded / CoverageStatus interaction (frozen):
    COMPLETE -> True   (full analysis of the requested slice)
    PARTIAL  -> True   (Detection successfully analyzed what was available;
                        this is NOT the same as "trust this like COMPLETE" —
                        that confidence judgment belongs to Findings, not
                        Detection)
    EMPTY    -> True   (nothing to analyze, not an error)
    FAILED   -> False  (analysis impossible)
    UNKNOWN  -> False  (insufficient evidence, same distrust level as FAILED)
detection_succeeded=False always means signals=[] — Detection refuses to
fabricate a result when it doesn't have grounds for one.

Numeric thresholds v1 (NetAudit engineering policy — NOT nginx or
external-tool standards; no authoritative external source exists for
these specific values):
    HIGH_4XX_RATE threshold            = 10   (events from one IP)
    HIGH_5XX_RATE threshold            = 5
    PATH_SCAN distinct_paths (D)       = 10
    PATH_SCAN 404_ratio (R)            = 0.80
    REQUEST_BURST window               = 10 seconds
    REQUEST_BURST threshold            = 20  (requests within the window)
    HIGH_PARSE_FAILURE_RATE threshold  = 0.25

This module is independent from ssh_auth_detection.py by design — no
shared code assumed until a second/third real case demonstrates the same
abstraction is warranted.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

from netaudit_pkg.nginx_access_parser import NginxAccessEvent, NginxAccessEventType


class CoverageStatus(Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    EMPTY = "empty"
    FAILED = "failed"
    UNKNOWN = "unknown"


class NginxAccessSignalType(Enum):
    HIGH_4XX_RATE = "high_4xx_rate"
    HIGH_5XX_RATE = "high_5xx_rate"
    PATH_SCAN = "path_scan"
    REQUEST_BURST = "request_burst"
    HIGH_PARSE_FAILURE_RATE = "high_parse_failure_rate"


# Numeric thresholds v1 — see module docstring for provenance/rationale.
HIGH_4XX_RATE_THRESHOLD = 10
HIGH_5XX_RATE_THRESHOLD = 5
PATH_SCAN_DISTINCT_PATHS_THRESHOLD = 10
PATH_SCAN_404_RATIO_THRESHOLD = 0.80
REQUEST_BURST_WINDOW_SECONDS = 10
REQUEST_BURST_THRESHOLD = 20
HIGH_PARSE_FAILURE_RATE_THRESHOLD = 0.25


@dataclass(frozen=True)
class NginxAccessSignal:
    """One detected pattern. Signal is a fact ("this pattern was found"),
    not an interpretation — severity/interpretation belongs to Findings.

    window_start/window_end are None for slice-wide signals (everything
    except REQUEST_BURST); populated only for REQUEST_BURST.

    raw_evidence contains ONLY the events that produced THIS signal — not
    the whole detection run — to avoid unbounded memory growth on real
    logs. For HIGH_PARSE_FAILURE_RATE specifically, raw_evidence contains
    only the UNKNOWN events (never PARSED events — they aren't evidence
    of a parsing failure).
    """

    signal_type: NginxAccessSignalType
    ip: str | None
    event_count: int
    window_start: datetime | None
    window_end: datetime | None
    raw_evidence: list[NginxAccessEvent]


@dataclass(frozen=True)
class NginxAccessDetectionResult:
    """Top-level Detection output for one collected access-log slice."""

    coverage: CoverageStatus
    detection_succeeded: bool
    signals: list[NginxAccessSignal]


def extract_path(request: str | None) -> str | None:
    """Extracts the URI path (no query string) from a combined-log
    `request` field for PATH_SCAN aggregation purposes.

    request = "METHOD SP REQUEST-TARGET SP HTTP-VERSION" -> path is the
    second whitespace-separated token, with any '?...' query string
    stripped. Method does not participate in path identity: GET /foo and
    POST /foo both yield "/foo".

    Never raises. Returns None for malformed/empty/None input — the
    caller must treat that as "this event does not participate in
    PATH_SCAN aggregation", not as an error.
    """
    if not request:
        return None
    parts = request.split()
    if len(parts) < 2:
        return None
    target = parts[1]
    path, _, _query = target.partition("?")
    return path if path else None


def _rate_signals(
    parsed_events: list[NginxAccessEvent],
    signal_type: NginxAccessSignalType,
    status_lo: int,
    status_hi: int,
    threshold: int,
) -> list[NginxAccessSignal]:
    """HIGH_4XX_RATE / HIGH_5XX_RATE: per-IP absolute count of events whose
    status falls in [status_lo, status_hi], slice-wide, no window."""
    by_ip: dict[str, list[NginxAccessEvent]] = defaultdict(list)
    for e in parsed_events:
        if e.remote_addr is None or e.status is None:
            continue
        if status_lo <= e.status <= status_hi:
            by_ip[e.remote_addr].append(e)

    signals = []
    for ip, matching in by_ip.items():
        if len(matching) >= threshold:
            signals.append(
                NginxAccessSignal(
                    signal_type=signal_type,
                    ip=ip,
                    event_count=len(matching),
                    window_start=None,
                    window_end=None,
                    raw_evidence=matching,
                )
            )
    return signals


def _path_scan_signals(parsed_events: list[NginxAccessEvent]) -> list[NginxAccessSignal]:
    """PATH_SCAN: per-IP, distinct-path cardinality + 404-ratio among those
    distinct paths (see extract_path() for path identity rules)."""
    by_ip_paths: dict[str, dict[str, list[NginxAccessEvent]]] = defaultdict(lambda: defaultdict(list))
    for e in parsed_events:
        if e.remote_addr is None:
            continue
        path = extract_path(e.request)
        if path is None:
            continue
        by_ip_paths[e.remote_addr][path].append(e)

    signals = []
    for ip, paths in by_ip_paths.items():
        distinct_paths = list(paths.keys())
        if len(distinct_paths) < PATH_SCAN_DISTINCT_PATHS_THRESHOLD:
            continue
        paths_with_404 = [p for p, evs in paths.items() if any(e.status == 404 for e in evs)]
        ratio = len(paths_with_404) / len(distinct_paths)
        if ratio >= PATH_SCAN_404_RATIO_THRESHOLD:
            evidence = [evs[0] for evs in paths.values()]
            signals.append(
                NginxAccessSignal(
                    signal_type=NginxAccessSignalType.PATH_SCAN,
                    ip=ip,
                    event_count=len(distinct_paths),
                    window_start=None,
                    window_end=None,
                    raw_evidence=evidence,
                )
            )
    return signals


def _request_burst_signals(parsed_events: list[NginxAccessEvent]) -> list[NginxAccessSignal]:
    """REQUEST_BURST: per-IP, fixed non-overlapping window of
    REQUEST_BURST_WINDOW_SECONDS length. One signal per qualifying window,
    not one aggregated signal for the whole slice."""
    timed = [e for e in parsed_events if e.remote_addr is not None and e.timestamp is not None]
    if not timed:
        return []

    epoch = min(e.timestamp for e in timed)
    by_ip_window: dict[tuple[str, int], list[NginxAccessEvent]] = defaultdict(list)
    for e in timed:
        offset_seconds = (e.timestamp - epoch).total_seconds()
        window_index = int(offset_seconds // REQUEST_BURST_WINDOW_SECONDS)
        by_ip_window[(e.remote_addr, window_index)].append(e)

    signals = []
    for (ip, window_index), matching in by_ip_window.items():
        if len(matching) >= REQUEST_BURST_THRESHOLD:
            window_start = epoch + timedelta(seconds=window_index * REQUEST_BURST_WINDOW_SECONDS)
            window_end = epoch + timedelta(seconds=(window_index + 1) * REQUEST_BURST_WINDOW_SECONDS)
            signals.append(
                NginxAccessSignal(
                    signal_type=NginxAccessSignalType.REQUEST_BURST,
                    ip=ip,
                    event_count=len(matching),
                    window_start=window_start,
                    window_end=window_end,
                    raw_evidence=matching,
                )
            )
    return signals


def _parse_failure_signal(all_events: list[NginxAccessEvent]) -> list[NginxAccessSignal]:
    """HIGH_PARSE_FAILURE_RATE: slice-wide, not per-IP. Ratio of UNKNOWN
    events over the total collected slice."""
    total = len(all_events)
    if total == 0:
        return []
    unknown_events = [e for e in all_events if e.event_type == NginxAccessEventType.UNKNOWN]
    ratio = len(unknown_events) / total
    if ratio >= HIGH_PARSE_FAILURE_RATE_THRESHOLD and unknown_events:
        return [
            NginxAccessSignal(
                signal_type=NginxAccessSignalType.HIGH_PARSE_FAILURE_RATE,
                ip=None,
                event_count=len(unknown_events),
                window_start=None,
                window_end=None,
                raw_evidence=unknown_events,
            )
        ]
    return []


def detect_access_signals(
    events: list[NginxAccessEvent],
    coverage: CoverageStatus,
) -> NginxAccessDetectionResult:
    """Runs all five Access Detection v1 rules over `events`, given the
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
        return NginxAccessDetectionResult(
            coverage=coverage,
            detection_succeeded=False,
            signals=[],
        )

    parsed_events = [e for e in events if e.event_type == NginxAccessEventType.PARSED]

    signals: list[NginxAccessSignal] = []
    signals.extend(
        _rate_signals(parsed_events, NginxAccessSignalType.HIGH_4XX_RATE, 400, 499, HIGH_4XX_RATE_THRESHOLD)
    )
    signals.extend(
        _rate_signals(parsed_events, NginxAccessSignalType.HIGH_5XX_RATE, 500, 599, HIGH_5XX_RATE_THRESHOLD)
    )
    signals.extend(_path_scan_signals(parsed_events))
    signals.extend(_request_burst_signals(parsed_events))
    signals.extend(_parse_failure_signal(events))

    return NginxAccessDetectionResult(
        coverage=coverage,
        detection_succeeded=True,
        signals=signals,
    )
