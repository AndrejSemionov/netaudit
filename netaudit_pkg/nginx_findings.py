"""Nginx Logs Audit — Findings (v1).

Scope v1 (frozen contract):

Pipeline position: Detection (Access/Error) -> Findings (this module) ->
@register orchestration. Findings does NOT re-derive facts Detection
already established — it interprets already-computed Signal objects into
severity/detail/recommendation. Findings never re-parses raw lines,
re-runs threshold logic, or talks to SSH.

Signal vs Finding (the central boundary of this module):
    Signal  = "this pattern was found" (a fact, produced by Detection)
    Finding = "how important this is and what to do" (an interpretation:
              severity + detail + recommendation), produced by this module
Detection signals do NOT know their own severity — Findings assigns it.

Two independent builder functions, NOT one combined function:
    build_access_findings(access_result: NginxAccessDetectionResult) -> list[Finding]
    build_error_findings(error_result: NginxErrorDetectionResult) -> list[Finding]
Orchestration combines them with a plain list-spread
(`[*build_access_findings(a), *build_error_findings(e)]`) — no
merge_findings() exists for this. Access and Error remain independent
contours, each with its own CoverageStatus; a builder does not need to
know the other source of signals exists. This also keeps future
expansion (e.g. an Apache access log contour) from requiring a change to
a shared function's signature.

Signal -> Finding mapping: exactly ONE Finding INSTANCE per Signal
INSTANCE, with no exceptions. REPEATED_ERROR in particular can produce
several independent signals in one run (one per "hot" message key) — that
yields the same number of independent Findings, never aggregated into one.

Severity is STATIC per signal_type — it does NOT depend on event_count.
event_count describes the *scale* of an already-triggered rule, not a new
degree of severity (10x404 and 500x404 both mean "anomalously many 4xx",
just at different scale — the scale stays in event_count/detail, not in
severity). This is a deliberate departure from SSH's count-based
escalation model. severity and confidence are independent axes.

Four severity levels only: info / low / medium / high (matching the
scale already used elsewhere in this project — no separate "critical"
level exists just because one signal is named CRITICAL_ERROR).

Static Severity Mapping v1 (7 of 8 Access+Error signal types):
    HIGH_4XX_RATE    -> low     (client-side noise: bots/typos, not proven attack)
    HIGH_5XX_RATE    -> medium  (server-side instability, a real problem)
    PATH_SCAN        -> medium  (directed scanning pattern, stronger than
                                  a single HIGH_4XX_RATE, but no confirmed
                                  attack success)
    REQUEST_BURST    -> low     (can be legitimate: browser retries, a crawler)
    HIGH_ERROR_RATE  -> medium  (analogous to HIGH_5XX_RATE)
    CRITICAL_ERROR   -> high    (nginx itself classified the event as
                                  crit/alert/emerg — not our heuristic)
    REPEATED_ERROR   -> medium  (a recurring systemic pattern; the nature
                                  of the underlying error is not classified
                                  in v1, so it does not warrant high)

HIGH_PARSE_FAILURE_RATE is the one signal type that NEVER becomes a
Finding. It remains a Detection Signal, but this module does not route it
into a Finding at all — a parser/coverage-quality signal is a
fundamentally different class of result than a security-relevant Finding
("25% of collected events could not be parsed" is not "there is a
security problem on the server"). Its eventual downstream representation
is a separate, not-yet-designed channel (working name
"CoverageDiagnostic" — the exact shape is intentionally out of scope for
this module and this v1 cycle). build_access_findings() silently skips
HIGH_PARSE_FAILURE_RATE signals rather than converting them.

Detail contract (deterministic, no hedging language like "possibly" or
"may indicate", never attributes cause/intent/attack-type that Detection
did not establish):
    HIGH_4XX_RATE:   "IP {ip} generated {event_count} HTTP 4xx responses in the collected slice (threshold: {threshold})."
    HIGH_5XX_RATE:   "IP {ip} generated {event_count} HTTP 5xx responses in the collected slice (threshold: {threshold})."
    PATH_SCAN:       "IP {ip} requested {distinct_paths_count} distinct paths; {paths_with_404_count} returned HTTP 404 ({ratio:.0%}, threshold: {ratio_threshold:.0%} of {distinct_threshold}+ distinct paths)."
                      ratio/paths_with_404_count are RECOMPUTED here from
                      raw_evidence using the exact same rules Detection
                      used (extract_path() for path identity, status==404
                      for the 404 criterion) — this is a display-only
                      recomputation of a fact Detection already
                      established, not a new decision. The invariant
                      Finding-ratio == Detection-ratio must hold for every
                      PATH_SCAN signal that reaches this builder (Detection
                      would not have emitted the signal otherwise).
    REQUEST_BURST:   "IP {ip} sent {event_count} requests between {window_start} and {window_end} (threshold: {threshold} requests per {window_seconds}s window)."
    HIGH_ERROR_RATE: "{event_count} error-or-higher severity events found in the collected slice (threshold: {threshold})." (no ip field — error.log often carries no client IP)
    CRITICAL_ERROR:  "{event_count} event(s) at crit/alert/emerg severity found in the collected slice." (threshold not mentioned — it's always 1, trivial)
    REPEATED_ERROR:  "The following error message recurred {event_count} times in the collected slice (threshold: {threshold}): \"{message_key}\"" (message_key verbatim, no truncation/redaction/substitution)

Recommendation contract (static per signal_type, never a function of
severity or coverage; never gives a specific remediation command like
"iptables -A ..." or "deny IP ..." — Detection does not know whether an
IP is malicious):
    HIGH_4XX_RATE:   Check the request source and determine whether the numerous 4xx responses are legitimate traffic or warrant rate limiting.
    HIGH_5XX_RATE:   Check the relevant requests and server-side components to determine the cause of the elevated 5xx count.
    PATH_SCAN:       Check the source and requested paths; if scanning is confirmed, consider appropriate access restriction measures.
    REQUEST_BURST:   Check the time window and request source to determine whether the high request rate is legitimate or anomalous.
    HIGH_ERROR_RATE: Check the error.log events in the collected slice and related nginx/application components to determine the cause.
    CRITICAL_ERROR:  Immediately review the relevant crit/alert/emerg events and assess impact on nginx or the served application.
    REPEATED_ERROR:  Investigate the recurring message and related events to determine and resolve the underlying cause.
The "Immediately" wording on CRITICAL_ERROR is tied directly to
signal_type (`if signal_type == CRITICAL_ERROR: ...`), NOT derived from
severity=="high" — deriving urgency from severity would break the
independence of these fields. The urgency reflects that nginx itself
classified the event as crit/alert/emerg, not this module's severity
policy; if the severity mapping for CRITICAL_ERROR ever changes, this
wording must not change automatically as a side effect.

Coverage / confidence contract v1 (final):
    CoverageStatus   detection_succeeded   Finding        confidence
    COMPLETE         True                  created        "high"
    PARTIAL          True                  created        "medium"
    EMPTY            True                  NOT created    n/a
    FAILED           False                 NOT created    n/a
    UNKNOWN          False                 NOT created    n/a
confidence depends ONLY on CoverageStatus, never on parser quality
(UNKNOWN-event ratio) — that question is already covered by the separate
HIGH_PARSE_FAILURE_RATE signal, which this module does not fold into
confidence. A COMPLETE-coverage slice with 25% UNKNOWN parser events and
a valid PATH_SCAN signal from the PARSED events yields a normal
confidence="high" PATH_SCAN Finding; the parser-quality concern is
represented separately, not by degrading this Finding's confidence.

This module is independent from ssh_auth_findings.py by design — no
shared code assumed until a second/third real case demonstrates the same
abstraction is warranted.
"""

from __future__ import annotations

from dataclasses import dataclass

from netaudit_pkg.nginx_access_detection import (
    HIGH_4XX_RATE_THRESHOLD,
    HIGH_5XX_RATE_THRESHOLD,
    PATH_SCAN_404_RATIO_THRESHOLD,
    PATH_SCAN_DISTINCT_PATHS_THRESHOLD,
    REQUEST_BURST_THRESHOLD,
    REQUEST_BURST_WINDOW_SECONDS,
    NginxAccessDetectionResult,
    NginxAccessSignal,
    NginxAccessSignalType,
    extract_path,
)
from netaudit_pkg.nginx_access_detection import (
    CoverageStatus as AccessCoverageStatus,
)
from netaudit_pkg.nginx_access_parser import NginxAccessEvent
from netaudit_pkg.nginx_error_detection import (
    HIGH_ERROR_RATE_THRESHOLD,
    REPEATED_ERROR_THRESHOLD,
    NginxErrorDetectionResult,
    NginxErrorSignal,
    NginxErrorSignalType,
)
from netaudit_pkg.nginx_error_detection import (
    CoverageStatus as ErrorCoverageStatus,
)


@dataclass(frozen=True)
class Finding:
    """One security-relevant conclusion, produced from exactly one Signal
    instance. severity/detail/recommendation are each independently
    assigned — none is derived from another.

    signal_type is kept on the Finding as a string (the enum's .value) so
    the Finding itself does not need to import both Access and Error
    signal-type enums to be self-describing.
    """

    finding_type: str
    severity: str
    confidence: str
    detail: str
    recommendation: str
    event_count: int
    raw_evidence: list


# ---------------------------------------------------------------------------
# Access Detection -> Finding policy
# ---------------------------------------------------------------------------

_ACCESS_SEVERITY = {
    NginxAccessSignalType.HIGH_4XX_RATE: "low",
    NginxAccessSignalType.HIGH_5XX_RATE: "medium",
    NginxAccessSignalType.PATH_SCAN: "medium",
    NginxAccessSignalType.REQUEST_BURST: "low",
}

_ACCESS_RECOMMENDATION = {
    NginxAccessSignalType.HIGH_4XX_RATE: (
        "Check the request source and determine whether the numerous 4xx "
        "responses are legitimate traffic or warrant rate limiting."
    ),
    NginxAccessSignalType.HIGH_5XX_RATE: (
        "Check the relevant requests and server-side components to "
        "determine the cause of the elevated 5xx count."
    ),
    NginxAccessSignalType.PATH_SCAN: (
        "Check the source and requested paths; if scanning is confirmed, "
        "consider appropriate access restriction measures."
    ),
    NginxAccessSignalType.REQUEST_BURST: (
        "Check the time window and request source to determine whether "
        "the high request rate is legitimate or anomalous."
    ),
}


def _access_confidence(coverage: AccessCoverageStatus) -> str:
    if coverage == AccessCoverageStatus.COMPLETE:
        return "high"
    if coverage == AccessCoverageStatus.PARTIAL:
        return "medium"
    raise ValueError(f"_access_confidence called with non-Finding-producing coverage: {coverage}")


def _high_4xx_detail(signal: NginxAccessSignal) -> str:
    return (
        f"IP {signal.ip} generated {signal.event_count} HTTP 4xx responses "
        f"in the collected slice (threshold: {HIGH_4XX_RATE_THRESHOLD})."
    )


def _high_5xx_detail(signal: NginxAccessSignal) -> str:
    return (
        f"IP {signal.ip} generated {signal.event_count} HTTP 5xx responses "
        f"in the collected slice (threshold: {HIGH_5XX_RATE_THRESHOLD})."
    )


def _path_scan_detail(signal: NginxAccessSignal) -> str:
    # Display-only recomputation of what Detection already established —
    # same rules Detection used (extract_path() for identity, status==404
    # for the criterion). Not a new decision.
    paths: dict[str, list[NginxAccessEvent]] = {}
    for e in signal.raw_evidence:
        path = extract_path(e.request)
        if path is None:
            continue
        paths.setdefault(path, []).append(e)

    distinct_paths_count = len(paths)
    paths_with_404_count = sum(
        1 for evs in paths.values() if any(e.status == 404 for e in evs)
    )
    ratio = paths_with_404_count / distinct_paths_count if distinct_paths_count else 0.0

    return (
        f"IP {signal.ip} requested {distinct_paths_count} distinct paths; "
        f"{paths_with_404_count} returned HTTP 404 ({ratio:.0%}, threshold: "
        f"{PATH_SCAN_404_RATIO_THRESHOLD:.0%} of {PATH_SCAN_DISTINCT_PATHS_THRESHOLD}+ "
        f"distinct paths)."
    )


def _request_burst_detail(signal: NginxAccessSignal) -> str:
    return (
        f"IP {signal.ip} sent {signal.event_count} requests between "
        f"{signal.window_start} and {signal.window_end} (threshold: "
        f"{REQUEST_BURST_THRESHOLD} requests per {REQUEST_BURST_WINDOW_SECONDS}s window)."
    )


_ACCESS_DETAIL_BUILDERS = {
    NginxAccessSignalType.HIGH_4XX_RATE: _high_4xx_detail,
    NginxAccessSignalType.HIGH_5XX_RATE: _high_5xx_detail,
    NginxAccessSignalType.PATH_SCAN: _path_scan_detail,
    NginxAccessSignalType.REQUEST_BURST: _request_burst_detail,
}


def build_access_findings(access_result: NginxAccessDetectionResult) -> list[Finding]:
    """Builds Findings from an Access Detection result. HIGH_PARSE_FAILURE_RATE
    signals are silently skipped — they never become a Finding (see this
    module's docstring). Returns [] when access_result.detection_succeeded
    is False or coverage is EMPTY (no signals possible either way).
    """
    if not access_result.detection_succeeded:
        return []
    if access_result.coverage == AccessCoverageStatus.EMPTY:
        return []

    confidence = _access_confidence(access_result.coverage)

    findings = []
    for signal in access_result.signals:
        if signal.signal_type == NginxAccessSignalType.HIGH_PARSE_FAILURE_RATE:
            continue
        detail_fn = _ACCESS_DETAIL_BUILDERS[signal.signal_type]
        findings.append(
            Finding(
                finding_type=signal.signal_type.value,
                severity=_ACCESS_SEVERITY[signal.signal_type],
                confidence=confidence,
                detail=detail_fn(signal),
                recommendation=_ACCESS_RECOMMENDATION[signal.signal_type],
                event_count=signal.event_count,
                raw_evidence=signal.raw_evidence,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Error Detection -> Finding policy
# ---------------------------------------------------------------------------

_ERROR_SEVERITY = {
    NginxErrorSignalType.HIGH_ERROR_RATE: "medium",
    NginxErrorSignalType.CRITICAL_ERROR: "high",
    NginxErrorSignalType.REPEATED_ERROR: "medium",
}

_ERROR_RECOMMENDATION = {
    NginxErrorSignalType.HIGH_ERROR_RATE: (
        "Check the error.log events in the collected slice and related "
        "nginx/application components to determine the cause."
    ),
    NginxErrorSignalType.CRITICAL_ERROR: (
        "Immediately review the relevant crit/alert/emerg events and "
        "assess impact on nginx or the served application."
    ),
    NginxErrorSignalType.REPEATED_ERROR: (
        "Investigate the recurring message and related events to "
        "determine and resolve the underlying cause."
    ),
}


def _error_confidence(coverage: ErrorCoverageStatus) -> str:
    if coverage == ErrorCoverageStatus.COMPLETE:
        return "high"
    if coverage == ErrorCoverageStatus.PARTIAL:
        return "medium"
    raise ValueError(f"_error_confidence called with non-Finding-producing coverage: {coverage}")


def _high_error_rate_detail(signal: NginxErrorSignal) -> str:
    return (
        f"{signal.event_count} error-or-higher severity events found in "
        f"the collected slice (threshold: {HIGH_ERROR_RATE_THRESHOLD})."
    )


def _critical_error_detail(signal: NginxErrorSignal) -> str:
    return (
        f"{signal.event_count} event(s) at crit/alert/emerg severity "
        f"found in the collected slice."
    )


def _repeated_error_detail(signal: NginxErrorSignal) -> str:
    return (
        f'The following error message recurred {signal.event_count} times '
        f'in the collected slice (threshold: {REPEATED_ERROR_THRESHOLD}): '
        f'"{signal.message_key}"'
    )


_ERROR_DETAIL_BUILDERS = {
    NginxErrorSignalType.HIGH_ERROR_RATE: _high_error_rate_detail,
    NginxErrorSignalType.CRITICAL_ERROR: _critical_error_detail,
    NginxErrorSignalType.REPEATED_ERROR: _repeated_error_detail,
}


def build_error_findings(error_result: NginxErrorDetectionResult) -> list[Finding]:
    """Builds Findings from an Error Detection result. Every
    NginxErrorSignalType maps to a Finding (unlike Access Detection, Error
    Detection has no parser-quality signal to exclude).
    """
    if not error_result.detection_succeeded:
        return []
    if error_result.coverage == ErrorCoverageStatus.EMPTY:
        return []

    confidence = _error_confidence(error_result.coverage)

    findings = []
    for signal in error_result.signals:
        detail_fn = _ERROR_DETAIL_BUILDERS[signal.signal_type]
        findings.append(
            Finding(
                finding_type=signal.signal_type.value,
                severity=_ERROR_SEVERITY[signal.signal_type],
                confidence=confidence,
                detail=detail_fn(signal),
                recommendation=_ERROR_RECOMMENDATION[signal.signal_type],
                event_count=signal.event_count,
                raw_evidence=signal.raw_evidence,
            )
        )
    return findings
