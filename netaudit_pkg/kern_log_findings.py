"""Kernel Log Findings (v1) — HIGH_DROP_RATE + PORT_SCAN.

Scope v1 (frozen contract, project session notes, 2026-08-21):

Pipeline position: Kern Log Detection -> Findings (this module) ->
@register orchestration. Findings does NOT re-derive facts Detection
already established — it interprets already-computed KernLogSignal
objects into severity/detail/recommendation. Findings never re-parses
raw lines, re-runs threshold logic, or talks to SSH.

Signal vs Finding (same boundary as nginx_findings.py / fail2ban_findings.py):
    Signal  = "this src_ip crossed this threshold" (a fact, produced by
              Detection)
    Finding = "how important this is and what to do" (an interpretation:
              severity + detail + recommendation), produced by this module

Signal -> Finding mapping: exactly ONE Finding INSTANCE per KernLogSignal
INSTANCE, no exceptions — same 1:1 principle as nginx_findings.py and
fail2ban_findings.py. A src_ip that triggers BOTH HIGH_DROP_RATE and
PORT_SCAN produces TWO independent Findings (different severities), not
one merged Finding — same "signals never merge" discipline already
applied to nginx (e.g. an IP that is both HIGH_4XX_RATE and PATH_SCAN
gets two separate Findings there too).

This module is NOT a mechanical copy of fail2ban_findings.py. kern.log's
signals are Detection's OWN interpretation of raw, undigested packet-drop
data (no other system's verdict is being recorded) — the same character
as nginx's Access Detection signals, not fail2ban's single BAN verdict.
Accordingly, severity/recommendation review here follows the nginx
Access Findings precedent (HIGH_4XX_RATE / PATH_SCAN), not fail2ban's.

Severity (frozen, individually reviewed per signal_type, NOT copied
mechanically — each has its own precedent):
    HIGH_DROP_RATE -> low
        Precedent: nginx HIGH_4XX_RATE = low ("client-side noise:
        bots/typos, not proven attack"). A high volume of dropped
        packets from one src_ip is, by itself, exactly this class of
        signal — real observed data (writer, 46.62.147.41) shows 679
        distinct src_ip in one collection window, median=1 hit each;
        even the top offender (307 drops) does not by itself prove
        malicious intent, only elevated attempt frequency. Volume alone
        is the weakest of the two v1 signals.
    PORT_SCAN -> medium
        Precedent: nginx PATH_SCAN = medium ("directed scanning
        pattern, stronger than a single HIGH_4XX_RATE, but no confirmed
        attack success"). One src_ip systematically probing many
        DISTINCT destination ports is a structured, directed pattern —
        stronger evidence of intent than raw volume — but still no
        confirmation the attacker found anything exploitable. Mirrors
        exactly why PATH_SCAN outranks HIGH_4XX_RATE in the nginx
        contour: cardinality-of-distinct-targets is a stronger signal
        than raw event count.
    Severity is NEVER a function of event_count — a HIGH_DROP_RATE
    signal with event_count=10 (at the threshold) and one with
    event_count=307 (real observed extreme) both produce severity=low
    Findings; the magnitude is visible in the detail text, not encoded
    into severity.

Confidence (frozen, identical model to nginx_findings.py and
fail2ban_findings.py, NOT shared code — independent copy in this module):
    CoverageStatus   detection_succeeded   Finding        confidence
    COMPLETE         True                  created        "high"
    PARTIAL          True                  created        "medium"
    EMPTY            True                  NOT created    n/a (EMPTY
                                              coverage means 0 parsed
                                              events, and a signal can
                                              never exist over zero
                                              events by construction —
                                              this module does not
                                              special-case it, it simply
                                              has zero signals to iterate)
    FAILED           False                 NOT created    n/a
    UNKNOWN          False                 NOT created    n/a

Detail contract (deterministic, no hedging language, threshold values
imported directly from kern_log_detection.py — never hardcoded here,
so a future threshold change cannot silently desync detail text from
the actual rule that fired):
    HIGH_DROP_RATE: "IP {src_ip} generated {event_count} dropped packets
        in the collected slice (threshold: {threshold})."
    PORT_SCAN:      "IP {src_ip} attempted {event_count} distinct
        destination ports in the collected slice (threshold:
        {threshold})."
event_count comes directly from the signal (already the correct
semantics per signal_type — raw count for HIGH_DROP_RATE, distinct-port
cardinality for PORT_SCAN; this module does not recompute either, it
trusts Detection's own event_count field, unlike nginx's PATH_SCAN
Finding which recomputes a ratio from raw_evidence — kern_log's
signals carry no derived ratio, only a plain count, so there is nothing
to recompute here).

Recommendation contract (static per signal_type, single fixed string
each — dict lookup, never a function of severity or coverage; never
gives a specific firewall command like "nft add rule ... drop" or "block
IP ..." — Detection does not know whether a src_ip is malicious, only
that it crossed a threshold):
    HIGH_DROP_RATE: "Check the source IP and determine whether the
        elevated drop count reflects routine internet background
        scanning or warrants closer investigation."
        Deliberately NOT phrased as nginx HIGH_4XX_RATE's "...warrant
        rate limiting" — the packets are already being dropped by the
        firewall; "rate limiting" is not a meaningful next action here
        the way it is for an nginx request stream. The wording stays
        as uncertain as the severity itself: it does not assert the
        src_ip is attacking, only that the pattern is worth a look.
    PORT_SCAN: "Check the source IP and targeted ports; if a scanning
        pattern is confirmed, consider appropriate access restriction
        measures."
        Deliberately echoes nginx PATH_SCAN's wording almost verbatim
        ("if scanning is confirmed, consider appropriate access
        restriction measures") — same semantic shape (directed
        scanning pattern, no confirmed attack success), so the same
        recommendation language applies by the same reasoning, not
        reused merely for consistency's sake.

This module is independent from nginx_findings.py and
fail2ban_findings.py by design — no shared code assumed until a
second/third real case demonstrates the same abstraction is warranted.
"""

from __future__ import annotations

from dataclasses import dataclass

from netaudit_pkg.kern_log_detection import (
    HIGH_DROP_RATE_THRESHOLD,
    PORT_SCAN_DISTINCT_PORTS_THRESHOLD,
    CoverageStatus,
    KernLogDetectionResult,
    KernLogSignalType,
)


@dataclass(frozen=True)
class Finding:
    """One security-relevant conclusion, produced from exactly one
    KernLogSignal instance. severity/detail/recommendation are each
    independently assigned — none is derived from another.

    finding_type is kept as a string (mirroring nginx_findings.Finding
    and fail2ban_findings.Finding) so the Finding itself is
    self-describing without importing the signal-type enum.
    """

    finding_type: str
    severity: str
    confidence: str
    detail: str
    recommendation: str
    event_count: int
    raw_evidence: list


_RECOMMENDATIONS = {
    KernLogSignalType.HIGH_DROP_RATE: (
        "Check the source IP and determine whether the elevated drop "
        "count reflects routine internet background scanning or "
        "warrants closer investigation."
    ),
    KernLogSignalType.PORT_SCAN: (
        "Check the source IP and targeted ports; if a scanning pattern "
        "is confirmed, consider appropriate access restriction measures."
    ),
}

_SEVERITIES = {
    KernLogSignalType.HIGH_DROP_RATE: "low",
    KernLogSignalType.PORT_SCAN: "medium",
}


def _confidence(coverage: CoverageStatus) -> str:
    if coverage == CoverageStatus.COMPLETE:
        return "high"
    if coverage == CoverageStatus.PARTIAL:
        return "medium"
    raise ValueError(f"_confidence called with non-Finding-producing coverage: {coverage}")


def build_kern_log_findings(detection_result: KernLogDetectionResult) -> list[Finding]:
    """Builds Findings from a KernLogDetectionResult.

    Returns [] when detection_result.detection_succeeded is False
    (coverage FAILED/UNKNOWN) — Findings never fabricates a result over
    data Detection itself did not successfully process. Also naturally
    returns [] when there are simply no signals (e.g. coverage=EMPTY, or
    COMPLETE/PARTIAL coverage with no src_ip crossing either threshold).
    """
    if not detection_result.detection_succeeded:
        return []

    if not detection_result.signals:
        return []

    confidence = _confidence(detection_result.coverage)
    threshold_by_type = {
        KernLogSignalType.HIGH_DROP_RATE: HIGH_DROP_RATE_THRESHOLD,
        KernLogSignalType.PORT_SCAN: PORT_SCAN_DISTINCT_PORTS_THRESHOLD,
    }

    findings = []
    for signal in detection_result.signals:
        threshold = threshold_by_type[signal.signal_type]
        if signal.signal_type == KernLogSignalType.HIGH_DROP_RATE:
            detail = (
                f"IP {signal.src_ip} generated {signal.event_count} dropped "
                f"packets in the collected slice (threshold: {threshold})."
            )
        else:
            detail = (
                f"IP {signal.src_ip} attempted {signal.event_count} distinct "
                f"destination ports in the collected slice (threshold: {threshold})."
            )

        findings.append(
            Finding(
                finding_type=signal.signal_type.value,
                severity=_SEVERITIES[signal.signal_type],
                confidence=confidence,
                detail=detail,
                recommendation=_RECOMMENDATIONS[signal.signal_type],
                event_count=signal.event_count,
                raw_evidence=signal.raw_evidence,
            )
        )
    return findings
