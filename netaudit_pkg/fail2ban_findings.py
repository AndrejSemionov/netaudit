"""Fail2Ban Log Findings (v1).

Scope v1 (frozen contract, project session notes, 2026-08-21):

Pipeline position: Fail2Ban Detection -> Findings (this module) ->
@register orchestration. Findings does NOT re-derive facts Detection
already established — it interprets already-computed Fail2BanSignal
objects into severity/detail/recommendation. Findings never re-parses
raw lines, re-runs threshold logic, or talks to SSH.

Signal vs Finding (same boundary as nginx_findings.py):
    Signal  = "fail2ban banned this IP" (a fact, produced by Detection)
    Finding = "how important this is and what to do" (an interpretation:
              severity + detail + recommendation), produced by this module

Signal -> Finding mapping: exactly ONE Finding INSTANCE per Fail2BanSignal
INSTANCE, no exceptions — same 1:1 principle as nginx_findings.py. Since
Fail2Ban Detection v1 has exactly one signal type (BAN), this is the
simplest possible builder: one signal_type, one static severity, one
static recommendation, no dict lookup needed.

Severity: STATIC, always "high" — the only value in v1. A BAN event is
not a NetAudit heuristic; fail2ban itself already crossed its own
maxretry threshold and took action. This is the same reasoning nginx
Findings applies to CRITICAL_ERROR="high" ("nginx itself classified the
event... not our heuristic") — Ban <ip> is fail2ban's own confirmed
decision, not our guess. Matches this project's four-level scale
(info/low/medium/high) — no separate "critical" level.

Confidence: depends ONLY on CoverageStatus, identical model to
nginx_findings.py (not shared code — independent module by design, same
principle already applied between nginx and fail2ban's parallel-but-
separate CoverageStatus enums):
    CoverageStatus   detection_succeeded   Finding        confidence
    COMPLETE         True                  created        "high"
    PARTIAL          True                  created        "medium"
    EMPTY            True                  NOT created    n/a (no BAN
                                              signal exists in an EMPTY
                                              slice by construction, but
                                              this module does not special-
                                              case it — it simply has zero
                                              signals to iterate over)
    FAILED           False                 NOT created    n/a
    UNKNOWN          False                 NOT created    n/a

Detail contract (deterministic, no hedging language):
    BAN: "Fail2Ban banned IP {ip} in jail '{jail}' (source: fail2ban.log)."
    ip/jail come directly from the signal's single raw_evidence event —
    no recomputation, no aggregation across signals.

Recommendation contract (static, single fixed string — the only
finding_type in v1 so no dict lookup is needed):
    BAN: "Review the banned IP and jail context; consider permanent
          blocking if this is a repeat offender."
    Deliberately NOT "no action required" — even though Fail2Ban already
    took action automatically, NetAudit still surfaces what happened and
    what to check, rather than implying nothing further is worth a
    look. "consider" (not "must"/"should") — this module does not
    mandate permanent blocking, only flags it as worth considering if
    the IP recurs; repeat-offender detection itself is out of v1 scope
    (see fail2ban_detection.py's docstring on this).

This module is independent from nginx_findings.py and ssh_auth_findings.py
by design — no shared code assumed until a second/third real case
demonstrates the same abstraction is warranted.
"""

from __future__ import annotations

from dataclasses import dataclass

from netaudit_pkg.fail2ban_detection import (
    CoverageStatus,
    Fail2BanDetectionResult,
)


@dataclass(frozen=True)
class Finding:
    """One security-relevant conclusion, produced from exactly one
    Fail2BanSignal instance. severity/detail/recommendation are each
    independently assigned — none is derived from another.

    finding_type is kept as a string (mirroring nginx_findings.Finding)
    so the Finding itself is self-describing without importing the
    signal-type enum.
    """

    finding_type: str
    severity: str
    confidence: str
    detail: str
    recommendation: str
    event_count: int
    raw_evidence: list


_RECOMMENDATION = (
    "Review the banned IP and jail context; consider permanent "
    "blocking if this is a repeat offender."
)


def _confidence(coverage: CoverageStatus) -> str:
    if coverage == CoverageStatus.COMPLETE:
        return "high"
    if coverage == CoverageStatus.PARTIAL:
        return "medium"
    raise ValueError(f"_confidence called with non-Finding-producing coverage: {coverage}")


def build_fail2ban_findings(detection_result: Fail2BanDetectionResult) -> list[Finding]:
    """Builds Findings from a Fail2BanDetectionResult.

    Returns [] when detection_result.detection_succeeded is False
    (coverage FAILED/UNKNOWN) — Findings never fabricates a result over
    data Detection itself did not successfully process. Also naturally
    returns [] when there are simply no BAN signals (e.g. coverage=EMPTY,
    or COMPLETE/PARTIAL coverage with zero bans in the slice).
    """
    if not detection_result.detection_succeeded:
        return []

    if not detection_result.signals:
        return []

    confidence = _confidence(detection_result.coverage)

    findings = []
    for signal in detection_result.signals:
        event = signal.raw_evidence[0]
        findings.append(
            Finding(
                finding_type=signal.signal_type.value,
                severity="high",
                confidence=confidence,
                detail=(
                    f"Fail2Ban banned IP {event.ip} in jail '{event.jail}' "
                    "(source: fail2ban.log)."
                ),
                recommendation=_RECOMMENDATION,
                event_count=signal.event_count,
                raw_evidence=signal.raw_evidence,
            )
        )
    return findings
