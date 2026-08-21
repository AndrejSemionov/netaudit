"""RED tests for fail2ban_findings.py — Fail2Ban Findings Contract v1.

Scenario table (frozen contract, project session notes, 2026-08-21):

Group A — BAN signal -> Finding
  A1. one BanSignal, coverage=COMPLETE   -> 1 Finding, severity=high, confidence=high
  A2. one BanSignal, coverage=PARTIAL    -> 1 Finding, confidence=medium
  A3. several BanSignals                  -> N independent Findings (1:1)
  A4. detail contains correct ip/jail from evidence
  A5. recommendation is fixed text, independent of event_count/coverage

Group B — coverage without Finding
  B1. detection_succeeded=False (coverage=FAILED)   -> [] Findings, even if signals were present
  B2. detection_succeeded=False (coverage=UNKNOWN)  -> []
  B3. coverage=EMPTY, signals=[]                     -> [] (naturally, no BAN signal existed)

Group C — invariants
  C1. finding.event_count == len(finding.raw_evidence) == 1
  C2. Finding order matches signal order

This gives 15+ concrete assertions across the parametrized cases below.
"""

from __future__ import annotations

from datetime import datetime, timezone

from netaudit_pkg.fail2ban_detection import (
    CoverageStatus,
    Fail2BanDetectionResult,
    Fail2BanSignal,
    Fail2BanSignalType,
)
from netaudit_pkg.fail2ban_findings import build_fail2ban_findings
from netaudit_pkg.fail2ban_parser import Fail2BanEvent, Fail2BanEventType

_TS = datetime(2026, 8, 21, 12, 0, 0, tzinfo=timezone.utc)


def _ban_event(ip: str, jail: str) -> Fail2BanEvent:
    return Fail2BanEvent(
        event_type=Fail2BanEventType.BAN,
        timestamp=_TS,
        logger="fail2ban.actions",
        pid=12345,
        level="NOTICE",
        jail=jail,
        message=f"Ban {ip}",
        ip=ip,
        matched_timestamp=None,
        raw_line=f"synthetic ban {ip} {jail}",
    )


def _ban_signal(ip: str, jail: str) -> Fail2BanSignal:
    event = _ban_event(ip, jail)
    return Fail2BanSignal(
        signal_type=Fail2BanSignalType.BAN,
        event_count=1,
        raw_evidence=[event],
    )


# ---------------------------------------------------------------------------
# Group A — BAN signal -> Finding
# ---------------------------------------------------------------------------


def test_a1_one_ban_signal_complete_coverage_produces_high_severity_finding():
    signal = _ban_signal("1.2.3.4", "sshd")
    result = Fail2BanDetectionResult(
        coverage=CoverageStatus.COMPLETE,
        detection_succeeded=True,
        signals=[signal],
    )
    findings = build_fail2ban_findings(result)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].confidence == "high"


def test_a2_partial_coverage_produces_medium_confidence():
    signal = _ban_signal("1.2.3.4", "sshd")
    result = Fail2BanDetectionResult(
        coverage=CoverageStatus.PARTIAL,
        detection_succeeded=True,
        signals=[signal],
    )
    findings = build_fail2ban_findings(result)
    assert len(findings) == 1
    assert findings[0].confidence == "medium"


def test_a3_several_ban_signals_produce_independent_findings():
    signals = [
        _ban_signal("1.1.1.1", "sshd"),
        _ban_signal("2.2.2.2", "sshd-ddos"),
        _ban_signal("3.3.3.3", "nginx-http-auth"),
    ]
    result = Fail2BanDetectionResult(
        coverage=CoverageStatus.COMPLETE,
        detection_succeeded=True,
        signals=signals,
    )
    findings = build_fail2ban_findings(result)
    assert len(findings) == 3
    for finding in findings:
        assert finding.severity == "high"


def test_a4_detail_contains_ip_and_jail_from_evidence():
    signal = _ban_signal("203.0.113.7", "nginx-http-auth")
    result = Fail2BanDetectionResult(
        coverage=CoverageStatus.COMPLETE,
        detection_succeeded=True,
        signals=[signal],
    )
    findings = build_fail2ban_findings(result)
    assert "203.0.113.7" in findings[0].detail
    assert "nginx-http-auth" in findings[0].detail


def test_a5_recommendation_is_fixed_text():
    signal1 = _ban_signal("1.1.1.1", "sshd")
    signal2 = _ban_signal("2.2.2.2", "sshd")
    result = Fail2BanDetectionResult(
        coverage=CoverageStatus.COMPLETE,
        detection_succeeded=True,
        signals=[signal1, signal2],
    )
    findings = build_fail2ban_findings(result)
    assert findings[0].recommendation == findings[1].recommendation
    assert "repeat offender" in findings[0].recommendation


# ---------------------------------------------------------------------------
# Group B — coverage without Finding
# ---------------------------------------------------------------------------


def test_b1_failed_coverage_produces_no_findings():
    # Even if a signal were somehow present, FAILED coverage never
    # produces a Finding — Findings trusts detection_succeeded, not
    # the mere presence of signals.
    signal = _ban_signal("1.2.3.4", "sshd")
    result = Fail2BanDetectionResult(
        coverage=CoverageStatus.FAILED,
        detection_succeeded=False,
        signals=[signal],
    )
    findings = build_fail2ban_findings(result)
    assert findings == []


def test_b2_unknown_coverage_produces_no_findings():
    result = Fail2BanDetectionResult(
        coverage=CoverageStatus.UNKNOWN,
        detection_succeeded=False,
        signals=[],
    )
    findings = build_fail2ban_findings(result)
    assert findings == []


def test_b3_empty_coverage_no_signals_produces_no_findings():
    result = Fail2BanDetectionResult(
        coverage=CoverageStatus.EMPTY,
        detection_succeeded=True,
        signals=[],
    )
    findings = build_fail2ban_findings(result)
    assert findings == []


# ---------------------------------------------------------------------------
# Group C — invariants
# ---------------------------------------------------------------------------


def test_c1_event_count_equals_raw_evidence_length():
    signal = _ban_signal("1.2.3.4", "sshd")
    result = Fail2BanDetectionResult(
        coverage=CoverageStatus.COMPLETE,
        detection_succeeded=True,
        signals=[signal],
    )
    findings = build_fail2ban_findings(result)
    assert findings[0].event_count == len(findings[0].raw_evidence) == 1


def test_c2_finding_order_matches_signal_order():
    signals = [
        _ban_signal("1.1.1.1", "sshd"),
        _ban_signal("2.2.2.2", "sshd"),
        _ban_signal("3.3.3.3", "sshd"),
    ]
    result = Fail2BanDetectionResult(
        coverage=CoverageStatus.COMPLETE,
        detection_succeeded=True,
        signals=signals,
    )
    findings = build_fail2ban_findings(result)
    ips_in_order = [f.raw_evidence[0].ip for f in findings]
    assert ips_in_order == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
