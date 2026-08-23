"""RED tests for kern_log_findings.py — Kern Log Findings Contract v1.

Scenario table (frozen contract, project session notes, 2026-08-21):

Group A — HIGH_DROP_RATE signal -> Finding
  A1. one HIGH_DROP_RATE signal, coverage=COMPLETE   -> 1 Finding, severity=low, confidence=high
  A2. one HIGH_DROP_RATE signal, coverage=PARTIAL    -> 1 Finding, confidence=medium
  A3. several HIGH_DROP_RATE signals (different IPs)  -> N independent Findings (1:1)
  A4. detail contains src_ip + event_count + threshold (10)
  A5. recommendation is fixed text

Group B — PORT_SCAN signal -> Finding
  B1. one PORT_SCAN signal, coverage=COMPLETE        -> 1 Finding, severity=medium, confidence=high
  B2. one PORT_SCAN signal, coverage=PARTIAL         -> 1 Finding, confidence=medium
  B3. several PORT_SCAN signals                       -> N independent Findings
  B4. detail contains src_ip + event_count (distinct port count) + threshold (10)
  B5. recommendation is its own fixed text, distinct from HIGH_DROP_RATE's

Group C — both signal types simultaneously
  C1. one src_ip triggers both HIGH_DROP_RATE and PORT_SCAN -> 2 independent Findings (different severities)

Group D — coverage without Finding
  D1. detection_succeeded=False (coverage=FAILED)   -> [] Findings
  D2. detection_succeeded=False (coverage=UNKNOWN)  -> []
  D3. coverage=EMPTY, signals=[]                      -> [] (naturally)

Group E — invariants
  E1. finding.event_count == signal.event_count (passed through, not recomputed)
  E2. finding.severity independent of event_count (10 or 307 — still low for HIGH_DROP_RATE)
  E3. Finding order matches signal order

This gives 15+ concrete assertions across the parametrized cases below.
"""

from __future__ import annotations

from datetime import datetime, timezone

from netaudit_pkg.kern_log_detection import (
    CoverageStatus,
    KernLogDetectionResult,
    KernLogSignal,
    KernLogSignalType,
)
from netaudit_pkg.kern_log_findings import build_kern_log_findings
from netaudit_pkg.kern_log_parser import KernLogEvent, KernLogEventType

_TS = datetime(2026, 8, 21, 12, 0, 0, tzinfo=timezone.utc)


def _dropped_event(src_ip: str, dst_port: int = 22) -> KernLogEvent:
    return KernLogEvent(
        event_type=KernLogEventType.NFT_DROPPED,
        timestamp=_TS,
        hostname="testhost",
        interface_in="eth0",
        interface_out=None,
        mac="00:00:00:00:00:00",
        mac_src=None,
        mac_dst=None,
        mac_proto=None,
        src_ip=src_ip,
        dst_ip="10.0.0.1",
        length=40,
        tos="0x00",
        prec="0x00",
        ttl=64,
        packet_id=1,
        df_flag=False,
        protocol="TCP",
        src_port=12345,
        dst_port=dst_port,
        window=65535,
        res="0x00",
        tcp_flags=["SYN"],
        urgp=0,
        payload_length=None,
        raw_line="synthetic drop event",
    )


def _rate_signal(src_ip: str, event_count: int) -> KernLogSignal:
    evidence = [_dropped_event(src_ip, dst_port=1000 + i) for i in range(event_count)]
    return KernLogSignal(
        signal_type=KernLogSignalType.HIGH_DROP_RATE,
        src_ip=src_ip,
        event_count=event_count,
        raw_evidence=evidence,
    )


def _scan_signal(src_ip: str, distinct_ports: int) -> KernLogSignal:
    evidence = [_dropped_event(src_ip, dst_port=2000 + i) for i in range(distinct_ports)]
    return KernLogSignal(
        signal_type=KernLogSignalType.PORT_SCAN,
        src_ip=src_ip,
        event_count=distinct_ports,
        raw_evidence=evidence,
    )


# ---------------------------------------------------------------------------
# Group A — HIGH_DROP_RATE signal -> Finding
# ---------------------------------------------------------------------------


def test_a1_one_rate_signal_complete_coverage_produces_low_severity_finding():
    signal = _rate_signal("1.2.3.4", 10)
    result = KernLogDetectionResult(
        coverage=CoverageStatus.COMPLETE, detection_succeeded=True, signals=[signal]
    )
    findings = build_kern_log_findings(result)
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert findings[0].confidence == "high"


def test_a2_partial_coverage_produces_medium_confidence():
    signal = _rate_signal("1.2.3.4", 10)
    result = KernLogDetectionResult(
        coverage=CoverageStatus.PARTIAL, detection_succeeded=True, signals=[signal]
    )
    findings = build_kern_log_findings(result)
    assert findings[0].confidence == "medium"


def test_a3_several_rate_signals_produce_independent_findings():
    signals = [
        _rate_signal("1.1.1.1", 10),
        _rate_signal("2.2.2.2", 50),
        _rate_signal("3.3.3.3", 307),
    ]
    result = KernLogDetectionResult(
        coverage=CoverageStatus.COMPLETE, detection_succeeded=True, signals=signals
    )
    findings = build_kern_log_findings(result)
    assert len(findings) == 3
    for f in findings:
        assert f.severity == "low"


def test_a4_detail_contains_src_ip_event_count_and_threshold():
    signal = _rate_signal("203.0.113.7", 42)
    result = KernLogDetectionResult(
        coverage=CoverageStatus.COMPLETE, detection_succeeded=True, signals=[signal]
    )
    findings = build_kern_log_findings(result)
    assert "203.0.113.7" in findings[0].detail
    assert "42" in findings[0].detail
    assert "10" in findings[0].detail  # threshold


def test_a5_recommendation_is_fixed_text():
    signal1 = _rate_signal("1.1.1.1", 10)
    signal2 = _rate_signal("2.2.2.2", 20)
    result = KernLogDetectionResult(
        coverage=CoverageStatus.COMPLETE, detection_succeeded=True, signals=[signal1, signal2]
    )
    findings = build_kern_log_findings(result)
    assert findings[0].recommendation == findings[1].recommendation
    assert "background scanning" in findings[0].recommendation


# ---------------------------------------------------------------------------
# Group B — PORT_SCAN signal -> Finding
# ---------------------------------------------------------------------------


def test_b1_one_scan_signal_complete_coverage_produces_medium_severity_finding():
    signal = _scan_signal("1.2.3.4", 10)
    result = KernLogDetectionResult(
        coverage=CoverageStatus.COMPLETE, detection_succeeded=True, signals=[signal]
    )
    findings = build_kern_log_findings(result)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].confidence == "high"


def test_b2_partial_coverage_produces_medium_confidence():
    signal = _scan_signal("1.2.3.4", 10)
    result = KernLogDetectionResult(
        coverage=CoverageStatus.PARTIAL, detection_succeeded=True, signals=[signal]
    )
    findings = build_kern_log_findings(result)
    assert findings[0].confidence == "medium"


def test_b3_several_scan_signals_produce_independent_findings():
    signals = [_scan_signal("1.1.1.1", 10), _scan_signal("2.2.2.2", 25)]
    result = KernLogDetectionResult(
        coverage=CoverageStatus.COMPLETE, detection_succeeded=True, signals=signals
    )
    findings = build_kern_log_findings(result)
    assert len(findings) == 2
    for f in findings:
        assert f.severity == "medium"


def test_b4_detail_contains_src_ip_distinct_port_count_and_threshold():
    signal = _scan_signal("198.51.100.9", 15)
    result = KernLogDetectionResult(
        coverage=CoverageStatus.COMPLETE, detection_succeeded=True, signals=[signal]
    )
    findings = build_kern_log_findings(result)
    assert "198.51.100.9" in findings[0].detail
    assert "15" in findings[0].detail
    assert "10" in findings[0].detail  # threshold


def test_b5_recommendation_distinct_from_high_drop_rate():
    rate_signal = _rate_signal("1.1.1.1", 10)
    scan_signal = _scan_signal("2.2.2.2", 10)
    result = KernLogDetectionResult(
        coverage=CoverageStatus.COMPLETE,
        detection_succeeded=True,
        signals=[rate_signal, scan_signal],
    )
    findings = build_kern_log_findings(result)
    rate_finding = next(f for f in findings if f.severity == "low")
    scan_finding = next(f for f in findings if f.severity == "medium")
    assert rate_finding.recommendation != scan_finding.recommendation
    assert "access restriction" in scan_finding.recommendation


# ---------------------------------------------------------------------------
# Group C — both signal types simultaneously
# ---------------------------------------------------------------------------


def test_c1_one_src_ip_triggers_both_signals_produces_two_findings():
    rate_signal = _rate_signal("1.2.3.4", 15)
    scan_signal = _scan_signal("1.2.3.4", 15)
    result = KernLogDetectionResult(
        coverage=CoverageStatus.COMPLETE,
        detection_succeeded=True,
        signals=[rate_signal, scan_signal],
    )
    findings = build_kern_log_findings(result)
    assert len(findings) == 2
    severities = {f.severity for f in findings}
    assert severities == {"low", "medium"}


# ---------------------------------------------------------------------------
# Group D — coverage without Finding
# ---------------------------------------------------------------------------


def test_d1_failed_coverage_produces_no_findings():
    signal = _rate_signal("1.2.3.4", 10)
    result = KernLogDetectionResult(
        coverage=CoverageStatus.FAILED, detection_succeeded=False, signals=[signal]
    )
    findings = build_kern_log_findings(result)
    assert findings == []


def test_d2_unknown_coverage_produces_no_findings():
    result = KernLogDetectionResult(
        coverage=CoverageStatus.UNKNOWN, detection_succeeded=False, signals=[]
    )
    findings = build_kern_log_findings(result)
    assert findings == []


def test_d3_empty_coverage_no_signals_produces_no_findings():
    result = KernLogDetectionResult(
        coverage=CoverageStatus.EMPTY, detection_succeeded=True, signals=[]
    )
    findings = build_kern_log_findings(result)
    assert findings == []


# ---------------------------------------------------------------------------
# Group E — invariants
# ---------------------------------------------------------------------------


def test_e1_event_count_passed_through_from_signal():
    signal = _rate_signal("1.2.3.4", 307)
    result = KernLogDetectionResult(
        coverage=CoverageStatus.COMPLETE, detection_succeeded=True, signals=[signal]
    )
    findings = build_kern_log_findings(result)
    assert findings[0].event_count == 307


def test_e2_severity_independent_of_event_count():
    small_signal = _rate_signal("1.1.1.1", 10)
    large_signal = _rate_signal("2.2.2.2", 307)
    result = KernLogDetectionResult(
        coverage=CoverageStatus.COMPLETE,
        detection_succeeded=True,
        signals=[small_signal, large_signal],
    )
    findings = build_kern_log_findings(result)
    assert all(f.severity == "low" for f in findings)


def test_e3_finding_order_matches_signal_order():
    signals = [
        _rate_signal("1.1.1.1", 10),
        _scan_signal("2.2.2.2", 10),
        _rate_signal("3.3.3.3", 20),
    ]
    result = KernLogDetectionResult(
        coverage=CoverageStatus.COMPLETE, detection_succeeded=True, signals=signals
    )
    findings = build_kern_log_findings(result)
    ips_in_order = [f.detail.split()[1] for f in findings]  # "IP {ip} ..." -> extract ip
    assert ips_in_order == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
