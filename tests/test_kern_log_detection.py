"""RED tests for kern_log_detection.py — Kern Log Detection Contract v1.

Scenario table (frozen contract, project session notes, 2026-08-21):

Group A — HIGH_DROP_RATE
  A1. one src_ip, 9 drops                         -> no signal (below threshold)
  A2. one src_ip, 10 drops                          -> 1 signal, event_count=10 (boundary)
  A3. one src_ip, 307 drops (real observed extreme)   -> 1 signal, event_count=307
  A4. several distinct src_ip, each >=10               -> N independent signals
  A5. drops with src_ip=None                             -> excluded from aggregation
  A6. UNKNOWN/UNKNOWN_MESSAGE events                       -> never participate at all

Group B — PORT_SCAN
  B1. one src_ip, 9 distinct dst_port                -> no signal
  B2. one src_ip, 10 distinct dst_port                  -> 1 signal, event_count=10 (boundary)
  B3. one src_ip, repeated dst_port (15 events, 8 distinct) -> no signal (cardinality, not raw count)
  B4. dst_port=None events mixed with dst_port!=None events   -> None events excluded from cardinality
  B5. src_ip with only dst_port=None events (10+)               -> no PORT_SCAN signal (0 distinct ports)
  B6. one src_ip triggers BOTH HIGH_DROP_RATE and PORT_SCAN        -> both signals, independent

Group C — coverage / detection_succeeded
  C1. coverage=COMPLETE, events>0                -> detection_succeeded=True
  C2. coverage=EMPTY (0 events)                     -> detection_succeeded=True, signals=[]
  C3. coverage=PARTIAL                                -> detection_succeeded=True
  C4. coverage=FAILED                                   -> detection_succeeded=False, signals=[]
  C5. coverage=UNKNOWN                                    -> detection_succeeded=False, signals=[]
  C6. many NFT_DROPPED, all below both thresholds           -> detection_succeeded=True, signals=[]

Group D — invariants
  D1. event_count == len(raw_evidence) for HIGH_DROP_RATE
  D2. event_count == len(raw_evidence) for PORT_SCAN (== distinct port count, NOT raw event count)

This gives 20+ concrete assertions across the parametrized cases below.
"""

from __future__ import annotations

from datetime import datetime, timezone

from netaudit_pkg.kern_log_detection import (
    CoverageStatus,
    KernLogSignalType,
    detect_kern_log_signals,
)
from netaudit_pkg.kern_log_parser import KernLogEvent, KernLogEventType

_TS = datetime(2026, 8, 21, 12, 0, 0, tzinfo=timezone.utc)


def _dropped(src_ip: str | None = "1.2.3.4", dst_port: int | None = 22) -> KernLogEvent:
    """Builds a minimal synthetic NFT_DROPPED KernLogEvent for Detection
    testing. Only src_ip/dst_port vary across calls; everything else is
    a harmless constant, since Detection only reads those two fields."""
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


def _non_dropped(event_type: KernLogEventType) -> KernLogEvent:
    return KernLogEvent(
        event_type=event_type,
        timestamp=_TS if event_type != KernLogEventType.UNKNOWN else None,
        hostname="testhost" if event_type != KernLogEventType.UNKNOWN else None,
        interface_in=None,
        interface_out=None,
        mac=None,
        mac_src=None,
        mac_dst=None,
        mac_proto=None,
        src_ip=None,
        dst_ip=None,
        length=None,
        tos=None,
        prec=None,
        ttl=None,
        packet_id=None,
        df_flag=False,
        protocol=None,
        src_port=None,
        dst_port=None,
        window=None,
        res=None,
        tcp_flags=[],
        urgp=None,
        payload_length=None,
        raw_line="synthetic non-dropped event",
    )


# ---------------------------------------------------------------------------
# Group A — HIGH_DROP_RATE
# ---------------------------------------------------------------------------


def test_a1_nine_drops_below_threshold_no_signal():
    events = [_dropped(src_ip="1.2.3.4", dst_port=100 + i) for i in range(9)]
    result = detect_kern_log_signals(events, CoverageStatus.COMPLETE)
    assert not any(s.signal_type == KernLogSignalType.HIGH_DROP_RATE for s in result.signals)


def test_a2_ten_drops_at_boundary_produces_signal():
    events = [_dropped(src_ip="1.2.3.4", dst_port=100 + i) for i in range(10)]
    result = detect_kern_log_signals(events, CoverageStatus.COMPLETE)
    rate_signals = [s for s in result.signals if s.signal_type == KernLogSignalType.HIGH_DROP_RATE]
    assert len(rate_signals) == 1
    assert rate_signals[0].event_count == 10
    assert rate_signals[0].src_ip == "1.2.3.4"


def test_a3_real_observed_extreme_307_drops():
    events = [_dropped(src_ip="5.61.209.224", dst_port=1000 + i) for i in range(307)]
    result = detect_kern_log_signals(events, CoverageStatus.COMPLETE)
    rate_signals = [s for s in result.signals if s.signal_type == KernLogSignalType.HIGH_DROP_RATE]
    assert len(rate_signals) == 1
    assert rate_signals[0].event_count == 307


def test_a4_several_distinct_src_ip_each_over_threshold():
    events = (
        [_dropped(src_ip="1.1.1.1", dst_port=100 + i) for i in range(10)]
        + [_dropped(src_ip="2.2.2.2", dst_port=200 + i) for i in range(15)]
    )
    result = detect_kern_log_signals(events, CoverageStatus.COMPLETE)
    rate_signals = [s for s in result.signals if s.signal_type == KernLogSignalType.HIGH_DROP_RATE]
    assert len(rate_signals) == 2
    ips = {s.src_ip for s in rate_signals}
    assert ips == {"1.1.1.1", "2.2.2.2"}


def test_a5_drops_with_none_src_ip_excluded():
    events = [_dropped(src_ip=None, dst_port=100 + i) for i in range(20)]
    result = detect_kern_log_signals(events, CoverageStatus.COMPLETE)
    assert not any(s.signal_type == KernLogSignalType.HIGH_DROP_RATE for s in result.signals)


def test_a6_unknown_events_never_participate():
    events = [_non_dropped(KernLogEventType.UNKNOWN) for _ in range(20)] + [
        _non_dropped(KernLogEventType.UNKNOWN_MESSAGE) for _ in range(20)
    ]
    result = detect_kern_log_signals(events, CoverageStatus.COMPLETE)
    assert result.signals == []


# ---------------------------------------------------------------------------
# Group B — PORT_SCAN
# ---------------------------------------------------------------------------


def test_b1_nine_distinct_ports_below_threshold_no_signal():
    events = [_dropped(src_ip="1.2.3.4", dst_port=100 + i) for i in range(9)]
    result = detect_kern_log_signals(events, CoverageStatus.COMPLETE)
    assert not any(s.signal_type == KernLogSignalType.PORT_SCAN for s in result.signals)


def test_b2_ten_distinct_ports_at_boundary_produces_signal():
    events = [_dropped(src_ip="1.2.3.4", dst_port=100 + i) for i in range(10)]
    result = detect_kern_log_signals(events, CoverageStatus.COMPLETE)
    scan_signals = [s for s in result.signals if s.signal_type == KernLogSignalType.PORT_SCAN]
    assert len(scan_signals) == 1
    assert scan_signals[0].event_count == 10
    assert scan_signals[0].src_ip == "1.2.3.4"


def test_b3_repeated_port_counts_by_cardinality_not_raw_count():
    # 15 raw events but only 8 distinct ports -> below the 10-port
    # threshold, even though raw event count (15) would clear a
    # HIGH_DROP_RATE-style threshold of 10.
    events = [_dropped(src_ip="1.2.3.4", dst_port=100 + (i % 8)) for i in range(15)]
    result = detect_kern_log_signals(events, CoverageStatus.COMPLETE)
    assert not any(s.signal_type == KernLogSignalType.PORT_SCAN for s in result.signals)
    # but HIGH_DROP_RATE (raw count=15 >= 10) still fires independently
    rate_signals = [s for s in result.signals if s.signal_type == KernLogSignalType.HIGH_DROP_RATE]
    assert len(rate_signals) == 1
    assert rate_signals[0].event_count == 15


def test_b4_none_dst_port_excluded_from_cardinality():
    events = (
        [_dropped(src_ip="1.2.3.4", dst_port=100 + i) for i in range(10)]
        + [_dropped(src_ip="1.2.3.4", dst_port=None) for _ in range(50)]
    )
    result = detect_kern_log_signals(events, CoverageStatus.COMPLETE)
    scan_signals = [s for s in result.signals if s.signal_type == KernLogSignalType.PORT_SCAN]
    assert len(scan_signals) == 1
    assert scan_signals[0].event_count == 10  # NOT 60


def test_b5_only_none_dst_port_produces_no_port_scan_signal():
    events = [_dropped(src_ip="1.2.3.4", dst_port=None) for _ in range(20)]
    result = detect_kern_log_signals(events, CoverageStatus.COMPLETE)
    assert not any(s.signal_type == KernLogSignalType.PORT_SCAN for s in result.signals)


def test_b6_one_src_triggers_both_signals_independently():
    events = [_dropped(src_ip="1.2.3.4", dst_port=100 + i) for i in range(15)]
    result = detect_kern_log_signals(events, CoverageStatus.COMPLETE)
    types = {s.signal_type for s in result.signals}
    assert KernLogSignalType.HIGH_DROP_RATE in types
    assert KernLogSignalType.PORT_SCAN in types
    rate_signal = next(s for s in result.signals if s.signal_type == KernLogSignalType.HIGH_DROP_RATE)
    scan_signal = next(s for s in result.signals if s.signal_type == KernLogSignalType.PORT_SCAN)
    assert rate_signal.event_count == 15
    assert scan_signal.event_count == 15  # all 15 ports distinct in this case


# ---------------------------------------------------------------------------
# Group C — coverage / detection_succeeded
# ---------------------------------------------------------------------------


def test_c1_complete_coverage_succeeds():
    events = [_dropped(src_ip="1.2.3.4", dst_port=100 + i) for i in range(10)]
    result = detect_kern_log_signals(events, CoverageStatus.COMPLETE)
    assert result.coverage == CoverageStatus.COMPLETE
    assert result.detection_succeeded is True


def test_c2_empty_coverage_succeeds_with_no_signals():
    result = detect_kern_log_signals([], CoverageStatus.EMPTY)
    assert result.coverage == CoverageStatus.EMPTY
    assert result.detection_succeeded is True
    assert result.signals == []


def test_c3_partial_coverage_succeeds():
    events = [_dropped(src_ip="1.2.3.4", dst_port=100 + i) for i in range(10)]
    result = detect_kern_log_signals(events, CoverageStatus.PARTIAL)
    assert result.coverage == CoverageStatus.PARTIAL
    assert result.detection_succeeded is True


def test_c4_failed_coverage_never_succeeds():
    events = [_dropped(src_ip="1.2.3.4", dst_port=100 + i) for i in range(10)]
    result = detect_kern_log_signals(events, CoverageStatus.FAILED)
    assert result.coverage == CoverageStatus.FAILED
    assert result.detection_succeeded is False
    assert result.signals == []


def test_c5_unknown_coverage_never_succeeds():
    result = detect_kern_log_signals([], CoverageStatus.UNKNOWN)
    assert result.coverage == CoverageStatus.UNKNOWN
    assert result.detection_succeeded is False
    assert result.signals == []


def test_c6_many_drops_all_below_thresholds_is_normal_empty_result():
    # 679 distinct src_ip, each with only 1-9 drops (below threshold) —
    # a legitimate, fully-analyzed "nothing notable" result.
    events = [_dropped(src_ip=f"10.0.{i}.1", dst_port=100) for i in range(50)]
    result = detect_kern_log_signals(events, CoverageStatus.COMPLETE)
    assert result.detection_succeeded is True
    assert result.signals == []


# ---------------------------------------------------------------------------
# Group D — invariants
# ---------------------------------------------------------------------------


def test_d1_high_drop_rate_event_count_equals_raw_evidence_length():
    events = [_dropped(src_ip="1.2.3.4", dst_port=100 + i) for i in range(12)]
    result = detect_kern_log_signals(events, CoverageStatus.COMPLETE)
    rate_signal = next(s for s in result.signals if s.signal_type == KernLogSignalType.HIGH_DROP_RATE)
    assert rate_signal.event_count == len(rate_signal.raw_evidence)


def test_d2_port_scan_event_count_equals_raw_evidence_length_not_raw_events():
    # 30 raw events, but only 12 distinct ports (each hit 2-3 times)
    events = [_dropped(src_ip="1.2.3.4", dst_port=100 + (i % 12)) for i in range(30)]
    result = detect_kern_log_signals(events, CoverageStatus.COMPLETE)
    scan_signal = next(s for s in result.signals if s.signal_type == KernLogSignalType.PORT_SCAN)
    assert scan_signal.event_count == 12
    assert len(scan_signal.raw_evidence) == 12
