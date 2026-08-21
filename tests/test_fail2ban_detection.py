"""RED tests for fail2ban_detection.py — Fail2Ban Detection Contract v1.

Scenario table (frozen contract, project session notes, 2026-08-21):

Group A — BAN signal (the only security signal in v1)
  A1. one BAN event                                    -> 1 Fail2BanSignal, event_count=1, raw_evidence=[that event]
  A2. several BAN events (different IPs)                -> N independent signals, one per event
  A3. BAN event's ip/jail retrievable via raw_evidence[0]

Group B — non-signal events (each explicitly produces NO signal)
  B1. only FOUND events, 0 BAN                          -> signals=[]
  B2. only UNBAN events                                 -> signals=[]
  B3. only RESTORE_BAN events                           -> signals=[]
  B4. only FLUSH events                                 -> signals=[]
  B5. only JAIL_START_WARNING events                    -> signals=[]
  B6. only UNKNOWN_MESSAGE events                       -> signals=[]
  B7. only UNKNOWN (envelope-level) events               -> signals=[]
  B8. mix of all non-BAN types, 0 BAN                    -> signals=[]

Group C — coverage / detection_succeeded (structurally identical to nginx Detection)
  C1. coverage=COMPLETE, events>0, contains BAN          -> detection_succeeded=True, BanSignal present
  C2. coverage=EMPTY (0 parsed events)                   -> detection_succeeded=True, signals=[]
  C3. coverage=PARTIAL                                   -> detection_succeeded=True
  C4. coverage=FAILED                                    -> detection_succeeded=False, signals=[] (even if events passed)
  C5. coverage=UNKNOWN                                   -> detection_succeeded=False, signals=[]
  C6. 100 FOUND + 0 BAN, coverage=COMPLETE                -> detection_succeeded=True, signals=[] (explicit boundary case)

Group D — invariants
  D1. event_count == len(raw_evidence) for every BanSignal -> always True
  D2. BanSignal order matches BAN event order in input      -> deterministic

This gives 20+ concrete assertions across the parametrized cases below.
"""

from __future__ import annotations

from datetime import datetime, timezone

from netaudit_pkg.fail2ban_detection import (
    CoverageStatus,
    Fail2BanSignalType,
    detect_fail2ban_signals,
)
from netaudit_pkg.fail2ban_parser import Fail2BanEvent, Fail2BanEventType

_TS = datetime(2026, 8, 21, 12, 0, 0, tzinfo=timezone.utc)


def _event(
    event_type: Fail2BanEventType,
    ip: str | None = None,
    jail: str = "sshd",
    message: str = "",
) -> Fail2BanEvent:
    """Builds a minimal synthetic Fail2BanEvent for Detection testing.
    Detection only cares about event_type/ip/jail — other fields are
    filled with harmless defaults, distinct per-call where it matters
    (raw_line) to avoid accidental identity collisions in assertions.
    """
    return Fail2BanEvent(
        event_type=event_type,
        timestamp=_TS,
        logger="fail2ban.actions",
        pid=12345,
        level="NOTICE",
        jail=jail,
        message=message,
        ip=ip,
        matched_timestamp=None,
        raw_line=f"synthetic {event_type.value} {ip or ''} {jail}",
    )


# ---------------------------------------------------------------------------
# Group A — BAN signal
# ---------------------------------------------------------------------------


def test_a1_one_ban_event_produces_one_signal():
    ban = _event(Fail2BanEventType.BAN, ip="1.2.3.4")
    result = detect_fail2ban_signals([ban], CoverageStatus.COMPLETE)
    assert len(result.signals) == 1
    assert result.signals[0].signal_type == Fail2BanSignalType.BAN
    assert result.signals[0].event_count == 1
    assert result.signals[0].raw_evidence == [ban]


def test_a2_several_ban_events_produce_independent_signals():
    ban1 = _event(Fail2BanEventType.BAN, ip="1.2.3.4")
    ban2 = _event(Fail2BanEventType.BAN, ip="5.6.7.8")
    ban3 = _event(Fail2BanEventType.BAN, ip="9.9.9.9")
    result = detect_fail2ban_signals([ban1, ban2, ban3], CoverageStatus.COMPLETE)
    assert len(result.signals) == 3
    for signal in result.signals:
        assert signal.signal_type == Fail2BanSignalType.BAN
        assert signal.event_count == 1
        assert len(signal.raw_evidence) == 1


def test_a3_ban_ip_and_jail_retrievable_from_evidence():
    ban = _event(Fail2BanEventType.BAN, ip="203.0.113.7", jail="nginx-http-auth")
    result = detect_fail2ban_signals([ban], CoverageStatus.COMPLETE)
    evidence = result.signals[0].raw_evidence[0]
    assert evidence.ip == "203.0.113.7"
    assert evidence.jail == "nginx-http-auth"


# ---------------------------------------------------------------------------
# Group B — non-signal events
# ---------------------------------------------------------------------------


def test_b1_only_found_events_produce_no_signal():
    events = [_event(Fail2BanEventType.FOUND, ip="1.2.3.4") for _ in range(5)]
    result = detect_fail2ban_signals(events, CoverageStatus.COMPLETE)
    assert result.signals == []


def test_b2_only_unban_events_produce_no_signal():
    events = [_event(Fail2BanEventType.UNBAN, ip="1.2.3.4")]
    result = detect_fail2ban_signals(events, CoverageStatus.COMPLETE)
    assert result.signals == []


def test_b3_only_restore_ban_events_produce_no_signal():
    events = [_event(Fail2BanEventType.RESTORE_BAN, ip="1.2.3.4")]
    result = detect_fail2ban_signals(events, CoverageStatus.COMPLETE)
    assert result.signals == []


def test_b4_only_flush_events_produce_no_signal():
    events = [_event(Fail2BanEventType.FLUSH, ip=None)]
    result = detect_fail2ban_signals(events, CoverageStatus.COMPLETE)
    assert result.signals == []


def test_b5_only_jail_start_warning_events_produce_no_signal():
    events = [_event(Fail2BanEventType.JAIL_START_WARNING, ip=None)]
    result = detect_fail2ban_signals(events, CoverageStatus.COMPLETE)
    assert result.signals == []


def test_b6_only_unknown_message_events_produce_no_signal():
    events = [_event(Fail2BanEventType.UNKNOWN_MESSAGE, ip=None)]
    result = detect_fail2ban_signals(events, CoverageStatus.COMPLETE)
    assert result.signals == []


def test_b7_only_unknown_envelope_events_produce_no_signal():
    events = [
        Fail2BanEvent(
            event_type=Fail2BanEventType.UNKNOWN,
            timestamp=None,
            logger=None,
            pid=None,
            level=None,
            jail=None,
            message=None,
            ip=None,
            matched_timestamp=None,
            raw_line="garbage line",
        )
    ]
    result = detect_fail2ban_signals(events, CoverageStatus.COMPLETE)
    assert result.signals == []


def test_b8_mixed_non_ban_types_produce_no_signal():
    events = [
        _event(Fail2BanEventType.FOUND, ip="1.2.3.4"),
        _event(Fail2BanEventType.UNBAN, ip="1.2.3.4"),
        _event(Fail2BanEventType.FLUSH, ip=None),
        _event(Fail2BanEventType.JAIL_START_WARNING, ip=None),
        _event(Fail2BanEventType.UNKNOWN_MESSAGE, ip=None),
        _event(Fail2BanEventType.RESTORE_BAN, ip="5.6.7.8"),
    ]
    result = detect_fail2ban_signals(events, CoverageStatus.COMPLETE)
    assert result.signals == []


# ---------------------------------------------------------------------------
# Group C — coverage / detection_succeeded
# ---------------------------------------------------------------------------


def test_c1_complete_coverage_with_ban_succeeds_with_signal():
    ban = _event(Fail2BanEventType.BAN, ip="1.2.3.4")
    result = detect_fail2ban_signals([ban], CoverageStatus.COMPLETE)
    assert result.coverage == CoverageStatus.COMPLETE
    assert result.detection_succeeded is True
    assert len(result.signals) == 1


def test_c2_empty_coverage_succeeds_with_no_signals():
    result = detect_fail2ban_signals([], CoverageStatus.EMPTY)
    assert result.coverage == CoverageStatus.EMPTY
    assert result.detection_succeeded is True
    assert result.signals == []


def test_c3_partial_coverage_succeeds():
    ban = _event(Fail2BanEventType.BAN, ip="1.2.3.4")
    result = detect_fail2ban_signals([ban], CoverageStatus.PARTIAL)
    assert result.coverage == CoverageStatus.PARTIAL
    assert result.detection_succeeded is True


def test_c4_failed_coverage_never_succeeds_even_with_events():
    ban = _event(Fail2BanEventType.BAN, ip="1.2.3.4")
    result = detect_fail2ban_signals([ban], CoverageStatus.FAILED)
    assert result.coverage == CoverageStatus.FAILED
    assert result.detection_succeeded is False
    assert result.signals == []


def test_c5_unknown_coverage_never_succeeds():
    result = detect_fail2ban_signals([], CoverageStatus.UNKNOWN)
    assert result.coverage == CoverageStatus.UNKNOWN
    assert result.detection_succeeded is False
    assert result.signals == []


def test_c6_many_found_zero_ban_is_complete_with_no_signals():
    # Explicit boundary case discussed in contract review: fail2ban never
    # actually banned anyone in this slice — that is a legitimate,
    # fully-analyzed empty result, not a detection failure.
    events = [_event(Fail2BanEventType.FOUND, ip="1.2.3.4") for _ in range(100)]
    result = detect_fail2ban_signals(events, CoverageStatus.COMPLETE)
    assert result.coverage == CoverageStatus.COMPLETE
    assert result.detection_succeeded is True
    assert result.signals == []


# ---------------------------------------------------------------------------
# Group D — invariants
# ---------------------------------------------------------------------------


def test_d1_event_count_equals_raw_evidence_length():
    events = [
        _event(Fail2BanEventType.BAN, ip="1.2.3.4"),
        _event(Fail2BanEventType.BAN, ip="5.6.7.8"),
    ]
    result = detect_fail2ban_signals(events, CoverageStatus.COMPLETE)
    for signal in result.signals:
        assert signal.event_count == len(signal.raw_evidence)


def test_d2_signal_order_matches_ban_event_order():
    ban1 = _event(Fail2BanEventType.BAN, ip="1.1.1.1")
    ban2 = _event(Fail2BanEventType.BAN, ip="2.2.2.2")
    ban3 = _event(Fail2BanEventType.BAN, ip="3.3.3.3")
    result = detect_fail2ban_signals([ban1, ban2, ban3], CoverageStatus.COMPLETE)
    ips_in_order = [s.raw_evidence[0].ip for s in result.signals]
    assert ips_in_order == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
