"""RED tests for nginx_error_detection.py — Error Detection Contract v1.

Full Scenario Table v1 (30 scenarios, groups A-D):
  Group A: HIGH_ERROR_RATE     — A1-A7
  Group B: CRITICAL_ERROR      — B1-B8
  Group C: REPEATED_ERROR      — C1-C10
  Group D: Coverage / detection_succeeded interaction — D1-D5

Every test traces back to a scenario in the frozen Scenario Table — no
scenario is added here purely to inflate the test count.
"""

from __future__ import annotations

import pytest

from netaudit_pkg.nginx_error_detection import (
    HIGH_ERROR_RATE_THRESHOLD,
    REPEATED_ERROR_THRESHOLD,
    CoverageStatus,
    NginxErrorSignalType,
    detect_error_signals,
    normalize_message,
)
from netaudit_pkg.nginx_error_parser import (
    NginxErrorEvent,
    NginxErrorEventType,
    NginxErrorSeverity,
)

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _parsed(
    severity: NginxErrorSeverity = NginxErrorSeverity.ERROR,
    message: str = "connect() failed (111: Connection refused) while connecting to upstream",
    pid: int = 1000,
    tid: int = 0,
) -> NginxErrorEvent:
    return NginxErrorEvent(
        event_type=NginxErrorEventType.PARSED,
        timestamp=None,
        severity=severity,
        pid=pid,
        tid=tid,
        connection_id=None,
        message=message,
        raw_line=f"2026/08/19 12:00:00 [{severity.value}] {pid}#{tid}: {message}",
    )


def _unknown(raw: str = "garbage line that does not match the error format") -> NginxErrorEvent:
    return NginxErrorEvent(
        event_type=NginxErrorEventType.UNKNOWN,
        timestamp=None,
        severity=None,
        pid=None,
        tid=None,
        connection_id=None,
        message=None,
        raw_line=raw,
    )


def _signals_of_type(result, signal_type: NginxErrorSignalType):
    return [s for s in result.signals if s.signal_type == signal_type]


# ===========================================================================
# GROUP A — HIGH_ERROR_RATE
# ===========================================================================


def test_a1_high_error_rate_at_threshold_produces_signal():
    events = [_parsed(severity=NginxErrorSeverity.ERROR) for _ in range(HIGH_ERROR_RATE_THRESHOLD)]
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxErrorSignalType.HIGH_ERROR_RATE)
    assert len(signals) == 1
    assert signals[0].event_count == HIGH_ERROR_RATE_THRESHOLD


def test_a2_high_error_rate_below_threshold_no_signal():
    events = [_parsed(severity=NginxErrorSeverity.ERROR) for _ in range(HIGH_ERROR_RATE_THRESHOLD - 1)]
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    assert _signals_of_type(result, NginxErrorSignalType.HIGH_ERROR_RATE) == []


@pytest.mark.parametrize(
    "count,expect_signal",
    [(HIGH_ERROR_RATE_THRESHOLD - 1, False), (HIGH_ERROR_RATE_THRESHOLD, True)],
)
def test_a3_high_error_rate_boundary(count, expect_signal):
    events = [_parsed(severity=NginxErrorSeverity.ERROR) for _ in range(count)]
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxErrorSignalType.HIGH_ERROR_RATE)
    assert (len(signals) == 1) == expect_signal


def test_a4_mixed_error_plus_severities_counted_together():
    events = (
        [_parsed(severity=NginxErrorSeverity.ERROR) for _ in range(4)]
        + [_parsed(severity=NginxErrorSeverity.CRIT) for _ in range(3)]
        + [_parsed(severity=NginxErrorSeverity.ALERT) for _ in range(2)]
        + [_parsed(severity=NginxErrorSeverity.EMERG) for _ in range(1)]
    )
    assert len(events) == HIGH_ERROR_RATE_THRESHOLD
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxErrorSignalType.HIGH_ERROR_RATE)
    assert len(signals) == 1
    assert signals[0].event_count == HIGH_ERROR_RATE_THRESHOLD


def test_a5_warn_and_below_never_count_toward_high_error_rate():
    events = (
        [_parsed(severity=NginxErrorSeverity.WARN) for _ in range(50)]
        + [_parsed(severity=NginxErrorSeverity.NOTICE) for _ in range(50)]
        + [_parsed(severity=NginxErrorSeverity.INFO) for _ in range(50)]
        + [_parsed(severity=NginxErrorSeverity.DEBUG) for _ in range(50)]
    )
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    assert _signals_of_type(result, NginxErrorSignalType.HIGH_ERROR_RATE) == []


def test_a6_single_crit_below_rate_threshold_still_triggers_critical_error_independently():
    events = [_parsed(severity=NginxErrorSeverity.CRIT)]
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    assert _signals_of_type(result, NginxErrorSignalType.HIGH_ERROR_RATE) == []
    critical_signals = _signals_of_type(result, NginxErrorSignalType.CRITICAL_ERROR)
    assert len(critical_signals) == 1
    assert critical_signals[0].event_count == 1


def test_a7_unknown_events_do_not_count_toward_high_error_rate():
    events = [_parsed(severity=NginxErrorSeverity.ERROR) for _ in range(HIGH_ERROR_RATE_THRESHOLD - 1)]
    events += [_unknown() for _ in range(50)]
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    assert _signals_of_type(result, NginxErrorSignalType.HIGH_ERROR_RATE) == []


# ===========================================================================
# GROUP B — CRITICAL_ERROR
# ===========================================================================


def test_b1_single_crit_produces_signal():
    events = [_parsed(severity=NginxErrorSeverity.CRIT)]
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxErrorSignalType.CRITICAL_ERROR)
    assert len(signals) == 1
    assert signals[0].event_count == 1


def test_b2_single_alert_produces_signal():
    events = [_parsed(severity=NginxErrorSeverity.ALERT)]
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxErrorSignalType.CRITICAL_ERROR)
    assert len(signals) == 1
    assert signals[0].event_count == 1


def test_b3_single_emerg_produces_signal():
    events = [_parsed(severity=NginxErrorSeverity.EMERG)]
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxErrorSignalType.CRITICAL_ERROR)
    assert len(signals) == 1
    assert signals[0].event_count == 1


def test_b4_multiple_crit_aggregate_into_one_signal():
    events = [_parsed(severity=NginxErrorSeverity.CRIT) for _ in range(3)]
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxErrorSignalType.CRITICAL_ERROR)
    assert len(signals) == 1
    assert signals[0].event_count == 3
    assert len(signals[0].raw_evidence) == 3


def test_b5_mixed_critical_severities_aggregate_together():
    events = (
        [_parsed(severity=NginxErrorSeverity.CRIT) for _ in range(2)]
        + [_parsed(severity=NginxErrorSeverity.ALERT) for _ in range(1)]
        + [_parsed(severity=NginxErrorSeverity.EMERG) for _ in range(1)]
    )
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxErrorSignalType.CRITICAL_ERROR)
    assert len(signals) == 1
    assert signals[0].event_count == 4


def test_b6_no_critical_severities_no_signal():
    events = [_parsed(severity=NginxErrorSeverity.ERROR) for _ in range(5)]
    events += [_parsed(severity=NginxErrorSeverity.WARN) for _ in range(5)]
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    assert _signals_of_type(result, NginxErrorSignalType.CRITICAL_ERROR) == []


def test_b7_high_error_rate_without_any_critical_severity():
    events = [_parsed(severity=NginxErrorSeverity.ERROR) for _ in range(100)]
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    assert len(_signals_of_type(result, NginxErrorSignalType.HIGH_ERROR_RATE)) == 1
    assert _signals_of_type(result, NginxErrorSignalType.CRITICAL_ERROR) == []


def test_b8_unknown_events_do_not_participate_in_critical_error():
    events = [_unknown() for _ in range(50)]
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    assert _signals_of_type(result, NginxErrorSignalType.CRITICAL_ERROR) == []


# ===========================================================================
# GROUP C — REPEATED_ERROR
# ===========================================================================


def test_c1_message_repeated_at_threshold_produces_signal():
    events = [
        _parsed(message="connect() failed (111: Connection refused) while connecting to upstream")
        for _ in range(REPEATED_ERROR_THRESHOLD)
    ]
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxErrorSignalType.REPEATED_ERROR)
    assert len(signals) == 1
    assert signals[0].event_count == REPEATED_ERROR_THRESHOLD
    assert len(signals[0].raw_evidence) == REPEATED_ERROR_THRESHOLD


def test_c2_message_repeated_below_threshold_no_signal():
    events = [
        _parsed(message="connect() failed (111: Connection refused) while connecting to upstream")
        for _ in range(REPEATED_ERROR_THRESHOLD - 1)
    ]
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    assert _signals_of_type(result, NginxErrorSignalType.REPEATED_ERROR) == []


@pytest.mark.parametrize(
    "count,expect_signal",
    [(REPEATED_ERROR_THRESHOLD - 1, False), (REPEATED_ERROR_THRESHOLD, True)],
)
def test_c3_repeated_error_boundary(count, expect_signal):
    events = [_parsed(message="same message every time") for _ in range(count)]
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxErrorSignalType.REPEATED_ERROR)
    assert (len(signals) == 1) == expect_signal


def test_c4_multiple_distinct_repeated_messages_produce_independent_signals():
    events = (
        [_parsed(message="message A") for _ in range(REPEATED_ERROR_THRESHOLD)]
        + [_parsed(message="message B") for _ in range(REPEATED_ERROR_THRESHOLD)]
    )
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxErrorSignalType.REPEATED_ERROR)
    assert len(signals) == 2
    keys = {s.message_key for s in signals}
    assert keys == {"message A", "message B"}


def test_c5_similar_but_not_identical_messages_are_not_grouped():
    events = (
        [_parsed(message="connect() failed, client: 1.2.3.4") for _ in range(REPEATED_ERROR_THRESHOLD)]
        + [_parsed(message="connect() failed, client: 5.6.7.8") for _ in range(REPEATED_ERROR_THRESHOLD)]
    )
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxErrorSignalType.REPEATED_ERROR)
    assert len(signals) == 2  # two separate signals, not merged into one


def test_c6_same_message_different_severities_still_grouped():
    events = (
        [_parsed(message="same message", severity=NginxErrorSeverity.ERROR) for _ in range(3)]
        + [_parsed(message="same message", severity=NginxErrorSeverity.CRIT) for _ in range(2)]
    )
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxErrorSignalType.REPEATED_ERROR)
    assert len(signals) == 1
    assert signals[0].event_count == 5


def test_c7_same_message_different_pid_tid_still_grouped():
    events = [
        _parsed(message="same message", pid=1000 + i, tid=i)
        for i in range(REPEATED_ERROR_THRESHOLD)
    ]
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxErrorSignalType.REPEATED_ERROR)
    assert len(signals) == 1
    assert signals[0].event_count == REPEATED_ERROR_THRESHOLD


def test_c8_extra_whitespace_normalizes_to_same_key():
    assert normalize_message("  hello world  ") == "hello world"
    assert normalize_message("hello world") == "hello world"
    events = (
        [_parsed(message="hello world") for _ in range(3)]
        + [_parsed(message="  hello world  ") for _ in range(2)]
    )
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxErrorSignalType.REPEATED_ERROR)
    assert len(signals) == 1
    assert signals[0].event_count == 5


def test_c9_unknown_events_do_not_participate_in_repeated_error():
    assert normalize_message(None) is None
    events = [_unknown() for _ in range(REPEATED_ERROR_THRESHOLD + 5)]
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    assert _signals_of_type(result, NginxErrorSignalType.REPEATED_ERROR) == []


def test_c10_repeated_error_and_critical_error_independently_trigger_on_same_events():
    events = [_parsed(message="same critical message", severity=NginxErrorSeverity.CRIT)
              for _ in range(REPEATED_ERROR_THRESHOLD)]
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    repeated = _signals_of_type(result, NginxErrorSignalType.REPEATED_ERROR)
    critical = _signals_of_type(result, NginxErrorSignalType.CRITICAL_ERROR)
    assert len(repeated) == 1
    assert len(critical) == 1
    assert repeated[0].event_count == REPEATED_ERROR_THRESHOLD
    assert critical[0].event_count == REPEATED_ERROR_THRESHOLD


# ===========================================================================
# GROUP D — Coverage / detection_succeeded interaction
# ===========================================================================


def test_d1_empty_coverage_succeeded_true_no_signals():
    result = detect_error_signals([], CoverageStatus.EMPTY)
    assert result.coverage == CoverageStatus.EMPTY
    assert result.detection_succeeded is True
    assert result.signals == []


def test_d2_failed_coverage_succeeded_false_no_signals():
    events = [_parsed(severity=NginxErrorSeverity.CRIT)]
    result = detect_error_signals(events, CoverageStatus.FAILED)
    assert result.coverage == CoverageStatus.FAILED
    assert result.detection_succeeded is False
    assert result.signals == []


def test_d3_complete_coverage_only_info_warn_is_not_empty_status():
    events = [_parsed(severity=NginxErrorSeverity.INFO, message=f"info message {i}") for i in range(500)]
    events += [_parsed(severity=NginxErrorSeverity.WARN, message=f"warn message {i}") for i in range(500)]
    result = detect_error_signals(events, CoverageStatus.COMPLETE)
    assert result.coverage == CoverageStatus.COMPLETE  # NOT EMPTY
    assert result.detection_succeeded is True
    assert result.signals == []


def test_d4_unknown_coverage_succeeded_false_no_signals():
    events = [_parsed(severity=NginxErrorSeverity.CRIT)]
    result = detect_error_signals(events, CoverageStatus.UNKNOWN)
    assert result.coverage == CoverageStatus.UNKNOWN
    assert result.detection_succeeded is False
    assert result.signals == []


def test_d5_partial_coverage_succeeded_true_detection_runs_coverage_stays_partial():
    events = [_parsed(severity=NginxErrorSeverity.ERROR) for _ in range(HIGH_ERROR_RATE_THRESHOLD)]
    result = detect_error_signals(events, CoverageStatus.PARTIAL)
    assert result.coverage == CoverageStatus.PARTIAL
    assert result.detection_succeeded is True
    assert len(_signals_of_type(result, NginxErrorSignalType.HIGH_ERROR_RATE)) == 1
