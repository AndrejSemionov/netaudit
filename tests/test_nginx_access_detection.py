"""RED tests for nginx_access_detection.py — Access Detection Contract v1.

Full Scenario Table v1 (38 scenarios, groups A-E):
  Group A: HIGH_4XX_RATE / HIGH_5XX_RATE  — A1-A8
  Group B: PATH_SCAN (incl. path-extraction B9-B11) — B1-B11
  Group C: REQUEST_BURST  — C1-C8
  Group D: HIGH_PARSE_FAILURE_RATE  — D1-D5
  Group E: Coverage / detection_succeeded interaction  — E1-E5

Every test traces back to a scenario in the frozen Scenario Table — no
scenario is added here purely to inflate the test count.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from netaudit_pkg.nginx_access_detection import (
    HIGH_4XX_RATE_THRESHOLD,
    HIGH_5XX_RATE_THRESHOLD,
    HIGH_PARSE_FAILURE_RATE_THRESHOLD,
    PATH_SCAN_404_RATIO_THRESHOLD,
    PATH_SCAN_DISTINCT_PATHS_THRESHOLD,
    REQUEST_BURST_THRESHOLD,
    REQUEST_BURST_WINDOW_SECONDS,
    CoverageStatus,
    NginxAccessSignalType,
    detect_access_signals,
    extract_path,
)
from netaudit_pkg.nginx_access_parser import NginxAccessEvent, NginxAccessEventType

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

_BASE_TS = datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc)


def _parsed(
    ip: str = "203.0.113.10",
    status: int = 200,
    request: str = "GET / HTTP/1.1",
    ts: datetime | None = None,
) -> NginxAccessEvent:
    return NginxAccessEvent(
        event_type=NginxAccessEventType.PARSED,
        remote_addr=ip,
        remote_user=None,
        timestamp=ts if ts is not None else _BASE_TS,
        request=request,
        status=status,
        body_bytes_sent=512,
        http_referer=None,
        http_user_agent="pytest-agent",
        raw_line=f'{ip} - - [19/Aug/2026:12:00:00 +0000] "{request}" {status} 512 "-" "pytest-agent"',
    )


def _unknown(raw: str = "not a valid combined log line") -> NginxAccessEvent:
    return NginxAccessEvent(
        event_type=NginxAccessEventType.UNKNOWN,
        remote_addr=None,
        remote_user=None,
        timestamp=None,
        request=None,
        status=None,
        body_bytes_sent=None,
        http_referer=None,
        http_user_agent=None,
        raw_line=raw,
    )


def _signals_of_type(result, signal_type: NginxAccessSignalType):
    return [s for s in result.signals if s.signal_type == signal_type]


# ===========================================================================
# GROUP A — HIGH_4XX_RATE / HIGH_5XX_RATE
# ===========================================================================


def test_a1_high_4xx_rate_at_threshold_produces_signal():
    events = [_parsed(status=404) for _ in range(HIGH_4XX_RATE_THRESHOLD)]
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxAccessSignalType.HIGH_4XX_RATE)
    assert len(signals) == 1
    assert signals[0].event_count == HIGH_4XX_RATE_THRESHOLD
    assert signals[0].ip == "203.0.113.10"


def test_a2_high_4xx_rate_below_threshold_no_signal():
    events = [_parsed(status=404) for _ in range(HIGH_4XX_RATE_THRESHOLD - 1)]
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    assert _signals_of_type(result, NginxAccessSignalType.HIGH_4XX_RATE) == []


@pytest.mark.parametrize(
    "count,expect_signal",
    [(HIGH_4XX_RATE_THRESHOLD - 1, False), (HIGH_4XX_RATE_THRESHOLD, True)],
)
def test_a3_high_4xx_rate_boundary(count, expect_signal):
    events = [_parsed(status=404) for _ in range(count)]
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxAccessSignalType.HIGH_4XX_RATE)
    assert (len(signals) == 1) == expect_signal


def test_a4_two_ips_both_over_threshold_two_independent_signals():
    events = (
        [_parsed(ip="203.0.113.10", status=404) for _ in range(HIGH_4XX_RATE_THRESHOLD)]
        + [_parsed(ip="203.0.113.20", status=404) for _ in range(HIGH_4XX_RATE_THRESHOLD)]
    )
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxAccessSignalType.HIGH_4XX_RATE)
    assert len(signals) == 2
    ips = {s.ip for s in signals}
    assert ips == {"203.0.113.10", "203.0.113.20"}


def test_a5_one_ip_over_both_4xx_and_5xx_thresholds_two_independent_signals():
    events = (
        [_parsed(status=404) for _ in range(HIGH_4XX_RATE_THRESHOLD)]
        + [_parsed(status=500) for _ in range(HIGH_5XX_RATE_THRESHOLD)]
    )
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    sig_4xx = _signals_of_type(result, NginxAccessSignalType.HIGH_4XX_RATE)
    sig_5xx = _signals_of_type(result, NginxAccessSignalType.HIGH_5XX_RATE)
    assert len(sig_4xx) == 1
    assert len(sig_5xx) == 1


def test_a6_various_4xx_codes_all_counted():
    codes = [401, 403, 404, 429]
    events = []
    for i in range(HIGH_4XX_RATE_THRESHOLD):
        events.append(_parsed(status=codes[i % len(codes)]))
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxAccessSignalType.HIGH_4XX_RATE)
    assert len(signals) == 1
    assert signals[0].event_count == HIGH_4XX_RATE_THRESHOLD


def test_a7_various_5xx_codes_all_counted():
    codes = [500, 502, 503]
    events = []
    for i in range(HIGH_5XX_RATE_THRESHOLD):
        events.append(_parsed(status=codes[i % len(codes)]))
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxAccessSignalType.HIGH_5XX_RATE)
    assert len(signals) == 1
    assert signals[0].event_count == HIGH_5XX_RATE_THRESHOLD


def test_a8_unknown_events_do_not_count_toward_4xx_rate():
    events = [_parsed(status=404) for _ in range(HIGH_4XX_RATE_THRESHOLD - 1)]
    events += [_unknown() for _ in range(50)]  # plenty of UNKNOWN, must not push it over
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    assert _signals_of_type(result, NginxAccessSignalType.HIGH_4XX_RATE) == []


# ===========================================================================
# GROUP B — PATH_SCAN
# ===========================================================================


def _distinct_404_events(ip: str, n: int) -> list[NginxAccessEvent]:
    return [_parsed(ip=ip, status=404, request=f"GET /path{i} HTTP/1.1") for i in range(n)]


def test_b1_all_distinct_paths_404_produces_signal():
    events = _distinct_404_events("203.0.113.10", PATH_SCAN_DISTINCT_PATHS_THRESHOLD)
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxAccessSignalType.PATH_SCAN)
    assert len(signals) == 1


def test_b2_ratio_below_threshold_no_signal():
    n = PATH_SCAN_DISTINCT_PATHS_THRESHOLD
    events = [_parsed(ip="203.0.113.10", status=404, request="GET /path0 HTTP/1.1")]
    events += [
        _parsed(ip="203.0.113.10", status=200, request=f"GET /path{i} HTTP/1.1")
        for i in range(1, n)
    ]
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    assert _signals_of_type(result, NginxAccessSignalType.PATH_SCAN) == []


def test_b3_distinct_paths_below_threshold_no_signal():
    events = _distinct_404_events("203.0.113.10", PATH_SCAN_DISTINCT_PATHS_THRESHOLD - 1)
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    assert _signals_of_type(result, NginxAccessSignalType.PATH_SCAN) == []


def test_b4_repeated_single_path_404_never_triggers_path_scan():
    events = [_parsed(ip="203.0.113.10", status=404, request="GET /wp-login.php HTTP/1.1")] * 100
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    assert _signals_of_type(result, NginxAccessSignalType.PATH_SCAN) == []


@pytest.mark.parametrize(
    "distinct_count,expect_signal",
    [
        (PATH_SCAN_DISTINCT_PATHS_THRESHOLD - 1, False),
        (PATH_SCAN_DISTINCT_PATHS_THRESHOLD, True),
    ],
)
def test_b5_path_scan_distinct_count_boundary(distinct_count, expect_signal):
    events = _distinct_404_events("203.0.113.10", distinct_count)
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxAccessSignalType.PATH_SCAN)
    assert (len(signals) == 1) == expect_signal


def test_b6_ratio_denominator_is_all_distinct_paths_not_just_404():
    n = PATH_SCAN_DISTINCT_PATHS_THRESHOLD
    n_404 = int(n * PATH_SCAN_404_RATIO_THRESHOLD)
    events = [
        _parsed(ip="203.0.113.10", status=404, request=f"GET /p{i} HTTP/1.1")
        for i in range(n_404)
    ]
    events += [
        _parsed(ip="203.0.113.10", status=200, request=f"GET /p{i} HTTP/1.1")
        for i in range(n_404, n)
    ]
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxAccessSignalType.PATH_SCAN)
    assert len(signals) == 1


def test_b7_path_scan_and_high_4xx_rate_independent_on_same_ip():
    events = _distinct_404_events("203.0.113.10", PATH_SCAN_DISTINCT_PATHS_THRESHOLD)
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    assert len(_signals_of_type(result, NginxAccessSignalType.PATH_SCAN)) == 1
    assert len(_signals_of_type(result, NginxAccessSignalType.HIGH_4XX_RATE)) == 1


def test_b8_unknown_events_do_not_participate_in_path_scan():
    events = _distinct_404_events("203.0.113.10", PATH_SCAN_DISTINCT_PATHS_THRESHOLD - 1)
    events += [_unknown() for _ in range(50)]
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    assert _signals_of_type(result, NginxAccessSignalType.PATH_SCAN) == []


def test_b9_get_and_post_same_path_count_as_one_distinct_path():
    path = extract_path("GET /foo HTTP/1.1")
    path2 = extract_path("POST /foo HTTP/1.1")
    assert path == path2 == "/foo"


def test_b10_different_query_strings_count_as_one_distinct_path():
    p1 = extract_path("GET /foo?a=1 HTTP/1.1")
    p2 = extract_path("GET /foo?a=2 HTTP/1.1")
    p3 = extract_path("GET /foo?a=3 HTTP/1.1")
    assert p1 == p2 == p3 == "/foo"


@pytest.mark.parametrize(
    "request_value",
    [None, "", "garbage", "onlyonetoken"],
)
def test_b11_malformed_request_path_unavailable_never_raises(request_value):
    result = extract_path(request_value)
    assert result is None


# ===========================================================================
# GROUP C — REQUEST_BURST
# ===========================================================================


def _burst_events(ip: str, n: int, start: datetime) -> list[NginxAccessEvent]:
    return [
        _parsed(ip=ip, ts=start + timedelta(seconds=i % REQUEST_BURST_WINDOW_SECONDS))
        for i in range(n)
    ]


def test_c1_burst_at_threshold_in_one_window_produces_signal():
    events = _burst_events("203.0.113.10", REQUEST_BURST_THRESHOLD, _BASE_TS)
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxAccessSignalType.REQUEST_BURST)
    assert len(signals) == 1
    assert signals[0].window_start is not None
    assert signals[0].window_end is not None


def test_c2_below_threshold_in_window_no_signal():
    events = _burst_events("203.0.113.10", REQUEST_BURST_THRESHOLD - 1, _BASE_TS)
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    assert _signals_of_type(result, NginxAccessSignalType.REQUEST_BURST) == []


def test_c3_burst_in_two_non_overlapping_windows_two_independent_signals():
    window1 = _burst_events("203.0.113.10", REQUEST_BURST_THRESHOLD, _BASE_TS)
    later_start = _BASE_TS + timedelta(seconds=REQUEST_BURST_WINDOW_SECONDS * 10)
    window2 = _burst_events("203.0.113.10", REQUEST_BURST_THRESHOLD, later_start)
    events = window1 + window2
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxAccessSignalType.REQUEST_BURST)
    assert len(signals) == 2


def test_c4_evenly_spread_events_no_signal_even_with_large_total():
    start = _BASE_TS
    events = [
        _parsed(ip="203.0.113.10", ts=start + timedelta(seconds=i * REQUEST_BURST_WINDOW_SECONDS))
        for i in range(REQUEST_BURST_THRESHOLD * 3)
    ]
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    assert _signals_of_type(result, NginxAccessSignalType.REQUEST_BURST) == []


def test_c5_event_exactly_on_window_boundary_is_inclusive():
    start = _BASE_TS
    events = [_parsed(ip="203.0.113.10", ts=start) for _ in range(REQUEST_BURST_THRESHOLD - 1)]
    events.append(
        _parsed(ip="203.0.113.10", ts=start + timedelta(seconds=REQUEST_BURST_WINDOW_SECONDS - 1))
    )
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxAccessSignalType.REQUEST_BURST)
    assert len(signals) == 1


def test_c6_two_ips_independent_bursts_in_same_window():
    events = (
        _burst_events("203.0.113.10", REQUEST_BURST_THRESHOLD, _BASE_TS)
        + _burst_events("203.0.113.20", REQUEST_BURST_THRESHOLD, _BASE_TS)
    )
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxAccessSignalType.REQUEST_BURST)
    assert len(signals) == 2
    ips = {s.ip for s in signals}
    assert ips == {"203.0.113.10", "203.0.113.20"}


def test_c7_unknown_events_do_not_participate_in_burst_windowing():
    events = _burst_events("203.0.113.10", REQUEST_BURST_THRESHOLD - 1, _BASE_TS)
    events += [_unknown() for _ in range(50)]
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    assert _signals_of_type(result, NginxAccessSignalType.REQUEST_BURST) == []


def test_c8_defensive_parsed_event_with_none_timestamp_does_not_participate():
    weird_event = NginxAccessEvent(
        event_type=NginxAccessEventType.PARSED,
        remote_addr="203.0.113.10",
        remote_user=None,
        timestamp=None,
        request="GET / HTTP/1.1",
        status=200,
        body_bytes_sent=1,
        http_referer=None,
        http_user_agent=None,
        raw_line="defensive-case",
    )
    events = [weird_event] * REQUEST_BURST_THRESHOLD
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    assert _signals_of_type(result, NginxAccessSignalType.REQUEST_BURST) == []


# ===========================================================================
# GROUP D — HIGH_PARSE_FAILURE_RATE
# ===========================================================================


def test_d1_parse_failure_at_threshold_produces_signal_with_unknown_evidence():
    total = 200
    unknown_count = int(total * HIGH_PARSE_FAILURE_RATE_THRESHOLD)
    events = [_unknown() for _ in range(unknown_count)]
    events += [_parsed() for _ in range(total - unknown_count)]
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxAccessSignalType.HIGH_PARSE_FAILURE_RATE)
    assert len(signals) == 1
    assert signals[0].event_count == unknown_count
    assert all(e.event_type == NginxAccessEventType.UNKNOWN for e in signals[0].raw_evidence)
    assert len(signals[0].raw_evidence) == unknown_count


def test_d2_parse_failure_below_threshold_no_signal():
    total = 200
    unknown_count = int(total * HIGH_PARSE_FAILURE_RATE_THRESHOLD) - 1
    events = [_unknown() for _ in range(unknown_count)]
    events += [_parsed() for _ in range(total - unknown_count)]
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    assert _signals_of_type(result, NginxAccessSignalType.HIGH_PARSE_FAILURE_RATE) == []


def test_d3_zero_percent_unknown_no_signal():
    events = [_parsed() for _ in range(200)]
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    assert _signals_of_type(result, NginxAccessSignalType.HIGH_PARSE_FAILURE_RATE) == []


def test_d4_hundred_percent_unknown_produces_signal():
    events = [_unknown() for _ in range(200)]
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    signals = _signals_of_type(result, NginxAccessSignalType.HIGH_PARSE_FAILURE_RATE)
    assert len(signals) == 1
    assert signals[0].event_count == 200


def test_d5_empty_collection_no_parse_failure_signal():
    result = detect_access_signals([], CoverageStatus.EMPTY)
    assert _signals_of_type(result, NginxAccessSignalType.HIGH_PARSE_FAILURE_RATE) == []


# ===========================================================================
# GROUP E — Coverage / detection_succeeded interaction
# ===========================================================================


def test_e1_empty_coverage_succeeded_true_no_signals():
    result = detect_access_signals([], CoverageStatus.EMPTY)
    assert result.coverage == CoverageStatus.EMPTY
    assert result.detection_succeeded is True
    assert result.signals == []


def test_e2_failed_coverage_succeeded_false_no_signals():
    events = [_parsed(status=404) for _ in range(HIGH_4XX_RATE_THRESHOLD)]
    result = detect_access_signals(events, CoverageStatus.FAILED)
    assert result.coverage == CoverageStatus.FAILED
    assert result.detection_succeeded is False
    assert result.signals == []


def test_e3_complete_coverage_mixed_parsed_and_unknown_both_signal_families_run():
    events = [_parsed(status=404) for _ in range(HIGH_4XX_RATE_THRESHOLD)]
    events += [_unknown() for _ in range(len(events))]
    result = detect_access_signals(events, CoverageStatus.COMPLETE)
    assert result.coverage == CoverageStatus.COMPLETE
    assert result.detection_succeeded is True
    assert len(_signals_of_type(result, NginxAccessSignalType.HIGH_4XX_RATE)) == 1
    assert len(_signals_of_type(result, NginxAccessSignalType.HIGH_PARSE_FAILURE_RATE)) == 1


def test_e4_unknown_coverage_succeeded_false_no_signals():
    events = [_parsed(status=404) for _ in range(HIGH_4XX_RATE_THRESHOLD)]
    result = detect_access_signals(events, CoverageStatus.UNKNOWN)
    assert result.coverage == CoverageStatus.UNKNOWN
    assert result.detection_succeeded is False
    assert result.signals == []


def test_e5_partial_coverage_succeeded_true_detection_runs_coverage_stays_partial():
    events = [_parsed(status=404) for _ in range(HIGH_4XX_RATE_THRESHOLD)]
    result = detect_access_signals(events, CoverageStatus.PARTIAL)
    assert result.coverage == CoverageStatus.PARTIAL
    assert result.detection_succeeded is True
    assert len(_signals_of_type(result, NginxAccessSignalType.HIGH_4XX_RATE)) == 1
