"""RED tests for nginx_findings.py — Findings Contract v1.

Scenario Table v1 (groups A-F, ~50+ checks):
  Group A: Signal -> Finding mapping (1:1 instance, event_count/raw_evidence preserved)
  Group B: Static severity (per signal_type, not event_count)
  Group C: Detail contract (deterministic, per-type mandatory fields, no attribution)
  Group D: Recommendation contract (static per signal_type, not severity/coverage)
  Group E: Coverage / confidence
  Group F: Cross-signal invariants

Every test traces back to a scenario in the frozen Scenario Table.
"""

from __future__ import annotations

from datetime import datetime, timezone

from netaudit_pkg.nginx_access_detection import (
    HIGH_4XX_RATE_THRESHOLD,
    HIGH_5XX_RATE_THRESHOLD,
    PATH_SCAN_DISTINCT_PATHS_THRESHOLD,
    REQUEST_BURST_THRESHOLD,
    REQUEST_BURST_WINDOW_SECONDS,
    NginxAccessDetectionResult,
    NginxAccessSignal,
    NginxAccessSignalType,
)
from netaudit_pkg.nginx_access_detection import (
    CoverageStatus as AccessCoverageStatus,
)
from netaudit_pkg.nginx_access_parser import NginxAccessEvent, NginxAccessEventType
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
from netaudit_pkg.nginx_error_parser import (
    NginxErrorEvent,
    NginxErrorEventType,
    NginxErrorSeverity,
)
from netaudit_pkg.nginx_findings import (
    build_access_findings,
    build_error_findings,
)

_BASE_TS = datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Fixture helpers — Access side
# ---------------------------------------------------------------------------


def _access_event(ip="203.0.113.10", status=404, request="GET /foo HTTP/1.1", ts=None) -> NginxAccessEvent:
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
        raw_line="fixture",
    )


def _access_unknown() -> NginxAccessEvent:
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
        raw_line="garbage",
    )


def _high_4xx_signal(ip="203.0.113.10", count=HIGH_4XX_RATE_THRESHOLD) -> NginxAccessSignal:
    evidence = [_access_event(ip=ip, status=404) for _ in range(count)]
    return NginxAccessSignal(
        signal_type=NginxAccessSignalType.HIGH_4XX_RATE,
        ip=ip,
        event_count=count,
        window_start=None,
        window_end=None,
        raw_evidence=evidence,
    )


def _high_5xx_signal(ip="203.0.113.10", count=HIGH_5XX_RATE_THRESHOLD) -> NginxAccessSignal:
    evidence = [_access_event(ip=ip, status=500) for _ in range(count)]
    return NginxAccessSignal(
        signal_type=NginxAccessSignalType.HIGH_5XX_RATE,
        ip=ip,
        event_count=count,
        window_start=None,
        window_end=None,
        raw_evidence=evidence,
    )


def _path_scan_signal(ip="203.0.113.10", distinct=PATH_SCAN_DISTINCT_PATHS_THRESHOLD, all_404=True):
    evidence = [
        _access_event(ip=ip, status=404 if all_404 else 200, request=f"GET /p{i} HTTP/1.1")
        for i in range(distinct)
    ]
    return NginxAccessSignal(
        signal_type=NginxAccessSignalType.PATH_SCAN,
        ip=ip,
        event_count=distinct,
        window_start=None,
        window_end=None,
        raw_evidence=evidence,
    )


def _request_burst_signal(ip="203.0.113.10", count=REQUEST_BURST_THRESHOLD):
    evidence = [_access_event(ip=ip, ts=_BASE_TS) for _ in range(count)]
    return NginxAccessSignal(
        signal_type=NginxAccessSignalType.REQUEST_BURST,
        ip=ip,
        event_count=count,
        window_start=_BASE_TS,
        window_end=_BASE_TS.replace(second=REQUEST_BURST_WINDOW_SECONDS),
        raw_evidence=evidence,
    )


def _parse_failure_signal(count=50):
    evidence = [_access_unknown() for _ in range(count)]
    return NginxAccessSignal(
        signal_type=NginxAccessSignalType.HIGH_PARSE_FAILURE_RATE,
        ip=None,
        event_count=count,
        window_start=None,
        window_end=None,
        raw_evidence=evidence,
    )


def _access_result(signals, coverage=AccessCoverageStatus.COMPLETE, succeeded=True):
    return NginxAccessDetectionResult(coverage=coverage, detection_succeeded=succeeded, signals=signals)


# ---------------------------------------------------------------------------
# Fixture helpers — Error side
# ---------------------------------------------------------------------------


def _error_event(severity=NginxErrorSeverity.ERROR, message="connect() failed") -> NginxErrorEvent:
    return NginxErrorEvent(
        event_type=NginxErrorEventType.PARSED,
        timestamp=None,
        severity=severity,
        pid=1000,
        tid=0,
        connection_id=None,
        message=message,
        raw_line="fixture",
    )


def _high_error_rate_signal(count=HIGH_ERROR_RATE_THRESHOLD) -> NginxErrorSignal:
    evidence = [_error_event(severity=NginxErrorSeverity.ERROR) for _ in range(count)]
    return NginxErrorSignal(
        signal_type=NginxErrorSignalType.HIGH_ERROR_RATE,
        message_key=None,
        event_count=count,
        raw_evidence=evidence,
    )


def _critical_error_signal(count=1) -> NginxErrorSignal:
    evidence = [_error_event(severity=NginxErrorSeverity.CRIT) for _ in range(count)]
    return NginxErrorSignal(
        signal_type=NginxErrorSignalType.CRITICAL_ERROR,
        message_key=None,
        event_count=count,
        raw_evidence=evidence,
    )


def _repeated_error_signal(message="same message", count=REPEATED_ERROR_THRESHOLD) -> NginxErrorSignal:
    evidence = [_error_event(message=message) for _ in range(count)]
    return NginxErrorSignal(
        signal_type=NginxErrorSignalType.REPEATED_ERROR,
        message_key=message,
        event_count=count,
        raw_evidence=evidence,
    )


def _error_result(signals, coverage=ErrorCoverageStatus.COMPLETE, succeeded=True):
    return NginxErrorDetectionResult(coverage=coverage, detection_succeeded=succeeded, signals=signals)


# ===========================================================================
# GROUP A — Signal -> Finding mapping
# ===========================================================================


def test_a1_high_4xx_signal_produces_one_finding():
    result = _access_result([_high_4xx_signal()])
    findings = build_access_findings(result)
    assert len(findings) == 1
    assert findings[0].finding_type == NginxAccessSignalType.HIGH_4XX_RATE.value


def test_a2_high_5xx_signal_produces_one_finding():
    result = _access_result([_high_5xx_signal()])
    findings = build_access_findings(result)
    assert len(findings) == 1
    assert findings[0].finding_type == NginxAccessSignalType.HIGH_5XX_RATE.value


def test_a3_path_scan_signal_produces_one_finding():
    result = _access_result([_path_scan_signal()])
    findings = build_access_findings(result)
    assert len(findings) == 1
    assert findings[0].finding_type == NginxAccessSignalType.PATH_SCAN.value


def test_a4_request_burst_signal_produces_one_finding():
    result = _access_result([_request_burst_signal()])
    findings = build_access_findings(result)
    assert len(findings) == 1
    assert findings[0].finding_type == NginxAccessSignalType.REQUEST_BURST.value


def test_a5_high_error_rate_signal_produces_one_finding():
    result = _error_result([_high_error_rate_signal()])
    findings = build_error_findings(result)
    assert len(findings) == 1
    assert findings[0].finding_type == NginxErrorSignalType.HIGH_ERROR_RATE.value


def test_a6_critical_error_signal_produces_one_finding():
    result = _error_result([_critical_error_signal()])
    findings = build_error_findings(result)
    assert len(findings) == 1
    assert findings[0].finding_type == NginxErrorSignalType.CRITICAL_ERROR.value


def test_a7_repeated_error_signal_produces_one_finding():
    result = _error_result([_repeated_error_signal()])
    findings = build_error_findings(result)
    assert len(findings) == 1
    assert findings[0].finding_type == NginxErrorSignalType.REPEATED_ERROR.value


def test_a8_three_repeated_error_signals_produce_three_findings_no_aggregation():
    signals = [
        _repeated_error_signal(message="message A"),
        _repeated_error_signal(message="message B"),
        _repeated_error_signal(message="message C"),
    ]
    result = _error_result(signals)
    findings = build_error_findings(result)
    assert len(findings) == 3
    assert all(f.finding_type == NginxErrorSignalType.REPEATED_ERROR.value for f in findings)


def test_a9_event_count_equals_len_raw_evidence_preserved_in_finding():
    signal = _high_4xx_signal(count=17)
    result = _access_result([signal])
    findings = build_access_findings(result)
    assert findings[0].event_count == 17
    assert len(findings[0].raw_evidence) == 17


def test_a10_signal_raw_evidence_fully_preserved_not_truncated():
    signal = _repeated_error_signal(count=250)
    result = _error_result([signal])
    findings = build_error_findings(result)
    assert findings[0].event_count == 250
    assert len(findings[0].raw_evidence) == 250


# ===========================================================================
# GROUP B — Static severity mapping
# ===========================================================================


def test_b1_high_4xx_rate_severity_is_low():
    result = _access_result([_high_4xx_signal()])
    assert build_access_findings(result)[0].severity == "low"


def test_b2_high_5xx_rate_severity_is_medium():
    result = _access_result([_high_5xx_signal()])
    assert build_access_findings(result)[0].severity == "medium"


def test_b3_path_scan_severity_is_medium():
    result = _access_result([_path_scan_signal()])
    assert build_access_findings(result)[0].severity == "medium"


def test_b4_request_burst_severity_is_low():
    result = _access_result([_request_burst_signal()])
    assert build_access_findings(result)[0].severity == "low"


def test_b5_high_error_rate_severity_is_medium():
    result = _error_result([_high_error_rate_signal()])
    assert build_error_findings(result)[0].severity == "medium"


def test_b6_critical_error_severity_is_high():
    result = _error_result([_critical_error_signal()])
    assert build_error_findings(result)[0].severity == "high"


def test_b7_repeated_error_severity_is_medium():
    result = _error_result([_repeated_error_signal()])
    assert build_error_findings(result)[0].severity == "medium"


def test_b8_severity_does_not_scale_with_event_count():
    small = _access_result([_high_4xx_signal(count=HIGH_4XX_RATE_THRESHOLD)])
    large = _access_result([_high_4xx_signal(count=500)])
    sev_small = build_access_findings(small)[0].severity
    sev_large = build_access_findings(large)[0].severity
    assert sev_small == sev_large == "low"


def test_b9_severity_does_not_rise_when_threshold_significantly_exceeded():
    result = _error_result([_high_error_rate_signal(count=10_000)])
    assert build_error_findings(result)[0].severity == "medium"


# ===========================================================================
# GROUP C — Detail contract
# ===========================================================================


def test_c1_high_4xx_detail_contains_ip_count_threshold():
    result = _access_result([_high_4xx_signal(ip="198.51.100.5", count=HIGH_4XX_RATE_THRESHOLD)])
    detail = build_access_findings(result)[0].detail
    assert "198.51.100.5" in detail
    assert str(HIGH_4XX_RATE_THRESHOLD) in detail


def test_c2_high_4xx_detail_says_4xx_not_specific_code():
    result = _access_result([_high_4xx_signal()])
    detail = build_access_findings(result)[0].detail
    assert "4xx" in detail
    assert "404" not in detail


def test_c3_high_4xx_detail_deterministic_for_large_count():
    result = _access_result([_high_4xx_signal(count=500)])
    detail1 = build_access_findings(result)[0].detail
    detail2 = build_access_findings(result)[0].detail
    assert detail1 == detail2


def test_c4_high_5xx_detail_contains_ip_count_threshold():
    result = _access_result([_high_5xx_signal(ip="198.51.100.5", count=HIGH_5XX_RATE_THRESHOLD)])
    detail = build_access_findings(result)[0].detail
    assert "198.51.100.5" in detail
    assert str(HIGH_5XX_RATE_THRESHOLD) in detail


def test_c5_high_5xx_detail_says_5xx_not_specific_code():
    result = _access_result([_high_5xx_signal()])
    detail = build_access_findings(result)[0].detail
    assert "5xx" in detail


def test_c6_high_5xx_detail_does_not_attribute_cause():
    result = _access_result([_high_5xx_signal()])
    detail = build_access_findings(result)[0].detail.lower()
    assert "overload" not in detail
    assert "backend failure" not in detail


def test_c7_path_scan_detail_contains_ip_distinct_count_and_ratio():
    result = _access_result([_path_scan_signal(ip="198.51.100.5", distinct=PATH_SCAN_DISTINCT_PATHS_THRESHOLD)])
    detail = build_access_findings(result)[0].detail
    assert "198.51.100.5" in detail
    assert str(PATH_SCAN_DISTINCT_PATHS_THRESHOLD) in detail
    assert "%" in detail


def test_c8_path_scan_ratio_matches_detection_ratio_invariant():
    signal = _path_scan_signal(distinct=PATH_SCAN_DISTINCT_PATHS_THRESHOLD, all_404=True)
    result = _access_result([signal])
    detail = build_access_findings(result)[0].detail
    # all_404=True means 100% ratio must appear
    assert "100%" in detail


def test_c9_path_scan_query_strings_do_not_change_distinct_count():
    ip = "203.0.113.10"
    evidence = [
        _access_event(ip=ip, status=404, request=f"GET /foo?x={i} HTTP/1.1")
        for i in range(PATH_SCAN_DISTINCT_PATHS_THRESHOLD)
    ]
    signal = NginxAccessSignal(
        signal_type=NginxAccessSignalType.PATH_SCAN,
        ip=ip,
        event_count=1,  # detection already collapsed these to 1 distinct path in its own accounting
        window_start=None,
        window_end=None,
        raw_evidence=evidence,
    )
    result = _access_result([signal])
    detail = build_access_findings(result)[0].detail
    assert "1" in detail  # should reflect 1 distinct path, not len(evidence)


def test_c10_path_scan_detail_has_no_semantic_classification():
    result = _access_result([_path_scan_signal()])
    detail = build_access_findings(result)[0].detail.lower()
    assert "wordpress" not in detail
    assert "phpmyadmin" not in detail


def test_c11_path_scan_detail_does_not_name_attack_type():
    result = _access_result([_path_scan_signal()])
    detail = build_access_findings(result)[0].detail.lower()
    assert "attack" not in detail
    assert "credential" not in detail


def test_c12_request_burst_detail_contains_ip_count_window_threshold():
    result = _access_result([_request_burst_signal(ip="198.51.100.5")])
    detail = build_access_findings(result)[0].detail
    assert "198.51.100.5" in detail
    assert str(REQUEST_BURST_THRESHOLD) in detail


def test_c13_request_burst_detail_reflects_actual_event_count():
    result = _access_result([_request_burst_signal(count=REQUEST_BURST_THRESHOLD + 30)])
    detail = build_access_findings(result)[0].detail
    assert str(REQUEST_BURST_THRESHOLD + 30) in detail


def test_c14_request_burst_detail_does_not_name_ddos_or_bruteforce():
    result = _access_result([_request_burst_signal()])
    detail = build_access_findings(result)[0].detail.lower()
    assert "ddos" not in detail
    assert "brute" not in detail


def test_c15_high_error_rate_detail_contains_count_and_threshold():
    result = _error_result([_high_error_rate_signal()])
    detail = build_error_findings(result)[0].detail
    assert str(HIGH_ERROR_RATE_THRESHOLD) in detail


def test_c16_high_error_rate_detail_has_no_ip_field():
    result = _error_result([_high_error_rate_signal()])
    detail = build_error_findings(result)[0].detail
    assert "203.0.113" not in detail  # no IP fixture value should ever appear


def test_c17_high_error_rate_detail_no_cause_assumption():
    result = _error_result([_high_error_rate_signal()])
    detail = build_error_findings(result)[0].detail.lower()
    assert "caused by" not in detail


def test_c18_critical_error_detail_single_crit_count_is_one():
    result = _error_result([_critical_error_signal(count=1)])
    detail = build_error_findings(result)[0].detail
    assert "1" in detail


def test_c19_critical_error_detail_aggregated_mixed_severities_shows_total_count():
    signal = NginxErrorSignal(
        signal_type=NginxErrorSignalType.CRITICAL_ERROR,
        message_key=None,
        event_count=4,
        raw_evidence=[_error_event(severity=s) for s in
                      (NginxErrorSeverity.CRIT, NginxErrorSeverity.CRIT,
                       NginxErrorSeverity.ALERT, NginxErrorSeverity.EMERG)],
    )
    result = _error_result([signal])
    detail = build_error_findings(result)[0].detail
    assert "4" in detail


def test_c20_critical_error_detail_mentions_severity_terms():
    result = _error_result([_critical_error_signal()])
    detail = build_error_findings(result)[0].detail.lower()
    assert "crit" in detail or "alert" in detail or "emerg" in detail


def test_c21_critical_error_threshold_not_required_in_detail():
    # threshold=1 is trivial; this test just documents that the builder
    # does not need to mention it (no assertion of ABSENCE required to
    # pass, but detail must still be non-empty and deterministic)
    result = _error_result([_critical_error_signal()])
    detail = build_error_findings(result)[0].detail
    assert detail  # non-empty, deterministic content is enough


def test_c22_repeated_error_detail_contains_message_key_count_threshold():
    result = _error_result([_repeated_error_signal(message="connect() failed upstream")])
    detail = build_error_findings(result)[0].detail
    assert "connect() failed upstream" in detail
    assert str(REPEATED_ERROR_THRESHOLD) in detail


def test_c23_repeated_error_detail_keeps_client_request_upstream_verbatim():
    msg = 'connect() failed, client: 1.2.3.4, request: "GET / HTTP/1.1", upstream: "http://127.0.0.1:8080/"'
    result = _error_result([_repeated_error_signal(message=msg)])
    detail = build_error_findings(result)[0].detail
    assert msg in detail


def test_c24_repeated_error_detail_no_ip_substitution():
    msg = "error involving 10.0.0.5"
    result = _error_result([_repeated_error_signal(message=msg)])
    detail = build_error_findings(result)[0].detail
    assert "10.0.0.5" in detail
    assert "<IP>" not in detail


def test_c25_repeated_error_detail_with_special_chars_deterministic():
    msg = 'weird "quoted" message with \\ backslash'
    result = _error_result([_repeated_error_signal(message=msg)])
    d1 = build_error_findings(result)[0].detail
    d2 = build_error_findings(result)[0].detail
    assert d1 == d2
    assert msg in d1


def test_c26_repeated_error_two_message_keys_two_findings():
    signals = [_repeated_error_signal(message="A"), _repeated_error_signal(message="B")]
    result = _error_result(signals)
    findings = build_error_findings(result)
    assert len(findings) == 2


def test_c27_repeated_error_all_n_evidence_preserved():
    result = _error_result([_repeated_error_signal(count=123)])
    findings = build_error_findings(result)
    assert findings[0].event_count == 123
    assert len(findings[0].raw_evidence) == 123


# ===========================================================================
# GROUP D — Recommendation contract
# ===========================================================================


def test_d1_high_4xx_recommendation_is_policy_text():
    result = _access_result([_high_4xx_signal()])
    rec = build_access_findings(result)[0].recommendation
    assert rec  # non-empty, exact wording checked structurally elsewhere


def test_d2_high_5xx_recommendation_is_policy_text():
    result = _access_result([_high_5xx_signal()])
    assert build_access_findings(result)[0].recommendation


def test_d3_path_scan_recommendation_does_not_assert_attack_type():
    result = _access_result([_path_scan_signal()])
    rec = build_access_findings(result)[0].recommendation.lower()
    assert "wordpress" not in rec
    assert "sql injection" not in rec


def test_d4_request_burst_recommendation_not_ddos_or_bruteforce():
    result = _access_result([_request_burst_signal()])
    rec = build_access_findings(result)[0].recommendation.lower()
    assert "ddos" not in rec
    assert "brute" not in rec


def test_d5_high_error_rate_recommendation_no_specific_cause():
    result = _error_result([_high_error_rate_signal()])
    rec = build_error_findings(result)[0].recommendation.lower()
    assert "caused by" not in rec


def test_d6_critical_error_recommendation_keeps_immediately():
    result = _error_result([_critical_error_signal()])
    rec = build_error_findings(result)[0].recommendation
    assert "Immediately" in rec or "immediately" in rec


def test_d7_repeated_error_recommendation_does_not_interpret_message_content():
    result = _error_result([_repeated_error_signal(message="connect() failed")])
    rec = build_error_findings(result)[0].recommendation
    assert "connect() failed" not in rec  # message content stays in detail, not recommendation


def test_d8_same_signal_complete_vs_partial_same_recommendation():
    signal = _high_4xx_signal()
    complete_result = _access_result([signal], coverage=AccessCoverageStatus.COMPLETE)
    partial_result = _access_result([signal], coverage=AccessCoverageStatus.PARTIAL)
    rec_complete = build_access_findings(complete_result)[0].recommendation
    rec_partial = build_access_findings(partial_result)[0].recommendation
    assert rec_complete == rec_partial


def test_d9_recommendation_is_not_function_of_severity():
    # HIGH_5XX_RATE (medium) and REPEATED_ERROR (medium) share severity but
    # must have DIFFERENT recommendations, proving recommendation isn't
    # derived from severity alone.
    access_result = _access_result([_high_5xx_signal()])
    error_result = _error_result([_repeated_error_signal()])
    rec1 = build_access_findings(access_result)[0].recommendation
    rec2 = build_error_findings(error_result)[0].recommendation
    assert rec1 != rec2


# ===========================================================================
# GROUP E — Coverage / confidence
# ===========================================================================


def test_e1_complete_coverage_confidence_high():
    result = _access_result([_high_4xx_signal()], coverage=AccessCoverageStatus.COMPLETE)
    assert build_access_findings(result)[0].confidence == "high"


def test_e2_partial_coverage_confidence_medium():
    result = _access_result([_high_4xx_signal()], coverage=AccessCoverageStatus.PARTIAL)
    assert build_access_findings(result)[0].confidence == "medium"


def test_e3_empty_coverage_no_findings():
    result = _access_result([], coverage=AccessCoverageStatus.EMPTY, succeeded=True)
    assert build_access_findings(result) == []


def test_e4_failed_coverage_no_findings_even_with_signals_present():
    # defensive: even if a signal were somehow present, FAILED means we
    # don't trust it enough to build a Finding
    result = _access_result([_high_4xx_signal()], coverage=AccessCoverageStatus.FAILED, succeeded=False)
    assert build_access_findings(result) == []


def test_e5_unknown_coverage_no_findings():
    result = _access_result([_high_4xx_signal()], coverage=AccessCoverageStatus.UNKNOWN, succeeded=False)
    assert build_access_findings(result) == []


def test_e6_complete_coverage_confidence_not_lowered_by_parser_quality():
    # PATH_SCAN signal alongside implied high UNKNOWN ratio (parser
    # quality) must still yield confidence=high; parser quality is a
    # separate concern (HIGH_PARSE_FAILURE_RATE), not folded into confidence
    result = _access_result(
        [_path_scan_signal(), _parse_failure_signal(count=500)],
        coverage=AccessCoverageStatus.COMPLETE,
    )
    findings = build_access_findings(result)
    path_scan_finding = next(f for f in findings if f.finding_type == NginxAccessSignalType.PATH_SCAN.value)
    assert path_scan_finding.confidence == "high"


def test_e7_partial_coverage_confidence_determined_by_coverage_not_extra_formula():
    result = _access_result([_high_4xx_signal()], coverage=AccessCoverageStatus.PARTIAL)
    assert build_access_findings(result)[0].confidence == "medium"


def test_e8_high_parse_failure_rate_never_creates_a_finding():
    result = _access_result([_parse_failure_signal()], coverage=AccessCoverageStatus.COMPLETE)
    findings = build_access_findings(result)
    assert findings == []


def test_e9_high_parse_failure_rate_alongside_other_signals_is_excluded_but_others_remain():
    result = _access_result(
        [_high_4xx_signal(), _parse_failure_signal()],
        coverage=AccessCoverageStatus.COMPLETE,
    )
    findings = build_access_findings(result)
    types = {f.finding_type for f in findings}
    assert NginxAccessSignalType.HIGH_4XX_RATE.value in types
    assert NginxAccessSignalType.HIGH_PARSE_FAILURE_RATE.value not in types
    assert len(findings) == 1


# ===========================================================================
# GROUP F — Cross-signal invariants
# ===========================================================================


def test_f1_access_and_error_findings_are_independent_builders():
    access_result = _access_result([_high_4xx_signal()])
    error_result = _error_result([_critical_error_signal()])
    access_findings = build_access_findings(access_result)
    error_findings = build_error_findings(error_result)
    assert len(access_findings) == 1
    assert len(error_findings) == 1
    combined = [*access_findings, *error_findings]
    assert len(combined) == 2


def test_f2_path_scan_and_high_4xx_on_same_ip_two_independent_findings():
    result = _access_result([_path_scan_signal(), _high_4xx_signal()])
    findings = build_access_findings(result)
    assert len(findings) == 2
    types = {f.finding_type for f in findings}
    assert types == {NginxAccessSignalType.PATH_SCAN.value, NginxAccessSignalType.HIGH_4XX_RATE.value}


def test_f3_critical_error_and_high_error_rate_two_independent_findings():
    result = _error_result([_critical_error_signal(), _high_error_rate_signal()])
    findings = build_error_findings(result)
    assert len(findings) == 2
    types = {f.finding_type for f in findings}
    assert types == {NginxErrorSignalType.CRITICAL_ERROR.value, NginxErrorSignalType.HIGH_ERROR_RATE.value}


def test_f4_repeated_error_and_critical_error_same_events_two_independent_findings():
    evidence = [_error_event(severity=NginxErrorSeverity.CRIT, message="recurring crit") for _ in range(REPEATED_ERROR_THRESHOLD)]
    repeated = NginxErrorSignal(
        signal_type=NginxErrorSignalType.REPEATED_ERROR,
        message_key="recurring crit",
        event_count=REPEATED_ERROR_THRESHOLD,
        raw_evidence=evidence,
    )
    critical = NginxErrorSignal(
        signal_type=NginxErrorSignalType.CRITICAL_ERROR,
        message_key=None,
        event_count=REPEATED_ERROR_THRESHOLD,
        raw_evidence=evidence,
    )
    result = _error_result([repeated, critical])
    findings = build_error_findings(result)
    assert len(findings) == 2


def test_f5_three_distinct_repeated_error_keys_three_findings():
    signals = [_repeated_error_signal(message=m) for m in ("A", "B", "C")]
    result = _error_result(signals)
    assert len(build_error_findings(result)) == 3


def test_f6_large_event_count_does_not_change_severity():
    result = _access_result([_high_4xx_signal(count=500)])
    assert build_access_findings(result)[0].severity == "low"


def test_f7_partial_coverage_does_not_change_severity():
    result = _access_result([_high_4xx_signal()], coverage=AccessCoverageStatus.PARTIAL)
    assert build_access_findings(result)[0].severity == "low"


def test_f8_partial_coverage_does_not_change_recommendation():
    complete_result = _access_result([_high_4xx_signal()], coverage=AccessCoverageStatus.COMPLETE)
    partial_result = _access_result([_high_4xx_signal()], coverage=AccessCoverageStatus.PARTIAL)
    assert (
        build_access_findings(complete_result)[0].recommendation
        == build_access_findings(partial_result)[0].recommendation
    )


def test_f9_parser_quality_signal_does_not_change_other_findings_severity_or_recommendation():
    without_parse_issue = _access_result([_high_4xx_signal()])
    with_parse_issue = _access_result([_high_4xx_signal(), _parse_failure_signal(count=1000)])
    f1 = next(f for f in build_access_findings(without_parse_issue) if f.finding_type == NginxAccessSignalType.HIGH_4XX_RATE.value)
    f2 = next(f for f in build_access_findings(with_parse_issue) if f.finding_type == NginxAccessSignalType.HIGH_4XX_RATE.value)
    assert f1.severity == f2.severity
    assert f1.recommendation == f2.recommendation


def test_f10_coverage_diagnostic_channel_never_appears_as_security_finding():
    result = _access_result([_parse_failure_signal()], coverage=AccessCoverageStatus.COMPLETE)
    findings = build_access_findings(result)
    assert all(f.finding_type != NginxAccessSignalType.HIGH_PARSE_FAILURE_RATE.value for f in findings)
