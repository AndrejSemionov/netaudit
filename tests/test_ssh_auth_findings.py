"""Tests for netaudit_pkg.ssh_auth_findings — Finding Contract (Findings
layer). Written test-first, before implementation, per project
methodology: contract freeze -> test matrix -> tests -> implementation.

Test matrix (agreed, do not reorder/skip):
  1  info finding — single failure/invalid_user
  2  low finding — 2-4 failures, below reference threshold
  3  high finding — >=5 failures, at/above reference threshold
  4  detail cites its threshold source explicitly
  5  coverage_uncertain=True -> confidence='medium', severity unchanged
  6  coverage_uncertain=False -> confidence='high' (baseline)
  7  high + coverage_uncertain=True -> requires_manual_verification=True
  8  low/info + coverage_uncertain=True -> requires_manual_verification
     stays False (no automatic escalation)
  9  one DetectionSignal -> exactly one Finding
  10 overlapping signals (same IP in two signal types) -> two
     independent Findings, no merge
  11 evidence contains ALL raw_line values, no truncation even for many events
  12 recommendation is empty/neutral when fail2ban state is unknown
  13 invalid_user enumeration: severity depends on count AND diversity
     independently
  14 distributed signal (username, >=2 IPs) uses distributed_ip_threshold,
     rationale cites "NetAudit policy", not Fail2Ban
  15 successful Detection + zero signals -> exactly one 'ok' Finding
  16 (gate) detection_succeeded=False -> empty findings list, no 'ok'
     finding fabricated from an empty/failed run
"""

from __future__ import annotations

from netaudit_pkg.ssh_auth_detection import (
    DetectionResult,
    RepeatedFailuresForUsernameSignal,
    RepeatedFailuresFromIPSignal,
    SuccessAfterFailureSignal,
)
from netaudit_pkg.ssh_auth_findings import DEFAULT_POLICY, build_findings
from netaudit_pkg.ssh_auth_parser import AuthMethod, SSHAuthEvent, SSHAuthEventType
from datetime import datetime, timezone


def _event(event_type, username=None, source_ip=None, auth_method=None,
           timestamp=None, raw_line=None) -> SSHAuthEvent:
    return SSHAuthEvent(
        timestamp=timestamp or datetime(2026, 8, 18, 10, 0, tzinfo=timezone.utc),
        event_type=event_type, username=username, source_ip=source_ip, auth_method=auth_method,
        pid=None, raw_line=raw_line or f'{event_type.value} {username}@{source_ip}',
    )


def _empty_result(**overrides) -> DetectionResult:
    base = dict(
        repeated_failures_by_ip=[], repeated_failures_by_username=[],
        success_after_failure=[], undated_event_count=0, coverage_uncertain=False,
    )
    base.update(overrides)
    return DetectionResult(**base)


# ===========================================================================
# 1. info finding — single failure
# ===========================================================================


def test_single_failure_is_info():
    signal = RepeatedFailuresFromIPSignal(
        source_ip='1.2.3.4', failed_password_count=1, invalid_user_count=0,
        invalid_usernames=set(), events=[_event(SSHAuthEventType.FAILED_PASSWORD, source_ip='1.2.3.4')],
    )
    result = _empty_result(repeated_failures_by_ip=[signal])
    findings = build_findings(result, detection_succeeded=True)

    ip_findings = [f for f in findings if f['severity'] != 'ok']
    assert len(ip_findings) == 1
    assert ip_findings[0]['severity'] == 'info'


# ===========================================================================
# 2. low finding — 2-4 failures
# ===========================================================================


def test_two_to_four_failures_is_low():
    events = [_event(SSHAuthEventType.FAILED_PASSWORD, source_ip='1.2.3.4') for _ in range(3)]
    signal = RepeatedFailuresFromIPSignal(
        source_ip='1.2.3.4', failed_password_count=3, invalid_user_count=0,
        invalid_usernames=set(), events=events,
    )
    result = _empty_result(repeated_failures_by_ip=[signal])
    findings = build_findings(result, detection_succeeded=True)

    ip_findings = [f for f in findings if f['severity'] != 'ok']
    assert len(ip_findings) == 1
    assert ip_findings[0]['severity'] == 'low'


# ===========================================================================
# 3. high finding — >=5 failures (reference_maxretry default)
# ===========================================================================


def test_five_or_more_failures_is_high():
    events = [_event(SSHAuthEventType.FAILED_PASSWORD, source_ip='1.2.3.4') for _ in range(5)]
    signal = RepeatedFailuresFromIPSignal(
        source_ip='1.2.3.4', failed_password_count=5, invalid_user_count=0,
        invalid_usernames=set(), events=events,
    )
    result = _empty_result(repeated_failures_by_ip=[signal])
    findings = build_findings(result, detection_succeeded=True)

    ip_findings = [f for f in findings if f['severity'] != 'ok']
    assert len(ip_findings) == 1
    assert ip_findings[0]['severity'] == 'high'


# ===========================================================================
# 4. detail cites the threshold source explicitly
# ===========================================================================


def test_high_finding_detail_cites_fail2ban_reference():
    events = [_event(SSHAuthEventType.FAILED_PASSWORD, source_ip='1.2.3.4') for _ in range(5)]
    signal = RepeatedFailuresFromIPSignal(
        source_ip='1.2.3.4', failed_password_count=5, invalid_user_count=0,
        invalid_usernames=set(), events=events,
    )
    result = _empty_result(repeated_failures_by_ip=[signal])
    findings = build_findings(result, detection_succeeded=True)

    high_finding = next(f for f in findings if f['severity'] == 'high')
    assert 'Fail2Ban' in high_finding['detail']
    assert '5' in high_finding['detail']


# ===========================================================================
# 5/6. coverage_uncertain -> confidence, never severity
# ===========================================================================


def test_coverage_uncertain_true_downgrades_confidence_not_severity():
    events = [_event(SSHAuthEventType.FAILED_PASSWORD, source_ip='1.2.3.4') for _ in range(5)]
    signal = RepeatedFailuresFromIPSignal(
        source_ip='1.2.3.4', failed_password_count=5, invalid_user_count=0,
        invalid_usernames=set(), events=events,
    )
    result = _empty_result(repeated_failures_by_ip=[signal], coverage_uncertain=True)
    findings = build_findings(result, detection_succeeded=True)

    high_finding = next(f for f in findings if f['severity'] == 'high')
    assert high_finding['confidence'] == 'medium'
    assert high_finding['severity'] == 'high'  # unchanged


def test_coverage_uncertain_false_keeps_confidence_high():
    events = [_event(SSHAuthEventType.FAILED_PASSWORD, source_ip='1.2.3.4') for _ in range(5)]
    signal = RepeatedFailuresFromIPSignal(
        source_ip='1.2.3.4', failed_password_count=5, invalid_user_count=0,
        invalid_usernames=set(), events=events,
    )
    result = _empty_result(repeated_failures_by_ip=[signal], coverage_uncertain=False)
    findings = build_findings(result, detection_succeeded=True)

    high_finding = next(f for f in findings if f['severity'] == 'high')
    assert high_finding['confidence'] == 'high'


# ===========================================================================
# 7/8. requires_manual_verification — policy, not automatic from confidence
# ===========================================================================


def test_high_plus_coverage_uncertain_requires_manual_verification():
    events = [_event(SSHAuthEventType.FAILED_PASSWORD, source_ip='1.2.3.4') for _ in range(5)]
    signal = RepeatedFailuresFromIPSignal(
        source_ip='1.2.3.4', failed_password_count=5, invalid_user_count=0,
        invalid_usernames=set(), events=events,
    )
    result = _empty_result(repeated_failures_by_ip=[signal], coverage_uncertain=True)
    findings = build_findings(result, detection_succeeded=True)

    high_finding = next(f for f in findings if f['severity'] == 'high')
    assert high_finding.get('requires_manual_verification') is True


def test_low_plus_coverage_uncertain_does_not_require_manual_verification():
    events = [_event(SSHAuthEventType.FAILED_PASSWORD, source_ip='1.2.3.4') for _ in range(2)]
    signal = RepeatedFailuresFromIPSignal(
        source_ip='1.2.3.4', failed_password_count=2, invalid_user_count=0,
        invalid_usernames=set(), events=events,
    )
    result = _empty_result(repeated_failures_by_ip=[signal], coverage_uncertain=True)
    findings = build_findings(result, detection_succeeded=True)

    low_finding = next(f for f in findings if f['severity'] == 'low')
    assert not low_finding.get('requires_manual_verification', False)


# ===========================================================================
# 9. one DetectionSignal -> exactly one Finding
# ===========================================================================


def test_one_signal_produces_exactly_one_finding():
    events = [_event(SSHAuthEventType.FAILED_PASSWORD, source_ip='1.2.3.4')]
    signal = RepeatedFailuresFromIPSignal(
        source_ip='1.2.3.4', failed_password_count=1, invalid_user_count=0,
        invalid_usernames=set(), events=events,
    )
    result = _empty_result(repeated_failures_by_ip=[signal])
    findings = build_findings(result, detection_succeeded=True)

    non_ok = [f for f in findings if f['severity'] != 'ok']
    assert len(non_ok) == 1


# ===========================================================================
# 10. overlapping signals -> two independent Findings, no merge
# ===========================================================================


def test_overlapping_ip_and_success_signals_produce_two_findings():
    failed_event = _event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='1.2.3.4')
    accepted_event = _event(SSHAuthEventType.ACCEPTED, username='alice', source_ip='1.2.3.4',
                             auth_method=AuthMethod.PASSWORD)

    ip_signal = RepeatedFailuresFromIPSignal(
        source_ip='1.2.3.4', failed_password_count=1, invalid_user_count=0,
        invalid_usernames=set(), events=[failed_event],
    )
    success_signal = SuccessAfterFailureSignal(
        source_ip='1.2.3.4', username='alice', failed_events=[failed_event], accepted_event=accepted_event,
    )
    result = _empty_result(repeated_failures_by_ip=[ip_signal], success_after_failure=[success_signal])
    findings = build_findings(result, detection_succeeded=True)

    non_ok = [f for f in findings if f['severity'] != 'ok']
    assert len(non_ok) == 2


# ===========================================================================
# 11. evidence contains ALL raw_line values, no truncation
# ===========================================================================


def test_evidence_contains_all_raw_lines_no_truncation():
    events = [
        _event(SSHAuthEventType.FAILED_PASSWORD, source_ip='1.2.3.4', raw_line=f'line-{i}')
        for i in range(50)
    ]
    signal = RepeatedFailuresFromIPSignal(
        source_ip='1.2.3.4', failed_password_count=50, invalid_user_count=0,
        invalid_usernames=set(), events=events,
    )
    result = _empty_result(repeated_failures_by_ip=[signal])
    findings = build_findings(result, detection_succeeded=True)

    high_finding = next(f for f in findings if f['severity'] == 'high')
    for i in range(50):
        assert f'line-{i}' in high_finding['evidence']


# ===========================================================================
# 12. recommendation stays empty/neutral without known fail2ban state
# ===========================================================================


def test_recommendation_empty_without_fail2ban_state_context():
    events = [_event(SSHAuthEventType.FAILED_PASSWORD, source_ip='1.2.3.4') for _ in range(5)]
    signal = RepeatedFailuresFromIPSignal(
        source_ip='1.2.3.4', failed_password_count=5, invalid_user_count=0,
        invalid_usernames=set(), events=events,
    )
    result = _empty_result(repeated_failures_by_ip=[signal])
    findings = build_findings(result, detection_succeeded=True)

    high_finding = next(f for f in findings if f['severity'] == 'high')
    assert high_finding.get('recommendation', '') == ''


# ===========================================================================
# 13. invalid_user enumeration: count AND diversity are independent axes
# ===========================================================================


def test_high_count_low_diversity_invalid_user_not_full_enumeration_severity():
    """5 invalid_user events but all for the SAME username — diversity=1,
    below invalid_username_diversity_threshold — must not reach the same
    severity as a genuinely diverse enumeration attempt."""
    events = [_event(SSHAuthEventType.INVALID_USER, username='root', source_ip='1.2.3.4') for _ in range(5)]
    signal = RepeatedFailuresFromIPSignal(
        source_ip='1.2.3.4', failed_password_count=0, invalid_user_count=5,
        invalid_usernames={'root'}, events=events,
    )
    result = _empty_result(repeated_failures_by_ip=[signal])
    findings = build_findings(result, detection_succeeded=True)

    low_diversity_finding = next(f for f in findings if f['severity'] != 'ok')
    high_count_high_diversity_events = [
        _event(SSHAuthEventType.INVALID_USER, username=u, source_ip='5.6.7.8')
        for u in ['admin', 'root', 'test', 'ubuntu', 'guest']
    ]
    diverse_signal = RepeatedFailuresFromIPSignal(
        source_ip='5.6.7.8', failed_password_count=0, invalid_user_count=5,
        invalid_usernames={'admin', 'root', 'test', 'ubuntu', 'guest'}, events=high_count_high_diversity_events,
    )
    diverse_result = _empty_result(repeated_failures_by_ip=[diverse_signal])
    diverse_findings = build_findings(diverse_result, detection_succeeded=True)
    high_diversity_finding = next(f for f in diverse_findings if f['severity'] != 'ok')

    # same count (5), different diversity -> different severity
    assert low_diversity_finding['severity'] != high_diversity_finding['severity']
    assert high_diversity_finding['severity'] == 'high'


# ===========================================================================
# 14. distributed signal (username, >=2 IPs) — NetAudit policy, not Fail2Ban
# ===========================================================================


def test_distributed_username_signal_cites_netaudit_policy():
    events = [
        _event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='1.2.3.4'),
        _event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='5.6.7.8'),
    ]
    signal = RepeatedFailuresForUsernameSignal(
        username='alice', failed_password_count=2, source_ips={'1.2.3.4', '5.6.7.8'}, events=events,
    )
    result = _empty_result(repeated_failures_by_username=[signal])
    findings = build_findings(result, detection_succeeded=True)

    username_finding = next(f for f in findings if f['severity'] != 'ok')
    assert 'NetAudit' in username_finding['detail']
    assert 'Fail2Ban' not in username_finding['detail']


def test_distributed_signal_below_threshold_stays_info():
    """A single source_ip for a username (no distribution at all) must
    not be treated as a distributed-source finding."""
    events = [_event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='1.2.3.4')]
    signal = RepeatedFailuresForUsernameSignal(
        username='alice', failed_password_count=1, source_ips={'1.2.3.4'}, events=events,
    )
    result = _empty_result(repeated_failures_by_username=[signal])
    findings = build_findings(result, detection_succeeded=True)

    username_finding = next(f for f in findings if f['severity'] != 'ok')
    assert username_finding['severity'] == 'info'


# ===========================================================================
# 15. successful Detection + zero signals -> exactly one 'ok' Finding
# ===========================================================================


def test_zero_signals_with_successful_detection_produces_ok_finding():
    result = _empty_result()
    findings = build_findings(result, detection_succeeded=True)

    assert len(findings) == 1
    assert findings[0]['severity'] == 'ok'
    assert findings[0]['confidence'] == 'high'


# ===========================================================================
# 16. (gate) detection_succeeded=False -> empty list, no fabricated 'ok'
# ===========================================================================


def test_detection_failed_produces_no_findings_at_all():
    result = _empty_result()
    findings = build_findings(result, detection_succeeded=False)

    assert findings == []


def test_detection_failed_with_signals_still_yields_no_ok_fabrication():
    """Even if a caller (incorrectly) passes signals alongside
    detection_succeeded=False, this module does not fabricate an 'ok'
    finding — but it also should not silently process signals from a
    run it's being told did not succeed. Empty list is the safe,
    unambiguous output."""
    events = [_event(SSHAuthEventType.FAILED_PASSWORD, source_ip='1.2.3.4')]
    signal = RepeatedFailuresFromIPSignal(
        source_ip='1.2.3.4', failed_password_count=1, invalid_user_count=0,
        invalid_usernames=set(), events=events,
    )
    result = _empty_result(repeated_failures_by_ip=[signal])
    findings = build_findings(result, detection_succeeded=False)

    assert findings == []


# ===========================================================================
# Policy defaults sanity check
# ===========================================================================


def test_default_policy_values_match_documented_sources():
    assert DEFAULT_POLICY.reference_maxretry == 5
    assert DEFAULT_POLICY.reference_findtime_minutes == 10
    assert DEFAULT_POLICY.distributed_ip_threshold == 2
    assert DEFAULT_POLICY.invalid_username_diversity_threshold == 2
