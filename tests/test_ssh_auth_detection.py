"""Tests for netaudit_pkg.ssh_auth_detection — Detection Contract
(Iteration 4). Written test-first, before implementation, per project
methodology: contract freeze -> test case table -> tests -> implementation.

Test case table (agreed, do not reorder/skip):
  1  1 failure -> IP signal (count=1 is valid, no threshold here)
  2  2 failures same IP -> one IP signal (aggregated, not two)
  3  failures same IP, different usernames -> invalid_usernames evidence
  4  same username, different IPs -> username signal with multiple source_ips
  5  invalid user -> IP signal (invalid_user_count)
  6  mixed failed+invalid same IP -> one IP aggregate with both counts
  7  failure -> accepted -> SuccessAfterFailureSignal
  8  failure -> unrelated event -> accepted -> signal still produced
  9  failure -> accepted -> failure -> accepted -> two independent
     signals, no failure reused
  10 invalid user -> accepted -> NO success-after-failure
  11 undated failure + dated accepted -> NO success-after-failure
  12 event exactly at window's lower bound -> in_window
  13 event exactly at window's upper bound -> in_window
  14 len(events) == collection_limit -> coverage_uncertain=True
  15 len(events) < collection_limit -> coverage_uncertain=False
  16 one event present in multiple projections simultaneously
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from netaudit_pkg.ssh_auth_detection import (
    DetectionContext,
    apply_window,
    detect,
)
from netaudit_pkg.ssh_auth_parser import AuthMethod, SSHAuthEvent, SSHAuthEventType


def _event(event_type, username=None, source_ip=None, auth_method=None,
           timestamp=None, pid=None, raw_line='') -> SSHAuthEvent:
    return SSHAuthEvent(
        timestamp=timestamp, event_type=event_type, username=username, source_ip=source_ip,
        auth_method=auth_method, pid=pid, raw_line=raw_line or f'{event_type.value} {username}@{source_ip}',
    )


def _ts(minute: int) -> datetime:
    """minute may exceed 59 — overflows into the hour, so callers can
    write e.g. _ts(61) to mean 'one minute past the 10:60 mark' without
    manually doing hour arithmetic."""
    return datetime(2026, 8, 18, 10, 0, 0, tzinfo=timezone.utc) + timedelta(minutes=minute)


def _context(reference_minute: int = 30, window_minutes: int = 60, collection_limit: int = 500) -> DetectionContext:
    return DetectionContext(
        reference_time=_ts(reference_minute), window=timedelta(minutes=window_minutes),
        collection_limit=collection_limit,
    )


# ===========================================================================
# 1. Single failure -> IP signal, count=1 is valid (no threshold in Detection)
# ===========================================================================


def test_single_failure_produces_ip_signal_with_count_one():
    events = [_event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='1.2.3.4', timestamp=_ts(5))]
    windowed = apply_window(events, _context())
    result = detect(windowed)

    assert len(result.repeated_failures_by_ip) == 1
    signal = result.repeated_failures_by_ip[0]
    assert signal.source_ip == '1.2.3.4'
    assert signal.failed_password_count == 1
    assert signal.invalid_user_count == 0
    assert signal.events == events


# ===========================================================================
# 2. Two failures, same IP -> one aggregated signal, not two
# ===========================================================================


def test_two_failures_same_ip_aggregate_into_one_signal():
    events = [
        _event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='1.2.3.4', timestamp=_ts(5)),
        _event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='1.2.3.4', timestamp=_ts(6)),
    ]
    windowed = apply_window(events, _context())
    result = detect(windowed)

    assert len(result.repeated_failures_by_ip) == 1
    assert result.repeated_failures_by_ip[0].failed_password_count == 2
    assert len(result.repeated_failures_by_ip[0].events) == 2


# ===========================================================================
# 3. Failures same IP, different usernames -> invalid_usernames evidence
#    (note: invalid_usernames is populated from INVALID_USER events, not
#    FAILED_PASSWORD usernames — this test uses INVALID_USER per the
#    field's own purpose: user-enumeration strength indicator)
# ===========================================================================


def test_failures_same_ip_different_invalid_usernames():
    events = [
        _event(SSHAuthEventType.INVALID_USER, username='admin', source_ip='1.2.3.4', timestamp=_ts(5)),
        _event(SSHAuthEventType.INVALID_USER, username='root', source_ip='1.2.3.4', timestamp=_ts(6)),
        _event(SSHAuthEventType.INVALID_USER, username='test', source_ip='1.2.3.4', timestamp=_ts(7)),
    ]
    windowed = apply_window(events, _context())
    result = detect(windowed)

    assert len(result.repeated_failures_by_ip) == 1
    signal = result.repeated_failures_by_ip[0]
    assert signal.invalid_user_count == 3
    assert signal.invalid_usernames == {'admin', 'root', 'test'}


# ===========================================================================
# 4. Same username, different IPs -> username signal with multiple source_ips
# ===========================================================================


def test_same_username_different_ips_aggregate_by_username():
    events = [
        _event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='1.2.3.4', timestamp=_ts(5)),
        _event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='5.6.7.8', timestamp=_ts(6)),
        _event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='9.9.9.9', timestamp=_ts(7)),
    ]
    windowed = apply_window(events, _context())
    result = detect(windowed)

    assert len(result.repeated_failures_by_username) == 1
    signal = result.repeated_failures_by_username[0]
    assert signal.username == 'alice'
    assert signal.failed_password_count == 3
    assert signal.source_ips == {'1.2.3.4', '5.6.7.8', '9.9.9.9'}


# ===========================================================================
# 5. Invalid user -> IP signal (invalid_user_count populated)
# ===========================================================================


def test_invalid_user_produces_ip_signal():
    events = [_event(SSHAuthEventType.INVALID_USER, username='root', source_ip='1.2.3.4', timestamp=_ts(5))]
    windowed = apply_window(events, _context())
    result = detect(windowed)

    assert len(result.repeated_failures_by_ip) == 1
    signal = result.repeated_failures_by_ip[0]
    assert signal.invalid_user_count == 1
    assert signal.failed_password_count == 0
    assert signal.invalid_usernames == {'root'}


# ===========================================================================
# 6. Mixed FAILED_PASSWORD + INVALID_USER, same IP -> one aggregate with both
# ===========================================================================


def test_mixed_failed_and_invalid_same_ip_one_aggregate():
    events = [
        _event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='1.2.3.4', timestamp=_ts(5)),
        _event(SSHAuthEventType.INVALID_USER, username='root', source_ip='1.2.3.4', timestamp=_ts(6)),
    ]
    windowed = apply_window(events, _context())
    result = detect(windowed)

    assert len(result.repeated_failures_by_ip) == 1
    signal = result.repeated_failures_by_ip[0]
    assert signal.failed_password_count == 1
    assert signal.invalid_user_count == 1
    assert len(signal.events) == 2


# ===========================================================================
# 7. failure -> accepted -> SuccessAfterFailureSignal
# ===========================================================================


def test_failure_then_accepted_produces_success_after_failure_signal():
    failed = _event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='1.2.3.4', timestamp=_ts(5))
    accepted = _event(SSHAuthEventType.ACCEPTED, username='alice', source_ip='1.2.3.4',
                       auth_method=AuthMethod.PASSWORD, timestamp=_ts(6))
    windowed = apply_window([failed, accepted], _context())
    result = detect(windowed)

    assert len(result.success_after_failure) == 1
    signal = result.success_after_failure[0]
    assert signal.source_ip == '1.2.3.4'
    assert signal.username == 'alice'
    assert signal.failed_events == [failed]
    assert signal.accepted_event == accepted


# ===========================================================================
# 8. failure -> unrelated event -> accepted -> signal still produced
# ===========================================================================


def test_unrelated_event_between_failure_and_accepted_does_not_break_signal():
    failed = _event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='1.2.3.4', timestamp=_ts(5))
    unrelated = _event(SSHAuthEventType.FAILED_PASSWORD, username='bob', source_ip='1.2.3.4', timestamp=_ts(6))
    accepted = _event(SSHAuthEventType.ACCEPTED, username='alice', source_ip='1.2.3.4',
                       auth_method=AuthMethod.PASSWORD, timestamp=_ts(7))
    windowed = apply_window([failed, unrelated, accepted], _context())
    result = detect(windowed)

    alice_signals = [s for s in result.success_after_failure if s.username == 'alice']
    assert len(alice_signals) == 1
    assert alice_signals[0].failed_events == [failed]


# ===========================================================================
# 9. failure -> accepted -> failure -> accepted -> two independent signals,
#    no failure reused across intervals
# ===========================================================================


def test_two_success_intervals_do_not_reuse_failures():
    failed1 = _event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='1.2.3.4', timestamp=_ts(5))
    accepted1 = _event(SSHAuthEventType.ACCEPTED, username='alice', source_ip='1.2.3.4',
                        auth_method=AuthMethod.PASSWORD, timestamp=_ts(6))
    failed2 = _event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='1.2.3.4', timestamp=_ts(20))
    accepted2 = _event(SSHAuthEventType.ACCEPTED, username='alice', source_ip='1.2.3.4',
                        auth_method=AuthMethod.PASSWORD, timestamp=_ts(21))
    windowed = apply_window([failed1, accepted1, failed2, accepted2], _context())
    result = detect(windowed)

    assert len(result.success_after_failure) == 2
    signal1, signal2 = result.success_after_failure
    assert signal1.failed_events == [failed1]
    assert signal1.accepted_event == accepted1
    assert signal2.failed_events == [failed2]
    assert signal2.accepted_event == accepted2
    # no overlap: failed1 must not appear in signal2's evidence
    assert failed1 not in signal2.failed_events


# ===========================================================================
# 10. invalid user -> accepted -> NO success-after-failure
# ===========================================================================


def test_invalid_user_does_not_produce_success_after_failure():
    invalid = _event(SSHAuthEventType.INVALID_USER, username='root', source_ip='1.2.3.4', timestamp=_ts(5))
    accepted = _event(SSHAuthEventType.ACCEPTED, username='root', source_ip='1.2.3.4',
                       auth_method=AuthMethod.PASSWORD, timestamp=_ts(6))
    windowed = apply_window([invalid, accepted], _context())
    result = detect(windowed)

    assert result.success_after_failure == []


# ===========================================================================
# 11. undated failure + dated accepted -> NO success-after-failure
# ===========================================================================


def test_undated_failure_does_not_produce_success_after_failure():
    undated_failed = _event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='1.2.3.4', timestamp=None)
    accepted = _event(SSHAuthEventType.ACCEPTED, username='alice', source_ip='1.2.3.4',
                       auth_method=AuthMethod.PASSWORD, timestamp=_ts(6))
    windowed = apply_window([undated_failed, accepted], _context())

    assert undated_failed in windowed.undated
    assert accepted in windowed.in_window

    result = detect(windowed)
    assert result.success_after_failure == []
    # the undated failure is still visible as IP/username aggregation
    # evidence (Rule 6) — absence from success_after_failure is not the
    # same as being invisible to Detection entirely
    assert result.repeated_failures_by_ip[0].failed_password_count == 1


def test_undated_failure_still_counted_in_ip_and_username_aggregation():
    """Rule 6: undated events participate in IP/username aggregation
    (combined with in_window events) even though they're excluded from
    SuccessAfterFailureSignal construction — order doesn't matter for
    simple counting, only for establishing a before/after sequence."""
    undated_failed = _event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='1.2.3.4', timestamp=None)
    windowed = apply_window([undated_failed], _context())
    result = detect(windowed)

    assert result.undated_event_count == 1
    assert len(result.repeated_failures_by_ip) == 1
    assert result.repeated_failures_by_ip[0].source_ip == '1.2.3.4'
    assert result.repeated_failures_by_ip[0].failed_password_count == 1
    assert undated_failed in result.repeated_failures_by_ip[0].events

    assert len(result.repeated_failures_by_username) == 1
    assert result.repeated_failures_by_username[0].username == 'alice'
    assert undated_failed in result.repeated_failures_by_username[0].events


def test_undated_failure_plus_dated_accepted_no_success_signal_but_ip_aggregate_exists():
    """Explicit combined check: an undated FAILED_PASSWORD and a dated
    ACCEPTED for the same (source_ip, username) must NOT produce a
    SuccessAfterFailureSignal (no total order available), while the
    undated failure still contributes to IP aggregation independently."""
    undated_failed = _event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='1.2.3.4', timestamp=None)
    accepted = _event(SSHAuthEventType.ACCEPTED, username='alice', source_ip='1.2.3.4',
                       auth_method=AuthMethod.PASSWORD, timestamp=_ts(6))
    windowed = apply_window([undated_failed, accepted], _context())
    result = detect(windowed)

    assert result.success_after_failure == []
    ip_signal = next(s for s in result.repeated_failures_by_ip if s.source_ip == '1.2.3.4')
    assert ip_signal.failed_password_count == 1
    assert undated_failed in ip_signal.events


# ===========================================================================
# 12/13. Window boundaries — inclusive on both ends
# ===========================================================================


def test_event_exactly_at_window_lower_bound_is_in_window():
    context = _context(reference_minute=60, window_minutes=30)  # window: [10:30, 11:00]
    lower_bound_event = _event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='1.2.3.4',
                                timestamp=_ts(30))
    windowed = apply_window([lower_bound_event], context)

    assert lower_bound_event in windowed.in_window
    assert lower_bound_event not in windowed.undated


def test_event_exactly_at_window_upper_bound_is_in_window():
    context = _context(reference_minute=60, window_minutes=30)  # window: [10:30, 11:00]
    upper_bound_event = _event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='1.2.3.4',
                                timestamp=_ts(60))
    windowed = apply_window([upper_bound_event], context)

    assert upper_bound_event in windowed.in_window


def test_event_just_outside_window_bounds_is_excluded():
    context = _context(reference_minute=60, window_minutes=30)  # window: [10:30, 11:00]
    too_early = _event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='1.2.3.4', timestamp=_ts(29))
    too_late = _event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='1.2.3.4', timestamp=_ts(61))
    windowed = apply_window([too_early, too_late], context)

    assert too_early not in windowed.in_window
    assert too_late not in windowed.in_window
    # out-of-window events are neither in_window nor undated — they simply
    # don't appear in this WindowedEvents result at all
    assert too_early not in windowed.undated
    assert too_late not in windowed.undated


# ===========================================================================
# 14/15. coverage_uncertain
# ===========================================================================


def test_coverage_uncertain_true_when_event_count_equals_collection_limit():
    context = _context(collection_limit=3)
    events = [
        _event(SSHAuthEventType.FAILED_PASSWORD, username='a', source_ip='1.1.1.1', timestamp=_ts(1)),
        _event(SSHAuthEventType.FAILED_PASSWORD, username='b', source_ip='1.1.1.1', timestamp=_ts(2)),
        _event(SSHAuthEventType.FAILED_PASSWORD, username='c', source_ip='1.1.1.1', timestamp=_ts(3)),
    ]
    windowed = apply_window(events, context)
    assert windowed.coverage_uncertain is True

    result = detect(windowed)
    assert result.coverage_uncertain is True


def test_coverage_uncertain_false_when_event_count_below_collection_limit():
    context = _context(collection_limit=500)
    events = [_event(SSHAuthEventType.FAILED_PASSWORD, username='a', source_ip='1.1.1.1', timestamp=_ts(1))]
    windowed = apply_window(events, context)
    assert windowed.coverage_uncertain is False

    result = detect(windowed)
    assert result.coverage_uncertain is False


# ===========================================================================
# 16. One event present in multiple projections simultaneously (Rule 5:
#     no deduplication between signal types)
# ===========================================================================


def test_one_event_appears_in_multiple_signal_types_simultaneously():
    failed = _event(SSHAuthEventType.FAILED_PASSWORD, username='alice', source_ip='1.2.3.4', timestamp=_ts(5))
    accepted = _event(SSHAuthEventType.ACCEPTED, username='alice', source_ip='1.2.3.4',
                       auth_method=AuthMethod.PASSWORD, timestamp=_ts(6))
    windowed = apply_window([failed, accepted], _context())
    result = detect(windowed)

    # same `failed` event is evidence in the IP aggregate...
    assert failed in result.repeated_failures_by_ip[0].events
    # ...AND the username aggregate...
    assert failed in result.repeated_failures_by_username[0].events
    # ...AND the success-after-failure signal, all at once, with no
    # deduplication or exclusivity between them
    assert failed in result.success_after_failure[0].failed_events
