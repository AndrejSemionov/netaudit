"""RED tests for nginx_error_parser.py — Error Parser Contract v1.

Scenario table (21 cases), matching the frozen contract:
  1.  normal line, no connection_id                         -> PARSED
  2.  normal line, with connection_id (*N)                   -> PARSED
  3.  each of the 8 valid severities                         -> PARSED (x8, parametrized)
  4.  empty message (PARSED, message="")                     -> PARSED
  5.  message containing ':' characters                      -> PARSED, message preserved verbatim
  6.  message containing '*' not in structural position       -> PARSED, '*' preserved as plain text
  7.  invalid connection_id "*abc" (non-digit after '*')      -> PARSED, connection_id=None,
                                                                  "*abc ..." folded entirely into message
  8.  malformed timestamp                                     -> UNKNOWN
  9.  malformed/unknown severity                              -> UNKNOWN
  10. malformed PID#TID (missing, non-numeric, wrong sep)     -> UNKNOWN (x3, parametrized)
  11. garbage / hostile input (empty string, random text)     -> UNKNOWN, never raises (x2, parametrized)
  12. timestamp is always timezone-aware, tzinfo=UTC          -> PARSED, policy assertion
  13. no exception on any malformed input incl. non-str-ish   -> never raises (x2, parametrized)

This gives 21 concrete assertions across the parametrized cases below.
"""

from __future__ import annotations

from datetime import timezone

import pytest

from nginx_error_parser import (
    NginxErrorEventType,
    NginxErrorSeverity,
    parse_nginx_error_line,
)

# ---------------------------------------------------------------------------
# 1. Normal line, no connection_id
# ---------------------------------------------------------------------------


def test_normal_line_no_connection_id_is_parsed():
    line = "2026/08/19 10:15:03 [error] 1234#5678: connect() failed (111: Connection refused)"
    result = parse_nginx_error_line(line)
    assert result.event_type == NginxErrorEventType.PARSED
    assert result.severity == NginxErrorSeverity.ERROR
    assert result.pid == 1234
    assert result.tid == 5678
    assert result.connection_id is None
    assert result.message == "connect() failed (111: Connection refused)"
    assert result.timestamp is not None
    assert result.timestamp.year == 2026
    assert result.timestamp.month == 8
    assert result.timestamp.day == 19
    assert result.timestamp.hour == 10
    assert result.timestamp.minute == 15
    assert result.timestamp.second == 3


# ---------------------------------------------------------------------------
# 2. Normal line, with connection_id
# ---------------------------------------------------------------------------


def test_normal_line_with_connection_id_is_parsed():
    line = "2026/08/19 10:15:03 [error] 1234#5678: *42 connect() failed (111: Connection refused)"
    result = parse_nginx_error_line(line)
    assert result.event_type == NginxErrorEventType.PARSED
    assert result.connection_id == 42
    assert result.message == "connect() failed (111: Connection refused)"


# ---------------------------------------------------------------------------
# 3. All 8 valid severities
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "level_text,expected_enum",
    [
        ("debug", NginxErrorSeverity.DEBUG),
        ("info", NginxErrorSeverity.INFO),
        ("notice", NginxErrorSeverity.NOTICE),
        ("warn", NginxErrorSeverity.WARN),
        ("error", NginxErrorSeverity.ERROR),
        ("crit", NginxErrorSeverity.CRIT),
        ("alert", NginxErrorSeverity.ALERT),
        ("emerg", NginxErrorSeverity.EMERG),
    ],
)
def test_all_eight_severities_are_parsed(level_text, expected_enum):
    line = f"2026/08/19 10:15:03 [{level_text}] 100#200: something happened"
    result = parse_nginx_error_line(line)
    assert result.event_type == NginxErrorEventType.PARSED
    assert result.severity == expected_enum


# ---------------------------------------------------------------------------
# 4. Empty message
# ---------------------------------------------------------------------------


def test_empty_message_is_parsed_with_empty_string():
    line = "2026/08/19 10:15:03 [notice] 100#200: "
    result = parse_nginx_error_line(line)
    assert result.event_type == NginxErrorEventType.PARSED
    assert result.message == ""


# ---------------------------------------------------------------------------
# 5. Message containing ':' characters (client:/server:/request:/upstream:
#    are NOT decomposed in v1 — they remain part of message verbatim)
# ---------------------------------------------------------------------------


def test_message_with_colons_is_preserved_verbatim():
    line = (
        "2026/08/19 10:15:03 [error] 100#200: *5 connect() failed "
        "(111: Connection refused) while connecting to upstream, "
        "client: 10.0.0.1, server: example.com, request: \"GET / HTTP/1.1\", "
        "upstream: \"http://127.0.0.1:8080/\", host: \"example.com\""
    )
    result = parse_nginx_error_line(line)
    assert result.event_type == NginxErrorEventType.PARSED
    assert result.connection_id == 5
    expected_message = (
        "connect() failed (111: Connection refused) while connecting to upstream, "
        "client: 10.0.0.1, server: example.com, request: \"GET / HTTP/1.1\", "
        "upstream: \"http://127.0.0.1:8080/\", host: \"example.com\""
    )
    assert result.message == expected_message


# ---------------------------------------------------------------------------
# 6. '*' inside message, not in structural position (right after ':')
# ---------------------------------------------------------------------------


def test_asterisk_inside_message_is_plain_text():
    line = "2026/08/19 10:15:03 [error] 100#200: pattern \"*.example.com\" did not match"
    result = parse_nginx_error_line(line)
    assert result.event_type == NginxErrorEventType.PARSED
    assert result.connection_id is None
    assert result.message == 'pattern "*.example.com" did not match'


# ---------------------------------------------------------------------------
# 7. Invalid connection_id "*abc" — folds entirely into message
# ---------------------------------------------------------------------------


def test_invalid_connection_id_folds_into_message():
    line = "2026/08/19 10:15:03 [error] 100#200: *abc something went wrong"
    result = parse_nginx_error_line(line)
    assert result.event_type == NginxErrorEventType.PARSED
    assert result.connection_id is None
    assert result.message == "*abc something went wrong"


# ---------------------------------------------------------------------------
# 8. Malformed timestamp
# ---------------------------------------------------------------------------


def test_malformed_timestamp_is_unknown():
    line = "not-a-timestamp [error] 100#200: something happened"
    result = parse_nginx_error_line(line)
    assert result.event_type == NginxErrorEventType.UNKNOWN
    assert result.timestamp is None
    assert result.severity is None
    assert result.pid is None
    assert result.tid is None
    assert result.connection_id is None
    assert result.message is None
    assert result.raw_line == line


# ---------------------------------------------------------------------------
# 9. Malformed / unknown severity
# ---------------------------------------------------------------------------


def test_unknown_severity_is_unknown():
    line = "2026/08/19 10:15:03 [verbose] 100#200: something happened"
    result = parse_nginx_error_line(line)
    assert result.event_type == NginxErrorEventType.UNKNOWN


# ---------------------------------------------------------------------------
# 10. Malformed PID#TID
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "2026/08/19 10:15:03 [error] : something happened",  # missing PID#TID entirely
        "2026/08/19 10:15:03 [error] abc#def: something happened",  # non-numeric
        "2026/08/19 10:15:03 [error] 100-200: something happened",  # wrong separator
    ],
)
def test_malformed_pid_tid_is_unknown(line):
    result = parse_nginx_error_line(line)
    assert result.event_type == NginxErrorEventType.UNKNOWN


# ---------------------------------------------------------------------------
# 11. Garbage / hostile input
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "",
        "the quick brown fox jumps over the lazy dog",
    ],
)
def test_garbage_input_is_unknown_and_never_raises(line):
    result = parse_nginx_error_line(line)
    assert result.event_type == NginxErrorEventType.UNKNOWN
    assert result.raw_line == line


# ---------------------------------------------------------------------------
# 12. Timestamp policy: always timezone-aware, tzinfo=UTC
# ---------------------------------------------------------------------------


def test_timestamp_is_always_timezone_aware_utc():
    line = "2026/08/19 10:15:03 [notice] 100#200: worker process started"
    result = parse_nginx_error_line(line)
    assert result.event_type == NginxErrorEventType.PARSED
    assert result.timestamp.tzinfo == timezone.utc


def test_error_timestamp_is_mutually_comparable_with_aware_datetime():
    """Guards against the exact class of bug already caught in the SSH E2E:
    TypeError when comparing a naive datetime against an aware one.
    """
    line = "2026/08/19 10:15:03 [notice] 100#200: worker process started"
    result = parse_nginx_error_line(line)
    other_aware = datetime_now_utc_placeholder()
    # Must not raise TypeError — both are aware.
    assert (result.timestamp <= other_aware) or (result.timestamp > other_aware)


def datetime_now_utc_placeholder():
    from datetime import datetime as _dt

    return _dt(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# 13. Never raises, including whitespace-only / non-line-shaped input
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "   ",
        "2026/08/19 10:15:03 [error] 100#200:",  # trailing colon, no space, no message
    ],
)
def test_never_raises_on_edge_shaped_input(line):
    result = parse_nginx_error_line(line)
    assert result.event_type in (NginxErrorEventType.PARSED, NginxErrorEventType.UNKNOWN)
