"""Tests for netaudit_pkg.nginx_access_parser — Parser Contract v1,
nginx predefined "combined" format only (project session notes,
2026-08-19). Written test-first, before implementation, per project
methodology: contract freeze -> test matrix -> tests -> implementation.

Test matrix (agreed, do not reorder/skip):
  1  normal combined line -> PARSED, all fields extracted
  2  request containing spaces (query string) -> single request field,
     not split into tokens
  3  User-Agent containing spaces -> extracted whole, not truncated
  4  Referer containing spaces -> extracted whole
  5  "-" remote_user -> None
  6  "-" referer -> None
  7  IPv4 remote_addr -> PARSED
  8  IPv6 remote_addr -> PARSED
  9  status 2xx/4xx/5xx -> all PARSED (no status-based filtering here)
  10 zero body_bytes_sent -> PARSED, body_bytes_sent == 0
  11 malformed timestamp -> UNKNOWN (see module docstring: combined's
     fixed shape means a bad timestamp usually breaks the whole match)
  12 missing quoted request -> UNKNOWN
  13 missing status -> UNKNOWN
  14 broken/mismatched quote -> UNKNOWN
  15 arbitrary custom-format line -> UNKNOWN
  16 empty string -> UNKNOWN
  17 whitespace-only string -> UNKNOWN
  18 parser never raises (invariant, exercised across all of the above
     plus deliberately hostile input)
  19 request with query string is one field, not split into 3 tokens
     (explicit pin, in addition to #2's general "spaces preserved" case)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from netaudit_pkg.nginx_access_parser import NginxAccessEventType, parse_nginx_access_line


# ===========================================================================
# 1. Normal combined line -> PARSED, all fields extracted
# ===========================================================================

def test_normal_combined_line_is_parsed():
    line = ('203.0.113.7 - - [10/Oct/2026:13:55:36 -0700] "GET /index.html HTTP/1.1" '
            '200 1024 "https://example.com/" "Mozilla/5.0"')
    event = parse_nginx_access_line(line)

    assert event.event_type == NginxAccessEventType.PARSED
    assert event.remote_addr == '203.0.113.7'
    assert event.remote_user is None
    assert event.timestamp == datetime(2026, 10, 10, 13, 55, 36, tzinfo=timezone(timedelta(hours=-7)))
    assert event.request == 'GET /index.html HTTP/1.1'
    assert event.status == 200
    assert event.body_bytes_sent == 1024
    assert event.http_referer == 'https://example.com/'
    assert event.http_user_agent == 'Mozilla/5.0'
    assert event.raw_line == line


# ===========================================================================
# 2/19. Request with spaces (query string) stays one field
# ===========================================================================

def test_request_with_query_string_stays_one_field():
    line = ('203.0.113.7 - - [10/Oct/2026:13:55:36 -0700] "GET /search?q=hello world HTTP/1.1" '
            '200 512 "-" "curl/8.0"')
    event = parse_nginx_access_line(line)

    assert event.event_type == NginxAccessEventType.PARSED
    assert event.request == 'GET /search?q=hello world HTTP/1.1'


def test_request_is_not_split_into_method_path_protocol():
    line = ('203.0.113.7 - - [10/Oct/2026:13:55:36 -0700] "GET /foo?a=1 HTTP/1.1" '
            '200 100 "-" "-"')
    event = parse_nginx_access_line(line)

    # single string, not decomposed — v1 scope
    assert event.request == 'GET /foo?a=1 HTTP/1.1'
    assert isinstance(event.request, str)


# ===========================================================================
# 3. User-Agent containing spaces
# ===========================================================================

def test_user_agent_with_spaces_extracted_whole():
    line = ('203.0.113.7 - - [10/Oct/2026:13:55:36 -0700] "GET / HTTP/1.1" 200 100 "-" '
            '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"')
    event = parse_nginx_access_line(line)

    assert event.http_user_agent == 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'


# ===========================================================================
# 4. Referer containing spaces
# ===========================================================================

def test_referer_with_spaces_extracted_whole():
    line = ('203.0.113.7 - - [10/Oct/2026:13:55:36 -0700] "GET / HTTP/1.1" 200 100 '
            '"https://example.com/search?q=hello world" "curl/8.0"')
    event = parse_nginx_access_line(line)

    assert event.http_referer == 'https://example.com/search?q=hello world'


# ===========================================================================
# 5/6. "-" fields normalize to None
# ===========================================================================

def test_dash_remote_user_is_none():
    line = '203.0.113.7 - - [10/Oct/2026:13:55:36 -0700] "GET / HTTP/1.1" 200 100 "-" "-"'
    event = parse_nginx_access_line(line)
    assert event.remote_user is None


def test_dash_referer_is_none():
    line = '203.0.113.7 - alice [10/Oct/2026:13:55:36 -0700] "GET / HTTP/1.1" 200 100 "-" "curl/8.0"'
    event = parse_nginx_access_line(line)
    assert event.remote_user == 'alice'
    assert event.http_referer is None


# ===========================================================================
# 7/8. IPv4 and IPv6 remote_addr
# ===========================================================================

def test_ipv4_remote_addr():
    line = '203.0.113.7 - - [10/Oct/2026:13:55:36 -0700] "GET / HTTP/1.1" 200 100 "-" "-"'
    event = parse_nginx_access_line(line)
    assert event.remote_addr == '203.0.113.7'
    assert event.event_type == NginxAccessEventType.PARSED


def test_ipv6_remote_addr():
    line = '2001:db8::1 - - [10/Oct/2026:13:55:36 -0700] "GET / HTTP/1.1" 200 100 "-" "-"'
    event = parse_nginx_access_line(line)
    assert event.remote_addr == '2001:db8::1'
    assert event.event_type == NginxAccessEventType.PARSED


# ===========================================================================
# 9. status 2xx/4xx/5xx — all PARSED, no status-based filtering here
# ===========================================================================

def test_status_2xx_is_parsed():
    line = '203.0.113.7 - - [10/Oct/2026:13:55:36 -0700] "GET / HTTP/1.1" 200 100 "-" "-"'
    event = parse_nginx_access_line(line)
    assert event.event_type == NginxAccessEventType.PARSED
    assert event.status == 200


def test_status_4xx_is_parsed():
    line = '203.0.113.7 - - [10/Oct/2026:13:55:36 -0700] "GET /missing HTTP/1.1" 404 0 "-" "-"'
    event = parse_nginx_access_line(line)
    assert event.event_type == NginxAccessEventType.PARSED
    assert event.status == 404


def test_status_5xx_is_parsed():
    line = '203.0.113.7 - - [10/Oct/2026:13:55:36 -0700] "GET / HTTP/1.1" 502 0 "-" "-"'
    event = parse_nginx_access_line(line)
    assert event.event_type == NginxAccessEventType.PARSED
    assert event.status == 502


# ===========================================================================
# 10. zero body_bytes_sent
# ===========================================================================

def test_zero_body_bytes_sent_is_parsed():
    line = '203.0.113.7 - - [10/Oct/2026:13:55:36 -0700] "HEAD / HTTP/1.1" 200 0 "-" "-"'
    event = parse_nginx_access_line(line)
    assert event.event_type == NginxAccessEventType.PARSED
    assert event.body_bytes_sent == 0


# ===========================================================================
# 11. malformed timestamp -> UNKNOWN
# ===========================================================================

def test_malformed_timestamp_is_unknown():
    line = '203.0.113.7 - - [NOT-A-DATE] "GET / HTTP/1.1" 200 100 "-" "-"'
    event = parse_nginx_access_line(line)
    assert event.event_type == NginxAccessEventType.UNKNOWN
    assert event.raw_line == line


# ===========================================================================
# 12. missing quoted request -> UNKNOWN
# ===========================================================================

def test_missing_quoted_request_is_unknown():
    line = '203.0.113.7 - - [10/Oct/2026:13:55:36 -0700] 200 100 "-" "-"'
    event = parse_nginx_access_line(line)
    assert event.event_type == NginxAccessEventType.UNKNOWN


# ===========================================================================
# 13. missing status -> UNKNOWN
# ===========================================================================

def test_missing_status_is_unknown():
    line = '203.0.113.7 - - [10/Oct/2026:13:55:36 -0700] "GET / HTTP/1.1" "-" "-"'
    event = parse_nginx_access_line(line)
    assert event.event_type == NginxAccessEventType.UNKNOWN


# ===========================================================================
# 14. broken/mismatched quote -> UNKNOWN
# ===========================================================================

def test_broken_quote_is_unknown():
    line = '203.0.113.7 - - [10/Oct/2026:13:55:36 -0700] "GET / HTTP/1.1 200 100 "-" "-"'
    event = parse_nginx_access_line(line)
    assert event.event_type == NginxAccessEventType.UNKNOWN


# ===========================================================================
# 15. arbitrary custom-format line -> UNKNOWN
# ===========================================================================

def test_custom_format_line_is_unknown():
    """A line from some other, non-combined log_format (e.g. a JSON
    line, or a differently-ordered custom format) must not be
    partially/incorrectly matched — it's simply UNKNOWN, not guessed at."""
    line = '{"remote_addr": "203.0.113.7", "status": 200, "custom_field": "value"}'
    event = parse_nginx_access_line(line)
    assert event.event_type == NginxAccessEventType.UNKNOWN


# ===========================================================================
# 16/17. Empty / whitespace-only strings
# ===========================================================================

def test_empty_string_is_unknown():
    event = parse_nginx_access_line('')
    assert event.event_type == NginxAccessEventType.UNKNOWN
    assert event.raw_line == ''


def test_whitespace_only_is_unknown():
    event = parse_nginx_access_line('   \t  ')
    assert event.event_type == NginxAccessEventType.UNKNOWN


# ===========================================================================
# 18. Parser never raises — invariant across hostile input
# ===========================================================================

def test_parser_never_raises_on_hostile_input():
    hostile_inputs = [
        'complete garbage not resembling any log format whatsoever !!!',
        '"""""""""""',
        '[[[[[[[[[[[[',
        '\x00\x01\x02 binary garbage',
        'a' * 10000,  # very long line
        '203.0.113.7 - - [10/Oct/2026:13:55:36 -0700] "GET / HTTP/1.1" abc 100 "-" "-"',  # non-numeric status
        '203.0.113.7 - - [10/Oct/2026:13:55:36 -0700] "GET / HTTP/1.1" 200 abc "-" "-"',  # non-numeric bytes
    ]
    for line in hostile_inputs:
        event = parse_nginx_access_line(line)  # must not raise
        assert event.raw_line == line
