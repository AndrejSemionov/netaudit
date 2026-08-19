"""
Nginx Logs Audit — Access log parser: parses one raw nginx access log
line (already obtained by Collection) into a structured NginxAccessEvent,
per Parser Contract v1 (project session notes, 2026-08-19).

Scope (frozen, do not extend without a fresh review)
------------------------------------------------------------------
Only nginx's predefined "combined" format is supported (nginx.org
ngx_http_log_module documentation: "If the format is not specified then
the predefined ‘combined’ format is used" — this is exactly what both
real project hosts use, confirmed empirically: neither has a
log_format directive anywhere in its config, per project session
notes' live inventory):

    $remote_addr - $remote_user [$time_local] "$request" $status
    $body_bytes_sent "$http_referer" "$http_user_agent"

Custom log_format definitions, arbitrary access-log layouts, and any
other predefined format nginx might offer are explicitly OUT of scope
for v1 — a line that doesn't match combined's shape is UNKNOWN, never
guessed at or partially reinterpreted as some other format. This
mirrors ssh_auth_parser.py's own scope discipline (one well-defined
format family per parser, everything else UNKNOWN) rather than
attempting a general-purpose access-log format detector.

This module never raises on malformed input — a parse failure is
recorded as NginxAccessEvent.event_type == UNKNOWN with whatever
sub-fields could still be salvaged (none, by design here, since combined
is a single fixed-shape line — unlike SSH's free-text messages, there's
no meaningful "partial parse" of a line that doesn't match the pattern
at all, so UNKNOWN carries only raw_line).

Field semantics
------------------------------------------------------------------
remote_user and http_referer: nginx writes the literal string "-" when
there is no value for these fields (no authenticated user; no Referer
header sent) — this parser normalizes "-" to None for both, since "-"
is nginx's own placeholder for absence, not a real value carrying
meaning of its own.

time_local: nginx's own timestamp format
    [10/Oct/2000:13:55:36 -0700]
is neither ISO8601 nor the classic syslog format ssh_auth_parser.py
handles — it has its own three-letter-month + explicit numeric offset
shape, and (unlike SSH's syslog format) ALREADY carries its own year,
so no reference_year parameter is needed here. A line whose timestamp
doesn't match this exact shape produces timestamp=None on an otherwise
still-attempted parse — but see the module docstring above: for
combined's fixed shape, a genuinely malformed line almost always fails
the line-level match entirely and becomes UNKNOWN outright, rather than
partially parsing with just a bad timestamp.

request: kept as a single raw string field in v1 (e.g.
'GET /foo?a=1 HTTP/1.1') — NOT split into method/path/protocol. That
decomposition is deliberately deferred; nothing downstream needs it yet
and splitting it introduces its own edge cases (malformed request
lines, missing HTTP version on some malformed/attack traffic) that are
out of scope for this first pass.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum


class NginxAccessEventType(str, Enum):
    PARSED = 'parsed'
    UNKNOWN = 'unknown'


@dataclass
class NginxAccessEvent:
    event_type: NginxAccessEventType
    remote_addr: str | None
    remote_user: str | None       # "-" in the raw line normalizes to None
    timestamp: datetime | None     # from $time_local; None if unparseable
    request: str | None            # raw, e.g. 'GET /foo?a=1 HTTP/1.1' — not decomposed in v1
    status: int | None
    body_bytes_sent: int | None
    http_referer: str | None       # "-" in the raw line normalizes to None
    http_user_agent: str | None
    raw_line: str


_COMBINED_LOG_RE = re.compile(
    r'^(?P<remote_addr>\S+) - (?P<remote_user>\S+) '
    r'\[(?P<time_local>[^\]]+)\] '
    r'"(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) (?P<body_bytes_sent>\d+) '
    r'"(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)"$'
)

_MONTH_NAMES = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12,
}

# nginx's own $time_local shape: 10/Oct/2000:13:55:36 -0700
_TIME_LOCAL_RE = re.compile(
    r'^(?P<day>\d{2})/(?P<month>[A-Z][a-z]{2})/(?P<year>\d{4}):'
    r'(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}) '
    r'(?P<offset>[+-]\d{4})$'
)


def _empty_event(line: str) -> NginxAccessEvent:
    return NginxAccessEvent(
        event_type=NginxAccessEventType.UNKNOWN, remote_addr=None, remote_user=None,
        timestamp=None, request=None, status=None, body_bytes_sent=None,
        http_referer=None, http_user_agent=None, raw_line=line,
    )


def _dash_to_none(value: str) -> str | None:
    return None if value == '-' else value


def _parse_time_local(raw: str) -> datetime | None:
    match = _TIME_LOCAL_RE.match(raw)
    if not match:
        return None
    g = match.groupdict()
    month = _MONTH_NAMES.get(g['month'])
    if month is None:
        return None

    offset_str = g['offset']
    sign = 1 if offset_str[0] == '+' else -1
    hours = int(offset_str[1:3])
    minutes = int(offset_str[3:5])
    tz = timezone(sign * timedelta(hours=hours, minutes=minutes))

    try:
        return datetime(int(g['year']), month, int(g['day']),
                         int(g['hour']), int(g['minute']), int(g['second']), tzinfo=tz)
    except ValueError:
        return None


def parse_nginx_access_line(line: str) -> NginxAccessEvent:
    """Parses one raw access log line against nginx's predefined
    "combined" format. Never raises — a line that doesn't match the
    combined shape produces an UNKNOWN event with every field None
    except raw_line."""
    match = _COMBINED_LOG_RE.match(line)
    if not match:
        return _empty_event(line)

    g = match.groupdict()

    timestamp = _parse_time_local(g['time_local'])
    if timestamp is None:
        # combined's fixed shape: an unparseable timestamp means this
        # line doesn't actually conform to the format we claim to
        # support, even though the outer regex matched the brackets —
        # treat the whole line as UNKNOWN rather than reporting a
        # partial parse with a missing timestamp (see module docstring).
        return _empty_event(line)

    try:
        status = int(g['status'])
        body_bytes_sent = int(g['body_bytes_sent'])
    except ValueError:
        return _empty_event(line)

    return NginxAccessEvent(
        event_type=NginxAccessEventType.PARSED,
        remote_addr=g['remote_addr'],
        remote_user=_dash_to_none(g['remote_user']),
        timestamp=timestamp,
        request=g['request'],
        status=status,
        body_bytes_sent=body_bytes_sent,
        http_referer=_dash_to_none(g['http_referer']),
        http_user_agent=_dash_to_none(g['http_user_agent']),
        raw_line=line,
    )
