"""Nginx error log content parser (v1).

Scope v1 (frozen contract):
    - Parses the single fixed nginx error-log line format hard-coded in
      ngx_log_error_core() (core/ngx_log.c). This format is NOT configurable
      via log_format or any directive, unlike access_log.
    - Format: "yyyy/mm/dd hh:mm:ss [level] pid#tid: *connection_id message"
      connection_id ("*N") is optional — present for request-specific
      messages, absent for startup/worker-level messages.
    - client:/server:/request:/upstream: sub-fields inside `message` are
      NOT decomposed in v1 — they remain part of the raw message string.
    - Never raises on malformed/hostile input; always returns a
      NginxErrorEvent (PARSED or UNKNOWN).

Timestamp policy (NetAudit-specific, not an objective fact from the line):
    The nginx error-log timestamp format ("yyyy/mm/dd hh:mm:ss") carries no
    timezone offset of its own — unlike access_log's $time_local, which
    always includes an explicit offset. NetAudit interprets these
    timezone-less error-log timestamps as UTC for internal temporal
    consistency, so that this parser's output is never accidentally
    compared against an aware datetime from elsewhere in the pipeline
    (the same class of bug already caught once in the SSH auth log E2E:
    TypeError on comparing naive vs aware datetimes). This is a NetAudit
    parsing policy, not a claim that nginx actually wrote UTC.

    timestamp: datetime  # always aware, tzinfo=UTC

This module is independent from nginx_access_parser.py by design — no
shared enum, no shared regex, no code reuse assumed until a second/third
real case demonstrates the same abstraction is warranted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum


class NginxErrorEventType(Enum):
    PARSED = "parsed"
    UNKNOWN = "unknown"


class NginxErrorSeverity(Enum):
    DEBUG = "debug"
    INFO = "info"
    NOTICE = "notice"
    WARN = "warn"
    ERROR = "error"
    CRIT = "crit"
    ALERT = "alert"
    EMERG = "emerg"


@dataclass(frozen=True)
class NginxErrorEvent:
    """Result of parsing a single nginx error log line.

    On UNKNOWN, all fields except event_type and raw_line are None —
    v1 does not attempt partial parsing of malformed error-log lines
    (unlike the SSH auth parser, which does partial-parse free-text
    syslog messages; nginx error log has a fixed structural format,
    so a structural mismatch means the whole line is unrecognized).
    """

    event_type: NginxErrorEventType
    timestamp: datetime | None
    severity: NginxErrorSeverity | None
    pid: int | None
    tid: int | None
    connection_id: int | None
    message: str | None
    raw_line: str


_VALID_SEVERITIES = {
    "debug": NginxErrorSeverity.DEBUG,
    "info": NginxErrorSeverity.INFO,
    "notice": NginxErrorSeverity.NOTICE,
    "warn": NginxErrorSeverity.WARN,
    "error": NginxErrorSeverity.ERROR,
    "crit": NginxErrorSeverity.CRIT,
    "alert": NginxErrorSeverity.ALERT,
    "emerg": NginxErrorSeverity.EMERG,
}

# Structural line format:
#   yyyy/mm/dd hh:mm:ss [level] pid#tid: rest
# `rest` is handled separately (connection_id + message), not by this regex,
# so that "*abc" (invalid connection_id) can be told apart from a genuinely
# malformed structural prefix.
_LINE_RE = re.compile(
    r"^(?P<year>\d{4})/(?P<month>\d{2})/(?P<day>\d{2})"
    r" (?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r" \[(?P<level>[a-z]+)\]"
    r" (?P<pid>\d+)#(?P<tid>\d+):"
    r"(?P<rest>.*)$"
)

# Structural connection_id: "*N" immediately after the mandatory single
# space following "pid#tid:", followed by a space or end of string.
_CONNECTION_ID_RE = re.compile(r"^\*(?P<cid>\d+)(?: |$)")


def parse_nginx_error_line(line: str) -> NginxErrorEvent:
    """Parse a single nginx error log line.

    Never raises. Returns NginxErrorEvent(event_type=UNKNOWN, ...) for any
    line that does not match the fixed nginx error-log structure.
    """
    unknown = NginxErrorEvent(
        event_type=NginxErrorEventType.UNKNOWN,
        timestamp=None,
        severity=None,
        pid=None,
        tid=None,
        connection_id=None,
        message=None,
        raw_line=line,
    )

    if not isinstance(line, str):
        return unknown

    match = _LINE_RE.match(line)
    if match is None:
        return unknown

    level_text = match.group("level")
    severity = _VALID_SEVERITIES.get(level_text)
    if severity is None:
        return unknown

    try:
        timestamp = datetime(
            int(match.group("year")),
            int(match.group("month")),
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            tzinfo=timezone.utc,
        )
    except ValueError:
        # Structurally matched but semantically invalid date/time
        # (e.g. month=13, day=32) — still UNKNOWN, never raises.
        return unknown

    pid = int(match.group("pid"))
    tid = int(match.group("tid"))

    # `rest` includes the mandatory single space after ':', per the fixed
    # nginx format ("pid#tid: rest"). Strip exactly that one leading space
    # if present; an empty rest after stripping means an empty message.
    rest = match.group("rest")
    rest = rest.removeprefix(" ")

    connection_id: int | None = None
    cid_match = _CONNECTION_ID_RE.match(rest)
    if cid_match is not None:
        connection_id = int(cid_match.group("cid"))
        message = rest[cid_match.end():]
    else:
        message = rest

    return NginxErrorEvent(
        event_type=NginxErrorEventType.PARSED,
        timestamp=timestamp,
        severity=severity,
        pid=pid,
        tid=tid,
        connection_id=connection_id,
        message=message,
        raw_line=line,
    )
