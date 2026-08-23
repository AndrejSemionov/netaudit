"""
Logs Audit — Analysis (Iteration 3): parses raw log lines already
obtained by Collection (Iteration 2) into structured SSHAuthEvent
objects. This module does not aggregate, threshold, correlate, or judge
severity — that is Detection/Findings (Iteration 4). A parsed event
answers only "what does this line say happened", never "is this a
problem".

Scope (per Analysis Contract v3 / SSHAuthEvent v1 freeze)
------------------------------------------------------------------
- Only SSH authentication events from sshd log lines are parsed here.
  Everything else (cron, systemd unit noise, journal boot/no-entries
  markers) classifies as SSHAuthEventType.UNKNOWN — this module never
  raises or drops a line just because it doesn't recognize it; a raw
  line always produces an event, even if every field but raw_line ends
  up None/UNKNOWN.
- event_type classification priority (most specific wins, checked in
  this order): INVALID_USER > FAILED_PASSWORD > ACCEPTED > UNKNOWN. A
  real sshd line like "Failed password for invalid user root from
  1.2.3.4" contains both "Invalid user" and "Failed password" — it
  classifies as INVALID_USER, not FAILED_PASSWORD, because the more
  specific signal (the account doesn't exist at all) is what a
  downstream detector actually needs, and mixing the two into a
  combined event_type would push that disambiguation onto every
  consumer instead of doing it once, here.
- auth_method is only ever PASSWORD or PUBLICKEY, and only for ACCEPTED/
  FAILED_PASSWORD events. INVALID_USER and UNKNOWN always get
  auth_method=None — INVALID_USER is not a statement about which
  authentication method was attempted in this model, and adding an
  INVALID_USER+PASSWORD combination would force every downstream
  consumer to unpack a compound semantic instead of a single event_type.
- timestamp parsing supports two formats seen on real hosts: auth.log's
  ISO8601-with-microseconds-and-offset ('2026-08-18T08:23:50.017004+00:00')
  and journal's classic syslog format without year or timezone
  ('Aug 17 19:52:31'). The syslog format cannot supply its own year —
  this module never guesses one; a reference_year must be supplied by
  the caller (see parse_ssh_auth_line()'s signature) for syslog-format
  lines, or the resulting timestamp is None rather than an assumed year.
- INVARIANT (added after a real E2E bug, see project session notes):
  when SSHAuthEvent.timestamp is not None, it is ALWAYS timezone-aware.
  ISO8601 timestamps keep their own explicit offset. Syslog-format
  timestamps carry no timezone of their own — this module interprets
  them as UTC, which is a documented NetAudit parser policy, not an
  objective fact recovered from the log line (the line itself contains
  no timezone information at all). Downstream consumers (Detection,
  Findings) are entitled to assume every non-None timestamp is aware
  and comparable to any other aware datetime — mixing an aware
  ISO8601 event with a naive syslog event in the same comparison
  previously raised TypeError inside Detection's window filtering; this
  is why the invariant is enforced here, at the single place all
  timestamps are constructed, rather than patched downstream.
- A line whose timestamp cannot be parsed at all (malformed, or a format
  this module doesn't recognize) yields timestamp=None — never
  datetime.now() or any other fabricated stand-in. A missing timestamp
  is honestly missing evidence, not something to paper over.
- This module has no opinion on what "-- No entries --" or a journal
  boot marker MEANS at the collection level (e.g. "the journal was
  successfully queried and had zero matching events") — that
  interpretation belongs to a layer above this one, which has access to
  the full CollectionResult (exit_code, completed), not just a raw line.
  Here, such a line simply doesn't match any sshd event pattern and
  becomes UNKNOWN, exactly like any other unrecognized line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum


class SSHAuthEventType(str, Enum):
    ACCEPTED = 'accepted'
    FAILED_PASSWORD = 'failed_password'  # nosec B105 - enum member value, not a hardcoded secret
    INVALID_USER = 'invalid_user'
    UNKNOWN = 'unknown'


class AuthMethod(str, Enum):
    PASSWORD = 'password'  # nosec B105 - enum member value, not a hardcoded secret
    PUBLICKEY = 'publickey'


@dataclass
class SSHAuthEvent:
    timestamp: datetime | None
    event_type: SSHAuthEventType
    username: str | None
    source_ip: str | None
    auth_method: AuthMethod | None
    pid: int | None
    raw_line: str


def parse_ssh_auth_line(line: str, reference_year: int | None = None) -> SSHAuthEvent:
    """Parses one raw log line into an SSHAuthEvent. Never raises on an
    unrecognized line — returns an UNKNOWN event with whatever fields
    (pid, timestamp) could still be extracted, and raw_line always set
    to the original input verbatim.

    reference_year is required to resolve journal-style syslog
    timestamps ('Aug 17 19:52:31', no year of their own) into a real
    datetime. If the line uses that format and reference_year is not
    supplied, timestamp is None rather than guessed. auth.log's own
    ISO8601 timestamps already carry their own year and do not need
    reference_year at all.
    """
    timestamp = _parse_timestamp(line, reference_year)
    pid = _parse_pid(line)
    event_type, username, source_ip, auth_method = _parse_body(line)

    return SSHAuthEvent(
        timestamp=timestamp, event_type=event_type, username=username, source_ip=source_ip,
        auth_method=auth_method, pid=pid, raw_line=line,
    )


# ===========================================================================
# Timestamp parsing
# ===========================================================================

# ISO8601 with microseconds and a numeric UTC offset — auth.log's own
# format, confirmed on both real hosts:
#   2026-08-18T08:23:50.017004+00:00
_ISO8601_RE = re.compile(
    r'^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})T'
    r'(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\.(?P<micro>\d{6})'
    r'(?P<offset>[+-]\d{2}:\d{2})'
)

# Classic syslog format, no year, no timezone — journal's format,
# confirmed on 192.168.88.20:
#   Aug 17 19:52:31
_SYSLOG_TS_RE = re.compile(
    r'^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+'
    r'(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})'
)

_MONTH_NAMES = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12,
}


def _parse_offset(offset: str) -> timezone:
    sign = 1 if offset[0] == '+' else -1
    hours, minutes = offset[1:].split(':')
    from datetime import timedelta
    return timezone(sign * timedelta(hours=int(hours), minutes=int(minutes)))


def _parse_timestamp(line: str, reference_year: int | None) -> datetime | None:
    """Tries the ISO8601 (auth.log) format first, then the syslog
    (journal) format. Returns None if neither matches, or if the syslog
    format matches but no reference_year was supplied — never guesses a
    year, never falls back to datetime.now()."""
    iso_match = _ISO8601_RE.match(line)
    if iso_match:
        g = iso_match.groupdict()
        try:
            return datetime(
                int(g['year']), int(g['month']), int(g['day']),
                int(g['hour']), int(g['minute']), int(g['second']), int(g['micro']),
                tzinfo=_parse_offset(g['offset']),
            )
        except ValueError:
            return None

    syslog_match = _SYSLOG_TS_RE.match(line)
    if syslog_match and reference_year is not None:
        g = syslog_match.groupdict()
        month = _MONTH_NAMES.get(g['month'])
        if month is None:
            return None
        try:
            return datetime(
                reference_year, month, int(g['day']),
                int(g['hour']), int(g['minute']), int(g['second']),
                tzinfo=timezone.utc,
            )
        except ValueError:
            return None

    return None


# ===========================================================================
# PID parsing
# ===========================================================================

# Matches both sshd[PID] and sshd-session[PID] — not tied to a specific
# distro's naming convention (see this module's docstring).
_SSHD_PID_RE = re.compile(r'sshd(?:-session)?\[(?P<pid>\d+)\]')


def _parse_pid(line: str) -> int | None:
    match = _SSHD_PID_RE.search(line)
    if match is None:
        return None
    return int(match.group('pid'))


# ===========================================================================
# Body parsing — event classification + username/source_ip/auth_method
# ===========================================================================

# Checked in this order (most specific wins) — see this module's
# docstring on why "Failed password for invalid user root" classifies as
# INVALID_USER, not FAILED_PASSWORD.
_INVALID_USER_RE = re.compile(r'[Ii]nvalid user (?P<user>\S+) from (?P<ip>\S+)')
_FAILED_PASSWORD_RE = re.compile(r'Failed password for (?P<user>\S+) from (?P<ip>\S+)')
_ACCEPTED_RE = re.compile(r'Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>\S+)')


def _parse_body(line: str) -> tuple[SSHAuthEventType, str | None, str | None, AuthMethod | None]:
    """Classifies the line's message body and extracts username/
    source_ip/auth_method for the matched event type. Order matters:
    INVALID_USER is checked before FAILED_PASSWORD so a line containing
    both phrases (the real, common sshd combination) classifies as the
    more specific INVALID_USER — see this module's docstring."""
    invalid_match = _INVALID_USER_RE.search(line)
    if invalid_match:
        return SSHAuthEventType.INVALID_USER, invalid_match.group('user'), invalid_match.group('ip'), None

    failed_match = _FAILED_PASSWORD_RE.search(line)
    if failed_match:
        return (SSHAuthEventType.FAILED_PASSWORD, failed_match.group('user'),
                failed_match.group('ip'), AuthMethod.PASSWORD)

    accepted_match = _ACCEPTED_RE.search(line)
    if accepted_match:
        method = AuthMethod.PASSWORD if accepted_match.group('method') == 'password' else AuthMethod.PUBLICKEY
        return SSHAuthEventType.ACCEPTED, accepted_match.group('user'), accepted_match.group('ip'), method

    return SSHAuthEventType.UNKNOWN, None, None, None
