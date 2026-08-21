"""Fail2Ban log content parser (v1).

Scope v1 (frozen contract, project session notes, 2026-08-21):
    - Parses /var/log/fail2ban.log lines, produced by fail2ban's own
      Python logging formatter (fail2ban/client/fail2banclient.py /
      fail2ban/server/server.py logging setup). Format confirmed
      empirically against live logs on writer (46.62.147.41), current
      + .log.1 + .log.2.gz/.3.gz/.4.gz archives, covering ~1 month of
      real traffic.
    - Two-level parsing, unlike nginx_error_parser's single fixed shape:
        1. Envelope: timestamp + logger name + pid + level + jail —
           common to every fail2ban.log line regardless of event kind.
        2. Message dispatch: the free-text message after "[jail] " is
           matched against 5 known v1 grammars (FOUND/BAN/UNBAN/
           RESTORE_BAN/FLUSH/JAIL_START_WARNING). A message that
           doesn't match any of them is UNKNOWN_MESSAGE, not UNKNOWN —
           see the UNKNOWN vs UNKNOWN_MESSAGE distinction below.
    - Format: "yyyy-mm-dd hh:mm:ss,mmm <logger>  [<pid>]: <LEVEL>  [<jail>] <message>"
      logger name and LEVEL are both space-padded by fail2ban's own
      formatter to a fixed column width — padding is NOT structurally
      significant and must not affect parsing.
    - jail is a required structural field for EVERY event, including
      ones with no IP (FLUSH, JAIL_START_WARNING). Parser never
      attempts to correlate an IP-less event with a preceding
      Found/Ban/Unban line — that is out of scope for v1 (a future
      correlation layer's job, if ever justified).
    - Never raises on malformed/hostile input.

event_type vs UNKNOWN vs UNKNOWN_MESSAGE (frozen distinction):
    UNKNOWN:
        The envelope itself did not parse (bad timestamp, missing
        pid/level/jail, garbage input, non-str input, ...). We do not
        know this is a fail2ban.log line at all. ALL fields are None
        except event_type and raw_line — mirrors nginx_error_parser's
        UNKNOWN policy exactly.
    UNKNOWN_MESSAGE:
        The envelope DID parse (timestamp/logger/pid/level/jail all
        extracted successfully), but the message text after "[jail] "
        does not match any of the 5 known v1 message grammars. This is
        fail2ban writing a message type we don't yet recognize — NOT a
        parsing failure. Envelope fields are preserved; message is
        preserved verbatim; ip and matched_timestamp are None.
    This split exists so a future/unknown fail2ban message never
    silently destroys already-extracted structural data, while a
    genuinely malformed line is never mistaken for a real event.

Timestamp policy (NetAudit-specific, matching nginx_error_parser.py):
    fail2ban.log timestamps carry no explicit timezone offset.
    NetAudit interprets them as UTC for internal temporal consistency
    (same policy as nginx_error_parser.py, same rationale — avoiding
    naive/aware datetime comparison bugs downstream).
    Unlike nginx error log, fail2ban.log timestamps DO include
    milliseconds (",mmm") — this is real precision present in the
    source data (not a formatting artifact), so v1 preserves it as
    microseconds on the returned datetime rather than discarding it.

    timestamp: datetime  # always aware, tzinfo=UTC, microsecond preserved

matched_timestamp (FOUND events only):
    The "- <matched_ts>" suffix in a Found line is fail2ban's own
    record of when the matching log line occurred, which is frequently
    (not always) a second or two earlier than the outer envelope
    timestamp (confirmed empirically, e.g. envelope 05:34:51 vs
    matched_timestamp 05:34:50). v1 does NOT assume these are equal
    and stores both independently. matched_timestamp has no
    milliseconds in the source format (fail2ban only writes
    "YYYY-MM-DD HH:MM:SS" for it) and is UTC per the same policy above.

This module is independent from nginx_error_parser.py / nginx_access_parser.py
by design — no shared enum, no shared regex, no code reuse assumed until a
second/third real case demonstrates the same abstraction is warranted
(same discipline already applied between the two nginx parsers).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum


class Fail2BanEventType(Enum):
    FOUND = "found"
    BAN = "ban"
    UNBAN = "unban"
    RESTORE_BAN = "restore_ban"
    FLUSH = "flush"
    JAIL_START_WARNING = "jail_start_warning"
    UNKNOWN_MESSAGE = "unknown_message"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Fail2BanEvent:
    """Result of parsing a single fail2ban.log line.

    On UNKNOWN, all fields except event_type and raw_line are None.
    On UNKNOWN_MESSAGE, envelope fields (timestamp/logger/pid/level/jail)
    and message are preserved; ip and matched_timestamp are None.
    """

    event_type: Fail2BanEventType
    timestamp: datetime | None
    logger: str | None
    pid: int | None
    level: str | None
    jail: str | None
    message: str | None
    ip: str | None
    matched_timestamp: datetime | None
    raw_line: str


_LEVELS = {"DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL"}

# Envelope structural line format:
#   yyyy-mm-dd hh:mm:ss,mmm <logger>  [<pid>]: <LEVEL>  [<jail>] <message>
# Logger name and LEVEL are both padded with variable whitespace by
# fail2ban's own formatter — \S+ for logger and a bare word for level,
# separated by flexible whitespace, so padding never affects extraction.
_ENVELOPE_RE = re.compile(
    r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
    r" (?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}),(?P<ms>\d{3})"
    r" (?P<logger>\S+)"
    r"\s+\[(?P<pid>\d+)\]:"
    r"\s+(?P<level>[A-Z]+)"
    r"\s+\[(?P<jail>[^\]]+)\]"
    r" (?P<message>.*)$"
)

# Message-level grammars (dispatched only after envelope parses).
_FOUND_RE = re.compile(
    r"^Found (?P<ip>\S+) - "
    r"(?P<my>\d{4})-(?P<mm>\d{2})-(?P<md>\d{2})"
    r" (?P<mh>\d{2}):(?P<mmin>\d{2}):(?P<ms_>\d{2})$"
)
_BAN_RE = re.compile(r"^Ban (?P<ip>\S+)$")
_UNBAN_RE = re.compile(r"^Unban (?P<ip>\S+)$")
_RESTORE_BAN_RE = re.compile(r"^Restore Ban (?P<ip>\S+)$")
_FLUSH_RE = re.compile(r"^Flush ticket\(s\) with \S+$")
_JAIL_START_WARNING_RE = re.compile(
    r"^Jail started without 'journalmatch' set\. "
)


def _unknown(line: str) -> Fail2BanEvent:
    return Fail2BanEvent(
        event_type=Fail2BanEventType.UNKNOWN,
        timestamp=None,
        logger=None,
        pid=None,
        level=None,
        jail=None,
        message=None,
        ip=None,
        matched_timestamp=None,
        raw_line=line,
    )


def parse_fail2ban_line(line: str) -> Fail2BanEvent:
    """Parse a single fail2ban.log line.

    Never raises. Returns Fail2BanEvent(event_type=UNKNOWN, ...) if the
    envelope itself cannot be parsed, or
    Fail2BanEvent(event_type=UNKNOWN_MESSAGE, ...) if the envelope parses
    but the message does not match any known v1 grammar.
    """
    if not isinstance(line, str):
        return _unknown(line if isinstance(line, str) else "")

    match = _ENVELOPE_RE.match(line)
    if match is None:
        return _unknown(line)

    level = match.group("level")
    if level not in _LEVELS:
        return _unknown(line)

    try:
        timestamp = datetime(
            int(match.group("year")),
            int(match.group("month")),
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            int(match.group("ms")) * 1000,
            tzinfo=timezone.utc,
        )
    except ValueError:
        return _unknown(line)

    logger = match.group("logger")
    pid = int(match.group("pid"))
    jail = match.group("jail")
    message = match.group("message")

    def _envelope_event(
        event_type: Fail2BanEventType,
        ip: str | None = None,
        matched_timestamp: datetime | None = None,
    ) -> Fail2BanEvent:
        return Fail2BanEvent(
            event_type=event_type,
            timestamp=timestamp,
            logger=logger,
            pid=pid,
            level=level,
            jail=jail,
            message=message,
            ip=ip,
            matched_timestamp=matched_timestamp,
            raw_line=line,
        )

    found_match = _FOUND_RE.match(message)
    if found_match is not None:
        try:
            matched_ts = datetime(
                int(found_match.group("my")),
                int(found_match.group("mm")),
                int(found_match.group("md")),
                int(found_match.group("mh")),
                int(found_match.group("mmin")),
                int(found_match.group("ms_")),
                tzinfo=timezone.utc,
            )
        except ValueError:
            return _envelope_event(Fail2BanEventType.UNKNOWN_MESSAGE)
        return _envelope_event(
            Fail2BanEventType.FOUND,
            ip=found_match.group("ip"),
            matched_timestamp=matched_ts,
        )

    ban_match = _BAN_RE.match(message)
    if ban_match is not None:
        return _envelope_event(Fail2BanEventType.BAN, ip=ban_match.group("ip"))

    unban_match = _UNBAN_RE.match(message)
    if unban_match is not None:
        return _envelope_event(Fail2BanEventType.UNBAN, ip=unban_match.group("ip"))

    restore_ban_match = _RESTORE_BAN_RE.match(message)
    if restore_ban_match is not None:
        return _envelope_event(
            Fail2BanEventType.RESTORE_BAN, ip=restore_ban_match.group("ip")
        )

    if _FLUSH_RE.match(message):
        return _envelope_event(Fail2BanEventType.FLUSH)

    if _JAIL_START_WARNING_RE.match(message):
        return _envelope_event(Fail2BanEventType.JAIL_START_WARNING)

    return _envelope_event(Fail2BanEventType.UNKNOWN_MESSAGE)
