"""RED tests for fail2ban_parser.py — Fail2Ban Parser Contract v1.

Scenario table (frozen contract, project session notes, 2026-08-21):

Group A — envelope structural (every event type shares one envelope shape)
  A1.  valid envelope, FOUND message                          -> PARSED (event_type=FOUND)
  A2.  valid envelope, logger=fail2ban.actions                -> PARSED
  A3.  valid envelope, logger=fail2ban.filtersystemd           -> PARSED
  A4.  malformed timestamp                                     -> UNKNOWN
  A5.  missing/non-numeric pid                                 -> UNKNOWN (x2, parametrized)
  A6.  malformed/unknown level                                 -> UNKNOWN
  A7.  missing jail bracket                                    -> UNKNOWN
  A8.  garbage / hostile input (empty string, random text)     -> UNKNOWN (x2, parametrized)
  A9.  non-str input                                           -> UNKNOWN, never raises (x2, parametrized)

Group B — message dispatch (envelope valid, message determines event_type)
  B1.  "Found <ip> - <matched_ts>"                             -> FOUND, ip + matched_timestamp set
  B2.  "Ban <ip>"                                               -> BAN, ip set, matched_timestamp=None
  B3.  "Unban <ip>"                                             -> UNBAN, ip set, matched_timestamp=None
  B4.  "Restore Ban <ip>"  (synthetic — never observed live)    -> RESTORE_BAN, ip set
  B5.  "Flush ticket(s) with <backend>"                         -> FLUSH, ip=None, matched_timestamp=None
  B6.  "Jail started without 'journalmatch' set. ..."           -> JAIL_START_WARNING, ip=None
  B7.  valid envelope + unrecognized message                   -> UNKNOWN_MESSAGE,
       envelope fields preserved, message preserved verbatim, ip=None, matched_timestamp=None

Group C — IP/timestamp edge cases
  C1.  matched_ts second differs from envelope timestamp (real observed case) -> PARSED, both preserved as-is
  C2.  IPv6 address in Found/Ban/Unban                          -> PARSED, ip as string
  C3.  jail name with hyphen/underscore (sshd-ddos, nginx-http-auth) -> PARSED, jail preserved verbatim

Group D — envelope invariants
  D1.  logger/level padding (extra spaces) does not affect parsing -> PARSED, fields extracted without padding
  D2.  timestamp format "YYYY-MM-DD HH:MM:SS,mmm" recognized correctly, milliseconds preserved as microseconds
  D3.  timestamp is always timezone-aware, tzinfo=UTC             -> policy assertion

This gives 30+ concrete assertions across the parametrized cases below.
"""

from __future__ import annotations

from datetime import timezone

import pytest

from netaudit_pkg.fail2ban_parser import (
    Fail2BanEventType,
    parse_fail2ban_line,
)

# ---------------------------------------------------------------------------
# Group A — envelope structural
# ---------------------------------------------------------------------------


def test_a1_valid_envelope_found_message_is_parsed():
    line = (
        "2026-08-17 02:37:53,736 fail2ban.filter         [314842]: "
        "INFO    [sshd-ddos] Found 85.217.149.44 - 2026-08-17 02:37:53"
    )
    result = parse_fail2ban_line(line)
    assert result.event_type == Fail2BanEventType.FOUND
    assert result.logger == "fail2ban.filter"
    assert result.pid == 314842
    assert result.level == "INFO"
    assert result.jail == "sshd-ddos"
    assert result.ip == "85.217.149.44"


def test_a2_valid_envelope_actions_logger_is_parsed():
    line = (
        "2026-08-03 08:39:56,463 fail2ban.actions        [217022]: "
        "NOTICE  [sshd] Ban 95.164.55.53"
    )
    result = parse_fail2ban_line(line)
    assert result.event_type == Fail2BanEventType.BAN
    assert result.logger == "fail2ban.actions"
    assert result.pid == 217022


def test_a3_valid_envelope_filtersystemd_logger_is_parsed():
    line = (
        "2026-08-12 06:14:26,394 fail2ban.filtersystemd  [314842]: "
        "NOTICE  [nginx-botsearch] Jail started without 'journalmatch' set. "
        "Jail regexs will be checked against all journal entries, "
        "which is not advised for performance reasons."
    )
    result = parse_fail2ban_line(line)
    assert result.event_type == Fail2BanEventType.JAIL_START_WARNING
    assert result.logger == "fail2ban.filtersystemd"
    assert result.pid == 314842


def test_a4_malformed_timestamp_is_unknown():
    line = (
        "2026-13-99 99:99:99,736 fail2ban.filter         [314842]: "
        "INFO    [sshd-ddos] Found 85.217.149.44 - 2026-08-17 02:37:53"
    )
    result = parse_fail2ban_line(line)
    assert result.event_type == Fail2BanEventType.UNKNOWN
    assert result.timestamp is None
    assert result.logger is None
    assert result.pid is None
    assert result.level is None
    assert result.jail is None
    assert result.message is None
    assert result.ip is None
    assert result.matched_timestamp is None


@pytest.mark.parametrize(
    "line",
    [
        (
            "2026-08-17 02:37:53,736 fail2ban.filter         []: "
            "INFO    [sshd-ddos] Found 85.217.149.44 - 2026-08-17 02:37:53"
        ),
        (
            "2026-08-17 02:37:53,736 fail2ban.filter         [abc]: "
            "INFO    [sshd-ddos] Found 85.217.149.44 - 2026-08-17 02:37:53"
        ),
    ],
)
def test_a5_missing_or_non_numeric_pid_is_unknown(line):
    result = parse_fail2ban_line(line)
    assert result.event_type == Fail2BanEventType.UNKNOWN


def test_a6_malformed_level_is_unknown():
    line = (
        "2026-08-17 02:37:53,736 fail2ban.filter         [314842]: "
        "BOGUS   [sshd-ddos] Found 85.217.149.44 - 2026-08-17 02:37:53"
    )
    result = parse_fail2ban_line(line)
    assert result.event_type == Fail2BanEventType.UNKNOWN


def test_a7_missing_jail_bracket_is_unknown():
    line = (
        "2026-08-17 02:37:53,736 fail2ban.filter         [314842]: "
        "INFO    sshd-ddos Found 85.217.149.44 - 2026-08-17 02:37:53"
    )
    result = parse_fail2ban_line(line)
    assert result.event_type == Fail2BanEventType.UNKNOWN


@pytest.mark.parametrize("line", ["", "this is not a fail2ban log line at all"])
def test_a8_garbage_input_is_unknown(line):
    result = parse_fail2ban_line(line)
    assert result.event_type == Fail2BanEventType.UNKNOWN
    assert result.raw_line == line


@pytest.mark.parametrize("value", [None, 12345])
def test_a9_non_str_input_is_unknown_never_raises(value):
    result = parse_fail2ban_line(value)
    assert result.event_type == Fail2BanEventType.UNKNOWN


# ---------------------------------------------------------------------------
# Group B — message dispatch
# ---------------------------------------------------------------------------


def test_b1_found_message_sets_ip_and_matched_timestamp():
    line = (
        "2026-08-18 05:34:51,238 fail2ban.filter         [314842]: "
        "INFO    [sshd-ddos] Found 162.216.149.17 - 2026-08-18 05:34:50"
    )
    result = parse_fail2ban_line(line)
    assert result.event_type == Fail2BanEventType.FOUND
    assert result.ip == "162.216.149.17"
    assert result.matched_timestamp is not None
    assert result.matched_timestamp.year == 2026
    assert result.matched_timestamp.month == 8
    assert result.matched_timestamp.day == 18
    assert result.matched_timestamp.hour == 5
    assert result.matched_timestamp.minute == 34
    assert result.matched_timestamp.second == 50


def test_b2_ban_message_sets_ip_no_matched_timestamp():
    line = (
        "2026-08-03 14:47:17,492 fail2ban.actions        [217022]: "
        "NOTICE  [sshd] Ban 185.25.118.108"
    )
    result = parse_fail2ban_line(line)
    assert result.event_type == Fail2BanEventType.BAN
    assert result.ip == "185.25.118.108"
    assert result.matched_timestamp is None


def test_b3_unban_message_sets_ip_no_matched_timestamp():
    line = (
        "2026-08-03 15:47:17,521 fail2ban.actions        [217022]: "
        "NOTICE  [sshd] Unban 185.25.118.108"
    )
    result = parse_fail2ban_line(line)
    assert result.event_type == Fail2BanEventType.UNBAN
    assert result.ip == "185.25.118.108"
    assert result.matched_timestamp is None


def test_b4_restore_ban_message_sets_ip_synthetic():
    # Never observed live on writer (checked .log, .log.1, .log.2/3/4.gz —
    # ~1 month of real traffic, zero occurrences). Documented per
    # fail2ban's actionrestore grammar (persistent banning on restart).
    line = (
        "2026-08-21 03:00:00,000 fail2ban.actions        [999999]: "
        "NOTICE  [sshd] Restore Ban 45.79.181.104"
    )
    result = parse_fail2ban_line(line)
    assert result.event_type == Fail2BanEventType.RESTORE_BAN
    assert result.ip == "45.79.181.104"
    assert result.matched_timestamp is None


def test_b5_flush_message_has_no_ip():
    line = (
        "2026-08-05 06:10:50,607 fail2ban.actions        [217022]: "
        "NOTICE  [nginx-limit-req] Flush ticket(s) with nftables-multiport"
    )
    result = parse_fail2ban_line(line)
    assert result.event_type == Fail2BanEventType.FLUSH
    assert result.ip is None
    assert result.matched_timestamp is None
    assert result.jail == "nginx-limit-req"
    assert result.message == "Flush ticket(s) with nftables-multiport"


def test_b6_jail_start_warning_has_no_ip():
    line = (
        "2026-08-05 06:10:51,452 fail2ban.filtersystemd  [258094]: "
        "NOTICE  [nginx-botsearch] Jail started without 'journalmatch' set. "
        "Jail regexs will be checked against all journal entries, "
        "which is not advised for performance reasons."
    )
    result = parse_fail2ban_line(line)
    assert result.event_type == Fail2BanEventType.JAIL_START_WARNING
    assert result.ip is None
    assert result.jail == "nginx-botsearch"


def test_b7_unrecognized_message_is_unknown_message_envelope_preserved():
    line = (
        "2026-08-21 12:00:00,123 fail2ban.actions        [123456]: "
        "NOTICE  [sshd] Some brand new fail2ban message type we've never seen"
    )
    result = parse_fail2ban_line(line)
    assert result.event_type == Fail2BanEventType.UNKNOWN_MESSAGE
    # envelope fields preserved (B7.1-B7.5)
    assert result.timestamp is not None
    assert result.logger == "fail2ban.actions"
    assert result.pid == 123456
    assert result.level == "NOTICE"
    assert result.jail == "sshd"
    # message preserved verbatim (B7.6)
    assert result.message == "Some brand new fail2ban message type we've never seen"
    # ip / matched_timestamp not inferred (B7.7-B7.8)
    assert result.ip is None
    assert result.matched_timestamp is None


# ---------------------------------------------------------------------------
# Group C — IP/timestamp edge cases
# ---------------------------------------------------------------------------


def test_c1_matched_timestamp_second_differs_from_envelope_real_case():
    # Real observed case from writer: envelope second (51) != matched_ts
    # second (50). Parser must not assume equality.
    line = (
        "2026-08-18 05:34:51,238 fail2ban.filter         [314842]: "
        "INFO    [sshd-ddos] Found 162.216.149.17 - 2026-08-18 05:34:50"
    )
    result = parse_fail2ban_line(line)
    assert result.timestamp.second == 51
    assert result.matched_timestamp.second == 50


def test_c2_ipv6_address_in_found_is_parsed():
    line = (
        "2026-08-17 02:37:53,736 fail2ban.filter         [314842]: "
        "INFO    [sshd-ddos] Found 2001:db8::1 - 2026-08-17 02:37:53"
    )
    result = parse_fail2ban_line(line)
    assert result.event_type == Fail2BanEventType.FOUND
    assert result.ip == "2001:db8::1"


def test_c3_jail_name_with_hyphen_is_preserved_verbatim():
    line = (
        "2026-08-05 06:10:50,612 fail2ban.actions        [217022]: "
        "NOTICE  [nginx-http-auth] Flush ticket(s) with nftables-multiport"
    )
    result = parse_fail2ban_line(line)
    assert result.jail == "nginx-http-auth"


# ---------------------------------------------------------------------------
# Group D — envelope invariants
# ---------------------------------------------------------------------------


def test_d1_logger_level_padding_does_not_affect_parsing():
    # Real fail2ban.log lines pad logger name and level to a fixed column
    # width with trailing spaces. Extracted fields must not include padding.
    line = (
        "2026-08-17 02:37:53,736 fail2ban.filter         [314842]: "
        "INFO    [sshd-ddos] Found 85.217.149.44 - 2026-08-17 02:37:53"
    )
    result = parse_fail2ban_line(line)
    assert result.logger == "fail2ban.filter"
    assert result.level == "INFO"


def test_d2_timestamp_milliseconds_preserved_as_microseconds():
    line = (
        "2026-08-17 02:37:53,736 fail2ban.filter         [314842]: "
        "INFO    [sshd-ddos] Found 85.217.149.44 - 2026-08-17 02:37:53"
    )
    result = parse_fail2ban_line(line)
    assert result.timestamp.microsecond == 736000


def test_d3_timestamp_is_always_aware_utc():
    line = (
        "2026-08-17 02:37:53,736 fail2ban.filter         [314842]: "
        "INFO    [sshd-ddos] Found 85.217.149.44 - 2026-08-17 02:37:53"
    )
    result = parse_fail2ban_line(line)
    assert result.timestamp.tzinfo == timezone.utc
