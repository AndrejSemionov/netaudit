"""Tests for netaudit_pkg.ssh_auth_parser — SSHAuthEvent v1 contract
(Iteration 3, Analysis). Written test-first, before implementation, per
project methodology: contract freeze -> test case table -> tests ->
implementation.

Test case table (agreed, do not reorder/skip):
  1  Accepted password           (real, 192.168.88.20 auth.log)
  2  Accepted publickey          (real, 46.62.147.41 auth.log)
  3  syslog timestamp            (real, 192.168.88.20 journal)
  4  Failed password             (synthetic, matches system.py's
                                   existing failed_ssh_logins grep pattern)
  5  Failed password + invalid user -> classified as INVALID_USER
  6  Invalid user (no "Failed password" wording)
  7  unrelated process line      -> UNKNOWN
  8  unknown sshd message        -> UNKNOWN + partial fields (pid/timestamp)
  9  malformed timestamp         -> timestamp=None
  10 "-- No entries --"          -> UNKNOWN
  11 "-- Boot ... --"            -> UNKNOWN
"""

from __future__ import annotations

from datetime import datetime, timezone

from netaudit_pkg.ssh_auth_parser import AuthMethod, SSHAuthEventType, parse_ssh_auth_line


# ===========================================================================
# 1. Accepted password (real line, 192.168.88.20)
# ===========================================================================


def test_accepted_password_real_line_iso8601():
    line = ('2026-08-18T08:23:50.017004+00:00 server sshd-session[1355]: '
            'Accepted password for netaudit from 192.168.88.12 port 37520 ssh2')
    event = parse_ssh_auth_line(line)

    assert event.event_type == SSHAuthEventType.ACCEPTED
    assert event.auth_method == AuthMethod.PASSWORD
    assert event.username == 'netaudit'
    assert event.source_ip == '192.168.88.12'
    assert event.pid == 1355
    assert event.raw_line == line
    assert event.timestamp == datetime(2026, 8, 18, 8, 23, 50, 17004, tzinfo=timezone.utc)


def test_accepted_password_matches_sshd_session_process_name():
    """sshd-session[PID] (newer Ubuntu per-session split) must be
    recognized, not just plain sshd[PID]."""
    line = ('2026-08-18T08:23:50.017004+00:00 server sshd-session[1355]: '
            'Accepted password for netaudit from 192.168.88.12 port 37520 ssh2')
    event = parse_ssh_auth_line(line)
    assert event.pid == 1355


# ===========================================================================
# 2. Accepted publickey (real line, 46.62.147.41)
# ===========================================================================


def test_accepted_publickey_real_line_with_fingerprint_tail():
    line = ('2026-08-18T08:25:39.891807+00:00 writer sshd[360992]: '
            'Accepted publickey for andreykapro from 5.20.17.250 port 50608 ssh2: '
            'ED25519 SHA256:TtxPy1jDru93GYSmaHI20/n4FUo6RaZh6C7erodvob0')
    event = parse_ssh_auth_line(line)

    assert event.event_type == SSHAuthEventType.ACCEPTED
    assert event.auth_method == AuthMethod.PUBLICKEY
    assert event.username == 'andreykapro'
    assert event.source_ip == '5.20.17.250'
    assert event.pid == 360992
    # the fingerprint tail is not parsed into a separate field (out of
    # scope per Analysis Contract v3), but must survive intact in raw_line
    assert 'ED25519 SHA256:TtxPy1jDru93GYSmaHI20/n4FUo6RaZh6C7erodvob0' in event.raw_line
    assert event.raw_line == line


def test_accepted_publickey_matches_plain_sshd_process_name():
    """Plain sshd[PID] (classic, non-split) must also be recognized."""
    line = ('2026-08-18T08:25:39.891807+00:00 writer sshd[360992]: '
            'Accepted publickey for andreykapro from 5.20.17.250 port 50608 ssh2')
    event = parse_ssh_auth_line(line)
    assert event.pid == 360992


# ===========================================================================
# 3. syslog-format timestamp (real line, 192.168.88.20 journal)
# ===========================================================================


def test_syslog_timestamp_with_reference_year():
    line = 'Aug 17 19:52:31 server sshd-session[2360]: Accepted password for netaudit from 192.168.88.12 port 35530 ssh2'
    event = parse_ssh_auth_line(line, reference_year=2026)

    assert event.event_type == SSHAuthEventType.ACCEPTED
    assert event.timestamp == datetime(2026, 8, 17, 19, 52, 31)
    assert event.username == 'netaudit'
    assert event.source_ip == '192.168.88.12'
    assert event.pid == 2360


def test_syslog_timestamp_without_reference_year_is_none():
    """No reference_year supplied -> timestamp=None, never a guessed
    year. Other fields are still parsed normally — a missing timestamp
    doesn't block the rest of the line from being understood."""
    line = 'Aug 17 19:52:31 server sshd-session[2360]: Accepted password for netaudit from 192.168.88.12 port 35530 ssh2'
    event = parse_ssh_auth_line(line)

    assert event.timestamp is None
    assert event.event_type == SSHAuthEventType.ACCEPTED
    assert event.username == 'netaudit'


# ===========================================================================
# 4. Failed password (synthetic, matches system.py's existing
#    failed_ssh_logins grep pattern: 'failed\\|invalid')
# ===========================================================================


def test_failed_password():
    line = ('2026-08-18T09:00:00.000000+00:00 writer sshd[400001]: '
            'Failed password for admin from 1.2.3.4 port 55555 ssh2')
    event = parse_ssh_auth_line(line)

    assert event.event_type == SSHAuthEventType.FAILED_PASSWORD
    assert event.auth_method == AuthMethod.PASSWORD
    assert event.username == 'admin'
    assert event.source_ip == '1.2.3.4'
    assert event.pid == 400001


# ===========================================================================
# 5. "Failed password for invalid user X" -> classified as INVALID_USER,
#    not FAILED_PASSWORD (most-specific-wins priority rule)
# ===========================================================================


def test_failed_password_for_invalid_user_is_classified_as_invalid_user():
    line = ('2026-08-18T09:00:00.000000+00:00 writer sshd[400002]: '
            'Failed password for invalid user root from 1.2.3.4 port 55556 ssh2')
    event = parse_ssh_auth_line(line)

    assert event.event_type == SSHAuthEventType.INVALID_USER
    assert event.username == 'root'
    assert event.source_ip == '1.2.3.4'
    assert event.pid == 400002
    # INVALID_USER never carries an auth_method in this model — see
    # ssh_auth_parser.py's docstring on why combining the two semantics
    # into one event_type is deliberately avoided
    assert event.auth_method is None


# ===========================================================================
# 6. "Invalid user X" without "Failed password" wording
# ===========================================================================


def test_invalid_user_without_failed_password_wording():
    line = ('2026-08-18T09:00:00.000000+00:00 writer sshd[400003]: '
            'Invalid user testuser from 5.6.7.8 port 22222')
    event = parse_ssh_auth_line(line)

    assert event.event_type == SSHAuthEventType.INVALID_USER
    assert event.username == 'testuser'
    assert event.source_ip == '5.6.7.8'
    assert event.pid == 400003
    assert event.auth_method is None


# ===========================================================================
# 7. unrelated process line -> UNKNOWN
# ===========================================================================


def test_unrelated_process_line_is_unknown():
    """Real line from 192.168.88.20 auth.log — not an sshd line at all."""
    line = ('2026-08-18T08:25:01.506081+00:00 server CRON[360989]: '
            'pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)')
    event = parse_ssh_auth_line(line)

    assert event.event_type == SSHAuthEventType.UNKNOWN
    assert event.auth_method is None
    assert event.username is None
    assert event.source_ip is None
    assert event.raw_line == line


# ===========================================================================
# 8. unknown sshd message -> UNKNOWN + partial fields (pid/timestamp
#    still extracted where possible)
# ===========================================================================


def test_unknown_sshd_message_still_extracts_pid_and_timestamp():
    """An sshd line whose message body isn't one of the recognized
    patterns must not be discarded wholesale — pid and timestamp, which
    don't depend on understanding the message body, are still extracted.
    This is the core 'partial parsing, not all-or-nothing' invariant."""
    line = '2026-08-18T09:05:00.000000+00:00 writer sshd[400004]: Received disconnect from 1.2.3.4 port 4321:11: disconnected by user'
    event = parse_ssh_auth_line(line)

    assert event.event_type == SSHAuthEventType.UNKNOWN
    assert event.pid == 400004
    assert event.timestamp == datetime(2026, 8, 18, 9, 5, 0, 0, tzinfo=timezone.utc)
    assert event.auth_method is None
    assert event.raw_line == line


# ===========================================================================
# 9. malformed timestamp -> timestamp=None
# ===========================================================================


def test_malformed_timestamp_yields_none_not_a_crash():
    line = 'NOT-A-TIMESTAMP sshd[400005]: Accepted password for admin from 1.2.3.4 port 1234 ssh2'
    event = parse_ssh_auth_line(line)

    assert event.timestamp is None
    # the rest of the line is still parseable independent of the broken timestamp
    assert event.event_type == SSHAuthEventType.ACCEPTED
    assert event.username == 'admin'
    assert event.pid == 400005


def test_completely_malformed_line_does_not_raise():
    """Parser must never raise on garbage input — worst case is an
    all-None UNKNOWN event with the original text preserved."""
    line = 'complete garbage not resembling any log format whatsoever !!!'
    event = parse_ssh_auth_line(line)

    assert event.event_type == SSHAuthEventType.UNKNOWN
    assert event.timestamp is None
    assert event.pid is None
    assert event.username is None
    assert event.source_ip is None
    assert event.raw_line == line


# ===========================================================================
# 10. "-- No entries --" (real journalctl marker, seen live on 46.62.147.41)
# ===========================================================================


def test_no_entries_marker_is_unknown_not_a_crash():
    """This module has no opinion on what '-- No entries --' means at
    the collection level (see ssh_auth_parser.py's docstring) — it's
    simply a line that doesn't match any sshd event pattern."""
    line = '-- No entries --'
    event = parse_ssh_auth_line(line)

    assert event.event_type == SSHAuthEventType.UNKNOWN
    assert event.raw_line == line
    assert event.pid is None
    assert event.timestamp is None


# ===========================================================================
# 11. "-- Boot ... --" (real journalctl marker, seen live on 192.168.88.20)
# ===========================================================================


def test_boot_marker_is_unknown_not_a_crash():
    line = '-- Boot ca030ad951de400e975a7326b8cb958c --'
    event = parse_ssh_auth_line(line)

    assert event.event_type == SSHAuthEventType.UNKNOWN
    assert event.raw_line == line
    assert event.pid is None
    assert event.timestamp is None
