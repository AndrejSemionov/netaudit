"""Tests for netaudit_pkg.checks.log_discovery_audit: turns raw
netaudit_pkg.log_discovery.LogDiscoveryEvidence into LogSource verdicts
(available/readable/requires_sudo/state) and Findings. See that module's
docstring for the collector/consumer split this test file assumes.

Where practical, fixtures reproduce the actual evidence shapes observed
on the two real project hosts (46.62.147.41 "writer", 192.168.88.20
"server") during live VM verification — see the project's session notes
for the original inventory this is modeled on.
"""

from __future__ import annotations

from netaudit_pkg.checks.log_discovery_audit import (
    LogFileState,
    SourceType,
    _file_verdict,
    _is_rotated_filename,
    _journal_verdict,
    _nginx_verdicts,
    _parse_stat_output,
    build_findings,
    build_report,
)
from netaudit_pkg.log_discovery import CommandResult, JournalEvidence, LogFileEvidence, NginxGlobEvidence


def _cr(completed=True, exit_code=0, stdout='', command='') -> CommandResult:
    return CommandResult(completed=completed, exit_code=exit_code, stdout=stdout, stderr='', command=command)


def _file_evidence(path, stat_stdout, stat_exit=0, stat_completed=True,
                    read_exit=0, read_completed=True) -> LogFileEvidence:
    return LogFileEvidence(
        path=path,
        stat_result=_cr(completed=stat_completed, exit_code=stat_exit, stdout=stat_stdout),
        read_probe=_cr(completed=read_completed, exit_code=read_exit),
    )


# ===========================================================================
# _parse_stat_output — pure parsing
# ===========================================================================


def test_parse_stat_output_well_formed():
    parsed = _parse_stat_output('320243|1787001461|syslog|adm|640')
    assert parsed == {'size': 320243, 'mtime': 1787001461, 'owner': 'syslog', 'group': 'adm', 'mode': '640'}


def test_parse_stat_output_malformed_returns_none():
    assert _parse_stat_output('not stat output at all') is None
    assert _parse_stat_output('') is None
    assert _parse_stat_output('a|b|c') is None  # wrong field count


def test_parse_stat_output_takes_last_line_ignoring_2gt1_error_prefix():
    """stat commands are run with 2>&1 — a hypothetical leading warning
    line before the real data line must not break parsing."""
    parsed = _parse_stat_output('some warning\n0|1|nginx|adm|640')
    assert parsed['size'] == 0


# ===========================================================================
# _file_verdict — DC-1/DC-2 as implemented by the semantic layer
# ===========================================================================


def test_verdict_available_and_readable():
    ev = _file_evidence('/var/log/auth.log', '320243|1|syslog|adm|644', read_exit=0)
    v = _file_verdict(ev, SourceType.AUTH_LOG)
    assert v.available is True
    assert v.readable is True
    assert v.requires_sudo is False
    assert v.state == LogFileState.ACTIVE


def test_verdict_available_but_not_readable_dc1_empirical_case():
    """The real 46.62.147.41/192.168.88.20 case: stat succeeds on a 640
    syslog:adm file, test -r fails for a non-adm user."""
    ev = _file_evidence('/var/log/auth.log', '320243|1|syslog|adm|640', read_exit=1)
    v = _file_verdict(ev, SourceType.AUTH_LOG)
    assert v.available is True
    assert v.readable is False
    assert v.requires_sudo is True
    assert v.state == LogFileState.ACTIVE
    assert v.owner == 'syslog'
    assert v.mode == '640'


def test_verdict_confirmed_absent():
    """192.168.88.20's real fail2ban.log case."""
    ev = _file_evidence(
        '/var/log/fail2ban.log',
        "stat: cannot statx '/var/log/fail2ban.log': No such file or directory",
        stat_exit=1,
    )
    v = _file_verdict(ev, SourceType.FAIL2BAN_LOG)
    assert v.available is False
    assert v.readable is False
    assert v.requires_sudo is False
    assert v.state is None


def test_verdict_collection_failure_is_not_confirmed_absent():
    """DC-4 at the semantic layer: stat never completing must produce
    the SAME available=False shape as confirmed-absence at this level of
    the model (Iteration 1 does not yet carry a three-way
    PRESENT/NOT_PRESENT/UNKNOWN enum at the LogSource level — see this
    module's docstring on _file_verdict for why that distinction is
    tracked in commentary but not yet exercised by a real observed case).
    The key invariant tested here is narrower and load-bearing: a
    collection failure must never be reported as available=True."""
    ev = _file_evidence('/var/log/auth.log', '', stat_completed=False, stat_exit=None)
    v = _file_verdict(ev, SourceType.AUTH_LOG)
    assert v.available is False


def test_verdict_zero_byte_is_stale_empty_not_error():
    ev = _file_evidence('/var/log/mail.log', '0|1|syslog|adm|640', read_exit=1)
    v = _file_verdict(ev, SourceType.MAIL_LOG)
    assert v.available is True
    assert v.state == LogFileState.STALE_EMPTY
    assert v.size_bytes == 0


def test_verdict_unparseable_stat_output_is_treated_as_collection_failure():
    ev = _file_evidence('/var/log/auth.log', 'garbage not matching the expected format')
    v = _file_verdict(ev, SourceType.AUTH_LOG)
    assert v.available is False


# ===========================================================================
# _is_rotated_filename
# ===========================================================================


def test_rotated_filename_detection():
    assert _is_rotated_filename('/var/log/nginx/access.log.1') is True
    assert _is_rotated_filename('/var/log/nginx/access.log.19.gz') is True
    assert _is_rotated_filename('/var/log/nginx/andreykapro_access.log.11.gz') is True
    assert _is_rotated_filename('/var/log/nginx/access.log') is False
    assert _is_rotated_filename('/var/log/nginx/andreykapro_access.log') is False
    assert _is_rotated_filename('/var/log/nginx/andreykapro_xmlrpc.log') is False


# ===========================================================================
# _nginx_verdicts — decoy detection + rotated-file filtering (writer's real layout)
# ===========================================================================


def test_nginx_vhost_split_decoy_detection_writer_case():
    """Reproduces writer's (46.62.147.41) real, live-verified layout:
    access.log/error.log are dead 0-byte stubs, andreykapro_access.log/
    andreykapro_error.log are the real active files, andreykapro_xmlrpc.log
    is a genuinely-empty-and-unrelated file (not a decoy — no active
    sibling of its own 'kind')."""
    per_file = [
        _file_evidence('/var/log/nginx/access.log', '0|1|nginx|adm|640', read_exit=1),
        _file_evidence('/var/log/nginx/andreykapro_access.log', '14638129|2|www-data|www-data|640', read_exit=1),
        _file_evidence('/var/log/nginx/andreykapro_error.log', '1594873|3|www-data|www-data|640', read_exit=1),
        _file_evidence('/var/log/nginx/error.log', '0|1|nginx|adm|640', read_exit=1),
        _file_evidence('/var/log/nginx/andreykapro_xmlrpc.log', '0|4|www-data|www-data|644', read_exit=0),
        # a rotated archive should be excluded entirely from verdicts
        _file_evidence('/var/log/nginx/access.log.1', '2216258|5|www-data|www-data|640', read_exit=1),
    ]
    evidence = NginxGlobEvidence(glob_result=_cr(), per_file=per_file)
    verdicts, rotated_count = _nginx_verdicts(evidence)

    assert rotated_count == 1
    by_path = {v.path: v for v in verdicts}

    assert by_path['/var/log/nginx/access.log'].state == LogFileState.DECOY_EMPTY
    assert by_path['/var/log/nginx/error.log'].state == LogFileState.DECOY_EMPTY
    assert by_path['/var/log/nginx/andreykapro_access.log'].state == LogFileState.ACTIVE
    assert by_path['/var/log/nginx/andreykapro_error.log'].state == LogFileState.ACTIVE
    # xmlrpc has no active sibling of the same 'kind' (its own full filename
    # is its 'kind', since it doesn't end in access.log/error.log) — stays
    # genuinely stale, not reclassified as a decoy
    assert by_path['/var/log/nginx/andreykapro_xmlrpc.log'].state == LogFileState.STALE_EMPTY


def test_nginx_single_vhost_no_split_server_case():
    """Reproduces 192.168.88.20's real layout: plain access.log (active)
    and error.log (genuinely empty, no split, no active sibling) — must
    NOT be misclassified as a decoy."""
    per_file = [
        _file_evidence('/var/log/nginx/access.log', '140458|1|www-data|adm|640', read_exit=1),
        _file_evidence('/var/log/nginx/error.log', '0|2|www-data|adm|640', read_exit=1),
    ]
    evidence = NginxGlobEvidence(glob_result=_cr(), per_file=per_file)
    verdicts, rotated_count = _nginx_verdicts(evidence)

    assert rotated_count == 0
    by_path = {v.path: v for v in verdicts}
    assert by_path['/var/log/nginx/access.log'].state == LogFileState.ACTIVE
    assert by_path['/var/log/nginx/error.log'].state == LogFileState.STALE_EMPTY


def test_nginx_empty_glob_yields_no_verdicts():
    evidence = NginxGlobEvidence(glob_result=_cr(), per_file=[])
    verdicts, rotated_count = _nginx_verdicts(evidence)
    assert verdicts == []
    assert rotated_count == 0


# ===========================================================================
# _journal_verdict
# ===========================================================================


def test_journal_verdict_writer_real_case():
    """Reproduces the actual live output from 46.62.147.41 (project
    session notes, live VM verification): disk-usage with -q, and
    journald.conf containing only the [Journal] section header —
    confirmed 'on defaults' evidence."""
    evidence = JournalEvidence(
        disk_usage=_cr(stdout='Archived and active journals take up 111.8M in the file system.'),
        journald_conf=_cr(stdout='[Journal]'),
    )
    info = _journal_verdict(evidence)
    assert info.available is True
    assert info.disk_usage_raw == '111.8M'
    assert info.on_defaults is True


def test_journal_verdict_explicit_setting_is_not_on_defaults():
    evidence = JournalEvidence(
        disk_usage=_cr(stdout='Archived and active journals take up 455.1M in the file system.'),
        journald_conf=_cr(stdout='[Journal]\nStorage=persistent'),
    )
    info = _journal_verdict(evidence)
    assert info.on_defaults is False


def test_journal_verdict_collection_failure():
    evidence = JournalEvidence(
        disk_usage=_cr(completed=False, exit_code=None, stdout=''),
        journald_conf=_cr(completed=False, exit_code=None, stdout=''),
    )
    info = _journal_verdict(evidence)
    assert info.available is False
    assert info.on_defaults is None


# ===========================================================================
# build_findings — end-to-end shape checks against a realistic report
# ===========================================================================


def test_build_findings_missing_fail2ban_is_info_not_medium():
    """fail2ban is an OPTIONAL source (192.168.88.20's real case: not
    installed at all) — its absence must be 'info', not treated the same
    as a core log source (auth_log/syslog/kern_log) going missing."""
    from netaudit_pkg.log_discovery import LogDiscoveryEvidence, LogrotateEvidence

    missing_f2b = _file_evidence('/var/log/fail2ban.log', 'No such file or directory', stat_exit=1)
    missing_mail = _file_evidence('/var/log/mail.log', 'No such file or directory', stat_exit=1)
    missing_aide = _file_evidence('/var/log/aide/aide.log', 'No such file or directory', stat_exit=1)
    present_auth = _file_evidence('/var/log/auth.log', '1000|1|syslog|adm|640', read_exit=1)
    present_syslog = _file_evidence('/var/log/syslog', '1000|1|syslog|adm|640', read_exit=1)
    present_kern = _file_evidence('/var/log/kern.log', '1000|1|syslog|adm|640', read_exit=1)

    evidence = LogDiscoveryEvidence(
        auth_log=present_auth, syslog=present_syslog, kern_log=present_kern, fail2ban_log=missing_f2b,
        mail_log=missing_mail, aide_log=missing_aide,
        nginx=NginxGlobEvidence(glob_result=_cr(), per_file=[]),
        journal=JournalEvidence(disk_usage=_cr(stdout='take up 10M in the file system'),
                                 journald_conf=_cr(stdout='[Journal]')),
        logrotate_configs=[LogrotateEvidence(name='fail2ban', config_check=_cr(exit_code=1))],
    )
    report = build_report(evidence)
    findings = build_findings(report)

    f2b_findings = [f for f in findings if 'fail2ban_log' in f['title']]
    assert len(f2b_findings) == 1
    assert f2b_findings[0]['severity'] == 'info'


def test_build_findings_core_source_missing_is_medium():
    from netaudit_pkg.log_discovery import LogDiscoveryEvidence

    missing_auth = _file_evidence('/var/log/auth.log', 'No such file or directory', stat_exit=1)
    missing_syslog = _file_evidence('/var/log/syslog', 'No such file or directory', stat_exit=1)
    missing_kern = _file_evidence('/var/log/kern.log', 'No such file or directory', stat_exit=1)
    missing_f2b = _file_evidence('/var/log/fail2ban.log', 'No such file or directory', stat_exit=1)
    missing_mail = _file_evidence('/var/log/mail.log', 'No such file or directory', stat_exit=1)
    missing_aide = _file_evidence('/var/log/aide/aide.log', 'No such file or directory', stat_exit=1)

    evidence = LogDiscoveryEvidence(
        auth_log=missing_auth, syslog=missing_syslog, kern_log=missing_kern, fail2ban_log=missing_f2b,
        mail_log=missing_mail, aide_log=missing_aide,
        nginx=NginxGlobEvidence(glob_result=_cr(), per_file=[]),
        journal=JournalEvidence(disk_usage=_cr(completed=False, exit_code=None, stdout=''),
                                 journald_conf=_cr(completed=False, exit_code=None, stdout='')),
        logrotate_configs=[],
    )
    report = build_report(evidence)
    findings = build_findings(report)

    auth_findings = [f for f in findings if '/var/log/auth.log' in f['title']]
    assert len(auth_findings) == 1
    assert auth_findings[0]['severity'] == 'medium'


def test_build_findings_requires_sudo_is_ok_not_a_problem():
    """A security log requiring sudo to read is the EXPECTED, healthy
    state on both real hosts — must be 'ok', not flagged as an issue."""
    from netaudit_pkg.log_discovery import LogDiscoveryEvidence, LogrotateEvidence

    protected_auth = _file_evidence('/var/log/auth.log', '1000|1|syslog|adm|640', read_exit=1)
    protected_syslog = _file_evidence('/var/log/syslog', '1000|1|syslog|adm|640', read_exit=1)
    protected_kern = _file_evidence('/var/log/kern.log', '1000|1|syslog|adm|640', read_exit=1)
    missing_f2b = _file_evidence('/var/log/fail2ban.log', 'No such file or directory', stat_exit=1)
    missing_mail = _file_evidence('/var/log/mail.log', 'No such file or directory', stat_exit=1)
    missing_aide = _file_evidence('/var/log/aide/aide.log', 'No such file or directory', stat_exit=1)

    evidence = LogDiscoveryEvidence(
        auth_log=protected_auth, syslog=protected_syslog, kern_log=protected_kern, fail2ban_log=missing_f2b,
        mail_log=missing_mail, aide_log=missing_aide,
        nginx=NginxGlobEvidence(glob_result=_cr(), per_file=[]),
        journal=JournalEvidence(disk_usage=_cr(stdout='take up 10M in the file system'),
                                 journald_conf=_cr(stdout='[Journal]')),
        logrotate_configs=[LogrotateEvidence(name='rsyslog', config_check=_cr(exit_code=0))],
    )
    report = build_report(evidence)
    findings = build_findings(report)

    auth_findings = [f for f in findings if '/var/log/auth.log' in f['title']]
    assert len(auth_findings) == 1
    assert auth_findings[0]['severity'] == 'ok'
    assert 'elevated access' in auth_findings[0]['title']


def test_build_findings_nginx_decoy_is_info():
    from netaudit_pkg.log_discovery import LogDiscoveryEvidence

    missing_auth = _file_evidence('/var/log/auth.log', 'No such file or directory', stat_exit=1)
    missing_syslog = _file_evidence('/var/log/syslog', 'No such file or directory', stat_exit=1)
    missing_kern = _file_evidence('/var/log/kern.log', 'No such file or directory', stat_exit=1)
    missing_f2b = _file_evidence('/var/log/fail2ban.log', 'No such file or directory', stat_exit=1)
    missing_mail = _file_evidence('/var/log/mail.log', 'No such file or directory', stat_exit=1)
    missing_aide = _file_evidence('/var/log/aide/aide.log', 'No such file or directory', stat_exit=1)
    nginx_evidence = NginxGlobEvidence(
        glob_result=_cr(),
        per_file=[
            _file_evidence('/var/log/nginx/access.log', '0|1|nginx|adm|640', read_exit=1),
            _file_evidence('/var/log/nginx/andreykapro_access.log', '100|2|www-data|www-data|640', read_exit=1),
        ],
    )
    evidence = LogDiscoveryEvidence(
        auth_log=missing_auth, syslog=missing_syslog, kern_log=missing_kern, fail2ban_log=missing_f2b,
        mail_log=missing_mail, aide_log=missing_aide, nginx=nginx_evidence,
        journal=JournalEvidence(disk_usage=_cr(completed=False, exit_code=None, stdout=''),
                                 journald_conf=_cr(completed=False, exit_code=None, stdout='')),
        logrotate_configs=[],
    )
    report = build_report(evidence)
    findings = build_findings(report)

    decoy_findings = [f for f in findings if 'unused default log' in f['title']]
    assert len(decoy_findings) == 1
    assert decoy_findings[0]['severity'] == 'info'


# ===========================================================================
# nginx activity vs rotation matrix — per project session decision
# (2026-08-18, live VM verification against 46.62.147.41): zero active
# current files immediately after a real logrotate cycle must not read as
# an alarm on its own — rotation history is strong evidence this is a
# normal post-rotation gap. Matrix:
#   active>0             -> ok, regardless of rotated count
#   active==0, rotated>0 -> info (likely just rotated)
#   active==0, rotated==0 -> medium (no evidence nginx ever logged here)
# ===========================================================================


def _nginx_report_with(per_file, rotated_count):
    """Builds a minimal LogDiscoveryReport with only nginx populated, for
    isolating build_findings()'s nginx branch from the rest of the report
    shape."""
    from netaudit_pkg.checks.log_discovery_audit import JournalInfo, LogDiscoveryReport

    return LogDiscoveryReport(
        fixed_sources=[], nginx_sources=per_file, nginx_rotated_count=rotated_count,
        journal=JournalInfo(available=False, disk_usage_bytes=None, disk_usage_raw=None, on_defaults=None),
        logrotate=[],
    )


def test_zero_active_with_rotated_logs_is_info():
    """The exact real case from 46.62.147.41: andreykapro_access.log and
    andreykapro_error.log both size=0 (just rotated), with 89 archived
    files present."""
    stale = _file_verdict(
        _file_evidence('/var/log/nginx/andreykapro_access.log', '0|1|nginx|adm|640', read_exit=1),
        SourceType.NGINX_LOG,
    )
    report = _nginx_report_with([stale], rotated_count=89)
    findings = build_findings(report)

    nginx_findings = [f for f in findings if 'nginx log' in f['title'].lower()]
    assert len(nginx_findings) == 1
    assert nginx_findings[0]['severity'] == 'info'
    assert 'rotation' in nginx_findings[0]['title'].lower()


def test_zero_active_without_rotated_logs_is_medium():
    """No current data AND no rotation history at all — the one case in
    the matrix that actually warrants a flag."""
    stale = _file_verdict(
        _file_evidence('/var/log/nginx/access.log', '0|1|nginx|adm|640', read_exit=1),
        SourceType.NGINX_LOG,
    )
    report = _nginx_report_with([stale], rotated_count=0)
    findings = build_findings(report)

    nginx_findings = [f for f in findings if 'nginx log' in f['title'].lower()]
    assert len(nginx_findings) == 1
    assert nginx_findings[0]['severity'] == 'medium'
    assert 'no rotation history' in nginx_findings[0]['title'].lower()


def test_active_logs_are_not_flagged():
    """A currently-active file means 'ok', regardless of how much
    rotation history exists alongside it — rotation count is irrelevant
    once there's live data."""
    active = _file_verdict(
        _file_evidence('/var/log/nginx/andreykapro_access.log', '14638129|1|www-data|www-data|640', read_exit=1),
        SourceType.NGINX_LOG,
    )
    report = _nginx_report_with([active], rotated_count=89)
    findings = build_findings(report)

    nginx_findings = [f for f in findings if 'active nginx log' in f['title'].lower()]
    assert len(nginx_findings) == 1
    assert nginx_findings[0]['severity'] == 'ok'
