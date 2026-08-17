"""Tests for netaudit_pkg.log_discovery: read-only Logs Audit Discovery
(Iteration 1) — stat + test -r evidence for fixed file sources, a
glob-discovered set of nginx logs, and systemd-journal state. This module
deliberately collects ONLY evidence — no available/readable/requires_sudo
verdicts, no findings — see log_discovery.py's own docstring. These tests
verify the evidence is correctly collected and correctly split per source,
not that any particular discovery state is "good" or "bad" (that belongs
to checks/log_discovery_audit.py's semantic layer, tested separately).

Session-note anchors covered here (see log_discovery.py's own docstring
for full background, and the project's Discovery Contract v1 freeze):
  DC-1: stat succeeding (exit_code==0) says NOTHING about read_probe —
        empirically confirmed on both real hosts that a 640 syslog:adm
        file is fully stat-able by an unprivileged, non-adm user.
  DC-2: stat exit_code != 0 must not be assumed to mean "file does not
        exist" without also checking the error text.
  DC-3: nginx discovery must be glob-based, not hardcoded filenames — an
        empty glob result (completed, exit_code=0, zero matches) is a
        valid, confirmed result, not a collection failure.
  DC-4: a dropped/truncated SSH command (no completion marker at all)
        must surface as completed=False, exit_code=None — never as a
        confirmed failure or confirmed success.
"""

from __future__ import annotations

from netaudit_pkg.log_discovery import (
    _FIXED_FILE_SOURCES,
    NGINX_LOG_DIR,
    collect_log_discovery,
)
from tests.conftest import ExitCodeFakeSSHExecutor

# ===========================================================================
# _collect_log_file (via collect_log_discovery's auth_log field) —
# stat + test -r independence
# ===========================================================================


def test_file_exists_and_readable():
    """DC-1 baseline: both probes succeed and agree — a world-readable
    or same-group file."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            "stat -c '%s|%Y|%U|%G|%a' /var/log/auth.log": '320243|1787001461|syslog|adm|644',
            'test -r /var/log/auth.log': '',
        },
        exit_codes={
            "stat -c '%s|%Y|%U|%G|%a' /var/log/auth.log": 0,
            'test -r /var/log/auth.log': 0,
        },
    )
    evidence = collect_log_discovery(fake)
    assert evidence.auth_log.stat_result.completed is True
    assert evidence.auth_log.stat_result.exit_code == 0
    assert '320243|1787001461|syslog|adm|644' in evidence.auth_log.stat_result.stdout
    assert evidence.auth_log.read_probe.completed is True
    assert evidence.auth_log.read_probe.exit_code == 0


def test_file_exists_but_not_readable_dc1_empirical_case():
    """DC-1 — the actual empirically-confirmed case from both real hosts
    (project session notes, 2026-08-18): stat succeeds (exit 0, full
    metadata) on a 640 syslog:adm file even though the connecting user
    (andreykapro / netaudit, neither in group adm) cannot read its
    content. test -r must independently report exit_code=1 (not
    readable) — this is the central fact the whole two-probe design
    exists to capture."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            "stat -c '%s|%Y|%U|%G|%a' /var/log/auth.log": '320243|1787001461|syslog|adm|640',
            'test -r /var/log/auth.log': '',
        },
        exit_codes={
            "stat -c '%s|%Y|%U|%G|%a' /var/log/auth.log": 0,
            'test -r /var/log/auth.log': 1,
        },
    )
    evidence = collect_log_discovery(fake)
    assert evidence.auth_log.stat_result.exit_code == 0
    assert 'syslog|adm|640' in evidence.auth_log.stat_result.stdout
    assert evidence.auth_log.read_probe.exit_code == 1
    # neither probe result may be derived from the other at collection time —
    # both are present and independently meaningful
    assert evidence.auth_log.stat_result.exit_code != evidence.auth_log.read_probe.exit_code


def test_file_does_not_exist():
    """DC-2: a confirmed 'No such file or directory' — genuinely absent.
    (fail2ban.log on 192.168.88.20, confirmed via real inventory.)"""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            "stat -c '%s|%Y|%U|%G|%a' /var/log/fail2ban.log":
                "stat: cannot statx '/var/log/fail2ban.log': No such file or directory",
        },
        exit_codes={
            "stat -c '%s|%Y|%U|%G|%a' /var/log/fail2ban.log": 1,
        },
    )
    evidence = collect_log_discovery(fake)
    assert evidence.fail2ban_log.stat_result.completed is True
    assert evidence.fail2ban_log.stat_result.exit_code == 1
    assert 'No such file or directory' in evidence.fail2ban_log.stat_result.stdout


def test_stat_collection_failure_is_not_confirmed_absence():
    """DC-4: no completion marker at all (dropped/truncated SSH command)
    must surface as completed=False, exit_code=None — the consumer must
    never treat this the same as a confirmed 'file does not exist'
    (DC-2) result. No exit_codes entry registered for this command
    simulates exactly that."""
    fake = ExitCodeFakeSSHExecutor(responses={}, exit_codes={})
    evidence = collect_log_discovery(fake)
    assert evidence.auth_log.stat_result.completed is False
    assert evidence.auth_log.stat_result.exit_code is None


def test_zero_byte_log_is_not_a_collection_failure():
    """A confirmed, genuinely empty file (size=0) is valid evidence, not
    an error — e.g. writer's /var/log/nginx/andreykapro_error.log
    (nginx:adm, size 0, real inventory)."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            "stat -c '%s|%Y|%U|%G|%a' /var/log/mail.log": '0|1787001461|syslog|adm|640',
            'test -r /var/log/mail.log': '',
        },
        exit_codes={
            "stat -c '%s|%Y|%U|%G|%a' /var/log/mail.log": 0,
            'test -r /var/log/mail.log': 1,
        },
    )
    evidence = collect_log_discovery(fake)
    assert evidence.mail_log.stat_result.completed is True
    assert evidence.mail_log.stat_result.stdout.startswith('0|')


# ===========================================================================
# All fixed sources are actually probed
# ===========================================================================


def test_all_fixed_sources_are_collected():
    """Every entry in _FIXED_FILE_SOURCES must produce evidence — this
    guards against silently dropping a source when the dict is extended
    later without updating the top-level collector's return statement."""
    fake = ExitCodeFakeSSHExecutor(responses={}, exit_codes={})
    evidence = collect_log_discovery(fake)
    assert evidence.auth_log.path == '/var/log/auth.log'
    assert evidence.syslog.path == '/var/log/syslog'
    assert evidence.kern_log.path == '/var/log/kern.log'
    assert evidence.fail2ban_log.path == '/var/log/fail2ban.log'
    assert evidence.mail_log.path == '/var/log/mail.log'
    assert evidence.aide_log.path == '/var/log/aide/aide.log'
    # exactly the fixed sources this iteration scopes — no silent scope creep
    assert len(_FIXED_FILE_SOURCES) == 6


def test_each_fixed_source_probed_exactly_once():
    """No source should be double-collected (e.g. via an accidental loop
    bug) — each stat command appears exactly once in the call log."""
    fake = ExitCodeFakeSSHExecutor(responses={}, exit_codes={})
    collect_log_discovery(fake)
    stat_calls = [c for c in fake.calls if c.strip().startswith('{ stat')]
    for name, (path, _) in _FIXED_FILE_SOURCES.items():
        matching = [c for c in stat_calls if path in c]
        assert len(matching) == 1, f'{name} ({path}) probed {len(matching)} times, expected 1'


# ===========================================================================
# nginx glob discovery — DC-3
# ===========================================================================


def test_nginx_glob_empty_result_is_not_a_collection_failure():
    """DC-3: find(1) with zero matches is completed=True, exit_code=0,
    empty stdout — a confirmed, valid result. Must not be treated as a
    collection failure (would incorrectly suppress the 'nginx not
    installed / no logs dir' finding at the semantic layer)."""
    fake = ExitCodeFakeSSHExecutor(
        responses={f'find {NGINX_LOG_DIR}': ''},
        exit_codes={f'find {NGINX_LOG_DIR}': 0},
    )
    evidence = collect_log_discovery(fake)
    assert evidence.nginx.glob_result.completed is True
    assert evidence.nginx.glob_result.exit_code == 0
    assert evidence.nginx.per_file == []


def test_nginx_glob_discovers_vhost_split_files_not_hardcoded_names():
    """DC-3 — writer's real vhost-split layout (project inventory,
    2026-08-18): NOT a single access.log/error.log pair. The collector
    must report whatever find(1) actually returned, including
    non-standard vhost-prefixed filenames, and probe each one."""
    glob_stdout = (
        '/var/log/nginx/access.log\n'
        '/var/log/nginx/andreykapro_access.log\n'
        '/var/log/nginx/andreykapro_error.log\n'
        '/var/log/nginx/andreykapro_xmlrpc.log\n'
    )
    fake = ExitCodeFakeSSHExecutor(
        responses={
            f'find {NGINX_LOG_DIR}': glob_stdout,
            "stat -c '%s|%Y|%U|%G|%a' /var/log/nginx/access.log": '0|1|nginx|adm|640',
            'test -r /var/log/nginx/access.log': '',
            "stat -c '%s|%Y|%U|%G|%a' /var/log/nginx/andreykapro_access.log": '14638129|2|www-data|www-data|640',
            'test -r /var/log/nginx/andreykapro_access.log': '',
            "stat -c '%s|%Y|%U|%G|%a' /var/log/nginx/andreykapro_error.log": '1594873|3|www-data|www-data|640',
            'test -r /var/log/nginx/andreykapro_error.log': '',
            "stat -c '%s|%Y|%U|%G|%a' /var/log/nginx/andreykapro_xmlrpc.log": '0|4|www-data|www-data|644',
            'test -r /var/log/nginx/andreykapro_xmlrpc.log': '',
        },
        exit_codes={
            f'find {NGINX_LOG_DIR}': 0,
            "stat -c '%s|%Y|%U|%G|%a' /var/log/nginx/access.log": 0,
            'test -r /var/log/nginx/access.log': 1,
            "stat -c '%s|%Y|%U|%G|%a' /var/log/nginx/andreykapro_access.log": 0,
            'test -r /var/log/nginx/andreykapro_access.log': 1,
            "stat -c '%s|%Y|%U|%G|%a' /var/log/nginx/andreykapro_error.log": 0,
            'test -r /var/log/nginx/andreykapro_error.log': 1,
            "stat -c '%s|%Y|%U|%G|%a' /var/log/nginx/andreykapro_xmlrpc.log": 0,
            'test -r /var/log/nginx/andreykapro_xmlrpc.log': 0,
        },
    )
    evidence = collect_log_discovery(fake)
    assert len(evidence.nginx.per_file) == 4
    paths = {f.path for f in evidence.nginx.per_file}
    assert paths == {
        '/var/log/nginx/access.log',
        '/var/log/nginx/andreykapro_access.log',
        '/var/log/nginx/andreykapro_error.log',
        '/var/log/nginx/andreykapro_xmlrpc.log',
    }
    # the world-readable decoy stub is distinguishable from the others at
    # the evidence level (readable=0 exit code), classification itself is
    # the semantic layer's job, not this collector's
    xmlrpc = next(f for f in evidence.nginx.per_file if f.path.endswith('xmlrpc.log'))
    assert xmlrpc.read_probe.exit_code == 0


def test_nginx_glob_collection_failure_yields_no_per_file_probes():
    """If the find(1) call itself never completes (dropped SSH command),
    no per-file probes should be attempted — there's nothing to iterate
    over, and attempting per-file probes against unknown paths would be
    meaningless."""
    fake = ExitCodeFakeSSHExecutor(responses={}, exit_codes={})
    evidence = collect_log_discovery(fake)
    assert evidence.nginx.glob_result.completed is False
    assert evidence.nginx.per_file == []


# ===========================================================================
# journald evidence
# ===========================================================================


def test_journal_disk_usage_collected():
    """-q suppresses journalctl's hint banner — confirmed necessary on
    live VM verification against 46.62.147.41 (project session notes):
    without -q, a multi-line hint precedes the actual disk-usage line in
    stdout. The command construction itself (with -q) is what's under
    test here; see also the live-output shape asserted below."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'journalctl --disk-usage -q':
                'Archived and active journals take up 111.8M in the file system.',
        },
        exit_codes={'journalctl --disk-usage -q': 0},
    )
    evidence = collect_log_discovery(fake)
    assert evidence.journal.disk_usage.completed is True
    assert '111.8M' in evidence.journal.disk_usage.stdout


def test_journald_conf_on_defaults_yields_only_section_header():
    """Corrected per live VM verification against 46.62.147.41 (project
    session notes): a fully-default journald.conf is NOT empty grep
    output — `[Journal]` (the section header) is itself a non-comment,
    non-blank line, so grep confirms exit_code=0 with '[Journal]' as the
    sole matched line. This is the actual empirical 'on defaults' signal
    the consumer must recognize — not an empty stdout, which was this
    test's previous (incorrect, unverified) assumption."""
    fake = ExitCodeFakeSSHExecutor(
        responses={"grep -v '^#\\|^$' /etc/systemd/journald.conf": '[Journal]'},
        exit_codes={"grep -v '^#\\|^$' /etc/systemd/journald.conf": 0},
    )
    evidence = collect_log_discovery(fake)
    assert evidence.journal.journald_conf.completed is True
    assert evidence.journal.journald_conf.exit_code == 0
    assert evidence.journal.journald_conf.stdout.strip() == '[Journal]'


# ===========================================================================
# logrotate.d config presence
# ===========================================================================


def test_logrotate_config_present():
    fake = ExitCodeFakeSSHExecutor(
        responses={'test -f /etc/logrotate.d/fail2ban': ''},
        exit_codes={'test -f /etc/logrotate.d/fail2ban': 0},
    )
    evidence = collect_log_discovery(fake)
    f2b_entry = next(e for e in evidence.logrotate_configs if e.name == 'fail2ban')
    assert f2b_entry.config_check.exit_code == 0


def test_logrotate_config_absent_is_valid_evidence():
    """192.168.88.20's real inventory: fail2ban.log itself doesn't exist,
    and there's no logrotate.d/fail2ban entry either — both are valid
    'not present' facts, not errors."""
    fake = ExitCodeFakeSSHExecutor(
        responses={'test -f /etc/logrotate.d/fail2ban': ''},
        exit_codes={'test -f /etc/logrotate.d/fail2ban': 1},
    )
    evidence = collect_log_discovery(fake)
    f2b_entry = next(e for e in evidence.logrotate_configs if e.name == 'fail2ban')
    assert f2b_entry.config_check.exit_code == 1


def test_logrotate_configs_deduplicated_by_name():
    """auth_log, syslog, kern_log, and mail_log all share the 'rsyslog'
    logrotate.d entry (confirmed on both real hosts) — the config
    presence probe for 'rsyslog' must run exactly once, not four times."""
    fake = ExitCodeFakeSSHExecutor(
        responses={'test -f /etc/logrotate.d/rsyslog': ''},
        exit_codes={'test -f /etc/logrotate.d/rsyslog': 0},
    )
    evidence = collect_log_discovery(fake)
    rsyslog_entries = [e for e in evidence.logrotate_configs if e.name == 'rsyslog']
    assert len(rsyslog_entries) == 1
    rsyslog_calls = [c for c in fake.calls if '/etc/logrotate.d/rsyslog' in c]
    assert len(rsyslog_calls) == 1


# ===========================================================================
# No sudo anywhere — Iteration 1 is deliberately unprivileged
# ===========================================================================


def test_no_probe_uses_sudo():
    """Central design invariant: log_discovery.py must never call
    ssh.sudo() — every probe is unprivileged by design, since the whole
    point of Discovery is to observe what an unprivileged connection
    already can and cannot see (see this module's docstring)."""

    class SudoTracker(ExitCodeFakeSSHExecutor):
        def sudo(self, cmd: str, timeout: int = 20):
            raise AssertionError(f'log_discovery.py must never call sudo(); got: {cmd!r}')

    fake = SudoTracker(responses={}, exit_codes={})
    collect_log_discovery(fake)  # raises via SudoTracker.sudo() if this invariant is ever broken
