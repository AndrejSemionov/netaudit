"""Tests for netaudit_pkg.checks.server_security.audit_fail2ban() - the
semantic layer that turns netaudit_pkg.fail2ban_config.Fail2banEvidence
(raw, uninterpreted evidence) into PRESENT/NOT_PRESENT/UNKNOWN,
SUCCESS/PARSE_FAILURE/ACCESS_DENIED/COMMAND_ERROR, and per-jail
CONFIRMED/UNKNOWN verdicts and findings.

This is the regression suite for the quality-audit findings FB-1
(which-collapse of collection failure into "not installed"), FB-2/FB-3
(exit_code==0 from an unprivileged status call is NOT sufficient
evidence of success - empirically confirmed on 46.62.147.41 - and no
sudo ever being attempted), FB-4/FB-6 (a jail-list parse failure
silently read as "confirmed zero jails"), and FB-5 (a per-jail query
failure silently contributing 0 to the total-bans count instead of
being surfaced as partial collection).

Two layers of tests:
  - Unit tests for the pure verdict functions (_fail2ban_binary_verdict,
    _fail2ban_status_verdict, _fail2ban_jail_verdict) - these take a
    Fail2banEvidence/JailEvidence and return (verdict, context) with no
    I/O, so they're tested directly without any SSH mocking.
  - Integration tests for audit_fail2ban() itself, verifying the actual
    findings (severity, title, requires_manual_verification) it produces
    for each evidence shape - this is what proves the original bugs are
    actually fixed, not just that evidence is parsed correctly.
"""

from __future__ import annotations

from netaudit_pkg.checks.server_security import (
    _fail2ban_binary_verdict,
    _fail2ban_jail_verdict,
    _fail2ban_status_verdict,
    audit_fail2ban,
)
from netaudit_pkg.fail2ban_config import CommandResult, Fail2banEvidence, JailEvidence
from tests.conftest import ExitCodeFakeSSHExecutor

# ===========================================================================
# Evidence-building helpers
# ===========================================================================

def _cr(completed=True, exit_code=0, stdout='', command='') -> CommandResult:
    return CommandResult(completed=completed, exit_code=exit_code, stdout=stdout, command=command)


def _evidence(binary_check=None, status_unpriv=None, status_sudo=None, jails=None) -> Fail2banEvidence:
    """Builds a Fail2banEvidence with sensible defaults (binary not
    present, no status attempted) - tests override only the field(s)
    relevant to what they're checking."""
    return Fail2banEvidence(
        binary_check=binary_check if binary_check is not None else _cr(exit_code=127),
        status_unpriv=status_unpriv if status_unpriv is not None else _cr(completed=False, exit_code=None),
        status_sudo=status_sudo,
        jails=jails if jails is not None else [],
    )


# ===========================================================================
# _fail2ban_binary_verdict — unit tests
# ===========================================================================

def test_binary_verdict_present():
    ev = _evidence(binary_check=_cr(exit_code=0, stdout='/usr/bin/fail2ban-client'))
    verdict, _ = _fail2ban_binary_verdict(ev)
    assert verdict == 'PRESENT'


def test_binary_verdict_not_present_exit_127():
    """Reproduces 192.168.88.20."""
    ev = _evidence(binary_check=_cr(exit_code=127))
    verdict, _ = _fail2ban_binary_verdict(ev)
    assert verdict == 'NOT_PRESENT'


def test_binary_verdict_unknown_on_other_nonzero_exit():
    """FB-1 correction: an exit code that is neither 0 nor 127 must be
    UNKNOWN, never NOT_PRESENT."""
    ev = _evidence(binary_check=_cr(exit_code=2, stdout='unexpected'))
    verdict, ctx = _fail2ban_binary_verdict(ev)
    assert verdict == 'UNKNOWN'
    assert 'reason' in ctx


def test_binary_verdict_unknown_on_collection_failure():
    ev = _evidence(binary_check=_cr(completed=False, exit_code=None))
    verdict, ctx = _fail2ban_binary_verdict(ev)
    assert verdict == 'UNKNOWN'
    assert 'reason' in ctx


# ===========================================================================
# _fail2ban_status_verdict — unit tests
# ===========================================================================

def test_status_verdict_success_with_jails():
    status_text = 'Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, nginx-auth'
    ev = _evidence(status_sudo=_cr(exit_code=0, stdout=status_text))
    verdict, ctx = _fail2ban_status_verdict(ev)
    assert verdict == 'SUCCESS'
    assert ctx['jail_names'] == ['sshd', 'nginx-auth']


def test_status_verdict_success_confirmed_empty_jail_list():
    status_text = 'Status\n|- Number of jail:\t0\n`- Jail list:\t'
    ev = _evidence(status_sudo=_cr(exit_code=0, stdout=status_text))
    verdict, ctx = _fail2ban_status_verdict(ev)
    assert verdict == 'SUCCESS'
    assert ctx['jail_names'] == []


def test_status_verdict_parse_failure_not_confirmed_empty():
    """FB-4/FB-6 fix: exit 0 but no 'Jail list:' line at all must be
    PARSE_FAILURE, distinct from a confirmed-empty jail list."""
    ev = _evidence(status_sudo=_cr(exit_code=0, stdout='some unrecognized output'))
    verdict, ctx = _fail2ban_status_verdict(ev)
    assert verdict == 'PARSE_FAILURE'
    assert 'raw_snippet' in ctx


def test_status_verdict_access_denied_from_sudo_nonzero():
    ev = _evidence(status_sudo=_cr(
        exit_code=1,
        stdout='ERROR Permission denied to socket: /var/run/fail2ban/fail2ban.sock, (you must be root)',
    ))
    verdict, ctx = _fail2ban_status_verdict(ev)
    assert verdict == 'ACCESS_DENIED'
    assert ctx['exit_code'] == 1


def test_status_verdict_command_error_from_sudo_nonzero_no_denial_text():
    """A confirmed nonzero exit that is NOT a permission-denied message
    must be COMMAND_ERROR, not automatically ACCESS_DENIED - the
    corrected contract (any non-zero != permission denied)."""
    ev = _evidence(status_sudo=_cr(exit_code=1, stdout='fail2ban-client: could not connect to socket (daemon not running)'))
    verdict, ctx = _fail2ban_status_verdict(ev)
    assert verdict == 'COMMAND_ERROR'
    assert ctx['exit_code'] == 1


def test_status_verdict_unknown_on_none():
    ev = _evidence(status_sudo=None)
    verdict, _ctx = _fail2ban_status_verdict(ev)
    assert verdict == 'UNKNOWN'


def test_status_verdict_unknown_on_collection_failure():
    ev = _evidence(status_sudo=_cr(completed=False, exit_code=None))
    verdict, _ctx = _fail2ban_status_verdict(ev)
    assert verdict == 'UNKNOWN'


def test_status_verdict_unpriv_exit_0_with_error_never_becomes_success():
    """The central empirically-confirmed 46.62.147.41 case: even though
    status_unpriv reports exit_code==0, it must NEVER be consulted to
    produce a SUCCESS verdict - only status_sudo drives this function.
    Here status_sudo genuinely succeeds, proving status_unpriv's content
    is irrelevant to the outcome either way."""
    status_text = 'Status\n|- Number of jail:\t1\n`- Jail list:\tsshd'
    ev = _evidence(
        status_unpriv=_cr(exit_code=0, stdout='ERROR Permission denied to socket (you must be root)'),
        status_sudo=_cr(exit_code=0, stdout=status_text),
    )
    verdict, ctx = _fail2ban_status_verdict(ev)
    assert verdict == 'SUCCESS'
    assert ctx['jail_names'] == ['sshd']


def test_status_verdict_flags_unpriv_also_denied_in_context():
    """When sudo itself fails AND unpriv also shows a denial, the
    context should carry that fact for a richer finding detail - but
    this must never change the verdict category itself."""
    ev = _evidence(
        status_unpriv=_cr(exit_code=0, stdout='ERROR Permission denied to socket (you must be root)'),
        status_sudo=_cr(exit_code=1, stdout='ERROR Permission denied to socket (you must be root)'),
    )
    verdict, ctx = _fail2ban_status_verdict(ev)
    assert verdict == 'ACCESS_DENIED'
    assert ctx.get('unpriv_also_denied') is True


# ===========================================================================
# _fail2ban_jail_verdict — unit tests
# ===========================================================================

def test_jail_verdict_confirmed_with_bans():
    je = JailEvidence(name='sshd', status=_cr(
        exit_code=0, stdout='Status for the jail: sshd\n`- Currently banned:\t2\n`- Total banned:\t5'))
    verdict, ctx = _fail2ban_jail_verdict(je)
    assert verdict == 'CONFIRMED'
    assert ctx['currently_banned'] == 2
    assert ctx['total_banned'] == 5


def test_jail_verdict_confirmed_zero_bans_is_real_zero_not_none():
    """A jail that succeeds and genuinely reports 0 must be int 0, not
    None - only an UNPARSEABLE count should be None."""
    je = JailEvidence(name='sshd', status=_cr(
        exit_code=0, stdout='Status for the jail: sshd\n`- Currently banned:\t0\n`- Total banned:\t0'))
    verdict, ctx = _fail2ban_jail_verdict(je)
    assert verdict == 'CONFIRMED'
    assert ctx['currently_banned'] == 0
    assert ctx['total_banned'] == 0


def test_jail_verdict_confirmed_but_counts_unparseable_stay_none():
    """FB-5 fix, most direct case: exit 0 (success) but the ban-count
    lines are missing/unrecognized from stdout - must yield None, NEVER
    silently substituted with 0."""
    je = JailEvidence(name='sshd', status=_cr(exit_code=0, stdout='Status for the jail: sshd\n(unexpected format)'))
    verdict, ctx = _fail2ban_jail_verdict(je)
    assert verdict == 'CONFIRMED'
    assert ctx['currently_banned'] is None
    assert ctx['total_banned'] is None


def test_jail_verdict_unknown_on_nonzero_exit():
    je = JailEvidence(name='sshd', status=_cr(exit_code=1, stdout='error'))
    verdict, _ctx = _fail2ban_jail_verdict(je)
    assert verdict == 'UNKNOWN'


def test_jail_verdict_unknown_on_collection_failure():
    je = JailEvidence(name='sshd', status=_cr(completed=False, exit_code=None))
    verdict, _ctx = _fail2ban_jail_verdict(je)
    assert verdict == 'UNKNOWN'


# ===========================================================================
# audit_fail2ban() — integration tests (real findings, real severities)
# ===========================================================================

def _fake_not_installed():
    return ExitCodeFakeSSHExecutor(
        responses={'command -v fail2ban-client': ''},
        exit_codes={'command -v fail2ban-client': 127},
    )


def test_audit_not_installed():
    result = audit_fail2ban(_fake_not_installed())
    assert result['installed'] is False
    assert len(result['findings']) == 1
    assert result['findings'][0]['severity'] == 'medium'
    assert 'not installed' in result['findings'][0]['title']


def test_audit_binary_collection_failure_is_low_unknown_never_not_present():
    """FB-1 regression: a genuine collection failure on the binary check
    must produce a 'low' + requires_manual_verification finding, and
    must NEVER be silently treated as 'not installed'."""
    fake = ExitCodeFakeSSHExecutor()  # no responses at all -> no marker -> collection failure
    result = audit_fail2ban(fake)
    assert result['installed'] is True  # NOT False - collection failure != confirmed absence
    titles = [f['title'] for f in result['findings']]
    assert any('could not determine whether fail2ban is installed' in t for t in titles)
    unknown_finding = next(f for f in result['findings']
                           if 'could not determine whether fail2ban is installed' in f['title'])
    assert unknown_finding['severity'] == 'low'
    assert unknown_finding.get('requires_manual_verification') is True


def test_audit_status_parse_failure_is_low_unknown():
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v fail2ban-client': '/usr/bin/fail2ban-client',
            'fail2ban-client status': 'some unrecognized garbled output',
        },
        exit_codes={'command -v fail2ban-client': 0, 'fail2ban-client status': 0},
    )
    result = audit_fail2ban(fake)
    assert result['installed'] is True
    assert result['jails'] == []
    parse_finding = next(f for f in result['findings'] if 'could not be parsed' in f['title'])
    assert parse_finding['severity'] == 'low'
    assert parse_finding.get('requires_manual_verification') is True


def test_audit_status_access_denied_even_with_sudo_is_low():
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v fail2ban-client': '/usr/bin/fail2ban-client',
            'fail2ban-client status': 'ERROR Permission denied to socket (you must be root)',
        },
        exit_codes={'command -v fail2ban-client': 0, 'fail2ban-client status': 1},
    )
    result = audit_fail2ban(fake)
    assert result['installed'] is True
    assert result['jails'] == []
    finding = next(f for f in result['findings'] if 'status could not be confirmed' in f['title'])
    assert finding['severity'] == 'low'
    assert finding.get('requires_manual_verification') is True


def test_audit_success_confirmed_empty_jails_produces_no_finding():
    """SUCCESS + jails == [] must NOT produce 'no active jails' and must
    NOT produce 'ok' - it's a confirmed non-problem state, matching
    audit_sql()'s NOT_LISTENING precedent (no finding at all)."""
    status_text = 'Status\n|- Number of jail:\t0\n`- Jail list:\t'
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v fail2ban-client': '/usr/bin/fail2ban-client',
            'fail2ban-client status': status_text,
        },
        exit_codes={'command -v fail2ban-client': 0, 'fail2ban-client status': 0},
    )
    result = audit_fail2ban(fake)
    assert result['installed'] is True
    assert result['jails'] == []
    assert result['findings'] == []


def test_audit_success_all_jails_confirmed_produces_ok():
    status_text = 'Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, nginx-auth'
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v fail2ban-client': '/usr/bin/fail2ban-client',
            'status sshd': 'Status for the jail: sshd\n`- Currently banned:\t2\n`- Total banned:\t5',
            'status nginx-auth': 'Status for the jail: nginx-auth\n`- Currently banned:\t0\n`- Total banned:\t3',
            'fail2ban-client status': status_text,
        },
        exit_codes={
            'command -v fail2ban-client': 0,
            'status sshd': 0,
            'status nginx-auth': 0,
            'fail2ban-client status': 0,
        },
    )
    result = audit_fail2ban(fake)
    assert result['installed'] is True
    assert len(result['jails']) == 2
    ok_finding = next(f for f in result['findings'] if f['severity'] == 'ok')
    assert 'active jails: 2' in ok_finding['title']
    assert 'total bans: 8' in ok_finding['detail']  # 5 + 3
    assert not any(f['severity'] == 'low' for f in result['findings'])


def test_audit_no_ssh_jail_produces_medium():
    status_text = 'Status\n|- Number of jail:\t1\n`- Jail list:\tnginx-auth'
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v fail2ban-client': '/usr/bin/fail2ban-client',
            'status nginx-auth': 'Status for the jail: nginx-auth\n`- Currently banned:\t0\n`- Total banned:\t0',
            'fail2ban-client status': status_text,
        },
        exit_codes={
            'command -v fail2ban-client': 0,
            'status nginx-auth': 0,
            'fail2ban-client status': 0,
        },
    )
    result = audit_fail2ban(fake)
    medium_finding = next(f for f in result['findings'] if f['severity'] == 'medium')
    assert 'no jail for SSH' in medium_finding['title']


def test_audit_partial_jail_collection_5_of_6_is_low_never_ok():
    """The core aggregation-contract test: 6 jails total, 5 confirmed
    successfully, 1 unconfirmed (collection failure) - must produce a
    LOW finding with 'X of Y jails confirmed' text, requires_manual_
    verification=True, and NEVER an 'ok' finding for the jail summary."""
    status_text = ('Status\n|- Number of jail:\t6\n'
                   '`- Jail list:\tnginx-botsearch, nginx-http-auth, nginx-limit-req, '
                   'recidive, sshd, sshd-ddos')

    class OneJailFailsFake(ExitCodeFakeSSHExecutor):
        def sudo(self, cmd, timeout=20):
            self.calls.append(cmd)
            if 'status recidive' in cmd:
                return 'dropped mid-command, no marker', ''
            return self._respond(cmd)

    fake = OneJailFailsFake(
        responses={
            'command -v fail2ban-client': '/usr/bin/fail2ban-client',
            'status nginx-botsearch': 'Status for the jail: nginx-botsearch\n`- Currently banned:\t0\n`- Total banned:\t1',
            'status nginx-http-auth': 'Status for the jail: nginx-http-auth\n`- Currently banned:\t0\n`- Total banned:\t2',
            'status nginx-limit-req': 'Status for the jail: nginx-limit-req\n`- Currently banned:\t0\n`- Total banned:\t3',
            'status sshd-ddos': 'Status for the jail: sshd-ddos\n`- Currently banned:\t0\n`- Total banned:\t4',
            'status sshd': 'Status for the jail: sshd\n`- Currently banned:\t2\n`- Total banned:\t5',
            'fail2ban-client status': status_text,
        },
        exit_codes={
            'command -v fail2ban-client': 0,
            'status nginx-botsearch': 0,
            'status nginx-http-auth': 0,
            'status nginx-limit-req': 0,
            'status sshd-ddos': 0,
            'status sshd': 0,
            'fail2ban-client status': 0,
        },
    )
    result = audit_fail2ban(fake)

    assert result['installed'] is True
    assert len(result['jails']) == 6
    recidive_entry = next(j for j in result['jails'] if j['jail'] == 'recidive')
    assert recidive_entry['currently_banned'] is None
    assert recidive_entry['total_banned'] is None

    assert not any(f['severity'] == 'ok' for f in result['findings']), \
        'partial jail collection must NEVER produce an ok finding'
    partial_finding = next(f for f in result['findings']
                           if 'could not fully determine' in f['title'])
    assert partial_finding['severity'] == 'low'
    assert partial_finding.get('requires_manual_verification') is True
    assert '5 of 6 jails confirmed' in partial_finding['detail']
    assert 'recidive' in partial_finding['detail']
    # total_confirmed_bans = 1+2+3+4+5 = 15 (recidive's unconfirmed total excluded)
    assert 'total confirmed bans: 15' in partial_finding['detail']


def test_audit_partial_jail_collection_access_denied_per_jail_also_low():
    """Same aggregation contract, but the failing jail's query completed
    with a confirmed nonzero exit (ACCESS_DENIED-shaped) rather than a
    raw collection failure - still must be LOW, never OK, and the jail
    still counts as unconfirmed (not a 0)."""
    status_text = 'Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, nginx-auth'
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'command -v fail2ban-client': '/usr/bin/fail2ban-client',
            'status sshd': 'Status for the jail: sshd\n`- Currently banned:\t1\n`- Total banned:\t2',
            'status nginx-auth': 'permission denied',
            'fail2ban-client status': status_text,
        },
        exit_codes={
            'command -v fail2ban-client': 0,
            'status sshd': 0,
            'status nginx-auth': 1,
            'fail2ban-client status': 0,
        },
    )
    result = audit_fail2ban(fake)
    assert not any(f['severity'] == 'ok' for f in result['findings'])
    partial_finding = next(f for f in result['findings'] if 'could not fully determine' in f['title'])
    assert partial_finding['severity'] == 'low'
    assert '1 of 2 jails confirmed' in partial_finding['detail']
    nginx_entry = next(j for j in result['jails'] if j['jail'] == 'nginx-auth')
    assert nginx_entry['currently_banned'] is None
    assert nginx_entry['total_banned'] is None


def test_audit_real_host_shape_46_62_147_41():
    """End-to-end reproduction of the empirically-confirmed real host:
    unprivileged status returns exit 0 with an embedded permission-
    denied error, sudo status succeeds with 6 real jails, and the
    overall result is a clean 'ok' (no partial collection in this
    shape - all 6 jails confirm)."""
    unpriv_error = ('2026-08-16 18:34:19,309 fail2ban [345062]: ERROR   Permission denied to '
                    'socket: /var/run/fail2ban/fail2ban.sock, (you must be root)')
    status_text = ('Status\n|- Number of jail:\t6\n'
                   '`- Jail list:\tnginx-botsearch, nginx-http-auth, nginx-limit-req, '
                   'recidive, sshd, sshd-ddos')

    class RealHostFake(ExitCodeFakeSSHExecutor):
        def run(self, cmd, timeout=20):
            self.calls.append(cmd)
            if 'fail2ban-client status' in cmd:
                import re as _re
                m = _re.search(r'__NETAUDIT_RC_[0-9a-f]+__', cmd)
                if m:
                    return f'{unpriv_error}\n{m.group(0)}:0\n', ''
            return self._respond(cmd)

        def sudo(self, cmd, timeout=20):
            self.calls.append(cmd)
            return self._respond(cmd)

    fake = RealHostFake(
        responses={
            'command -v fail2ban-client': '/usr/bin/fail2ban-client',
            'status nginx-botsearch': 'Status for the jail: nginx-botsearch\n`- Currently banned:\t0\n`- Total banned:\t0',
            'status nginx-http-auth': 'Status for the jail: nginx-http-auth\n`- Currently banned:\t0\n`- Total banned:\t0',
            'status nginx-limit-req': 'Status for the jail: nginx-limit-req\n`- Currently banned:\t0\n`- Total banned:\t0',
            'status recidive': 'Status for the jail: recidive\n`- Currently banned:\t0\n`- Total banned:\t0',
            'status sshd-ddos': 'Status for the jail: sshd-ddos\n`- Currently banned:\t0\n`- Total banned:\t0',
            'status sshd': 'Status for the jail: sshd\n`- Currently banned:\t0\n`- Total banned:\t0',
            'fail2ban-client status': status_text,
        },
        exit_codes={
            'command -v fail2ban-client': 0,
            'status nginx-botsearch': 0,
            'status nginx-http-auth': 0,
            'status nginx-limit-req': 0,
            'status recidive': 0,
            'status sshd-ddos': 0,
            'status sshd': 0,
            'fail2ban-client status': 0,
        },
    )
    result = audit_fail2ban(fake)
    assert result['installed'] is True
    assert len(result['jails']) == 6
    ok_finding = next(f for f in result['findings'] if f['severity'] == 'ok')
    assert 'active jails: 6' in ok_finding['title']
    assert not any(f['severity'] == 'low' for f in result['findings'])
