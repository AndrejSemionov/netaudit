"""Tests for netaudit_pkg.checks.server_security.audit_sql() - the
semantic layer that turns netaudit_pkg.sql_config.SQLEvidence (raw,
uninterpreted evidence) into PRESENT/NOT_PRESENT/UNKNOWN,
LISTENING_LOCAL/LISTENING_EXTERNAL/NOT_LISTENING/UNKNOWN, and
FOUND_ACTIVE/NOT_FOUND/UNKNOWN verdicts plus findings.

This is the regression suite for the quality-audit findings SQL-1
(which-mysql-mariadb collapsing collection failure into absence), SQL-2
(grep's own no-match exit code driving the ss failure/no-match
ambiguity), SQL-3 (compound collection failure silently read as "not
installed", with no findings key at all), SQL-4 (unreadable bind-address
config silently skipping the exposure check), and SQL-5 (the resulting
empty findings list unconditionally defaulting to 'ok' with zero
evidence behind it - the most severe finding of the audit).
"""

from __future__ import annotations

from netaudit_pkg.checks.server_security import (
    _classify_listen_address,
    _parse_ss_local_addresses,
    _sql_binary_verdict,
    _sql_bind_address_evidence,
    _sql_bind_address_security,
    _sql_listener_verdict,
    _sql_presence_verdict,
    audit_sql,
)
from netaudit_pkg.sql_config import SQLEvidence
from tests.conftest import ExitCodeFakeSSHExecutor

# ===========================================================================
# Evidence-building helpers
# ===========================================================================

def _cr(completed=True, exit_code=0, stdout='', command='') -> object:
    from netaudit_pkg.sql_config import CommandResult
    return CommandResult(completed=completed, exit_code=exit_code, stdout=stdout, command=command)


def _evidence(mysql_present=None, mariadb_present=None, listener=None, bind_address_config=None) -> SQLEvidence:
    """Builds an SQLEvidence with sensible defaults (both binaries
    confirmed absent, listener/config collection failed) - tests
    override only the field(s) relevant to what they're checking."""
    return SQLEvidence(
        mysql_present=mysql_present if mysql_present is not None else _cr(exit_code=127),
        mariadb_present=mariadb_present if mariadb_present is not None else _cr(exit_code=127),
        listener=listener if listener is not None else _cr(completed=False, exit_code=None),
        bind_address_config=bind_address_config if bind_address_config is not None else _cr(completed=False, exit_code=None),
    )


# ===========================================================================
# _sql_binary_verdict / _sql_presence_verdict — unit tests
# ===========================================================================

def test_sql_binary_verdict_found():
    assert _sql_binary_verdict(_cr(exit_code=0)) == 'FOUND'


def test_sql_binary_verdict_not_found_on_127():
    assert _sql_binary_verdict(_cr(exit_code=127)) == 'NOT_FOUND'


def test_sql_binary_verdict_unknown_on_other_exit():
    assert _sql_binary_verdict(_cr(exit_code=2)) == 'UNKNOWN'


def test_sql_binary_verdict_unknown_on_collection_failure():
    assert _sql_binary_verdict(_cr(completed=False, exit_code=None)) == 'UNKNOWN'


def test_sql_presence_verdict_not_present_requires_both_confirmed():
    """Regression test for SQL-1/SQL-3: NOT_PRESENT requires BOTH mysql
    and mariadb to be confirmed absent (exit 127) - the exact contract
    that prevents a single successful `which`-style false-absence from
    ever masking a collection failure on the other check."""
    ev = _evidence(mysql_present=_cr(exit_code=127), mariadb_present=_cr(exit_code=127))
    verdict, _ = _sql_presence_verdict(ev)
    assert verdict == 'NOT_PRESENT'


def test_sql_presence_verdict_present_if_either_found():
    ev = _evidence(mysql_present=_cr(exit_code=0), mariadb_present=_cr(exit_code=127))
    verdict, _ = _sql_presence_verdict(ev)
    assert verdict == 'PRESENT'


def test_sql_presence_verdict_present_even_if_other_unknown():
    """PRESENT, once proven by one confirmed FOUND, is not undone by the
    other check being inconclusive."""
    ev = _evidence(mysql_present=_cr(exit_code=0), mariadb_present=_cr(completed=False, exit_code=None))
    verdict, _ = _sql_presence_verdict(ev)
    assert verdict == 'PRESENT'


def test_sql_presence_verdict_unknown_never_downgrades_to_not_present():
    """Regression test for SQL-1: a single UNKNOWN (collection failure)
    on either check must NEVER let the combined verdict become
    NOT_PRESENT, even if the other check confirms absence."""
    ev = _evidence(mysql_present=_cr(completed=False, exit_code=None), mariadb_present=_cr(exit_code=127))
    verdict, _ = _sql_presence_verdict(ev)
    assert verdict == 'UNKNOWN'


def test_sql_presence_verdict_unknown_both_unknown():
    ev = _evidence(mysql_present=_cr(completed=False, exit_code=None),
                    mariadb_present=_cr(completed=False, exit_code=None))
    verdict, _ = _sql_presence_verdict(ev)
    assert verdict == 'UNKNOWN'


# ===========================================================================
# _classify_listen_address / _parse_ss_local_addresses — unit tests
# ===========================================================================

def test_classify_listen_address_loopback_ipv4():
    assert _classify_listen_address('127.0.0.1') is True


def test_classify_listen_address_loopback_ipv4_full_range():
    """127.0.0.0/8 is entirely loopback, not just 127.0.0.1."""
    assert _classify_listen_address('127.0.0.5') is True


def test_classify_listen_address_wildcard_ipv4_is_non_loopback():
    assert _classify_listen_address('0.0.0.0') is False


def test_classify_listen_address_loopback_ipv6():
    assert _classify_listen_address('::1') is True


def test_classify_listen_address_wildcard_ipv6_is_non_loopback():
    assert _classify_listen_address('::') is False


def test_classify_listen_address_specific_non_loopback():
    assert _classify_listen_address('192.168.1.10') is False


def test_classify_listen_address_unparseable_returns_none():
    assert _classify_listen_address('not-an-address') is None


def test_parse_ss_local_addresses_ipv4():
    stdout = 'tcp   LISTEN 0      60             127.0.0.1:3306      0.0.0.0:*'
    assert _parse_ss_local_addresses(stdout, '3306') == ['127.0.0.1']


def test_parse_ss_local_addresses_bracketed_ipv6():
    stdout = 'tcp   LISTEN 0      511                 [::]:3306          [::]:*'
    assert _parse_ss_local_addresses(stdout, '3306') == ['::']


def test_parse_ss_local_addresses_ignores_other_ports():
    stdout = (
        'tcp   LISTEN 0      511              0.0.0.0:80        0.0.0.0:*\n'
        'tcp   LISTEN 0      60             127.0.0.1:3306      0.0.0.0:*\n'
    )
    assert _parse_ss_local_addresses(stdout, '3306') == ['127.0.0.1']


def test_parse_ss_local_addresses_multiple_listeners_same_port():
    stdout = (
        'tcp   LISTEN 0      60             127.0.0.1:3306      0.0.0.0:*\n'
        'tcp   LISTEN 0      60                 [::1]:3306          [::]:*\n'
    )
    assert _parse_ss_local_addresses(stdout, '3306') == ['127.0.0.1', '::1']


def test_parse_ss_local_addresses_no_match():
    stdout = 'tcp   LISTEN 0      511              0.0.0.0:80        0.0.0.0:*'
    assert _parse_ss_local_addresses(stdout, '3306') == []


# ===========================================================================
# _sql_listener_verdict — unit tests
# ===========================================================================

def test_sql_listener_verdict_local():
    ev = _evidence(listener=_cr(exit_code=0, stdout='tcp LISTEN 0 60 127.0.0.1:3306 0.0.0.0:*'))
    verdict, _ = _sql_listener_verdict(ev)
    assert verdict == 'LISTENING_LOCAL'


def test_sql_listener_verdict_external_wildcard():
    """Regression test for SQL-2's original intent: 0.0.0.0:3306 must be
    flagged external."""
    ev = _evidence(listener=_cr(exit_code=0, stdout='tcp LISTEN 0 60 0.0.0.0:3306 0.0.0.0:*'))
    verdict, _ = _sql_listener_verdict(ev)
    assert verdict == 'LISTENING_EXTERNAL'


def test_sql_listener_verdict_external_ipv6_wildcard():
    ev = _evidence(listener=_cr(exit_code=0, stdout='tcp LISTEN 0 60 [::]:3306 [::]:*'))
    verdict, _ = _sql_listener_verdict(ev)
    assert verdict == 'LISTENING_EXTERNAL'


def test_sql_listener_verdict_local_ipv6():
    ev = _evidence(listener=_cr(exit_code=0, stdout='tcp LISTEN 0 60 [::1]:3306 [::]:*'))
    verdict, _ = _sql_listener_verdict(ev)
    assert verdict == 'LISTENING_LOCAL'


def test_sql_listener_verdict_external_specific_ip():
    ev = _evidence(listener=_cr(exit_code=0, stdout='tcp LISTEN 0 60 192.168.1.10:3306 0.0.0.0:*'))
    verdict, _ = _sql_listener_verdict(ev)
    assert verdict == 'LISTENING_EXTERNAL'


def test_sql_listener_verdict_not_listening():
    ev = _evidence(listener=_cr(exit_code=0, stdout='tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:*'))
    verdict, _ = _sql_listener_verdict(ev)
    assert verdict == 'NOT_LISTENING'


def test_sql_listener_verdict_not_listening_on_confirmed_empty_output():
    ev = _evidence(listener=_cr(exit_code=0, stdout=''))
    verdict, _ = _sql_listener_verdict(ev)
    assert verdict == 'NOT_LISTENING'


def test_sql_listener_verdict_multiple_listeners_worst_case_wins():
    """One loopback listener + one external listener on the SAME port
    (unusual, but the parser must handle it) - external must win, not be
    hidden by the safer of the two facts."""
    stdout = (
        'tcp LISTEN 0 60 127.0.0.1:3306 0.0.0.0:*\n'
        'tcp LISTEN 0 60 0.0.0.0:3306 0.0.0.0:*\n'
    )
    ev = _evidence(listener=_cr(exit_code=0, stdout=stdout))
    verdict, _ = _sql_listener_verdict(ev)
    assert verdict == 'LISTENING_EXTERNAL'


def test_sql_listener_verdict_unknown_on_collection_failure():
    """Regression test for SQL-2: ss itself failing to complete must be
    UNKNOWN, never NOT_LISTENING."""
    ev = _evidence(listener=_cr(completed=False, exit_code=None))
    verdict, _ = _sql_listener_verdict(ev)
    assert verdict == 'UNKNOWN'


def test_sql_listener_verdict_unknown_on_nonzero_exit():
    """Regression test for SQL-2: ss completing with a failure exit code
    must be UNKNOWN, never NOT_LISTENING (the original bug: grep's own
    'no match' exit code masked this exact distinction)."""
    ev = _evidence(listener=_cr(exit_code=1, stdout=''))
    verdict, _ = _sql_listener_verdict(ev)
    assert verdict == 'UNKNOWN'


def test_sql_listener_verdict_unknown_on_unparseable_address():
    """A :3306 line exists but its address can't be parsed - must be
    UNKNOWN, not silently NOT_LISTENING or LISTENING_LOCAL."""
    ev = _evidence(listener=_cr(exit_code=0, stdout='tcp LISTEN 0 60 garbage:3306 0.0.0.0:*'))
    verdict, _ = _sql_listener_verdict(ev)
    assert verdict == 'UNKNOWN'


# ===========================================================================
# _sql_bind_address_evidence / _sql_bind_address_security — unit tests
# ===========================================================================

def test_sql_bind_address_evidence_found_active():
    ev = _evidence(bind_address_config=_cr(exit_code=0, stdout='bind-address = 0.0.0.0'))
    verdict, ctx = _sql_bind_address_evidence(ev)
    assert verdict == 'FOUND_ACTIVE'
    assert ctx['lines'] == ['bind-address = 0.0.0.0']


def test_sql_bind_address_evidence_commented_line_is_not_found_active():
    """Regression test - the explicit requirement from this quality
    audit's semantic-layer contract: a commented-out bind-address line
    must NOT count as FOUND_ACTIVE."""
    ev = _evidence(bind_address_config=_cr(exit_code=0, stdout='#bind-address = 0.0.0.0'))
    verdict, _ = _sql_bind_address_evidence(ev)
    assert verdict == 'NOT_FOUND'


def test_sql_bind_address_evidence_mixed_commented_and_active():
    """A commented default line PLUS a real active line - only the
    active one counts."""
    ev = _evidence(bind_address_config=_cr(
        exit_code=0, stdout='#bind-address = 0.0.0.0\nbind-address = 127.0.0.1'))
    verdict, ctx = _sql_bind_address_evidence(ev)
    assert verdict == 'FOUND_ACTIVE'
    assert ctx['lines'] == ['bind-address = 127.0.0.1']


def test_sql_bind_address_evidence_not_found_no_match():
    ev = _evidence(bind_address_config=_cr(exit_code=1, stdout=''))
    verdict, _ = _sql_bind_address_evidence(ev)
    assert verdict == 'NOT_FOUND'


def test_sql_bind_address_evidence_unknown_on_collection_failure():
    """Regression test for SQL-4: a permission-denied/collection-failed
    read must be UNKNOWN, never silently NOT_FOUND."""
    ev = _evidence(bind_address_config=_cr(completed=False, exit_code=None))
    verdict, _ = _sql_bind_address_evidence(ev)
    assert verdict == 'UNKNOWN'


def test_sql_bind_address_evidence_unknown_on_unexpected_exit():
    ev = _evidence(bind_address_config=_cr(exit_code=2, stdout=''))
    verdict, _ = _sql_bind_address_evidence(ev)
    assert verdict == 'UNKNOWN'


def test_sql_bind_address_security_exposed_wildcard():
    assert _sql_bind_address_security(['bind-address = 0.0.0.0']) == 'EXPOSED'


def test_sql_bind_address_security_safe_loopback():
    assert _sql_bind_address_security(['bind-address = 127.0.0.1']) == 'SAFE'


def test_sql_bind_address_security_worst_case_wins_on_conflicting_lines():
    """One safe line, one exposed line (redundant/conflicting config) -
    must report EXPOSED, not let the safe line hide the exposed one."""
    lines = ['bind-address = 127.0.0.1', 'bind-address = 0.0.0.0']
    assert _sql_bind_address_security(lines) == 'EXPOSED'


def test_sql_bind_address_security_unparseable_errs_toward_exposed():
    """A line matching the bind-address pattern but with an unparseable
    value - the safe failure direction is EXPOSED (raising the question)
    rather than SAFE (silently dismissing it)."""
    assert _sql_bind_address_security(['bind-address = not-an-address']) == 'EXPOSED'


# ===========================================================================
# audit_sql() — integration tests: findings actually produced
# ===========================================================================

def _responses_for(mysql_exit=127, mariadb_exit=127, ss_stdout='', ss_exit=0,
                    bind_stdout='', bind_exit=1):
    responses = {
        'command -v mysql': '/usr/bin/mysql' if mysql_exit == 0 else '',
        'command -v mariadb': '/usr/bin/mariadb' if mariadb_exit == 0 else '',
        'ss -tlnp': ss_stdout,
        "grep -rh '^\\s*bind-address' /etc/mysql/": bind_stdout,
    }
    exit_codes = {
        'command -v mysql': mysql_exit,
        'command -v mariadb': mariadb_exit,
        'ss -tlnp': ss_exit,
        "grep -rh '^\\s*bind-address' /etc/mysql/": bind_exit,
    }
    return responses, exit_codes


def test_audit_sql_not_present_gives_no_findings_not_ok():
    """Regression test for SQL-3, corrected per the semantic-layer
    contract: confirmed absence (both mysql and mariadb exit 127) must
    produce an explicit 'findings' key (fixing SQL-3's original "no
    findings key at all" bug) that is EMPTY - NOT_PRESENT is N/A, not a
    security 'ok'. 'ok' means a check ran and confirmed a safe state;
    N/A means this SQL-exposure audit doesn't apply to a host with no
    database installed at all. Conflating the two would let hosts with
    no database inflate a passed-checks count for a check that never
    actually evaluated anything."""
    responses, exit_codes = _responses_for(mysql_exit=127, mariadb_exit=127)
    fake = ExitCodeFakeSSHExecutor(responses=responses, exit_codes=exit_codes)
    result = audit_sql(fake)
    assert result['installed'] is False
    assert 'findings' in result
    assert result['findings'] == []


def test_audit_sql_unknown_presence_never_produces_ok_with_no_evidence():
    """Regression test for SQL-1/SQL-5: total collection failure across
    presence AND listener AND bind-address must NOT produce a confident
    'ok' - every single finding must be non-ok/manual-verification."""
    fake = ExitCodeFakeSSHExecutor()  # nothing registered at all - total collection failure
    result = audit_sql(fake)
    assert result['installed'] is True  # not NOT_PRESENT - presence itself is unknown
    assert len(result['findings']) >= 1
    assert all(f['severity'] != 'ok' for f in result['findings'])
    assert all(f.get('requires_manual_verification') for f in result['findings'])


def test_audit_sql_listening_external_gives_high():
    responses, exit_codes = _responses_for(
        mysql_exit=0, ss_stdout='tcp LISTEN 0 60 0.0.0.0:3306 0.0.0.0:*', ss_exit=0)
    fake = ExitCodeFakeSSHExecutor(responses=responses, exit_codes=exit_codes)
    result = audit_sql(fake)
    high = [f for f in result['findings'] if f['severity'] == 'high']
    assert len(high) == 1
    assert 'non-loopback' in high[0]['title'].lower()


def test_audit_sql_listening_local_gives_ok():
    responses, exit_codes = _responses_for(
        mysql_exit=0, ss_stdout='tcp LISTEN 0 60 127.0.0.1:3306 0.0.0.0:*', ss_exit=0)
    fake = ExitCodeFakeSSHExecutor(responses=responses, exit_codes=exit_codes)
    result = audit_sql(fake)
    ok_findings = [f for f in result['findings'] if f['severity'] == 'ok']
    assert len(ok_findings) == 1
    assert 'locally' in ok_findings[0]['title'].lower()


def test_audit_sql_not_listening_produces_no_listener_finding():
    """Regression test for the explicit contract decision: NOT_LISTENING
    (present but not listening on 3306) must produce NO finding at all -
    not 'ok', not silence-as-bug, a genuine valid empty-findings case."""
    responses, exit_codes = _responses_for(mysql_exit=0, ss_stdout='', ss_exit=0)
    fake = ExitCodeFakeSSHExecutor(responses=responses, exit_codes=exit_codes)
    result = audit_sql(fake)
    listener_related = [f for f in result['findings']
                        if 'listen' in f['title'].lower() or 'local' in f['title'].lower()]
    assert listener_related == []


def test_audit_sql_exposed_bind_address_gives_high():
    responses, exit_codes = _responses_for(
        mysql_exit=0, ss_stdout='', ss_exit=0,
        bind_stdout='bind-address = 0.0.0.0', bind_exit=0)
    fake = ExitCodeFakeSSHExecutor(responses=responses, exit_codes=exit_codes)
    result = audit_sql(fake)
    high = [f for f in result['findings'] if f['severity'] == 'high']
    assert len(high) == 1
    assert 'bind-address' in high[0]['title'].lower()


def test_audit_sql_commented_bind_address_does_not_trigger_high():
    """CRITICAL regression test: '# bind-address = 0.0.0.0' must NOT
    produce an EXPOSED/high finding - this is the exact false-positive
    the original code's comment already knew about, verified end-to-end
    through the full audit_sql() call, not just at the evidence-parsing
    unit level."""
    responses, exit_codes = _responses_for(
        mysql_exit=0, ss_stdout='', ss_exit=0,
        bind_stdout='#bind-address = 0.0.0.0', bind_exit=0)
    fake = ExitCodeFakeSSHExecutor(responses=responses, exit_codes=exit_codes)
    result = audit_sql(fake)
    bind_findings = [f for f in result['findings'] if 'bind-address' in f['title'].lower()]
    assert bind_findings == []
    assert all(f['severity'] != 'high' for f in result['findings'])


def test_audit_sql_active_bind_address_gives_high_not_commented_default():
    """Companion to the commented-line test: an ACTIVE bind-address =
    0.0.0.0 line alongside an unrelated commented line must still
    trigger HIGH - the fix must not overcorrect into ignoring real
    exposure."""
    responses, exit_codes = _responses_for(
        mysql_exit=0, ss_stdout='', ss_exit=0,
        bind_stdout='#bind-address = 127.0.0.1\nbind-address = 0.0.0.0', bind_exit=0)
    fake = ExitCodeFakeSSHExecutor(responses=responses, exit_codes=exit_codes)
    result = audit_sql(fake)
    high = [f for f in result['findings'] if f['severity'] == 'high']
    assert len(high) == 1


def test_audit_sql_collection_failure_never_becomes_ok_with_no_evidence():
    """Regression test for SQL-5, the most severe finding of the audit:
    presence PRESENT (confirmed), but listener AND bind-address BOTH
    fail to collect - findings must include explicit low/manual-
    verification entries, and must NOT fall back to a confident 'ok'
    with zero evidence behind it."""
    fake = ExitCodeFakeSSHExecutor(
        responses={'command -v mysql': '/usr/bin/mysql'},
        exit_codes={'command -v mysql': 0},
        # ss and bind-address: nothing registered -> both collection failures
    )
    result = audit_sql(fake)
    assert result['installed'] is True
    assert len(result['findings']) == 2  # listener UNKNOWN + bind-address UNKNOWN
    assert all(f['severity'] == 'low' for f in result['findings'])
    assert all(f.get('requires_manual_verification') for f in result['findings'])
    assert not any(f['severity'] == 'ok' for f in result['findings'])


def test_audit_sql_presence_unknown_still_checks_listener_and_bind():
    """Presence UNKNOWN must not short-circuit the listener/bind-address
    checks - a :3306 external listener is still worth surfacing even if
    we can't confirm which binary owns it."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'ss -tlnp': 'tcp LISTEN 0 60 0.0.0.0:3306 0.0.0.0:*',
        },
        exit_codes={
            'ss -tlnp': 0,
            # command -v mysql/mariadb: not registered -> both UNKNOWN
        },
    )
    result = audit_sql(fake)
    presence_findings = [f for f in result['findings'] if 'installed' in f['title'].lower()]
    listener_findings = [f for f in result['findings'] if 'non-loopback' in f['title'].lower()]
    assert len(presence_findings) == 1
    assert presence_findings[0]['severity'] == 'low'
    assert len(listener_findings) == 1
    assert listener_findings[0]['severity'] == 'high'


def test_audit_sql_multiple_findings_do_not_suppress_each_other():
    """Regression test: presence UNKNOWN + listener EXTERNAL + bind
    EXPOSED must all appear as independent findings simultaneously - no
    single aggregate verdict hides any of them."""
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'ss -tlnp': 'tcp LISTEN 0 60 0.0.0.0:3306 0.0.0.0:*',
            "grep -rh '^\\s*bind-address' /etc/mysql/": 'bind-address = 0.0.0.0',
        },
        exit_codes={
            'ss -tlnp': 0,
            "grep -rh '^\\s*bind-address' /etc/mysql/": 0,
            # presence: not registered -> UNKNOWN
        },
    )
    result = audit_sql(fake)
    severities = sorted(f['severity'] for f in result['findings'])
    assert severities == ['high', 'high', 'low']
    assert len(result['findings']) == 3
