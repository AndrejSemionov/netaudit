"""Tests for netaudit_pkg.checks.fail2ban_logs_audit — the @register
orchestration wiring Discovery -> Collection -> Parser -> Detection ->
Findings for Fail2Ban Logs Audit.

Scope, deliberately (mirrors test_nginx_logs_audit.py's own scope
discipline): this file tests only the NEW logic this module adds —

    1. The coverage-resolution adapter (_source_coverage), the one piece
       of logic this module adds that no other layer owns.
    2. The registry entrypoint's own contract (no-host, connection
       failure, closes SSH on error, registered correctly) — same shape
       as test_nginx_logs_audit.py's / test_ssh_auth_audit-style tests,
       since check_fail2ban_logs_audit() is a thin SSH-connect wrapper
       with the identical contract.
    3. A regression guard confirming checks/__init__.py actually imports
       this module — the exact class of gap nginx_logs_audit.py's tests
       already guard against (without the import, @register never runs).

A full mocked-SSH E2E (Discovery's probe, Collection's tail, Parser's
line-by-line dispatch, Detection's BAN-only signal, Findings' severity
mapping) is deliberately NOT re-tested here — every one of those layers
already has its own test suite (test_fail2ban_parser.py,
test_fail2ban_detection.py, test_fail2ban_findings.py). Re-asserting
their behavior here through a mocked fixture would be duplicated
coverage, not new coverage.
"""

from __future__ import annotations

from netaudit_pkg.checks.fail2ban_logs_audit import (
    _source_coverage,
    check_fail2ban_logs_audit,
)
from netaudit_pkg.fail2ban_detection import CoverageStatus
from netaudit_pkg.log_collection import CollectionResult, CommandResult, SourceKind
from netaudit_pkg.ssh import HostKeyMismatchError
from tests.conftest import FakeSSHExecutor


# ===========================================================================
# Helpers
# ===========================================================================

def _collected(*, completed=True, exit_code=0, line_count=0, stdout=''):
    cmd_result = CommandResult(completed=completed, exit_code=exit_code, stdout=stdout, stderr='',
                                command='tail -n 200 /var/log/fail2ban.log')
    return CollectionResult(source_kind=SourceKind.FILE, source_path='/var/log/fail2ban.log',
                             unit_name=None, result=cmd_result, line_count=line_count)


# ===========================================================================
# _source_coverage — the 4 reachable outcomes (PARTIAL not reachable)
# ===========================================================================

def test_source_coverage_none_is_unknown():
    # source.available was False — collect_file() was never even called.
    assert _source_coverage(None) == CoverageStatus.UNKNOWN


def test_source_coverage_not_completed_is_failed():
    collected = _collected(completed=False, exit_code=None, line_count=0)
    assert _source_coverage(collected) == CoverageStatus.FAILED


def test_source_coverage_nonzero_exit_is_failed():
    collected = _collected(completed=True, exit_code=1, line_count=5, stdout='x\n' * 5)
    assert _source_coverage(collected) == CoverageStatus.FAILED


def test_source_coverage_zero_lines_is_empty():
    collected = _collected(completed=True, exit_code=0, line_count=0, stdout='')
    assert _source_coverage(collected) == CoverageStatus.EMPTY


def test_source_coverage_nonzero_lines_is_complete():
    collected = _collected(completed=True, exit_code=0, line_count=3, stdout='a\nb\nc\n')
    assert _source_coverage(collected) == CoverageStatus.COMPLETE


# ===========================================================================
# Registry entrypoint — mirrors test_nginx_logs_audit.py's equivalent tests
# ===========================================================================

def test_check_fail2ban_logs_audit_no_host():
    result = check_fail2ban_logs_audit(host='')
    assert result == {'error': 'host not specified'}


def test_check_fail2ban_logs_audit_connection_failure(monkeypatch):
    class _BoomSSH:
        def __init__(self, *a, **kw):
            pass

        def connect(self):
            raise Exception('connection refused')

    monkeypatch.setattr('netaudit_pkg.checks.fail2ban_logs_audit.SSHExecutor', _BoomSSH)
    result = check_fail2ban_logs_audit(host='10.0.0.5')
    assert 'error' in result
    assert 'could not connect' in result['error']


def test_check_fail2ban_logs_audit_host_key_mismatch(monkeypatch):
    class _MismatchSSH:
        def __init__(self, *a, **kw):
            pass

        def connect(self):
            raise HostKeyMismatchError('host key changed')

    monkeypatch.setattr('netaudit_pkg.checks.fail2ban_logs_audit.SSHExecutor', _MismatchSSH)
    result = check_fail2ban_logs_audit(host='10.0.0.5')
    assert result == {'error': 'host key changed'}


def test_check_fail2ban_logs_audit_closes_ssh_even_on_error(monkeypatch):
    # source.available ends up False (no stat response configured), so
    # the pipeline runs to completion (coverage=UNKNOWN, no findings)
    # rather than raising — this test only asserts the SSH session is
    # always closed, regardless of what the pipeline produces.
    fake = FakeSSHExecutor(responses={})
    monkeypatch.setattr('netaudit_pkg.checks.fail2ban_logs_audit.SSHExecutor', lambda *a, **kw: fake)
    check_fail2ban_logs_audit(host='10.0.0.5')
    assert fake.closed is True


# ===========================================================================
# Regression guard — checks/__init__.py must import this module, or
# @register never runs and this check silently does not exist.
# ===========================================================================

def test_fail2ban_logs_audit_is_imported_by_checks_package():
    import netaudit_pkg.checks as checks_pkg
    assert hasattr(checks_pkg, 'fail2ban_logs_audit')
