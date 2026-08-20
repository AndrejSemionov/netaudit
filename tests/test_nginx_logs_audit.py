"""Tests for netaudit_pkg.checks.nginx_logs_audit — the @register
orchestration wiring Discovery -> Resolver -> Matching -> Collection ->
Parser -> Detection -> Findings for Nginx Logs Audit.

Scope, deliberately (mirrors this project's "Detection does not re-prove
facts" principle, applied to orchestration): this file tests only the
NEW logic this module adds —

    1. The coverage-resolution adapter (_source_coverage /
       _aggregate_coverage_str), which is the one piece of logic this
       session's plan identified as missing from every other layer.
    2. The registry entrypoint's own contract (no-host, connection
       failure, host-key mismatch, closes SSH on error, registered
       correctly) — same shape as test_nginx_hardening.py's equivalent
       tests, since check_nginx_logs_audit() is a thin SSH-connect
       wrapper with the identical contract.
    3. A regression guard confirming checks/__init__.py actually imports
       this module — the exact gap caught and fixed this session
       (without it, @register never runs, and nothing else in this file
       would catch that).

A full mocked-SSH E2E across every server block (Discovery's full nginx
glob + fixed-source probes + journal + logrotate, Resolver's cascade,
Matching's dedup, Collection's tail) is deliberately NOT re-tested here —
every one of those layers already has its own test suite
(test_nginx_log_resolver.py, test_nginx_log_matching.py,
test_nginx_log_collection.py, test_nginx_access_parser.py,
test_nginx_error_parser.py, test_nginx_access_detection.py,
test_nginx_error_detection.py, test_nginx_findings.py). Re-asserting
their behavior here through a giant mocked fixture would be duplicated
coverage, not new coverage.
"""

from __future__ import annotations

from netaudit_pkg.checks.nginx_logs_audit import (
    _aggregate_coverage_str,
    _resolve_access_coverage,
    _resolve_error_coverage,
    _source_coverage,
    check_nginx_logs_audit,
)
from netaudit_pkg.log_collection import CollectionResult, CommandResult, SourceKind
from netaudit_pkg.nginx_access_detection import CoverageStatus as AccessCoverageStatus
from netaudit_pkg.nginx_error_detection import CoverageStatus as ErrorCoverageStatus
from netaudit_pkg.nginx_log_collection import NginxLogCollectionResult
from netaudit_pkg.ssh import HostKeyMismatchError
from tests.conftest import FakeSSHExecutor

# ===========================================================================
# Helpers
# ===========================================================================

def _log_source():
    """A minimal LogSource stand-in — _source_coverage()/aggregation
    never inspect it, only NginxLogCollectionResult.result/.error, so a
    bare object satisfies the dataclass field without needing the real
    LogSource shape."""
    return object()


def _collected(*, completed=True, exit_code=0, line_count=0, error=None,
                stdout=''):
    if error is not None:
        return NginxLogCollectionResult(source=_log_source(), result=None, error=error)
    cmd_result = CommandResult(completed=completed, exit_code=exit_code, stdout=stdout, stderr='',
                                command='tail -n 200 /var/log/nginx/access.log')
    result = CollectionResult(source_kind=SourceKind.FILE, source_path='/var/log/nginx/access.log',
                               unit_name=None, result=cmd_result, line_count=line_count)
    return NginxLogCollectionResult(source=_log_source(), result=result, error=None)


# ===========================================================================
# _source_coverage — per-source, the 4 reachable outcomes
# ===========================================================================

def test_source_coverage_exception_is_unknown():
    collected = _collected(error='SSHException: channel closed')
    assert _source_coverage(collected) == 'unknown'


def test_source_coverage_not_completed_is_failed():
    collected = _collected(completed=False, exit_code=None, line_count=0)
    assert _source_coverage(collected) == 'failed'


def test_source_coverage_nonzero_exit_is_failed():
    collected = _collected(completed=True, exit_code=1, line_count=5, stdout='x\n' * 5)
    assert _source_coverage(collected) == 'failed'


def test_source_coverage_zero_lines_is_empty():
    collected = _collected(completed=True, exit_code=0, line_count=0, stdout='')
    assert _source_coverage(collected) == 'empty'


def test_source_coverage_nonzero_lines_is_complete():
    collected = _collected(completed=True, exit_code=0, line_count=3, stdout='a\nb\nc\n')
    assert _source_coverage(collected) == 'complete'


def test_source_coverage_result_none_without_error_is_failed():
    # Defensive: result=None and error=None shouldn't happen in practice
    # (NginxLogCollectionResult's own contract says exactly one is set),
    # but the adapter must not raise if it ever does — treat as FAILED,
    # the same as any other "collection didn't produce usable evidence"
    # case, rather than crashing the whole orchestration run.
    collected = NginxLogCollectionResult(source=_log_source(), result=None, error=None)
    assert _source_coverage(collected) == 'failed'


# ===========================================================================
# _aggregate_coverage_str — the full frozen aggregation table
# ===========================================================================

def test_aggregate_empty_list_is_unknown():
    assert _aggregate_coverage_str([]) == 'unknown'


def test_aggregate_all_same_status_stays_that_status():
    assert _aggregate_coverage_str(['complete']) == 'complete'
    assert _aggregate_coverage_str(['complete', 'complete']) == 'complete'
    assert _aggregate_coverage_str(['empty', 'empty']) == 'empty'
    assert _aggregate_coverage_str(['failed', 'failed']) == 'failed'
    assert _aggregate_coverage_str(['unknown', 'unknown']) == 'unknown'


def test_aggregate_complete_and_empty_is_complete():
    assert _aggregate_coverage_str(['complete', 'empty']) == 'complete'
    assert _aggregate_coverage_str(['empty', 'complete', 'empty']) == 'complete'


def test_aggregate_complete_and_failed_is_partial():
    assert _aggregate_coverage_str(['complete', 'failed']) == 'partial'


def test_aggregate_complete_and_unknown_is_partial():
    assert _aggregate_coverage_str(['complete', 'unknown']) == 'partial'


def test_aggregate_empty_and_failed_is_partial():
    assert _aggregate_coverage_str(['empty', 'failed']) == 'partial'


def test_aggregate_empty_and_unknown_is_partial():
    assert _aggregate_coverage_str(['empty', 'unknown']) == 'partial'


def test_aggregate_failed_and_unknown_is_partial():
    # Session decision: CoverageStatus describes coverage completeness,
    # not error severity — FAILED does not automatically win over
    # UNKNOWN just because it's a more definite outcome.
    assert _aggregate_coverage_str(['failed', 'unknown']) == 'partial'


def test_aggregate_three_way_mix_is_partial():
    assert _aggregate_coverage_str(['complete', 'empty', 'failed']) == 'partial'
    assert _aggregate_coverage_str(['complete', 'failed', 'unknown']) == 'partial'


# ===========================================================================
# _resolve_access_coverage / _resolve_error_coverage — correct enum class
# ===========================================================================

def test_resolve_access_coverage_returns_access_enum():
    result = _resolve_access_coverage(['complete'])
    assert result is AccessCoverageStatus.COMPLETE


def test_resolve_error_coverage_returns_error_enum():
    result = _resolve_error_coverage(['complete'])
    assert result is ErrorCoverageStatus.COMPLETE


def test_resolve_access_and_error_coverage_are_distinct_enum_classes():
    # nginx_access_detection.CoverageStatus and nginx_error_detection.
    # CoverageStatus are two separate enum classes with identical values
    # (see this project's session notes) — confirm the adapter returns
    # the right one for each, not just a value that happens to compare
    # equal.
    access = _resolve_access_coverage(['failed'])
    error = _resolve_error_coverage(['failed'])
    assert isinstance(access, AccessCoverageStatus)
    assert isinstance(error, ErrorCoverageStatus)
    assert not isinstance(access, ErrorCoverageStatus)
    assert not isinstance(error, AccessCoverageStatus)


# ===========================================================================
# Registry entrypoint — mirrors test_nginx_hardening.py's equivalent
# tests, since check_nginx_logs_audit() is the same
# connect/delegate/close shape.
# ===========================================================================

def test_check_nginx_logs_audit_no_host():
    result = check_nginx_logs_audit(host='')
    assert result == {'error': 'host not specified'}


def test_check_nginx_logs_audit_not_installed(monkeypatch):
    fake = FakeSSHExecutor(responses={'which nginx': ('NONE', '')})
    monkeypatch.setattr('netaudit_pkg.checks.nginx_logs_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_nginx_logs_audit(host='10.0.0.5')
    assert result == {'installed': False}
    assert fake.closed is True


def test_check_nginx_logs_audit_closes_ssh_even_on_error(monkeypatch):
    fake = FakeSSHExecutor(responses={'which nginx': ('NONE', '')})
    monkeypatch.setattr('netaudit_pkg.checks.nginx_logs_audit.SSHExecutor', lambda *a, **kw: fake)
    check_nginx_logs_audit(host='10.0.0.5')
    assert fake.closed is True


def test_check_nginx_logs_audit_connection_failure(monkeypatch):
    class _BoomSSH:
        def __init__(self, *a, **kw):
            pass

        def connect(self):
            raise ConnectionRefusedError('connection refused')

    monkeypatch.setattr('netaudit_pkg.checks.nginx_logs_audit.SSHExecutor', _BoomSSH)
    result = check_nginx_logs_audit(host='10.0.0.5')
    assert 'error' in result
    assert 'could not connect' in result['error']


def test_check_nginx_logs_audit_host_key_mismatch(monkeypatch):
    class _MismatchSSH:
        def __init__(self, *a, **kw):
            pass

        def connect(self):
            raise HostKeyMismatchError('host key changed for 10.0.0.5')

    monkeypatch.setattr('netaudit_pkg.checks.nginx_logs_audit.SSHExecutor', _MismatchSSH)
    result = check_nginx_logs_audit(host='10.0.0.5')
    assert 'error' in result
    assert 'host key changed' in result['error']


def test_check_nginx_logs_audit_registered_as_server_category():
    from netaudit_pkg.registry import registry
    spec = registry.get('nginx_logs_audit')
    assert spec is not None
    assert spec.category == 'server'
    assert spec.risk_level == 'READ_ONLY'


# ===========================================================================
# Regression guard: checks/__init__.py must import this module, or
# @register never runs at all (the exact gap caught this session).
# ===========================================================================

def test_registered_check_is_discoverable_via_checks_package():
    import netaudit_pkg.checks  # noqa: F401 — importing the package must

    # register nginx_logs_audit as a side effect, exactly like every
    # other check module listed in checks/__init__.py.
    from netaudit_pkg.registry import registry
    assert registry.get('nginx_logs_audit') is not None, (
        'netaudit_pkg/checks/__init__.py must import nginx_logs_audit — '
        'otherwise @register never executes and the check is invisible '
        'to the CLI/web UI despite existing in source.'
    )


# ===========================================================================
# Regression (2026-08-20): UI contract documentation. web/static/index.html's
# generic findings renderer (the `if (r.findings && !r.sections)` block)
# originally assumed every finding has a human 'title' field — true for the
# older shared netaudit_pkg/findings.py Finding (used by server_audit,
# dns_audit, cve_audit, systemd_hardening) but NOT true for
# nginx_findings.py's Finding, whose contract is deliberately
# finding_type/severity/confidence/detail/recommendation/event_count with
# no title field. Caught via manual UI audit against a live nginx_logs_audit
# API response. Fixed in index.html with a `f.title || f.finding_type`
# fallback rather than adding an artificial 'title' to nginx_findings.py —
# the machine-readable finding_type (e.g. "HIGH_5XX_RATE") is the correct
# fallback headline, not a workaround.
#
# This test cannot exercise the JS renderer itself (no JS test
# infrastructure in this project — plain static files, no build/test
# runner) — it documents and locks the Python-side half of the contract:
# the JSON this check emits carries 'finding_type', never 'title'. If a
# future change added 'title' back to nginx_findings.Finding, this test
# would need updating too, which is the point: the two sides of this
# contract (API JSON shape here, JS fallback in index.html) must be
# changed together, not silently drift apart again.
# ===========================================================================

def test_finding_json_has_finding_type_not_title():
    """Documents the actual JSON shape check_nginx_logs_audit() emits for
    each finding — 'finding_type' present, 'title' absent — so the UI's
    fallback rendering (f.title || f.finding_type) has a concrete contract
    to stay in sync with."""
    from netaudit_pkg.nginx_access_detection import (
        CoverageStatus as AccessCoverageStatus,
    )
    from netaudit_pkg.nginx_access_detection import detect_access_signals

    # A single HIGH_5XX_RATE-triggering event set is the simplest way to
    # get one real Finding out of the actual Access Detection + Findings
    # pipeline, rather than hand-constructing a Finding and risking it
    # drifting from what build_access_findings() actually produces.
    from netaudit_pkg.nginx_access_parser import NginxAccessEvent, NginxAccessEventType
    from netaudit_pkg.nginx_findings import build_access_findings
    events = [
        NginxAccessEvent(event_type=NginxAccessEventType.PARSED, remote_addr='1.2.3.4',
                          remote_user=None, timestamp=None, request='GET /', status=500,
                          body_bytes_sent=0, http_referer=None, http_user_agent=None, raw_line='x')
        for _ in range(10)
    ]
    result = detect_access_signals(events, AccessCoverageStatus.COMPLETE)
    findings = build_access_findings(result)
    assert findings, 'expected at least one Finding from 10x 5xx events (fixture assumption)'

    finding_dict = {
        'finding_type': findings[0].finding_type, 'severity': findings[0].severity,
        'confidence': findings[0].confidence, 'detail': findings[0].detail,
        'recommendation': findings[0].recommendation, 'event_count': findings[0].event_count,
    }
    assert 'finding_type' in finding_dict
    assert 'title' not in finding_dict, (
        "nginx_findings.Finding must not grow a 'title' field without updating "
        "web/static/index.html's generic findings renderer fallback together with it."
    )

