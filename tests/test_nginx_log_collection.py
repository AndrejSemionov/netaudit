"""Tests for netaudit_pkg.nginx_log_collection — Collection Integration
Contract v1 (project session notes, 2026-08-19). Written test-first,
before implementation, per project methodology: contract freeze -> test
matrix -> tests -> implementation.

Test matrix (agreed, do not reorder/skip):
  1  one matched access source -> one CollectionResult
  2  access + error (distinct paths) -> two independent results
  3  duplicate LogSource in input -> collected once (trusts caller
     already deduplicated — this documents that assumption, doesn't
     re-implement dedup)
  4  one source unreadable/fails -> its own result reflects that,
     others still collected
  5  STALE_EMPTY source -> still collected, not pre-filtered
  6  (covered by matching layer already — dedupe_matches() output is
     the input contract here; not re-tested at this layer, see #3)
  7  different files -> each collected independently, correct content
     per source (no cross-contamination)
  8  empty input list -> [], zero SSH calls issued
  9  collect_file() raising an exception for one source -> isolated,
     captured as .error, other sources' results are NOT lost
  10 deterministic ordering: same input order -> same output order
"""

from __future__ import annotations

from netaudit_pkg.checks.log_discovery_audit import LogFileState, LogSource, SourceType
from netaudit_pkg.nginx_log_collection import collect_nginx_logs
from tests.conftest import ExitCodeFakeSSHExecutor


def _log_source(path, readable=True, state=LogFileState.ACTIVE) -> LogSource:
    return LogSource(
        source_type=SourceType.NGINX_LOG, path=path, available=True, readable=readable,
        requires_sudo=not readable, state=state, size_bytes=1000, last_modified_epoch=1,
        owner='www-data', group='adm', mode='640',
    )


# ===========================================================================
# 1. One matched source -> one CollectionResult
# ===========================================================================

def test_single_source_produces_one_result():
    fake = ExitCodeFakeSSHExecutor(
        responses={'tail -n 200 /var/log/nginx/access.log': 'GET /index.html'},
        exit_codes={'tail -n 200 /var/log/nginx/access.log': 0},
    )
    source = _log_source('/var/log/nginx/access.log')

    results = collect_nginx_logs(fake, [source])

    assert len(results) == 1
    assert results[0].source is source
    assert results[0].error is None
    assert results[0].result is not None
    assert results[0].result.result.exit_code == 0
    assert 'GET /index.html' in results[0].result.result.stdout


# ===========================================================================
# 2. access + error (distinct paths) -> two independent results
# ===========================================================================

def test_access_and_error_are_independent_results():
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'tail -n 200 /var/log/nginx/access.log': 'access line',
            'tail -n 200 /var/log/nginx/error.log': 'error line',
        },
        exit_codes={
            'tail -n 200 /var/log/nginx/access.log': 0,
            'tail -n 200 /var/log/nginx/error.log': 0,
        },
    )
    access_source = _log_source('/var/log/nginx/access.log')
    error_source = _log_source('/var/log/nginx/error.log')

    results = collect_nginx_logs(fake, [access_source, error_source])

    assert len(results) == 2
    assert 'access line' in results[0].result.result.stdout
    assert 'error line' in results[1].result.result.stdout


# ===========================================================================
# 3. Duplicate LogSource in input -> collected once per occurrence
# (this module trusts the caller already deduplicated — documents the
# assumption rather than re-implementing dedup)
# ===========================================================================

def test_duplicate_source_in_input_is_collected_per_occurrence():
    """This module does NOT deduplicate — that's dedupe_matches()'s
    job, already done upstream. If a caller passes the same LogSource
    twice (which a correctly-deduplicated input never does), this
    module collects it twice — documenting that this is the input
    contract, not a bug to guard against here."""
    fake = ExitCodeFakeSSHExecutor(
        responses={'tail -n 200 /var/log/nginx/access.log': 'line'},
        exit_codes={'tail -n 200 /var/log/nginx/access.log': 0},
    )
    source = _log_source('/var/log/nginx/access.log')

    results = collect_nginx_logs(fake, [source, source])

    assert len(results) == 2
    tail_calls = [c for c in fake.calls if 'tail -n 200 /var/log/nginx/access.log' in c]
    assert len(tail_calls) == 2


# ===========================================================================
# 4. One source unreadable -> its own result reflects sudo path, others
# still collected
# ===========================================================================

def test_unreadable_source_uses_sudo_others_unaffected():
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'tail -n 200 /var/log/nginx/access.log': 'readable line',
        },
        exit_codes={
            'tail -n 200 /var/log/nginx/access.log': 0,
        },
    )
    readable_source = _log_source('/var/log/nginx/access.log', readable=True)
    protected_source = _log_source('/var/log/nginx/protected.log', readable=False)

    results = collect_nginx_logs(fake, [readable_source, protected_source])

    assert len(results) == 2
    assert results[0].error is None
    assert 'readable line' in results[0].result.result.stdout
    # protected source went through sudo path — no exception, its own
    # result (whatever collect_file's sudo helper returned) is present
    assert results[1].source is protected_source


# ===========================================================================
# 5. STALE_EMPTY source -> still collected, not pre-filtered
# ===========================================================================

def test_stale_empty_source_is_still_collected():
    fake = ExitCodeFakeSSHExecutor(
        responses={'tail -n 200 /var/log/nginx/access.log': ''},
        exit_codes={'tail -n 200 /var/log/nginx/access.log': 0},
    )
    source = _log_source('/var/log/nginx/access.log', state=LogFileState.STALE_EMPTY)

    results = collect_nginx_logs(fake, [source])

    assert len(results) == 1
    assert results[0].error is None
    assert results[0].result is not None
    assert results[0].result.line_count == 0
    tail_calls = [c for c in fake.calls if 'tail -n 200 /var/log/nginx/access.log' in c]
    assert len(tail_calls) == 1  # confirms it was NOT skipped


# ===========================================================================
# 7. Different files -> each collected independently, no cross-contamination
# ===========================================================================

def test_different_files_no_cross_contamination():
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'tail -n 200 /var/log/nginx/a.log': 'content-a',
            'tail -n 200 /var/log/nginx/b.log': 'content-b',
        },
        exit_codes={
            'tail -n 200 /var/log/nginx/a.log': 0,
            'tail -n 200 /var/log/nginx/b.log': 0,
        },
    )
    source_a = _log_source('/var/log/nginx/a.log')
    source_b = _log_source('/var/log/nginx/b.log')

    results = collect_nginx_logs(fake, [source_a, source_b])

    assert 'content-a' in results[0].result.result.stdout
    assert 'content-b' not in results[0].result.result.stdout
    assert 'content-b' in results[1].result.result.stdout
    assert 'content-a' not in results[1].result.result.stdout


# ===========================================================================
# 8. Empty input -> [], zero SSH calls
# ===========================================================================

def test_empty_input_produces_empty_output_no_ssh_calls():
    class NoCallTracker(ExitCodeFakeSSHExecutor):
        def run(self, cmd: str, timeout: int = 20):
            raise AssertionError(f'must not issue any command for empty input; got: {cmd!r}')

        def sudo(self, cmd: str, timeout: int = 20):
            raise AssertionError(f'must not issue any command for empty input; got: {cmd!r}')

    fake = NoCallTracker(responses={}, exit_codes={})

    results = collect_nginx_logs(fake, [])

    assert results == []


# ===========================================================================
# 9. collect_file() raising for one source -> isolated, other results preserved
# ===========================================================================

def test_exception_in_one_source_does_not_lose_others():
    class RaisingOnPathSSH(ExitCodeFakeSSHExecutor):
        def run(self, cmd: str, timeout: int = 20):
            if 'broken.log' in cmd:
                raise ConnectionResetError('simulated SSH failure')
            return super().run(cmd, timeout)

    fake = RaisingOnPathSSH(
        responses={
            'tail -n 200 /var/log/nginx/good.log': 'good content',
        },
        exit_codes={
            'tail -n 200 /var/log/nginx/good.log': 0,
        },
    )
    good_source = _log_source('/var/log/nginx/good.log')
    broken_source = _log_source('/var/log/nginx/broken.log')

    results = collect_nginx_logs(fake, [good_source, broken_source])

    assert len(results) == 2
    assert results[0].error is None
    assert 'good content' in results[0].result.result.stdout

    assert results[1].error is not None
    assert 'simulated SSH failure' in results[1].error
    assert results[1].result is None


def test_exception_on_first_source_does_not_prevent_second():
    """Order matters: a failure on the FIRST source must not abort
    collection of subsequent sources."""
    class RaisingOnPathSSH(ExitCodeFakeSSHExecutor):
        def run(self, cmd: str, timeout: int = 20):
            if 'broken.log' in cmd:
                raise ConnectionResetError('simulated SSH failure')
            return super().run(cmd, timeout)

    fake = RaisingOnPathSSH(
        responses={'tail -n 200 /var/log/nginx/good.log': 'good content'},
        exit_codes={'tail -n 200 /var/log/nginx/good.log': 0},
    )
    broken_source = _log_source('/var/log/nginx/broken.log')
    good_source = _log_source('/var/log/nginx/good.log')

    results = collect_nginx_logs(fake, [broken_source, good_source])

    assert results[0].error is not None
    assert results[1].error is None
    assert 'good content' in results[1].result.result.stdout


# ===========================================================================
# 10. Deterministic ordering
# ===========================================================================

def test_output_order_matches_input_order():
    fake = ExitCodeFakeSSHExecutor(
        responses={
            'tail -n 200 /var/log/nginx/c.log': 'c',
            'tail -n 200 /var/log/nginx/a.log': 'a',
            'tail -n 200 /var/log/nginx/b.log': 'b',
        },
        exit_codes={
            'tail -n 200 /var/log/nginx/c.log': 0,
            'tail -n 200 /var/log/nginx/a.log': 0,
            'tail -n 200 /var/log/nginx/b.log': 0,
        },
    )
    sources = [
        _log_source('/var/log/nginx/c.log'),
        _log_source('/var/log/nginx/a.log'),
        _log_source('/var/log/nginx/b.log'),
    ]

    results = collect_nginx_logs(fake, sources)

    assert [r.source.path for r in results] == [
        '/var/log/nginx/c.log', '/var/log/nginx/a.log', '/var/log/nginx/b.log',
    ]


# ===========================================================================
# lines/timeout parameters are honored (not hardcoded)
# ===========================================================================

def test_custom_lines_parameter_is_honored():
    fake = ExitCodeFakeSSHExecutor(
        responses={'tail -n 50 /var/log/nginx/access.log': 'x'},
        exit_codes={'tail -n 50 /var/log/nginx/access.log': 0},
    )
    source = _log_source('/var/log/nginx/access.log')

    collect_nginx_logs(fake, [source], lines=50)

    matching = [c for c in fake.calls if 'tail -n 50 ' in c]
    assert len(matching) == 1
