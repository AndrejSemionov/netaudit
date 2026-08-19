"""Tests for netaudit_pkg.nginx_log_matching — Matching Contract v1
(project session notes, 2026-08-18). Written test-first, before
implementation, per project methodology: contract freeze -> test
matrix -> tests -> implementation.

Test matrix (agreed, do not reorder/skip):
  1  exact path match (basename-only similarity does NOT match)
  2  multiple CONFIGURED destinations each matched independently
  3  configured path with no matching LogSource -> NOT_FOUND, never a
     silent skip or similar-name fallback
  4  discovered files with no configured path are never selected
  5  rotated files never appear as match candidates (Discovery already
     excludes them — this test documents the assumption, not a new rule)
  6  DISABLED -> matched_sources always empty, no matching attempted
  7  UNCONFIGURED -> matched_sources always empty, no filesystem-default
     assumption
  8  two servers resolving to the same path -> deduplicated to one
     LogSource in dedupe_matches(), evidence of multiple servers preserved
     per-match (not lost)
"""

from __future__ import annotations

from netaudit_pkg.checks.log_discovery_audit import LogFileState, LogSource, SourceType
from netaudit_pkg.nginx_log_matching import (
    MatchStatus,
    dedupe_matches,
    match_log_directive,
)
from netaudit_pkg.nginx_log_resolver import LogDestination, LogDirectiveState, ResolvedLogDirective


def _log_source(path, available=True, readable=True) -> LogSource:
    return LogSource(
        source_type=SourceType.NGINX_LOG, path=path, available=available, readable=readable,
        requires_sudo=not readable, state=LogFileState.ACTIVE, size_bytes=1000,
        last_modified_epoch=1, owner='www-data', group='adm', mode='640',
    )


def _resolved(state, paths, source_level='server') -> ResolvedLogDirective:
    destinations = [LogDestination(path=p, options=None) for p in paths]
    return ResolvedLogDirective(state=state, destinations=destinations, source_level=source_level)


# ===========================================================================
# 1. Exact path match — no basename matching
# ===========================================================================

def test_exact_path_match():
    resolved = _resolved(LogDirectiveState.CONFIGURED, ['/var/log/nginx/andreykapro_access.log'])
    discovered = [_log_source('/var/log/nginx/andreykapro_access.log')]

    result = match_log_directive(resolved, discovered)

    assert result.state == LogDirectiveState.CONFIGURED
    assert len(result.destinations) == 1
    assert result.destinations[0].status == MatchStatus.MATCHED
    assert result.destinations[0].source.path == '/var/log/nginx/andreykapro_access.log'


def test_basename_similarity_does_not_match():
    """/etc/nginx/access.log and /var/log/nginx/access.log share a
    basename but are different files — must NOT match."""
    resolved = _resolved(LogDirectiveState.CONFIGURED, ['/etc/nginx/access.log'])
    discovered = [_log_source('/var/log/nginx/access.log')]

    result = match_log_directive(resolved, discovered)

    assert result.destinations[0].status == MatchStatus.NOT_FOUND
    assert result.destinations[0].source is None


# ===========================================================================
# 2. Multiple CONFIGURED destinations matched independently
# ===========================================================================

def test_multiple_destinations_each_matched_independently():
    resolved = _resolved(LogDirectiveState.CONFIGURED,
                          ['/var/log/nginx/access.log', '/var/log/nginx/security.log'])
    discovered = [
        _log_source('/var/log/nginx/access.log'),
        _log_source('/var/log/nginx/security.log'),
    ]

    result = match_log_directive(resolved, discovered)

    assert len(result.destinations) == 2
    assert all(d.status == MatchStatus.MATCHED for d in result.destinations)
    assert len(result.matched_sources) == 2


def test_multiple_destinations_partial_match():
    """One destination found, one not — each destination's status is
    independent, not all-or-nothing."""
    resolved = _resolved(LogDirectiveState.CONFIGURED,
                          ['/var/log/nginx/access.log', '/var/log/nginx/missing.log'])
    discovered = [_log_source('/var/log/nginx/access.log')]

    result = match_log_directive(resolved, discovered)

    statuses = {d.configured_path: d.status for d in result.destinations}
    assert statuses['/var/log/nginx/access.log'] == MatchStatus.MATCHED
    assert statuses['/var/log/nginx/missing.log'] == MatchStatus.NOT_FOUND
    assert len(result.matched_sources) == 1


# ===========================================================================
# 3. Configured path with no matching LogSource -> NOT_FOUND
# ===========================================================================

def test_configured_path_not_in_discovery_is_not_found():
    resolved = _resolved(LogDirectiveState.CONFIGURED, ['/var/log/nginx/access.log'])
    discovered = []

    result = match_log_directive(resolved, discovered)

    assert result.destinations[0].status == MatchStatus.NOT_FOUND
    assert result.destinations[0].source is None
    assert result.matched_sources == []


def test_not_found_never_falls_back_to_similar_file():
    """Discovery has a differently-named file that a naive heuristic
    might pick — must NOT be used as a fallback."""
    resolved = _resolved(LogDirectiveState.CONFIGURED, ['/var/log/nginx/andreykapro_access.log'])
    discovered = [_log_source('/var/log/nginx/access.log')]  # decoy — must not be picked

    result = match_log_directive(resolved, discovered)

    assert result.destinations[0].status == MatchStatus.NOT_FOUND
    assert result.matched_sources == []


# ===========================================================================
# 4. Discovered files with no configured path are never selected
# ===========================================================================

def test_discovered_extra_files_are_never_selected():
    resolved = _resolved(LogDirectiveState.CONFIGURED, ['/var/log/nginx/andreykapro_access.log'])
    discovered = [
        _log_source('/var/log/nginx/andreykapro_access.log'),
        _log_source('/var/log/nginx/access.log'),  # decoy, not configured — must be ignored
    ]

    result = match_log_directive(resolved, discovered)

    assert len(result.matched_sources) == 1
    assert result.matched_sources[0].path == '/var/log/nginx/andreykapro_access.log'


# ===========================================================================
# 5. Rotated files are never match candidates (Discovery already
# excludes them from its LogSource list — this documents the assumption)
# ===========================================================================

def test_rotated_looking_path_in_discovery_does_not_prefix_match():
    """Even if Discovery somehow included a rotated-looking file, exact
    path equality (rule 1) means a configured base path never matches
    it — there is no prefix/rotation-aware matching in this layer."""
    resolved = _resolved(LogDirectiveState.CONFIGURED, ['/var/log/nginx/access.log'])
    discovered = [_log_source('/var/log/nginx/access.log.1')]

    result = match_log_directive(resolved, discovered)

    assert result.destinations[0].status == MatchStatus.NOT_FOUND


# ===========================================================================
# 6. DISABLED -> matched_sources always empty, no matching attempted
# ===========================================================================

def test_disabled_state_produces_no_destinations():
    resolved = ResolvedLogDirective(state=LogDirectiveState.DISABLED, destinations=[], source_level='server')
    discovered = [_log_source('/var/log/nginx/access.log')]

    result = match_log_directive(resolved, discovered)

    assert result.state == LogDirectiveState.DISABLED
    assert result.destinations == []
    assert result.matched_sources == []


# ===========================================================================
# 7. UNCONFIGURED -> matched_sources always empty, no filesystem-default assumption
# ===========================================================================

def test_unconfigured_state_produces_no_destinations():
    resolved = ResolvedLogDirective(state=LogDirectiveState.UNCONFIGURED, destinations=[], source_level=None)
    # Discovery happens to have the conventional default path available —
    # must NOT be picked up, since nothing in config named it.
    discovered = [_log_source('/var/log/nginx/access.log')]

    result = match_log_directive(resolved, discovered)

    assert result.state == LogDirectiveState.UNCONFIGURED
    assert result.destinations == []
    assert result.matched_sources == []


# ===========================================================================
# 8. Two servers resolving to the same path -> deduplicated in
# dedupe_matches(), evidence preserved per-match beforehand
# ===========================================================================

def test_dedupe_matches_collapses_shared_path_to_one_source():
    shared_source = _log_source('/var/log/nginx/access.log')
    match_a = match_log_directive(
        _resolved(LogDirectiveState.CONFIGURED, ['/var/log/nginx/access.log']), [shared_source],
    )
    match_b = match_log_directive(
        _resolved(LogDirectiveState.CONFIGURED, ['/var/log/nginx/access.log']), [shared_source],
    )

    # Before dedup: each individual match correctly reports its own MATCHED
    # destination — evidence that both server blocks configured this path
    # is preserved at this stage, not lost.
    assert match_a.matched_sources[0].path == '/var/log/nginx/access.log'
    assert match_b.matched_sources[0].path == '/var/log/nginx/access.log'

    deduped = dedupe_matches([match_a, match_b])

    assert len(deduped) == 1
    assert deduped[0].path == '/var/log/nginx/access.log'


def test_dedupe_matches_preserves_distinct_paths():
    source_a = _log_source('/var/log/nginx/a.log')
    source_b = _log_source('/var/log/nginx/b.log')
    match_a = match_log_directive(_resolved(LogDirectiveState.CONFIGURED, ['/var/log/nginx/a.log']), [source_a])
    match_b = match_log_directive(_resolved(LogDirectiveState.CONFIGURED, ['/var/log/nginx/b.log']), [source_b])

    deduped = dedupe_matches([match_a, match_b])

    paths = {s.path for s in deduped}
    assert paths == {'/var/log/nginx/a.log', '/var/log/nginx/b.log'}


def test_dedupe_matches_order_preserving_first_occurrence_wins():
    shared_source_first = _log_source('/var/log/nginx/access.log')
    shared_source_again = _log_source('/var/log/nginx/access.log')  # a distinct object, same path
    match_a = match_log_directive(
        _resolved(LogDirectiveState.CONFIGURED, ['/var/log/nginx/access.log']), [shared_source_first],
    )
    match_b = match_log_directive(
        _resolved(LogDirectiveState.CONFIGURED, ['/var/log/nginx/access.log']), [shared_source_again],
    )

    deduped = dedupe_matches([match_a, match_b])

    assert len(deduped) == 1
    assert deduped[0] is shared_source_first


def test_dedupe_matches_empty_input():
    assert dedupe_matches([]) == []


def test_dedupe_matches_skips_not_found_and_disabled():
    not_found_match = match_log_directive(
        _resolved(LogDirectiveState.CONFIGURED, ['/var/log/nginx/missing.log']), [],
    )
    disabled_match = ResolvedLogDirective(state=LogDirectiveState.DISABLED, destinations=[], source_level='server')
    disabled_match = match_log_directive(disabled_match, [])

    deduped = dedupe_matches([not_found_match, disabled_match])
    assert deduped == []
