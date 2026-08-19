"""
Nginx Logs Audit — Collection integration: a thin adapter that takes
the already-deduplicated, authoritative list[LogSource] produced by
nginx_log_matching.dedupe_matches() and collects each one independently
via the existing log_collection.collect_file() — no new reading
mechanism, no nginx-specific knowledge, no security judgment.

Why this is a separate, deliberately thin module
------------------------------------------------------------------
Discovery, the resolver, and matching each answer their own question
(project session notes, 2026-08-18/19): "what exists", "what does
config say", "what corresponds to what". This module answers only "read
what was already decided to be authoritative" — it does not re-derive
which sources matter, does not treat LogFileState.STALE_EMPTY as a
reason to skip a source (that's a Discovery-level fact about the file's
size at discovery time, not a collection-time decision — see this
module's docstring on why every matched source is collected
unconditionally), and does not decide whether collected content is
"useful" (that's Parser/Detection's job, not yet reached).

Collection Integration Contract v1 (frozen, do not change without a
fresh review)
------------------------------------------------------------------
1. Every LogSource in the input list is collected independently via
   collect_file() — no filtering, no skipping based on
   LogFileState/size/anything else Discovery already recorded.
2. Duplicate LogSource objects (same path) are never collected twice —
   but deduplication is dedupe_matches()'s job (already done before
   this module runs), not re-implemented here. This module trusts its
   input is already deduplicated.
3. collect_file() itself is not modified, wrapped in new retry logic,
   or reimplemented — this module calls it as-is.
4. A failure collecting one source (an exception from collect_file()'s
   underlying SSH call, which is not caught inside collect_file()
   itself — confirmed by reading its source) must not prevent the
   other sources from being collected. Each source's outcome is
   isolated.
5. Results are returned in the same order as the input list —
   deterministic given a deterministic input, regardless of collection
   timing.
6. Rotation is out of scope here, same as everywhere upstream in this
   contour — the input list is Discovery's already-rotation-filtered
   current-file view.
7. Empty input -> empty output, with zero SSH calls issued.
"""

from __future__ import annotations

from dataclasses import dataclass

from .checks.log_discovery_audit import LogSource
from .log_collection import CollectionResult, collect_file
from .ssh import SSHExecutor


@dataclass(frozen=True)
class NginxLogCollectionResult:
    """One LogSource's collection outcome. Exactly one of `result` /
    `error` is set — collect_file() raising is captured here rather
    than propagating, so one source's failure can never take down the
    others (Contract rule 4)."""
    source: LogSource
    result: CollectionResult | None
    error: str | None  # str(exception) if collect_file() raised; None on success


def collect_nginx_logs(ssh: SSHExecutor, sources: list[LogSource],
                        lines: int = 200, timeout: int = 20) -> list[NginxLogCollectionResult]:
    """Collects each LogSource in `sources` independently via
    collect_file(), in order, isolating any exception per-source. See
    this module's docstring for the full contract. `sources` is
    expected to already be deduplicated (e.g. the output of
    nginx_log_matching.dedupe_matches()) — this function does not
    deduplicate again."""
    results: list[NginxLogCollectionResult] = []

    for source in sources:
        try:
            result = collect_file(ssh, source, lines=lines, timeout=timeout)
        except Exception as e:  # noqa: BLE001 - deliberately broad: any SSH-layer
            # failure for one source must not abort collection of the
            # rest (Contract rule 4) — collect_file() does not catch
            # its own underlying SSH exceptions (confirmed by reading
            # its source), so this is the boundary where isolation
            # actually happens.
            results.append(NginxLogCollectionResult(source=source, result=None, error=str(e)))
            continue

        results.append(NginxLogCollectionResult(source=source, result=result, error=None))

    return results
