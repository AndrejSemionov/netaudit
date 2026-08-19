"""
Nginx Logs Audit — Discovery/Resolver matching: connects the nginx
configuration's authoritative log paths (ResolvedLogDirective, from
nginx_log_resolver.py) to the filesystem facts Discovery actually
observed (LogSource, from log_discovery.py/checks/log_discovery_audit.py).

Why this is its own layer, not folded into Discovery or the resolver
------------------------------------------------------------------
Three distinct questions, three distinct layers (project session notes,
2026-08-18):
  Discovery = "what log files exist on disk?" (facts, no config knowledge)
  Resolver  = "what does nginx's config SAY it logs to?" (config
              semantics, no filesystem knowledge)
  Matching  = "which discovered files correspond to configured paths?"
              (relationship between the two — this module)
  Collection = "read the matched files" (a later, separate step)

Matching Contract v1 (frozen, do not change without a fresh review)
------------------------------------------------------------------
1. Exact path match only — no basename matching, no "looks similar"
   heuristics. '/etc/nginx/access.log' and '/var/log/nginx/access.log'
   are different files even though they share a basename.
2. Multiple CONFIGURED destinations each get their own independent
   match attempt — if a server logs to two files, both are matched (or
   not) independently, not "at least one matches -> good enough."
3. A configured path with no matching LogSource is NOT_FOUND — never a
   silent skip, never a fallback search for a similarly-named file.
   This is the central protection this whole layer exists for: without
   it, "access.log configured but not found" could quietly resolve to
   whatever Discovery happened to find, defeating the entire point of
   making configuration authoritative.
4. Discovered files with no matching configured path are simply never
   selected — Discovery answering "what exists" is not itself
   authorization to collect a file config didn't name.
5. Rotated files (.N / .N.gz) are never matched in v1, even if a
   configured base path would technically prefix-match one — Discovery
   itself already excludes them from its LogSource list (see
   log_discovery_audit.py's _is_rotated_filename()), so this layer
   doesn't need its own rotation-awareness; a rotated file simply isn't
   a candidate LogSource to begin with.
6. DISABLED (`access_log off;`) -> no matching attempted at all,
   matched_sources is always empty for that state. There is nothing to
   look for.
7. UNCONFIGURED -> no matching attempted, matched_sources is always
   empty. UNCONFIGURED must never be treated as "assume the filesystem
   default path" — this layer has no opinion on what nginx's compiled-in
   default might be.
8. Two servers resolving to the same configured path must not cause
   that file to be matched (or eventually collected) twice — matching
   is deduplicated by path, while still preserving which server
   block(s) that path came from as evidence (for future Findings use).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .checks.log_discovery_audit import LogSource
from .nginx_log_resolver import LogDirectiveState, ResolvedLogDirective


class MatchStatus(str, Enum):
    MATCHED = 'matched'
    NOT_FOUND = 'not_found'


@dataclass(frozen=True)
class DestinationMatch:
    configured_path: str
    status: MatchStatus
    source: LogSource | None  # set iff status == MATCHED


@dataclass(frozen=True)
class NginxLogSourceMatch:
    """Result of matching one ResolvedLogDirective (already the
    effective, cascaded result for one server) against Discovery's
    LogSource list. One entry in `destinations` per configured
    destination path (Matching Contract v1 rule 2) — empty for
    DISABLED/UNCONFIGURED states (rules 6-7)."""
    state: LogDirectiveState  # carried through from the ResolvedLogDirective this was matched against
    destinations: list[DestinationMatch] = field(default_factory=list)

    @property
    def matched_sources(self) -> list[LogSource]:
        return [d.source for d in self.destinations if d.status == MatchStatus.MATCHED and d.source is not None]


def match_log_directive(resolved: ResolvedLogDirective, discovered: list[LogSource]) -> NginxLogSourceMatch:
    """Matches one ResolvedLogDirective's destinations against
    Discovery's list of LogSource candidates, per Matching Contract v1.
    Exact path equality only (rule 1) — discovered is typically
    LogDiscoveryReport.nginx_sources (or any list of LogSource with
    SourceType.NGINX_LOG), but this function doesn't filter by
    source_type itself — that's the caller's responsibility to have
    already narrowed, same as it narrows to non-rotated files upstream
    in Discovery."""
    if resolved.state in (LogDirectiveState.DISABLED, LogDirectiveState.UNCONFIGURED):
        return NginxLogSourceMatch(state=resolved.state, destinations=[])

    by_path = {source.path: source for source in discovered if source.path is not None}

    destinations: list[DestinationMatch] = []
    for dest in resolved.destinations:
        source = by_path.get(dest.path)
        if source is not None:
            destinations.append(DestinationMatch(
                configured_path=dest.path, status=MatchStatus.MATCHED, source=source,
            ))
        else:
            destinations.append(DestinationMatch(
                configured_path=dest.path, status=MatchStatus.NOT_FOUND, source=None,
            ))

    return NginxLogSourceMatch(state=resolved.state, destinations=destinations)


def dedupe_matches(matches: list[NginxLogSourceMatch]) -> list[LogSource]:
    """Flattens matched_sources across several NginxLogSourceMatch
    results (e.g. one per server block) into a single deduplicated
    list of LogSource to collect — per Matching Contract v1 rule 8: the
    same file must never appear twice just because two server blocks
    both configured it. Deduplicates by LogSource.path; first
    occurrence wins (order-preserving)."""
    seen: dict[str, LogSource] = {}
    for match in matches:
        for source in match.matched_sources:
            if source.path not in seen:
                seen[source.path] = source
    return list(seen.values())
