"""
Nginx Logs Audit — log directive resolution: determines the
authoritative access_log/error_log filesystem paths for a given
ServerBlock, from the nginx configuration itself (NginxConfigV2),
rather than guessing from filenames/sizes/mtimes on disk.

Why this exists (project session notes, 2026-08-18)
------------------------------------------------------------------
Discovery's NGINX_LOG source type (log_discovery.py's nginx glob) can
return several current (non-rotated) candidate files at once — e.g.
writer's real layout has both a dead 0-byte /var/log/nginx/access.log
decoy AND the real, active /var/log/nginx/andreykapro_access.log. There
is no filename/size/mtime heuristic that reliably distinguishes "the
real log" from "the decoy" across arbitrary nginx configurations — the
nginx configuration ITSELF is the only authoritative source for where a
given server logs to, since NginxConfigV2's generic `directives` dict
already captures access_log/error_log verbatim (confirmed empirically:
no parser changes were needed - see this module's test file for the
edge-case matrix this was verified against).

Cascade contract (frozen, do not change without a fresh review)
------------------------------------------------------------------
For a given ServerBlock:
  - If the server level has ANY access_log directive(s) (or
    error_log), those entries COMPLETELY REPLACE the http-level list —
    this is not a per-entry merge. Presence of even one server-level
    directive switches inheritance off entirely for that directive
    name at that server.
  - If the server level has NONE, the http-level list is inherited
    in full.
  - `access_log off;` (or `error_log off;`) at the server level is an
    explicit override that stops inheritance — it does NOT fall back
    to the http-level list. An http-level "off" with no server-level
    directive at all is inherited normally (server sees DISABLED,
    correctly, via inheritance rather than an override).
  - location-level access_log/error_log directives are NOT read by
    this module in v1 — this resolver determines host-level log
    sources for the audit, not per-request effective logging after
    nginx's location-selection algorithm (which this project does not
    implement at all — see nginx_config_v2.py's LocationBlock
    docstring). This is a deliberate scope boundary, not an oversight.

Four states, not a bare list[str]
------------------------------------------------------------------
Collapsing "no directive present" and "explicitly disabled" and
"directive present but unparseable" into the same "empty list" shape
would lose distinctions Detection/Findings and E2E verification need
later — the same principle already applied to
LogSource.available/readable in log_discovery.py, and to
CollectionResult.completed vs a confirmed-empty result in
log_collection.py:
  UNCONFIGURED — no directive at this level or inherited from http;
                 nginx's own compiled-in default access.log/error.log
                 applies (this resolver does not know that default
                 path — it only reports that nothing was explicitly
                 configured)
  CONFIGURED   — one or more resolved destinations
  DISABLED     — explicit `off` (at the level that determined the
                 effective value, which may be inherited from http)
  UNRESOLVED   — a directive is present but this resolver could not
                 confidently extract a path from it (reserved for
                 future syntax this v1 doesn't yet handle - see
                 _parse_destination())
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .nginx_config_v2 import NginxConfigV2, ServerBlock


class LogDirectiveState(str, Enum):
    UNCONFIGURED = 'unconfigured'
    CONFIGURED = 'configured'
    DISABLED = 'disabled'
    UNRESOLVED = 'unresolved'


@dataclass(frozen=True)
class LogDestination:
    path: str
    options: str | None  # everything after the path (format name, buffer=, level, etc.) - not further parsed in v1


@dataclass(frozen=True)
class ResolvedLogDirective:
    state: LogDirectiveState
    destinations: list[LogDestination]
    source_level: str | None  # 'server' | 'http' | None (UNCONFIGURED/no directive anywhere) - which level's directive determined this result, for evidence/debugging


def _parse_destination(raw: str) -> LogDestination:
    """Splits one directive argument string into path + options.
    `raw` is the whole remainder of the directive after its name (e.g.
    '/var/log/nginx/access.log combined buffer=32k') — the first
    whitespace-delimited token is the path, everything after it (if
    any) is preserved verbatim as options, not further parsed."""
    parts = raw.split(None, 1)
    path = parts[0]
    options = parts[1] if len(parts) > 1 else None
    return LogDestination(path=path, options=options)


def _resolve(directive_name: str, cfg: NginxConfigV2, server: ServerBlock) -> ResolvedLogDirective:
    """Shared cascade logic for both access_log and error_log — see
    this module's docstring for the frozen cascade contract. Kept as a
    single shared implementation (not duplicated per directive name) so
    the two public functions can never silently drift apart."""
    server_values = server.directives.get(directive_name)
    if server_values:
        return _resolve_from_values(server_values, source_level='server')

    http_values = cfg.http_directives.get(directive_name)
    if http_values:
        return _resolve_from_values(http_values, source_level='http')

    return ResolvedLogDirective(state=LogDirectiveState.UNCONFIGURED, destinations=[], source_level=None)


def _resolve_from_values(values: list[str], source_level: str) -> ResolvedLogDirective:
    """values is the raw list of argument strings for one directive
    name at one level (e.g. server.directives['access_log']) — already
    determined to be the effective source for this level per the
    cascade rule in _resolve(). 'off' as the sole value at this level
    is DISABLED; anything else becomes one or more CONFIGURED
    destinations, in order."""
    if values == ['off']:
        return ResolvedLogDirective(state=LogDirectiveState.DISABLED, destinations=[], source_level=source_level)

    destinations = [_parse_destination(v) for v in values]
    return ResolvedLogDirective(state=LogDirectiveState.CONFIGURED, destinations=destinations,
                                 source_level=source_level)


def resolve_access_log(cfg: NginxConfigV2, server: ServerBlock) -> ResolvedLogDirective:
    """Resolves the effective access_log directive for `server`, per
    the cascade contract in this module's docstring."""
    return _resolve('access_log', cfg, server)


def resolve_error_log(cfg: NginxConfigV2, server: ServerBlock) -> ResolvedLogDirective:
    """Resolves the effective error_log directive for `server`, per the
    cascade contract in this module's docstring (identical rule to
    resolve_access_log, applied to the 'error_log' directive name)."""
    return _resolve('error_log', cfg, server)
