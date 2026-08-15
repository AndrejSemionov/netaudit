"""
Semantic resolution over a parsed NginxConfigV2 (nginx_config_v2.py):
effective directive values across the http -> server -> location cascade,
default_server ambiguity per address:port listen group, and HTTP/HTTPS
server_name pairing for redirect-exposure checks.

This module is where "what did the config literally say at each level"
(nginx_config_v2.py's job) turns into "what is actually in effect, and
with what confidence" - the fact every Tier-2 control (NGX-TLS-004,
NGX-HDR-004/005/006, NGX-CONF-003, NGX-EXP-002/003; see
docs/checks/nginx_hardening.md section 7) needs before it can decide
PASS/FAIL/N/A/UNKNOWN. Resolvers never make that PASS/FAIL/UNKNOWN
decision themselves - they hand back an EffectiveValue (or a listen-group
/ server-pair relationship) with enough provenance for a control to
decide, and stop there. Keeping that line intact is what lets a single
resolver bug-fix apply to all seven controls at once instead of each
control re-deriving its own notion of "effective."

Read-only with respect to its input: no function here mutates the
NginxConfigV2/ServerBlock/ListenEndpoint/LocationBlock/AddHeader passed
to it (see nginx_config_v2.py's module docstring on the immutability
contract this depends on).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .nginx_config_v2 import AddHeader, ListenEndpoint, ServerBlock
from .nginx_v2_utils import has_nginx_variable


# ===========================================================================
# EffectiveValueResolver — ordinary cascading directives
# (ssl_ciphers, client_max_body_size: both documented http/server/location
# context, nginx.org — nearest explicit level wins, no special inheritance
# rule stated, so ordinary cascading applies)
# ===========================================================================

@dataclass(frozen=True)
class EffectiveValue:
    """Result of resolving one directive's effective value across the
    http -> server -> location cascade.

    `source` records *which* level actually supplied the value (or that
    none did and nginx's own compiled-in default applies), separately
    from `explicit` (whether a level in the config named the directive
    at all, vs. it being nginx's default). This split matters for
    evidence text: NGX-TLS-004's nginx-default cipher list
    (HIGH:!aNULL:!MD5) is `explicit=False, source='nginx-default'`, which
    is a materially different fact for a report reader than
    `explicit=True, source='http'` even when a control's PASS/FAIL/
    UNKNOWN verdict on the two might coincide.

    `has_variable` is surfaced here (not left for every control to
    recompute) because it is the same lexical fact regardless of which
    directive is being resolved - see has_nginx_variable()'s docstring
    for why detecting it is this module's job and interpreting it
    (-> UNKNOWN, per every Tier-2 control's agreed semantics) is the
    control's.
    """

    value: str | None
    source: Literal['explicit', 'nginx-default', 'absent']
    level: Literal['location', 'server', 'http', 'default', None]
    explicit: bool
    has_variable: bool


def resolve_cascading_value(
    directive: str,
    nginx_default: str | None,
    *,
    http_directives: dict[str, list[str]],
    server_directives: dict[str, list[str]] | None = None,
    location_directives: dict[str, list[str]] | None = None,
) -> EffectiveValue:
    """Resolve `directive`'s effective value using nginx's ordinary
    cascading rule: nearest explicit level wins (location beats server
    beats http beats nginx's own compiled-in default). This is the rule
    ssl_ciphers and client_max_body_size both follow - neither directive
    is documented with add_header's special all-or-nothing-per-level
    inheritance (see resolve_add_headers() below for that one).

    Callers pass whichever of `server_directives`/`location_directives`
    are relevant to the ServerBlock/LocationBlock being evaluated -
    passing only `http_directives` resolves the http-level value (useful
    when a control needs to know what a server would inherit absent its
    own override). Each dict is the raw `directives` mapping straight off
    NginxConfigV2/ServerBlock/LocationBlock - deliberately NOT
    pre-merged by the caller (see this module's top docstring and the
    Milestone 2 architecture decision it reflects: "no changes to
    parser/model levels are pre-merged before a resolver sees them").

    If `directive` appears more than once at the same level (nginx
    allows a directive to be repeated in some contexts, though neither
    ssl_ciphers nor client_max_body_size documents itself as repeatable -
    nginx.org shows each with a single-value Syntax line), the last
    occurrence at that level is used, matching nginx's own
    last-directive-wins behavior for non-repeatable directives at a
    single level.
    """
    for level_name, directives in (
        ('location', location_directives),
        ('server', server_directives),
        ('http', http_directives),
    ):
        if directives and directive in directives and directives[directive]:
            value = directives[directive][-1]
            return EffectiveValue(
                value=value, source='explicit', level=level_name,
                explicit=True, has_variable=has_nginx_variable(value),
            )

    if nginx_default is not None:
        return EffectiveValue(
            value=nginx_default, source='nginx-default', level='default',
            explicit=False, has_variable=has_nginx_variable(nginx_default),
        )

    return EffectiveValue(value=None, source='absent', level=None,
                           explicit=False, has_variable=False)


# ===========================================================================
# EffectiveValueResolver — add_header (special all-or-nothing inheritance)
# ===========================================================================

def resolve_add_headers(
    *,
    http_add_headers: list[AddHeader],
    server_add_headers: list[AddHeader] | None = None,
    location_add_headers: list[AddHeader] | None = None,
) -> list[AddHeader]:
    """Resolve the effective set of add_header directives in force at a
    given location/server, per nginx.org's ngx_http_headers_module:
    "There could be several add_header directives. These directives are
    inherited from the previous configuration level if and only if there
    are no add_header directives defined on the current level."

    This is deliberately NOT the same algorithm as
    resolve_cascading_value() above: add_header inheritance is
    all-or-nothing per level (if the current level defines even one
    add_header, none of the parent level's add_headers apply - not just
    the one with a matching name), whereas ssl_ciphers/
    client_max_body_size have no such rule and simply take the nearest
    explicit single value. Conflating the two would silently apply the
    wrong inheritance model to whichever directive got the "simpler"
    treatment.

    `add_header_inherit` (nginx 1.29.3+, allows `on`/`off`/`merge`
    inheritance modes - nginx.org, ngx_http_headers_module) is out of
    scope: this project's target VM runs nginx/1.28.3, and the standard
    (pre-1.29.3) inheritance model implemented here is what
    docs/checks/nginx_hardening.md's Tier-2 planning settled on for v1 -
    see that document for the explicit decision not to model
    add_header_inherit now.

    Returns the location's own add_headers if it has any, else the
    server's if it has any, else the http level's (which may be empty).
    """
    if location_add_headers:
        return location_add_headers
    if server_add_headers:
        return server_add_headers
    return list(http_add_headers)


def find_effective_header(name: str, add_headers: list[AddHeader]) -> AddHeader | None:
    """Find the effective add_header for response header `name` (case-
    insensitive, per HTTP header name matching) within an already-
    resolved add_headers list (see resolve_add_headers()). If `name`
    appears more than once in the list (nginx explicitly allows repeated
    add_header directives for different headers, and technically for the
    same header name too), the last one wins - matching how nginx itself
    applies directives in file order within a single context.

    Returns None if no add_header for `name` is present in the resolved
    set - the caller (a Tier-2 control) is expected to treat that as
    "header absent," per each control's own FAIL/UNKNOWN handling for
    absence (see docs/checks/nginx_hardening.md NGX-HDR-004/005/006).
    """
    match = None
    for h in add_headers:
        if h.name.lower() == name.lower():
            match = h
    return match


# ===========================================================================
# ListenGroupResolver — NGX-EXP-003 (default_server ambiguity)
# ===========================================================================

@dataclass(frozen=True)
class ListenGroup:
    """All (ServerBlock, ListenEndpoint) pairs sharing one normalized
    address:port group_key (see ListenEndpoint.group_key), plus the
    resolved effective default for that group.

    `ambiguous` is the fact NGX-EXP-003 actually checks (see
    docs/checks/nginx_hardening.md's finalized semantics): True when the
    group has more than one member and none of them explicitly declared
    `default_server` - in which case nginx silently picks the first
    member by config order (nginx.org's `listen` directive: "If none of
    the directives have the default_server parameter then the first
    server with the address:port pair will be the default server for
    this pair."), and this project's Tier-2 policy treats that as an
    unintended-exposure signal. `ambiguous=False` covers both the
    single-member case (default is unambiguous because there is no
    alternative) and the explicit-default_server case (administrator
    intent is expressed) - NGX-EXP-003 does not distinguish these two
    "fine" cases from each other, only from the ambiguous one.

    `effective_default` is the (ServerBlock, ListenEndpoint) pair that
    would actually serve as nginx's default for this group - the
    explicit default_server if one exists, else the earliest-`order`
    member. Present even when `ambiguous=True`, since nginx still picks
    *someone* by config order; NGX-EXP-003's FAIL is about the ambiguity
    of that choice, not about the group having no default server at all
    (every group always has exactly one, per nginx's own selection
    rule).
    """

    group_key: tuple[str, int | None]
    members: list[tuple[ServerBlock, ListenEndpoint]]
    effective_default: tuple[ServerBlock, ListenEndpoint]
    ambiguous: bool


def resolve_listen_groups(servers: list[ServerBlock]) -> list[ListenGroup]:
    """Group every (ServerBlock, ListenEndpoint) pair across `servers` by
    normalized address:port (ListenEndpoint.group_key), and resolve each
    group's effective default_server per nginx.org's documented rule
    (see ListenGroup's docstring).

    Groups are built purely from ListenEndpoint.group_key equality - no
    attempt is made to reason about whether two *different* group keys
    might overlap at the socket level (e.g. a concrete IP vs `*` on the
    same port could both accept connections for that IP in practice).
    This mirrors normalize_listen_address()'s own documented scope
    (nginx_v2_utils.py): this project groups by literal, normalized
    address:port, not by simulating nginx's full socket-binding
    semantics - see that function's docstring for the specific case
    (IPv4 `*` vs IPv6 `[::]`) this project deliberately keeps distinct
    rather than trying to resolve.

    Within a group, members are naturally in ascending `order` because
    ListenEndpoint.order is assigned during parsing in `nginx -T`
    encounter order and this function does not reorder the input -
    callers relying on `effective_default` being the *first* member when
    no explicit default_server exists depend on this, so this function
    must not sort members by anything other than preserving input order
    (which is why it appends to each group's list in the order it
    encounters ServerBlocks/ListenEndpoints, never sorts them
    afterward).
    """
    groups: dict[tuple[str, int | None], list[tuple[ServerBlock, ListenEndpoint]]] = {}

    for server in servers:
        for listen in server.listens:
            groups.setdefault(listen.group_key, []).append((server, listen))

    result: list[ListenGroup] = []
    for key, members in groups.items():
        explicit_default = next((m for m in members if m[1].default_server), None)
        if explicit_default is not None:
            effective_default = explicit_default
            ambiguous = False
        else:
            effective_default = members[0]  # earliest by parse order
            ambiguous = len(members) > 1

        result.append(ListenGroup(group_key=key, members=members,
                                   effective_default=effective_default,
                                   ambiguous=ambiguous))

    return result


# ===========================================================================
# ServerPairResolver — NGX-EXP-002 (HTTP -> HTTPS server_name pairing)
# ===========================================================================

def _is_exact_server_name(name: str) -> bool:
    """True if `name` is an exact, literal server_name - no wildcard
    (`*.example.com`, `example.*`, or a bare `.example.com` shorthand
    per nginx.org's `server_name` directive) and no regex (`~...`
    prefix). Only exact names are used for NGX-EXP-002 pairing in v1 -
    see find_https_pair()'s docstring for why wildcard/regex names route
    to an unpaired (UNKNOWN-worthy) result instead of being matched.
    """
    if name.startswith('~'):
        return False
    if '*' in name:
        return False
    if name.startswith('.'):
        return False
    return True


@dataclass(frozen=True)
class ServerPairResult:
    """Result of trying to find the HTTPS ServerBlock that pairs with a
    given HTTP ServerBlock for NGX-EXP-002 purposes.

    `https_server` is None whenever no exact-name-match HTTPS pair could
    be established - `reason` distinguishes *why*, which the control
    needs to choose between UNKNOWN ('no_https_endpoint' - see
    docs/checks/nginx_hardening.md's finalized NGX-EXP-002 semantics:
    "HTTP endpoint + нет доказуемого exact-match HTTPS endpoint ->
    UNKNOWN", not FAIL, because an HTTP-only site by design is not
    provably a redirect-exposure gap) and 'wildcard_or_regex_name'
    (also UNKNOWN, per the same spec discussion: this project does not
    implement nginx's wildcard/regex server_name matching priority, so a
    config using either is honestly unresolvable in v1 rather than
    guessed at).
    """

    https_server: ServerBlock | None
    reason: Literal['paired', 'no_https_endpoint', 'wildcard_or_regex_name'] | None


def find_https_pair(http_server: ServerBlock, all_servers: list[ServerBlock]) -> ServerPairResult:
    """Find the HTTPS ServerBlock (has a `listen ... ssl` endpoint) whose
    server_names exact-match at least one of `http_server`'s
    server_names, per the exact-literal-only matching this project
    settled on for NGX-EXP-002 (docs/checks/nginx_hardening.md: "Если
    wildcard/regex встречается в соответствующем server_name, результат:
    UNKNOWN... не пытаемся интерпретировать" nginx's own
    exact/wildcard/regex priority order).

    If ANY of `http_server`'s server_names is a wildcard or regex form,
    this returns `reason='wildcard_or_regex_name'` immediately without
    attempting a match - not because such a config can't have a valid
    HTTPS pair, but because this project does not implement nginx's
    server_name matching algorithm (exact > longest-wildcard-prefix >
    longest-wildcard-suffix > first-matching-regex, per nginx.org's
    `server_name` directive) and would rather say "cannot prove this" than
    silently apply exact-string matching to a name form where that isn't
    how nginx actually resolves it - the same asymmetric-proof principle
    every other Tier-2 control in this project follows.

    HTTPS candidates with any wildcard/regex server_name are skipped for
    the same reason (an exact-name match against a candidate whose
    matching semantics this project doesn't model would be an unproven
    claim of a pairing).

    `all_servers` is expected to include `http_server` itself (it will
    simply never match, since it has no `ssl` listen); passing the full
    NginxConfigV2.servers list is the intended usage.
    """
    if any(not _is_exact_server_name(n) for n in http_server.server_names):
        return ServerPairResult(https_server=None, reason='wildcard_or_regex_name')

    http_names = set(http_server.server_names)

    for candidate in all_servers:
        if candidate is http_server:
            continue
        if not any(le.ssl for le in candidate.listens):
            continue
        if any(not _is_exact_server_name(n) for n in candidate.server_names):
            continue
        if http_names & set(candidate.server_names):
            return ServerPairResult(https_server=candidate, reason='paired')

    return ServerPairResult(https_server=None, reason='no_https_endpoint')


def is_https_redirect_target(target: str) -> bool | None:
    """Classify a `return`/`rewrite` redirect target for NGX-EXP-002's
    "doказуемый HTTPS redirect" test (docs/checks/nginx_hardening.md):

    - True: target literally begins with `https://` (case-sensitive,
      matching nginx's own literal-string check for redirect URL
      handling per ngx_http_rewrite_module - anything after the literal
      prefix, including nginx variables like $host/$request_uri, does
      not change this - the protocol itself is what must be provably
      static, not the whole URL).
    - False: target begins with a variable (most commonly $scheme) or
      any other non-https:// literal (e.g. plain `http://...`, or a
      bare path) - the protocol is not provably HTTPS from config text
      alone.
    - None is never returned by this function directly, but see the
      calling control's handling: a `has_nginx_variable(target)` check
      before the literal-prefix test would misclassify
      'https://$host$request_uri' as unprovable, since it DOES contain a
      variable - just not in the protocol position. This function
      exists specifically so NGX-EXP-002 does not make that mistake:
      only the literal-prefix fact matters here, not general variable
      presence in the target as a whole.
    """
    return target.startswith('https://')
