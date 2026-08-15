"""
NginxConfigV2: structured, per-server-block model of `nginx -T` output,
built for the Tier-2 nginx_hardening controls (NGX-TLS-004, NGX-HDR-004/
005/006, NGX-CONF-003, NGX-EXP-002/003 - see docs/checks/nginx_hardening.md
section 7) that the legacy flat `NginxConfig` (nginx_config.py) cannot
answer: per-server_name/listen questions like "does *this* server_name's
HTTPS endpoint exist" or "is default_server ambiguous for *this*
address:port pair" need the block structure, not a flattened blob of every
directive found anywhere in the file.

The dataclasses and parse_nginx_config_v2() below are domain model +
parsing ONLY - no opinion about PASS/FAIL/UNKNOWN for any NGX-* control,
and no opinion about *effective* values across the http -> server ->
location cascade (that's nginx_v2_resolvers.py's job, deliberately kept
separate - see that module's docstring). collect_nginx_config_v2() at the
bottom of this file is the one exception to "parsing only" - it's the SSH
I/O wrapper around parse_nginx_config_v2(), placed here (not in
checks/nginx_hardening.py) specifically so nginx_hardening.py never needs
to know how NginxConfigV2 gets built, only that it can ask for one -
mirroring collect_nginx_config()'s placement in nginx_config.py for the
same reason.

Parallel to, not a replacement for, the legacy `NginxConfig`
(nginx_config.py): that module and audit_nginx() (server_security.py) are
untouched by this work. See docs/checks/nginx_hardening.md section 7 for
why the two coexist in v1 (two `nginx -T` SSH round-trips is an accepted,
temporary v1 tradeoff, not a design goal - a shared-collection refactor is
explicitly out of scope here).

Immutability contract: once built, a NginxConfigV2 (and everything it
contains - ServerBlock, ListenEndpoint, LocationBlock, AddHeader) is meant
to be read-only. Resolvers (nginx_v2_resolvers.py) and controls
(checks/nginx_hardening.py, once Tier-2 lands there) must not mutate
`.directives`, `.servers`, `.listens`, etc. - they derive new state
(EffectiveValue, Finding, Component) instead. This is what lets the same
parsed config be run through all seven Tier-2 controls and get
deterministic, order-independent results in tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .nginx_v2_utils import normalize_listen_address
from .ssh import SSHExecutor


@dataclass(frozen=True)
class ListenEndpoint:
    """One `listen` directive, already parsed and address-normalized.

    `address`/`port` together form the `address:port` group key that
    NGX-EXP-003 (default_server ambiguity) groups ListenEndpoints by -
    see `group_key` below. Per nginx.org's `listen` directive:
    "default_server... will cause the server to become the default
    server for the specified address:port pair. If none of the
    directives have the default_server parameter then the first server
    with the address:port pair will be the default server for this
    pair." default_server-ness is therefore a property of a
    (ServerBlock, ListenEndpoint) pair relative to its group, not a
    standalone flag meaningful on its own - `default_server` here just
    records whether *this* listen directive carried the explicit keyword;
    resolving "is this the effective default for its group" is
    nginx_v2_resolvers.py's ListenGroupResolver, not this dataclass.

    `order` is this listen directive's position in `nginx -T` output
    (0-indexed, global across the whole config, not per-server) -
    required because nginx's implicit-default-is-first-in-file rule makes
    config order part of the security-relevant state, not incidental
    detail a dict/set representation could safely discard.

    UNIX-domain sockets (`listen unix:/path;`) are represented with
    `address` set to the literal `unix:/path` string and `port=None` -
    they are not an address:port pair at all (nginx.org documents them as
    a distinct `listen unix:path ...;` syntax form), so callers must not
    assume `port` is always an int. `group_key` for a unix listen is
    `(address, None)`, which will never collide with a real address:port
    pair (ports are always non-None ints for IP listens), so grouping
    stays correct without special-casing unix sockets at the resolver
    level - a unix-socket group simply never has more than the unix
    listens that literally repeat the same path.
    """

    address: str
    port: int | None
    ssl: bool
    default_server: bool
    order: int

    @property
    def group_key(self) -> tuple[str, int | None]:
        return self.address, self.port


@dataclass(frozen=True)
class AddHeader:
    """Parsed nginx `add_header` directive.

    Kept separate from the generic `directives: dict[str, list[str]]`
    bucket (on ServerBlock/LocationBlock/NginxConfigV2) not because
    add_header takes multiple arguments - several directives do - but
    because add_header has a unique, documented inheritance rule
    (nginx.org, ngx_http_headers_module): "There could be several
    add_header directives. These directives are inherited from the
    previous configuration level if and only if there are no add_header
    directives defined on the current level." That is an all-or-nothing,
    per-level rule distinct from the ordinary cascading inheritance every
    other Tier-2 directive (ssl_ciphers, client_max_body_size) follows -
    see nginx_v2_resolvers.py for where that difference is actually
    implemented. A generic dict-of-strings representation could not
    distinguish "this level explicitly cleared inheritance by defining
    its own add_header set" from "this level said nothing," which is
    exactly the distinction NGX-HDR-004/005/006 need to get right.
    """

    name: str
    value: str
    always: bool


@dataclass(frozen=True)
class LocationBlock:
    """One `location` block. `modifier` and `path` are stored as parsed
    but NOT interpreted - this project does not implement nginx's
    location-selection algorithm (longest-prefix match, regex priority,
    `^~` short-circuiting, etc.; see nginx.org's `location` directive and
    docs/checks/nginx_hardening.md section 7 for why that's explicitly
    out of scope for v1). Tier-2 controls that read LocationBlock treat
    each location independently; none of them currently need to reason
    about which location nginx would actually select for a given request.

    `modifier` is one of `None` (prefix match, no modifier), `'='`
    (exact), `'^~'` (prefix, skip regex check), `'~'` (case-sensitive
    regex), `'~*'` (case-insensitive regex) - stored verbatim from the
    config, not validated against this list, so an nginx version that
    adds a new modifier wouldn't be silently misparsed.
    """

    modifier: str | None
    path: str
    directives: dict[str, list[str]] = field(default_factory=dict)
    add_headers: list[AddHeader] = field(default_factory=list)
    order: int = 0


@dataclass(frozen=True)
class ServerBlock:
    """One `server {}` block.

    `server_names` is `list[str]`, not `set[str]`, and NOT deduplicated
    or sorted - order and repetition are preserved because nginx.org's
    `server_name` directive gives the first name special meaning ("The
    first name becomes the primary server name") and defines wildcard/
    regex matching priority by *position* among other things. Tier-2's
    NGX-EXP-002 (docs/checks/nginx_hardening.md Tier-2 planning) only
    uses exact-literal-name intersection in v1 and explicitly punts to
    UNKNOWN when either side's server_names include a wildcard (`*.`) or
    regex (`~`) form - see nginx_v2_resolvers.py's ServerPairResolver.
    This dataclass does not pre-classify names into exact/wildcard/regex
    buckets; that classification is a resolver concern, kept out of the
    parser so the parser stays a faithful structural transcription of
    what `nginx -T` printed.

    `directives` and `add_headers` follow the same split as
    LocationBlock (see AddHeader's docstring for why).

    `order` is this server block's position in `nginx -T` output
    (0-indexed, global) - required by NGX-EXP-003's implicit-default-is-
    first-in-config-order rule.
    """

    order: int
    server_names: list[str] = field(default_factory=list)
    listens: list[ListenEndpoint] = field(default_factory=list)
    directives: dict[str, list[str]] = field(default_factory=dict)
    add_headers: list[AddHeader] = field(default_factory=list)
    locations: list[LocationBlock] = field(default_factory=list)


@dataclass(frozen=True)
class NginxConfigV2:
    """Top-level parsed structure: everything at `http {}` level plus
    every `server {}` block found (in `nginx -T` order - see ServerBlock's
    `order` field).

    `installed`/`readable` mirror the legacy NginxConfig's fields for the
    same reasons documented there (nginx_config.py): a check consuming
    this needs to distinguish "nginx isn't installed", "nginx -T needed
    root and we don't have it" (readable=False), and "parsed
    successfully but the http{} block was empty" (readable=True, empty
    servers list) - three different situations a single boolean or a
    None couldn't tell apart.
    """

    installed: bool
    readable: bool = False
    http_directives: dict[str, list[str]] = field(default_factory=dict)
    http_add_headers: list[AddHeader] = field(default_factory=list)
    servers: list[ServerBlock] = field(default_factory=list)


# ===========================================================================
# Parser
# ===========================================================================

def _strip_comments(conf: str) -> str:
    """Identical algorithm to nginx_config.py's `_strip_comments()` -
    quote-aware, line-by-line `#`-comment removal, deliberately
    duplicated here rather than imported.

    Not shared via import because the two modules are independent by
    design (see this module's top docstring: v1's two-collector-two-SSH-
    round-trip tradeoff is accepted precisely so V2 does not create a
    dependency on the legacy parser's internals, which would make the
    "V2 doesn't touch legacy" boundary (docs/checks/nginx_hardening.md
    Tier-2 planning) harder to keep honest over time). A future shared-
    collection refactor (out of scope for v1) is the right place to
    de-duplicate this, once both parsers are stable.

    See nginx_config.py's `_strip_comments()` docstring for the full
    rationale (a real bug found on a live VM: a commented-out directive
    silently read as active without this).
    """
    out_lines = []
    for line in conf.splitlines():
        result = []
        in_squote = False
        in_dquote = False
        for ch in line:
            if ch == "'" and not in_dquote:
                in_squote = not in_squote
            elif ch == '"' and not in_squote:
                in_dquote = not in_dquote
            elif ch == '#' and not in_squote and not in_dquote:
                break
            result.append(ch)
        out_lines.append(''.join(result))
    return '\n'.join(out_lines)


def _tokenize(conf: str) -> list[str]:
    """Split comment-stripped nginx config text into a flat token stream:
    each directive name, each argument, and each of `{`/`}`/`;` becomes
    one token. Quote-aware (a quoted string, e.g. `"default-src 'self'"`,
    is one token including its quotes stripped, even if it contains
    spaces) - this is what lets `add_header X-Custom "a b";` produce
    exactly one value token `a b`, not two.

    This is a tokenizer, not a full nginx grammar parser: it has no
    concept of directive-specific argument counts or types, no escape-
    sequence handling beyond quote-tracking, and does not validate
    balanced braces (an unbalanced input just produces a token stream
    _parse_block() will raise on, rather than nginx's own more specific
    syntax errors). That is intentional and sufficient for the
    structural facts Tier-2 needs (see this module's top docstring on
    why a full nginx AST is explicitly out of scope).
    """
    tokens: list[str] = []
    current: list[str] = []
    in_squote = False
    in_dquote = False

    def flush():
        if current:
            tokens.append(''.join(current))
            current.clear()

    i = 0
    n = len(conf)
    while i < n:
        ch = conf[i]
        if in_squote:
            if ch == "'":
                in_squote = False
            else:
                current.append(ch)
        elif in_dquote:
            if ch == '"':
                in_dquote = False
            else:
                current.append(ch)
        elif ch == "'":
            in_squote = True
        elif ch == '"':
            in_dquote = True
        elif ch in '{};':
            flush()
            tokens.append(ch)
        elif ch.isspace():
            flush()
        else:
            current.append(ch)
        i += 1
    flush()
    return tokens


class _BlockParser:
    """Consumes a flat token stream (see _tokenize()) and builds a tree
    of directives/blocks. Stateful by necessity (tracks token position
    and a running `order` counter across the whole config so ServerBlock/
    ListenEndpoint `order` values are globally comparable, not just
    comparable within one server) - kept as an internal class rather
    than a public one because nothing outside this module's own
    `_parse_config()` needs to drive it directly.
    """

    def __init__(self, tokens: list[str]):
        self._tokens = tokens
        self._pos = 0
        self._order = 0

    def _peek(self) -> str | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _next(self) -> str | None:
        tok = self._peek()
        if tok is not None:
            self._pos += 1
        return tok

    def _next_order(self) -> int:
        n = self._order
        self._order += 1
        return n

    def parse_block(self, depth: int = 0) -> tuple[dict[str, list[str]], list[AddHeader], list[ServerBlock], list[LocationBlock]]:
        """Parse directives/nested blocks until the matching `}` (or end
        of input at depth 0, i.e. the implicit top-level `http {}`
        contents `nginx -T` prints without an enclosing block marker of
        its own in the flattened output this parser receives - see
        collect_nginx_config_v2()'s caller for how the http{} body is
        isolated before this ever runs).

        Returns four parallel lists: generic directives, add_headers,
        any `server {}` blocks found at this level, any `location {}`
        blocks found at this level. Callers pick out only the piece
        they need (NginxConfigV2 wants servers, ServerBlock wants
        locations, LocationBlock wants none of the block variants -
        nginx does not nest server{} or location{} inside a location{}
        in any form this project treats as in-scope).
        """
        directives: dict[str, list[str]] = {}
        add_headers: list[AddHeader] = []
        servers: list[ServerBlock] = []
        locations: list[LocationBlock] = []

        while True:
            tok = self._peek()
            if tok is None or tok == '}':
                if tok == '}':
                    self._next()
                return directives, add_headers, servers, locations

            name = self._next()
            args: list[str] = []
            while True:
                nxt = self._peek()
                if nxt in (';', '{', None):
                    break
                args.append(self._next())

            closer = self._next()  # ';' or '{'
            if closer == '{':
                if name == 'server':
                    servers.append(self._parse_server())
                elif name == 'location':
                    locations.append(self._parse_location(args))
                else:
                    # Unknown/unsupported block type (e.g. `map {}`,
                    # `upstream {}`) - skip its contents. Tier-2 v1 has
                    # no control that needs these; silently discarding
                    # rather than raising keeps the parser tolerant of
                    # config sections outside its declared scope, matching
                    # this project's stance that missing data should
                    # route a control to UNKNOWN, not crash collection.
                    self._skip_block()
            elif name == 'add_header':
                add_headers.append(self._make_add_header(args))
            elif name is not None:
                directives.setdefault(name, []).append(' '.join(args))

        # unreachable - loop always returns via the `tok is None or '}'`
        # branch

    def parse_top_level_stream(self) -> tuple[dict[str, list[str]], list[AddHeader], list[ServerBlock]]:
        """Walk the entire token stream at position 0, treating `http {}`
        specially (its contents merge into the returned directives/
        add_headers/servers rather than nesting) and any top-level
        `server {}` as directly belonging to the result - see
        _parse_top_level()'s module-level docstring/caller for why a
        top-level `server {}` (one `nginx -T` prints outside http{}'s
        braces, from an included file) must still be collected. Any
        other top-level block (`events {}`, `map {}`, etc.) is skipped
        via _skip_block().

        This is the only entry point external callers
        (parse_nginx_config_v2) should use; parse_block()/_parse_server()/
        etc. remain internal recursive-descent helpers.
        """
        directives: dict[str, list[str]] = {}
        add_headers: list[AddHeader] = []
        servers: list[ServerBlock] = []

        while True:
            tok = self._peek()
            if tok is None:
                return directives, add_headers, servers
            if tok == 'http' and self._pos + 1 < len(self._tokens) and self._tokens[self._pos + 1] == '{':
                self._next()  # 'http'
                self._next()  # '{'
                h_directives, h_add_headers, h_servers, _locs = self.parse_block()
                for k, v in h_directives.items():
                    directives.setdefault(k, []).extend(v)
                add_headers.extend(h_add_headers)
                servers.extend(h_servers)
            elif tok == 'server' and self._pos + 1 < len(self._tokens) and self._tokens[self._pos + 1] == '{':
                self._next()  # 'server'
                self._next()  # '{'
                servers.append(self._parse_server())
            elif tok == '{':
                self._next()
                self._skip_block()
            else:
                self._next()

    def _skip_block(self) -> None:
        depth = 1
        while depth > 0:
            tok = self._next()
            if tok is None:
                return
            if tok == '{':
                depth += 1
            elif tok == '}':
                depth -= 1

    @staticmethod
    def _make_add_header(args: list[str]) -> AddHeader:
        # add_header name value [always];  (nginx.org, ngx_http_headers_module)
        name = args[0] if len(args) >= 1 else ''
        value = args[1] if len(args) >= 2 else ''
        always = len(args) >= 3 and args[2] == 'always'
        return AddHeader(name=name, value=value, always=always)

    def _parse_listen(self, args: list[str]) -> ListenEndpoint:
        # listen address[:port] [default_server] [ssl] ...;  (nginx.org,
        # ngx_http_core_module `listen`) - this project only extracts
        # address, port, ssl, default_server; every other listen
        # parameter (backlog=, reuseport, so_keepalive=, etc.) is
        # deliberately not modeled, per this module's stated non-goal of
        # reproducing the full listen grammar.
        order = self._next_order()
        if not args:
            return ListenEndpoint(address='*', port=80, ssl=False,
                                   default_server=False, order=order)

        target = args[0]
        flags = set(args[1:])
        ssl = 'ssl' in flags
        default_server = 'default_server' in flags or 'default' in flags

        if target.startswith('unix:'):
            return ListenEndpoint(address=target, port=None, ssl=ssl,
                                   default_server=default_server, order=order)

        # IPv6 form: [addr]:port or [addr]
        if target.startswith('['):
            close = target.find(']')
            addr = target[:close + 1] if close != -1 else target
            rest = target[close + 1:] if close != -1 else ''
            port = int(rest[1:]) if rest.startswith(':') and rest[1:].isdigit() else 80
            return ListenEndpoint(address=normalize_listen_address(addr), port=port,
                                   ssl=ssl, default_server=default_server, order=order)

        # IPv4 / hostname / bare port forms: addr:port | addr | port
        if ':' in target:
            addr, _, port_s = target.rpartition(':')
            port = int(port_s) if port_s.isdigit() else 80
            return ListenEndpoint(address=normalize_listen_address(addr), port=port,
                                   ssl=ssl, default_server=default_server, order=order)
        if target.isdigit():
            return ListenEndpoint(address=normalize_listen_address(None), port=int(target),
                                   ssl=ssl, default_server=default_server, order=order)
        # Address only, no port -> nginx defaults to port 80 (nginx.org:
        # "If only address is given, the port 80 is used.")
        return ListenEndpoint(address=normalize_listen_address(target), port=80,
                               ssl=ssl, default_server=default_server, order=order)

    def _parse_server(self) -> ServerBlock:
        order = self._next_order()
        directives, add_headers, _nested_servers, locations = self.parse_block()

        listens = [self._parse_listen(a.split()) for a in directives.pop('listen', [])]
        server_names: list[str] = []
        for raw in directives.pop('server_name', []):
            server_names.extend(raw.split())

        return ServerBlock(order=order, server_names=server_names, listens=listens,
                            directives=directives, add_headers=add_headers,
                            locations=locations)

    def _parse_location(self, args: list[str]) -> LocationBlock:
        order = self._next_order()
        if len(args) >= 2 and args[0] in ('=', '^~', '~', '~*'):
            modifier, path = args[0], args[1]
        elif args:
            modifier, path = None, args[0]
        else:
            modifier, path = None, ''

        directives, add_headers, _servers, _locations = self.parse_block()
        return LocationBlock(modifier=modifier, path=path, directives=directives,
                              add_headers=add_headers, order=order)


def parse_nginx_config_v2(conf: str) -> NginxConfigV2:
    """Pure parsing, no I/O - takes the same raw `nginx -T` text the
    legacy `_parse_nginx_config()` (nginx_config.py) does, and builds the
    structured NginxConfigV2 instead of the legacy flat NginxConfig.
    Split out from any SSH-collection wrapper so it can be unit-tested
    against fixture text directly (same pattern as
    nginx_config.py/_parse_nginx_config).

    Walks the whole token stream via _BlockParser.parse_top_level_stream()
    rather than isolating one `http { ... }` block first, because
    `nginx -T` prints `include`d files' contents (e.g. every real vhost
    under sites-enabled/) as separate sections *after* the closing `}` of
    `http {}`, not textually nested inside it - see
    parse_top_level_stream()'s docstring for the full rationale and the
    real-VM evidence behind this.
    """
    active = _strip_comments(conf)
    tokens = _tokenize(active)
    parser = _BlockParser(tokens)
    http_directives, http_add_headers, servers = parser.parse_top_level_stream()

    return NginxConfigV2(installed=True, readable=True,
                          http_directives=http_directives,
                          http_add_headers=http_add_headers,
                          servers=servers)


def collect_nginx_config_v2(ssh: SSHExecutor) -> NginxConfigV2:
    """Run `nginx -T` over the given (already-connected) SSH session and
    parse the output into a NginxConfigV2. Mirrors
    nginx_config.py/collect_nginx_config() deliberately - same `which
    nginx` install check, same `ssh.sudo()` (not `ssh.run()`) for the
    same reason documented there (server{}/location{} source files often
    aren't world-readable), same installed/readable state handling.

    This is a SEPARATE `nginx -T` invocation from
    collect_nginx_config()'s - two SSH round-trips per full
    nginx_hardening audit run instead of one. This is a known, accepted
    v1 tradeoff (docs/checks/nginx_hardening.md section 7's Tier-2
    planning: "Два nginx -T... Принимаем как известный временный
    trade-off v1... Оптимизацию shared collection не смешиваем с
    текущей задачей"), not an oversight - a shared-collection refactor
    (parsing both NginxConfig and NginxConfigV2 from one captured
    `nginx -T` output) is explicitly deferred, so this function does not
    attempt it.

    `ssh.sudo()`'s passwordless-sudo check is cached after the first
    call (see ssh.py's SSHExecutor.sudo()), so calling this after
    collect_nginx_config() on the same SSHExecutor does not repeat that
    particular sub-cost, even though the `nginx -T` command itself still
    runs twice.
    """
    out, _ = ssh.run('which nginx || echo NONE')
    if 'NONE' in out:
        return NginxConfigV2(installed=False)

    conf, _ = ssh.sudo('nginx -T 2>/dev/null')
    if not conf:
        return NginxConfigV2(installed=True, readable=False)

    return parse_nginx_config_v2(conf)
