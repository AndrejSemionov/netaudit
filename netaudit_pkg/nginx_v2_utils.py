"""
Shared lexical/parsing helpers for the nginx_config_v2 / nginx_v2_resolvers
pair. Pure functions only - no I/O, no security judgment, no knowledge of
any NGX-* control's PASS/FAIL semantics.

This module exists so a lexical fact (say, "does this value contain an
nginx variable reference") is decided in exactly one place. Every Tier-2
resolver (TLS-004, CONF-003, HDR-004/005/006) independently needs that
same fact - without a shared helper each would grow its own slightly
different `'$' in value` check, and the day one of them needs to also
treat `\\$` (escaped dollar, not a variable) as non-variable, only one of
five copies would get fixed.

Split from `nginx_v2_resolvers.py` deliberately: resolvers decide
`explicit / inherited / nginx-default` provenance and hand that off to a
control; this module never sees provenance, only raw directive value
strings. Split from `nginx_config_v2.py` (the parser) because these
helpers are used both while parsing (`listen` address normalization) and
later while resolving effective values (`has_nginx_variable`,
`parse_nginx_size`) - putting them in the parser file would blur the
"parser produces a raw structural model, resolver adds semantics" line
this Tier-2 effort is built on (docs/checks/nginx_hardening.md).
"""

from __future__ import annotations

import re

# nginx variable reference: $name or ${name}. Deliberately permissive on
# `name` (nginx allows letters, digits, underscore) - this helper only
# needs to detect *that* a variable is present, not validate the name is
# one nginx actually defines. A false-positive here (flagging a literal
# '$' that isn't actually a variable, e.g. inside a quoted string nginx
# itself wouldn't interpret) is safe: the caller's fallback for "contains
# a variable" is UNKNOWN, never FAIL, so over-detecting costs precision,
# not correctness. Under-detecting would be worse (a real variable
# silently treated as a literal), so this stays intentionally broad.
#
# Escaping semantics (nginx's own `\$` to emit a literal dollar sign) are
# intentionally out of scope for v1 - this helper performs lexical
# detection only and does not distinguish an escaped dollar from a real
# variable reference. A config using `\$` for a literal dollar sign would
# be over-detected as containing a variable (-> UNKNOWN, not FAIL), which
# is the safe direction per the paragraph above.
_VARIABLE_RE = re.compile(r'\$\{?[a-zA-Z_][a-zA-Z0-9_]*\}?')

# nginx size suffixes, case-insensitive: k/K = kilobytes (1024), m/M =
# megabytes (1024^2), g/G = gigabytes (1024^3). No suffix = bytes. This is
# the same suffix syntax nginx uses throughout ngx_http_core_module
# (client_max_body_size, client_body_buffer_size, etc.) - not something
# specific to any one directive, which is why it lives here rather than
# inside a CONF-003-specific resolver.
_SIZE_RE = re.compile(r'^(\d+)([kKmMgG]?)$')
_SIZE_MULTIPLIERS = {'': 1, 'k': 1024, 'm': 1024 ** 2, 'g': 1024 ** 3}


def has_nginx_variable(value: str) -> bool:
    """True if `value` contains an nginx variable reference ($name or
    ${name}). Purely lexical - does not know whether the variable exists,
    what it resolves to at request time, or whether that matters for any
    particular control. Callers (resolvers) are the ones that decide a
    variable reference means "cannot prove this statically -> UNKNOWN";
    this function only supplies the underlying fact.
    """
    return bool(_VARIABLE_RE.search(value))


def parse_nginx_size(value: str) -> int | None:
    """Parse an nginx size literal (e.g. '50m', '0', '1024') into a byte
    count. Returns None if `value` is not a literal size this function
    can parse - notably, this includes values containing an nginx
    variable (parse_nginx_size('$my_limit') -> None), which is not an
    error: the caller (a resolver) is expected to check
    has_nginx_variable() first and route to UNKNOWN before ever calling
    this, or to treat a None return as "not a literal, don't guess" as a
    matter of course - this function never raises or fails loudly, it
    just declines to produce a number.

    `0` parses to `0` (not None) - nginx's own documented meaning for
    `client_max_body_size 0;` is "disable the size check", which is a
    real, valid literal value, not an absence of one. What that `0`
    means as security policy (FAIL, per NGX-CONF-003 - see
    docs/checks/nginx_hardening.md) is for the resolver/control to
    decide, not this function.
    """
    m = _SIZE_RE.match(value.strip())
    if not m:
        return None
    digits, suffix = m.groups()
    return int(digits) * _SIZE_MULTIPLIERS[suffix.lower()]


def normalize_listen_address(raw_address: str | None) -> str:
    """Normalize the address portion of an already-parsed `listen`
    directive to a canonical string suitable as an `address:port` group
    key (ListenEndpoint.group_key). This function does not parse the raw
    `listen` directive text itself - that is NginxParser's job (splitting
    `listen 80;` into address=None, port=80, or `listen *:8000;` into
    address='*', port=8000). This function only normalizes the address
    component the parser has already extracted, so `raw_address=None`
    here means "the parser found no address token in this listen
    directive", not "figure out nginx's listen syntax."

    `raw_address=None` (parser saw `listen 80;` with no address) and
    `raw_address='*'` (parser saw `listen *:80;` explicitly) both mean
    "all IPv4 addresses" per ngx_http_core_module's `listen` directive -
    nginx.org: "If only address is given, the port 80 is used... If the
    directive is not present then either *:80 is used if nginx runs with
    the superuser privileges, or *:8000 otherwise." Both normalize to '*'
    here so they group together under the same address:port key.

    `[::]` (IPv6 wildcard) is deliberately NOT collapsed into '*' - it is
    a distinct socket from the IPv4 wildcard, and nginx's own `ipv6only`
    handling (on by default per nginx.org) means listen 80 (IPv4-only)
    and listen [::]:80 (IPv6, and by default IPv6-only) are two separate
    address:port groups, not one. Collapsing them would silently merge
    two different listen groups into a false default_server ambiguity
    for NGX-EXP-003, or a false NGX-EXP-002 pairing across the wrong
    socket - exactly the kind of false-positive this project's
    methodology rejects (see docs/checks/nginx_hardening.md section 7).

    Any other literal address (a concrete IPv4/IPv6 address, a hostname)
    is returned unchanged; lowercasing is NOT applied (nginx addresses
    are not case-sensitive in practice, but this function does not
    attempt to resolve hostnames or normalize case - a config using
    inconsistent case is an edge case this v1 helper does not claim to
    solve).

    UNIX-domain sockets (`listen unix:/path;`) are out of scope for this
    function entirely - they have no address:port pair at all, and
    ListenEndpoint/NginxParser are expected to represent them distinctly
    rather than pass a fabricated address through here.
    """
    if raw_address is None or raw_address == '' or raw_address == '*':
        return '*'
    return raw_address
