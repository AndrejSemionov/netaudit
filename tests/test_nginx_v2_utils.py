"""
Tests for netaudit_pkg.nginx_v2_utils: shared lexical helpers used by both
the NginxConfigV2 parser and the Tier-2 resolvers (nginx_v2_resolvers.py).
Pure functions, no I/O - see nginx_v2_utils.py's module docstring for why
these live separately from both the parser and the resolvers.
"""

from __future__ import annotations

from netaudit_pkg.nginx_v2_utils import (
    has_nginx_variable,
    normalize_listen_address,
    parse_nginx_size,
)


# ===========================================================================
# has_nginx_variable()
# ===========================================================================

def test_has_nginx_variable_simple():
    assert has_nginx_variable('https://$host$request_uri') is True


def test_has_nginx_variable_braced():
    assert has_nginx_variable('${scheme}://example.com') is True


def test_has_nginx_variable_absent():
    assert has_nginx_variable('https://example.com/path') is False


def test_has_nginx_variable_no_dollar_at_all():
    assert has_nginx_variable('HIGH:!aNULL:!MD5') is False


def test_has_nginx_variable_scheme_prefix():
    # NGX-EXP-002: this is exactly the "cannot prove HTTPS statically"
    # case (docs/checks/nginx_hardening.md Tier-2 planning) - $scheme
    # resolves at request time, not from config alone.
    assert has_nginx_variable('$scheme://$host$request_uri') is True


def test_has_nginx_variable_literal_https_prefix_with_vars_after():
    # Still True - the variable is present even though the protocol
    # itself is a literal. Distinguishing "literal protocol, variable
    # path" from "variable protocol" is the resolver's job, not this
    # function's; this only reports presence.
    assert has_nginx_variable('https://$host$request_uri') is True


# ===========================================================================
# parse_nginx_size()
# ===========================================================================

def test_parse_nginx_size_bytes_no_suffix():
    assert parse_nginx_size('1024') == 1024


def test_parse_nginx_size_kilobytes():
    assert parse_nginx_size('10k') == 10 * 1024


def test_parse_nginx_size_kilobytes_uppercase():
    assert parse_nginx_size('10K') == 10 * 1024


def test_parse_nginx_size_megabytes():
    assert parse_nginx_size('50m') == 50 * 1024 ** 2


def test_parse_nginx_size_megabytes_uppercase():
    assert parse_nginx_size('50M') == 50 * 1024 ** 2


def test_parse_nginx_size_gigabytes():
    assert parse_nginx_size('2g') == 2 * 1024 ** 3


def test_parse_nginx_size_zero_is_a_valid_literal():
    # nginx.org: "Setting size to 0 disables checking of client request
    # body size." This is a real, parseable value - 0, not None. What it
    # means for NGX-CONF-003 (FAIL) is the resolver/control's decision,
    # not this function's.
    assert parse_nginx_size('0') == 0


def test_parse_nginx_size_variable_is_unparseable():
    assert parse_nginx_size('$my_limit') is None


def test_parse_nginx_size_garbage_is_unparseable():
    assert parse_nginx_size('not_a_size') is None


def test_parse_nginx_size_empty_string_is_unparseable():
    assert parse_nginx_size('') is None


def test_parse_nginx_size_strips_whitespace():
    assert parse_nginx_size('  50m  ') == 50 * 1024 ** 2


# ===========================================================================
# normalize_listen_address()
# ===========================================================================

def test_normalize_listen_address_none_becomes_wildcard():
    # `listen 80;` with no address at all - nginx.org: "If the directive
    # is not present then either *:80 is used..."
    assert normalize_listen_address(None) == '*'


def test_normalize_listen_address_empty_becomes_wildcard():
    assert normalize_listen_address('') == '*'


def test_normalize_listen_address_explicit_wildcard_stays_wildcard():
    assert normalize_listen_address('*') == '*'


def test_normalize_listen_address_ipv6_wildcard_not_collapsed():
    # Deliberately distinct from '*' (IPv4 wildcard) - see
    # nginx_v2_utils.py docstring for why merging these would create a
    # false EXP-003 ambiguity or a false EXP-002 pairing.
    assert normalize_listen_address('[::]') == '[::]'


def test_normalize_listen_address_concrete_ip_unchanged():
    assert normalize_listen_address('192.168.88.20') == '192.168.88.20'


def test_normalize_listen_address_localhost_unchanged():
    assert normalize_listen_address('127.0.0.1') == '127.0.0.1'
