"""
Tests for netaudit_pkg.nginx_v2_resolvers: effective-value resolution
(cascading and add_header's all-or-nothing model), default_server
ambiguity grouping, and HTTP/HTTPS server_name pairing — the semantic
layer between NginxConfigV2 (nginx_config_v2.py, structural parsing only)
and the seven Tier-2 controls (docs/checks/nginx_hardening.md section 7).
"""

from __future__ import annotations

from netaudit_pkg.nginx_config_v2 import parse_nginx_config_v2
from netaudit_pkg.nginx_v2_resolvers import (
    find_effective_header,
    find_https_pair,
    is_https_redirect_target,
    resolve_add_headers,
    resolve_cascading_value,
    resolve_listen_groups,
)


# ===========================================================================
# resolve_cascading_value() — ssl_ciphers / client_max_body_size model
# ===========================================================================

def test_cascading_explicit_at_location_wins_over_server():
    conf = '''
    http {
        server {
            client_max_body_size 50m;
            location /upload {
                client_max_body_size 0;
            }
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    server = cfg.servers[0]
    loc = server.locations[0]
    ev = resolve_cascading_value(
        'client_max_body_size', '1m',
        http_directives=cfg.http_directives,
        server_directives=server.directives,
        location_directives=loc.directives,
    )
    assert ev.value == '0'
    assert ev.level == 'location'
    assert ev.explicit is True
    assert ev.source == 'explicit'


def test_cascading_falls_through_to_server_when_location_silent():
    conf = '''
    http {
        server {
            client_max_body_size 50m;
            location / { }
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    server = cfg.servers[0]
    loc = server.locations[0]
    ev = resolve_cascading_value(
        'client_max_body_size', '1m',
        http_directives=cfg.http_directives,
        server_directives=server.directives,
        location_directives=loc.directives,
    )
    assert ev.value == '50m'
    assert ev.level == 'server'


def test_cascading_falls_through_to_http_when_server_silent():
    conf = 'http { client_max_body_size 20m; server { } }'
    cfg = parse_nginx_config_v2(conf)
    server = cfg.servers[0]
    ev = resolve_cascading_value(
        'client_max_body_size', '1m',
        http_directives=cfg.http_directives,
        server_directives=server.directives,
    )
    assert ev.value == '20m'
    assert ev.level == 'http'


def test_cascading_falls_through_to_nginx_default_when_absent_everywhere():
    cfg = parse_nginx_config_v2('http { server { } }')
    server = cfg.servers[0]
    ev = resolve_cascading_value(
        'client_max_body_size', '1m',
        http_directives=cfg.http_directives,
        server_directives=server.directives,
    )
    assert ev.value == '1m'
    assert ev.source == 'nginx-default'
    assert ev.level == 'default'
    assert ev.explicit is False


def test_cascading_zero_is_explicit_not_absent():
    # nginx.org: "Setting size to 0 disables checking..." — 0 is a real
    # literal value, distinct from the directive being absent.
    cfg = parse_nginx_config_v2('http { server { client_max_body_size 0; } }')
    server = cfg.servers[0]
    ev = resolve_cascading_value(
        'client_max_body_size', '1m',
        http_directives=cfg.http_directives,
        server_directives=server.directives,
    )
    assert ev.value == '0'
    assert ev.explicit is True
    assert ev.source == 'explicit'


def test_cascading_no_directive_and_no_default_is_absent():
    cfg = parse_nginx_config_v2('http { server { } }')
    server = cfg.servers[0]
    ev = resolve_cascading_value(
        'ssl_ciphers', None,
        http_directives=cfg.http_directives,
        server_directives=server.directives,
    )
    assert ev.value is None
    assert ev.source == 'absent'
    assert ev.explicit is False


def test_cascading_flags_variable_in_value():
    cfg = parse_nginx_config_v2('http { server { client_max_body_size $limit; } }')
    server = cfg.servers[0]
    ev = resolve_cascading_value(
        'client_max_body_size', '1m',
        http_directives=cfg.http_directives,
        server_directives=server.directives,
    )
    assert ev.has_variable is True


def test_cascading_no_variable_in_literal_value():
    cfg = parse_nginx_config_v2('http { server { client_max_body_size 50m; } }')
    server = cfg.servers[0]
    ev = resolve_cascading_value(
        'client_max_body_size', '1m',
        http_directives=cfg.http_directives,
        server_directives=server.directives,
    )
    assert ev.has_variable is False


def test_cascading_vm_baseline_client_max_body_size_is_nginx_default():
    # Regression anchor: real VM config never sets client_max_body_size
    # anywhere, so effective value must resolve to nginx's own 1m
    # default, not error or return None.
    conf = '''
    http {
        server {
            listen 80;
            server_name 192.168.88.20;
            location / {
                proxy_pass http://127.0.0.1:8000;
            }
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    server = cfg.servers[0]
    loc = server.locations[0]
    ev = resolve_cascading_value(
        'client_max_body_size', '1m',
        http_directives=cfg.http_directives,
        server_directives=server.directives,
        location_directives=loc.directives,
    )
    assert ev.value == '1m'
    assert ev.source == 'nginx-default'


# ===========================================================================
# resolve_add_headers() — all-or-nothing per level
# ===========================================================================

def test_add_header_location_own_set_blocks_inheritance():
    conf = '''
    http {
        add_header X-Frame-Options DENY always;
        server {
            add_header Referrer-Policy no-referrer;
            location /api {
                add_header X-Custom test;
            }
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    server = cfg.servers[0]
    loc = server.locations[0]
    effective = resolve_add_headers(
        http_add_headers=cfg.http_add_headers,
        server_add_headers=server.add_headers,
        location_add_headers=loc.add_headers,
    )
    names = {h.name for h in effective}
    assert names == {'X-Custom'}


def test_add_header_location_silent_inherits_server_set():
    conf = '''
    http {
        add_header X-Frame-Options DENY always;
        server {
            add_header Referrer-Policy no-referrer;
            location / { }
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    server = cfg.servers[0]
    loc = server.locations[0]
    effective = resolve_add_headers(
        http_add_headers=cfg.http_add_headers,
        server_add_headers=server.add_headers,
        location_add_headers=loc.add_headers,
    )
    names = {h.name for h in effective}
    assert names == {'Referrer-Policy'}


def test_add_header_server_silent_inherits_http_set():
    conf = '''
    http {
        add_header X-Frame-Options DENY always;
        server { }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    server = cfg.servers[0]
    effective = resolve_add_headers(
        http_add_headers=cfg.http_add_headers,
        server_add_headers=server.add_headers,
    )
    names = {h.name for h in effective}
    assert names == {'X-Frame-Options'}


def test_add_header_server_own_set_blocks_http_inheritance_entirely():
    # Critical case: server defines ITS OWN add_header for a DIFFERENT
    # header than http's — http's X-Frame-Options must NOT survive, per
    # the all-or-nothing rule (not per-name inheritance).
    conf = '''
    http {
        add_header X-Frame-Options DENY always;
        server {
            add_header Content-Security-Policy "default-src 'self'";
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    server = cfg.servers[0]
    effective = resolve_add_headers(
        http_add_headers=cfg.http_add_headers,
        server_add_headers=server.add_headers,
    )
    names = {h.name for h in effective}
    assert names == {'Content-Security-Policy'}
    assert 'X-Frame-Options' not in names


def test_find_effective_header_present():
    conf = 'http { add_header X-Frame-Options DENY always; server { } }'
    cfg = parse_nginx_config_v2(conf)
    server = cfg.servers[0]
    effective = resolve_add_headers(
        http_add_headers=cfg.http_add_headers,
        server_add_headers=server.add_headers,
    )
    header = find_effective_header('x-frame-options', effective)  # case-insensitive
    assert header is not None
    assert header.value == 'DENY'


def test_find_effective_header_absent():
    conf = 'http { server { } }'
    cfg = parse_nginx_config_v2(conf)
    server = cfg.servers[0]
    effective = resolve_add_headers(
        http_add_headers=cfg.http_add_headers,
        server_add_headers=server.add_headers,
    )
    assert find_effective_header('Content-Security-Policy', effective) is None


def test_vm_baseline_no_add_headers_anywhere_resolves_empty():
    conf = '''
    http {
        server {
            listen 80;
            server_name 192.168.88.20;
            location / {
                proxy_pass http://127.0.0.1:8000;
            }
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    server = cfg.servers[0]
    loc = server.locations[0]
    effective = resolve_add_headers(
        http_add_headers=cfg.http_add_headers,
        server_add_headers=server.add_headers,
        location_add_headers=loc.add_headers,
    )
    assert effective == []


# ===========================================================================
# resolve_listen_groups() — NGX-EXP-003 default_server ambiguity
# ===========================================================================

def test_listen_group_single_member_never_ambiguous():
    cfg = parse_nginx_config_v2('http { server { listen 80; } }')
    groups = resolve_listen_groups(cfg.servers)
    assert len(groups) == 1
    assert groups[0].ambiguous is False
    assert len(groups[0].members) == 1


def test_listen_group_multiple_members_explicit_default_not_ambiguous():
    conf = '''
    http {
        server { listen 80 default_server; server_name a.com; }
        server { listen 80; server_name b.com; }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    groups = resolve_listen_groups(cfg.servers)
    assert len(groups) == 1
    g = groups[0]
    assert g.ambiguous is False
    assert g.effective_default[0].server_names == ['a.com']


def test_listen_group_multiple_members_no_explicit_default_is_ambiguous():
    conf = '''
    http {
        server { listen 80; server_name first.com; }
        server { listen 80; server_name second.com; }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    groups = resolve_listen_groups(cfg.servers)
    g = groups[0]
    assert g.ambiguous is True
    # Implicit default is the first server by nginx -T / config order,
    # per nginx.org: "the first server with the address:port pair will
    # be the default server for this pair."
    assert g.effective_default[0].server_names == ['first.com']


def test_listen_group_ipv4_and_ipv6_wildcards_are_separate_groups():
    conf = '''
    http {
        server {
            listen 80;
            listen [::]:80;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    groups = resolve_listen_groups(cfg.servers)
    keys = {g.group_key for g in groups}
    assert ('*', 80) in keys
    assert ('[::]', 80) in keys
    assert len(groups) == 2


def test_listen_group_different_ports_are_separate_groups():
    conf = '''
    http {
        server { listen 80; }
        server { listen 443 ssl; }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    groups = resolve_listen_groups(cfg.servers)
    assert len(groups) == 2
    for g in groups:
        assert g.ambiguous is False  # each group has exactly 1 member


def test_listen_group_unix_socket_never_collides_with_ip_listen():
    conf = '''
    http {
        server { listen unix:/var/run/nginx.sock; }
        server { listen 80; }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    groups = resolve_listen_groups(cfg.servers)
    assert len(groups) == 2
    for g in groups:
        assert g.ambiguous is False


# ===========================================================================
# find_https_pair() / is_https_redirect_target() — NGX-EXP-002
# ===========================================================================

HTTP_HTTPS_PAIR_CONF = '''
http {
    server {
        listen 80;
        server_name example.com www.example.com;
        return 301 https://$host$request_uri;
    }
    server {
        listen 443 ssl;
        server_name example.com www.example.com;
    }
}
'''


def test_find_https_pair_exact_match_found():
    cfg = parse_nginx_config_v2(HTTP_HTTPS_PAIR_CONF)
    http_server, https_server = cfg.servers
    result = find_https_pair(http_server, cfg.servers)
    assert result.reason == 'paired'
    assert result.https_server is https_server


def test_find_https_pair_partial_name_overlap_still_pairs():
    conf = '''
    http {
        server {
            listen 80;
            server_name example.com other.com;
        }
        server {
            listen 443 ssl;
            server_name example.com different.com;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    http_server, https_server = cfg.servers
    result = find_https_pair(http_server, cfg.servers)
    assert result.reason == 'paired'
    assert result.https_server is https_server


def test_find_https_pair_no_https_server_anywhere():
    conf = 'http { server { listen 80; server_name a.com; } }'
    cfg = parse_nginx_config_v2(conf)
    http_server = cfg.servers[0]
    result = find_https_pair(http_server, cfg.servers)
    assert result.reason == 'no_https_endpoint'
    assert result.https_server is None


def test_find_https_pair_no_overlapping_name_is_unpaired():
    conf = '''
    http {
        server { listen 80; server_name a.com; }
        server { listen 443 ssl; server_name b.com; }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    http_server = cfg.servers[0]
    result = find_https_pair(http_server, cfg.servers)
    assert result.reason == 'no_https_endpoint'


def test_find_https_pair_wildcard_http_name_is_unknown():
    conf = '''
    http {
        server { listen 80; server_name *.example.com; }
        server { listen 443 ssl; server_name *.example.com; }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    http_server = cfg.servers[0]
    result = find_https_pair(http_server, cfg.servers)
    assert result.reason == 'wildcard_or_regex_name'
    assert result.https_server is None


def test_find_https_pair_regex_http_name_is_unknown():
    conf = r'''
    http {
        server { listen 80; server_name ~^www\d+\.example\.com$; }
        server { listen 443 ssl; server_name example.com; }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    http_server = cfg.servers[0]
    result = find_https_pair(http_server, cfg.servers)
    assert result.reason == 'wildcard_or_regex_name'


def test_find_https_pair_wildcard_https_candidate_is_skipped():
    # HTTP side is exact, but the only HTTPS candidate uses a wildcard —
    # this project doesn't implement wildcard matching, so no pairing.
    conf = '''
    http {
        server { listen 80; server_name example.com; }
        server { listen 443 ssl; server_name *.example.com; }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    http_server = cfg.servers[0]
    result = find_https_pair(http_server, cfg.servers)
    assert result.reason == 'no_https_endpoint'


def test_vm_baseline_http_only_server_has_no_https_pair():
    # Regression anchor: the real VM config is HTTP-only, TLS block
    # entirely commented out. This must resolve to 'no_https_endpoint'
    # (UNKNOWN-worthy), not a crash and not a false pairing.
    conf = '''
    http {
        server {
            listen 80;
            server_name 192.168.88.20;
            location / {
                proxy_pass http://127.0.0.1:8000;
            }
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    result = find_https_pair(cfg.servers[0], cfg.servers)
    assert result.reason == 'no_https_endpoint'
    assert result.https_server is None


def test_is_https_redirect_target_literal_https_prefix():
    assert is_https_redirect_target('https://$host$request_uri') is True


def test_is_https_redirect_target_literal_https_no_variables():
    assert is_https_redirect_target('https://example.com/path') is True


def test_is_https_redirect_target_scheme_variable_prefix():
    assert is_https_redirect_target('$scheme://$host$request_uri') is False


def test_is_https_redirect_target_plain_http():
    assert is_https_redirect_target('http://example.com') is False


def test_is_https_redirect_target_relative_path():
    assert is_https_redirect_target('/some/path') is False
