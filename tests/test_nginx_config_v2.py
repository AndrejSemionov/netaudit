"""
Tests for netaudit_pkg.nginx_config_v2: the structured, per-server-block
`nginx -T` parser built for Tier-2 controls (NGX-TLS-004, NGX-HDR-004/
005/006, NGX-CONF-003, NGX-EXP-002/003 - see
docs/checks/nginx_hardening.md section 7). Pure parsing tests only - no
security judgment, no effective-value resolution (that's
nginx_v2_resolvers.py's territory, tested separately).
"""

from __future__ import annotations

from netaudit_pkg.nginx_config_v2 import (
    AddHeader,
    parse_nginx_config_v2,
)


# ===========================================================================
# Real VM baseline (docs/checks/nginx_hardening.md Milestone 1 capture) —
# the regression anchor. This exact text is what `sudo nginx -T` produced
# on the project's own VM (192.168.88.20, nginx/1.28.3): a single HTTP-only
# vhost sourced from /etc/nginx/sites-enabled/, no TLS.
# ===========================================================================

VM_BASELINE_CONF = '''
# configuration file /etc/nginx/nginx.conf:
user www-data;
worker_processes auto;
worker_cpu_affinity auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
include /etc/nginx/modules-enabled/*.conf;

events {
	worker_connections 768;
	# multi_accept on;
}

http {

	##
	# Basic Settings
	##

	sendfile on;
	tcp_nopush on;
	types_hash_max_size 2048;
	server_tokens build; # Recommended practice is to turn this off

	include /etc/nginx/mime.types;
	default_type application/octet-stream;

	##
	# SSL Settings
	##

	ssl_protocols TLSv1.2 TLSv1.3; # Dropping SSLv3 (POODLE), TLS 1.0, 1.1
	ssl_prefer_server_ciphers off; # Don't force server cipher order.

	access_log /var/log/nginx/access.log;

	gzip on;

	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}

# configuration file /etc/nginx/mime.types:
types {
    text/html html;
    text/css css;
}

# configuration file /etc/nginx/sites-enabled/netaudit:
server {
    listen 80;
    server_name 192.168.88.20;

    # listen 443 ssl;
    # ssl_certificate     /etc/letsencrypt/live/192.168.88.20/fullchain.pem;

    auth_basic "NetAudit";
    auth_basic_user_file /etc/nginx/.netaudit_htpasswd;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 3600s;
        proxy_connect_timeout 75s;
        proxy_buffering off;
        proxy_cache off;
        proxy_set_header Connection '';
        proxy_http_version 1.1;
    }
}
'''


def test_vm_baseline_finds_the_one_server_block():
    # This is the regression case that caught the "http{} closes before
    # nginx -T prints included sites-enabled/ sections" bug during
    # Milestone 2 development - a naive brace-nesting-only parser found
    # zero servers here.
    cfg = parse_nginx_config_v2(VM_BASELINE_CONF)
    assert len(cfg.servers) == 1


def test_vm_baseline_server_name():
    cfg = parse_nginx_config_v2(VM_BASELINE_CONF)
    assert cfg.servers[0].server_names == ['192.168.88.20']


def test_vm_baseline_listen_is_http_only_no_ssl():
    cfg = parse_nginx_config_v2(VM_BASELINE_CONF)
    listens = cfg.servers[0].listens
    assert len(listens) == 1
    assert listens[0].ssl is False
    assert listens[0].port == 80
    assert listens[0].address == '*'


def test_vm_baseline_commented_listen_443_not_parsed():
    # The commented-out `# listen 443 ssl;` must not produce a second
    # ListenEndpoint - this is the exact class of bug _strip_comments()
    # exists to prevent (see nginx_config.py's _strip_comments()
    # docstring for the original finding on a live VM).
    cfg = parse_nginx_config_v2(VM_BASELINE_CONF)
    assert len(cfg.servers[0].listens) == 1


def test_vm_baseline_http_level_directives_present():
    cfg = parse_nginx_config_v2(VM_BASELINE_CONF)
    assert cfg.http_directives['server_tokens'] == ['build']
    assert cfg.http_directives['ssl_prefer_server_ciphers'] == ['off']


def test_vm_baseline_location_proxy_pass():
    cfg = parse_nginx_config_v2(VM_BASELINE_CONF)
    loc = cfg.servers[0].locations[0]
    assert loc.path == '/'
    assert loc.modifier is None
    assert loc.directives['proxy_pass'] == ['http://127.0.0.1:8000']


def test_vm_baseline_no_add_headers_anywhere():
    # Confirmed in Milestone 1: this real config has zero add_header
    # directives anywhere (http, server, or location level).
    cfg = parse_nginx_config_v2(VM_BASELINE_CONF)
    assert cfg.http_add_headers == []
    assert cfg.servers[0].add_headers == []
    assert cfg.servers[0].locations[0].add_headers == []


# ===========================================================================
# Comment stripping — quote-aware, same class of bug as nginx_config.py
# ===========================================================================

def test_comment_after_directive_is_stripped():
    conf = 'http { server { listen 80; server_name a.com; # this is a comment\\n } }'
    cfg = parse_nginx_config_v2(conf)
    assert cfg.servers[0].server_names == ['a.com']


def test_hash_inside_quoted_string_is_not_a_comment():
    conf = 'http { server { listen 80; add_header X-Custom "a#b"; } }'
    cfg = parse_nginx_config_v2(conf)
    assert cfg.servers[0].add_headers[0].value == 'a#b'


def test_fully_commented_directive_is_not_parsed():
    conf = 'http { server { listen 80; # server_name commented.example.com;\\n } }'
    cfg = parse_nginx_config_v2(conf)
    assert cfg.servers[0].server_names == []


# ===========================================================================
# Multiple server blocks, listen forms, default_server, IPv6
# ===========================================================================

MULTI_SERVER_CONF = '''
http {
    add_header X-Frame-Options DENY always;

    server {
        listen 80;
        listen 443 ssl;
        server_name a.example.com;
        ssl_ciphers HIGH:!aNULL:!MD5;
        client_max_body_size 50m;

        add_header Content-Security-Policy "default-src 'self'";

        location / {
            client_max_body_size 0;
        }
    }

    server {
        listen 80 default_server;
        listen [::]:80;
        server_name b.example.com;
        return 301 https://$host$request_uri;
    }
}
'''


def test_multi_server_finds_both_servers():
    cfg = parse_nginx_config_v2(MULTI_SERVER_CONF)
    assert len(cfg.servers) == 2


def test_multi_server_order_is_sequential():
    cfg = parse_nginx_config_v2(MULTI_SERVER_CONF)
    assert cfg.servers[0].order < cfg.servers[1].order


def test_multi_server_first_server_has_two_listens():
    cfg = parse_nginx_config_v2(MULTI_SERVER_CONF)
    listens = cfg.servers[0].listens
    assert len(listens) == 2
    assert listens[0].ssl is False and listens[0].port == 80
    assert listens[1].ssl is True and listens[1].port == 443


def test_multi_server_explicit_default_server_flag():
    cfg = parse_nginx_config_v2(MULTI_SERVER_CONF)
    b_listens = cfg.servers[1].listens
    assert b_listens[0].default_server is True  # listen 80 default_server
    assert b_listens[1].default_server is False  # listen [::]:80


def test_multi_server_ipv6_wildcard_not_collapsed_to_star():
    cfg = parse_nginx_config_v2(MULTI_SERVER_CONF)
    b_listens = cfg.servers[1].listens
    assert b_listens[1].address == '[::]'
    assert b_listens[1].address != '*'


def test_multi_server_ipv4_and_ipv6_are_different_group_keys():
    cfg = parse_nginx_config_v2(MULTI_SERVER_CONF)
    b_listens = cfg.servers[1].listens
    assert b_listens[0].group_key != b_listens[1].group_key


def test_multi_server_http_level_add_header_inherited_structurally():
    # Parser stores what's literally present at each level; whether the
    # http-level X-Frame-Options is *effectively* inherited by a server
    # that defines its own add_header is nginx_v2_resolvers.py's job,
    # not this parser's. Here we only confirm the http-level AddHeader
    # itself was captured correctly.
    cfg = parse_nginx_config_v2(MULTI_SERVER_CONF)
    assert cfg.http_add_headers == [AddHeader('X-Frame-Options', 'DENY', True)]


def test_multi_server_server_level_add_header_captured():
    cfg = parse_nginx_config_v2(MULTI_SERVER_CONF)
    csp = cfg.servers[0].add_headers[0]
    assert csp.name == 'Content-Security-Policy'
    assert csp.value == "default-src 'self'"
    assert csp.always is False


def test_multi_server_ssl_ciphers_captured_verbatim():
    cfg = parse_nginx_config_v2(MULTI_SERVER_CONF)
    assert cfg.servers[0].directives['ssl_ciphers'] == ['HIGH:!aNULL:!MD5']


def test_multi_server_client_max_body_size_server_vs_location():
    cfg = parse_nginx_config_v2(MULTI_SERVER_CONF)
    server = cfg.servers[0]
    location = server.locations[0]
    assert server.directives['client_max_body_size'] == ['50m']
    assert location.directives['client_max_body_size'] == ['0']


def test_multi_server_return_directive_with_variables_captured_verbatim():
    # Parser does not classify this as PASS/FAIL/UNKNOWN - it only needs
    # to preserve the literal text so the resolver can later check
    # whether the target starts with a literal 'https://' vs a variable
    # like $scheme (see docs/checks/nginx_hardening.md NGX-EXP-002
    # semantics).
    cfg = parse_nginx_config_v2(MULTI_SERVER_CONF)
    assert cfg.servers[1].directives['return'] == ['301 https://$host$request_uri']


# ===========================================================================
# listen normalization forms
# ===========================================================================

def test_listen_bare_port():
    cfg = parse_nginx_config_v2('http { server { listen 8080; } }')
    le = cfg.servers[0].listens[0]
    assert le.address == '*' and le.port == 8080


def test_listen_wildcard_explicit():
    cfg = parse_nginx_config_v2('http { server { listen *:8080; } }')
    le = cfg.servers[0].listens[0]
    assert le.address == '*' and le.port == 8080


def test_listen_concrete_ipv4_with_port():
    cfg = parse_nginx_config_v2('http { server { listen 127.0.0.1:8000; } }')
    le = cfg.servers[0].listens[0]
    assert le.address == '127.0.0.1' and le.port == 8000


def test_listen_address_only_defaults_to_port_80():
    cfg = parse_nginx_config_v2('http { server { listen 127.0.0.1; } }')
    le = cfg.servers[0].listens[0]
    assert le.address == '127.0.0.1' and le.port == 80


def test_listen_ipv6_with_port():
    cfg = parse_nginx_config_v2('http { server { listen [::1]:8000; } }')
    le = cfg.servers[0].listens[0]
    assert le.address == '[::1]' and le.port == 8000


def test_listen_unix_socket():
    cfg = parse_nginx_config_v2('http { server { listen unix:/var/run/nginx.sock; } }')
    le = cfg.servers[0].listens[0]
    assert le.address == 'unix:/var/run/nginx.sock'
    assert le.port is None


def test_listen_unix_socket_group_key_never_collides_with_ip_listen():
    cfg = parse_nginx_config_v2(
        'http { server { listen unix:/var/run/nginx.sock; listen 80; } }'
    )
    listens = cfg.servers[0].listens
    assert listens[0].group_key != listens[1].group_key


# ===========================================================================
# location modifiers (structural only — no selection-algorithm logic)
# ===========================================================================

def test_location_no_modifier():
    cfg = parse_nginx_config_v2('http { server { location /foo { } } }')
    loc = cfg.servers[0].locations[0]
    assert loc.modifier is None and loc.path == '/foo'


def test_location_exact_modifier():
    cfg = parse_nginx_config_v2('http { server { location = /foo { } } }')
    loc = cfg.servers[0].locations[0]
    assert loc.modifier == '=' and loc.path == '/foo'


def test_location_regex_modifier():
    cfg = parse_nginx_config_v2(r'http { server { location ~ \.php$ { } } }')
    loc = cfg.servers[0].locations[0]
    assert loc.modifier == '~'


def test_location_case_insensitive_regex_modifier():
    cfg = parse_nginx_config_v2(r'http { server { location ~* \.php$ { } } }')
    loc = cfg.servers[0].locations[0]
    assert loc.modifier == '~*'


def test_location_prefix_no_regex_modifier():
    cfg = parse_nginx_config_v2('http { server { location ^~ /static/ { } } }')
    loc = cfg.servers[0].locations[0]
    assert loc.modifier == '^~'


# ===========================================================================
# Unknown/unsupported block types are skipped, not fatal
# ===========================================================================

def test_unknown_top_level_block_is_skipped_not_fatal():
    conf = '''
    map $http_upgrade $connection_upgrade {
        default upgrade;
        '' close;
    }
    http {
        server {
            listen 80;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    assert len(cfg.servers) == 1


def test_unknown_nested_block_inside_http_is_skipped():
    conf = '''
    http {
        upstream backend {
            server 127.0.0.1:8000;
        }
        server {
            listen 80;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    assert len(cfg.servers) == 1
    assert cfg.servers[0].listens[0].port == 80
