"""Tests for netaudit_pkg.nginx_log_resolver — the access_log/error_log
cascade resolution contract (project session notes, 2026-08-18). Written
test-first, before implementation, per project methodology: contract
freeze -> test matrix -> tests -> implementation.

Test matrix (agreed, do not reorder/skip):
  1  no directive anywhere -> UNCONFIGURED
  2  http-level only, no server override -> inherited, CONFIGURED,
     source_level='http'
  3  server-level directive present -> CONFIGURED, source_level='server',
     completely replaces http-level (not merged)
  4  server-level access_log off -> DISABLED, source_level='server'
     (explicit override, does NOT fall back to http-level)
  5  http-level off, no server-level directive -> DISABLED,
     source_level='http' (inherited disable, not an override)
  6  multiple destinations at server level -> all of them, in order,
     none from http level
  7  multiple destinations at http level (no server override) -> all
     inherited
  8  error_log follows the identical cascade rule independently of
     access_log (a server can override one and inherit the other)
  9  options string (format name, buffer=, level) is preserved
     separately from path, not concatenated back together
  10 location-level directives are never read by this resolver (v1
     scope boundary)
"""

from __future__ import annotations

from netaudit_pkg.nginx_config_v2 import parse_nginx_config_v2
from netaudit_pkg.nginx_log_resolver import (
    LogDirectiveState,
    resolve_access_log,
    resolve_error_log,
)


# ===========================================================================
# 1. No directive anywhere -> UNCONFIGURED
# ===========================================================================

def test_no_directive_anywhere_is_unconfigured():
    conf = '''
    http {
        server {
            listen 80;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    result = resolve_access_log(cfg, cfg.servers[0])

    assert result.state == LogDirectiveState.UNCONFIGURED
    assert result.destinations == []
    assert result.source_level is None


# ===========================================================================
# 2. http-level only -> inherited
# ===========================================================================

def test_http_level_only_is_inherited():
    conf = '''
    http {
        access_log /var/log/nginx/access.log;
        server {
            listen 80;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    result = resolve_access_log(cfg, cfg.servers[0])

    assert result.state == LogDirectiveState.CONFIGURED
    assert result.source_level == 'http'
    assert len(result.destinations) == 1
    assert result.destinations[0].path == '/var/log/nginx/access.log'
    assert result.destinations[0].options is None


# ===========================================================================
# 3. server-level directive completely replaces http-level (not merged)
# ===========================================================================

def test_server_level_replaces_http_level_completely():
    conf = '''
    http {
        access_log /var/log/nginx/access.log;
        access_log /var/log/nginx/security.log;
        server {
            listen 80;
            access_log /var/log/nginx/site.log combined;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    result = resolve_access_log(cfg, cfg.servers[0])

    assert result.state == LogDirectiveState.CONFIGURED
    assert result.source_level == 'server'
    assert len(result.destinations) == 1
    assert result.destinations[0].path == '/var/log/nginx/site.log'
    assert result.destinations[0].options == 'combined'
    # http-level destinations must NOT leak into the result
    paths = {d.path for d in result.destinations}
    assert '/var/log/nginx/access.log' not in paths
    assert '/var/log/nginx/security.log' not in paths


# ===========================================================================
# 4. server-level "off" is an explicit override, does not fall back to http
# ===========================================================================

def test_server_level_off_overrides_http_level_configured():
    conf = '''
    http {
        access_log /var/log/nginx/access.log;
        server {
            listen 80;
            access_log off;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    result = resolve_access_log(cfg, cfg.servers[0])

    assert result.state == LogDirectiveState.DISABLED
    assert result.source_level == 'server'
    assert result.destinations == []


# ===========================================================================
# 5. http-level "off", no server-level directive -> inherited disable
# ===========================================================================

def test_http_level_off_is_inherited_as_disabled():
    conf = '''
    http {
        access_log off;
        server {
            listen 80;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    result = resolve_access_log(cfg, cfg.servers[0])

    assert result.state == LogDirectiveState.DISABLED
    assert result.source_level == 'http'
    assert result.destinations == []


# ===========================================================================
# 6/7. Multiple destinations — server level and http level (independently)
# ===========================================================================

def test_multiple_destinations_at_server_level():
    conf = '''
    http {
        server {
            listen 80;
            access_log /var/log/nginx/a.log;
            access_log /var/log/nginx/b.log combined;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    result = resolve_access_log(cfg, cfg.servers[0])

    assert result.state == LogDirectiveState.CONFIGURED
    assert result.source_level == 'server'
    assert [d.path for d in result.destinations] == ['/var/log/nginx/a.log', '/var/log/nginx/b.log']
    assert result.destinations[1].options == 'combined'


def test_multiple_destinations_at_http_level_all_inherited():
    conf = '''
    http {
        access_log /var/log/nginx/a.log;
        access_log /var/log/nginx/b.log;
        server {
            listen 80;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    result = resolve_access_log(cfg, cfg.servers[0])

    assert result.state == LogDirectiveState.CONFIGURED
    assert result.source_level == 'http'
    assert [d.path for d in result.destinations] == ['/var/log/nginx/a.log', '/var/log/nginx/b.log']


# ===========================================================================
# 8. error_log follows the identical rule, independently of access_log
# ===========================================================================

def test_error_log_and_access_log_cascade_independently():
    """A server can override access_log while inheriting error_log, or
    vice versa — the two directives' cascade resolution must not
    interfere with each other."""
    conf = '''
    http {
        access_log /var/log/nginx/http_access.log;
        error_log /var/log/nginx/http_error.log;
        server {
            listen 80;
            access_log /var/log/nginx/server_access.log;
            # no server-level error_log — must inherit http's
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    access_result = resolve_access_log(cfg, cfg.servers[0])
    error_result = resolve_error_log(cfg, cfg.servers[0])

    assert access_result.source_level == 'server'
    assert access_result.destinations[0].path == '/var/log/nginx/server_access.log'

    assert error_result.source_level == 'http'
    assert error_result.destinations[0].path == '/var/log/nginx/http_error.log'


def test_error_log_off_at_server_independent_of_access_log():
    conf = '''
    http {
        access_log /var/log/nginx/http_access.log;
        error_log /var/log/nginx/http_error.log;
        server {
            listen 80;
            error_log off;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    access_result = resolve_access_log(cfg, cfg.servers[0])
    error_result = resolve_error_log(cfg, cfg.servers[0])

    # access_log still inherited normally — error_log's override must
    # not bleed into access_log's resolution
    assert access_result.state == LogDirectiveState.CONFIGURED
    assert access_result.source_level == 'http'

    assert error_result.state == LogDirectiveState.DISABLED
    assert error_result.source_level == 'server'


# ===========================================================================
# 9. options string preserved separately from path
# ===========================================================================

def test_options_string_preserved_separately_from_path():
    conf = '''
    http {
        server {
            listen 80;
            access_log /var/log/nginx/access.log combined buffer=32k flush=5s;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    result = resolve_access_log(cfg, cfg.servers[0])

    assert result.destinations[0].path == '/var/log/nginx/access.log'
    assert result.destinations[0].options == 'combined buffer=32k flush=5s'


def test_no_options_is_none_not_empty_string():
    conf = '''
    http {
        server {
            listen 80;
            access_log /var/log/nginx/access.log;
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    result = resolve_access_log(cfg, cfg.servers[0])

    assert result.destinations[0].path == '/var/log/nginx/access.log'
    assert result.destinations[0].options is None


# ===========================================================================
# 10. location-level directives are never read (v1 scope boundary)
# ===========================================================================

def test_location_level_directive_is_ignored():
    """A location-level access_log must have zero effect on the
    server-level resolution this module produces — v1 deliberately does
    not implement nginx's location-selection algorithm or per-location
    effective logging (see this module's docstring)."""
    conf = '''
    http {
        access_log /var/log/nginx/http.log;
        server {
            listen 80;
            location /api {
                access_log /var/log/nginx/api_only.log;
            }
        }
    }
    '''
    cfg = parse_nginx_config_v2(conf)
    result = resolve_access_log(cfg, cfg.servers[0])

    # server has no directive of its own -> inherits http-level,
    # completely unaffected by the location's directive
    assert result.state == LogDirectiveState.CONFIGURED
    assert result.source_level == 'http'
    paths = {d.path for d in result.destinations}
    assert paths == {'/var/log/nginx/http.log'}
    assert '/var/log/nginx/api_only.log' not in paths
