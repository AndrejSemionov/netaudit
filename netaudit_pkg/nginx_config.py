"""
nginx config collection and parsing: the single place that runs `nginx -T`
over SSH and turns the raw text into a structured NginxConfig.

Both audit_nginx() (server_security.py, produces Findings) and the future
nginx_hardening check (produces scoring Components) are consumers of this
module - neither owns the regex/parsing logic itself. This exists so that a
config detail (say, how ssl_protocols is parsed) is fixed in exactly one
place: today only audit_nginx() reads it, but nginx_hardening will read the
same NginxConfig.ssl_protocols field rather than re-parsing `conf` with its
own regex.

Deliberately data-only: NginxConfig holds facts extracted from the config
(what protocols are listed, whether autoindex is on), never judgments (no
"tls_score" field here). Today's finding logic in audit_nginx() decides
severity; tomorrow's nginx_hardening will decide weight/score - if either
scoring methodology changes, this module doesn't have to.

Each check that needs nginx data still opens its own SSH connection (see
docs/scoring.md discussion / project decision: a shared cross-check SSH
connection pool is a bigger architectural change than this refactor and is
explicitly out of scope here) - `collect_nginx_config()` just takes an
already-connected SSHExecutor, same as audit_nginx() did before this split.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .ssh import SSHExecutor


@dataclass
class NginxConfig:
    """Structured facts extracted from `nginx -T` output. Data only - no
    severity, no score, no opinion about whether a value is good or bad.
    That judgment belongs to the consumer (audit_nginx for Findings,
    nginx_hardening for scoring), not to this parser.
    """

    installed: bool
    version: str = ''
    conf: str = ''
    # None when nginx -T produced no output (e.g. needs root and we don't
    # have it) - distinct from an empty string, which would mean "we read
    # the config and it was empty" (which doesn't happen in practice, but
    # the distinction matters for a consumer deciding whether to report
    # "couldn't read config" vs "read an empty config").
    readable: bool = False
    server_tokens: str | None = None  # 'off' / 'on' / None if not explicitly set
    ssl_protocols: list[str] = field(default_factory=list)
    has_ssl_certificate: bool = False
    headers_present: set[str] = field(default_factory=set)  # lowercased header names found via add_header
    autoindex_on: bool = False


def collect_nginx_config(ssh: SSHExecutor) -> NginxConfig:
    """Run `nginx -v` / `nginx -T` over the given (already-connected) SSH
    session and parse the output into a NginxConfig. Read-only - runs the
    same two commands audit_nginx() always has, just factored out so a
    second consumer (nginx_hardening) doesn't have to duplicate them or the
    parsing that follows.
    """
    out, _ = ssh.run('which nginx || echo NONE')
    if 'NONE' in out:
        return NginxConfig(installed=False)

    ver, _ = ssh.run('nginx -v 2>&1')
    conf, _ = ssh.run('nginx -T 2>/dev/null')

    if not conf:
        return NginxConfig(installed=True, version=ver.strip(), readable=False)

    return _parse_nginx_config(conf, version=ver.strip())


def _parse_nginx_config(conf: str, version: str = '') -> NginxConfig:
    """Pure parsing, no I/O - split out from collect_nginx_config() so it
    can be unit-tested against fixture text without an SSH mock."""
    server_tokens: str | None = None
    if re.search(r'server_tokens\s+off\s*;', conf):
        server_tokens = 'off'
    elif re.search(r'server_tokens\s+on\s*;', conf):
        server_tokens = 'on'

    ssl_protocols: list[str] = []
    ssl_proto_m = re.search(r'ssl_protocols\s+([^;]+);', conf)
    if ssl_proto_m:
        ssl_protocols = ssl_proto_m.group(1).split()

    headers_present = set()
    for hdr in ('strict-transport-security', 'x-frame-options', 'x-content-type-options',
                'content-security-policy', 'x-xss-protection', 'referrer-policy'):
        if hdr in conf.lower():
            headers_present.add(hdr)

    return NginxConfig(
        installed=True,
        version=version,
        conf=conf,
        readable=True,
        server_tokens=server_tokens,
        ssl_protocols=ssl_protocols,
        has_ssl_certificate='ssl_certificate' in conf,
        headers_present=headers_present,
        autoindex_on=bool(re.search(r'autoindex\s+on', conf)),
    )
