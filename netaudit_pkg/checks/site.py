"""Site check plugins: SSL (openssl), HTTP timings (curl), security headers."""

from __future__ import annotations

import json as _json
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

from ..registry import register
from ..utils import run_cmd, tool_available

CURL_TIMING = (
    '{"dns_ms":%{time_namelookup},"connect_ms":%{time_connect},'
    '"tls_ms":%{time_appconnect},"ttfb_ms":%{time_starttransfer},'
    '"total_ms":%{time_total},"http_code":%{http_code},'
    '"size_download":%{size_download},"num_redirects":%{num_redirects}}'
)


def _ssl_stdlib(hostname: str, port: int = 443) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                issuer = dict(x[0] for x in cert.get('issuer', []))
                return {'ok': True, 'expires': not_after.isoformat(),
                        'days_left': (not_after - datetime.now()).days,
                        'issuer': issuer.get('organizationName', issuer.get('commonName', '—'))}
    except (socket.timeout, socket.gaierror, ssl.SSLError, ConnectionRefusedError, OSError) as e:
        return {'ok': False, 'error': str(e)}


@register(
    id='ssl', label='SSL/TLS certificate', category='site', risk_level='PASSIVE',
    params=[
        {'name': 'url', 'type': 'text', 'label': 'URL', 'default': 'https://example.com'},
        {'name': 'method', 'type': 'select', 'label': 'Tool',
         'options': ['auto', 'openssl', 'python'], 'default': 'auto'},
    ],
    required_tools=[],
    description='Protocol, cipher, certificate chain, expiration. auto = openssl if available, otherwise python.',
)
def check_ssl(url: str = 'https://example.com', method: str = 'auto') -> dict:
    hostname = urlparse(url if '://' in url else f'https://{url}').hostname
    if not hostname:
        return {'ok': False, 'error': f'could not parse URL: {url}'}

    # tool selection
    use_openssl = (method == 'openssl') or (method == 'auto' and tool_available('openssl'))
    if method == 'openssl' and not tool_available('openssl'):
        return {'ok': False, 'error': 'openssl is not installed, but was explicitly selected'}
    if method == 'python' or not use_openssl:
        res = _ssl_stdlib(hostname)
        res['tool_used'] = 'python'
        return res

    code, out, err = run_cmd(['openssl', 's_client', '-connect', f'{hostname}:443',
                              '-servername', hostname, '-brief'], timeout=15, input_text='Q\n')
    combined = out + err
    if 'CONNECTION ESTABLISHED' not in combined and 'CONNECTED' not in combined:
        return {'ok': False, 'error': err.strip() or out.strip() or 'could not connect'}
    protocol = cipher = None
    for line in combined.splitlines():
        if line.startswith('Protocol version:'):
            protocol = line.split(':', 1)[1].strip()
        elif line.startswith('Ciphersuite:'):
            cipher = line.split(':', 1)[1].strip()
    stdlib = _ssl_stdlib(hostname)
    code2, out2, _ = run_cmd(['openssl', 's_client', '-connect', f'{hostname}:443',
                              '-servername', hostname, '-showcerts'], timeout=15, input_text='Q\n')
    return {'ok': True, 'hostname': hostname, 'protocol': protocol, 'cipher': cipher,
            'cert_chain_length': out2.count('BEGIN CERTIFICATE'),
            'expires': stdlib.get('expires'), 'days_left': stdlib.get('days_left'),
            'issuer': stdlib.get('issuer'), 'tool_used': 'openssl'}


@register(
    id='http', label='HTTP timings', category='site', risk_level='PASSIVE',
    params=[
        {'name': 'url', 'type': 'text', 'label': 'URL', 'default': 'https://example.com'},
        {'name': 'method', 'type': 'select', 'label': 'Tool',
         'options': ['auto', 'curl', 'python'], 'default': 'auto'},
    ],
    required_tools=[],
    description='Per-phase timings: DNS / TCP connect / TLS / TTFB. auto = curl if available, otherwise python.',
)
def check_http(url: str = 'https://example.com', method: str = 'auto') -> dict:
    full = url if '://' in url else f'https://{url}'
    use_curl = (method == 'curl') or (method == 'auto' and tool_available('curl'))
    if method == 'curl' and not tool_available('curl'):
        return {'error': 'curl is not installed, but was explicitly selected'}
    if method == 'python' or not use_curl:
        return _http_python(full)

    code, out, err = run_cmd(['curl', '-s', '-o', '/dev/null', '-L', '--max-time', '15',
                              '-w', CURL_TIMING, full], timeout=20)
    if code != 0:
        return {'error': err.strip() or f'curl exit code {code}'}
    try:
        t = _json.loads(out)
        for k in ('dns_ms', 'connect_ms', 'tls_ms', 'ttfb_ms', 'total_ms'):
            t[k] = round(float(t[k]) * 1000, 1)
        t['tool_used'] = 'curl'
        return t
    except (ValueError, KeyError) as e:
        return {'error': f'curl parsing: {e}', 'raw': out}


def _http_python(url: str) -> dict:
    """HTTP timings via httpx (fallback without curl). Coarser phases - no separate TLS."""
    try:
        import httpx
    except ImportError:
        return {'error': 'neither curl nor httpx is available'}
    import time
    try:
        start = time.monotonic()
        with httpx.Client(follow_redirects=True, timeout=15) as c:
            resp = c.get(url)
        total = round((time.monotonic() - start) * 1000, 1)
        return {'dns_ms': None, 'connect_ms': None, 'tls_ms': None,
                'ttfb_ms': total, 'total_ms': total, 'http_code': resp.status_code,
                'num_redirects': len(resp.history), 'tool_used': 'python'}
    except httpx.HTTPError as e:
        return {'error': str(e)}


@register(
    id='security_headers', label='Security headers', category='site', risk_level='PASSIVE',
    params=[{'name': 'url', 'type': 'text', 'label': 'URL', 'default': 'https://example.com'}],
    required_tools=['curl'],
    description='HSTS, X-Frame-Options, X-Content-Type-Options, CSP.',
)
def check_security_headers(url: str = 'https://example.com') -> dict:
    if not tool_available('curl'):
        return {'error': 'curl is not installed'}
    full = url if '://' in url else f'https://{url}'
    code, out, err = run_cmd(['curl', '-s', '-I', '-L', '--max-time', '10', full], timeout=15)
    if code != 0:
        return {'error': err.strip()}
    headers = {}
    for line in out.splitlines():
        if ':' in line:
            k, _, v = line.partition(':')
            headers[k.strip().lower()] = v.strip()
    return {
        'strict-transport-security': headers.get('strict-transport-security'),
        'x-frame-options': headers.get('x-frame-options'),
        'x-content-type-options': headers.get('x-content-type-options'),
        'content-security-policy': headers.get('content-security-policy'),
        'server': headers.get('server'),
    }
