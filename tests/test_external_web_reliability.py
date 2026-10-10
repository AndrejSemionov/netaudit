"""F2 (docs/research/external_web_reliability.md): the TLS and external web
checks never report a clean result from data they did not get.

No network: run_cmd, _ssl_stdlib, the TLS probe context and socket are faked.
"""

from __future__ import annotations

import ssl

import pytest

from netaudit_pkg.checks import server_security, site

TLS10, TLS11 = ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1

HEAD_OK = ('HTTP/2 200\r\n'
           'strict-transport-security: max-age=63072000\r\n'
           'x-frame-options: DENY\r\n'
           'x-content-type-options: nosniff\r\n'
           "content-security-policy: default-src 'self'\r\n\r\n")

# HSTS and a cookie only on the redirect, not on the final page
HEAD_REDIRECT = ('HTTP/1.1 301 Moved Permanently\r\n'
                 'Location: https://www.example.com/\r\n'
                 'Strict-Transport-Security: max-age=63072000\r\n'
                 'Set-Cookie: sid=1\r\n\r\n'
                 'HTTP/2 200\r\n'
                 'x-frame-options: DENY\r\n'
                 'x-content-type-options: nosniff\r\n'
                 "content-security-policy: default-src 'self'\r\n\r\n")


def _web(monkeypatch, head=(0, HEAD_OK, ''), paths=None, tls=None):
    """Fakes curl for web_security_external; returns the list of curl calls."""
    calls = []
    paths = paths or {}

    def fake_run_cmd(cmd, timeout=30, input_text=None):
        calls.append(cmd)
        if '-w' in cmd:  # sensitive-path probe: prints the status code
            path = '/' + cmd[-1].split('/', 3)[3]
            return paths.get(path, (0, '404', ''))
        if any(a.startswith('Origin:') for a in cmd):
            return 0, HEAD_OK, ''
        if '-I' in cmd:
            return head
        return 0, '<html>404</html>', ''  # error-page probe

    monkeypatch.setattr(server_security, 'tool_available', lambda name: True)
    monkeypatch.setattr(server_security, 'run_cmd', fake_run_cmd)
    tls = tls if tls is not None else {TLS10: 'refused', TLS11: 'refused'}
    monkeypatch.setattr(server_security, '_check_tls_version', lambda host, version: tls[version])
    return calls


def _titles(result):
    return [(f['severity'], f['title']) for f in result.get('findings', [])]


# ===========================================================================
# RA-01: ssl, openssl path
# ===========================================================================

def _ssl(monkeypatch, stdlib):
    def fake_run_cmd(cmd, timeout=30, input_text=None):
        if '-brief' in cmd:
            return 0, '', 'CONNECTION ESTABLISHED\nProtocol version: TLSv1.2\nCiphersuite: ECDHE-RSA-AES128-GCM-SHA256\n'
        return 0, '-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n', ''

    monkeypatch.setattr(site, 'tool_available', lambda name: True)
    monkeypatch.setattr(site, 'run_cmd', fake_run_cmd)
    monkeypatch.setattr(site, '_ssl_stdlib', lambda hostname: dict(stdlib))


def test_ssl_openssl_path_reports_a_failed_certificate_verification(monkeypatch):
    """expired / self-signed / wrong-host certificates used to give ok: True."""
    _ssl(monkeypatch, {'ok': False, 'error': 'certificate verify failed: certificate has expired'})
    result = site.check_ssl('https://expired.example')
    assert result['ok'] is False
    assert 'certificate has expired' in result['error']
    assert result['protocol'] == 'TLSv1.2'
    assert result['tool_used'] == 'openssl'


def test_ssl_openssl_path_with_a_valid_certificate_is_unchanged(monkeypatch):
    _ssl(monkeypatch, {'ok': True, 'expires': '2030-01-01T00:00:00', 'days_left': 1000, 'issuer': 'CA'})
    result = site.check_ssl('https://good.example')
    assert result['ok'] is True
    assert result['days_left'] == 1000
    assert result['issuer'] == 'CA'
    assert 'error' not in result


# ===========================================================================
# RA-03: TLS 1.0/1.1 probe
# ===========================================================================

class _Sock:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def close(self):
        pass


class _Ctx:
    def __init__(self, outcome):
        self.outcome = outcome

    def wrap_socket(self, sock, server_hostname=None):
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return _Sock()


def _probe(monkeypatch, *, can_offer=True, connect=None, handshake=None):
    monkeypatch.setattr(server_security, '_client_can_offer', lambda version: can_offer)

    def fake_connect(addr, timeout=None):
        if connect is not None:
            raise connect
        return _Sock()

    monkeypatch.setattr(server_security.socket, 'create_connection', fake_connect)
    monkeypatch.setattr(server_security, '_tls_probe_context', lambda version: _Ctx(handshake))


def test_tls_probe_untested_when_this_client_cannot_offer_the_version(monkeypatch):
    _probe(monkeypatch, can_offer=False, connect=AssertionError('no connection expected'))
    assert server_security._check_tls_version('h.example', TLS10) == 'untested'


def test_tls_probe_untested_when_the_connection_fails(monkeypatch):
    _probe(monkeypatch, connect=OSError('connection refused'))
    assert server_security._check_tls_version('h.example', TLS10) == 'untested'


@pytest.mark.parametrize('outcome', [
    ssl.SSLError(1, '[SSL: UNSUPPORTED_PROTOCOL] unsupported protocol'),
    ConnectionResetError(104, 'Connection reset by peer'),
])
def test_tls_probe_refused_when_the_server_ends_the_handshake(monkeypatch, outcome):
    _probe(monkeypatch, handshake=outcome)
    assert server_security._check_tls_version('h.example', TLS10) == 'refused'


def test_tls_probe_untested_on_a_handshake_timeout(monkeypatch):
    _probe(monkeypatch, handshake=TimeoutError('timed out'))
    assert server_security._check_tls_version('h.example', TLS10) == 'untested'


def test_tls_probe_accepted_when_the_handshake_completes(monkeypatch):
    _probe(monkeypatch, handshake=None)
    assert server_security._check_tls_version('h.example', TLS10) == 'accepted'


# ===========================================================================
# RA-04 / RA-03 / D4: web_security_external
# ===========================================================================

def test_unreachable_site_is_an_error_not_missing_headers(monkeypatch):
    calls = _web(monkeypatch, head=(6, '', 'curl: (6) Could not resolve host: down.example'),
                 tls={TLS10: AssertionError, TLS11: AssertionError})
    result = server_security.check_web_security_external('https://down.example')
    assert 'could not fetch' in result['error']
    assert 'Could not resolve host' in result['error']
    assert not result.get('findings')
    assert len(calls) == 1  # no CORS, error-page or path probes after a failed fetch


def test_untested_old_tls_is_reported_and_blocks_the_clean_result(monkeypatch):
    _web(monkeypatch, tls={TLS10: 'untested', TLS11: 'untested'})
    result = server_security.check_web_security_external('https://site.example')
    infos = [f for f in result['findings'] if f['severity'] == 'info']
    assert len(infos) == 1 and 'TLS 1.0' in infos[0]['title'] and 'TLS 1.1' in infos[0]['title']
    assert ('ok', 'no external issues found') not in _titles(result)


def test_accepted_old_tls_still_raises_web_tls_001(monkeypatch):
    _web(monkeypatch, tls={TLS10: 'accepted', TLS11: 'refused'})
    result = server_security.check_web_security_external('https://site.example')
    [f] = [f for f in result['findings'] if f.get('id') == 'WEB-TLS-001']
    assert f['severity'] == 'high' and f['detail'] == 'TLS 1.0'


def test_all_probes_clean_still_gives_ok(monkeypatch):
    _web(monkeypatch)
    result = server_security.check_web_security_external('https://site.example')
    assert _titles(result) == [('ok', 'no external issues found')]


def test_failed_sensitive_path_request_is_not_checked_not_clean(monkeypatch):
    _web(monkeypatch, paths={'/.env': (28, '000', 'curl: (28) Operation timed out')})
    result = server_security.check_web_security_external('https://site.example')
    infos = [f for f in result['findings'] if f['severity'] == 'info']
    assert len(infos) == 1 and '/.env' in infos[0]['detail']
    assert '/.env' not in result['exposed_paths']
    assert ('ok', 'no external issues found') not in _titles(result)


# ===========================================================================
# RA-11: only the final response's headers count
# ===========================================================================

def test_web_security_external_reads_headers_of_the_final_response(monkeypatch):
    _web(monkeypatch, head=(0, HEAD_REDIRECT, ''))
    result = server_security.check_web_security_external('https://site.example')
    assert ('medium', 'missing header strict-transport-security') in _titles(result)
    # a cookie set during the redirect is still a real cookie
    assert any(f.get('id', '').startswith('WEB-COOKIE-002:sid') for f in result['findings'])


def test_security_headers_reads_headers_of_the_final_response(monkeypatch):
    monkeypatch.setattr(site, 'tool_available', lambda name: True)
    monkeypatch.setattr(site, 'run_cmd', lambda cmd, timeout=30, input_text=None: (0, HEAD_REDIRECT, ''))
    result = site.check_security_headers('https://site.example')
    assert result['strict-transport-security'] is None
    assert result['x-frame-options'] == 'DENY'
