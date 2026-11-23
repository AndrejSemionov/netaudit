"""
What the site checks by address share (docs/research/laravel_audit.md §6,
contract L5): fetching a page the safe way, telling an answer from no
answer, HTTPS / the http redirect / the certificate / three headers, and
the score and verdict. Moved from checks/wordpress.py, whose behaviour and
tests stay as they were; each check keeps its own request seam and its own
finding ids, passed in here.

- fetch(): GET only, the start of the body, redirects followed by hand and
  checked before each hop - the same site only (http -> https, with or
  without www) - at most MAX_REDIRECTS (review #59 pass 1-2).
- answered(): a 5xx, 408 or 429 is no answer to judge by: "not checked",
  never "closed" (review #59 pass 1).
- verdict(): critical/high -> danger, medium/low -> warn, any item not
  checked -> incomplete, else ok; score(): 100 minus PENALTY per finding,
  naming what it could not count.
"""

from __future__ import annotations

import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urljoin, urlparse

import httpx

from . import wordpress_org
from .findings import finding as _finding

TIMEOUT = 10
MAX_BODY = 256 * 1024       # a public log can be gigabytes: the start is enough
MAX_REDIRECTS = 5
CERT_WARN_DAYS = 14
PENALTY = {'critical': 40, 'high': 25, 'medium': 10, 'low': 3}
REDIRECTS = (301, 302, 303, 307, 308)


@dataclass
class Page:
    status: int
    url: str          # the final URL, after redirects when they were followed
    headers: dict     # lower-case names
    text: str         # at most MAX_BODY bytes, decoded
    cookies: list = field(default_factory=list)   # each Set-Cookie of the final answer, as sent


class OffSiteRedirect(httpx.HTTPError):
    """A redirect to another host or scheme: not followed (review #59 pass 1),
    the request is not answered by this site."""


def base_url(url: str) -> str | None:
    """'blog.test' -> 'https://blog.test/', 'https://blog.test/shop' -> 'https://blog.test/shop/',
    'https://blog.test/index.php' -> 'https://blog.test/' (a file is not the site's directory)."""
    parsed = urlparse(url.strip() if '://' in url else f'https://{url.strip()}')
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        return None
    port = f':{parsed.port}' if parsed.port else ''
    path = parsed.path or '/'
    if not path.endswith('/'):
        head, _, last = path.rpartition('/')
        path = head + '/' if '.' in last else path + '/'
    return f'{parsed.scheme}://{parsed.hostname}{port}{path}'


def same_site(url: str, base: str) -> bool:
    a, b = urlparse(url).hostname or '', urlparse(base).hostname or ''
    return a.removeprefix('www.') == b.removeprefix('www.')


def fetch(url: str, follow: bool = True, *, transport=None) -> Page:
    """A GET and the start of the body; redirects checked per hop. Transport
    errors raise httpx.HTTPError."""
    start = url
    with httpx.Client(timeout=TIMEOUT, follow_redirects=False, transport=transport,
                      headers={'User-Agent': wordpress_org.USER_AGENT}) as client:
        for _ in range(MAX_REDIRECTS + 1):
            try:
                with client.stream('GET', url) as resp:
                    if follow and resp.status_code in REDIRECTS and 'location' in resp.headers:
                        target = urljoin(url, resp.headers['location'])
                        if urlparse(target).scheme not in ('http', 'https') or not same_site(target, start):
                            raise OffSiteRedirect(
                                f'redirected to another site: {urlparse(target).hostname or target}')
                        url = target
                        continue
                    body = bytearray()
                    for chunk in resp.iter_bytes():
                        body += chunk
                        if len(body) >= MAX_BODY:
                            break
                    text = bytes(body[:MAX_BODY]).decode(resp.charset_encoding or 'utf-8', errors='replace')
                    cookies = [v for k, v in resp.headers.multi_items() if k.lower() == 'set-cookie']
                    return Page(resp.status_code, url, {k.lower(): v for k, v in resp.headers.items()}, text,
                                cookies)
            except httpx.InvalidURL as e:
                # httpx parses Location even when it does not follow it: a site's
                # "javascript:..." must not crash the check (InvalidURL is no HTTPError)
                raise OffSiteRedirect(f'redirected to an address that is not a web page: {e}') from e
    raise httpx.TooManyRedirects(f'more than {MAX_REDIRECTS} redirects from {start}')


def fetch_twice(fetch_fn: Callable[[str, bool], Page], url: str, follow: bool = True) -> Page:
    """fetch_fn, once more after a transport error: a single network blip
    should not turn a part of the report into "not checked". A redirect off
    the site is an answer, not a blip: not tried again."""
    try:
        return fetch_fn(url, follow)
    except OffSiteRedirect:
        raise
    except httpx.HTTPError:
        return fetch_fn(url, follow)


def answered(page: Page | None) -> bool:
    """Whether the site gave an answer to judge by. A server error, a rate
    limit or a timeout is none: "not checked", never "closed"."""
    return page is not None and page.status < 500 and page.status not in (408, 429)


def why(page: Page | None) -> str:
    return 'the request failed' if page is None else f'HTTP {page.status}'


def cert_not_after(host: str, port: int) -> datetime:
    """When the site's certificate ends."""
    context = ssl.create_default_context()
    with (socket.create_connection((host, port), timeout=TIMEOUT) as sock,
          context.wrap_socket(sock, server_hostname=host) as tls):
        cert = tls.getpeercert()
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(cert['notAfter']), tz=UTC)


def check_certificate(host: str, port: int, findings: list, checked: list, *, ids: dict,
                      cert_fn: Callable[[str, int], datetime]) -> dict | None:
    try:
        not_after = cert_fn(host, port)
    except (OSError, ValueError, KeyError) as e:
        checked.append({'item': 'certificate', 'status': 'not_checked', 'detail': f'could not read it: {e}'})
        return None
    days = (not_after - datetime.now(UTC)).days
    until = not_after.strftime('%Y-%m-%d')
    detail = f'valid until {until}, {days} days left'
    if days < CERT_WARN_DAYS:
        findings.append(_finding('medium', f'the certificate ends in {days} days', f'valid until {until}',
                                 id=ids['cert'],
                                 recommendation='Renew it now and make sure automatic renewal works '
                                                '(certbot renew --dry-run).'))
        checked.append({'item': 'certificate', 'status': 'problem', 'detail': detail})
    else:
        checked.append({'item': 'certificate', 'status': 'ok', 'detail': detail})
    return {'not_after': until, 'days_left': days}


def check_transport(home: Page, base: str, findings: list, checked: list, *, ids: dict,
                    fetch_twice_fn: Callable[[str], Page],
                    cert_fn: Callable[[str, int], datetime]) -> dict | None:
    """HTTPS, the http -> https redirect, the certificate and three headers.
    `ids` names the check's finding ids: no_https, no_redirect, cert, hsts,
    nosniff, framing. Returns the certificate's end date and days left when
    it was read."""
    parsed = urlparse(base)
    https = parsed.scheme == 'https'
    cert = None
    if not https:
        findings.append(_finding('high', 'the site does not use HTTPS',
                                 f'{base} opens over plain http: logins and cookies travel unencrypted',
                                 id=ids['no_https'],
                                 recommendation="Get a certificate (Let's Encrypt is free) and redirect "
                                                'http to https.'))
        checked.append({'item': 'https', 'status': 'problem', 'detail': 'plain http'})
    else:
        checked.append({'item': 'https', 'status': 'ok', 'detail': 'the site opens over HTTPS'})
        plain_url = f'http://{parsed.hostname}{parsed.path}'
        # follow it the way a browser would, on this site only: the redirect
        # counts when the site itself ends on https (review #59 pass 2)
        try:
            plain = fetch_twice_fn(plain_url)
        except OffSiteRedirect as e:
            plain, gap = None, f'{e}: no proof that this site redirects to https'
        except httpx.HTTPError:
            plain, gap = None, 'the request failed'
        else:
            gap = None if answered(plain) else why(plain)
        if gap:
            checked.append({'item': 'http_redirect', 'status': 'not_checked', 'detail': gap})
        elif urlparse(plain.url).scheme == 'https':
            checked.append({'item': 'http_redirect', 'status': 'ok', 'detail': f'http redirects to {plain.url}'})
        elif 200 <= plain.status < 300:
            findings.append(_finding('medium', 'http does not redirect to https',
                                     f'{plain.url} answers {plain.status} with a page over plain http',
                                     id=ids['no_redirect'],
                                     recommendation='Redirect every http request to https (301).'))
            checked.append({'item': 'http_redirect', 'status': 'problem', 'detail': f'http answers {plain.status}'})
        else:
            checked.append({'item': 'http_redirect', 'status': 'not_checked',
                            'detail': f'http answers {plain.status} without a redirect to https'})
        cert = check_certificate(parsed.hostname, parsed.port or 443, findings, checked, ids=ids, cert_fn=cert_fn)

    headers = home.headers
    if https:
        if 'strict-transport-security' in headers:
            checked.append({'item': 'hsts', 'status': 'ok', 'detail': headers['strict-transport-security'][:80]})
        else:
            findings.append(_finding('low', 'HSTS is off',
                                     'no Strict-Transport-Security header: a browser may still try http first',
                                     id=ids['hsts'],
                                     recommendation='Send Strict-Transport-Security: max-age=31536000.'))
            checked.append({'item': 'hsts', 'status': 'problem', 'detail': 'no Strict-Transport-Security'})
    if headers.get('x-content-type-options', '').strip().lower() == 'nosniff':
        checked.append({'item': 'nosniff', 'status': 'ok', 'detail': 'X-Content-Type-Options: nosniff'})
    else:
        findings.append(_finding('low', 'X-Content-Type-Options: nosniff is missing',
                                 'a browser may guess a file\'s type and run an uploaded file as a script',
                                 id=ids['nosniff'], recommendation='Send X-Content-Type-Options: nosniff.'))
        checked.append({'item': 'nosniff', 'status': 'problem', 'detail': 'no X-Content-Type-Options: nosniff'})
    if 'x-frame-options' in headers or 'frame-ancestors' in headers.get('content-security-policy', '').lower():
        checked.append({'item': 'framing', 'status': 'ok', 'detail': 'X-Frame-Options or CSP frame-ancestors'})
    else:
        findings.append(_finding('low', 'no protection from framing (clickjacking)',
                                 'neither X-Frame-Options nor CSP frame-ancestors: another site can show this '
                                 'one in a frame and trick a click', id=ids['framing'],
                                 recommendation="Send X-Frame-Options: SAMEORIGIN or CSP frame-ancestors 'self'."))
        checked.append({'item': 'framing', 'status': 'problem', 'detail': 'no X-Frame-Options, no frame-ancestors'})
    return cert


def summary(findings: list) -> dict:
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'ok': 0}
    for f in findings:
        counts[f['severity']] += 1
    return counts


def score(findings: list, checked: list) -> dict:
    gaps = [c['item'] for c in checked if c['status'] == 'not_checked']
    value = max(0, 100 - sum(PENALTY.get(f['severity'], 0) for f in findings))
    return {'value': value, 'complete': not gaps, 'not_checked': gaps}


def verdict(findings: list, checked: list) -> str:
    severities = {f['severity'] for f in findings}
    if severities & {'critical', 'high'}:
        return 'danger'
    if severities & {'medium', 'low'}:
        return 'warn'
    if any(c['status'] == 'not_checked' for c in checked):
        return 'incomplete'
    return 'ok'
