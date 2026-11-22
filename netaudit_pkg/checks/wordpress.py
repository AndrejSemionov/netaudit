"""
WordPress checked from outside (docs/research/wordpress_audit.md §4, §6;
contract C2): what any visitor of the site can see. GET requests only, and
only to the site itself; wordpress.org answers come from wordpress_org.

The verdict follows the project's outcomes (result_reliability_audit.md):
- 'unreachable' - the site did not answer (an error, no findings);
- 'not_wp'      - no sign of WordPress: not applicable, nothing else probed;
- 'danger' / 'warn' - critical/high, or medium/low findings;
- 'incomplete'  - nothing bad found, but a part could not be checked (a
                  hidden core version, a failed request): never "ok";
- 'ok'          - every part was checked and nothing was found.
Known plugin vulnerabilities need a vulnerability database (contract C3):
until then they are reported as not checked, never as "none".

Every part is its own item in 'checked' (USER 2026-11-22 asked for a report
more detailed than the reference's): HTTPS, the http redirect, the
certificate, three headers, the core, plugins, usernames, XML-RPC and five
kinds of public files. The score is 100 minus PENALTY per finding; it names
the items it could not count.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import parse_qs, unquote, urljoin, urlparse

import httpx

from .. import wordpress_org
from ..findings import finding as _finding
from ..findings import subject_id
from ..registry import register

TIMEOUT = 10
MAX_BODY = 256 * 1024       # a public debug.log can be gigabytes: the start is enough
MAX_REDIRECTS = 5
MAX_PLUGINS = 25
MAX_USERS = 10

# wp-content/debug.log, copies of wp-config.php an editor or a backup left
# next to it, and a directory listing of uploads. Each one counts only when
# its content says so: many sites answer 200 with their own "not found" page.
LOG_FILE = 'wp-content/debug.log'
CONFIG_COPIES = ('wp-config.php.bak', 'wp-config.php~', 'wp-config.php.save', 'wp-config.php.old',
                 'wp-config.php.orig', 'wp-config.bak', 'wp-config.txt')
UPLOADS = 'wp-content/uploads/'
README = 'readme.html'
LICENSE = 'license.txt'
PUBLIC_FILES = (LOG_FILE, *CONFIG_COPIES, UPLOADS, README, LICENSE)
CERT_WARN_DAYS = 14
PENALTY = {'critical': 40, 'high': 25, 'medium': 10, 'low': 3}
_REDIRECTS = (301, 302, 303, 307, 308)

_LOG_LINE = re.compile(r'PHP (?:Fatal error|Parse error|Warning|Notice|Deprecated)|WordPress database error')
_CONFIG_DEFINE = re.compile(r'''define\s*\(\s*['"]DB_(?:NAME|USER|PASSWORD|HOST)['"]''')
_DIR_LISTING = re.compile(r'<title>\s*Index of /', re.IGNORECASE)
_README = re.compile(r'<title>\s*WordPress\s*(?:&#8250;|\u203a)\s*ReadMe', re.IGNORECASE)  # readme.html
_LICENSE = re.compile(r'WordPress - Web publishing software')                          # license.txt
_XMLRPC_GET = 'XML-RPC server accepts POST requests only'   # wp-includes/IXR/class-IXR-server.php

_VERSION = r'([0-9][0-9A-Za-z.\-]{0,19})'
_GENERATOR = (  # wp_generator(): <meta name="generator" content="WordPress X">, either attribute order
    re.compile(r'<meta\s[^>]*name=["\']generator["\'][^>]*content=["\']WordPress\s+' + _VERSION + r'["\']', re.IGNORECASE),
    re.compile(r'<meta\s[^>]*content=["\']WordPress\s+' + _VERSION + r'["\'][^>]*name=["\']generator["\']', re.IGNORECASE),
)
_FEED_GENERATOR = re.compile(r'<generator>\s*https?://wordpress\.org/\?v=' + _VERSION + r'\s*</generator>', re.IGNORECASE)
_ASSET = re.compile(r'''\b(?:src|href)\s*=\s*["']([^"'<>]+)["']''', re.IGNORECASE)
_PLUGIN_PATH = re.compile(r'^(/(?:[^/]+/)*?wp-content/plugins/)([A-Za-z0-9_-]{1,100})/')
_STABLE_TAG = re.compile(r'^[ \t]*stable tag:[ \t]*(\S+)', re.IGNORECASE | re.MULTILINE)
_AUTHOR_PATH = re.compile(r'/author/([^/?#]{1,60})(?:/|$)')
_LOC = re.compile(r'<loc>\s*([^<\s]+)\s*</loc>', re.IGNORECASE)
_META_GENERATOR = (
    re.compile(r'<meta\s[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']{1,200})["\']', re.IGNORECASE),
    re.compile(r'<meta\s[^>]*content=["\']([^"\']{1,200})["\'][^>]*name=["\']generator["\']', re.IGNORECASE),
)
# plugins that print their own version in a generator tag, as seen on a real site
_PLUGIN_GENERATORS = (
    ('elementor', re.compile(r'^Elementor\s+([0-9]+(?:\.[0-9]+)+)\b')),
    ('sitepress-multilingual-cms', re.compile(r'^WPML ver:([0-9]+(?:\.[0-9]+)+)\b')),
)
_DOTTED = re.compile(r'[0-9]+(?:\.[0-9]+)+')
# where a plugin's version was read, weakest last: ?ver= is set by whoever
# enqueues the file, and a bundled library carries its own
VERSION_SOURCES = {
    'generator': ('medium', "the plugin's own generator tag"),
    'readme.txt': ('medium', "the plugin's public readme.txt"),
    'asset ver': ('low', "the ?ver= of the plugin's files on the page"),
}


@dataclass
class Page:
    status: int
    url: str          # the final URL, after redirects when they were followed
    headers: dict     # lower-case names
    text: str         # at most MAX_BODY bytes, decoded


def _fetch(url: str, follow: bool = True) -> Page:
    """The one request seam of this check: a GET, the start of the body.
    Transport errors raise httpx.HTTPError."""
    with (httpx.Client(timeout=TIMEOUT, follow_redirects=follow, max_redirects=MAX_REDIRECTS,
                       headers={'User-Agent': wordpress_org.USER_AGENT}) as client,
          client.stream('GET', url) as resp):
        body = bytearray()
        for chunk in resp.iter_bytes():
            body += chunk
            if len(body) >= MAX_BODY:
                break
        text = bytes(body[:MAX_BODY]).decode(resp.charset_encoding or 'utf-8', errors='replace')
        return Page(resp.status_code, str(resp.url), {k.lower(): v for k, v in resp.headers.items()}, text)


def _base_url(url: str) -> str | None:
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


def _same_site(url: str, base: str) -> bool:
    a, b = urlparse(url).hostname or '', urlparse(base).hostname or ''
    return a.removeprefix('www.') == b.removeprefix('www.')


def _fetch_twice(url: str, follow: bool = True) -> Page:
    """_fetch, once more after a transport error: a single network blip
    should not turn a part of the report into "not checked"."""
    try:
        return _fetch(url, follow)
    except httpx.HTTPError:
        return _fetch(url, follow)


def _try(url: str, follow: bool = True) -> Page | None:
    try:
        return _fetch_twice(url, follow)
    except httpx.HTTPError:
        return None


def _cert_not_after(host: str, port: int) -> datetime:
    """When the site's certificate ends."""
    context = ssl.create_default_context()
    with (socket.create_connection((host, port), timeout=TIMEOUT) as sock,
          context.wrap_socket(sock, server_hostname=host) as tls):
        cert = tls.getpeercert()
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(cert['notAfter']), tz=UTC)


def _check_certificate(host: str, port: int, findings: list, checked: list) -> dict | None:
    try:
        not_after = _cert_not_after(host, port)
    except (OSError, ValueError, KeyError) as e:
        checked.append({'item': 'certificate', 'status': 'not_checked', 'detail': f'could not read it: {e}'})
        return None
    days = (not_after - datetime.now(UTC)).days
    until = not_after.strftime('%Y-%m-%d')
    detail = f'valid until {until}, {days} days left'
    if days < CERT_WARN_DAYS:
        findings.append(_finding('medium', f'the certificate ends in {days} days', f'valid until {until}',
                                 id='WP-TLS-003',
                                 recommendation='Renew it now and make sure automatic renewal works '
                                                '(certbot renew --dry-run).'))
        checked.append({'item': 'certificate', 'status': 'problem', 'detail': detail})
    else:
        checked.append({'item': 'certificate', 'status': 'ok', 'detail': detail})
    return {'not_after': until, 'days_left': days}


def _check_transport(home: Page, base: str, findings: list, checked: list) -> dict | None:
    """HTTPS, the http -> https redirect, the certificate and three headers.
    Returns the certificate's end date and days left when it was read."""
    parsed = urlparse(base)
    https = parsed.scheme == 'https'
    cert = None
    if not https:
        findings.append(_finding('high', 'the site does not use HTTPS',
                                 f'{base} opens over plain http: logins and cookies travel unencrypted',
                                 id='WP-TLS-001',
                                 recommendation="Get a certificate (Let's Encrypt is free) and redirect "
                                                'http to https.'))
        checked.append({'item': 'https', 'status': 'problem', 'detail': 'plain http'})
    else:
        checked.append({'item': 'https', 'status': 'ok', 'detail': 'the site opens over HTTPS'})
        plain_url = f'http://{parsed.hostname}{parsed.path}'
        plain = _try(plain_url, follow=False)
        if plain is None:
            checked.append({'item': 'http_redirect', 'status': 'not_checked', 'detail': 'the request failed'})
        elif plain.status in _REDIRECTS and plain.headers.get('location', '').startswith('https://'):
            checked.append({'item': 'http_redirect', 'status': 'ok', 'detail': 'http redirects to https'})
        elif 200 <= plain.status < 300:
            findings.append(_finding('medium', 'http does not redirect to https',
                                     f'{plain_url} answers {plain.status} with the page itself',
                                     id='WP-TLS-002',
                                     recommendation='Redirect every http request to https (301).'))
            checked.append({'item': 'http_redirect', 'status': 'problem', 'detail': f'http answers {plain.status}'})
        else:
            checked.append({'item': 'http_redirect', 'status': 'ok',
                            'detail': f'http answers {plain.status}: the site is not served over it'})
        cert = _check_certificate(parsed.hostname, parsed.port or 443, findings, checked)

    headers = home.headers
    if https:
        if 'strict-transport-security' in headers:
            checked.append({'item': 'hsts', 'status': 'ok', 'detail': headers['strict-transport-security'][:80]})
        else:
            findings.append(_finding('low', 'HSTS is off',
                                     'no Strict-Transport-Security header: a browser may still try http first',
                                     id='WP-HDR-001',
                                     recommendation='Send Strict-Transport-Security: max-age=31536000.'))
            checked.append({'item': 'hsts', 'status': 'problem', 'detail': 'no Strict-Transport-Security'})
    if headers.get('x-content-type-options', '').strip().lower() == 'nosniff':
        checked.append({'item': 'nosniff', 'status': 'ok', 'detail': 'X-Content-Type-Options: nosniff'})
    else:
        findings.append(_finding('low', 'X-Content-Type-Options: nosniff is missing',
                                 'a browser may guess a file\'s type and run an uploaded file as a script',
                                 id='WP-HDR-002', recommendation='Send X-Content-Type-Options: nosniff.'))
        checked.append({'item': 'nosniff', 'status': 'problem', 'detail': 'no X-Content-Type-Options: nosniff'})
    if 'x-frame-options' in headers or 'frame-ancestors' in headers.get('content-security-policy', '').lower():
        checked.append({'item': 'framing', 'status': 'ok', 'detail': 'X-Frame-Options or CSP frame-ancestors'})
    else:
        findings.append(_finding('low', 'no protection from framing (clickjacking)',
                                 'neither X-Frame-Options nor CSP frame-ancestors: another site can show this '
                                 'one in a frame and trick a click', id='WP-HDR-003',
                                 recommendation="Send X-Frame-Options: SAMEORIGIN or CSP frame-ancestors 'self'."))
        checked.append({'item': 'framing', 'status': 'problem', 'detail': 'no X-Frame-Options, no frame-ancestors'})
    return cert


def _is_wordpress(home: Page, base: str) -> bool:
    if 'api.w.org' in home.headers.get('link', ''):
        return True
    html = home.text
    if 'api.w.org' in html or '/wp-content/' in html or '/wp-includes/' in html:
        return True
    if any(rx.search(html) for rx in _GENERATOR):
        return True
    root = _try(base + '?rest_route=/')
    if root is None or root.status != 200:
        return False
    try:
        data = json.loads(root.text)
    except ValueError:
        return False
    return isinstance(data, dict) and 'wp/v2' in (data.get('namespaces') or [])


def _core_version(home: Page, base: str) -> tuple[str | None, str | None]:
    for rx in _GENERATOR:
        m = rx.search(home.text)
        if m:
            return m.group(1), 'generator'
    feed = _try(base + '?feed=rss2')
    if feed is not None and feed.status == 200:
        m = _FEED_GENERATOR.search(feed.text)
        if m:
            return m.group(1), 'feed'
    return None, None


def _check_core(home: Page, base: str, findings: list, checked: list) -> dict:
    version, source = _core_version(home, base)
    if version is None:
        findings.append(_finding('info', 'the WordPress version is hidden — the core was not checked',
                                 'neither the generator tag nor the RSS feed shows it; look it up in the '
                                 'admin panel (Dashboard → Updates)', requires_manual_verification=True))
        checked.append({'item': 'core', 'status': 'not_checked', 'detail': 'version hidden'})
        return {'version': None, 'source': None, 'status': 'not_checked', 'latest': None}
    status = wordpress_org.core_status(version)
    core = {'version': version, 'source': source, 'status': status['status'], 'latest': status['latest']}
    latest = status['latest']
    if status['status'] == 'insecure':
        findings.append(_finding('high', f'WordPress {version} is insecure',
                                 'wordpress.org lists this version as insecure: later releases fix '
                                 'security issues in it', id='WP-CORE-001',
                                 recommendation=f'Update WordPress to {latest}.'))
        checked.append({'item': 'core', 'status': 'problem', 'detail': f'{version}: insecure'})
    elif status['status'] == 'outdated':
        findings.append(_finding('low', f'WordPress {version} is not the latest release',
                                 'wordpress.org lists it as outdated, not insecure', id='WP-CORE-002',
                                 recommendation=f'Update WordPress to {latest}.'))
        checked.append({'item': 'core', 'status': 'problem', 'detail': f'{version}: outdated'})
    elif status['status'] == 'latest':
        checked.append({'item': 'core', 'status': 'ok', 'detail': f'{version}: latest'})
    else:
        reason = status['error'] or f'{version} is not in the wordpress.org release list'
        findings.append(_finding('info', f'WordPress {version} could not be checked against wordpress.org',
                                 reason, requires_manual_verification=True))
        checked.append({'item': 'core', 'status': 'not_checked', 'detail': reason})
    return core


def _asset_version(vers: list[str], core_version: str | None) -> str | None:
    """The ?ver= most of a plugin's files agree on: at least two files and
    more than half of the dotted values. Not the core version: WordPress
    puts its own on a file registered without one."""
    dotted = [v for v in vers if _DOTTED.fullmatch(v)]
    if not dotted:
        return None
    best = max(set(dotted), key=dotted.count)
    if dotted.count(best) < 2 or dotted.count(best) * 2 <= len(dotted) or best == core_version:
        return None
    return best


def _visible_plugins(home: Page, base: str, core_version: str | None) -> tuple[list[dict], bool]:
    """Plugins whose files this site's pages load or whose generator tag is
    on the page, capped at MAX_PLUGINS, and whether the cap was hit:
    [{'slug', 'readme', 'generator', 'asset'}] (the last two are versions)."""
    origin = '{0.scheme}://{0.netloc}'.format(urlparse(base))
    found: dict[str, dict] = {}
    for raw in _ASSET.findall(home.text):
        url = urljoin(base, raw)
        if not _same_site(url, base):
            continue
        parsed = urlparse(url)
        m = _PLUGIN_PATH.match(parsed.path)
        if not m:
            continue
        entry = found.setdefault(m.group(2), {'slug': m.group(2), 'generator': None, 'vers': [],
                                              'readme': f'{origin}{m.group(1)}{m.group(2)}/readme.txt'})
        entry['vers'] += parse_qs(parsed.query).get('ver', [])
    for rx in _META_GENERATOR:
        for content in rx.findall(home.text):
            for slug, plugin_rx in _PLUGIN_GENERATORS:
                m = plugin_rx.match(content.strip())
                if m:
                    found.setdefault(slug, {'slug': slug, 'vers': [],
                                            'readme': f'{base}wp-content/plugins/{slug}/readme.txt'})
                    found[slug]['generator'] = m.group(1)
    plugins = [{'slug': e['slug'], 'readme': e['readme'], 'generator': e.get('generator'),
                'asset': _asset_version(e['vers'], core_version)} for e in found.values()]
    return plugins[:MAX_PLUGINS], len(plugins) > MAX_PLUGINS


def _readme_version(url: str) -> str | None:
    readme = _try(url)
    if readme is None or readme.status != 200:
        return None
    m = _STABLE_TAG.search(readme.text)
    return m.group(1) if m and wordpress_org.version_tuple(m.group(1)) else None


def _plugin(seen: dict) -> dict:
    version, source = seen['generator'], 'generator'
    if version is None:
        version, source = _readme_version(seen['readme']), 'readme.txt'
    if version is None:
        version, source = seen['asset'], 'asset ver'
    entry = {'slug': seen['slug'], 'version': version, 'version_source': source if version else None,
             'latest': None, 'status': 'unknown'}
    if version is None:
        return entry
    slug = seen['slug']
    latest = wordpress_org.plugin_latest(slug)
    if latest['status'] == 'error':
        entry['status'] = 'not_checked'
    elif latest['status'] == 'ok':
        entry['latest'] = latest['version']
        older = wordpress_org.is_older(version, latest['version'])
        entry['status'] = {True: 'outdated', False: 'current'}.get(older, 'unknown')
    return entry


def _check_plugins(home: Page, base: str, core_version: str | None, findings: list,
                   checked: list) -> tuple[list, bool]:
    visible, truncated = _visible_plugins(home, base, core_version)
    plugins = sorted((_plugin(seen) for seen in visible), key=lambda p: p['slug'])
    for p in plugins:
        if p['status'] == 'outdated':
            confidence, where = VERSION_SOURCES[p['version_source']]
            findings.append(_finding('medium', f'plugin {p["slug"]} {p["version"]} is outdated',
                                     f'the latest version on wordpress.org is {p["latest"]}; the installed '
                                     f'version is read from {where}',
                                     confidence=confidence, id=subject_id('WP-PLG-001', p['slug']),
                                     recommendation=f'Update {p["slug"]} to {p["latest"]}.'))
    outdated = [p['slug'] for p in plugins if p['status'] == 'outdated']
    if outdated:
        checked.append({'item': 'plugins', 'status': 'problem', 'detail': f'outdated: {", ".join(outdated)}'})
    elif any(p['status'] == 'not_checked' for p in plugins):
        checked.append({'item': 'plugins', 'status': 'not_checked',
                        'detail': 'wordpress.org did not answer for some plugins'})
    else:
        checked.append({'item': 'plugins', 'status': 'ok', 'detail': f'{len(plugins)} visible from outside'})
    checked.append({'item': 'plugin_vulns', 'status': 'not_checked',
                    'detail': 'no vulnerability database is connected'})
    return plugins, truncated


def _author_slugs(urls: list[str], base: str) -> list[str]:
    out = []
    for url in urls:
        full = urljoin(base, url)
        m = _AUTHOR_PATH.search(urlparse(full).path)
        if m and _same_site(full, base):
            out.append(unquote(m.group(1)))
    return out


def _check_users(base: str, findings: list, checked: list) -> dict:
    exposed, sources, failed = [], [], False

    def add(source, slugs):
        new = [s for s in slugs if s and s not in exposed]
        if slugs and source not in sources:
            sources.append(source)
        exposed.extend(new)

    rest = _try(base + '?rest_route=/wp/v2/users')
    if rest is None:
        failed = True
    elif rest.status == 200:
        try:
            data = json.loads(rest.text)
        except ValueError:
            data = None
        if isinstance(data, list):
            add('rest', [str(u['slug'])[:60] for u in data if isinstance(u, dict) and u.get('slug')])
    author = _try(base + '?author=1', follow=False)
    if author is None:
        failed = True
    elif author.status in (301, 302, 303, 307, 308):
        add('author', _author_slugs([author.headers.get('location', '')], base))
    sitemap = _try(base + '?sitemap=users&paged=1')
    if sitemap is None:
        failed = True
    elif sitemap.status == 200:
        add('sitemap', _author_slugs(_LOC.findall(sitemap.text), base))

    if exposed:
        findings.append(_finding('medium', 'author usernames are public',
                                 f'{", ".join(exposed[:MAX_USERS])} — seen via {", ".join(sources)}',
                                 id='WP-USR-001',
                                 recommendation='Hide the user list from visitors (REST API users, author '
                                                'archives, the users sitemap) and make sure no admin logs in '
                                                'with a public author name.'))
        checked.append({'item': 'users', 'status': 'problem', 'detail': f'{len(exposed)} public'})
    elif failed:
        checked.append({'item': 'users', 'status': 'not_checked', 'detail': 'a request failed'})
    else:
        checked.append({'item': 'users', 'status': 'ok', 'detail': 'not listed for visitors'})
    return {'exposed': exposed, 'sources': sources}


def _check_xmlrpc(base: str, findings: list, checked: list) -> None:
    page = _try(base + 'xmlrpc.php')
    if page is None:
        checked.append({'item': 'xmlrpc', 'status': 'not_checked', 'detail': 'the request failed'})
    elif _XMLRPC_GET in page.text:
        # a GET cannot tell whether WordPress turned the login methods off
        # (the xmlrpc_enabled filter): the endpoint is there, pingbacks too
        findings.append(_finding('low', 'xmlrpc.php is reachable',
                                 'XML-RPC answers requests; unless it is turned off inside WordPress, bots '
                                 'use it to try many passwords in one request (system.multicall), and its '
                                 'pingbacks are abused for attacks on other sites', id='WP-XMLRPC-001',
                                 recommendation='Block xmlrpc.php in the web server if no app or plugin '
                                                'needs it.'))
        checked.append({'item': 'xmlrpc', 'status': 'problem', 'detail': 'reachable'})
    else:
        checked.append({'item': 'xmlrpc', 'status': 'ok', 'detail': 'not answering'})


def _check_files(base: str, findings: list, checked: list) -> None:
    pages = {path: _try(base + path) for path in PUBLIC_FILES}
    unchecked = [path for path, page in pages.items() if page is None]

    def public(path, rx):
        page = pages[path]
        # only the verdict is kept: a config copy holds the database password
        return page is not None and page.status == 200 and bool(rx.search(page.text))

    log = public(LOG_FILE, _LOG_LINE)
    configs = [path for path in CONFIG_COPIES if public(path, _CONFIG_DEFINE)]
    listing = public(UPLOADS, _DIR_LISTING)
    info_files = [path for path, rx in ((README, _README), (LICENSE, _LICENSE)) if public(path, rx)]
    if configs:
        findings.append(_finding('critical', 'a copy of wp-config.php is public', ', '.join(configs),
                                 id='WP-FILE-002',
                                 recommendation='Delete the copies now, then change the database password '
                                                'and the keys and salts in wp-config.php: anyone could have '
                                                'read them.'))
    if log:
        findings.append(_finding('high', 'the WordPress debug log is public', LOG_FILE, id='WP-FILE-001',
                                 recommendation='Delete it and keep the log out of the site directory '
                                                '(WP_DEBUG_LOG off or a path outside it).'))
    if listing:
        findings.append(_finding('low', 'directory listing is on in uploads', UPLOADS, id='WP-FILE-003',
                                 recommendation='Turn directory listing off in the web server '
                                                '(nginx autoindex off, Apache Options -Indexes).'))
    if info_files:
        findings.append(_finding('low', 'WordPress service files are public', ', '.join(info_files),
                                 id='WP-FILE-004',
                                 recommendation='Delete them or deny them in the web server: they tell a bot '
                                                'the site runs WordPress.'))
    if unchecked:
        findings.append(_finding('info', f'{len(unchecked)} file(s) could not be checked',
                                 'the request failed twice (timeout or connection error), not confirmed '
                                 'absent: ' + ', '.join(unchecked), requires_manual_verification=True))

    def item(name, paths, found, ok_detail):
        if found:
            checked.append({'item': name, 'status': 'problem', 'detail': ', '.join(found)})
        elif any(path in unchecked for path in paths):
            checked.append({'item': name, 'status': 'not_checked', 'detail': 'the request failed'})
        else:
            checked.append({'item': name, 'status': 'ok', 'detail': ok_detail})

    item('debug_log', [LOG_FILE], [LOG_FILE] if log else [], 'not public')
    item('config_copies', CONFIG_COPIES, configs, 'no copy of wp-config.php is public')
    item('uploads_listing', [UPLOADS], [UPLOADS] if listing else [], 'no directory listing')
    item('readme_html', [README], [README] if README in info_files else [], 'not public')
    item('license_txt', [LICENSE], [LICENSE] if LICENSE in info_files else [], 'not public')


def _summary(findings: list) -> dict:
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'ok': 0}
    for f in findings:
        counts[f['severity']] += 1
    return counts


def _score(findings: list, checked: list) -> dict:
    gaps = [c['item'] for c in checked if c['status'] == 'not_checked']
    value = max(0, 100 - sum(PENALTY.get(f['severity'], 0) for f in findings))
    return {'value': value, 'complete': not gaps, 'not_checked': gaps}


def _verdict(findings: list, checked: list) -> str:
    severities = {f['severity'] for f in findings}
    if severities & {'critical', 'high'}:
        return 'danger'
    if severities & {'medium', 'low'}:
        return 'warn'
    if any(c['status'] == 'not_checked' for c in checked if c['item'] != 'plugin_vulns'):
        return 'incomplete'
    return 'ok'


@register(
    id='wordpress_external', label='WordPress check (no access)', category='wordpress', risk_level='PASSIVE',
    params=[{'name': 'url', 'type': 'text', 'label': 'Site URL', 'default': 'https://example.com', 'format': 'url'}],
    description='Checks a WordPress site the way any visitor sees it: the WordPress version against '
                'wordpress.org, plugins visible from outside and whether they are outdated, public author '
                'usernames, XML-RPC, a public debug log, wp-config copies and directory listing. GET requests '
                'only, no login.',
)
def check_wordpress_external(url='https://example.com') -> dict:
    base = _base_url(url)
    if base is None:
        return {'url': url, 'verdict': 'unreachable', 'error': f'could not parse URL: {url}'}
    try:
        home = _fetch_twice(base)
    except httpx.HTTPError as e:
        return {'url': base, 'verdict': 'unreachable', 'error': f'could not open {base}: {e}'}
    if not 200 <= home.status < 300:
        return {'url': base, 'verdict': 'unreachable', 'error': f'{base} answered HTTP {home.status}'}
    base = _base_url(home.url) or base   # follow the site's own redirect (http -> https, www)

    if not _is_wordpress(home, base):
        findings = [_finding('info', 'no sign of WordPress',
                             'no WordPress markers on the home page and no WordPress REST API; '
                             'nothing else was checked', confidence='medium')]
        return {'url': base, 'wordpress': False, 'verdict': 'not_wp', 'findings': findings,
                'summary': _summary(findings)}

    findings: list = []
    checked: list = []
    cert = _check_transport(home, base, findings, checked)
    core = _check_core(home, base, findings, checked)
    plugins, truncated = _check_plugins(home, base, core['version'], findings, checked)
    users = _check_users(base, findings, checked)
    _check_xmlrpc(base, findings, checked)
    _check_files(base, findings, checked)

    verdict = _verdict(findings, checked)
    if verdict == 'ok':
        findings.append(_finding('ok', 'no issues seen from outside'))
    return {'url': base, 'wordpress': True, 'verdict': verdict, 'score': _score(findings, checked),
            'core': core, 'certificate': cert, 'plugins': plugins, 'plugins_truncated': truncated,
            'users': users, 'checked': checked, 'findings': findings, 'summary': _summary(findings)}
