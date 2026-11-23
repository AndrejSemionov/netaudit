"""
wordpress_external: a WordPress site checked from outside, GET requests only
(docs/research/wordpress_audit.md §4, §6, contract C2).

No network: the site is a dict of URL -> response behind the module's one
fetch seam (wordpress._fetch), and the wordpress.org answers are faked at
wordpress_org.core_status / plugin_latest (tested in test_wordpress_org.py).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from urllib.parse import urljoin, urlparse

import httpx
import pytest

import netaudit_pkg.checks  # noqa: F401 - registers every check
from netaudit_pkg import wordfence, wordpress_org
from netaudit_pkg.checks import wordpress
from netaudit_pkg.registry import registry

BASE = 'https://blog.test/'
LATEST = '7.1.5'
PLAIN = '<html><head><title>Shop</title></head><body>hello</body></html>'
# what a well-kept site sends; tests about other parts use it so the headers stay out of the way
HOME_HEADERS = {'Strict-Transport-Security': 'max-age=31536000', 'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'SAMEORIGIN'}


def _wp_home(head='', body=''):
    return (f'<html><head>{head}<link rel="https://api.w.org/" href="{BASE}wp-json/">'
            f'<link rel="stylesheet" href="{BASE}wp-includes/css/dist/block-library/style.min.css"></head>'
            f'<body>{body}</body></html>')


GENERATOR = '<meta name="generator" content="WordPress {}">'


def _site(monkeypatch, pages, *, core=None, plugins=None, cert_days=90):
    """pages: url -> (status, headers, text) | Exception. Unlisted URLs answer 404,
    except http://blog.test/, which redirects to https like a well-kept site.
    With follow, redirects are followed the way the real _fetch does: on the
    same site only, otherwise OffSiteRedirect.
    cert_days: the certificate's days left, or an exception raised reading it.
    Returns the list of requested (url, follow) pairs."""
    requested = []
    pages.setdefault('http://blog.test/', (301, {'Location': BASE}, ''))

    def fetch(url, follow=True):
        requested.append((url, follow))
        start = url
        for _ in range(6):
            hit = pages.get(url)
            if isinstance(hit, Exception):
                raise hit
            if hit is None:
                return wordpress.Page(404, url, {}, '<html>Not Found</html>')
            status, headers, text = hit
            headers = {k.lower(): v for k, v in headers.items()}
            if follow and status in (301, 302, 303, 307, 308) and 'location' in headers:
                target = urljoin(url, headers['location'])
                if urlparse(target).scheme not in ('http', 'https') or not wordpress._same_site(target, start):
                    raise wordpress.OffSiteRedirect(f'redirected to another site: {urlparse(target).hostname}')
                url = target
                continue
            return wordpress.Page(status, url, headers, text)
        raise httpx.TooManyRedirects('loop')

    monkeypatch.setattr(wordpress, '_fetch', fetch)

    def not_after(host, port):
        if isinstance(cert_days, Exception):
            raise cert_days
        return datetime.now(UTC) + timedelta(days=cert_days, hours=1)

    monkeypatch.setattr(wordpress, '_cert_not_after', not_after)
    core = core or {}
    plugins = plugins or {}
    monkeypatch.setattr(wordpress_org, 'core_status',
                        lambda v: core.get(v, {'status': 'unknown', 'latest': LATEST, 'error': None}))
    monkeypatch.setattr(wordpress_org, 'plugin_latest',
                        lambda slug: plugins.get(slug, {'status': 'not_found', 'version': None, 'error': None}))
    monkeypatch.setattr(wordpress, '_wordfence_key', lambda: '')
    return requested


def _ids(result):
    return [f.get('id') for f in result.get('findings', [])]


def _by_id(result, fid):
    return next(f for f in result['findings'] if f.get('id') == fid)


def _checked(result):
    return {c['item']: c['status'] for c in result['checked']}


CORE_LATEST = {LATEST: {'status': 'latest', 'latest': LATEST, 'error': None}}


# --- registration -----------------------------------------------------------

def test_registered_as_a_passive_check_in_the_wordpress_category():
    spec = registry.get('wordpress_external')
    assert spec.category == 'wordpress'
    assert spec.risk_level == 'PASSIVE'
    assert [p['name'] for p in spec.params] == ['url']
    assert spec.params[0]['format'] == 'url'


@pytest.mark.parametrize('given', ['blog.test', 'https://blog.test', 'https://blog.test/'])
def test_site_address_becomes_a_base_url(monkeypatch, given):
    requested = _site(monkeypatch, {BASE: (200, {}, PLAIN)})
    result = wordpress.check_wordpress_external(given)
    assert result['url'] == BASE
    assert requested[0] == (BASE, True)


# --- the site does not answer / is not WordPress ----------------------------

def test_unreachable_site_is_an_error_not_a_verdict(monkeypatch):
    _site(monkeypatch, {BASE: httpx.ConnectError('refused')})
    result = wordpress.check_wordpress_external(BASE)
    assert result['verdict'] == 'unreachable'
    assert 'refused' in result['error']
    assert not [f for f in result.get('findings', []) if f['severity'] == 'ok']


def test_http_error_status_is_an_error(monkeypatch):
    _site(monkeypatch, {BASE: (503, {}, 'busy')})
    result = wordpress.check_wordpress_external(BASE)
    assert result['verdict'] == 'unreachable'
    assert '503' in result['error']


def test_site_without_wordpress_signs_is_not_applicable(monkeypatch):
    requested = _site(monkeypatch, {BASE: (200, {}, PLAIN)})
    result = wordpress.check_wordpress_external(BASE)
    assert result['verdict'] == 'not_wp'
    assert result['wordpress'] is False
    assert 'error' not in result
    assert not [f for f in result['findings'] if f['severity'] == 'ok']
    # one look at the REST root, nothing WordPress-specific probed on a non-WordPress site
    assert [u for u, _ in requested] == [BASE, BASE + '?rest_route=/']


def test_rest_root_alone_identifies_wordpress(monkeypatch):
    rest = json.dumps({'name': 'Blog', 'namespaces': ['oembed/1.0', 'wp/v2']})
    _site(monkeypatch, {BASE: (200, {}, PLAIN), BASE + '?rest_route=/': (200, {}, rest)})
    result = wordpress.check_wordpress_external(BASE)
    assert result['wordpress'] is True
    assert result['verdict'] != 'not_wp'


# --- core ---------------------------------------------------------------------

def test_insecure_core_from_the_generator_tag_is_high(monkeypatch):
    _site(monkeypatch, {BASE: (200, HOME_HEADERS, _wp_home(GENERATOR.format('6.8.3')))},
          core={'6.8.3': {'status': 'insecure', 'latest': LATEST, 'error': None}})
    result = wordpress.check_wordpress_external(BASE)
    assert result['core'] == {'version': '6.8.3', 'source': 'generator', 'status': 'insecure', 'latest': LATEST}
    finding = _by_id(result, 'WP-CORE-001')
    assert finding['severity'] == 'high'
    assert '6.8.3' in finding['title'] and LATEST in finding['recommendation']
    assert result['verdict'] == 'danger'
    assert _checked(result)['core'] == 'problem'
    assert result['score']['value'] == 75     # 100 - 25 for a high finding


def test_core_version_from_the_feed_when_the_tag_is_removed(monkeypatch):
    feed = f'<rss><channel><generator>https://wordpress.org/?v={LATEST}</generator></channel></rss>'
    _site(monkeypatch, {BASE: (200, HOME_HEADERS, _wp_home()), BASE + '?feed=rss2': (200, {}, feed)}, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    assert result['core']['version'] == LATEST
    assert result['core']['source'] == 'feed'
    assert not {'WP-CORE-001', 'WP-CORE-002'} & set(_ids(result))
    assert _checked(result)['core'] == 'ok'


def test_outdated_core_is_low(monkeypatch):
    _site(monkeypatch, {BASE: (200, HOME_HEADERS, _wp_home(GENERATOR.format('7.0.9')))},
          core={'7.0.9': {'status': 'outdated', 'latest': LATEST, 'error': None}})
    result = wordpress.check_wordpress_external(BASE)
    assert _by_id(result, 'WP-CORE-002')['severity'] == 'low'


def test_hidden_core_version_is_never_up_to_date(monkeypatch):
    _site(monkeypatch, {BASE: (200, HOME_HEADERS, _wp_home())})
    result = wordpress.check_wordpress_external(BASE)
    assert result['core']['version'] is None
    assert _checked(result)['core'] == 'not_checked'
    gap = [f for f in result['findings'] if f['severity'] == 'info' and f.get('requires_manual_verification')]
    assert any('version' in f['title'] for f in gap)
    assert result['verdict'] == 'incomplete'


@pytest.mark.parametrize('status', [
    {'status': 'error', 'latest': None, 'error': 'wordpress.org: HTTP 503'},
    {'status': 'unknown', 'latest': LATEST, 'error': None},
])
def test_core_status_not_known_is_not_checked(monkeypatch, status):
    _site(monkeypatch, {BASE: (200, HOME_HEADERS, _wp_home(GENERATOR.format('7.2-RC2')))}, core={'7.2-RC2': status})
    result = wordpress.check_wordpress_external(BASE)
    assert result['core']['version'] == '7.2-RC2'
    assert _checked(result)['core'] == 'not_checked'
    assert not {'WP-CORE-001', 'WP-CORE-002'} & set(_ids(result))
    assert result['verdict'] == 'incomplete'


# --- plugins ------------------------------------------------------------------

PLUGIN_HTML = (
    f'<link rel="stylesheet" href="{BASE}wp-content/plugins/contact-form-7/includes/css/styles.css?ver=6.2.5">'
    '<script src="/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=4.1.0"></script>'
    '<script src="https://cdn.other.test/wp-content/plugins/not-this-site/x.js"></script>'
    '<link rel="stylesheet" href="//blog.test/wp-content/plugins/premium-thing/a.css">'
)


def _plugin_pages():
    return {
        BASE: (200, HOME_HEADERS, _wp_home(GENERATOR.format(LATEST), PLUGIN_HTML)),
        BASE + 'wp-content/plugins/contact-form-7/readme.txt':
            (200, {'Content-Type': 'text/plain'}, '=== Contact Form 7 ===\nStable tag: 6.2.5\n'),
        BASE + 'wp-content/plugins/elementor/readme.txt':
            (200, {'Content-Type': 'text/plain'}, '=== Elementor ===\nstable tag: 4.1.0\n'),
    }


PLUGIN_LATEST = {
    'contact-form-7': {'status': 'ok', 'version': '6.2.5', 'error': None},
    'elementor': {'status': 'ok', 'version': '4.4.1', 'error': None},
}


def test_visible_plugins_with_versions_and_the_latest(monkeypatch):
    _site(monkeypatch, _plugin_pages(), core=CORE_LATEST, plugins=PLUGIN_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    plugins = {p['slug']: p for p in result['plugins']}
    assert sorted(plugins) == ['contact-form-7', 'elementor', 'premium-thing']   # another host's plugin is not this site's
    assert plugins['contact-form-7'] == {'slug': 'contact-form-7', 'version': '6.2.5', 'version_source': 'readme.txt',
                                         'latest': '6.2.5', 'status': 'current', 'vulns': None}   # no Wordfence key
    assert plugins['elementor']['status'] == 'outdated'
    assert plugins['premium-thing'] == {'slug': 'premium-thing', 'version': None, 'version_source': None,
                                        'latest': None, 'status': 'unknown', 'vulns': None}
    outdated = _by_id(result, 'WP-PLG-001:elementor')
    assert outdated['severity'] == 'medium'
    assert outdated['confidence'] == 'medium'    # the version comes from readme.txt
    assert '4.1.0' in outdated['title'] and '4.4.1' in outdated['recommendation']
    assert [i for i in _ids(result) if i and i.startswith('WP-PLG-')] == ['WP-PLG-001:elementor']
    assert result['plugins_truncated'] is False
    assert result['verdict'] == 'warn'


def test_readme_trunk_is_not_a_version(monkeypatch):
    pages = _plugin_pages()
    pages[BASE + 'wp-content/plugins/elementor/readme.txt'] = (200, {}, 'Stable tag: trunk\n')
    _site(monkeypatch, pages, core=CORE_LATEST, plugins=PLUGIN_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    elementor = next(p for p in result['plugins'] if p['slug'] == 'elementor')
    assert elementor['version'] is None
    assert elementor['status'] == 'unknown'
    assert 'WP-PLG-001:elementor' not in _ids(result)


def test_latest_plugin_version_not_known_is_not_checked(monkeypatch):
    plugins = dict(PLUGIN_LATEST, elementor={'status': 'error', 'version': None, 'error': 'timeout'})
    _site(monkeypatch, _plugin_pages(), core=CORE_LATEST, plugins=plugins)
    result = wordpress.check_wordpress_external(BASE)
    elementor = next(p for p in result['plugins'] if p['slug'] == 'elementor')
    assert elementor['status'] == 'not_checked'
    assert 'WP-PLG-001:elementor' not in _ids(result)


def test_plugin_list_is_capped(monkeypatch):
    body = ''.join(f'<script src="/wp-content/plugins/p{i:02d}/x.js"></script>' for i in range(40))
    requested = _site(monkeypatch, {BASE: (200, HOME_HEADERS, _wp_home(GENERATOR.format(LATEST), body))}, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    assert len(result['plugins']) == wordpress.MAX_PLUGINS
    assert result['plugins_truncated'] is True
    assert len([u for u, _ in requested if u.endswith('/readme.txt')]) == wordpress.MAX_PLUGINS


def test_odd_plugin_paths_are_not_slugs(monkeypatch):
    body = ('<script src="/wp-content/plugins/../../etc/x.js"></script>'
            '<script src="/wp-content/plugins/%2e%2e/x.js"></script>'
            '<script src="/wp-content/plugins/ok-slug/x.js"></script>')
    _site(monkeypatch, {BASE: (200, HOME_HEADERS, _wp_home(GENERATOR.format(LATEST), body))}, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    assert [p['slug'] for p in result['plugins']] == ['ok-slug']


# Seen on a real, hardened site (sysadmin.courses, 2026-11-22): readme.txt
# answers 403, the core version is hidden, but Elementor and WPML print their
# own generator tags, and a plugin's own files carry ?ver=<its version>.
REAL_HEAD = (
    '<meta name="generator" content="WPML ver:4.9.2.1 stt:1,32,45;" />'
    '<meta name="generator" content="Elementor 4.4.1; features: additional_custom_breakpoints; '
    'settings: css_print_method-external">'
)
REAL_BODY = (
    '<link rel="stylesheet" href="/wp-content/plugins/elementor/assets/css/frontend.min.css?ver=4.4.1">'
    '<script src="/wp-content/plugins/elementor/assets/lib/swiper/v8/swiper.min.js?ver=8.4.5"></script>'
    '<script src="/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=4.4.1"></script>'
    '<link rel="stylesheet" href="/wp-content/plugins/learnpress/assets/css/learnpress.min.css?ver=4.5.0">'
    '<script src="/wp-content/plugins/learnpress/assets/js/dist/loadAJAX.min.js?ver=4.5.0"></script>'
    '<script src="/wp-content/plugins/sitepress-multilingual-cms/res/js/cookies.js?ver=492100"></script>'
    '<script src="/wp-content/plugins/one-file/x.js?ver=2.0.1"></script>'
    '<script src="/wp-content/plugins/split/a.js?ver=1.2.0"></script>'
    '<script src="/wp-content/plugins/split/b.js?ver=5.57.0"></script>'
)


def _real_pages():
    pages = {BASE: (200, HOME_HEADERS, _wp_home(REAL_HEAD, REAL_BODY))}
    for slug in ('elementor', 'learnpress', 'sitepress-multilingual-cms', 'one-file', 'split'):
        pages[f'{BASE}wp-content/plugins/{slug}/readme.txt'] = (403, {}, 'Forbidden')
    return pages


REAL_LATEST = {
    'elementor': {'status': 'ok', 'version': '4.4.1', 'error': None},
    'learnpress': {'status': 'ok', 'version': '4.6.2', 'error': None},
    'one-file': {'status': 'ok', 'version': '3.0.0', 'error': None},
    'split': {'status': 'ok', 'version': '9.9.9', 'error': None},
}


def _plugins(result):
    return {p['slug']: p for p in result['plugins']}


def test_plugin_version_from_its_own_generator_tag(monkeypatch):
    _site(monkeypatch, _real_pages(), core=CORE_LATEST, plugins=REAL_LATEST)
    plugins = _plugins(wordpress.check_wordpress_external(BASE))
    assert (plugins['elementor']['version'], plugins['elementor']['version_source']) == ('4.4.1', 'generator')
    assert plugins['elementor']['status'] == 'current'
    wpml = plugins['sitepress-multilingual-cms']
    assert (wpml['version'], wpml['version_source']) == ('4.9.2.1', 'generator')
    assert wpml['status'] == 'unknown'          # premium: not on wordpress.org


def test_plugin_version_from_the_ver_of_its_own_files(monkeypatch):
    _site(monkeypatch, _real_pages(), core=CORE_LATEST, plugins=REAL_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    learnpress = _plugins(result)['learnpress']
    assert (learnpress['version'], learnpress['version_source']) == ('4.5.0', 'asset ver')
    assert learnpress['status'] == 'outdated'
    finding = _by_id(result, 'WP-PLG-001:learnpress')
    assert finding['confidence'] == 'low'        # ?ver= is the weakest source
    assert '?ver=' in finding['detail']


def test_ver_without_two_agreeing_files_is_not_a_version(monkeypatch):
    # one file is not enough (a bundled library has its own ?ver=), two
    # different values are no majority, and a number without a dot is a build id
    _site(monkeypatch, _real_pages(), core=CORE_LATEST, plugins=REAL_LATEST)
    plugins = _plugins(wordpress.check_wordpress_external(BASE))
    for slug in ('one-file', 'split'):
        assert plugins[slug]['version'] is None, slug
        assert plugins[slug]['status'] == 'unknown', slug


def test_ver_equal_to_the_core_version_is_not_the_plugin_s(monkeypatch):
    # a plugin that registers its files without a version gets WordPress's own
    body = ('<script src="/wp-content/plugins/lazy/a.js?ver=7.1.5"></script>'
            '<script src="/wp-content/plugins/lazy/b.js?ver=7.1.5"></script>')
    _site(monkeypatch, {BASE: (200, HOME_HEADERS, _wp_home(GENERATOR.format(LATEST), body))}, core=CORE_LATEST)
    lazy = _plugins(wordpress.check_wordpress_external(BASE))['lazy']
    assert lazy['version'] is None


def test_a_generator_tag_alone_is_enough_to_list_the_plugin(monkeypatch):
    _site(monkeypatch, {BASE: (200, HOME_HEADERS, _wp_home(GENERATOR.format(LATEST) + REAL_HEAD))}, core=CORE_LATEST,
          plugins=REAL_LATEST)
    plugins = _plugins(wordpress.check_wordpress_external(BASE))
    assert sorted(plugins) == ['elementor', 'sitepress-multilingual-cms']


def test_without_a_wordfence_key_vulnerabilities_are_not_checked(monkeypatch):
    # never "no vulnerabilities" without the database (contract C3)
    _site(monkeypatch, _plugin_pages(), core=CORE_LATEST, plugins=PLUGIN_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    item = next(c for c in result['checked'] if c['item'] == 'vulns')
    assert item['status'] == 'not_checked'
    assert 'no Wordfence API key' in item['detail']
    assert all(p['vulns'] is None for p in result['plugins'])


# --- usernames ----------------------------------------------------------------

def _home_latest():
    return {BASE: (200, HOME_HEADERS, _wp_home(GENERATOR.format(LATEST)))}


def test_author_usernames_from_the_rest_api(monkeypatch):
    pages = _home_latest()
    pages[BASE + '?rest_route=/wp/v2/users'] = (
        200, {'Content-Type': 'application/json'},
        json.dumps([{'id': 1, 'slug': 'admin-anna', 'name': 'Anna'}, {'id': 2, 'slug': 'bob', 'name': 'Bob'}]))
    _site(monkeypatch, pages, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    assert result['users'] == {'exposed': ['admin-anna', 'bob'], 'sources': ['rest']}
    finding = _by_id(result, 'WP-USR-001')
    assert finding['severity'] == 'medium'
    assert 'admin-anna' in finding['detail']
    assert _checked(result)['users'] == 'problem'


def test_author_redirect_and_sitemap_expose_usernames(monkeypatch):
    pages = _home_latest()
    pages[BASE + '?author=1'] = (301, {'Location': BASE + 'author/carol/'}, '')
    pages[BASE + '?sitemap=users&paged=1'] = (
        200, {'Content-Type': 'application/xml'},
        f'<urlset><url><loc>{BASE}author/dave/</loc></url></urlset>')
    requested = _site(monkeypatch, pages, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    assert result['users'] == {'exposed': ['carol', 'dave'], 'sources': ['author', 'sitemap']}
    assert (BASE + '?author=1', False) in requested   # the redirect itself is the evidence


def test_no_public_usernames_no_finding(monkeypatch):
    pages = _home_latest()
    pages[BASE + '?rest_route=/wp/v2/users'] = (401, {}, '{"code":"rest_forbidden"}')
    _site(monkeypatch, pages, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    assert result['users'] == {'exposed': [], 'sources': []}
    assert 'WP-USR-001' not in _ids(result)
    assert _checked(result)['users'] == 'ok'


# --- XML-RPC and public files -------------------------------------------------

def test_xmlrpc_enabled_is_low(monkeypatch):
    pages = _home_latest()
    # what WordPress answers to a GET (wp-includes/IXR/class-IXR-server.php)
    pages[BASE + 'xmlrpc.php'] = (405, {'Allow': 'POST'}, 'XML-RPC server accepts POST requests only.')
    _site(monkeypatch, pages, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    assert _by_id(result, 'WP-XMLRPC-001')['severity'] == 'low'
    assert _checked(result)['xmlrpc'] == 'problem'


def test_public_debug_log_is_high(monkeypatch):
    pages = _home_latest()
    pages[BASE + 'wp-content/debug.log'] = (
        200, {'Content-Type': 'text/plain'},
        '[22-Nov-2026 10:00:00 UTC] PHP Warning:  Undefined variable $x in /var/www/a.php on line 3\n')
    _site(monkeypatch, pages, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    finding = _by_id(result, 'WP-FILE-001')
    assert finding['severity'] == 'high'
    assert 'wp-content/debug.log' in finding['detail']
    assert result['verdict'] == 'danger'


def test_soft_404_is_not_a_public_file(monkeypatch):
    # many sites answer 200 with their own "not found" page for any path
    pages = _home_latest()
    soft = (200, {'Content-Type': 'text/html'}, '<html><body>Page not found</body></html>')
    for path in wordpress.PUBLIC_FILES:
        pages[BASE + path] = soft
    _site(monkeypatch, pages, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    assert not [i for i in _ids(result) if i and i.startswith('WP-FILE-')]
    statuses = _checked(result)
    for item in ('debug_log', 'config_copies', 'uploads_listing', 'readme_html', 'license_txt'):
        assert statuses[item] == 'ok', item


def test_wp_config_backup_is_critical_and_its_content_is_not_kept(monkeypatch):
    pages = _home_latest()
    pages[BASE + 'wp-config.php.bak'] = (
        200, {'Content-Type': 'text/plain'},
        "<?php\ndefine( 'DB_NAME', 'shop' );\ndefine( 'DB_PASSWORD', 's3cr3t-Pa55' );\n")
    _site(monkeypatch, pages, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    finding = _by_id(result, 'WP-FILE-002')
    assert finding['severity'] == 'critical'
    assert 'wp-config.php.bak' in finding['detail']
    assert 's3cr3t-Pa55' not in json.dumps(result)


def test_uploads_directory_listing_is_low(monkeypatch):
    pages = _home_latest()
    pages[BASE + 'wp-content/uploads/'] = (200, {}, '<html><title>Index of /wp-content/uploads</title></html>')
    _site(monkeypatch, pages, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    assert _by_id(result, 'WP-FILE-003')['severity'] == 'low'


def test_failed_probe_is_not_checked_not_absent(monkeypatch):
    pages = _home_latest()
    pages[BASE + 'wp-content/debug.log'] = httpx.ReadTimeout('slow')
    _site(monkeypatch, pages, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    gap = [f for f in result['findings'] if f['severity'] == 'info' and f.get('requires_manual_verification')]
    assert any('wp-content/debug.log' in f['detail'] for f in gap)
    assert _checked(result)['debug_log'] == 'not_checked'
    assert result['verdict'] == 'incomplete'


# --- the whole result -----------------------------------------------------------

def test_clean_site_is_incomplete_while_plugin_vulnerabilities_are_not_checked(monkeypatch):
    # review #59 pass 1 (3): every part counts toward the verdict, plugin
    # vulnerabilities too - "ok" needs the vulnerability database (contract C3)
    _site(monkeypatch, _home_latest(), core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    assert result['verdict'] == 'incomplete'
    assert not [f for f in result['findings'] if f['severity'] == 'ok']
    statuses = _checked(result)
    assert statuses == {
        'https': 'ok', 'http_redirect': 'ok', 'certificate': 'ok', 'hsts': 'ok', 'nosniff': 'ok', 'framing': 'ok',
        'core': 'ok', 'plugins': 'ok', 'plugin_versions': 'ok', 'vulns': 'not_checked', 'users': 'ok',
        'xmlrpc': 'ok',
        'debug_log': 'ok', 'config_copies': 'ok', 'uploads_listing': 'ok', 'readme_html': 'ok', 'license_txt': 'ok'}
    # the score says what it could not count
    assert result['score'] == {'value': 100, 'complete': False, 'not_checked': ['vulns']}


def test_only_the_site_itself_is_requested(monkeypatch):
    requested = _site(monkeypatch, _plugin_pages(), core=CORE_LATEST, plugins=PLUGIN_LATEST)
    wordpress.check_wordpress_external(BASE)
    assert requested
    assert {urlparse(url).hostname for url, _ in requested} == {'blog.test'}


# --- HTTPS, certificate, headers (the reference's "what is fine", and more) ----

def test_http_that_does_not_redirect_to_https_is_medium(monkeypatch):
    pages = _home_latest()
    pages['http://blog.test/'] = (200, {}, PLAIN)
    requested = _site(monkeypatch, pages, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    assert _by_id(result, 'WP-TLS-002')['severity'] == 'medium'
    assert _checked(result)['http_redirect'] == 'problem'
    assert ('http://blog.test/', True) in requested


def test_http_redirect_to_https_is_fine(monkeypatch):
    pages = _home_latest()
    pages['http://blog.test/'] = (301, {'Location': BASE}, '')
    _site(monkeypatch, pages, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    assert _checked(result)['http_redirect'] == 'ok'
    assert 'WP-TLS-002' not in _ids(result)


def test_site_only_on_http_is_high(monkeypatch):
    http_base = 'http://blog.test/'
    home = (200, HOME_HEADERS, _wp_home(GENERATOR.format(LATEST)))
    _site(monkeypatch, {http_base: home}, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(http_base)
    assert _by_id(result, 'WP-TLS-001')['severity'] == 'high'
    statuses = _checked(result)
    assert statuses['https'] == 'problem'
    assert 'certificate' not in statuses and 'http_redirect' not in statuses


def test_certificate_valid_until_and_days_left(monkeypatch):
    _site(monkeypatch, _home_latest(), core=CORE_LATEST, cert_days=43)
    result = wordpress.check_wordpress_external(BASE)
    cert = next(c for c in result['checked'] if c['item'] == 'certificate')
    assert cert['status'] == 'ok'
    assert '43 days left' in cert['detail']
    assert result['certificate']['days_left'] == 43


def test_certificate_ending_soon_is_medium(monkeypatch):
    _site(monkeypatch, _home_latest(), core=CORE_LATEST, cert_days=10)
    result = wordpress.check_wordpress_external(BASE)
    finding = _by_id(result, 'WP-TLS-003')
    assert finding['severity'] == 'medium'
    assert '10 days' in finding['title']
    assert _checked(result)['certificate'] == 'problem'


def test_certificate_not_read_is_not_checked(monkeypatch):
    _site(monkeypatch, _home_latest(), core=CORE_LATEST, cert_days=OSError('reset'))
    result = wordpress.check_wordpress_external(BASE)
    assert _checked(result)['certificate'] == 'not_checked'
    assert result['verdict'] == 'incomplete'


def test_missing_security_headers_are_low(monkeypatch):
    _site(monkeypatch, {BASE: (200, {}, _wp_home(GENERATOR.format(LATEST)))}, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    for fid in ('WP-HDR-001', 'WP-HDR-002', 'WP-HDR-003'):
        assert _by_id(result, fid)['severity'] == 'low', fid
    statuses = _checked(result)
    assert (statuses['hsts'], statuses['nosniff'], statuses['framing']) == ('problem', 'problem', 'problem')
    assert result['score']['value'] == 91     # 100 - 3 x 3


def test_csp_frame_ancestors_protects_from_framing(monkeypatch):
    headers = {'Strict-Transport-Security': 'max-age=63072000', 'X-Content-Type-Options': 'nosniff',
               'Content-Security-Policy': "default-src 'self'; frame-ancestors 'self'"}
    _site(monkeypatch, {BASE: (200, headers, _wp_home(GENERATOR.format(LATEST)))}, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    assert _checked(result)['framing'] == 'ok'
    assert 'WP-HDR-003' not in _ids(result)


def test_public_readme_and_license_are_low(monkeypatch):
    pages = _home_latest()
    pages[BASE + 'readme.html'] = (200, {}, '<html><head><title>WordPress &#8250; ReadMe</title></head></html>')
    pages[BASE + 'license.txt'] = (200, {}, 'WordPress - Web publishing software\n\nCopyright 2011-2026')
    _site(monkeypatch, pages, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    finding = _by_id(result, 'WP-FILE-004')
    assert finding['severity'] == 'low'
    assert 'readme.html' in finding['detail'] and 'license.txt' in finding['detail']
    statuses = _checked(result)
    assert (statuses['readme_html'], statuses['license_txt']) == ('problem', 'problem')


# --- the score and a flaky network ------------------------------------------------

def test_not_wordpress_and_unreachable_have_no_score(monkeypatch):
    _site(monkeypatch, {BASE: (200, {}, PLAIN)})
    assert 'score' not in wordpress.check_wordpress_external(BASE)
    _site(monkeypatch, {BASE: httpx.ConnectError('refused')})
    assert 'score' not in wordpress.check_wordpress_external(BASE)


def test_score_counts_what_was_not_checked(monkeypatch):
    _site(monkeypatch, {BASE: (200, HOME_HEADERS, _wp_home())})   # the version is hidden
    result = wordpress.check_wordpress_external(BASE)
    assert result['score'] == {'value': 100, 'complete': False, 'not_checked': ['core', 'vulns']}


def test_a_request_that_fails_once_is_tried_again(monkeypatch):
    _site(monkeypatch, _home_latest(), core=CORE_LATEST)
    fetch = wordpress._fetch
    failed = []

    def flaky(url, follow=True):
        if url.endswith('debug.log') and not failed:
            failed.append(url)
            raise httpx.ConnectError('blip')
        return fetch(url, follow)

    monkeypatch.setattr(wordpress, '_fetch', flaky)
    result = wordpress.check_wordpress_external(BASE)
    assert failed
    assert _checked(result)['debug_log'] == 'ok'


# --- review #59 pass 1 ----------------------------------------------------------
# (1) a server error or a rate limit is not an answer: "not checked", never "closed"

@pytest.mark.parametrize('status', [500, 502, 503, 429])
def test_server_errors_are_not_checked_not_closed(monkeypatch, status):
    pages = _home_latest()
    error = (status, {}, 'upstream error')
    for path in wordpress.PUBLIC_FILES:
        pages[BASE + path] = error
    for url in (BASE + '?rest_route=/wp/v2/users', BASE + '?author=1', BASE + '?sitemap=users&paged=1',
                BASE + 'xmlrpc.php', 'http://blog.test/'):
        pages[url] = error
    _site(monkeypatch, pages, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    statuses = _checked(result)
    for item in ('debug_log', 'config_copies', 'uploads_listing', 'readme_html', 'license_txt',
                 'users', 'xmlrpc', 'http_redirect'):
        assert statuses[item] == 'not_checked', item
    gap = [f for f in result['findings'] if f['severity'] == 'info' and f.get('requires_manual_verification')]
    assert any(f'HTTP {status}' in f['detail'] for f in gap)
    assert result['verdict'] == 'incomplete'


def test_users_answer_that_is_not_a_list_is_not_checked(monkeypatch):
    pages = _home_latest()
    pages[BASE + '?rest_route=/wp/v2/users'] = (200, {'Content-Type': 'text/html'}, '<html>home page</html>')
    _site(monkeypatch, pages, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    assert _checked(result)['users'] == 'not_checked'


# (3) a plugin that could not be judged is a gap, not "fine"

def _item(result, name):
    return next(c for c in result['checked'] if c['item'] == name)


def test_plugin_without_a_known_version_is_a_gap(monkeypatch):
    body = '<script src="/wp-content/plugins/mystery/x.js"></script>'
    _site(monkeypatch, {BASE: (200, HOME_HEADERS, _wp_home(GENERATOR.format(LATEST), body))}, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    # nothing could be judged: neither "no outdated plugins" nor "all versions known"
    assert _item(result, 'plugins')['status'] == 'not_checked'
    versions = _item(result, 'plugin_versions')
    assert versions['status'] == 'not_checked' and 'mystery' in versions['detail']
    assert result['score']['not_checked'] == ['plugins', 'plugin_versions', 'vulns']


def test_plugin_missing_from_wordpress_org_is_a_gap(monkeypatch):
    # WPML: the version is known, the latest is not
    _site(monkeypatch, {BASE: (200, HOME_HEADERS, _wp_home(GENERATOR.format(LATEST) + REAL_HEAD))},
          core=CORE_LATEST, plugins={'elementor': {'status': 'ok', 'version': '4.4.1', 'error': None}})
    result = wordpress.check_wordpress_external(BASE)
    assert _item(result, 'plugins')['status'] == 'ok'          # elementor was judged: current
    versions = _item(result, 'plugin_versions')
    assert versions['status'] == 'not_checked' and 'sitepress-multilingual-cms' in versions['detail']


def _many_plugins(n, outdated=()):
    body = ''.join(f'<script src="/wp-content/plugins/p{i:02d}/x.js?ver=1.0.{i}"></script>'
                   f'<script src="/wp-content/plugins/p{i:02d}/y.js?ver=1.0.{i}"></script>' for i in range(n))
    latest = {f'p{i:02d}': {'status': 'ok', 'version': f'1.0.{i}' if i not in outdated else '9.0.0', 'error': None}
              for i in range(n)}
    return {BASE: (200, HOME_HEADERS, _wp_home(GENERATOR.format(LATEST), body))}, latest


def test_capped_plugin_list_is_a_gap(monkeypatch):
    pages, latest = _many_plugins(30)
    _site(monkeypatch, pages, core=CORE_LATEST, plugins=latest)
    result = wordpress.check_wordpress_external(BASE)
    assert {p['status'] for p in result['plugins']} == {'current'}
    assert _item(result, 'plugins')['status'] == 'ok'
    versions = _item(result, 'plugin_versions')
    assert versions['status'] == 'not_checked' and str(wordpress.MAX_PLUGINS) in versions['detail']


# review #59 pass 2 (3): a finding about one plugin does not hide the gaps about others

def test_outdated_and_unjudged_plugins_show_both(monkeypatch):
    _site(monkeypatch, _plugin_pages(), core=CORE_LATEST, plugins=PLUGIN_LATEST)   # elementor outdated, premium-thing unknown
    result = wordpress.check_wordpress_external(BASE)
    assert 'WP-PLG-001:elementor' in _ids(result)
    assert result['verdict'] == 'warn'
    assert _item(result, 'plugins')['status'] == 'problem'
    versions = _item(result, 'plugin_versions')
    assert versions['status'] == 'not_checked' and 'premium-thing' in versions['detail']
    assert 'plugin_versions' in result['score']['not_checked']


def test_outdated_plugin_in_a_capped_list_shows_both(monkeypatch):
    pages, latest = _many_plugins(30, outdated={3})
    _site(monkeypatch, pages, core=CORE_LATEST, plugins=latest)
    result = wordpress.check_wordpress_external(BASE)
    assert _item(result, 'plugins')['status'] == 'problem'
    assert 'plugin_versions' in result['score']['not_checked']


# review #59 pass 2 (1): detection without an answer is not "not WordPress"

@pytest.mark.parametrize('status', [500, 502, 429])
def test_detection_without_an_answer_is_not_checked(monkeypatch, status):
    _site(monkeypatch, {BASE: (200, HOME_HEADERS, PLAIN), BASE + '?rest_route=/': (status, {}, 'busy')})
    result = wordpress.check_wordpress_external(BASE)
    assert result['wordpress'] is None
    assert result['verdict'] == 'incomplete'
    assert 'score' not in result
    [gap] = result['findings']
    assert gap['severity'] == 'info' and gap.get('requires_manual_verification')
    assert f'HTTP {status}' in gap['detail']


def test_static_page_with_a_rest_404_is_still_not_wordpress(monkeypatch):
    _site(monkeypatch, {BASE: (200, HOME_HEADERS, PLAIN), BASE + '?rest_route=/': (404, {}, 'Not Found')})
    assert wordpress.check_wordpress_external(BASE)['verdict'] == 'not_wp'


# review #59 pass 2 (2): only a redirect of this site to https proves the redirect

def test_http_redirect_to_another_https_site_is_not_proof(monkeypatch):
    pages = _home_latest()
    pages['http://blog.test/'] = (302, {'Location': 'https://other.test/'}, '')
    _site(monkeypatch, pages, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    item = _item(result, 'http_redirect')
    assert item['status'] == 'not_checked' and 'other.test' in item['detail']


def test_http_redirect_that_stays_on_http_is_a_problem(monkeypatch):
    pages = _home_latest()
    pages['http://blog.test/'] = (302, {'Location': '/home'}, '')
    pages['http://blog.test/home'] = (200, {}, PLAIN)
    _site(monkeypatch, pages, core=CORE_LATEST)
    result = wordpress.check_wordpress_external(BASE)
    assert _item(result, 'http_redirect')['status'] == 'problem'
    assert 'WP-TLS-002' in _ids(result)


def test_http_redirect_chain_that_reaches_https_is_fine(monkeypatch):
    pages = _home_latest()
    pages['http://blog.test/'] = (302, {'Location': '/start'}, '')
    pages['http://blog.test/start'] = (301, {'Location': 'https://www.blog.test/'}, '')
    pages['https://www.blog.test/'] = (200, {}, PLAIN)
    _site(monkeypatch, pages, core=CORE_LATEST)
    assert _item(wordpress.check_wordpress_external(BASE), 'http_redirect')['status'] == 'ok'


def test_http_without_a_redirect_or_a_page_is_not_proof(monkeypatch):
    pages = _home_latest()
    pages['http://blog.test/'] = (403, {}, 'Forbidden')
    _site(monkeypatch, pages, core=CORE_LATEST)
    item = _item(wordpress.check_wordpress_external(BASE), 'http_redirect')
    assert item['status'] == 'not_checked' and '403' in item['detail']


# the same rule for the core version: a feed that did not answer is named

def test_hidden_core_names_a_feed_error(monkeypatch):
    _site(monkeypatch, {BASE: (200, HOME_HEADERS, _wp_home()), BASE + '?feed=rss2': (503, {}, 'busy')})
    core = _item(wordpress.check_wordpress_external(BASE), 'core')
    assert core['status'] == 'not_checked' and 'HTTP 503' in core['detail']


# (4) a redirect never leaves the site: checked before each hop, through the real _fetch

def _transport(monkeypatch, routes):
    """routes: url -> (status, headers, text). Returns the requested URLs."""
    seen = []

    def handler(request):
        url = str(request.url)
        seen.append(url)
        status, headers, text = routes.get(url, (404, {}, 'not found'))
        return httpx.Response(status, headers=headers, text=text)

    monkeypatch.setattr(wordpress, '_TRANSPORT', httpx.MockTransport(handler))
    return seen


def test_redirect_to_another_site_is_not_followed(monkeypatch):
    seen = _transport(monkeypatch, {
        'https://site.test/wp-config.php.bak': (302, {'Location': 'http://other.test/private'}, ''),
        'http://other.test/private': (200, {}, "define('DB_PASSWORD', 'x');"),
    })
    with pytest.raises(wordpress.OffSiteRedirect, match='other.test'):
        wordpress._fetch('https://site.test/wp-config.php.bak')
    assert seen == ['https://site.test/wp-config.php.bak']


@pytest.mark.parametrize('location', ['ftp://site.test/x', 'javascript:alert(1)'])
def test_redirect_to_another_scheme_is_not_followed(monkeypatch, location):
    _transport(monkeypatch, {'https://site.test/a': (301, {'Location': location}, '')})
    with pytest.raises(wordpress.OffSiteRedirect):
        wordpress._fetch('https://site.test/a')


def test_canonical_redirects_are_followed(monkeypatch):
    # http -> https and the bare name -> www are the same site
    seen = _transport(monkeypatch, {
        'http://site.test/': (301, {'Location': 'https://site.test/'}, ''),
        'https://site.test/': (301, {'Location': 'https://www.site.test/'}, ''),
        'https://www.site.test/': (200, {}, 'home'),
    })
    page = wordpress._fetch('http://site.test/')
    assert (page.status, page.url, page.text) == (200, 'https://www.site.test/', 'home')
    assert seen == ['http://site.test/', 'https://site.test/', 'https://www.site.test/']


def test_too_many_redirects_is_an_error(monkeypatch):
    _transport(monkeypatch, {'https://site.test/loop': (302, {'Location': '/loop'}, '')})
    with pytest.raises(httpx.HTTPError):
        wordpress._fetch('https://site.test/loop')


def test_follow_false_returns_the_redirect_itself(monkeypatch):
    seen = _transport(monkeypatch, {'https://site.test/?author=1': (301, {'Location': 'https://site.test/author/a/'}, '')})
    page = wordpress._fetch('https://site.test/?author=1', follow=False)
    assert page.status == 301 and page.headers['location'] == 'https://site.test/author/a/'
    assert seen == ['https://site.test/?author=1']


def test_off_site_redirect_is_not_retried(monkeypatch):
    calls = []

    def fetch(url, follow=True):
        calls.append(url)
        raise wordpress.OffSiteRedirect('redirected to another site: other.test')

    monkeypatch.setattr(wordpress, '_fetch', fetch)
    assert wordpress._try('https://site.test/x') is None
    assert calls == ['https://site.test/x']


def test_home_redirect_to_another_site_is_unreachable(monkeypatch):
    _site(monkeypatch, {BASE: wordpress.OffSiteRedirect('redirected to another site: other.test')})
    result = wordpress.check_wordpress_external(BASE)
    assert result['verdict'] == 'unreachable'
    assert 'other.test' in result['error']


# --- known vulnerabilities (contract C3, docs/research/wordpress_audit.md §9) ----------

WF_KEY = 'wf-key-not-in-any-report'
NOTICES = [{'name': 'defiant', 'notice': 'Copyright 2012-2026 Defiant Inc.', 'license': 'Defiant grants.',
            'license_url': 'https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/'}]


def _vuln(uid, rating='High', score=8.1, cve='CVE-2026-0001', patched=('9.9.9',), title='SQL Injection'):
    return {'id': uid, 'title': title, 'cve': cve, 'rating': rating, 'score': score,
            'patched_versions': list(patched), 'remediation': f'Update to version {patched[0]}' if patched else '',
            'link': f'https://www.wordfence.com/threat-intel/vulnerabilities/id/{uid}'}


def _wordfence(monkeypatch, *, matches=None, uncertain=None, error=None, stale=False, refresh_error=None):
    """Fakes the key and wordfence.vulnerabilities; returns the items it was asked about."""
    asked = []

    def vulnerabilities(items, key):
        asked.extend(items)
        assert key == WF_KEY
        if error:
            return {'status': 'error', 'error': error, 'matches': {}, 'uncertain': {}}
        keys = ['core' if t == 'core' else f'plugin:{s.lower()}' for t, s, _ in items]
        return {'status': 'ok', 'error': None, 'source': 'Wordfence Intelligence',
                'fetched_at': '2026-11-23T10:00:00Z', 'stale': stale, 'refresh_error': refresh_error,
                'matches': {k: (matches or {}).get(k, []) for k in keys},
                'uncertain': {k: (uncertain or {}).get(k, []) for k in keys}, 'notices': NOTICES}

    monkeypatch.setattr(wordpress, '_wordfence_key', lambda: WF_KEY)
    monkeypatch.setattr(wordfence, 'vulnerabilities', vulnerabilities)
    return asked


def test_only_items_with_a_known_version_are_looked_up(monkeypatch):
    _site(monkeypatch, _plugin_pages(), core=CORE_LATEST, plugins=PLUGIN_LATEST)
    asked = _wordfence(monkeypatch)
    wordpress.check_wordpress_external(BASE)
    # premium-thing has no version: it stays a plugin_versions gap, never "no vulnerabilities"
    assert asked == [('core', 'wordpress', LATEST), ('plugin', 'contact-form-7', '6.2.5'),
                     ('plugin', 'elementor', '4.1.0')]


def test_known_vulnerabilities_are_findings(monkeypatch):
    _site(monkeypatch, _plugin_pages(), core=CORE_LATEST, plugins=PLUGIN_LATEST)
    _wordfence(monkeypatch, matches={
        'plugin:elementor': [_vuln('e-1', rating='Critical', score=9.8, cve='CVE-2024-1111', patched=('4.0.2',)),
                             _vuln('e-2', rating=None, score=None, cve=None, patched=())],
        'core': [_vuln('c-1', rating='Low', score=3.1, cve='CVE-2024-2222', title='Core XSS')]})
    result = wordpress.check_wordpress_external(BASE)
    crit = _by_id(result, 'WP-VULN-001:elementor:e-1')
    assert crit['severity'] == 'critical'
    assert 'elementor 4.1.0' in crit['title'] and 'SQL Injection' in crit['title']
    assert 'CVE-2024-1111' in crit['detail'] and 'CVSS 9.8' in crit['detail'] and '4.0.2' in crit['detail']
    assert 'https://www.wordfence.com/threat-intel/vulnerabilities/id/e-1' in crit['detail']
    assert crit['recommendation'] == 'Update to version 4.0.2'
    assert _by_id(result, 'WP-VULN-001:elementor:e-2')['severity'] == 'medium'    # no rating: not downplayed
    assert _by_id(result, 'WP-VULN-001:wordpress:c-1')['severity'] == 'low'
    rows = {p['slug']: p['vulns'] for p in result['plugins']}
    assert rows == {'contact-form-7': 0, 'elementor': 2, 'premium-thing': None}
    assert _checked(result)['vulns'] == 'problem'
    assert result['verdict'] == 'danger'
    assert result['vuln_data']['source'] == 'Wordfence Intelligence'
    assert result['vuln_data']['notices'] == NOTICES
    assert WF_KEY not in json.dumps(result)


def test_no_known_vulnerabilities_lets_a_site_be_ok(monkeypatch):
    _site(monkeypatch, _home_latest(), core=CORE_LATEST)
    _wordfence(monkeypatch)
    result = wordpress.check_wordpress_external(BASE)
    item = next(c for c in result['checked'] if c['item'] == 'vulns')
    assert item['status'] == 'ok' and '2026-11-23' in item['detail']
    assert result['verdict'] == 'ok'
    assert result['score'] == {'value': 100, 'complete': True, 'not_checked': []}


def test_vulnerability_data_error_is_not_checked(monkeypatch):
    _site(monkeypatch, _home_latest(), core=CORE_LATEST)
    _wordfence(monkeypatch, error='the Wordfence key was rejected (HTTP 401)')
    result = wordpress.check_wordpress_external(BASE)
    item = next(c for c in result['checked'] if c['item'] == 'vulns')
    assert item['status'] == 'not_checked' and 'HTTP 401' in item['detail']
    assert result['verdict'] == 'incomplete'
    assert 'vuln_data' not in result


def test_bounds_that_could_not_be_compared_are_not_checked(monkeypatch):
    _site(monkeypatch, _plugin_pages(), core=CORE_LATEST, plugins=PLUGIN_LATEST)
    _wordfence(monkeypatch, uncertain={'plugin:contact-form-7': ['x-1']})
    result = wordpress.check_wordpress_external(BASE)
    item = next(c for c in result['checked'] if c['item'] == 'vulns')
    assert item['status'] == 'not_checked' and 'contact-form-7' in item['detail']


def test_stale_vulnerability_data_says_how_old(monkeypatch):
    _site(monkeypatch, _home_latest(), core=CORE_LATEST)
    _wordfence(monkeypatch, stale=True, refresh_error='Wordfence rate limit (HTTP 429)')
    result = wordpress.check_wordpress_external(BASE)
    item = next(c for c in result['checked'] if c['item'] == 'vulns')
    assert item['status'] == 'ok'
    assert '2026-11-23' in item['detail'] and 'HTTP 429' in item['detail']
    assert result['vuln_data']['stale'] is True
