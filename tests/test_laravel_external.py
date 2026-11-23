"""
laravel_external: a Laravel site checked from outside, GET requests only
(docs/research/laravel_audit.md §4, §6, contract L2/L3).

No network: the site is a dict of URL -> response behind the module's one
fetch seam (laravel._fetch); versions' data is faked at laravel_data.support
and laravel_data.vulnerabilities (tested in test_laravel_data.py).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from urllib.parse import urljoin, urlparse

import httpx
import pytest

import netaudit_pkg.checks  # noqa: F401 - registers every check
from netaudit_pkg import laravel_data, webprobe
from netaudit_pkg.checks import laravel
from netaudit_pkg.findings import subject_id
from netaudit_pkg.registry import registry

BASE = 'https://app.test/'
HOME = '<html><head><title>App</title></head><body>hello</body></html>'
HOME_HEADERS = {'Strict-Transport-Security': 'max-age=31536000', 'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'SAMEORIGIN'}
WHEN = 'expires=Mon, 23 Nov 2026 14:00:00 GMT; Max-Age=7200; path=/'
XSRF = f'XSRF-TOKEN=eyJpdiI6IkFCQyJ9%3D; {WHEN}; secure; samesite=lax'
SESSION = f'app-session=eyJpdiI6IkRFRiJ9%3D; {WHEN}; secure; httponly; samesite=lax'
APP_KEY = 'base64:c2VjcmV0LWtleS1uZXZlci1zaG93bg=='
ENV_TEXT = f'APP_NAME=App\nAPP_ENV=production\nAPP_KEY={APP_KEY}\nDB_PASSWORD=hunter2-secret\n'
LOG_TEXT = ('[2026-11-23 10:00:00] production.ERROR: SQLSTATE[HY000] [2002] Connection refused '
            '{"exception":"[object] (PDOException(code: 2002))"}\n')
TELESCOPE = '<!DOCTYPE html><html><head><title>Telescope - App</title></head><body><div id="telescope" v-cloak>'
HORIZON = '<!DOCTYPE html><html><head><title>Horizon - App</title></head><body><div id="horizon" v-cloak>'
LOCK = json.dumps({'packages': [{'name': 'laravel/framework', 'version': 'v11.0.0'},
                                {'name': 'guzzlehttp/guzzle', 'version': '7.4.0'}],
                   'packages-dev': [{'name': 'phpunit/phpunit', 'version': '10.5.1'}]})
SUPPORTED = {'status': 'supported', 'cycle': '12', 'eol': '2027-02-24', 'latest': '12.73.0', 'error': None}
ENDED = {'status': 'ended', 'cycle': '11', 'eol': '2026-03-12', 'latest': '11.57.1', 'error': None}
NO_VULNS = {'status': 'ok', 'matches': {}, 'unanswered': [], 'error': None, 'checked': 0}
GHSA = {'id': 'GHSA-78fx-h6xr-vch4', 'title': 'Laravel has a File Validation Bypass', 'severity': 'medium',
        'cve': 'CVE-2025-27515', 'fixed': ['11.44.1'],
        'link': 'https://osv.dev/vulnerability/GHSA-78fx-h6xr-vch4', 'error': None}


def _site(monkeypatch, pages, *, cookies=(XSRF, SESSION), cert_days=90, support=SUPPORTED, vulns=NO_VULNS):
    """pages: url -> (status, headers, text[, cookies]) | Exception. Unlisted
    URLs answer 404; the home page answers with `cookies`; http://app.test/
    redirects to https. Redirects are followed like the real fetch does.
    Returns the requested (url, follow) pairs; the versions' data calls are
    kept in requested.support / requested.vulns."""
    requested = _Calls()
    pages.setdefault(BASE, (200, HOME_HEADERS, HOME, list(cookies)))
    pages.setdefault('http://app.test/', (301, {'Location': BASE}, ''))

    def fetch(url, follow=True):
        requested.append((url, follow))
        start = url
        for _ in range(6):
            hit = pages.get(url)
            if isinstance(hit, Exception):
                raise hit
            if hit is None:
                return webprobe.Page(404, url, {}, '<html>Not Found</html>')
            status, headers, text, *rest = hit
            headers = {k.lower(): v for k, v in headers.items()}
            if follow and status in (301, 302, 303, 307, 308) and 'location' in headers:
                target = urljoin(url, headers['location'])
                if urlparse(target).scheme not in ('http', 'https') or not webprobe.same_site(target, start):
                    raise webprobe.OffSiteRedirect(f'redirected to another site: {urlparse(target).hostname}')
                url = target
                continue
            return webprobe.Page(status, url, headers, text, list(rest[0]) if rest else [])
        raise httpx.TooManyRedirects('loop')

    monkeypatch.setattr(laravel, '_fetch', fetch)

    def not_after(host, port):
        if isinstance(cert_days, Exception):
            raise cert_days
        return datetime.now(UTC) + timedelta(days=cert_days, hours=1)

    monkeypatch.setattr(laravel, '_cert_not_after', not_after)
    monkeypatch.setattr(laravel_data, 'support', lambda version, today=None: requested.support.append(version)
                        or support)
    monkeypatch.setattr(laravel_data, 'vulnerabilities', lambda packages: requested.vulns.append(packages)
                        or vulns)
    return requested


class _Calls(list):
    def __init__(self):
        super().__init__()
        self.support = []
        self.vulns = []


def _ids(result):
    return [f.get('id') for f in result.get('findings', [])]


def _by_id(result, fid):
    return next(f for f in result['findings'] if f.get('id') == fid)


def _checked(result):
    return {c['item']: c['status'] for c in result['checked']}


def _detail(result, item):
    return next(c['detail'] for c in result['checked'] if c['item'] == item)


# --- registration ------------------------------------------------------------------

def test_registered_as_a_passive_check_in_the_laravel_category():
    spec = registry.get('laravel_external')
    assert spec.category == 'laravel'
    assert spec.risk_level == 'PASSIVE'
    assert [p['name'] for p in spec.params] == ['url']
    assert spec.params[0]['format'] == 'url'


def test_site_address_becomes_a_base_url_and_paths_stay_under_it(monkeypatch):
    requested = _site(monkeypatch, {'https://app.test/shop/': (200, HOME_HEADERS, HOME, [XSRF, SESSION])})
    result = laravel.check_laravel_external('https://app.test/shop')
    assert result['url'] == 'https://app.test/shop/'
    assert ('https://app.test/shop/.env', True) in requested
    assert ('https://app.test/.env', True) not in requested


def test_every_request_is_a_get_to_the_site_itself(monkeypatch):
    requested = _site(monkeypatch, {})
    laravel.check_laravel_external(BASE)
    assert requested
    assert {urlparse(url).hostname for url, _ in requested} == {'app.test'}


# --- unreachable and detection ------------------------------------------------------------

def test_site_that_does_not_answer_is_unreachable(monkeypatch):
    _site(monkeypatch, {BASE: httpx.ConnectError('refused')})
    result = laravel.check_laravel_external(BASE)
    assert result['verdict'] == 'unreachable'
    assert 'error' in result


def test_server_error_on_the_home_page_is_unreachable(monkeypatch):
    _site(monkeypatch, {BASE: (503, {}, 'busy')})
    assert laravel.check_laravel_external(BASE)['verdict'] == 'unreachable'


def test_xsrf_cookie_is_a_sign_of_laravel(monkeypatch):
    _site(monkeypatch, {}, cookies=[XSRF])
    result = laravel.check_laravel_external(BASE)
    assert result['laravel'] is True
    assert 'XSRF-TOKEN' in result['detected_by']


def test_an_encrypted_laravel_cookie_is_a_sign(monkeypatch):
    _site(monkeypatch, {}, cookies=['shop_cart=eyJpdiI6IlhZWiJ9; path=/; secure; httponly; samesite=lax'])
    result = laravel.check_laravel_external(BASE)
    assert result['laravel'] is True
    assert 'encrypted' in result['detected_by']


def test_login_page_cookies_count_when_the_home_page_sets_none(monkeypatch):
    _site(monkeypatch, {f'{BASE}login': (200, {}, '<form>', [XSRF, SESSION])}, cookies=[])
    result = laravel.check_laravel_external(BASE)
    assert result['laravel'] is True
    assert 'login' in result['detected_by']


def test_no_sign_of_laravel(monkeypatch):
    _site(monkeypatch, {BASE: (200, {}, HOME, ['PHPSESSID=abc; path=/'])})
    result = laravel.check_laravel_external(BASE)
    assert result['laravel'] is False
    assert result['verdict'] == 'not_laravel'
    # nothing judged on a site that is not Laravel: no header findings, no score
    assert {f['severity'] for f in result['findings']} == {'info'}
    assert 'score' not in result


def test_no_cookies_and_no_answer_from_login_cannot_tell(monkeypatch):
    _site(monkeypatch, {f'{BASE}login': (503, {}, 'busy')}, cookies=[])
    result = laravel.check_laravel_external(BASE)
    assert result['laravel'] is None
    assert result['verdict'] == 'incomplete'
    assert 'HTTP 503' in result['findings'][0]['detail']


def test_an_open_laravel_file_is_a_sign_even_without_cookies(monkeypatch):
    # a cached home page drops Set-Cookie; the open .env still names the site
    _site(monkeypatch, {f'{BASE}.env': (200, {}, ENV_TEXT)}, cookies=[])
    result = laravel.check_laravel_external(BASE)
    assert result['laravel'] is True
    assert '.env' in result['detected_by']
    assert 'LV-ENV-001' in _ids(result)


# --- a clean site ---------------------------------------------------------------------

ALL_ITEMS = {'https', 'http_redirect', 'certificate', 'hsts', 'nosniff', 'framing', 'session_cookie', 'env',
             'ignition', 'debugbar', 'telescope', 'horizon', 'laravel_log', 'project_files', 'git_config',
             'laravel_version', 'vulns'}


def test_clean_site_is_incomplete_only_because_versions_are_not_visible(monkeypatch):
    requested = _site(monkeypatch, {})
    result = laravel.check_laravel_external(BASE)
    checked = _checked(result)
    assert set(checked) == ALL_ITEMS
    assert {k for k, v in checked.items() if v != 'ok'} == {'laravel_version', 'vulns'}
    assert checked['laravel_version'] == checked['vulns'] == 'not_checked'
    assert 'composer.lock' in _detail(result, 'laravel_version')
    assert result['verdict'] == 'incomplete'
    assert result['score'] == {'value': 100, 'complete': False, 'not_checked': ['laravel_version', 'vulns']}
    assert [f['severity'] for f in result['findings']] == []
    assert requested.vulns == [] and requested.support == []


def test_transport_findings_use_laravel_ids(monkeypatch):
    _site(monkeypatch, {BASE: (200, {}, HOME, [XSRF, SESSION])})
    ids = _ids(laravel.check_laravel_external(BASE))
    assert {'LV-HDR-001', 'LV-HDR-002', 'LV-HDR-003'} <= set(ids)
    assert not [i for i in ids if i and i.startswith('WP-')]


def test_plain_http_site(monkeypatch):
    plain = 'http://app.test/'
    _site(monkeypatch, {plain: (200, HOME_HEADERS, HOME, ['XSRF-TOKEN=eyJpdiI6; path=/',
                                                          'app-session=eyJpdiI6; path=/; httponly; samesite=lax'])})
    result = laravel.check_laravel_external(plain)
    assert 'LV-TLS-001' in _ids(result)
    # Secure cannot be asked of a cookie on a plain-http site: that is LV-TLS-001
    assert 'LV-CKE-001' not in _ids(result)


def test_certificate_ending_soon(monkeypatch):
    _site(monkeypatch, {}, cert_days=3)
    assert 'LV-TLS-003' in _ids(laravel.check_laravel_external(BASE))


# --- .env ------------------------------------------------------------------------------------

def test_public_env_is_critical_and_its_values_are_never_kept(monkeypatch):
    _site(monkeypatch, {f'{BASE}.env': (200, {'Content-Type': 'text/plain'}, ENV_TEXT)})
    result = laravel.check_laravel_external(BASE)
    f = _by_id(result, 'LV-ENV-001')
    assert f['severity'] == 'critical'
    assert '.env' in f['detail'] and 'APP_KEY' in f['detail'] and 'DB_PASSWORD' in f['detail']
    dumped = json.dumps(result)
    assert APP_KEY not in dumped and 'hunter2' not in dumped
    assert _checked(result)['env'] == 'problem'
    assert result['verdict'] == 'danger'
    assert result['score']['value'] == 60


def test_env_copies_are_checked_too(monkeypatch):
    _site(monkeypatch, {f'{BASE}.env.bak': (200, {}, ENV_TEXT)})
    f = _by_id(laravel.check_laravel_external(BASE), 'LV-ENV-001')
    assert '.env.bak' in f['detail']


def test_a_soft_404_for_env_is_not_a_finding(monkeypatch):
    _site(monkeypatch, {f'{BASE}.env': (200, {}, '<html><title>Page not found</title></html>')})
    result = laravel.check_laravel_external(BASE)
    assert 'LV-ENV-001' not in _ids(result)
    assert _checked(result)['env'] == 'ok'


def test_env_without_an_answer_is_not_checked(monkeypatch):
    _site(monkeypatch, {f'{BASE}.env': (503, {}, 'busy')})
    result = laravel.check_laravel_external(BASE)
    assert _checked(result)['env'] == 'not_checked'
    assert 'HTTP 503' in _detail(result, 'env')
    info = [f for f in result['findings'] if f['severity'] == 'info']
    assert info and '.env (HTTP 503)' in info[0]['detail']


# --- debug tools --------------------------------------------------------------------------------

def test_open_ignition_is_critical(monkeypatch):
    _site(monkeypatch, {f'{BASE}_ignition/health-check': (200, {'Content-Type': 'application/json'},
                                                          '{"can_execute_commands":true}')})
    result = laravel.check_laravel_external(BASE)
    f = _by_id(result, 'LV-IGN-001')
    assert f['severity'] == 'critical'
    assert _checked(result)['ignition'] == 'problem'


@pytest.mark.parametrize('answer', [(404, {}, 'Not Found'), (200, {}, '<html>home</html>'),
                                    (200, {}, '{"status":"ok"}')])
def test_closed_ignition(monkeypatch, answer):
    _site(monkeypatch, {f'{BASE}_ignition/health-check': answer})
    result = laravel.check_laravel_external(BASE)
    assert 'LV-IGN-001' not in _ids(result)
    assert _checked(result)['ignition'] == 'ok'


def test_ignition_without_an_answer_is_not_checked(monkeypatch):
    _site(monkeypatch, {f'{BASE}_ignition/health-check': (500, {}, 'Server Error')})
    assert _checked(laravel.check_laravel_external(BASE))['ignition'] == 'not_checked'


def test_debugbar_on_the_home_page(monkeypatch):
    page = HOME.replace('</body>', '<!-- Laravel Debugbar Widget --><script>var phpdebugbar = '
                                   'new PhpDebugBar.DebugBar();</script></body>')
    _site(monkeypatch, {BASE: (200, HOME_HEADERS, page, [XSRF, SESSION])})
    result = laravel.check_laravel_external(BASE)
    assert _by_id(result, 'LV-DBG-001')['severity'] == 'high'
    assert _checked(result)['debugbar'] == 'problem'


@pytest.mark.parametrize(('path', 'page', 'fid', 'item'), [
    ('telescope', TELESCOPE, 'LV-TEL-001', 'telescope'),
    ('horizon', HORIZON, 'LV-HRZ-001', 'horizon'),
])
def test_open_telescope_and_horizon(monkeypatch, path, page, fid, item):
    _site(monkeypatch, {f'{BASE}{path}': (200, {}, page)})
    result = laravel.check_laravel_external(BASE)
    assert _by_id(result, fid)['severity'] == 'high'
    assert _checked(result)[item] == 'problem'


@pytest.mark.parametrize('answer', [(403, {}, 'Forbidden'), (404, {}, 'Not Found'),
                                    (302, {'Location': '/login'}, '')])
def test_closed_telescope(monkeypatch, answer):
    _site(monkeypatch, {f'{BASE}telescope': answer, f'{BASE}login': (200, {}, '<form>login</form>')})
    result = laravel.check_laravel_external(BASE)
    assert 'LV-TEL-001' not in _ids(result)
    assert _checked(result)['telescope'] == 'ok'


def test_telescope_redirect_off_the_site_is_not_checked(monkeypatch):
    _site(monkeypatch, {f'{BASE}telescope': (302, {'Location': 'https://sso.other.test/'}, '')})
    assert _checked(laravel.check_laravel_external(BASE))['telescope'] == 'not_checked'


# --- files ---------------------------------------------------------------------------------------

def test_public_laravel_log(monkeypatch):
    _site(monkeypatch, {f'{BASE}storage/logs/laravel.log': (200, {}, LOG_TEXT)})
    result = laravel.check_laravel_external(BASE)
    assert _by_id(result, 'LV-FILE-001')['severity'] == 'high'
    assert 'Connection refused' not in json.dumps(result)


def test_soft_404_for_the_log_is_not_a_finding(monkeypatch):
    _site(monkeypatch, {f'{BASE}storage/logs/laravel.log': (200, {}, HOME)})
    result = laravel.check_laravel_external(BASE)
    assert 'LV-FILE-001' not in _ids(result)
    assert _checked(result)['laravel_log'] == 'ok'


def test_public_composer_json(monkeypatch):
    _site(monkeypatch, {f'{BASE}composer.json': (200, {}, '{"require": {"laravel/framework": "^12.0"}}')})
    result = laravel.check_laravel_external(BASE)
    f = _by_id(result, 'LV-FILE-002')
    assert f['severity'] == 'medium' and 'composer.json' in f['detail']
    assert _checked(result)['project_files'] == 'problem'


def test_public_git_config(monkeypatch):
    _site(monkeypatch, {f'{BASE}.git/config': (200, {}, '[core]\n\trepositoryformatversion = 0\n\tbare = false\n')})
    result = laravel.check_laravel_external(BASE)
    assert _by_id(result, 'LV-FILE-003')['severity'] == 'high'
    assert _checked(result)['git_config'] == 'problem'


# --- versions from a public composer.lock ----------------------------------------------------------

def test_public_lock_gives_versions_support_and_vulnerabilities(monkeypatch):
    vulns = {'status': 'ok', 'matches': {'laravel/framework': [GHSA], 'guzzlehttp/guzzle': [],
                                         'phpunit/phpunit': []},
             'unanswered': [], 'error': None, 'checked': 3}
    requested = _site(monkeypatch, {f'{BASE}composer.lock': (200, {}, LOCK)}, support=ENDED, vulns=vulns)
    result = laravel.check_laravel_external(BASE)
    assert requested.support == ['11.0.0']
    assert requested.vulns == [[{'name': 'laravel/framework', 'version': '11.0.0'},
                                {'name': 'guzzlehttp/guzzle', 'version': '7.4.0'},
                                {'name': 'phpunit/phpunit', 'version': '10.5.1'}]]
    assert result['framework'] == {'version': '11.0.0', 'source': 'composer.lock', 'support': ENDED}
    eol = _by_id(result, 'LV-EOL-001')
    assert eol['severity'] == 'high' and '2026-03-12' in eol['detail']
    vid = subject_id('LV-VULN-001', 'laravel/framework', 'GHSA-78fx-h6xr-vch4')
    v = _by_id(result, vid)
    assert v['severity'] == 'medium'
    assert 'CVE-2025-27515' in v['detail'] and '11.44.1' in v['detail']
    assert v['link'] == GHSA['link']
    assert 'LV-FILE-002' in _ids(result)
    checked = _checked(result)
    assert checked['laravel_version'] == 'problem' and checked['vulns'] == 'problem'
    assert result['packages'] == {'source': 'composer.lock', 'count': 3,
                                  'vulnerable': [{'name': 'laravel/framework', 'version': '11.0.0', 'vulns': 1}]}
    assert {n['name'] for n in result['vuln_data']['notices']} >= {'OSV.dev', 'GitHub Advisory Database',
                                                                   'endoflife.date'}


def test_installed_json_when_the_lock_is_not_public(monkeypatch):
    installed = json.dumps({'packages': [{'name': 'laravel/framework', 'version': 'v12.3.0'}]})
    requested = _site(monkeypatch, {f'{BASE}vendor/composer/installed.json': (200, {}, installed)})
    result = laravel.check_laravel_external(BASE)
    assert result['framework']['source'] == 'vendor/composer/installed.json'
    assert requested.support == ['12.3.0']
    assert _checked(result)['laravel_version'] == 'ok'
    assert '2027-02-24' in _detail(result, 'laravel_version')
    assert _checked(result)['vulns'] == 'ok'


def test_supported_laravel_with_no_known_vulnerabilities_can_be_ok(monkeypatch):
    lock = json.dumps({'packages': [{'name': 'laravel/framework', 'version': 'v12.3.0'}]})
    vulns = {'status': 'ok', 'matches': {'laravel/framework': []}, 'unanswered': [], 'error': None, 'checked': 1}
    _site(monkeypatch, {f'{BASE}composer.lock': (200, {}, lock)}, vulns=vulns)
    result = laravel.check_laravel_external(BASE)
    assert _checked(result)['vulns'] == 'ok'
    assert 'none known for 1 package' in _detail(result, 'vulns')
    # the public lock itself is the only problem
    assert {f['id'] for f in result['findings'] if f['severity'] != 'info'} == {'LV-FILE-002'}


def test_vulnerability_data_failure_is_not_checked(monkeypatch):
    vulns = {'status': 'error', 'matches': {}, 'unanswered': [], 'error': 'OSV.dev gave no answer', 'checked': 0}
    _site(monkeypatch, {f'{BASE}composer.lock': (200, {}, LOCK)}, vulns=vulns)
    result = laravel.check_laravel_external(BASE)
    assert _checked(result)['vulns'] == 'not_checked'
    assert 'OSV.dev gave no answer' in _detail(result, 'vulns')


def test_packages_without_an_answer_are_a_gap_next_to_a_finding(monkeypatch):
    vulns = {'status': 'ok', 'matches': {'laravel/framework': [GHSA]}, 'unanswered': ['guzzlehttp/guzzle'],
             'error': None, 'checked': 3}
    _site(monkeypatch, {f'{BASE}composer.lock': (200, {}, LOCK)}, vulns=vulns)
    result = laravel.check_laravel_external(BASE)
    checked = _checked(result)
    assert checked['vulns'] == 'problem'
    assert checked['vuln_gaps'] == 'not_checked'
    assert 'guzzlehttp/guzzle' in _detail(result, 'vuln_gaps')


def test_unknown_support_is_not_checked(monkeypatch):
    unknown = {'status': 'unknown', 'cycle': None, 'eol': None, 'latest': None, 'error': None}
    _site(monkeypatch, {f'{BASE}composer.lock': (200, {}, LOCK)}, support=unknown)
    result = laravel.check_laravel_external(BASE)
    assert _checked(result)['laravel_version'] == 'not_checked'
    assert 'LV-EOL-001' not in _ids(result)


def test_lock_without_laravel_framework(monkeypatch):
    lock = json.dumps({'packages': [{'name': 'guzzlehttp/guzzle', 'version': '7.4.0'}]})
    requested = _site(monkeypatch, {f'{BASE}composer.lock': (200, {}, lock)})
    result = laravel.check_laravel_external(BASE)
    assert _checked(result)['laravel_version'] == 'not_checked'
    assert 'laravel/framework' in _detail(result, 'laravel_version')
    assert requested.support == []
    assert _checked(result)['vulns'] == 'ok'


def test_a_soft_404_lock_is_not_a_lock(monkeypatch):
    requested = _site(monkeypatch, {f'{BASE}composer.lock': (200, {}, HOME)})
    result = laravel.check_laravel_external(BASE)
    assert 'LV-FILE-002' not in _ids(result)
    assert requested.vulns == []


# --- the session cookie ------------------------------------------------------------------------------

@pytest.mark.parametrize(('cookie', 'fid', 'severity'), [
    (f'app-session=eyJpdiI6; {WHEN}; httponly; samesite=lax', 'LV-CKE-001', 'medium'),
    (f'app-session=eyJpdiI6; {WHEN}; secure; samesite=lax', 'LV-CKE-002', 'medium'),
    (f'app-session=eyJpdiI6; {WHEN}; secure; httponly', 'LV-CKE-003', 'low'),
    (f'app-session=eyJpdiI6; {WHEN}; secure; httponly; samesite=none', 'LV-CKE-003', 'low'),
])
def test_session_cookie_flags(monkeypatch, cookie, fid, severity):
    _site(monkeypatch, {}, cookies=[XSRF, cookie])
    result = laravel.check_laravel_external(BASE)
    f = _by_id(result, fid)
    assert f['severity'] == severity and 'app-session' in f['detail']
    assert _checked(result)['session_cookie'] == 'problem'


def test_older_session_cookie_name_and_the_xsrf_cookie_is_meant_for_scripts(monkeypatch):
    _site(monkeypatch, {}, cookies=[f'XSRF-TOKEN=eyJpdiI6; {WHEN}; secure; samesite=lax',
                                    f'laravel_session=eyJpdiI6; {WHEN}; secure; httponly; samesite=lax'])
    result = laravel.check_laravel_external(BASE)
    assert _checked(result)['session_cookie'] == 'ok'
    assert 'laravel_session' in _detail(result, 'session_cookie')


def test_no_session_cookie_seen_is_not_checked(monkeypatch):
    _site(monkeypatch, {f'{BASE}.env': (200, {}, ENV_TEXT)}, cookies=[])
    assert _checked(laravel.check_laravel_external(BASE))['session_cookie'] == 'not_checked'


# --- the real fetch keeps every Set-Cookie -----------------------------------------------------------------

def test_fetch_keeps_each_set_cookie_header(monkeypatch):
    def handler(request):
        return httpx.Response(200, headers=[('Set-Cookie', XSRF), ('Set-Cookie', SESSION)], text=HOME)

    monkeypatch.setattr(laravel, '_TRANSPORT', httpx.MockTransport(handler))
    page = laravel._fetch(BASE)
    assert page.cookies == [XSRF, SESSION]


# --- self-review: the probed root, the session cookie picked, Ignition's answer ---------------------------

def test_a_redirect_inside_the_app_does_not_move_the_probed_root(monkeypatch):
    # "/" -> "/en/" is routing inside the app: the project's files stay at the given path
    requested = _site(monkeypatch, {BASE: (302, {'Location': '/en/'}, ''),
                                    f'{BASE}en/': (200, HOME_HEADERS, HOME, [XSRF, SESSION])})
    result = laravel.check_laravel_external(BASE)
    assert result['url'] == BASE
    assert (f'{BASE}.env', True) in requested
    assert (f'{BASE}en/.env', True) not in requested


def test_the_host_and_scheme_still_follow_the_sites_redirect(monkeypatch):
    requested = _site(monkeypatch, {'http://app.test/': (301, {'Location': 'https://www.app.test/'}, ''),
                                    'https://www.app.test/': (200, HOME_HEADERS, HOME, [XSRF, SESSION])})
    result = laravel.check_laravel_external('http://app.test/')
    assert result['url'] == 'https://www.app.test/'
    assert ('https://www.app.test/.env', True) in requested


def test_the_session_cookie_is_picked_by_its_name_first(monkeypatch):
    _site(monkeypatch, {}, cookies=[XSRF, 'shop_cart=eyJpdiI6IlhZWiJ9; path=/', SESSION])
    result = laravel.check_laravel_external(BASE)
    assert _checked(result)['session_cookie'] == 'ok'
    assert 'app-session' in _detail(result, 'session_cookie')


@pytest.mark.parametrize('value', ['true', 'false'])
def test_ignition_detail_says_what_it_answered(monkeypatch, value):
    _site(monkeypatch, {f'{BASE}_ignition/health-check': (200, {}, f'{{"can_execute_commands":{value}}}')})
    f = _by_id(laravel.check_laravel_external(BASE), 'LV-IGN-001')
    assert f['severity'] == 'critical'
    assert f'can_execute_commands: {value}' in f['detail']
