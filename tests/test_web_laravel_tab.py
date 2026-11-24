"""
The Laravel tab (docs/research/laravel_audit.md §6, contract L1): a site
address field and a check button, run through the existing /api/stream/start,
and a result view of its own, like the WordPress tab. Static checks of
web/static: the suite has no JS engine (as test_web_wordpress_tab.py).
"""

from __future__ import annotations

import re

from tests.test_web_frontend_escaping import HTML_WRITERS, _functions, _script
from tests.test_web_wordpress_tab import INDEX, _lang_block

# every checked item laravel_external can report (tests/test_laravel_external.py)
ITEMS = ('https', 'http_redirect', 'certificate', 'hsts', 'nosniff', 'framing', 'session_cookie', 'env',
         'ignition', 'debugbar', 'telescope', 'horizon', 'laravel_log', 'project_files', 'git_config',
         'laravel_version', 'vulns', 'vuln_gaps', 'version_sources')
VERDICTS = ('ok', 'warn', 'danger', 'incomplete', 'not_laravel', 'unreachable')


def test_tab_button_and_page():
    assert re.search(r'<button class="tab-btn" data-tab="laravel" onclick="switchTab\(\'laravel\'\)" '
                     r'data-i18n="tab.laravel">Laravel</button>', INDEX)
    nav = INDEX[INDEX.index('<nav class="tabs-nav">'):INDEX.index('</nav>')]
    assert nav.index('data-tab="wordpress"') < nav.index('data-tab="laravel"') < nav.index('data-tab="trends"')
    page = INDEX[INDEX.index('id="tab-laravel"'):]
    assert re.search(r'<input[^>]+id="lvUrl"', page)
    assert 'onclick="runLaravelCheck()"' in page
    assert 'id="lvResult"' in page


def test_labels_in_both_languages():
    for lang in ('ru', 'en'):
        block = _lang_block(lang)
        assert "'tab.laravel': 'Laravel'" in block, lang
        assert "'cat.laravel': 'Laravel'" in block, lang
        keys = ['lv.title', 'lv.hint', 'lv.address', 'lv.check', 'lv.empty', 'lv.running', 'lv.version_hidden',
                'lv.packages', 'lv.packages_note', 'lv.col.package', 'lv.col.version', 'lv.col.vulns',
                'lv.vuln_source', 'lv.vuln_record', 'lv.support_until', 'lv.support_ended']
        keys += [f'lv.verdict.{v}' for v in VERDICTS] + [f'lv.item.{i}' for i in ITEMS]
        for key in keys:
            assert f"'{key}':" in block, (lang, key)


def test_check_list_names_the_laravel_category():
    assert "laravel: t('cat.laravel')" in _functions(_script())['renderCheckList']


def test_check_runs_through_the_existing_stream_api():
    body = _functions(_script())['runLaravelCheck']
    assert "fetch('/api/stream/start'" in body
    assert "id: 'laravel_external'" in body
    assert "new EventSource('/api/stream/' + " in body
    assert "'https://' + " in body
    assert 'out.innerHTML = renderLaravel(result);' in body
    assert HTML_WRITERS.get('runLaravelCheck') == 'escapes'


def test_result_view_escapes_once_and_is_shared_with_the_audit_tab():
    functions = _functions(_script())
    assert re.search(r'^\s*r = escDeep\(r\);\s*return laravelHtml\(r\);',
                     functions['renderLaravel'].split('{', 1)[1], re.MULTILINE)
    view = functions['laravelHtml']
    for part in ('r.verdict', 'r.checked', 'r.findings', 'r.packages', 'r.framework', 'r.vuln_data', 'r.score'):
        assert part in view, part
    assert "if (id === 'laravel_external') return { html: laravelHtml(r) };" in functions['renderResult']


def test_score_colour_follows_the_value_like_wordpress():
    view = _functions(_script())['laravelHtml']
    assert "const grade = value >= 80 ? 'good' : value >= 50 ? 'medium' : 'bad';" in view
    assert "const scoreClass = { good: 'ok', medium: 'warn', bad: 'bad' }[grade];" in view


def test_vulnerability_record_link_and_data_notices():
    view = _functions(_script())['laravelHtml']
    assert 'href="${f.link}"' in view and 'rel="noopener noreferrer"' in view
    for part in ('.notices', '.license_url', '.license'):
        assert part in view, part


# --- laravel_server (contract L4): in the Audit tab, with a view of its own ---------------

SERVER_ITEMS = ('discovery', 'env_files', 'app_debug', 'app_env', 'effective_config', 'writable_dirs', 'read_gaps',
                'laravel_version', 'vulns', 'vuln_gaps', 'version_sources')


def test_server_check_has_its_own_view_in_the_audit_tab():
    functions = _functions(_script())
    assert "if (id === 'laravel_server') return { html: laravelServerHtml(r) };" in functions['renderResult']
    view = functions['laravelServerHtml']
    for part in ('r.verdict', 'r.checked', 'r.findings', 'r.projects', 'r.score', 'c.project', 'r.vuln_data',
                 'r.collected_without_sudo', 'r.skipped'):
        assert part in view, part
    assert 'href="${f.link}"' in view and 'rel="noopener noreferrer"' in view
    assert "const grade = value >= 80 ? 'good' : value >= 50 ? 'medium' : 'bad';" in view


def test_server_labels_in_both_languages():
    keys = [f'lv.srv.item.{i}' for i in SERVER_ITEMS]
    keys += ['lv.srv.projects', 'lv.srv.col.path', 'lv.srv.col.version', 'lv.srv.col.debug', 'lv.srv.col.env',
             'lv.srv.col.vulns', 'lv.srv.without_sudo', 'lv.srv.skipped', 'lv.srv.verdict.not_laravel', 'lv.server_hint']
    for lang in ('ru', 'en'):
        block = _lang_block(lang)
        for key in keys:
            assert f"'{key}':" in block, (lang, key)


def test_the_laravel_tab_points_to_the_server_check():
    page = INDEX[INDEX.index('id="tab-laravel"'):INDEX.index('id="tab-trends"')]
    assert 'data-i18n="lv.server_hint"' in page
