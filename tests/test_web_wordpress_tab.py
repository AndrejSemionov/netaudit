"""
The WordPress tab (docs/research/wordpress_audit.md contract C1/C1a): a site
address field and a check button, run through the existing /api/stream/start,
and a result view of its own. Static checks of web/static: the suite has no JS
engine (same approach as test_web_frontend_escaping.py).
"""

from __future__ import annotations

import re
from pathlib import Path

from tests.test_web_frontend_escaping import _functions, _script

STATIC = Path(__file__).resolve().parent.parent / 'web' / 'static'
INDEX = (STATIC / 'index.html').read_text(encoding='utf-8')
I18N = (STATIC / 'i18n.js').read_text(encoding='utf-8')


def _lang_block(lang: str) -> str:
    """The RU or EN key/value block of i18n.js (they are the first two maps)."""
    blocks = re.findall(r"\n  (ru|en): \{(.*?)\n  \},", I18N, re.DOTALL)
    return dict(blocks)[lang]


def test_tab_button_and_page():
    assert re.search(r'<button class="tab-btn" data-tab="wordpress" onclick="switchTab\(\'wordpress\'\)" '
                     r'data-i18n="tab.wordpress">WordPress</button>', INDEX)
    nav = INDEX[INDEX.index('<nav class="tabs-nav">'):INDEX.index('</nav>')]
    assert nav.index('data-tab="audit"') < nav.index('data-tab="wordpress"') < nav.index('data-tab="trends"')
    page = INDEX[INDEX.index('id="tab-wordpress"'):]
    assert re.search(r'<input[^>]+id="wpUrl"', page)
    assert 'onclick="runWordPressCheck()"' in page
    assert 'id="wpResult"' in page


def test_tab_and_category_labels_in_both_languages():
    for lang in ('ru', 'en'):
        block = _lang_block(lang)
        assert "'tab.wordpress': 'WordPress'" in block, lang
        assert "'cat.wordpress': 'WordPress'" in block, lang
        for key in ('wp.address', 'wp.check', 'wp.verdict.ok', 'wp.verdict.warn', 'wp.verdict.danger',
                    'wp.verdict.incomplete', 'wp.verdict.not_wp', 'wp.verdict.unreachable', 'wp.plugins'):
            assert f"'{key}':" in block, (lang, key)


def test_check_list_names_the_wordpress_category():
    body = _functions(_script())['renderCheckList']
    assert "wordpress: t('cat.wordpress')" in body


def test_check_runs_through_the_existing_stream_api():
    body = _functions(_script())['runWordPressCheck']
    assert "fetch('/api/stream/start'" in body
    assert "id: 'wordpress_external'" in body
    assert "new EventSource('/api/stream/' + " in body
    # a bare address gets https://, as the reference page accepts "mysite.com"
    assert "'https://' + " in body


def test_result_view_escapes_and_is_shared_with_the_audit_tab():
    js = _script()
    functions = _functions(js)
    # the tab escapes the raw result once; the Audit tab passes renderReport()'s
    # display copy, which is already escaped - so one view, wordPressHtml(),
    # and no double escaping
    assert re.search(r'^\s*r = escDeep\(r\);\s*return wordPressHtml\(r\);',
                     functions['renderWordPress'].split('{', 1)[1], re.MULTILINE)
    assert 'out.innerHTML = renderWordPress(result);' in functions['runWordPressCheck']
    view = functions['wordPressHtml']
    for part in ('r.verdict', 'r.checked', 'r.findings', 'r.plugins'):
        assert part in view, part
    assert "if (id === 'wordpress_external') return { html: wordPressHtml(r) };" in functions['renderResult']


def test_score_colour_and_word_follow_the_value():
    # USER: "if it is good it must be green, medium orange, bad red"
    view = _functions(_script())['wordPressHtml']
    assert "const grade = value >= 80 ? 'good' : value >= 50 ? 'medium' : 'bad';" in view
    assert "const scoreClass = { good: 'ok', medium: 'warn', bad: 'bad' }[grade];" in view
    assert "${t('wp.grade.' + grade)}" in view
    for lang, words in (('ru', ('хорошо', 'средне', 'плохо')), ('en', ('good', 'medium', 'bad'))):
        block = _lang_block(lang)
        for grade, word in zip(('good', 'medium', 'bad'), words):
            assert f"'wp.grade.{grade}': '{word}'" in block, (lang, grade)



def test_wordfence_key_in_settings():
    # the field, its status and saving it - like the HIBP key
    page = INDEX[INDEX.index('id="tab-settings"'):]
    assert re.search(r'<input type="password" id="wordfenceApiKey"', page)
    assert 'id="wordfenceKeyStatus"' in page
    functions = _functions(_script())
    assert "settings.wordfence_api_key = wf" in functions['saveSettings']
    assert "s.wordfence_api_key" in functions['loadSettings']
    for lang in ('ru', 'en'):
        block = _lang_block(lang)
        for key in ('settings.wordfence.title', 'settings.wordfence.hint', 'settings.wordfence.key.label'):
            assert f"'{key}':" in block, (lang, key)


def test_vulnerability_data_shown_with_its_source_and_licence():
    view = _functions(_script())['wordPressHtml']
    assert 'r.vuln_data' in view
    for part in ('.source', '.fetched_at', '.notices', '.license_url', '.license'):
        assert part in view, part
    assert 'p.vulns' in view          # the plugins table has a vulnerabilities column
    for lang in ('ru', 'en'):
        block = _lang_block(lang)
        for key in ('wp.item.vulns', 'wp.col.vulns', 'wp.vuln_source', 'wp.vuln_stale'):
            assert f"'{key}':" in block, (lang, key)



def test_vulnerability_record_link_and_unclear_counts_are_shown():
    # review #61 pass 1: the record is a hyperlink; a count that could not be complete says so
    view = _functions(_script())['wordPressHtml']
    assert 'href="${f.link}"' in view and 'rel="noopener noreferrer"' in view
    assert 'p.vulns_unclear' in view
    for lang in ('ru', 'en'):
        assert "'wp.vuln_record':" in _lang_block(lang), lang
