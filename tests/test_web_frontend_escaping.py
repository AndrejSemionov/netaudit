"""
Guard against stored XSS in web/static/index.html.

Report data is attacker-influenced: web_security_external puts a scanned
site's raw Set-Cookie line into a finding's detail, mtr hop names come from
reverse DNS, AI output can be steered by report content. The page builds HTML
with template literals, so every value that came from the server must be
HTML-escaped (esc()/escDeep()) before it is interpolated.

These are static checks - the suite has no JS engine. They make a new
HTML-writing function, or a new data interpolation inside an inline event
handler, fail until someone has looked at where its data comes from.
"""

from __future__ import annotations

import re
from pathlib import Path

INDEX = Path(__file__).resolve().parent.parent / 'web' / 'static' / 'index.html'

# Every top-level function that writes HTML, and why its output is safe.
#   'escapes'      - server data passes through esc()/escDeep() first
#   'code-defined' - renders only the check registry and translations
#   'static'       - no server data at all
HTML_WRITERS = {
    'renderCheckList': 'code-defined',
    'addHostInstance': 'code-defined',
    'runAudit': 'static',
    'finishStream': 'escapes',
    'renderReport': 'escapes',
    'loadHistory': 'escapes',
    'renderAnalysis': 'escapes',
    'loadTrendTargets': 'escapes',
    'loadHistoryCapture': 'escapes',
    'queryHistoryCapture': 'escapes',
    'loadRep': 'escapes',
    'loadTools': 'escapes',
    'loadTargets': 'escapes',
    'loadPresetBar': 'escapes',
    'loadPresetsManage': 'escapes',
    'loadSavedTargetsDatalist': 'escapes',
}

# Interpolations allowed inside inline on*="..." handlers: check/tool ids from
# the code registry and integer DB ids. HTML escaping does not protect a JS
# string inside an attribute (the browser decodes entities first), so nothing
# else may go there.
HANDLER_SAFE_EXPRS = {'c.id', 'checkId', 'nextIdx', 'it.id', 'x.id', 'tool.tool', 'tg.id', 'p.id'}

HTML_SINK = re.compile(r'\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML\(')
TOP_FUNC = re.compile(r'^(?:async\s+)?function\s+(\w+)\s*\(', re.M)


def _script() -> str:
    html = INDEX.read_text(encoding='utf-8')
    return html[html.index('<script>', html.index('/static/i18n.js')):]


def _functions(js: str) -> dict[str, str]:
    starts = [(m.start(), m.group(1)) for m in TOP_FUNC.finditer(js)]
    bodies = {}
    for i, (pos, name) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(js)
        bodies[name] = js[pos:end]
    return bodies


def test_escape_helpers_exist_and_cover_html_metacharacters():
    js = _script()
    assert re.search(r'^function esc\(', js, re.M)
    assert re.search(r'^function escDeep\(', js, re.M)
    esc_body = _functions(js)['esc']
    for entity in ('&amp;', '&lt;', '&gt;', '&quot;', '&#39;'):
        assert entity in esc_body


def test_every_html_writing_function_is_reviewed():
    writers = {name for name, body in _functions(_script()).items() if HTML_SINK.search(body)}
    assert writers == set(HTML_WRITERS), (
        'HTML-writing functions changed - review where their data comes from '
        'and update HTML_WRITERS')


def test_functions_marked_escapes_actually_escape():
    bodies = _functions(_script())
    for name, kind in HTML_WRITERS.items():
        if kind == 'escapes':
            assert re.search(r'\besc(Deep)?\(', bodies[name]), name


def test_inline_handlers_interpolate_only_code_or_integer_ids():
    html = INDEX.read_text(encoding='utf-8')
    for handler in re.findall(r'\son\w+="([^"]*)"', html):
        for expr in re.findall(r'\$\{([^}]*)\}', handler):
            assert expr.strip() in HANDLER_SAFE_EXPRS, handler
