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


# --- taint check -------------------------------------------------------------
# Inside every 'escapes'/'static' writer, a value is RAW if it comes from a
# parameter, from `.json()` not wrapped in escDeep(), from a raw global, or is
# derived from a raw value (assignment, destructuring, for-of, array callback
# parameter). Any ${...} whose expression still mentions a raw value outside an
# esc()/escDeep() call is a violation. Heuristic, not a JS parser - it only has
# to be right for this one file, and the mutation test below proves it notices
# every escaping site being removed.

RAW_GLOBALS = {'LAST_REPORT', 'STREAM_STATE', 'window'}
NOT_DATA = {'t', 'esc', 'escDeep', 'await', 'typeof', 'new', 'Math', 'JSON', 'Number', 'String',
            'Object', 'Array', 'true', 'false', 'null', 'undefined', 'encodeURIComponent'}
# ${...} that reach textContent (setStatus/.textContent), never HTML.
TEXT_ONLY = {
    ('finishStream', "report.total_time || '—'"),
    ('finishStream', 'report.timestamp'),
    ('loadHistoryCapture', "st.last_run.replace('T',' ').slice(0,19)"),
    ('loadHistoryCapture', 'st.snapshots_taken'),
}
ROOT_IDENT = re.compile(r'(?<![\w$.])[A-Za-z_$][\w$]*')
CALLBACK = re.compile(r'\.(?:map|forEach|filter|flatMap|some|every|find|sort|reduce)\(\s*'
                      r'(?:\(([^()]*)\)|([A-Za-z_$][\w$]*))\s*=>')


def _skip_comment(s: str, i: int) -> int | None:
    """Index just past a // or /* */ comment starting at s[i], else None."""
    if s.startswith('//', i):
        end = s.find('\n', i)
        return len(s) if end < 0 else end
    if s.startswith('/*', i):
        end = s.find('*/', i + 2)
        return len(s) if end < 0 else end + 2
    return None


def _skip_string(s: str, i: int) -> int:
    """s[i] is ' or " - index just past the closing quote."""
    q, i = s[i], i + 1
    while i < len(s) and s[i] != q:
        i += 2 if s[i] == '\\' else 1
    return i + 1


def _skip_template(s: str, i: int, found: list | None = None) -> int:
    """s[i] is a backtick - index just past the closing one. Records each
    ${...} as (start, expr) into `found`, nested ones included."""
    i += 1
    while i < len(s) and s[i] != '`':
        if s[i] == '\\':
            i += 2
        elif s.startswith('${', i):
            end = _close(s, i + 1, found)
            if found is not None:
                found.append((i, s[i + 2:end]))
            i = end + 1
        else:
            i += 1
    return i + 1


def _close(s: str, i: int, found: list | None = None) -> int:
    """s[i] is ( [ or { - index of its matching closer."""
    depth = 0
    while i < len(s):
        c = s[i]
        skip = _skip_comment(s, i)
        if skip is not None:
            i = skip
            continue
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
            if depth == 0:
                return i
        elif c in '\'"':
            i = _skip_string(s, i)
            continue
        elif c == '`':
            i = _skip_template(s, i, found)
            continue
        i += 1
    raise ValueError('unbalanced')


def _interpolations(body: str) -> list[tuple[int, str]]:
    found, i = [], 0
    while i < len(body):
        skip = _skip_comment(body, i)
        if skip is not None:
            i = skip
        elif body[i] in '\'"':
            i = _skip_string(body, i)
        elif body[i] == '`':
            i = _skip_template(body, i, found)
        else:
            i += 1
    return found


def _strip(expr: str) -> str:
    """Drop string/template literals and esc()/escDeep() calls - what is left
    is the part of the expression that can still carry raw data."""
    out, i = [], 0
    while i < len(expr):
        m = re.match(r'(?<![\w$.])escDeep\(|(?<![\w$.])esc\(', expr[i:]) if (
            i == 0 or not (expr[i - 1].isalnum() or expr[i - 1] in '_$.')) else None
        if m:
            i = _close(expr, i + m.end() - 1) + 1
            out.append('""')
        elif expr[i] in '\'"':
            i = _skip_string(expr, i)
            out.append('""')
        elif expr[i] == '`':
            i = _skip_template(expr, i)
            out.append('""')
        else:
            out.append(expr[i])
            i += 1
    return ''.join(out)


def _is_raw(expr: str, raw: set[str]) -> bool:
    s = _strip(expr)
    return '.json(' in s or any(tok in raw for tok in ROOT_IDENT.findall(s) if tok not in NOT_DATA)


def _statement_end(body: str, i: int) -> int:
    depth = 0
    while i < len(body):
        c = body[i]
        skip = _skip_comment(body, i)
        if skip is not None:
            i = skip
            continue
        if c in '([{':
            depth += 1
        elif c in ')]}':
            if depth == 0:
                return i
            depth -= 1
        elif c in '\'"':
            i = _skip_string(body, i)
            continue
        elif c == '`':
            i = _skip_template(body, i)
            continue
        elif c == ';' and depth == 0:
            return i
        i += 1
    return i


def _receiver(body: str, dot: int) -> str:
    """Expression a `.map(` etc. is called on: walk back over names, dots and
    balanced (...)/[...] groups."""
    i = dot
    while i > 0:
        c = body[i - 1]
        if c.isalnum() or c in '_$.?':
            i -= 1
        elif c in ')]':
            depth, j = 0, i - 1
            while j >= 0:
                if body[j] in ')]':
                    depth += 1
                elif body[j] in '([':
                    depth -= 1
                    if depth == 0:
                        break
                j -= 1
            i = j
        else:
            break
    return body[i:dot]


def _names(pattern: str) -> set[str]:
    return {n for n in ROOT_IDENT.findall(re.sub(r'=[^,}\]]*', '', pattern)) if n not in NOT_DATA}


def _bindings(body: str) -> list[tuple[set[str], str, int]]:
    """(names bound, source expression, position) for every binding form."""
    out = []
    for m in re.finditer(r'\b(?:const|let|var)\s+(\{[^}]*\}|\[[^\]]*\]|[A-Za-z_$][\w$]*)\s*=(?!=)', body):
        out.append((_names(m.group(1)), body[m.end():_statement_end(body, m.end())], m.start()))
    for m in re.finditer(r'\bfor\s*\(\s*(?:const|let|var)\s+(\{[^}]*\}|\[[^\]]*\]|[A-Za-z_$][\w$]*)'
                         r'\s+of\s+', body):
        out.append((_names(m.group(1)), body[m.end():_statement_end(body, m.end())], m.start()))
    for m in CALLBACK.finditer(body):
        params = m.group(1) if m.group(1) is not None else m.group(2)
        out.append((_names(params), _receiver(body, m.start()), m.start()))
    return out


def _violations(js: str) -> list[tuple[str, str]]:
    bodies = _functions(js)
    found = []
    for name, kind in HTML_WRITERS.items():
        if kind == 'code-defined':
            continue
        body = bodies[name]
        sig = body[body.index('(') + 1:body.index(')')]
        raw = set(RAW_GLOBALS) | _names(sig)
        # `param = escDeep(param)` cleans a parameter from that point on
        cleaned = {m.group(1): m.start()
                   for m in re.finditer(r'(?<![\w$.])([A-Za-z_$][\w$]*)\s*=\s*escDeep\(\s*\1\s*\)', body)}
        bindings = _bindings(body)
        changed = True
        while changed:
            changed = False
            for names, src, _ in bindings:
                if names - raw and _is_raw(src, raw - set(cleaned)):
                    raw |= names
                    changed = True
        for pos, expr in _interpolations(body):
            if (name, expr.strip()) in TEXT_ONLY:
                continue
            live_raw = {r for r in raw if r not in cleaned or pos < cleaned[r]}
            if _is_raw(expr, live_raw):
                found.append((name, expr.strip()))
    return found


def test_no_raw_value_reaches_a_template_in_html_writers():
    assert _violations(_script()) == []


def test_guard_notices_every_escaping_site_being_removed():
    """Mutation check: remove one esc()/escDeep() call at a time (keep its
    argument) - the taint check must report each mutant."""
    js = _script()
    bodies = _functions(js)
    sites = []
    for name, kind in HTML_WRITERS.items():
        if kind != 'escapes':
            continue
        start = js.index(bodies[name])
        for m in re.finditer(r'(?<![\w$.])(escDeep|esc)\(', bodies[name]):
            open_paren = start + m.end() - 1
            sites.append((name, start + m.start(), open_paren, _close(js, open_paren)))
    assert len(sites) >= 14
    for name, call_start, open_paren, close_paren in sites:
        mutant = js[:call_start] + js[open_paren + 1:close_paren] + js[close_paren + 1:]
        assert _violations(mutant), f'removing an escape in {name} went unnoticed'


# Only fixed class names may be interpolated into class="..." - never data.
CLASS_SAFE_EXPRS = {
    "h.loss_pct > 10 ? 'bad' : ''", 'lossClass(h.loss_pct)', 'lossClass(r.loss_pct||0)',
    'daysClass', 'scoreClass', 'pillClass', 'predClass', 'rowClass', 'AI_SEV_CLASS[p.severity] || \'\'',
}


def test_class_attributes_interpolate_only_fixed_mappings():
    html = INDEX.read_text(encoding='utf-8')
    for attr in re.findall(r'class="([^"]*\$\{[^"]*)"', html):
        for expr in re.findall(r'\$\{([^}]*)\}', attr):
            assert expr.strip() in CLASS_SAFE_EXPRS, attr


def test_inline_handlers_interpolate_only_code_or_integer_ids():
    html = INDEX.read_text(encoding='utf-8')
    for handler in re.findall(r'\son\w+="([^"]*)"', html):
        for expr in re.findall(r'\$\{([^}]*)\}', handler):
            assert expr.strip() in HANDLER_SAFE_EXPRS, handler
