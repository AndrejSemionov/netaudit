"""
Every check reads in Russian in the Russian UI, and the Telegram hint says
what uses the token (docs/research/web_ru_texts.md). Static checks of
web/static/i18n.js against the registry: the suite has no JS engine (same
approach as test_i18n_common_params.py).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import netaudit_pkg.checks  # noqa: F401 - registers every check
from netaudit_pkg.registry import registry

STATIC = Path(__file__).resolve().parent.parent / 'web' / 'static'
I18N = (STATIC / 'i18n.js').read_text(encoding='utf-8')
INDEX = (STATIC / 'index.html').read_text(encoding='utf-8')
CYRILLIC = re.compile('[а-яё]', re.IGNORECASE)
# tool and command names, shown as they are in both languages
TOOL_NAMES = {'openssl', 'python', 'curl', 'client', 'status-wrapper'}


def _entry(check_id: str) -> str | None:
    found = re.search(r'\n  ' + re.escape(check_id) + r': \{(.*?)\n  \},', I18N, re.DOTALL)
    return found.group(1) if found else None


def _common() -> set[str]:
    block = re.search(r'const COMMON_PARAM_RU = \{(.*?)\};', I18N, re.DOTALL)
    return set(re.findall(r'(\w+): ', block.group(1)))


def _options(entry: str) -> dict[str, str]:
    """Choice value -> its translation, from the entry's `options` block
    (brace-matched: quotes in the texts hold no braces)."""
    start = entry.find('options: {')
    if start < 0:
        return {}
    depth, i = 0, start + len('options: ')
    for end in range(i, len(entry)):
        depth += {'{': 1, '}': -1}.get(entry[end], 0)
        if depth == 0:
            break
    text = entry[i:end + 1]
    return {m.group(2): m.group(3)
            for m in re.finditer(r"""(['"])(.+?)\1: \{ (\w+: (?:'[^']*'|"[^"]*")) \}""", text)}


CHECKS = sorted(spec.id for spec in registry.all())


@pytest.mark.parametrize('check_id', CHECKS)
def test_every_check_has_a_russian_name_and_description(check_id):
    entry = _entry(check_id)
    assert entry is not None, f'{check_id}: no I18N_CHECKS entry'
    label = re.search(r"label: \{ ru: '([^']+)' \}", entry)
    desc = re.search(r"desc: \{ ru: ['\"](.+?)['\"]", entry, re.DOTALL)
    assert label and desc, f'{check_id}: no Russian label or description'
    # a tool name ('Ping', 'TCP traceroute') is the same in both languages,
    # but the card must say something in Russian
    assert CYRILLIC.search(label.group(1) + desc.group(1)), f'{check_id}: nothing in Russian'


@pytest.mark.parametrize('check_id', CHECKS)
def test_every_parameter_has_a_russian_label(check_id):
    own = set(re.findall(r'(\w+): \{ ru:', _entry(check_id) or ''))
    missing = [p['name'] for p in registry.get(check_id).params
               if p['name'] not in own and p['name'] not in _common()]
    assert missing == [], f'{check_id}: {missing}'


@pytest.mark.parametrize('check_id', CHECKS)
def test_every_choice_is_translated_by_its_value(check_id):
    options = _options(_entry(check_id) or '')
    for p in registry.get(check_id).params:
        for value in p.get('options', []):
            if value in TOOL_NAMES:
                continue
            assert value in options, f'{check_id}.{p["name"]}: no entry for {value!r}'
            lang = 'en' if CYRILLIC.search(value) else 'ru'
            assert options[value].startswith(f'{lang}: '), f'{check_id}: {value!r} needs {lang}'


@pytest.mark.parametrize('check_id', CHECKS)
def test_no_choice_entry_for_a_value_the_check_no_longer_has(check_id):
    values = {o for p in registry.get(check_id).params for o in p.get('options', [])}
    stale = sorted(set(_options(_entry(check_id) or '')) - values)
    assert stale == [], f'{check_id}: {stale}'


def _hints() -> list[str]:
    hints = re.findall(r"'settings\.tg\.hint': '([^']+)'", I18N)
    html = re.search(r'data-i18n="settings\.tg\.hint">([^<]+)<', INDEX)
    return hints + ([html.group(1)] if html else [])


def test_telegram_hint_says_what_uses_the_token():
    hints = _hints()
    assert len(hints) == 3  # ru, en, index.html default
    for hint in hints:
        assert '--notify' in hint and 'setup-timer' in hint, hint
        assert 'future' not in hint.lower() and 'будущ' not in hint.lower(), hint
