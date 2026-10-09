"""Russian labels for the params many SSH checks share (host, user, port, key,
passwords, log lines) come from one common map in web/static/i18n.js, so a
check without its own translation entry no longer shows them in English.
A check's own translation still wins. Static checks: the suite has no JS
engine (same approach as test_web_frontend_escaping.py)."""

from __future__ import annotations

import re
from pathlib import Path

I18N = (Path(__file__).resolve().parent.parent / 'web' / 'static' / 'i18n.js').read_text(encoding='utf-8')

SHARED = {'host', 'user', 'port', 'key_path', 'password', 'sudo_password', 'lines', 'window_hours'}


def _common_map() -> dict[str, str]:
    block = re.search(r'const COMMON_PARAM_RU = \{(.*?)\};', I18N, re.DOTALL)
    assert block, 'COMMON_PARAM_RU map not found'
    return dict(re.findall(r"(\w+): '([^']+)'", block.group(1)))


def test_common_map_covers_the_shared_ssh_params():
    assert set(_common_map()) >= SHARED
    assert _common_map()['sudo_password'] == 'Пароль sudo (если sudo его спрашивает)'
    assert _common_map()['password'] == 'Пароль SSH (если без ключа)'


def test_every_shared_param_without_its_own_translation_gets_one():
    import netaudit_pkg.checks  # noqa: F401 - registers every check
    from netaudit_pkg.registry import registry
    common = _common_map()
    for spec in registry.all():
        entry = re.search(r'\n  ' + re.escape(spec.id) + r': \{(.*?)\n  \},', I18N, re.DOTALL)
        own = set(re.findall(r'(\w+): \{ ru:', entry.group(1))) if entry else set()
        for p in spec.params:
            if p['name'] in SHARED and p['name'] not in own:
                assert p['name'] in common, (spec.id, p['name'])


def test_tcheck_falls_back_to_the_common_map_in_both_branches():
    body = I18N[I18N.index('function tCheck('):I18N.index('\n}\n', I18N.index('function tCheck('))]
    assert body.count('commonParamLabel(p)') == 2
