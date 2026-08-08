"""
Проверка утечек данных (data breach check): были ли указанные email-адреса
засвечены в известных утечках баз данных.

Два источника, оба можно включить одновременно — что вернёт результат, то и покажем:
  - XposedOrNot — бесплатный, без API-ключа, лимит 2 запроса/сек на IP.
  - HaveIBeenPwned (HIBP) — требует платный API-ключ (hibp-api-key), но база
    обычно самая полная и активно поддерживается Troy Hunt.

Домен целиком без верификации владения ни один из провайдеров не отдаёт (у HIBP и
XposedOrNot domain-эндпоинты требуют подтверждённое владение доменом через их кабинет) —
поэтому здесь принимается список конкретных email-адресов через запятую.

Это OSINT-проверка: не ищет дыру на сервере, а смотрит, "засветились" ли уже
учётные данные в публично известных утечках. Полезно перед аудитом инфраструктуры
клиента — если пароль от почты сотрудника уже утёк, это фактор риска независимо
от того, насколько хорошо защищён сам сервер.
"""

from __future__ import annotations

import re
import time

import httpx

from ..registry import register
from .. import storage

EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

XON_ENDPOINT = 'https://api.xposedornot.com/v1/check-email/{email}'
HIBP_ENDPOINT = 'https://haveibeenpwned.com/api/v3/breachedaccount/{email}'

# XposedOrNot просит не превышать 2 запроса/сек с одного IP
_XON_MIN_INTERVAL = 0.55


def _finding(severity, title, detail=''):
    return {'severity': severity, 'title': title, 'detail': detail}


def _resolve_hibp_key() -> str | None:
    """Ключ HIBP: только настройка в БД — это платный сервис, у него нет
    бесплатного тира вообще, так что переменная окружения тут не нужна,
    в отличие от anthropic_api_key."""
    return storage.setting_get('hibp_api_key') or None


def _check_email_xposedornot(email: str) -> dict:
    """Возвращает {'ok': bool, 'breaches': [...], 'error': str|None}."""
    try:
        resp = httpx.get(XON_ENDPOINT.format(email=email), timeout=15,
                          headers={'User-Agent': 'NetAudit (github.com/AndrejSemionov/netaudit)'})
    except httpx.HTTPError as e:
        return {'ok': False, 'breaches': [], 'error': str(e)}

    if resp.status_code == 404:
        return {'ok': True, 'breaches': [], 'error': None}
    if resp.status_code == 429:
        return {'ok': False, 'breaches': [], 'error': 'rate limit (429) — слишком много запросов, попробуй позже'}
    if resp.status_code != 200:
        return {'ok': False, 'breaches': [], 'error': f'HTTP {resp.status_code}'}

    try:
        data = resp.json()
    except ValueError:
        return {'ok': False, 'breaches': [], 'error': 'не распарсить ответ'}

    # XposedOrNot возвращает {"breaches": [["Site1", "Site2", ...]]} — вложенный список
    raw = data.get('breaches', [])
    names = []
    for item in raw:
        if isinstance(item, list):
            names.extend(item)
        elif isinstance(item, str):
            names.append(item)
    return {'ok': True, 'breaches': names, 'error': None}


def _check_email_hibp(email: str, api_key: str) -> dict:
    """Возвращает {'ok': bool, 'breaches': [...], 'error': str|None}."""
    try:
        resp = httpx.get(HIBP_ENDPOINT.format(email=email),
                          params={'truncateResponse': 'true'},
                          headers={'hibp-api-key': api_key,
                                   'User-Agent': 'NetAudit (github.com/AndrejSemionov/netaudit)'},
                          timeout=15)
    except httpx.HTTPError as e:
        return {'ok': False, 'breaches': [], 'error': str(e)}

    if resp.status_code == 404:
        return {'ok': True, 'breaches': [], 'error': None}
    if resp.status_code == 401:
        return {'ok': False, 'breaches': [], 'error': 'ключ HIBP отклонён (401) — проверь настройку hibp_api_key'}
    if resp.status_code == 429:
        return {'ok': False, 'breaches': [], 'error': 'rate limit (429) — подожди перед повтором'}
    if resp.status_code != 200:
        return {'ok': False, 'breaches': [], 'error': f'HTTP {resp.status_code}'}

    try:
        data = resp.json()
    except ValueError:
        return {'ok': False, 'breaches': [], 'error': 'не распарсить ответ'}

    names = [b.get('Name', '?') for b in data] if isinstance(data, list) else []
    return {'ok': True, 'breaches': names, 'error': None}


@register(
    id='breach_check', label='Проверка утечек данных (email)', category='security',
    params=[
        {'name': 'emails', 'type': 'text', 'label': 'Email-адреса (через запятую)', 'default': ''},
        {'name': 'use_xposedornot', 'type': 'checkbox', 'label': 'Проверять через XposedOrNot (бесплатно)',
         'default': True},
        {'name': 'use_hibp', 'type': 'checkbox',
         'label': 'Проверять через HaveIBeenPwned (нужен платный ключ в настройках)', 'default': False},
    ],
    required_tools=[],
    description='OSINT-проверка: засветились ли указанные email в известных утечках баз данных '
                '(XposedOrNot бесплатно, HaveIBeenPwned платно). Не проверяет сервер — проверяет '
                'публичную историю утечек по адресу.',
)
def check_breach(emails: str = '', use_xposedornot: bool = True, use_hibp: bool = False) -> dict:
    address_list = [e.strip() for e in emails.split(',') if e.strip()]
    if not address_list:
        return {'error': 'не указано ни одного email-адреса'}

    invalid = [e for e in address_list if not EMAIL_RE.match(e)]
    if invalid:
        return {'error': f'похоже не на email: {", ".join(invalid)}'}

    if not use_xposedornot and not use_hibp:
        return {'error': 'выбери хотя бы один источник проверки (XposedOrNot или HIBP)'}

    hibp_key = _resolve_hibp_key() if use_hibp else None
    if use_hibp and not hibp_key:
        return {'error': 'HIBP выбран, но hibp_api_key не задан в настройках'}

    results = []
    counts = {'exposed': 0, 'clean': 0, 'error': 0}
    last_xon_call = 0.0

    for email in address_list:
        entry = {'email': email, 'sources': {}}
        any_breach = False
        any_error = False

        if use_xposedornot:
            # уважаем rate limit XON — не долбим быстрее 2 req/sec
            elapsed = time.monotonic() - last_xon_call
            if elapsed < _XON_MIN_INTERVAL:
                time.sleep(_XON_MIN_INTERVAL - elapsed)
            xon = _check_email_xposedornot(email)
            last_xon_call = time.monotonic()
            entry['sources']['xposedornot'] = xon
            if xon['error']:
                any_error = True
            elif xon['breaches']:
                any_breach = True

        if use_hibp:
            hibp = _check_email_hibp(email, hibp_key)
            entry['sources']['hibp'] = hibp
            if hibp['error']:
                any_error = True
            elif hibp['breaches']:
                any_breach = True

        if any_breach:
            all_names = set()
            for src in entry['sources'].values():
                all_names.update(src.get('breaches', []))
            entry['severity'] = 'high'
            entry['summary'] = f'найден в {len(all_names)} утечке(ах): {", ".join(sorted(all_names))}'
            counts['exposed'] += 1
        elif any_error and not any(s['ok'] for s in entry['sources'].values()):
            entry['severity'] = 'error'
            errs = [s['error'] for s in entry['sources'].values() if s.get('error')]
            entry['summary'] = '; '.join(errs)
            counts['error'] += 1
        else:
            entry['severity'] = 'ok'
            entry['summary'] = 'в известных утечках не найден'
            counts['clean'] += 1

        results.append(entry)

    return {'checked': len(address_list), 'summary': counts, 'results': results}
