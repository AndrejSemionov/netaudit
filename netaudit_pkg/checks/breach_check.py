"""
Data breach check: have the given email addresses shown up in known database breaches.

Two sources, both can be enabled at once - whatever comes back, we show:
  - XposedOrNot - free, no API key, limit 2 requests/sec per IP.
  - HaveIBeenPwned (HIBP) - requires a paid API key (hibp-api-key), but the
    database is usually the most complete and is actively maintained by Troy Hunt.

Neither provider hands over a whole domain without verified ownership (HIBP's
and XposedOrNot's domain endpoints require confirmed domain ownership through
their own dashboard) - so this accepts a comma-separated list of specific
email addresses instead.

This is an OSINT check: it doesn't look for a hole on the server, it checks
whether credentials have already shown up in publicly known breaches. Useful
before auditing a client's infrastructure - if an employee's mailbox password
has already leaked, that's a risk factor regardless of how well the server
itself is protected.
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

# XposedOrNot asks not to exceed 2 requests/sec from one IP
_XON_MIN_INTERVAL = 0.55


def _finding(severity, title, detail='', confidence='high', id=None):
    f = {'severity': severity, 'title': title, 'detail': detail, 'confidence': confidence}
    if id:
        f['id'] = id
    return f


def _resolve_hibp_key() -> str | None:
    """HIBP key: DB setting only - it's a paid service with no free tier at
    all, so an environment variable isn't needed here, unlike anthropic_api_key."""
    return storage.setting_get('hibp_api_key') or None


def _check_email_xposedornot(email: str) -> dict:
    """Returns {'ok': bool, 'breaches': [...], 'error': str|None}."""
    try:
        resp = httpx.get(XON_ENDPOINT.format(email=email), timeout=15,
                          headers={'User-Agent': 'NetAudit (github.com/AndrejSemionov/netaudit)'})
    except httpx.HTTPError as e:
        return {'ok': False, 'breaches': [], 'error': str(e)}

    if resp.status_code == 404:
        return {'ok': True, 'breaches': [], 'error': None}
    if resp.status_code == 429:
        return {'ok': False, 'breaches': [], 'error': 'rate limit (429) — too many requests, try again later'}
    if resp.status_code != 200:
        return {'ok': False, 'breaches': [], 'error': f'HTTP {resp.status_code}'}

    try:
        data = resp.json()
    except ValueError:
        return {'ok': False, 'breaches': [], 'error': 'could not parse the response'}

    # XposedOrNot returns {"breaches": [["Site1", "Site2", ...]]} - a nested list
    raw = data.get('breaches', [])
    names = []
    for item in raw:
        if isinstance(item, list):
            names.extend(item)
        elif isinstance(item, str):
            names.append(item)
    return {'ok': True, 'breaches': names, 'error': None}


def _check_email_hibp(email: str, api_key: str) -> dict:
    """Returns {'ok': bool, 'breaches': [...], 'error': str|None}."""
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
        return {'ok': False, 'breaches': [], 'error': 'HIBP key rejected (401) — check the hibp_api_key setting'}
    if resp.status_code == 429:
        return {'ok': False, 'breaches': [], 'error': 'rate limit (429) — wait before retrying'}
    if resp.status_code != 200:
        return {'ok': False, 'breaches': [], 'error': f'HTTP {resp.status_code}'}

    try:
        data = resp.json()
    except ValueError:
        return {'ok': False, 'breaches': [], 'error': 'could not parse the response'}

    names = [b.get('Name', '?') for b in data] if isinstance(data, list) else []
    return {'ok': True, 'breaches': names, 'error': None}


@register(
    id='breach_check', label='Data breach check (email)', category='security', risk_level='PASSIVE',
    params=[
        {'name': 'emails', 'type': 'text', 'label': 'Email addresses (comma-separated)', 'default': ''},
        {'name': 'use_xposedornot', 'type': 'checkbox', 'label': 'Check via XposedOrNot (free)',
         'default': True},
        {'name': 'use_hibp', 'type': 'checkbox',
         'label': 'Check via HaveIBeenPwned (needs a paid key in settings)', 'default': False},
    ],
    required_tools=[],
    description='OSINT check: have the given emails shown up in known data breaches '
                '(XposedOrNot free, HaveIBeenPwned paid). Doesn\'t check the server — checks '
                'the public breach history for the address.',
)
def check_breach(emails: str = '', use_xposedornot: bool = True, use_hibp: bool = False) -> dict:
    address_list = [e.strip() for e in emails.split(',') if e.strip()]
    if not address_list:
        return {'error': 'no email address given'}

    invalid = [e for e in address_list if not EMAIL_RE.match(e)]
    if invalid:
        return {'error': f'doesn\'t look like an email: {", ".join(invalid)}'}

    if not use_xposedornot and not use_hibp:
        return {'error': 'select at least one source (XposedOrNot or HIBP)'}

    hibp_key = _resolve_hibp_key() if use_hibp else None
    if use_hibp and not hibp_key:
        return {'error': 'HIBP is selected, but hibp_api_key is not set in settings'}

    results = []
    counts = {'exposed': 0, 'clean': 0, 'error': 0}
    last_xon_call = 0.0

    for email in address_list:
        entry = {'email': email, 'sources': {}}
        any_breach = False
        any_error = False

        if use_xposedornot:
            # respect XON's rate limit - never hit it faster than 2 req/sec
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
            entry['summary'] = f'found in {len(all_names)} breach(es): {", ".join(sorted(all_names))}'
            counts['exposed'] += 1
        elif any_error and not any(s['ok'] for s in entry['sources'].values()):
            entry['severity'] = 'error'
            errs = [s['error'] for s in entry['sources'].values() if s.get('error')]
            entry['summary'] = '; '.join(errs)
            counts['error'] += 1
        else:
            entry['severity'] = 'ok'
            entry['summary'] = 'not found in known breaches'
            counts['clean'] += 1

        results.append(entry)

    return {'checked': len(address_list), 'summary': counts, 'results': results}
