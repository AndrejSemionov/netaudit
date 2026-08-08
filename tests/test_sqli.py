"""
Tests for netaudit_pkg.checks.sqli — in particular the authorization gate in
front of active sqlmap scanning.

This is the single most safety-critical test file in the project: a bug here
means the tool could actively attack a site the user doesn't have permission
to test, which is illegal (unauthorized access) rather than merely buggy
software. Every test that exercises the gate asserts BOTH that sqlmap did not
run AND that the result says so - a passing check that silently doesn't
scan is just as much a test failure as one that scans when it shouldn't.
"""

from __future__ import annotations

import pytest

from netaudit_pkg.checks.sqli import (
    check_sql_injection, _find_injection_points, AUTH_CONFIRM,
)


# ===========================================================================
# The authorization gate — the critical path
# ===========================================================================

def test_active_mode_without_authorization_is_blocked(monkeypatch):
    """The core guarantee: requesting active mode with authorization='no'
    must never reach sqlmap."""
    sqlmap_called = {'value': False}

    def fake_run_sqlmap(*args, **kwargs):
        sqlmap_called['value'] = True
        return {'vulnerable': False, 'findings': []}

    monkeypatch.setattr('netaudit_pkg.checks.sqli._run_sqlmap', fake_run_sqlmap)
    monkeypatch.setattr('netaudit_pkg.checks.sqli._fetch_html', lambda url: None)

    result = check_sql_injection(
        url='http://test.local/?id=1',
        authorization='no',
        mode='passive + sqlmap',
        crawl='no',
    )

    assert sqlmap_called['value'] is False
    assert result['active_blocked'] is True
    assert result['mode'] == 'passive'
    assert any('NOT started' in f['title'] for f in result['findings'])


def test_active_mode_with_empty_authorization_is_blocked(monkeypatch):
    """authorization='' (never explicitly set) must be treated the same as
    'no' - the gate checks for an exact match against AUTH_CONFIRM, so any
    value that isn't that exact string blocks the scan."""
    sqlmap_called = {'value': False}
    monkeypatch.setattr('netaudit_pkg.checks.sqli._run_sqlmap',
                         lambda *a, **kw: sqlmap_called.__setitem__('value', True))
    monkeypatch.setattr('netaudit_pkg.checks.sqli._fetch_html', lambda url: None)

    result = check_sql_injection(url='http://test.local/?id=1', authorization='',
                                  mode='passive + sqlmap')
    assert sqlmap_called['value'] is False
    assert result['active_blocked'] is True


def test_active_mode_with_near_miss_authorization_string_is_blocked(monkeypatch):
    """Guards against a class of bug where a case-insensitive or substring
    match would let a similar-but-wrong string through. The gate must require
    an exact match to AUTH_CONFIRM."""
    sqlmap_called = {'value': False}
    monkeypatch.setattr('netaudit_pkg.checks.sqli._run_sqlmap',
                         lambda *a, **kw: sqlmap_called.__setitem__('value', True))
    monkeypatch.setattr('netaudit_pkg.checks.sqli._fetch_html', lambda url: None)

    near_misses = [
        'yes',
        'YES — I\'M THE OWNER / I HAVE WRITTEN PERMISSION',
        AUTH_CONFIRM + ' ',  # trailing space
        ' ' + AUTH_CONFIRM,  # leading space
        AUTH_CONFIRM[:-1],   # truncated by one char
    ]
    for bad_auth in near_misses:
        result = check_sql_injection(url='http://test.local/?id=1', authorization=bad_auth,
                                      mode='passive + sqlmap')
        assert sqlmap_called['value'] is False, f'sqlmap ran with authorization={bad_auth!r}'
        assert result['active_blocked'] is True, f'gate did not block authorization={bad_auth!r}'


def test_passive_mode_never_touches_the_gate(monkeypatch):
    """When mode is passive-only (the default), the function shouldn't even
    evaluate the authorization gate - active_blocked shouldn't appear in the
    result at all, since active scanning was never requested."""
    sqlmap_called = {'value': False}
    monkeypatch.setattr('netaudit_pkg.checks.sqli._run_sqlmap',
                         lambda *a, **kw: sqlmap_called.__setitem__('value', True))
    monkeypatch.setattr('netaudit_pkg.checks.sqli._fetch_html', lambda url: None)

    result = check_sql_injection(url='http://test.local/?id=1', authorization='no',
                                  mode='passive (input points only)')
    assert sqlmap_called['value'] is False
    assert 'active_blocked' not in result
    assert result['mode'] == 'passive'


def test_active_mode_with_correct_authorization_runs_sqlmap(monkeypatch):
    """The gate must not be so strict that legitimate, explicitly-confirmed
    scans are blocked too - that would make the feature unusable."""
    sqlmap_called = {'value': False}

    def fake_run_sqlmap(url, crawl, level=1, risk=1):
        sqlmap_called['value'] = True
        return {'vulnerable': False, 'findings': [{'severity': 'ok', 'title': 'clean', 'detail': ''}]}

    monkeypatch.setattr('netaudit_pkg.checks.sqli._run_sqlmap', fake_run_sqlmap)
    monkeypatch.setattr('netaudit_pkg.checks.sqli._fetch_html', lambda url: None)

    result = check_sql_injection(
        url='http://test.local/?id=1',
        authorization=AUTH_CONFIRM,
        mode='passive + sqlmap',
    )

    assert sqlmap_called['value'] is True
    assert result.get('active_blocked') is None
    assert result['mode'] == 'active'
    assert 'sqlmap' in result


@pytest.mark.parametrize('mode', [
    'passive (input points only)',
    'PASSIVE + SQLMAP',   # wrong case
    'passive+sqlmap',     # no spaces
    'active',              # not a real mode value at all
])
def test_only_exact_mode_string_triggers_active_path(monkeypatch, mode):
    """The mode check (`mode == 'passive + sqlmap'`) must be an exact match -
    any other string, including near-misses, should fall through to the
    passive-only path and never approach the authorization gate or sqlmap."""
    sqlmap_called = {'value': False}
    monkeypatch.setattr('netaudit_pkg.checks.sqli._run_sqlmap',
                         lambda *a, **kw: sqlmap_called.__setitem__('value', True))
    monkeypatch.setattr('netaudit_pkg.checks.sqli._fetch_html', lambda url: None)

    result = check_sql_injection(url='http://test.local/?id=1', authorization=AUTH_CONFIRM, mode=mode)
    assert sqlmap_called['value'] is False
    assert result['mode'] == 'passive'


# ===========================================================================
# Passive discovery (always runs, no gate involved)
# ===========================================================================

def test_no_input_points_found():
    points = _find_injection_points('http://test.local/', None)
    assert points['get_params'] == []
    assert points['forms'] == []


def test_get_params_detected_from_url():
    points = _find_injection_points('http://test.local/?id=1&name=x', None)
    assert set(points['get_params']) == {'id', 'name'}


def test_form_fields_detected_from_html():
    html = '<form action="/search" method="POST"><input name="q"><input name="page"></form>'
    points = _find_injection_points('http://test.local/', html)
    assert len(points['forms']) == 1
    assert points['forms'][0]['method'] == 'POST'
    assert set(points['forms'][0]['inputs']) == {'q', 'page'}


def test_check_sql_injection_requires_url():
    result = check_sql_injection(url='')
    assert 'error' in result


def test_check_sql_injection_passive_summary(monkeypatch):
    monkeypatch.setattr('netaudit_pkg.checks.sqli._fetch_html',
                         lambda url: '<form><input name="q"></form>')
    result = check_sql_injection(url='http://test.local/?id=1')
    assert result['mode'] == 'passive'
    assert result['summary']['low'] >= 1  # input points found -> low finding
