"""F5 (docs/research/sqli_breach_partial.md): a page that could not be
fetched, or a breach source that did not answer, is not a clean result."""

from __future__ import annotations

from netaudit_pkg.checks import breach_check, sqli


def _titles(result):
    return [(f['severity'], f['title']) for f in result['findings']]


def test_unfetched_page_without_parameters_is_not_ok(monkeypatch):
    monkeypatch.setattr(sqli, '_fetch_html', lambda url: None)
    result = sqli.check_sql_injection(url='https://down.example/')
    assert not any(sev == 'ok' for sev, _ in _titles(result))
    infos = [f for f in result['findings'] if f['severity'] == 'info']
    assert len(infos) == 1 and 'could not be fetched' in infos[0]['title']
    assert infos[0]['requires_manual_verification'] is True


def test_unfetched_page_still_lists_url_parameters(monkeypatch):
    monkeypatch.setattr(sqli, '_fetch_html', lambda url: None)
    result = sqli.check_sql_injection(url='https://down.example/?id=1')
    sevs = [sev for sev, _ in _titles(result)]
    assert sevs == ['low', 'info']
    assert result['injection_points']['get_params'] == ['id']


def test_fetched_empty_page_without_parameters_is_still_ok(monkeypatch):
    monkeypatch.setattr(sqli, '_fetch_html', lambda url: '')
    result = sqli.check_sql_injection(url='https://up.example/')
    assert _titles(result) == [('ok', 'no input points found')]


def _sources(monkeypatch, xon, hibp):
    monkeypatch.setattr(breach_check, '_check_email_xposedornot', lambda email: dict(xon))
    monkeypatch.setattr(breach_check, '_check_email_hibp', lambda email, key: dict(hibp))
    monkeypatch.setattr(breach_check, '_resolve_hibp_key', lambda: 'k')
    monkeypatch.setattr(breach_check, '_XON_MIN_INTERVAL', 0)


NOT_FOUND = {'ok': True, 'breaches': [], 'error': None}
RATE_LIMITED = {'ok': False, 'breaches': [], 'error': 'rate limit (429) — wait before retrying'}


def test_one_source_failed_other_clean_is_partial_not_clean(monkeypatch):
    _sources(monkeypatch, NOT_FOUND, RATE_LIMITED)
    result = breach_check.check_breach(emails='a@example.com', use_xposedornot=True, use_hibp=True)
    [entry] = result['results']
    assert entry['severity'] == 'info'
    assert 'xposedornot' in entry['summary'] and '429' in entry['summary']
    assert result['summary'] == {'exposed': 0, 'clean': 0, 'error': 0, 'partial': 1}


def test_both_sources_clean_is_still_ok(monkeypatch):
    _sources(monkeypatch, NOT_FOUND, NOT_FOUND)
    result = breach_check.check_breach(emails='a@example.com', use_xposedornot=True, use_hibp=True)
    assert result['results'][0]['severity'] == 'ok'
    assert result['summary']['clean'] == 1


def test_both_sources_failed_is_still_an_error(monkeypatch):
    _sources(monkeypatch, RATE_LIMITED, RATE_LIMITED)
    result = breach_check.check_breach(emails='a@example.com', use_xposedornot=True, use_hibp=True)
    assert result['results'][0]['severity'] == 'error'
    assert result['summary']['error'] == 1
