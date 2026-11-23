"""
Wordfence Intelligence v3 feed -> a local index -> known vulnerabilities of
the WordPress core and plugins (docs/research/wordpress_audit.md §9, C3).
No network: the one download seam, wordfence._download, yields text chunks
or raises FeedError; the index lives next to the isolated test database.
"""

from __future__ import annotations

import json
import os
import stat
import time

import pytest

from netaudit_pkg import storage, wordfence

KEY = 'wf-test-key-0123456789'
DEFIANT = {'notice': 'Copyright 2012-2026 Defiant Inc.', 'license': 'Defiant hereby grants you a licence.',
           'license_url': 'https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/'}
MITRE = {'notice': 'Copyright 1999-2026 The MITRE Corporation', 'license': 'CVE Usage: MITRE grants.',
         'license_url': 'https://www.cve.org/Legal/TermsOfUse'}


def _range(frm, to, fi=True, ti=True):
    return {f'{frm} - {to}': {'from_version': frm, 'from_inclusive': fi, 'to_version': to, 'to_inclusive': ti}}


def _record(uid, slug, ranges, *, type_='plugin', cve='CVE-2026-0001', rating='High', score=8.1,
            patched=('9.9.9',), informational=False, title='Example hole'):
    affected = {}
    for r in ranges:
        affected.update(r)
    return {
        'id': uid, 'title': title, 'informational': informational,
        'software': [{'type': type_, 'name': slug.title(), 'slug': slug, 'affected_versions': affected,
                      'patched': bool(patched), 'patched_versions': list(patched),
                      'remediation': f'Update to version {patched[0]}' if patched else 'No known patch'}],
        'references': [f'https://www.wordfence.com/threat-intel/vulnerabilities/id/{uid}?source=api-prod'],
        'cve': cve, 'cvss': {'vector': 'CVSS:3.1/AV:N', 'score': score, 'rating': rating} if rating else None,
        'copyrights': {'message': 'subject to copyright', 'defiant': DEFIANT, **({'mitre': MITRE} if cve else {})},
    }


FEED = {
    'aaaa-1': _record('aaaa-1', 'learnpress', [_range('*', '4.2.6')], cve='CVE-2024-1111', rating='Critical', score=9.8,
                      patched=('4.2.7',), title='SQL Injection'),
    'aaaa-2': _record('aaaa-2', 'learnpress', [_range('4.0.0', '4.5.0', ti=False)], cve=None, rating='Medium', score=5.3,
                      patched=('4.5.0',), title='Missing Authorization "x" {y}'),
    'aaaa-3': _record('aaaa-3', 'elementor', [_range('3.0.0', '3.20.2')], rating='High', patched=('3.20.3',)),
    'aaaa-4': _record('aaaa-4', 'elementor', [_range('*', '*')], informational=True, title='Info only'),
    'aaaa-5': _record('aaaa-5', 'WordPress', [_range('6.4.0', '6.4.3')], type_='core', cve='CVE-2024-2222',
                      rating='Medium', patched=('6.4.4',), title='Core XSS'),
    'aaaa-6': _record('aaaa-6', 'oddplugin', [_range('beta', 'trunk')], rating=None, patched=()),
}


def _feed_text(feed=None, indent=None):
    return json.dumps(FEED if feed is None else feed, indent=indent)


def _chunks(text, size):
    return [text[i:i + size] for i in range(0, len(text), size)]


class _Calls(list):
    feed: str
    error: Exception | None


@pytest.fixture
def downloads(monkeypatch, isolated_db):
    """Replaces the download; returns the list of keys it was called with.
    Set .feed (a str) or .error (a FeedError) on the returned list."""
    calls = _Calls()
    calls.feed = _feed_text()
    calls.error = None

    def download(key):
        calls.append(key)
        if calls.error is not None:
            raise calls.error
        return iter(_chunks(calls.feed, 4096))

    monkeypatch.setattr(wordfence, '_download', download)
    return calls


# --- the stream parser --------------------------------------------------------

@pytest.mark.parametrize('size', [1, 2, 3, 7, 64, 100000])
def test_records_come_out_whole_at_any_chunk_size(size):
    text = _feed_text(indent=2)
    records = list(wordfence.iter_records(_chunks(text, size)))
    assert [uid for uid, _ in records] == list(FEED)
    assert dict(records) == FEED


def test_empty_feed_has_no_records():
    assert list(wordfence.iter_records(['  {', ' } '])) == []


@pytest.mark.parametrize('text', ['[1, 2]', '{"a": {"id": 1}', '{"a" {"id": 1}}', '{"a": {"id": 1}} trailing',
                                  'not json'])
def test_broken_feed_is_an_error(text):
    with pytest.raises(wordfence.FeedError):
        list(wordfence.iter_records(_chunks(text, 3)))


# --- version ranges -------------------------------------------------------------

@pytest.mark.parametrize('version, expected', [
    ('4.2.6', True), ('4.2.7', False), ('1.0', True),          # * - 4.2.6 inclusive
])
def test_open_lower_bound(version, expected):
    assert wordfence.affects([['*', True, '4.2.6', True]], version) is expected


@pytest.mark.parametrize('version, expected', [
    ('4.0.0', True), ('4.0', True), ('4.4.9', True), ('4.5.0', False), ('4.5', False), ('3.9.9', False),
])
def test_bounds_and_inclusive_flags(version, expected):
    assert wordfence.affects([['4.0.0', True, '4.5.0', False]], version) is expected


def test_exclusive_lower_bound():
    assert wordfence.affects([['4.0.0', False, '*', True]], '4.0.0') is False
    assert wordfence.affects([['4.0.0', False, '*', True]], '4.0.1') is True


def test_any_version():
    assert wordfence.affects([['*', True, '*', True]], '1.2.3') is True


# review #61 pass 1 (5): a suffix is not dropped - 2.0-rc1 comes before 2.0, "1.*" is
# not "1"; anything but dotted numbers or a lone "*" is unknown

@pytest.mark.parametrize('ranges, version', [
    ([['*', True, '6.4.3', True]], '6.4.3-RC2'),
    ([['1.0', True, '2.0', False]], '2.0-rc1'),
    ([['1.*', True, '*', True]], '1.5'),
    ([['1.0', True, '2.0.x', True]], '1.5'),
])
def test_anything_but_dotted_numbers_is_unknown(ranges, version):
    assert wordfence.affects(ranges, version) is None


@pytest.mark.parametrize('ranges', [
    [[None, True, '2.0', True]],            # a missing bound is not "any"
    [['1.0', None, '2.0', True]],           # nor is a missing inclusive flag
    None,                                   # no affected_versions at all
])
def test_a_missing_part_of_a_range_is_unknown(ranges):
    assert wordfence.affects(ranges, '1.5') is None


@pytest.mark.parametrize('ranges', [[['beta', True, 'trunk', True]], [['1.0', True, 'dev', True]]])
def test_a_bound_that_is_not_a_version_is_unknown(ranges):
    assert wordfence.affects(ranges, '1.2.0') is None


def test_one_matching_range_is_enough():
    assert wordfence.affects([['1.0', True, '1.1', True], ['2.0', True, '2.1', True]], '2.0.5') is True


def test_a_version_that_is_not_a_version_is_unknown():
    assert wordfence.affects([['*', True, '*', True]], 'trunk') is None


# --- the index and its cache --------------------------------------------------------

def test_refresh_builds_a_private_index_next_to_the_database(downloads):
    meta = wordfence.refresh(KEY)
    path = wordfence.index_path()
    assert path.parent == storage.DB_PATH.parent
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert meta['records'] == 5                                 # the informational one is skipped
    assert downloads == [KEY]
    text = path.read_bytes()
    assert KEY.encode() not in text                             # the key is never stored


def test_lookup_by_core_and_plugin_slug(downloads):
    result = wordfence.vulnerabilities([('core', 'wordpress', '6.4.3'), ('plugin', 'LearnPress', '4.2.6'),
                                        ('plugin', 'elementor', '3.20.3')], KEY)
    assert result['status'] == 'ok'
    assert [v['id'] for v in result['matches']['core']] == ['aaaa-5']
    assert sorted(v['id'] for v in result['matches']['plugin:learnpress']) == ['aaaa-1', 'aaaa-2']
    assert result['matches']['plugin:elementor'] == []          # 3.20.3 is fixed; aaaa-4 informational
    hole = next(v for v in result['matches']['plugin:learnpress'] if v['id'] == 'aaaa-1')
    assert hole['cve'] == 'CVE-2024-1111' and hole['rating'] == 'Critical' and hole['score'] == 9.8
    assert hole['patched_versions'] == ['4.2.7']
    assert hole['remediation'] == 'Update to version 4.2.7'
    assert hole['link'] == 'https://www.wordfence.com/threat-intel/vulnerabilities/id/aaaa-1?source=api-prod'


def test_notices_for_the_licence(downloads):
    result = wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY)
    notices = {n['notice']: n for n in result['notices']}
    assert notices[DEFIANT['notice']]['license_url'] == DEFIANT['license_url']
    assert MITRE['notice'] in notices
    assert result['source'] == 'Wordfence Intelligence'


def test_unknown_bounds_are_reported_not_dropped(downloads):
    result = wordfence.vulnerabilities([('plugin', 'oddplugin', '1.2.0')], KEY)
    assert result['matches']['plugin:oddplugin'] == []
    assert result['uncertain']['plugin:oddplugin'] == ['aaaa-6']


def test_a_fresh_index_is_not_downloaded_again(downloads):
    wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY)
    wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY)
    assert downloads == [KEY]


def test_an_index_older_than_a_day_is_refreshed(downloads):
    wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY)
    later = time.time() + wordfence.MAX_AGE_SEC + 60
    result = wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY, now=later)
    assert downloads == [KEY, KEY]
    assert result['stale'] is False


@pytest.mark.parametrize('error, words', [
    (wordfence.FeedError('the Wordfence key was rejected (HTTP 401)'), 'rejected'),
    (wordfence.FeedError('Wordfence rate limit (HTTP 429)'), '429'),
    (wordfence.FeedError('could not download the Wordfence feed: timed out'), 'timed out'),
])
def test_no_index_and_a_failed_download_is_an_error(downloads, error, words):
    downloads.error = error
    result = wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY)
    assert result['status'] == 'error'
    assert words in result['error']
    assert KEY not in json.dumps(result)
    assert not wordfence.index_path().exists()


def test_a_failed_refresh_keeps_a_recent_index_and_says_so(downloads):
    wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY)
    downloads.error = wordfence.FeedError('Wordfence rate limit (HTTP 429)')
    later = time.time() + 2 * 86400
    result = wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY, now=later)
    assert result['status'] == 'ok'
    assert result['stale'] is True
    assert '429' in result['refresh_error']
    assert len(result['matches']['plugin:learnpress']) == 2


def test_an_index_too_old_to_trust_is_an_error(downloads):
    wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY)
    downloads.error = wordfence.FeedError('could not download the Wordfence feed: timed out')
    later = time.time() + (wordfence.MAX_STALE_DAYS + 1) * 86400
    result = wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY, now=later)
    assert result['status'] == 'error'
    assert 'days old' in result['error']


def test_a_broken_download_never_replaces_a_good_index(downloads):
    wordfence.refresh(KEY)
    before = wordfence.index_path().read_bytes()
    downloads.feed = _feed_text()[:-200]                        # cut in the middle
    with pytest.raises(wordfence.FeedError):
        wordfence.refresh(KEY)
    assert wordfence.index_path().read_bytes() == before
    assert [p.name for p in wordfence.index_path().parent.iterdir() if p.name.startswith('wordfence')] == ['wordfence.db']


def test_no_key_is_not_a_download(downloads):
    result = wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], '')
    assert result['status'] == 'error'
    assert 'no Wordfence API key' in result['error']
    assert downloads == []


# --- the real download, its errors and the key ----------------------------------------

def _transport(monkeypatch, status, body=b'{}', seen=None):
    import httpx

    def handler(request):
        if seen is not None:
            seen.append(request)
        return httpx.Response(status, content=body)

    monkeypatch.setattr(wordfence, '_TRANSPORT', httpx.MockTransport(handler))


def test_download_sends_the_key_as_a_bearer_token(monkeypatch):
    seen = []
    _transport(monkeypatch, 200, b'{"a": {"id": "a"}}', seen)
    assert ''.join(wordfence._download(KEY)) == '{"a": {"id": "a"}}'
    [request] = seen
    assert str(request.url) == wordfence.FEED_URL
    assert request.headers['authorization'] == f'Bearer {KEY}'


@pytest.mark.parametrize('status, words', [(401, 'rejected'), (403, 'rejected'), (429, '429'), (500, 'HTTP 500')])
def test_download_errors_name_the_reason_not_the_key(monkeypatch, status, words):
    _transport(monkeypatch, status, b'{"message": "nope"}')
    with pytest.raises(wordfence.FeedError) as e:
        list(wordfence._download(KEY))
    assert words in str(e.value)
    assert KEY not in str(e.value)
    assert e.value.auth_failed is (status in (401, 403))
    assert e.value.rate_limited is (status == 429)


def test_download_has_a_size_cap(monkeypatch):
    monkeypatch.setattr(wordfence, 'MAX_FEED_BYTES', 10)
    _transport(monkeypatch, 200, b'{"a": {"id": "aaaaaaaaaaaaaaaa"}}')
    with pytest.raises(wordfence.FeedError, match='larger than'):
        list(wordfence._download(KEY))


def test_index_directory_stays_private(downloads):
    wordfence.refresh(KEY)
    assert not stat.S_IMODE(os.stat(wordfence.index_path().parent).st_mode) & 0o077



# --- review #61 pass 1 -----------------------------------------------------------------
# (1) a feed must hold records the index can use before it replaces anything

def test_an_empty_feed_never_replaces_a_good_index(downloads):
    wordfence.refresh(KEY)
    before = wordfence.index_path().read_bytes()
    downloads.feed = '{}'
    with pytest.raises(wordfence.FeedError, match='no vulnerability records'):
        wordfence.refresh(KEY)
    assert wordfence.index_path().read_bytes() == before
    later = time.time() + wordfence.MAX_AGE_SEC + 60
    result = wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY, now=later)
    assert result['stale'] is True and len(result['matches']['plugin:learnpress']) == 2


def test_a_much_smaller_feed_never_replaces_a_good_index(downloads):
    wordfence.refresh(KEY)                                          # 5 records
    downloads.feed = _feed_text({'aaaa-3': FEED['aaaa-3']})
    with pytest.raises(wordfence.FeedError, match='previous'):
        wordfence.refresh(KEY)


def test_a_first_empty_feed_is_an_error_not_a_clean_index(downloads):
    # a record without software is now refused as unexpected (pass 2); an empty feed is this case
    downloads.feed = '{}'
    result = wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY)
    assert result['status'] == 'error' and 'no vulnerability records' in result['error']


def test_a_record_without_ranges_is_unknown_not_none(downloads):
    feed = dict(FEED)
    feed['bbbb-1'] = _record('bbbb-1', 'noranges', [])
    del feed['bbbb-1']['software'][0]['affected_versions']
    downloads.feed = _feed_text(feed)
    result = wordfence.vulnerabilities([('plugin', 'noranges', '1.0')], KEY)
    assert result['matches']['plugin:noranges'] == []
    assert result['uncertain']['plugin:noranges'] == ['bbbb-1']


# (2) the key never reaches an error text, whatever the library says

def test_a_transport_error_text_is_never_passed_on(monkeypatch):
    import httpx

    def handler(request):
        raise httpx.LocalProtocolError(f"Illegal header value b'Bearer {KEY}'")

    monkeypatch.setattr(wordfence, '_TRANSPORT', httpx.MockTransport(handler))
    with pytest.raises(wordfence.FeedError) as e:
        list(wordfence._download(KEY))
    assert KEY not in str(e.value) and 'Illegal header' not in str(e.value)


@pytest.mark.parametrize('bad', ['has space inside', 'line\nbreak-0123456789', 'short', 'x' * 600])
def test_a_key_that_cannot_be_a_key_is_refused_before_any_request(downloads, bad):
    result = wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], bad)
    assert result['status'] == 'error' and 'not a valid' in result['error']
    assert bad not in result['error']
    assert downloads == []


# (3) one download at a time, and a pause after a failure

def test_parallel_lookups_download_once(downloads, monkeypatch):
    import threading

    download = wordfence._download
    slow_calls = []

    def slow(key):
        slow_calls.append(key)
        time.sleep(0.3)
        return download(key)

    monkeypatch.setattr(wordfence, '_download', slow)
    start = threading.Barrier(2)
    results = []

    def lookup():
        start.wait()
        results.append(wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY))

    threads = [threading.Thread(target=lookup) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(slow_calls) == 1
    assert [r['status'] for r in results] == ['ok', 'ok']


def test_a_failed_download_is_not_tried_again_at_once(downloads):
    downloads.error = wordfence.FeedError('could not download the Wordfence feed: timed out')
    now = time.time()
    first = wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY, now=now)
    second = wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY, now=now + 60)
    assert downloads == [KEY]
    assert first['status'] == second['status'] == 'error'
    assert 'timed out' in second['error'] and 'next try' in second['error']
    wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY, now=now + wordfence.RETRY_SEC + 60)
    assert downloads == [KEY, KEY]


def test_a_rate_limit_pauses_longer(downloads):
    downloads.error = wordfence.FeedError('Wordfence rate limit (HTTP 429): try again later', rate_limited=True)
    now = time.time()
    wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY, now=now)
    wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY, now=now + wordfence.RETRY_SEC + 60)
    assert downloads == [KEY]
    wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY, now=now + wordfence.RETRY_429_SEC + 60)
    assert downloads == [KEY, KEY]


def test_a_success_clears_the_pause(downloads):
    downloads.error = wordfence.FeedError('could not download the Wordfence feed: timed out')
    now = time.time()
    wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY, now=now)
    downloads.error = None
    ok = wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY, now=now + wordfence.RETRY_SEC + 60)
    assert ok['status'] == 'ok' and ok['stale'] is False


def test_the_stale_window_is_exact(downloads):
    now = time.time()
    wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY, now=now)
    downloads.error = wordfence.FeedError('could not download the Wordfence feed: timed out')
    late = now + wordfence.MAX_STALE_DAYS * 86400 + 3600              # 7 days and an hour
    result = wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY, now=late)
    assert result['status'] == 'error' and 'days old' in result['error']


# (attribution) the record's own link, https; none is made up

def test_the_documented_http_reference_becomes_the_https_link(downloads):
    feed = {'cccc-1': _record('cccc-1', 'linked', [_range('*', '2.0')])}
    feed['cccc-1']['references'] = ['http://www.wordfence.com/threat-intel/vulnerabilities/example']
    feed.update({k: FEED[k] for k in ('aaaa-1', 'aaaa-2', 'aaaa-3')})
    downloads.feed = _feed_text(feed)
    [hit] = wordfence.vulnerabilities([('plugin', 'linked', '1.0')], KEY)['matches']['plugin:linked']
    assert hit['link'] == 'https://www.wordfence.com/threat-intel/vulnerabilities/example'


def test_no_record_link_is_no_link(downloads):
    feed = {'cccc-2': _record('cccc-2', 'unlinked', [_range('*', '2.0')])}
    feed['cccc-2']['references'] = ['https://example.com/advisory', 'javascript:alert(1)']
    feed.update({k: FEED[k] for k in ('aaaa-1', 'aaaa-2', 'aaaa-3')})
    downloads.feed = _feed_text(feed)
    [hit] = wordfence.vulnerabilities([('plugin', 'unlinked', '1.0')], KEY)['matches']['plugin:unlinked']
    assert hit['link'] is None


# --- review #61 pass 2 ----------------------------------------------------------------
# (1) a damaged record: unknown component -> the whole new feed is refused;
# known component -> its broken ranges are "unknown"; no shape crashes

def _two_records():
    return {'aaaa-1': FEED['aaaa-1'], 'aaaa-3': FEED['aaaa-3']}


@pytest.mark.parametrize('damage', [
    lambda r: r.update(software=None),
    lambda r: r.update(software=5),
    lambda r: r.update(software='plugin'),
    lambda r: r.update(software=[5]),
    lambda r: r['software'][0].update(type=7),
    lambda r: r['software'][0].pop('slug'),
    lambda r: r['software'][0].update(slug=['x']),
])
def test_a_record_of_an_unknown_component_refuses_the_whole_feed(downloads, damage):
    downloads.feed = _feed_text(_two_records())
    wordfence.refresh(KEY)
    before = wordfence.index_path().read_bytes()
    damaged = json.loads(_feed_text(_two_records()))
    damage(damaged['aaaa-1'])
    downloads.feed = json.dumps(damaged)
    with pytest.raises(wordfence.FeedError, match='unexpected'):
        wordfence.refresh(KEY)
    assert wordfence.index_path().read_bytes() == before
    later = time.time() + wordfence.MAX_AGE_SEC + 60
    result = wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY, now=later)
    assert result['stale'] is True
    assert [v['id'] for v in result['matches']['plugin:learnpress']] == ['aaaa-1']


@pytest.mark.parametrize('affected', [
    {'ok': {'from_version': '9.0', 'from_inclusive': True, 'to_version': '9.1', 'to_inclusive': True}, 'bad': None},
    {'ok': {'from_version': '9.0', 'from_inclusive': True, 'to_version': '9.1', 'to_inclusive': True}, 'bad': 'x'},
    ['not', 'a', 'map'],
    {},
])
def test_broken_ranges_of_a_known_component_are_unknown(downloads, affected):
    feed = dict(FEED)
    feed['dddd-1'] = _record('dddd-1', 'mixed', [_range('9.0', '9.1')])
    feed['dddd-1']['software'][0]['affected_versions'] = affected
    downloads.feed = _feed_text(feed)
    result = wordfence.vulnerabilities([('plugin', 'mixed', '1.0')], KEY)
    assert result['status'] == 'ok'
    assert result['matches']['plugin:mixed'] == []
    assert result['uncertain']['plugin:mixed'] == ['dddd-1']


def test_odd_shapes_of_other_fields_do_not_crash(downloads):
    feed = dict(FEED)
    odd = _record('eeee-1', 'oddfields', [_range('*', '2.0')])
    odd.update(cvss='high', references='http://www.wordfence.com/threat-intel/vulnerabilities/x',
               copyrights=['not', 'a', 'map'], informational='no', title=12)
    odd['software'][0].update(patched_versions='2.1', remediation=None)
    feed['eeee-1'] = odd
    downloads.feed = _feed_text(feed)
    result = wordfence.vulnerabilities([('plugin', 'oddfields', '1.0')], KEY)
    [hit] = result['matches']['plugin:oddfields']
    assert hit['rating'] is None and hit['score'] is None and hit['link'] is None
    assert hit['patched_versions'] == [] and hit['title'] == '12'


def test_an_unknown_software_type_is_skipped_not_refused(downloads):
    # a positive control: a new kind of software Wordfence may add later is not ours to judge
    feed = dict(FEED)
    feed['ffff-1'] = _record('ffff-1', 'somelib', [_range('*', '2.0')], type_='library')
    downloads.feed = _feed_text(feed)
    assert wordfence.refresh(KEY)['records'] == 5
    result = wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY)
    assert len(result['matches']['plugin:learnpress']) == 2


# (2) a rejected key pauses only itself; a rate limit pauses everyone

def test_a_new_key_is_tried_at_once_after_a_rejected_one(downloads):
    downloads.error = wordfence.FeedError('the Wordfence key was rejected (HTTP 401): check it in Settings',
                                          auth_failed=True)
    now = time.time()
    wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY, now=now)
    again = wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY, now=now + 1)
    assert downloads == [KEY] and 'next try' in again['error']             # the same key waits
    downloads.error = None
    new_key = 'wf-new-key-9876543210'
    result = wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], new_key, now=now + 2)
    assert downloads == [KEY, new_key]
    assert result['status'] == 'ok'
    assert KEY not in wordfence._failure_path().read_text() if wordfence._failure_path().exists() else True


def test_a_rate_limit_pauses_a_new_key_too(downloads):
    downloads.error = wordfence.FeedError('Wordfence rate limit (HTTP 429): try again later', rate_limited=True)
    now = time.time()
    wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY, now=now)
    wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], 'wf-new-key-9876543210', now=now + 2)
    assert downloads == [KEY]


def test_the_pause_file_never_holds_the_key(downloads):
    downloads.error = wordfence.FeedError('the Wordfence key was rejected (HTTP 401): check it in Settings',
                                          auth_failed=True)
    wordfence.vulnerabilities([('plugin', 'learnpress', '4.2.6')], KEY)
    text = wordfence._failure_path().read_text()
    assert KEY not in text
