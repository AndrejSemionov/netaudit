"""
Known WordPress vulnerabilities from the Wordfence Intelligence feed
(docs/research/wordpress_audit.md §3, §9; contract C3).

The v3 production feed is one JSON object of records keyed by UUID, free
with a personal key (`Authorization: Bearer`), whole or nothing - there is
no per-plugin query. It is downloaded at most once a day and parsed as a
stream, one record at a time, into a small SQLite index next to the
NetAudit database: the feed is never held in memory whole. A failed or
broken download never replaces a good index; an index up to MAX_STALE_DAYS
old is used when a refresh fails, and says so.

The key goes only into the request header: never into the index, an error
text or a result. A version is compared by its leading dotted numbers; a
range bound that is not a version makes the answer "unknown", not "no".
"""

from __future__ import annotations

import codecs
import contextlib
import json
import os
import re
import sqlite3
import tempfile
import time
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path

import httpx

from . import storage, wordpress_org

FEED_URL = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production'
RECORD_URL = 'https://www.wordfence.com/threat-intel/vulnerabilities/'
SOURCE = 'Wordfence Intelligence'
TIMEOUT = 60
MAX_FEED_BYTES = 800 * 1024 * 1024
MAX_AGE_SEC = 24 * 3600
MAX_STALE_DAYS = 7

_TRANSPORT = None   # tests put an httpx.MockTransport here
_WS = ' \t\r\n'
_LEAD = re.compile(r'\d+(?:\.\d+)*')


class FeedError(Exception):
    """The feed could not be had or read; the message names the reason, never the key."""


# --- download --------------------------------------------------------------------

def _download(key: str) -> Iterator[str]:
    """The feed as text chunks. Raises FeedError on any failure."""
    try:
        with (httpx.Client(timeout=TIMEOUT, transport=_TRANSPORT,
                           headers={'User-Agent': wordpress_org.USER_AGENT}) as client,
              client.stream('GET', FEED_URL, headers={'Authorization': f'Bearer {key}'}) as resp):
            if resp.status_code in (401, 403):
                raise FeedError(f'the Wordfence key was rejected (HTTP {resp.status_code}): check it in Settings')
            if resp.status_code == 429:
                raise FeedError('Wordfence rate limit (HTTP 429): try again later')
            if resp.status_code != 200:
                raise FeedError(f'the Wordfence feed answered HTTP {resp.status_code}')
            decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
            size = 0
            for chunk in resp.iter_bytes():
                size += len(chunk)
                if size > MAX_FEED_BYTES:
                    raise FeedError(f'the Wordfence feed is larger than {MAX_FEED_BYTES} bytes')
                text = decoder.decode(chunk)
                if text:
                    yield text
            tail = decoder.decode(b'', final=True)
            if tail:
                yield tail
    except httpx.HTTPError as e:
        raise FeedError(f'could not download the Wordfence feed: {e}') from None


# --- the stream parser -------------------------------------------------------------

def iter_records(chunks: Iterable[str]) -> Iterator[tuple[str, dict]]:
    """(uuid, record) pairs of the feed's top-level object, one at a time.
    Only the record being read is kept in memory. FeedError on bad JSON."""
    decoder = json.JSONDecoder()
    source = iter(chunks)
    buf, pos = '', 0

    def more() -> bool:
        nonlocal buf, pos
        for chunk in source:
            if chunk:
                buf, pos = buf[pos:] + chunk, 0
                return True
        return False

    def skip_ws() -> bool:
        """Moves past whitespace; False at the end of the feed."""
        nonlocal pos
        while True:
            while pos < len(buf) and buf[pos] in _WS:
                pos += 1
            if pos < len(buf):
                return True
            if not more():
                return False

    def take(char: str) -> None:
        nonlocal pos
        if not skip_ws() or buf[pos] != char:
            raise FeedError(f'the Wordfence feed is not the expected JSON (expected {char!r})')
        pos += 1

    def value():
        nonlocal pos
        if not skip_ws():
            raise FeedError('the Wordfence feed ended in the middle of a record')
        while True:
            try:
                obj, end = decoder.raw_decode(buf, pos)
            except json.JSONDecodeError:
                if not more():
                    raise FeedError('the Wordfence feed ended in the middle of a record') from None
                continue
            pos = end
            return obj

    take('{')
    if not skip_ws():
        raise FeedError('the Wordfence feed ended in the middle of a record')
    if buf[pos] == '}':
        pos += 1
    else:
        while True:
            uid = value()
            take(':')
            record = value()
            if not isinstance(uid, str) or not isinstance(record, dict):
                raise FeedError('the Wordfence feed is not the expected JSON (a record is not an object)')
            yield uid, record
            if not skip_ws():
                raise FeedError('the Wordfence feed ended in the middle of a record')
            char = buf[pos]
            pos += 1
            if char == '}':
                break
            if char != ',':
                raise FeedError('the Wordfence feed is not the expected JSON (between records)')
    if skip_ws():
        raise FeedError('the Wordfence feed is not the expected JSON (data after its end)')


# --- versions ------------------------------------------------------------------------

def _version_key(version) -> tuple[int, ...] | None:
    m = _LEAD.match(str(version).strip())
    return tuple(int(part) for part in m.group().split('.')) if m else None


def _compare(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    width = max(len(a), len(b))
    a, b = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    return (a > b) - (a < b)


def affects(ranges: list, version: str) -> bool | None:
    """True when `version` is in one of the [from, from_inclusive, to,
    to_inclusive] ranges ('*' = any); None when that cannot be told (the
    version or a bound is not a version); False otherwise."""
    current = _version_key(version)
    if current is None:
        return None
    unknown = False
    for low, low_incl, high, high_incl in ranges:
        lo = None if low == '*' else _version_key(low)
        hi = None if high == '*' else _version_key(high)
        if (low != '*' and lo is None) or (high != '*' and hi is None):
            unknown = True
            continue
        if lo is not None:
            c = _compare(current, lo)
            if c < 0 or (c == 0 and not low_incl):
                continue
        if hi is not None:
            c = _compare(current, hi)
            if c > 0 or (c == 0 and not high_incl):
                continue
        return True
    return None if unknown else False


# --- the index ---------------------------------------------------------------------

def index_path() -> Path:
    return storage.DB_PATH.parent / 'wordfence.db'


def _entry(uid: str, record: dict, software: dict) -> dict:
    cvss = record.get('cvss') if isinstance(record.get('cvss'), dict) else {}
    links = [r for r in record.get('references') or [] if isinstance(r, str) and r.startswith(RECORD_URL)]
    ranges = [[r.get('from_version', '*'), bool(r.get('from_inclusive', True)),
               r.get('to_version', '*'), bool(r.get('to_inclusive', True))]
              for r in (software.get('affected_versions') or {}).values() if isinstance(r, dict)]
    return {'id': uid, 'title': str(record.get('title') or '')[:300], 'cve': record.get('cve') or None,
            'score': cvss.get('score'), 'rating': cvss.get('rating'), 'ranges': ranges,
            'patched_versions': [str(v) for v in software.get('patched_versions') or []][:10],
            'remediation': str(software.get('remediation') or '')[:300],
            'link': links[0] if links else f'{RECORD_URL}id/{uid}'}


def refresh(key: str, now: float | None = None) -> dict:
    """Downloads the feed into a new index and puts it in place only when it
    is complete. Returns {'records', 'fetched_at'}; raises FeedError."""
    storage.DB_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    storage._private_path(storage.DB_PATH.parent, 0o700)   # like the database's directory (C1 D6)
    final = index_path()
    fd, tmp = tempfile.mkstemp(prefix='wordfence-', suffix='.tmp', dir=final.parent)   # mode 0600
    os.close(fd)
    fetched_at = time.time() if now is None else now
    try:
        conn = sqlite3.connect(tmp)
        try:
            conn.execute('CREATE TABLE vulns (key TEXT NOT NULL, data TEXT NOT NULL)')
            conn.execute('CREATE TABLE meta (name TEXT PRIMARY KEY, value TEXT NOT NULL)')
            notices: dict[str, dict] = {}
            records = 0
            for uid, record in iter_records(_download(key)):
                if record.get('informational'):
                    continue
                records += 1
                for software in record.get('software') or []:
                    if not isinstance(software, dict):
                        continue
                    slug = str(software.get('slug') or '').strip().lower()
                    if software.get('type') == 'core':
                        index_key = 'core'
                    elif software.get('type') in ('plugin', 'theme') and slug:
                        index_key = f'{software["type"]}:{slug}'
                    else:
                        continue
                    conn.execute('INSERT INTO vulns VALUES (?, ?)',
                                 (index_key, json.dumps(_entry(uid, record, software))))
                for name, claim in (record.get('copyrights') or {}).items():
                    if isinstance(claim, dict) and claim.get('notice') and name not in notices:
                        notices[name] = {'name': name, 'notice': str(claim['notice']),
                                         'license': str(claim.get('license') or ''),
                                         'license_url': str(claim.get('license_url') or '')}
            conn.execute('CREATE INDEX vulns_key ON vulns (key)')
            conn.executemany('INSERT INTO meta VALUES (?, ?)', [
                ('fetched_at', str(fetched_at)), ('records', str(records)),
                ('notices', json.dumps(list(notices.values())))])
            conn.commit()
        finally:
            conn.close()
        os.replace(tmp, final)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    return {'records': records, 'fetched_at': fetched_at}


def _open_index() -> sqlite3.Connection | None:
    path = index_path()
    if not path.exists():
        return None
    try:
        conn = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
        conn.execute('SELECT 1 FROM meta LIMIT 1')
        return conn
    except sqlite3.Error:
        return None   # unreadable: rebuilt by the next refresh


def _meta(conn: sqlite3.Connection) -> dict:
    return dict(conn.execute('SELECT name, value FROM meta').fetchall())


# --- the lookup ----------------------------------------------------------------------

def _key(type_: str, slug: str) -> str:
    return 'core' if type_ == 'core' else f'{type_}:{slug.strip().lower()}'


def vulnerabilities(items: list[tuple[str, str, str]], key: str, now: float | None = None) -> dict:
    """Known vulnerabilities of (type, slug, version) items: 'core' or 'plugin'.
    {'status': 'ok', 'matches': {key: [vuln]}, 'uncertain': {key: [ids]},
    'source', 'fetched_at', 'stale', 'refresh_error', 'notices'} or
    {'status': 'error', 'error': reason, 'matches': {}, 'uncertain': {}}."""
    def error(reason):
        return {'status': 'error', 'error': reason, 'matches': {}, 'uncertain': {}}

    if not key:
        return error('no Wordfence API key in Settings (a free key from wordfence.com)')
    now = time.time() if now is None else now
    conn = _open_index()
    refresh_error = None
    if conn is None or now - float(_meta(conn)['fetched_at']) >= MAX_AGE_SEC:
        if conn is not None:
            conn.close()
        try:
            refresh(key, now=now)
        except FeedError as e:
            refresh_error = str(e)
        conn = _open_index()
    if conn is None:
        return error(refresh_error or 'the Wordfence data could not be read')
    try:
        meta = _meta(conn)
        fetched_at = float(meta['fetched_at'])
        age_days = int((now - fetched_at) // 86400)
        if refresh_error and age_days > MAX_STALE_DAYS:
            return error(f'{refresh_error}; the local Wordfence data is {age_days} days old')
        matches, uncertain = {}, {}
        for type_, slug, version in items:
            index_key = _key(type_, slug)
            matches[index_key], uncertain[index_key] = [], []
            for (data,) in conn.execute('SELECT data FROM vulns WHERE key = ?', (index_key,)):
                vuln = json.loads(data)
                hit = affects(vuln['ranges'], version)
                if hit:
                    matches[index_key].append({k: v for k, v in vuln.items() if k != 'ranges'})
                elif hit is None:
                    uncertain[index_key].append(vuln['id'])
        return {'status': 'ok', 'error': None, 'source': SOURCE,
                'fetched_at': datetime.fromtimestamp(fetched_at, UTC).strftime('%Y-%m-%dT%H:%M:%SZ'),
                'stale': refresh_error is not None, 'refresh_error': refresh_error,
                'matches': matches, 'uncertain': uncertain, 'notices': json.loads(meta.get('notices') or '[]')}
    finally:
        conn.close()
