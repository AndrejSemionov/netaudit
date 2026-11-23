"""
Known WordPress vulnerabilities from the Wordfence Intelligence feed
(docs/research/wordpress_audit.md §3, §9; contract C3).

The v3 production feed is one JSON object of records keyed by UUID, free
with a personal key (`Authorization: Bearer`), whole or nothing - there is
no per-plugin query. It is downloaded at most once a day, by one caller at
a time (a file lock), and parsed as a stream, one record at a time, into a
small SQLite index next to the NetAudit database: the feed is never held
in memory whole. A failed, broken, empty or much smaller download never
replaces a good index; after a failure the next try waits RETRY_SEC
(RETRY_429_SEC after a rate limit); an index up to MAX_STALE_DAYS old is
used meanwhile, and says so.

The key goes only into the request header, and only after it passed a
plain format check: never into the index, an error text or a result. Error
texts are fixed reasons, never a library's message. A version is compared
only when it and the range bounds are dotted numbers (or a lone '*'); a
suffix ("2.0-rc1"), a pattern ("1.*") or a missing bound or flag makes the
answer "unknown", not "no" (review #61 pass 1).
"""

from __future__ import annotations

import codecs
import contextlib
import hashlib
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

try:
    import fcntl
except ImportError:   # not POSIX: no lock between processes, the rest still holds
    fcntl = None

FEED_URL = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production'
SOURCE = 'Wordfence Intelligence'
TIMEOUT = 60
MAX_FEED_BYTES = 800 * 1024 * 1024
MAX_AGE_SEC = 24 * 3600
MAX_STALE_DAYS = 7
RETRY_SEC = 3600
RETRY_429_SEC = 6 * 3600

_TRANSPORT = None   # tests put an httpx.MockTransport here
_WS = ' \t\r\n'
_VERSION = re.compile(r'\d+(?:\.\d+)*')
_KEY = re.compile(r'[\x21-\x7e]{8,512}')      # printable ASCII, no space: safe in a header
_RECORD_LINK = re.compile(r'https?://www\.wordfence\.com/threat-intel/vulnerabilities/[A-Za-z0-9/_.?=&%-]+')


class FeedError(Exception):
    """The feed could not be had or read; the message names the reason, never the key."""

    def __init__(self, message: str, *, rate_limited: bool = False, auth_failed: bool = False):
        super().__init__(message)
        self.rate_limited = rate_limited
        self.auth_failed = auth_failed


# --- download --------------------------------------------------------------------

def _download(key: str) -> Iterator[str]:
    """The feed as text chunks. Raises FeedError on any failure, with a fixed
    reason: a library's own message may quote a header, the key included."""
    try:
        with (httpx.Client(timeout=TIMEOUT, transport=_TRANSPORT,
                           headers={'User-Agent': wordpress_org.USER_AGENT}) as client,
              client.stream('GET', FEED_URL, headers={'Authorization': f'Bearer {key}'}) as resp):
            if resp.status_code in (401, 403):
                raise FeedError(f'the Wordfence key was rejected (HTTP {resp.status_code}): check it in Settings',
                                auth_failed=True)
            if resp.status_code == 429:
                raise FeedError('Wordfence rate limit (HTTP 429): try again later', rate_limited=True)
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
    except httpx.TimeoutException:
        raise FeedError('could not download the Wordfence feed: timed out') from None
    except httpx.ConnectError:
        raise FeedError('could not download the Wordfence feed: could not connect') from None
    except httpx.HTTPError as e:
        raise FeedError(f'could not download the Wordfence feed: {type(e).__name__}') from None


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
    """Dotted numbers only; anything else (a suffix, a pattern, None) is None."""
    if not isinstance(version, str) or not _VERSION.fullmatch(version.strip()):
        return None
    return tuple(int(part) for part in version.strip().split('.'))


def _compare(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    width = max(len(a), len(b))
    a, b = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    return (a > b) - (a < b)


def affects(ranges: list | None, version: str) -> bool | None:
    """True when `version` is in one of the [from, from_inclusive, to,
    to_inclusive] ranges ('*' = any); None when that cannot be told (no
    ranges, a missing bound or flag, a bound or the version not dotted
    numbers); False otherwise."""
    current = _version_key(version)
    if current is None or not ranges:
        return None
    unknown = False
    for low, low_incl, high, high_incl in ranges:
        lo = None if low == '*' else _version_key(low)
        hi = None if high == '*' else _version_key(high)
        if ((low != '*' and lo is None) or (high != '*' and hi is None)
                or not isinstance(low_incl, bool) or not isinstance(high_incl, bool)):
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


def _record_link(record: dict) -> str | None:
    """The record's own page on wordfence.com (http -> https); none is made up."""
    refs = record.get('references')
    for ref in refs if isinstance(refs, list) else []:
        if isinstance(ref, str) and _RECORD_LINK.fullmatch(ref):
            return 'https://' + ref.split('://', 1)[1]
    return None


def _ranges(software: dict) -> list | None:
    """[[from, from_inclusive, to, to_inclusive]] as given - a missing part
    stays missing (None), it is not "any" - or None without ranges."""
    affected = software.get('affected_versions')
    if not isinstance(affected, dict) or not affected:
        return None
    if not all(isinstance(r, dict) for r in affected.values()):
        return None   # one broken range makes the whole entry unknown, it is not dropped (review #61 pass 2)
    return [[r.get('from_version'), r.get('from_inclusive'), r.get('to_version'), r.get('to_inclusive')]
            for r in affected.values()]


def _entry(uid: str, record: dict, software: dict) -> dict:
    """What the index keeps of one component of a record. Fields of an odd
    shape are left out, never a crash (review #61 pass 2)."""
    cvss = record.get('cvss') if isinstance(record.get('cvss'), dict) else {}
    score = cvss.get('score')
    patched = software.get('patched_versions')
    return {'id': uid, 'title': str(record.get('title') or '')[:300],
            'cve': record['cve'] if isinstance(record.get('cve'), str) and record['cve'] else None,
            'score': score if isinstance(score, (int, float)) and not isinstance(score, bool) else None,
            'rating': cvss['rating'] if isinstance(cvss.get('rating'), str) else None,
            'ranges': _ranges(software),
            'patched_versions': [str(v) for v in patched][:10] if isinstance(patched, list) else [],
            'remediation': str(software.get('remediation') or '')[:300], 'link': _record_link(record)}


def _unexpected(uid: str, what: str) -> FeedError:
    safe = re.sub(r'[^A-Za-z0-9-]', '', uid)[:40]
    return FeedError(f'the Wordfence feed has an unexpected record ({safe}: {what}): the previous data is kept')


def _components(uid: str, record: dict) -> list[tuple[str, dict]]:
    """(index key, software) of each component of the record we judge: the
    core, a plugin, a theme; another type is not ours and is skipped. A
    component that cannot be told (software not a list of objects, no type,
    a plugin or theme without a slug) refuses the whole feed: a record that
    is dropped could be the one that matches (review #61 pass 2)."""
    software = record.get('software')
    if not isinstance(software, list) or not software:
        raise _unexpected(uid, 'no software list')
    out = []
    for item in software:
        if not isinstance(item, dict) or not isinstance(item.get('type'), str):
            raise _unexpected(uid, 'a software entry without a type')
        if item['type'] == 'core':
            out.append(('core', item))
        elif item['type'] in ('plugin', 'theme'):
            slug = item.get('slug')
            if not isinstance(slug, str) or not slug.strip():
                raise _unexpected(uid, f'a {item["type"]} without a slug')
            out.append((f'{item["type"]}:{slug.strip().lower()}', item))
    return out


def _records_in_index() -> int | None:
    conn = _open_index()
    if conn is None:
        return None
    try:
        return int(_meta(conn).get('records') or 0)
    finally:
        conn.close()


def refresh(key: str, now: float | None = None) -> dict:
    """Downloads the feed into a new index and puts it in place only when it
    is complete and plausible: at least one record with software to index,
    and not less than half the records of the index it replaces. Returns
    {'records', 'fetched_at'}; raises FeedError."""
    storage.DB_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    storage._private_path(storage.DB_PATH.parent, 0o700)   # like the database's directory (C1 D6)
    final = index_path()
    previous = _records_in_index()
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
                if record.get('informational') is True:
                    continue
                components = _components(uid, record)
                for index_key, software in components:
                    conn.execute('INSERT INTO vulns VALUES (?, ?)',
                                 (index_key, json.dumps(_entry(uid, record, software))))
                if not components:
                    continue
                records += 1
                claims = record.get('copyrights')
                for name, claim in (claims.items() if isinstance(claims, dict) else []):
                    if isinstance(claim, dict) and claim.get('notice') and name not in notices:
                        notices[name] = {'name': name, 'notice': str(claim['notice']),
                                         'license': str(claim.get('license') or ''),
                                         'license_url': str(claim.get('license_url') or '')}
            if not records:
                raise FeedError('the Wordfence feed has no vulnerability records: the previous data is kept')
            if previous and records * 2 < previous:
                raise FeedError(f'the new Wordfence feed has {records} records, the previous had {previous}: '
                                'the previous data is kept')
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


def _fetched_at() -> float | None:
    conn = _open_index()
    if conn is None:
        return None
    try:
        return float(_meta(conn)['fetched_at'])
    except (KeyError, ValueError, sqlite3.Error):
        return None
    finally:
        conn.close()


# --- one refresh at a time, and a pause after a failure -----------------------------------

@contextlib.contextmanager
def _refresh_lock():
    """One refresh at a time, across threads and processes (Web and CLI)."""
    path = index_path().with_name('wordfence.lock')
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _failure_path() -> Path:
    return index_path().with_name('wordfence.failed')


def _last_failure() -> dict | None:
    try:
        data = json.loads(_failure_path().read_text())
        return data if isinstance(data, dict) and 'retry_at' in data and 'error' in data else None
    except (OSError, ValueError):
        return None


def _key_id(key: str) -> str:
    """Which key failed, without keeping it: a short hash."""
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _record_failure(error: FeedError, now: float, key: str) -> None:
    """A rejected key pauses only itself - a new key from Settings is tried at
    once; a rate limit or any other failure pauses every key (review #61 pass 2)."""
    wait = RETRY_429_SEC if error.rate_limited else RETRY_SEC
    data = {'error': str(error), 'retry_at': now + wait}
    if error.auth_failed:
        data['key_id'] = _key_id(key)
    fd = os.open(_failure_path(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(data, f)


def _pending_failure(now: float, key: str) -> str | None:
    """The last failure's reason while its pause lasts for this key, else None."""
    failure = _last_failure()
    if failure is None or now >= float(failure['retry_at']):
        return None
    if 'key_id' in failure and failure['key_id'] != _key_id(key):
        return None
    at = datetime.fromtimestamp(float(failure['retry_at']), UTC).strftime('%Y-%m-%d %H:%M UTC')
    return f'{failure["error"]} (next try after {at})'


def _ensure_fresh(key: str, now: float) -> str | None:
    """Refreshes the index when it is missing or older than MAX_AGE_SEC; the
    reason it could not, or None."""
    fetched = _fetched_at()
    if fetched is not None and now - fetched < MAX_AGE_SEC:
        return None
    pending = _pending_failure(now, key)
    if pending:
        return pending
    storage.DB_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with _refresh_lock():
        # another thread or process may have refreshed or failed meanwhile
        fetched = _fetched_at()
        if fetched is not None and now - fetched < MAX_AGE_SEC:
            return None
        pending = _pending_failure(now, key)
        if pending:
            return pending
        try:
            refresh(key, now=now)
        except FeedError as e:
            _record_failure(e, now, key)
            return str(e)
        with contextlib.suppress(FileNotFoundError):
            _failure_path().unlink()
        return None


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
    if not _KEY.fullmatch(key):
        return error('the Wordfence key in Settings is not a valid key (unexpected characters or length)')
    now = time.time() if now is None else now
    refresh_error = _ensure_fresh(key, now)
    conn = _open_index()
    if conn is None:
        return error(refresh_error or 'the Wordfence data could not be read')
    try:
        meta = _meta(conn)
        fetched_at = float(meta['fetched_at'])
        age = now - fetched_at
        if refresh_error and age > MAX_STALE_DAYS * 86400:
            return error(f'{refresh_error}; the local Wordfence data is {int(age // 86400)} days old')
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
