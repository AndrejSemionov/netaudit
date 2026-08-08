"""
Single storage layer on SQLite. All other code goes through this module's
functions and doesn't know about SQL - if the backend ever needs to change,
only this file changes.

Tables:
  reports        - report history (metadata in columns + full JSON blob)
  timing_stats   - adaptive timing stats keyed by (check::target)
  settings       - key-value settings (API key, thresholds, Telegram)
  presets        - saved check sets
  targets        - default targets

Schema is versioned (PRAGMA user_version) - migrations are added to MIGRATIONS.
DB: ~/.netaudit/netaudit.db
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path

DB_PATH = Path.home() / '.netaudit' / 'netaudit.db'

_local = threading.local()


def _conn() -> sqlite3.Connection:
    """Per-thread connection (SQLite doesn't like being shared across threads)."""
    if not hasattr(_local, 'conn'):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL')  # safer under concurrent reads
        conn.execute('PRAGMA foreign_keys=ON')
        _local.conn = conn
        _migrate(conn)
    return _local.conn


# --- Migrations: list of functions, applied in order up to the current version ---

def _m1(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        checks TEXT NOT NULL,          -- CSV of check ids, for a quick listing
        total_time REAL,
        data TEXT NOT NULL             -- full report JSON
    );
    CREATE INDEX IF NOT EXISTS idx_reports_ts ON reports(timestamp);

    CREATE TABLE IF NOT EXISTS timing_stats (
        key TEXT PRIMARY KEY,          -- 'mtr::8.8.8.8'
        ema REAL NOT NULL,
        count INTEGER NOT NULL,
        last REAL NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    );

    CREATE TABLE IF NOT EXISTS presets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        checks TEXT NOT NULL,          -- JSON [{id, params}]
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        label TEXT,
        value TEXT NOT NULL,           -- IP or URL
        kind TEXT DEFAULT 'ip'         -- ip | url
    );
    """)


def _m2(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS rep_list (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern TEXT NOT NULL,          -- IP, subnet, or a domain substring
        list_type TEXT NOT NULL,        -- 'allow' | 'block'
        note TEXT,
        created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_rep_type ON rep_list(list_type);

    CREATE TABLE IF NOT EXISTS asn_cache (
        ip TEXT PRIMARY KEY,
        org TEXT,
        country TEXT,
        updated_at TEXT NOT NULL
    );
    """)


def _m3(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS cve_cache (
        key TEXT PRIMARY KEY,           -- 'nginx::1.24.0'
        data TEXT NOT NULL,             -- JSON: list of vulnerability IDs
        updated_at TEXT NOT NULL
    );
    """)


def _m4(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS traffic_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_ip TEXT NOT NULL,
        dst_ip TEXT NOT NULL,
        dst_port TEXT,
        protocol TEXT,
        risk_level TEXT,
        risk_score INTEGER,
        seen_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_traffic_history_seen ON traffic_history(seen_at);
    CREATE INDEX IF NOT EXISTS idx_traffic_history_target ON traffic_history(target_ip, seen_at);
    """)


MIGRATIONS = [_m1, _m2, _m3, _m4]


def _seed_presets(conn: sqlite3.Connection) -> None:
    """Starter presets for common tasks - created once, only if the table is empty.

    NOTE: preset names below are intentionally Russian - they're used as lookup
    keys in web/static/i18n.js's PRESET_NAME_TR dict, which translates them for
    display based on the UI language. Renaming a key here without updating that
    dict breaks the translation for both the newly-seeded default and anyone's
    already-stored presets on existing installs."""
    count = conn.execute('SELECT COUNT(*) FROM presets').fetchone()[0]
    if count > 0:
        return
    import json as _j
    from datetime import datetime as _dt
    defaults = [
        ('🌐 Неполадки в сети', [
            {'id': 'mtr', 'params': {'target': '8.8.8.8', 'count': 15}},
            {'id': 'tcptraceroute', 'params': {'target': '8.8.8.8', 'port': 80}},
            {'id': 'ping', 'params': {'target': '8.8.8.8', 'count': 10}},
            {'id': 'dig', 'params': {'hostname': 'google.com', 'record_type': 'A'}},
        ]),
        ('🔒 Аудит сайта (снаружи)', [
            {'id': 'ssl', 'params': {'url': 'https://example.com', 'method': 'auto'}},
            {'id': 'web_security_external', 'params': {'url': 'https://example.com'}},
            {'id': 'security_headers', 'params': {'url': 'https://example.com'}},
        ]),
        ('🖥️ Аудит сервера (SSH)', [
            {'id': 'server_audit', 'params': {'host': '', 'user': 'root', 'port': 22, 'key_path': '~/.ssh/id_rsa'}},
        ]),
        ('🛡️ Аудит сервера + CVE (SSH)', [
            {'id': 'server_audit', 'params': {'host': '', 'user': 'root', 'port': 22, 'key_path': '~/.ssh/id_rsa'}},
            {'id': 'cve_audit', 'params': {'host': '', 'user': 'root', 'port': 22, 'key_path': '~/.ssh/id_rsa'}},
        ]),
        ('📡 Куда уходит трафик', [
            {'id': 'mikrotik_sniffer', 'params': {'router': '192.168.88.1', 'user': 'admin', 'target_ip': '', 'analyze_threats': 'да'}},
        ]),
    ]
    for name, checks in defaults:
        conn.execute('INSERT INTO presets (name, checks, created_at) VALUES (?,?,?)',
                     (name, _j.dumps(checks, ensure_ascii=False), _dt.now().isoformat()))
    conn.commit()


_migrate_lock = threading.Lock()


def _migrate(conn: sqlite3.Connection) -> None:
    with _migrate_lock:
        version = conn.execute('PRAGMA user_version').fetchone()[0]
        for i, migration in enumerate(MIGRATIONS[version:], start=version):
            migration(conn)
            conn.execute(f'PRAGMA user_version = {i + 1}')
        conn.commit()
        _seed_presets(conn)


# ===========================================================================
# Reports
# ===========================================================================

def save_report(report: dict) -> int:
    conn = _conn()
    checks = ','.join(report.get('results', {}).keys())
    cur = conn.execute(
        'INSERT INTO reports (timestamp, checks, total_time, data) VALUES (?,?,?,?)',
        (report.get('timestamp'), checks, report.get('total_time'), json.dumps(report, ensure_ascii=False)),
    )
    conn.commit()
    return cur.lastrowid


def list_reports(limit: int = 50) -> list[dict]:
    conn = _conn()
    rows = conn.execute(
        'SELECT id, timestamp, checks, total_time FROM reports ORDER BY id DESC LIMIT ?',
        (limit,),
    ).fetchall()
    return [{'id': r['id'], 'timestamp': r['timestamp'],
             'checks': r['checks'].split(',') if r['checks'] else [],
             'total_time': r['total_time']} for r in rows]


def load_report(report_id: int) -> dict | None:
    conn = _conn()
    row = conn.execute('SELECT data FROM reports WHERE id=?', (report_id,)).fetchone()
    return json.loads(row['data']) if row else None


def query_reports(check_id: str | None = None, since: str | None = None, limit: int = 200) -> list[dict]:
    """Analytics for the future: filter by check and date. Returns metadata."""
    conn = _conn()
    sql = 'SELECT id, timestamp, checks, total_time FROM reports WHERE 1=1'
    params: list = []
    if check_id:
        sql += ' AND checks LIKE ?'
        params.append(f'%{check_id}%')
    if since:
        sql += ' AND timestamp >= ?'
        params.append(since)
    sql += ' ORDER BY id DESC LIMIT ?'
    params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def timeseries_mtr_loss(target: str, limit: int = 100) -> list[dict]:
    """
    mtr loss trend for a specific target over time.
    Returns [{timestamp, max_loss, worst_hop}] from the most recent reports that had this target.
    """
    conn = _conn()
    rows = conn.execute(
        "SELECT timestamp, data FROM reports WHERE checks LIKE '%mtr%' ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    out = []
    for r in reversed(rows):  # chronological order
        data = json.loads(r['data'])
        mtr = data.get('results', {}).get('mtr', {})
        if mtr.get('target') != target or not mtr.get('hops'):
            continue
        max_loss, worst_hop = 0.0, None
        for h in mtr['hops']:
            if h['loss_pct'] > max_loss:
                max_loss, worst_hop = h['loss_pct'], f"{h['hop']}. {h['host']}"
        out.append({'timestamp': r['timestamp'], 'max_loss': max_loss, 'worst_hop': worst_hop})
    return out


def distinct_mtr_targets(limit: int = 50) -> list[str]:
    """List of targets with mtr history - for the trend chart dropdown."""
    conn = _conn()
    rows = conn.execute(
        "SELECT data FROM reports WHERE checks LIKE '%mtr%' ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    targets = []
    for r in rows:
        t = json.loads(r['data']).get('results', {}).get('mtr', {}).get('target')
        if t and t not in targets:
            targets.append(t)
    return targets


# ===========================================================================
# Timing stats
# ===========================================================================

def timing_get(key: str) -> dict | None:
    conn = _conn()
    row = conn.execute('SELECT ema, count, last FROM timing_stats WHERE key=?', (key,)).fetchone()
    return dict(row) if row else None


def timing_all_for_check(check_id: str) -> list[float]:
    conn = _conn()
    rows = conn.execute(
        "SELECT ema FROM timing_stats WHERE key = ? OR key LIKE ?",
        (check_id, f'{check_id}::%'),
    ).fetchall()
    return [r['ema'] for r in rows]


def timing_upsert(key: str, ema: float, count: int, last: float) -> None:
    conn = _conn()
    conn.execute(
        """INSERT INTO timing_stats (key, ema, count, last, updated_at)
           VALUES (?,?,?,?,?)
           ON CONFLICT(key) DO UPDATE SET ema=?, count=?, last=?, updated_at=?""",
        (key, ema, count, last, datetime.now().isoformat(),
         ema, count, last, datetime.now().isoformat()),
    )
    conn.commit()


def timing_snapshot() -> dict:
    conn = _conn()
    rows = conn.execute('SELECT key, ema, count, last FROM timing_stats').fetchall()
    return {r['key']: {'ema': r['ema'], 'count': r['count'], 'last': r['last']} for r in rows}


# ===========================================================================
# Settings (key-value)
# ===========================================================================

def setting_get(key: str, default=None):
    conn = _conn()
    row = conn.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
    return row['value'] if row else default


def setting_set(key: str, value: str) -> None:
    conn = _conn()
    conn.execute(
        'INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=?',
        (key, value, value),
    )
    conn.commit()


def settings_all() -> dict:
    conn = _conn()
    rows = conn.execute('SELECT key, value FROM settings').fetchall()
    return {r['key']: r['value'] for r in rows}


# ===========================================================================
# Presets
# ===========================================================================

def preset_save(name: str, checks: list[dict]) -> int:
    conn = _conn()
    cur = conn.execute(
        """INSERT INTO presets (name, checks, created_at) VALUES (?,?,?)
           ON CONFLICT(name) DO UPDATE SET checks=?""",
        (name, json.dumps(checks, ensure_ascii=False), datetime.now().isoformat(),
         json.dumps(checks, ensure_ascii=False)),
    )
    conn.commit()
    return cur.lastrowid


def presets_list() -> list[dict]:
    conn = _conn()
    rows = conn.execute('SELECT id, name, checks, created_at FROM presets ORDER BY name').fetchall()
    return [{'id': r['id'], 'name': r['name'], 'checks': json.loads(r['checks']),
             'created_at': r['created_at']} for r in rows]


def preset_delete(preset_id: int) -> None:
    conn = _conn()
    conn.execute('DELETE FROM presets WHERE id=?', (preset_id,))
    conn.commit()


# ===========================================================================
# Targets
# ===========================================================================

def target_add(value: str, label: str = '', kind: str = 'ip') -> int:
    conn = _conn()
    cur = conn.execute('INSERT INTO targets (label, value, kind) VALUES (?,?,?)', (label, value, kind))
    conn.commit()
    return cur.lastrowid


def targets_list() -> list[dict]:
    conn = _conn()
    rows = conn.execute('SELECT id, label, value, kind FROM targets ORDER BY id').fetchall()
    return [dict(r) for r in rows]


def target_delete(target_id: int) -> None:
    conn = _conn()
    conn.execute('DELETE FROM targets WHERE id=?', (target_id,))
    conn.commit()


# ===========================================================================
# Reputation lists (allow / block)
# ===========================================================================

def rep_add(pattern: str, list_type: str, note: str = '') -> int:
    conn = _conn()
    cur = conn.execute(
        'INSERT INTO rep_list (pattern, list_type, note, created_at) VALUES (?,?,?,?)',
        (pattern, list_type, note, datetime.now().isoformat()),
    )
    conn.commit()
    return cur.lastrowid


def rep_list(list_type: str | None = None) -> list[dict]:
    conn = _conn()
    if list_type:
        rows = conn.execute('SELECT id, pattern, list_type, note FROM rep_list WHERE list_type=? ORDER BY id', (list_type,)).fetchall()
    else:
        rows = conn.execute('SELECT id, pattern, list_type, note FROM rep_list ORDER BY list_type, id').fetchall()
    return [dict(r) for r in rows]


def rep_delete(rep_id: int) -> None:
    conn = _conn()
    conn.execute('DELETE FROM rep_list WHERE id=?', (rep_id,))
    conn.commit()


# ===========================================================================
# ASN cache (to avoid hammering whois for the same IP repeatedly)
# ===========================================================================

def asn_get(ip: str) -> dict | None:
    conn = _conn()
    row = conn.execute('SELECT org, country FROM asn_cache WHERE ip=?', (ip,)).fetchone()
    return dict(row) if row else None


def asn_set(ip: str, org: str | None, country: str | None) -> None:
    conn = _conn()
    conn.execute(
        """INSERT INTO asn_cache (ip, org, country, updated_at) VALUES (?,?,?,?)
           ON CONFLICT(ip) DO UPDATE SET org=?, country=?, updated_at=?""",
        (ip, org, country, datetime.now().isoformat(), org, country, datetime.now().isoformat()),
    )
    conn.commit()


# ===========================================================================
# CVE cache (OSV.dev - to avoid hitting the API on every run for the same version)
# ===========================================================================

def cve_get(key: str) -> dict | None:
    conn = _conn()
    row = conn.execute('SELECT data, updated_at FROM cve_cache WHERE key=?', (key,)).fetchone()
    if not row:
        return None
    return {'data': json.loads(row['data']), 'updated_at': row['updated_at']}


def cve_set(key: str, data: list) -> None:
    conn = _conn()
    conn.execute(
        """INSERT INTO cve_cache (key, data, updated_at) VALUES (?,?,?)
           ON CONFLICT(key) DO UPDATE SET data=?, updated_at=?""",
        (key, json.dumps(data, ensure_ascii=False), datetime.now().isoformat(),
         json.dumps(data, ensure_ascii=False), datetime.now().isoformat()),
    )
    conn.commit()


# ===========================================================================
# Traffic history - MikroTik connection tracking snapshots, accumulated by a
# background watcher (see history_capture.py), so you can "rewind" and see
# where a device connected to over a past period, not just at the moment a
# check runs.
# ===========================================================================

def traffic_history_add(target_ip: str, destinations: list[dict]) -> None:
    """destinations: [{'ip','port'?,'protocol'?,'risk_level'?,'risk_score'?}, ...]"""
    conn = _conn()
    now = datetime.now().isoformat()
    conn.executemany(
        """INSERT INTO traffic_history (target_ip, dst_ip, dst_port, protocol, risk_level, risk_score, seen_at)
           VALUES (?,?,?,?,?,?,?)""",
        [(target_ip, d['ip'], d.get('port'), d.get('protocol'),
          d.get('risk_level'), d.get('risk_score'), now) for d in destinations],
    )
    conn.commit()


def traffic_history_query(target_ip: str, since: str, until: str | None = None) -> list[dict]:
    conn = _conn()
    if until:
        rows = conn.execute(
            """SELECT * FROM traffic_history WHERE target_ip=? AND seen_at>=? AND seen_at<=?
               ORDER BY seen_at DESC""", (target_ip, since, until)).fetchall()
    else:
        rows = conn.execute(
            """SELECT * FROM traffic_history WHERE target_ip=? AND seen_at>=?
               ORDER BY seen_at DESC""", (target_ip, since)).fetchall()
    return [dict(r) for r in rows]


def traffic_history_prune(older_than: str) -> int:
    """Deletes records older than the given ISO timestamp. Called periodically by the watcher."""
    conn = _conn()
    cur = conn.execute('DELETE FROM traffic_history WHERE seen_at < ?', (older_than,))
    conn.commit()
    return cur.rowcount
