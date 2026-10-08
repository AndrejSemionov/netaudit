"""Explicit, offline cleanup of legacy secret params in saved report JSON.

No default database path, no startup migration. The real database must not be
passed here during development or tests. See docs/research/legacy_secret_scrub.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .redaction import SECRET_PARAM_NAMES, redact_report


class ScrubError(Exception):
    """Safe-to-display scrub failure. Never include report data or SQL errors."""

    def __init__(self, message: str, sensitive_backup: Path | None = None):
        super().__init__(message)
        self.sensitive_backup = sensitive_backup


@dataclass
class ScanResult:
    total: int = 0
    affected: int = 0
    malformed: int = 0
    unsupported: int = 0
    outside_context: int = 0
    space_warning: bool = False
    updates: list[tuple[int, str]] = field(default_factory=list, repr=False)
    fingerprint: str = field(default='', repr=False)

    @property
    def eligible(self) -> bool:
        return self.malformed == 0 and self.unsupported == 0


@dataclass(frozen=True)
class ScrubResult:
    status: str  # complete, incomplete, noop
    affected: int
    stage: str = ''


def _contains_secret_key(value: object) -> bool:
    if isinstance(value, dict):
        return any(key in SECRET_PARAM_NAMES or _contains_secret_key(item)
                   for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_secret_key(item) for item in value)
    return False


def _database_path(path: str | Path) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute() or candidate.is_symlink() or not candidate.is_file():
        raise ScrubError('database must be an existing regular file at an explicit absolute path')
    return candidate.resolve(strict=True)


def _backup_path(path: str | Path, database: Path) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute() or candidate.exists() or candidate.is_symlink():
        raise ScrubError('backup must be a new file at an explicit absolute path')
    resolved = candidate.resolve(strict=False)
    if not candidate.parent.is_dir() or resolved == database:
        raise ScrubError('backup parent must exist and backup must differ from database')
    if resolved in (Path(f'{database}{suffix}') for suffix in ('-journal', '-wal', '-shm')):
        raise ScrubError('backup must not use a database sidecar path')
    if any(Path(f'{candidate}{suffix}').exists() or Path(f'{candidate}{suffix}').is_symlink()
           for suffix in ('-journal', '-wal', '-shm')):
        raise ScrubError('backup sidecar path already exists')
    return candidate


def _connect_ro(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f'{path.as_uri()}?mode=ro', uri=True, timeout=0.2)


def _scan_conn(conn: sqlite3.Connection) -> ScanResult:
    scan = ScanResult()
    digest = hashlib.sha256()
    try:
        rows = conn.execute('SELECT id, data FROM reports ORDER BY id')
        for row_id, raw in rows:
            scan.total += 1
            digest.update(str(row_id).encode('ascii'))
            digest.update(b'\0')
            if isinstance(raw, str):
                digest.update(raw.encode('utf-8', errors='surrogatepass'))
            elif isinstance(raw, bytes):
                digest.update(raw)
            else:
                digest.update(b'non-text')
            digest.update(b'\0')
            if not isinstance(raw, str):
                scan.malformed += 1
                continue
            try:
                report = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                scan.malformed += 1
                continue
            if not isinstance(report, dict):
                scan.malformed += 1
                continue
            if _contains_secret_key({k: v for k, v in report.items() if k != 'execution_context'}):
                scan.outside_context += 1
            context = report.get('execution_context', {})
            if not isinstance(context, dict) or any(not isinstance(entry, dict)
                                                    for entry in context.values()):
                scan.unsupported += 1
                continue
            redacted = redact_report(report)
            if _contains_secret_key(redacted.get('execution_context')):
                scan.unsupported += 1
                continue
            if redacted != report:
                scan.affected += 1
                scan.updates.append((row_id, json.dumps(redacted, ensure_ascii=False)))
    except (sqlite3.Error, UnicodeError) as exc:
        raise ScrubError('cannot read reports table') from exc
    scan.fingerprint = digest.hexdigest()
    return scan


def _space_warning(database: Path, backup: Path | None = None) -> bool:
    try:
        size = database.stat().st_size
        db_free = shutil.disk_usage(database.parent).free
        if backup is None:
            return db_free < 2 * size
        backup_free = shutil.disk_usage(backup.parent).free
        if database.parent.stat().st_dev == backup.parent.stat().st_dev:
            return db_free < 3 * size
        return db_free < 2 * size or backup_free < size
    except OSError:
        return True  # unknown free space: warn, never claim there is enough


def scan_database(database: str | Path) -> ScanResult:
    """Read raw SQLite JSON without modifying any report row."""
    path = _database_path(database)
    conn = None
    try:
        conn = _connect_ro(path)
        scan = _scan_conn(conn)
    except sqlite3.Error as exc:
        raise ScrubError('cannot open database for preflight') from exc
    finally:
        if conn is not None:
            conn.close()
    scan.space_warning = _space_warning(path)
    return scan


def _reserve_backup(path: Path) -> None:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        raise ScrubError('cannot reserve private backup path') from exc
    os.close(fd)


def _private_backup_files(path: Path) -> bool:
    for candidate in [path, *(Path(f'{path}{suffix}') for suffix in ('-journal', '-wal', '-shm'))]:
        if candidate.exists() and stat.S_IMODE(candidate.stat().st_mode) & 0o077:
            return False
    return True


def _make_backup(database: Path, backup: Path, expected_rows: int) -> None:
    source = destination = None
    try:
        source = _connect_ro(database)  # separate from the writer-lock connection
        destination = sqlite3.connect(str(backup), timeout=0.2)
        source.backup(destination)
        if destination.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ScrubError('backup integrity check failed')
        if destination.execute('SELECT count(*) FROM reports').fetchone()[0] != expected_rows:
            raise ScrubError('backup report count differs from source')
    except sqlite3.Error as exc:
        raise ScrubError('backup failed before source was changed') from exc
    finally:
        if source is not None:
            source.close()
        if destination is not None:
            destination.close()
    if not _private_backup_files(backup):
        raise ScrubError('backup or its SQLite sidecar has unsafe permissions')


def _perform_updates(conn: sqlite3.Connection, updates: list[tuple[int, str]]) -> None:
    conn.executemany('UPDATE reports SET data=? WHERE id=?',
                     ((data, row_id) for row_id, data in updates))


def _run_vacuum(conn: sqlite3.Connection) -> None:
    conn.execute('VACUUM')


def _checkpoint(conn: sqlite3.Connection) -> tuple[int, int, int]:
    return conn.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()


def apply_scrub(database: str | Path, backup: str | Path) -> ScrubResult:
    """Scrub explicit database; never called automatically by NetAudit."""
    path = _database_path(database)
    backup_path = _backup_path(backup, path)
    old_umask = os.umask(0o077)
    conn: sqlite3.Connection | None = None
    committed = False
    backup_reserved = False
    try:
        preflight = scan_database(path)
        if not preflight.eligible:
            raise ScrubError('preflight found malformed or unsupported report data')
        if not preflight.affected:
            return ScrubResult('noop', 0)
        try:
            conn = sqlite3.connect(f'{path.as_uri()}?mode=rw', uri=True, timeout=0.2)
            if conn.execute('PRAGMA journal_mode').fetchone()[0].lower() != 'wal':
                raise ScrubError('apply requires a WAL-mode database')
            conn.execute('BEGIN IMMEDIATE')
            locked = _scan_conn(conn)
            if not locked.eligible or locked.fingerprint != preflight.fingerprint:
                raise ScrubError('database changed since preflight or has invalid report data')
            _reserve_backup(backup_path)
            backup_reserved = True
            _make_backup(path, backup_path, locked.total)
            conn.execute('PRAGMA secure_delete=ON')
            _perform_updates(conn, locked.updates)
            verified = _scan_conn(conn)
            if not verified.eligible or verified.affected or verified.total != locked.total:
                raise ScrubError('in-transaction verification failed')
            conn.commit()
            committed = True
        except ScrubError as exc:
            if backup_reserved:
                exc.sensitive_backup = backup_path
            raise
        except Exception as exc:
            raise ScrubError('apply failed before commit; source rolled back',
                             backup_path if backup_reserved else None) from exc
        try:
            _run_vacuum(conn)
        except Exception:
            return ScrubResult('incomplete', locked.affected, 'vacuum')
        try:
            checkpoint = _checkpoint(conn)
            if checkpoint is None or checkpoint[0] != 0:
                return ScrubResult('incomplete', locked.affected, 'checkpoint')
        except Exception:
            return ScrubResult('incomplete', locked.affected, 'checkpoint')
        try:
            if conn.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                return ScrubResult('incomplete', locked.affected, 'verify')
            final = _scan_conn(conn)  # raw SELECT, never storage.load_report()
            if not final.eligible or final.affected or final.total != locked.total:
                return ScrubResult('incomplete', locked.affected, 'verify')
            if not _private_backup_files(backup_path):
                return ScrubResult('incomplete', locked.affected, 'permissions')
        except Exception:
            return ScrubResult('incomplete', locked.affected, 'verify')
        return ScrubResult('complete', locked.affected)
    finally:
        try:
            if conn is not None:
                try:
                    if not committed:
                        conn.rollback()
                finally:
                    conn.close()
        finally:
            os.umask(old_umask)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Inspect or scrub old secret params in report JSON')
    parser.add_argument('--database', required=True, help='explicit absolute SQLite path')
    parser.add_argument('--apply', action='store_true', help='modify database after private backup')
    parser.add_argument('--backup', help='new explicit absolute path for plaintext backup')
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)
    try:
        if args.apply:
            if not args.backup:
                raise ScrubError('--apply requires --backup')
            result = apply_scrub(args.database, args.backup)
            print(f'status={result.status} affected={result.affected} stage={result.stage or "done"}')
            if result.status != 'noop':
                print(f'space_warning={_space_warning(Path(args.database), Path(args.backup))}')
                print(f'Backup with original secrets: {args.backup} — protect and retain only as needed.')
            else:
                print('No logical report keys need scrubbing. This does not prove a prior '
                      'VACUUM/checkpoint completed; review any earlier incomplete run.')
            if result.status == 'incomplete':
                print(f'Logical UPDATE committed, but {result.stage} did not complete. '
                      'Keep the backup; do not treat this as a full physical cleanup.')
            return 3 if result.status == 'incomplete' else 0
        if args.backup:
            raise ScrubError('--backup is used only with --apply')
        scan = scan_database(args.database)
        print(f'reports={scan.total} affected={scan.affected} malformed={scan.malformed} '
              f'unsupported={scan.unsupported} outside_context={scan.outside_context} '
              f'eligible={scan.eligible} space_warning={scan.space_warning}')
        return 0 if scan.eligible else 2
    except ScrubError as exc:
        print(f'error: {exc}', file=sys.stderr)
        if exc.sensitive_backup is not None:
            print(f'Backup at {exc.sensitive_backup} may contain original secrets; '
                  'protect it and follow your backup retention policy.', file=sys.stderr)
        return 2
    except Exception:
        # Unexpected OS/SQLite exception text may contain external report
        # data. Keep diagnostics generic at the command-line boundary.
        print('error: scrub failed; no report data was printed', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
