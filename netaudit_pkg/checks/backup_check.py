"""
Backup verification over SSH - not "cron looks configured", but the fact:
backups actually exist, are recent, aren't corrupted, and there's more than
one copy.

The most common backup failure mode is silent: a script "works" for years via
cron but has been failing quietly into a log nobody reads, and the gap only
surfaces during an actual disaster recovery, when it's too late to roll back.
This is exactly the kind of problem worth checking automatically, rather than
relying on someone manually noticing.

Checked for each given directory:
  - freshness of the latest file (mtime) against the expected interval;
  - suspiciously small size (a sign of a dump that failed midway);
  - archive integrity if the format is recognized (.gz/.tar.gz/.zip/.sql) -
    without full extraction, header-level check only;
  - number of files in the directory - a single copy violates the basic
    "3-2-1" rule (a single copy alone is already a risk: if it gets
    corrupted, there's nothing to restore from);
  - free space on the partition where the backups live (if the disk is
    nearly full, the next backup could silently fail to fit or get truncated).

Never modifies anything on the server - read-only (stat, ls, gzip -t/tar -tzf
without writing to disk, df).
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Literal

from ..findings import finding as _finding
from ..findings import subject_id
from ..registry import register
from ..ssh import HostKeyMismatchError, SSHExecutor
from ..ssh_utils import run_command_with_exit_code

try:
    import paramiko
except ImportError:
    paramiko = None

# minimum "sane" backup file size - below this, it's almost certainly a dump
# that failed midway, not a legitimately small database
MIN_SANE_BACKUP_BYTES = 1024  # 1 KB

ARCHIVE_EXT_RE = re.compile(r'\.(tar\.gz|tgz|gz|zip|sql|sql\.gz|bz2|tar\.bz2|xz)$', re.IGNORECASE)

def _find_files(ssh: SSHExecutor, directory: str) -> list[dict] | dict | None:
    """Machine-readable ls -la via stat, each line:
    epoch_mtime|size_bytes|filename"""
    # find instead of ls -la - doesn't break on files with spaces/special chars
    # in the name, and gives the needed fields directly via -printf
    cmd = (f"find {shlex.quote(directory)} -maxdepth 1 -type f "
           r"-printf '%T@|%s|%f\n' 2>&1")
    out, code = run_command_with_exit_code(ssh, cmd)
    if code is None:
        return {'error': 'could not confirm listing backup directory'}
    if code != 0 and 'No such file or directory' in out:
        # `find` may name a child removed during rotation, while `directory`
        # itself still exists. Confirm the root separately before calling it
        # absent; an inconclusive probe stays a collection error.
        _, dir_code = run_command_with_exit_code(ssh, f'test -d {shlex.quote(directory)}')
        if dir_code == 1:
            return None
    if code != 0:
        return {'error': f'failed to list backup directory (exit {code})', 'detail': out.strip()[:300]}
    files = []
    unparsed = False
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split('|', 2)
        if len(parts) != 3:
            unparsed = True
            continue
        try:
            mtime = float(parts[0])
            size = int(parts[1])
        except ValueError:
            unparsed = True
            continue
        files.append({'mtime': mtime, 'size': size, 'name': parts[2]})
    if unparsed:
        return {'error': 'could not parse backup directory listing'}
    return files

@dataclass(frozen=True)
class ArchiveIntegrity:
    status: Literal['ok', 'corrupt', 'unknown', 'skipped']
    detail: str = ''


def _check_archive_integrity(ssh: SSHExecutor, directory: str, filename: str) -> ArchiveIntegrity:
    """Classify a read-only archive test without conflating missing tools and damage."""
    path = f'{directory.rstrip("/")}/{filename}'
    lower = filename.lower()
    quoted = shlex.quote(path)

    if lower.endswith(('.tar.gz', '.tgz')):
        cmd = f'tar -tzf {quoted} 2>&1 1>/dev/null'
    elif lower.endswith('.gz'):
        cmd = f'gzip -t {quoted} 2>&1'
    elif lower.endswith('.zip'):
        cmd = f'unzip -t {quoted} 2>&1 1>/dev/null'
    elif lower.endswith(('.tar.bz2', '.tbz2')):
        cmd = f'tar -tjf {quoted} 2>&1 1>/dev/null'
    elif lower.endswith('.sql'):
        # a bare .sql file has no real "integrity" check - only verify it isn't
        # empty and doesn't look like an HTML error page (a common sign that
        # the dump was cut short by a redirect/authentication error instead of SQL)
        out, code = run_command_with_exit_code(ssh, f'head -c 200 {quoted} 2>&1')
        if code is None or code != 0:
            return ArchiveIntegrity('unknown', 'could not read SQL backup header')
        if '<html' in out.lower() or '<!doctype' in out.lower():
            return ArchiveIntegrity('corrupt', 'the start of the file looks like HTML, not an SQL dump')
        return ArchiveIntegrity('ok')
    else:
        return ArchiveIntegrity('skipped', 'format not recognized')

    out, code = run_command_with_exit_code(ssh, cmd)
    if code is None:
        return ArchiveIntegrity('unknown', 'archive check did not complete')
    if code == 0:
        return ArchiveIntegrity('ok')
    if code == 127 or any(term in out.lower() for term in ('permission denied', 'not found', 'cannot open')):
        return ArchiveIntegrity('unknown', f'archive check could not run (exit {code})')
    return ArchiveIntegrity('corrupt', 'archive fails the integrity check (corrupted or incomplete)')

def _check_disk_space(ssh: SSHExecutor, directory: str) -> tuple[int | None, str | None]:
    """Returns (percent_used, error)."""
    out, code = run_command_with_exit_code(ssh, f'df -P {shlex.quote(directory)} 2>&1')
    if code != 0:
        return None, 'could not confirm disk usage'
    parts = out.strip().splitlines()[-1].split() if out.strip() else []
    if len(parts) >= 5 and parts[4].endswith('%'):
        try:
            return int(parts[4].rstrip('%')), None
        except ValueError:
            pass
    return None, 'could not determine disk usage'

@register(
    id='backup_check', label='Backup check (SSH)', category='server',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Host', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'User', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH port', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Key path', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'SSH password (if no key)', 'default': ''},
        {'name': 'directories', 'type': 'text', 'label': 'Backup directories (comma-separated)',
         'default': '/var/backups'},
        {'name': 'max_age_hours', 'type': 'number', 'label': 'Expected freshness, hours', 'default': 26},
        {'name': 'min_copies', 'type': 'number', 'label': 'Minimum copies (local retention)', 'default': 2},
    ],
    required_tools=[],
    description='Backup verification over SSH: latest file freshness, suspiciously small size '
                '(a failed dump), archive integrity (gz/tar.gz/zip/sql), local copy count, '
                'partition usage. Read-only — only reads files and metadata. '
                'Note: this only checks local retention, not the full 3-2-1 rule (3 copies, '
                '2 media types, 1 off-site) — a healthy count here does not by itself confirm '
                'an off-site or cross-media copy exists.',
)
def check_backup(host='', user='root', port=22, key_path='', password='',  # nosec B107 - empty default is a CLI/API parameter, not a hardcoded credential
                  directories='/var/backups', max_age_hours=26, min_copies=2) -> dict:
    if paramiko is None:
        return {'error': 'paramiko not installed'}
    if not host:
        return {'error': 'host not specified'}

    dir_list = [d.strip() for d in directories.split(',') if d.strip()]
    if not dir_list:
        return {'error': 'no directories specified'}
    # absolute paths only: a name starting with "-" would be read by `find`
    # as an expression (`-delete`), and `~` was never expanded inside quotes
    not_absolute = [d for d in dir_list if not d.startswith('/')]
    if not_absolute:
        return {'error': f'backup directories must be absolute paths: {", ".join(not_absolute)}'}

    try:
        ssh = SSHExecutor(host, user, port, key_path, password).connect()
    except HostKeyMismatchError as e:
        return {'error': str(e)}
    # SSH libraries can fail with transport, auth, or socket errors; keep the check isolated.
    except Exception as e:  # noqa: BLE001
        return {'error': f'could not connect: {e}'}

    results = []
    all_findings = []

    try:
        import time
        now = time.time()

        for directory in dir_list:
            entry = {'directory': directory}
            files = _find_files(ssh, directory)

            if isinstance(files, dict):
                entry.update(files)
                all_findings.append(_finding('low', f'{directory}: could not list backup directory',
                                              files['error'], id=subject_id('BKP-COL-001', directory),
                                              requires_manual_verification=True))
                results.append(entry)
                continue

            if files is None:
                entry['error'] = 'directory does not exist'
                all_findings.append(_finding('high', f'{directory}: backup directory does not exist',
                                              'check the path or the whole backup job — it might be writing elsewhere',
                                              id=subject_id('BKP-DIR-001', directory)))
                results.append(entry)
                continue

            if not files:
                entry['file_count'] = 0
                all_findings.append(_finding('high', f'{directory}: no backup files found',
                                              'the directory is empty — the backup either never ran, or everything gets deleted too soon',
                                              id=subject_id('BKP-DIR-002', directory)))
                results.append(entry)
                continue

            files.sort(key=lambda f: f['mtime'], reverse=True)
            latest = files[0]
            age_hours = (now - latest['mtime']) / 3600

            entry['file_count'] = len(files)
            entry['latest_file'] = latest['name']
            entry['latest_age_hours'] = round(age_hours, 1)
            entry['latest_size_bytes'] = latest['size']

            if age_hours > max_age_hours:
                all_findings.append(_finding(
                    'high', f'{directory}: the latest backup is stale ({age_hours:.0f}h, expected ≤{max_age_hours}h)',
                    f'file {latest["name"]}, check the cron/systemd timer and the last run log on the server',
                    id=subject_id('BKP-AGE-001', directory),
                ))

            if 0 < latest['size'] < MIN_SANE_BACKUP_BYTES:
                all_findings.append(_finding(
                    'high', f'{directory}: the latest backup is suspiciously small ({latest["size"]} bytes)',
                    f'file {latest["name"]} — the script likely failed midway, or the database was empty at dump time',
                    id=subject_id('BKP-SIZE-001', directory),
                ))

            if len(files) < min_copies:
                all_findings.append(_finding(
                    'medium', f'{directory}: fewer local backup copies than expected ({len(files)}, need ≥{min_copies})',
                    'this only counts files in this one directory on this one server — it does not confirm '
                    'an off-site or cross-media copy exists (the actual 3-2-1 rule), only that local retention is thin',
                    id=subject_id('BKP-COPY-001', directory),
                ))

            if ARCHIVE_EXT_RE.search(latest['name']):
                integrity = _check_archive_integrity(ssh, directory, latest['name'])
                entry['integrity_ok'] = (integrity.status == 'ok' if integrity.status in ('ok', 'corrupt') else None)
                if integrity.status == 'corrupt':
                    all_findings.append(_finding(
                        'high', f'{directory}: the latest backup fails the integrity check',
                        f'{latest["name"]}: {integrity.detail}',
                        id=subject_id('BKP-INT-001', directory),
                    ))
                elif integrity.status == 'unknown':
                    all_findings.append(_finding(
                        'low', f'{directory}: could not verify backup integrity',
                        f'{latest["name"]}: {integrity.detail}',
                        id=subject_id('BKP-INT-002', directory),
                        requires_manual_verification=True,
                    ))
                elif integrity.status == 'skipped':
                    all_findings.append(_finding(
                        'low', f'{directory}: backup integrity was not checked',
                        f'{latest["name"]}: {integrity.detail}',
                        id=subject_id('BKP-INT-003', directory),
                        requires_manual_verification=True,
                    ))

            disk_pct, disk_err = _check_disk_space(ssh, directory)
            if disk_pct is not None:
                entry['disk_used_pct'] = disk_pct
                if disk_pct >= 90:
                    all_findings.append(_finding(
                        'medium', f'{directory}: partition is {disk_pct}% full',
                        'the next backup risks not fitting — free up space or move backups to another disk',
                        id=subject_id('BKP-DISK-001', directory),
                    ))
            elif disk_err:
                all_findings.append(_finding('low', f'{directory}: could not determine disk usage',
                                              disk_err, id=subject_id('BKP-DISK-002', directory),
                                              requires_manual_verification=True))

            results.append(entry)

    finally:
        ssh.close()

    if not all_findings:
        all_findings.append(_finding('ok', 'backups are fresh, intact, with enough copies'))

    counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
    for f in all_findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    return {
        'host': host,
        'directories': results,
        'findings': all_findings,
        'summary': counts,
    }
