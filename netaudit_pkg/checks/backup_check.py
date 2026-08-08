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

from ..registry import register
from ..ssh import SSHExecutor, HostKeyMismatchError

try:
    import paramiko
except ImportError:
    paramiko = None


def _finding(severity, title, detail='', confidence='high', id=None):
    f = {'severity': severity, 'title': title, 'detail': detail, 'confidence': confidence}
    if id:
        f['id'] = id
    return f


# minimum "sane" backup file size - below this, it's almost certainly a dump
# that failed midway, not a legitimately small database
MIN_SANE_BACKUP_BYTES = 1024  # 1 KB

ARCHIVE_EXT_RE = re.compile(r'\.(tar\.gz|tgz|gz|zip|sql|sql\.gz|bz2|tar\.bz2|xz)$', re.IGNORECASE)


def _find_files(ssh: SSHExecutor, directory: str) -> list[dict]:
    """Machine-readable ls -la via stat, each line:
    epoch_mtime|size_bytes|filename"""
    # find instead of ls -la - doesn't break on files with spaces/special chars
    # in the name, and gives the needed fields directly via -printf
    cmd = (f"find {directory!r} -maxdepth 1 -type f "
           r"-printf '%T@|%s|%f\n' 2>&1")
    out, err = ssh.run(cmd)
    if 'No such file or directory' in out or 'No such file or directory' in err:
        return None  # directory doesn't exist - distinguish from "exists but empty"
    files = []
    for line in out.splitlines():
        line = line.strip()
        if not line or '|' not in line:
            continue
        parts = line.split('|', 2)
        if len(parts) != 3:
            continue
        try:
            mtime = float(parts[0])
            size = int(parts[1])
        except ValueError:
            continue
        files.append({'mtime': mtime, 'size': size, 'name': parts[2]})
    return files


def _check_archive_integrity(ssh: SSHExecutor, directory: str, filename: str) -> str | None:
    """Returns None if integrity is fine or the format isn't recognized (not checked),
    otherwise an error message. All checks are read-only, nothing is extracted to disk."""
    path = f'{directory.rstrip("/")}/{filename}'
    lower = filename.lower()
    quoted = path.replace("'", "'\\''")

    if lower.endswith(('.tar.gz', '.tgz')):
        out, err = ssh.run(f"tar -tzf '{quoted}' > /dev/null 2>&1 && echo OK || echo FAIL")
    elif lower.endswith('.gz'):
        out, err = ssh.run(f"gzip -t '{quoted}' 2>&1 && echo OK || echo FAIL")
    elif lower.endswith('.zip'):
        out, err = ssh.run(f"unzip -t '{quoted}' > /dev/null 2>&1 && echo OK || echo FAIL")
    elif lower.endswith(('.tar.bz2', '.tbz2')):
        out, err = ssh.run(f"tar -tjf '{quoted}' > /dev/null 2>&1 && echo OK || echo FAIL")
    elif lower.endswith('.sql'):
        # a bare .sql file has no real "integrity" check - only verify it isn't
        # empty and doesn't look like an HTML error page (a common sign that
        # the dump was cut short by a redirect/authentication error instead of SQL)
        out, err = ssh.run(f"head -c 200 '{quoted}' 2>&1")
        if '<html' in out.lower() or '<!doctype' in out.lower():
            return 'the start of the file looks like HTML, not an SQL dump — likely an error instead of data'
        return None
    else:
        return None  # format not recognized, integrity not checked (not an error)

    if 'FAIL' in out or 'FAIL' in err:
        return 'archive fails the integrity check (corrupted or incomplete)'
    return None


def _check_disk_space(ssh: SSHExecutor, directory: str) -> tuple[int | None, str | None]:
    """Returns (percent_used, error)."""
    out, err = ssh.run(f"df -P {directory!r} 2>&1 | tail -1")
    parts = out.split()
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
        {'name': 'password', 'type': 'password', 'label': 'Password (if not using a key)', 'default': ''},
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
def check_backup(host='', user='root', port=22, key_path='', password='',
                  directories='/var/backups', max_age_hours=26, min_copies=2) -> dict:
    if paramiko is None:
        return {'error': 'paramiko not installed'}
    if not host:
        return {'error': 'host not specified'}

    dir_list = [d.strip() for d in directories.split(',') if d.strip()]
    if not dir_list:
        return {'error': 'no directories specified'}

    try:
        ssh = SSHExecutor(host, user, port, key_path, password).connect()
    except HostKeyMismatchError as e:
        return {'error': str(e)}
    except Exception as e:
        return {'error': f'could not connect: {e}'}

    results = []
    all_findings = []

    try:
        import time
        now = time.time()
        max_age_seconds = float(max_age_hours) * 3600

        for directory in dir_list:
            entry = {'directory': directory}
            files = _find_files(ssh, directory)

            if files is None:
                entry['error'] = 'directory does not exist'
                all_findings.append(_finding('high', f'{directory}: backup directory does not exist',
                                              'check the path or the whole backup job — it might be writing elsewhere'))
                results.append(entry)
                continue

            if not files:
                entry['file_count'] = 0
                all_findings.append(_finding('high', f'{directory}: no backup files found',
                                              'the directory is empty — the backup either never ran, or everything gets deleted too soon'))
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
                    f'file {latest["name"]}, check the cron/systemd timer and the last run log on the server'
                ))

            if 0 < latest['size'] < MIN_SANE_BACKUP_BYTES:
                all_findings.append(_finding(
                    'high', f'{directory}: the latest backup is suspiciously small ({latest["size"]} bytes)',
                    f'file {latest["name"]} — the script likely failed midway, or the database was empty at dump time'
                ))

            if len(files) < min_copies:
                all_findings.append(_finding(
                    'medium', f'{directory}: fewer local backup copies than expected ({len(files)}, need ≥{min_copies})',
                    'this only counts files in this one directory on this one server — it does not confirm '
                    'an off-site or cross-media copy exists (the actual 3-2-1 rule), only that local retention is thin'
                ))

            if ARCHIVE_EXT_RE.search(latest['name']):
                integrity_error = _check_archive_integrity(ssh, directory, latest['name'])
                entry['integrity_ok'] = integrity_error is None
                if integrity_error:
                    all_findings.append(_finding(
                        'high', f'{directory}: the latest backup fails the integrity check',
                        f'{latest["name"]}: {integrity_error}'
                    ))

            disk_pct, disk_err = _check_disk_space(ssh, directory)
            if disk_pct is not None:
                entry['disk_used_pct'] = disk_pct
                if disk_pct >= 90:
                    all_findings.append(_finding(
                        'medium', f'{directory}: partition is {disk_pct}% full',
                        'the next backup risks not fitting — free up space or move backups to another disk'
                    ))

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
