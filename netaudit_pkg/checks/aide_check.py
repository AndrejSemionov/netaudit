"""
File Integrity Monitoring via AIDE (Advanced Intrusion Detection Environment) over SSH.

Unlike rkhunter/chkrootkit (just run it - see the result), AIDE requires prior
state: a database of "reference" hashes for all files has to be built first
(`aide --init`), and only then does `aide --check` have anything to compare
against. Without an initialized database, AIDE checks nothing - there's simply
no database.

Hence two modes here (the `mode` param, values from a dropdown on the frontend
- 'check for changes' / 'reinitialize the database', mapped internally to
'check'/'init'):
  - 'check' (default) - compares the current filesystem state against an
    already-existing database. This is the everyday scenario: "did system
    binaries change since last time".
  - 'init' - (re)initializes the database with the current state as the
    reference. Needs to run once during initial setup, and again after every
    legitimate system update (otherwise routine apt upgrades will keep
    surfacing as "changes").

AIDE prints a summary like:
    Summary:
      Total number of entries:    54832
      Added entries:               2
      Removed entries:             1
      Changed entries:             5
That's the only thing parsed directly - the detailed line-by-line list of
changed files (with report_level=list_entries) is taken separately as raw
text for the report, without trying to decode the positional attribute
strings (YlZbpugamcinHAXSEC...) - for audit purposes it's enough to know what
and how much changed; the specific attributes can be checked in the detailed
output on the server if needed.
"""

from __future__ import annotations

import re

from ..registry import register, confirm_param, CONFIRM_MODIFY
from ..findings import finding as _finding
from ..ssh import SSHExecutor, HostKeyMismatchError

try:
    import paramiko
except ImportError:
    paramiko = None

# The Debian/Ubuntu 'aide' package ships its config at /etc/aide/aide.conf, not
# /etc/aide.conf - AIDE 0.19.2 (confirmed against the actual target during
# testing) does NOT fall back to that path automatically and errors out with
# "missing configuration (use '--config' ...)" without an explicit --config,
# so every invocation below passes it explicitly rather than relying on a
# compiled-in default this build doesn't have.
AIDE_CONFIG = '/etc/aide/aide.conf'

SUMMARY_RE = re.compile(
    r'Total number of entries:\s*(\d+).*?'
    r'Added entries:\s*(\d+).*?'
    r'Removed entries:\s*(\d+).*?'
    r'Changed entries:\s*(\d+)',
    re.DOTALL,
)

# after 'Added entries' AIDE usually lists added files line by line
# (default report_level is list_entries+); capture a few for context,
# not the whole list - on a large system it could be huge
CHANGED_FILE_RE = re.compile(r'^(?:f|d|l)\S*\s+(\S+)\s*$', re.MULTILINE)

def _parse_summary(raw: str) -> dict | None:
    m = SUMMARY_RE.search(raw)
    if not m:
        return None
    return {
        'total_entries': int(m.group(1)),
        'added': int(m.group(2)),
        'removed': int(m.group(3)),
        'changed': int(m.group(4)),
    }

@register(
    id='aide_check', label='File Integrity Monitoring (AIDE, SSH)', category='server', risk_level='MODIFYING',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Host', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'User', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH port', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Key path', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Password (if not using a key)', 'default': ''},
        {'name': 'mode', 'type': 'select', 'label': 'Mode',
         'options': ['check for changes', 'reinitialize the database'],
         'default': 'check for changes'},
        {'name': 'auto_install', 'type': 'checkbox', 'label': 'Install aide if missing',
         'default': False},
        confirm_param('Confirm: this may install packages / reinitialize the AIDE database'),
    ],
    required_tools=[],
    description='File Integrity Monitoring via AIDE over SSH - tracks changes to system files '
                'outside normal updates (alerts if binaries changed not via unattended-upgrades). '
                '"check" mode compares against an existing database (read-only); "init" overwrites '
                'the reference database and requires confirmation, same as auto-installing aide.',
)
def check_aide(host='', user='root', port=22, key_path='', password='',
                mode='check for changes', auto_install=False, confirm_modify='no') -> dict:
    if paramiko is None:
        return {'error': 'paramiko not installed'}
    if not host:
        return {'error': 'host not specified'}
    mode_map = {'check for changes': 'check', 'reinitialize the database': 'init',
                'check': 'check', 'init': 'init'}  # 'check'/'init' - for direct calls from code/CLI
    mode = mode_map.get(mode)
    if mode is None:
        return {'error': f'unknown mode: {mode}'}
    if mode == 'init' and confirm_modify != CONFIRM_MODIFY:
        return {'error': 'mode=init overwrites the AIDE reference database (a modifying action) '
                          'but was not confirmed',
                'hint': 'set "Confirm: this may install packages / reinitialize the AIDE database" to proceed'}

    try:
        ssh = SSHExecutor(host, user, port, key_path, password).connect()
    except HostKeyMismatchError as e:
        return {'error': str(e)}
    except Exception as e:
        return {'error': f'could not connect: {e}'}

    try:
        if not ssh.is_tool_installed('aide'):
            if not auto_install:
                return {'error': 'aide is not installed on the server',
                        'hint': 'apt install aide -y (or enable auto_install)'}
            if confirm_modify != CONFIRM_MODIFY:
                return {'error': 'auto_install would modify the target system (install a package) '
                                  'but was not confirmed',
                        'hint': 'set "Confirm: this may install packages / reinitialize the AIDE database" to proceed'}
            installed, install_err = ssh.ensure_tool_installed('aide', timeout=120)
            if not installed:
                return {'error': 'failed to install aide', 'detail': install_err}

        # AIDE on Debian/Ubuntu usually keeps the database at /var/lib/aide/aide.db
        # (writing a new one as aide.db.new on --init) - these paths are standard
        # for the repo package, a custom aide.conf might differ
        if mode == 'init':
            out, err = ssh.sudo(f'aide --config {AIDE_CONFIG} --init 2>&1', timeout=600)
            # --init writes the new database as aide.db.new, it has to be
            # explicitly activated by renaming - otherwise the next --check
            # would compare against the old (or missing) database
            ssh.sudo('mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>&1 '
                      '|| mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>&1', timeout=30)
            if 'error' in out.lower() and 'Total number of entries' not in out:
                return {'error': 'error initializing the AIDE database', 'detail': out.strip()[-500:]}
            return {'host': host, 'mode': 'init', 'output_tail': out.strip()[-800:],
                    'findings': [_finding('ok', 'AIDE database initialized — you can now run mode=check')],
                    'summary': {'high': 0, 'medium': 0, 'low': 0, 'ok': 1}}

        # mode == 'check'. Uses sudo, same as the actual --check below - the
        # database directory is root:root (0700-ish) on a standard aide
        # install, so an unprivileged `test -f` here would report MISSING
        # even when the database genuinely exists, from permission denied
        # rather than absence (confirmed against the real target: `ls
        # /var/lib/aide/` as the unprivileged user returns "Permission
        # denied", not "No such file or directory").
        db_check, _ = ssh.sudo('test -f /var/lib/aide/aide.db || test -f /var/lib/aide/aide.db.gz '
                                '&& echo EXISTS || echo MISSING')
        if 'MISSING' in db_check:
            return {'error': 'AIDE database not found — run this same check with mode=init first',
                    'hint': '/var/lib/aide/aide.db does not exist'}

        # timeout=900 (15 min): a full filesystem scan on a real target took
        # ~7 minutes end to end (confirmed via `time aide --check`), same
        # ballpark as --init above - a low timeout here would kill a
        # legitimate scan on any server with a non-trivial filesystem.
        out, err = ssh.sudo(f'aide --config {AIDE_CONFIG} --check 2>&1', timeout=900)

    finally:
        ssh.close()

    summary = _parse_summary(out)
    if summary is None:
        # AIDE reports "no changes" with different wording if nothing changed at all -
        # or there's genuinely no Summary block, in which case don't pretend we parsed it
        if 'no differences' in out.lower() or 'looks okay' in out.lower():
            return {'host': host, 'mode': 'check',
                    'findings': [_finding('ok', 'no changes found — the filesystem matches the database')],
                    'summary': {'high': 0, 'medium': 0, 'low': 0, 'ok': 1}}
        return {'error': 'failed to parse aide --check output', 'detail': out.strip()[-500:]}

    findings = []
    if summary['added'] > 0:
        findings.append(_finding('medium', f"files added: {summary['added']}",
                                  'new files outside of updates - worth checking where they came from'))
    if summary['removed'] > 0:
        findings.append(_finding('medium', f"files removed: {summary['removed']}"))
    if summary['changed'] > 0:
        findings.append(_finding('high', f"files changed: {summary['changed']}",
                                  'if this isn\'t the result of a routine apt upgrade - figure out what '
                                  'exactly changed and why; after a legitimate update, reinitialize the '
                                  'database (mode=init), otherwise it will keep making noise'))
    if not findings:
        findings.append(_finding('ok', 'no changes found — the filesystem matches the database'))

    counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
    for f in findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    return {
        'host': host,
        'mode': 'check',
        'total_entries': summary['total_entries'],
        'added': summary['added'],
        'removed': summary['removed'],
        'changed': summary['changed'],
        'findings': findings,
        'summary': counts,
    }
