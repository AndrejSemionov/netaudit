"""
Rootkit check via rkhunter and/or chkrootkit over SSH.

Both tools do similar work (looking for known rootkit signatures, tampered
system commands, hidden processes), but with different signature databases
and different false-positive patterns - so by default we run both and don't
deduplicate findings, to avoid losing something caught by only one of them.

rkhunter: `--check --skip-keypress --report-warnings-only --nocolors` -
non-interactive, only Warning: lines, no ANSI codes (otherwise parsing
breaks on escape sequences).

chkrootkit: line-by-line output "Checking `name'... STATUS", where STATUS is
one of: not infected / INFECTED / not tested / not found / Vulnerable but
disabled. Only INFECTED lines matter.

IMPORTANT about false positives: both tools are known for them - e.g.
chkrootkit sometimes confuses a legitimate bindshell (Exim TLS) for a real
backdoor, and on some VPS/containers reports "hidden processes" due to
virtualization quirks rather than an actual rootkit. A finding here is a
reason to investigate, not a confirmed compromise.
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

# confidence: 'high' (default) - the finding is a direct fact (a file's mtime,
# a config value). 'low'/'medium' - the finding comes from a heuristic or a tool
# known for false positives (rkhunter/chkrootkit here) and needs a human to verify
# it before treating it as confirmed.

# ===========================================================================
# rkhunter
# ===========================================================================

def _parse_rkhunter(raw: str) -> list[dict]:
    """With --report-warnings-only, the output is left with almost only
    'Warning: ...' lines (plus a version banner and system messages)."""
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith('Warning:'):
            text = line[len('Warning:'):].strip()
            findings.append(_finding('medium', text, confidence='low',
                                      requires_manual_verification=True))
    return findings

def _run_rkhunter(ssh: SSHExecutor) -> tuple[list[dict], str | None]:
    """Returns (findings, error). error is not None if the tool
    failed to run.

    No presence check here - the caller (check_rootkit(), via
    _ensure_installed()) already confirmed the tool is installed via
    SSHExecutor.is_tool_installed() before this function is ever
    called. A second, redundant presence check used to live here
    (`which rkhunter || echo NOTFOUND`) - removed as part of the same
    quality-audit fix that corrected is_tool_installed() itself: that
    old check had the identical which-collapse bug (any nonzero exit
    of `which`, including a transient SSH hiccup, collapsed into "not
    installed"), and running it a second time here only gave that bug
    a second chance to produce a false negative on a tool the caller
    had already confirmed present."""
    out, _ = ssh.sudo('rkhunter --check --skip-keypress --report-warnings-only --nocolors 2>&1', timeout=300)

    if not out.strip():
        return [], 'rkhunter returned no output (check sudo privileges)'

    return _parse_rkhunter(out), None

# ===========================================================================
# chkrootkit
# ===========================================================================

CHKROOTKIT_LINE_RE = re.compile(r"^Checking `([^']+)'\.\.\.\s*(.+)$")

def _parse_chkrootkit(raw: str) -> list[dict]:
    findings = []
    for line in raw.splitlines():
        m = CHKROOTKIT_LINE_RE.match(line.strip())
        if not m:
            continue
        name, status = m.group(1), m.group(2).strip()
        if status.startswith('INFECTED'):
            findings.append(_finding('high', f'{name}: {status}',
                                      'verify manually before drawing conclusions — false positives are known '
                                      '(e.g. a legitimate bindshell on non-standard ports)',
                                      confidence='low', requires_manual_verification=True))
        elif status.startswith('Vulnerable but disabled'):
            findings.append(_finding('low', f'{name}: {status}',
                                      'the command is vulnerable but not in use (not running/not in config)'))
    return findings

def _run_chkrootkit(ssh: SSHExecutor) -> tuple[list[dict], str | None]:
    """Returns (findings, error). See _run_rkhunter()'s docstring for
    why there's no presence check here either - same reasoning, same
    fix."""
    out, _ = ssh.sudo('chkrootkit 2>&1', timeout=300)

    if not out.strip():
        return [], 'chkrootkit returned no output (check sudo privileges)'

    return _parse_chkrootkit(out), None

# ===========================================================================
# Check
# ===========================================================================

@register(
    id='rootkit_check', label='Rootkit check (rkhunter/chkrootkit, SSH)', category='server',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Host', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'User', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH port', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Key path', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Password (if not using a key)', 'default': ''},
        {'name': 'use_rkhunter', 'type': 'checkbox', 'label': 'Run rkhunter', 'default': True},
        {'name': 'use_chkrootkit', 'type': 'checkbox', 'label': 'Run chkrootkit', 'default': True},
        {'name': 'auto_install', 'type': 'checkbox', 'label': 'Install missing tools',
         'default': False},
        confirm_param('Confirm: this may install packages on the target'),
    ],
    required_tools=[],
    description='Searches for known rootkits and tampered system commands via rkhunter and/or '
                'chkrootkit over SSH. Read-only, system reads only, unless "Install missing tools" '
                'is enabled and confirmed. Both tools produce '
                'false positives — findings need manual verification, not a ready-made verdict.',
)
def check_rootkit(host='', user='root', port=22, key_path='', password='',
                   use_rkhunter=True, use_chkrootkit=True, auto_install=False,
                   confirm_modify='no') -> dict:
    if paramiko is None:
        return {'error': 'paramiko not installed'}
    if not host:
        return {'error': 'host not specified'}
    if not use_rkhunter and not use_chkrootkit:
        return {'error': 'select at least one tool (rkhunter or chkrootkit)'}
    if auto_install and confirm_modify != CONFIRM_MODIFY:
        return {'error': 'auto_install would modify the target system (install packages) '
                          'but was not confirmed',
                'hint': 'set "Confirm: this may install packages on the target" to proceed'}

    try:
        ssh = SSHExecutor(host, user, port, key_path, password).connect()
    except HostKeyMismatchError as e:
        return {'error': str(e)}
    except Exception as e:
        return {'error': f'could not connect: {e}'}

    try:
        def _ensure_installed(tool):
            if ssh.is_tool_installed(tool):
                return True
            if not auto_install:
                return False
            installed, _ = ssh.ensure_tool_installed(tool, timeout=120)
            return installed

        tools_status = {}
        all_findings = []
        errors = []

        if use_rkhunter:
            if not _ensure_installed('rkhunter'):
                errors.append('rkhunter is not installed' + (' and could not be installed' if auto_install else ''))
                tools_status['rkhunter'] = {'ran': False}
            else:
                findings, err = _run_rkhunter(ssh)
                if err:
                    errors.append(f'rkhunter: {err}')
                    tools_status['rkhunter'] = {'ran': False}
                else:
                    for f in findings:
                        f['source'] = 'rkhunter'
                    all_findings.extend(findings)
                    tools_status['rkhunter'] = {'ran': True, 'findings_count': len(findings)}

        if use_chkrootkit:
            if not _ensure_installed('chkrootkit'):
                errors.append('chkrootkit is not installed' + (' and could not be installed' if auto_install else ''))
                tools_status['chkrootkit'] = {'ran': False}
            else:
                findings, err = _run_chkrootkit(ssh)
                if err:
                    errors.append(f'chkrootkit: {err}')
                    tools_status['chkrootkit'] = {'ran': False}
                else:
                    for f in findings:
                        f['source'] = 'chkrootkit'
                    all_findings.extend(findings)
                    tools_status['chkrootkit'] = {'ran': True, 'findings_count': len(findings)}

    finally:
        ssh.close()

    if not any(s.get('ran') for s in tools_status.values()):
        return {'error': 'no tool ran', 'detail': '; '.join(errors)}

    if not all_findings:
        all_findings.append(_finding('ok', 'no signs of rootkits found'))

    counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
    for f in all_findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    result = {
        'host': host,
        'tools': tools_status,
        'findings': all_findings,
        'summary': counts,
    }
    if errors:
        result['warnings'] = errors
    return result
