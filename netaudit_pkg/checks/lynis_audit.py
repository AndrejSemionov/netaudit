"""
Lynis audit of a remote server over SSH.

Runs `lynis audit system` on the target host, reads the machine-readable
/var/log/lynis-report.dat, and maps warnings/suggestions into the same
findings format (severity/title/detail) as server_audit.

Requires: lynis installed on the remote server, passwordless sudo (or
running as root) - otherwise check coverage is significantly reduced.
Doesn't change anything on the server - lynis itself is read-only in audit mode.
"""

from __future__ import annotations

import re

from ..registry import register

try:
    import paramiko
except ImportError:
    paramiko = None


# ===========================================================================
# Helpers (same pattern as server_security.py)
# ===========================================================================

def _ssh_connect(host, user, port, key_path, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {'hostname': host, 'port': int(port), 'username': user, 'timeout': 10,
              'look_for_keys': bool(key_path), 'allow_agent': bool(key_path)}
    if key_path and key_path.strip():
        from pathlib import Path
        kwargs['key_filename'] = str(Path(key_path).expanduser())
    elif password:
        kwargs['password'] = password
    client.connect(**kwargs)
    return client


def _run(client, cmd, timeout=15):
    _, so, se = client.exec_command(cmd, timeout=timeout)
    return so.read().decode(errors='replace'), se.read().decode(errors='replace')


def _run_sudo(client, cmd, sudo_password, timeout=15):
    """
    sudo without a TTY: a plain `sudo cmd` fails with 'a terminal is required
    to authenticate' if NOPASSWD isn't set up for the user (a common case on
    other people's/client servers where sudoers can't be tweaked).
    `sudo -S` reads the password from stdin - works without a TTY, no need
    to pre-configure sudoers on the target machine.
    If passwordless sudo is actually available, an empty stdin also works fine.
    """
    stdin, so, se = client.exec_command(f'sudo -S -p "" {cmd}', timeout=timeout)
    stdin.write((sudo_password or '') + '\n')
    stdin.flush()
    stdin.channel.shutdown_write()
    return so.read().decode(errors='replace'), se.read().decode(errors='replace')


def _finding(severity, title, detail=''):
    return {'severity': severity, 'title': title, 'detail': detail}


# ===========================================================================
# Parsing lynis-report.dat
# ===========================================================================

def _parse_report(raw: str) -> dict:
    """
    report.dat format - flat key=value, repeated keys (warning[], suggestion[])
    come as a list of lines. Values inside are Test:ID|text|extra.
    """
    hardening_index = None
    warnings = []
    suggestions = []
    tests_performed = 0
    os_name = ''

    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '=' not in line:
            continue
        key, _, value = line.partition('=')

        if key == 'hardening_index':
            try:
                hardening_index = int(value)
            except ValueError:
                pass
        elif key == 'tests_executed':
            try:
                tests_performed = int(value)
            except ValueError:
                pass
        elif key == 'os_fullname' or key == 'os_name':
            os_name = os_name or value
        elif key == 'warning[]':
            parts = value.split('|')
            text = parts[1] if len(parts) > 1 else value
            test_id = parts[0] if parts else ''
            warnings.append((test_id, text))
        elif key == 'suggestion[]':
            parts = value.split('|')
            text = parts[1] if len(parts) > 1 else value
            test_id = parts[0] if parts else ''
            suggestions.append((test_id, text))

    return {
        'hardening_index': hardening_index,
        'os_name': os_name,
        'tests_performed': tests_performed,
        'warnings': warnings,
        'suggestions': suggestions,
    }


def _to_findings(parsed: dict) -> list[dict]:
    findings = []
    # Lynis warnings are real problems - map to high
    for test_id, text in parsed['warnings']:
        findings.append(_finding('high', text.strip(), f'Lynis [{test_id}]'))
    # suggestions are improvement recommendations - map to low
    for test_id, text in parsed['suggestions']:
        findings.append(_finding('low', text.strip(), f'Lynis [{test_id}]'))
    if not findings:
        findings.append(_finding('ok', 'Lynis found no issues'))
    return findings


# ===========================================================================
# Check
# ===========================================================================

@register(
    id='lynis_audit', label='Lynis security audit (SSH)', category='server',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Host', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'User', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH port', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Key path', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Password (if not using a key)', 'default': ''},
        {'name': 'auto_install', 'type': 'checkbox', 'label': 'Install lynis if missing',
         'default': False},
    ],
    required_tools=[],
    description='Server security audit via Lynis (hardening index + findings) over SSH. Read-only.',
)
def check_lynis_audit(host='', user='root', port=22, key_path='', password='',
                       auto_install=False) -> dict:
    if paramiko is None:
        return {'error': 'paramiko not installed'}
    if not host:
        return {'error': 'host not specified'}
    try:
        client = _ssh_connect(host, user, port, key_path, password)
    except Exception as e:
        return {'error': f'could not connect: {e}'}

    try:
        which_out, _ = _run(client, 'which lynis || echo NOTFOUND')
        if 'NOTFOUND' in which_out:
            if not auto_install:
                return {'error': 'lynis is not installed on the server',
                        'hint': 'apt install lynis -y (or enable auto_install)'}
            install_out, install_err = _run(
                client, 'sudo apt-get install -y lynis 2>&1', timeout=90
            )
            which_out, _ = _run(client, 'which lynis || echo NOTFOUND')
            if 'NOTFOUND' in which_out:
                return {'error': 'failed to install lynis',
                        'detail': (install_out + install_err)[-500:]}

        # passwordless sudo? if not - use sudo -S with the password over stdin,
        # this works without a TTY and without pre-configuring sudoers on the
        # target machine (relevant for other people's/client servers)
        sudo_check, _ = _run(client, 'sudo -n true 2>&1 && echo OK || echo NOPASS')
        no_sudo = 'NOPASS' in sudo_check

        if no_sudo and not password:
            return {'error': 'sudo is needed, but passwordless sudo isn\'t set up and no password was given',
                    'hint': 'set "Password (if not using a key)" — it will also be used for sudo -S'}

        if no_sudo:
            _run_sudo(client, 'lynis audit system --quiet --no-colors', password, timeout=180)
            report_raw, report_err = _run_sudo(client, 'cat /var/log/lynis-report.dat', password)
        else:
            _run(client, 'sudo lynis audit system --quiet --no-colors', timeout=180)
            # the file is always root:root with 640 permissions, read it via sudo
            # regardless of how the audit itself was run - otherwise cat silently
            # fails with Permission denied
            report_raw, report_err = _run(client, 'sudo cat /var/log/lynis-report.dat 2>&1')

        if not report_raw.strip() or 'hardening_index' not in report_raw:
            return {'error': 'failed to read /var/log/lynis-report.dat',
                    'detail': report_err.strip()[:500] or report_raw.strip()[:500],
                    'hint': 'check the sudo password or permissions: ls -la /var/log/lynis-report.dat'}

    finally:
        client.close()

    parsed = _parse_report(report_raw)
    findings = _to_findings(parsed)

    counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
    for f in findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    result = {
        'host': host,
        'os_name': parsed['os_name'],
        'hardening_index': parsed['hardening_index'],
        'tests_performed': parsed['tests_performed'],
        'findings': findings,
        'summary': counts,
    }
    return result
