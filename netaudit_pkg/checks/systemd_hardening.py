"""
systemd sandboxing audit of a remote service unit, over SSH.

Runs `systemd-analyze security <unit> --json=short` on the target host and
maps each failed/partial hardening directive to a finding. Requires
systemd >= 246 (json output support) - older systemd (e.g. Ubuntu 18.04,
Debian 10) either lacks --json or lacks the subcommand entirely.

Read-only: systemd-analyze security only inspects the unit file and running
process, it changes nothing.
"""

from __future__ import annotations

import json

from ..registry import register
from ..findings import finding as _finding
from ..ssh import SSHExecutor, HostKeyMismatchError

try:
    import paramiko
except ImportError:
    paramiko = None

# ===========================================================================
# Parsing systemd-analyze security --json=short
# ===========================================================================

# exposure contribution -> severity. systemd-analyze assigns each directive
# a weight (0.1-0.5); anything failed at >=0.3 is worth flagging as medium+,
# smaller weights (NoNewPrivileges, RestrictSUIDSGID, etc.) as low.
_HIGH_WEIGHT = 0.4
_MEDIUM_WEIGHT = 0.2


def _severity_for_weight(weight: float, is_exposed: bool) -> str:
    if not is_exposed:
        return 'ok'
    if weight >= _HIGH_WEIGHT:
        return 'high'
    if weight >= _MEDIUM_WEIGHT:
        return 'medium'
    return 'low'


def _parse_json(raw: str) -> dict:
    """systemd-analyze security --json=short returns a JSON array of
    {name, description, json_field, exposure, happy}-shaped rows plus a
    trailing overall score - the exact schema varies a bit across systemd
    versions, so we're defensive about missing keys."""
    data = json.loads(raw)
    rows = data if isinstance(data, list) else data.get('entries', [])

    overall = None
    directives = []
    for row in rows:
        name = row.get('name') or row.get('id') or ''
        if name in ('OVERALL EXPOSURE LEVEL', 'overall'):
            overall = row.get('exposure') or row.get('value')
            continue
        directives.append(row)

    return {'overall': overall, 'directives': directives}


def _to_findings(parsed: dict, unit: str) -> list[dict]:
    findings = []
    for d in parsed['directives']:
        name = d.get('name', '')
        desc = d.get('description', '')
        exposure = d.get('exposure', 0) or 0
        # systemd marks a directive as exposed with an 'x' (unset/permissive)
        # in text mode; in json mode this is typically a bool 'exposed' field
        # or exposure > 0 with no 'happy'/'✓' marker - handle both shapes.
        exposed = bool(d.get('exposed', exposure and not d.get('happy', False)))
        if not exposed:
            continue
        severity = _severity_for_weight(float(exposure), exposed)
        if severity == 'ok':
            continue
        findings.append(_finding(
            severity, f'{name} not restricted',
            f'{desc} (exposure weight {exposure}) — unit: {unit}',
        ))
    if not findings:
        findings.append(_finding('ok', f'systemd sandboxing for {unit} looks reasonably hardened'))
    return findings


# ===========================================================================
# Check
# ===========================================================================

@register(
    id='systemd_hardening', label='systemd sandboxing audit (SSH)', category='server',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Host', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'User', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH port', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Key path', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Password (if not using a key)', 'default': ''},
        {'name': 'unit', 'type': 'text', 'label': 'systemd unit', 'default': 'nginx.service'},
    ],
    required_tools=[],
    description='Audits a systemd service unit\'s sandboxing directives (ProtectSystem, '
                 'NoNewPrivileges, PrivateNetwork, etc.) via `systemd-analyze security`. '
                 'Read-only. Requires systemd >= 246 on the target.',
)
def check_systemd_hardening(host='', user='root', port=22, key_path='', password='',
                             unit='nginx.service') -> dict:
    if paramiko is None:
        return {'error': 'paramiko not installed'}
    if not host:
        return {'error': 'host not specified'}
    if not unit:
        return {'error': 'unit not specified'}

    try:
        ssh = SSHExecutor(host, user, port, key_path, password).connect()
    except HostKeyMismatchError as e:
        return {'error': str(e)}
    except Exception as e:
        return {'error': f'could not connect: {e}'}

    try:
        # confirm the unit exists before running the full analysis, so a
        # typo'd unit name gives a clear error instead of a confusing
        # "0 directives found" result.
        status_out, _ = ssh.run(f'systemctl status {unit} --no-pager 2>&1 | head -1')
        if 'could not be found' in status_out or 'Unit ' in status_out and 'not found' in status_out:
            return {'error': f'unit {unit!r} not found on {host}'}

        raw, err = ssh.sudo(f'systemd-analyze security {unit} --no-pager --json=short 2>&1')
        if not raw.strip():
            return {'error': 'empty output from systemd-analyze',
                    'hint': 'systemd-analyze security requires systemd >= 246'}
        if raw.lstrip().startswith('Unknown') or 'not installed' in raw or 'command not found' in raw:
            return {'error': 'systemd-analyze security not available on this host',
                    'detail': raw.strip()[:300],
                    'hint': 'requires systemd >= 246 (Ubuntu 20.04+, Debian 11+)'}
    finally:
        ssh.close()

    try:
        parsed = _parse_json(raw)
    except json.JSONDecodeError as e:
        return {'error': 'failed to parse systemd-analyze output as JSON', 'detail': str(e),
                'raw_excerpt': raw.strip()[:500]}

    findings = _to_findings(parsed, unit)

    counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
    for f in findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    return {
        'host': host,
        'unit': unit,
        'overall_exposure': parsed['overall'],
        'findings': findings,
        'summary': counts,
    }
