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
    """systemd-analyze security --json=short returns a flat JSON array of
    directive rows: {set, name, json_field, description, exposure}. `set`
    is true when the directive IS configured (safe/restricted) and false
    when it's left at its permissive default (exposed) - `exposure` is the
    weight contributed to the overall score, as a string, and can be null
    for directives that don't carry an exposure weight (e.g. NotifyAccess=).
    There is no trailing "overall score" row in --json=short output (unlike
    the text/table mode) - the overall exposure level has to be computed
    ourselves from the sum of exposed directives' weights, or left as None.
    """
    data = json.loads(raw)
    rows = data if isinstance(data, list) else data.get('entries', [])
    return {'directives': rows}


def _to_findings(parsed: dict, unit: str) -> list[dict]:
    findings = []
    total_exposure = 0.0
    for d in parsed['directives']:
        name = d.get('name', '')
        desc = d.get('description', '')
        # 'set' is true when the directive is configured (restricted/safe).
        # false means it's at its permissive default - that's what we flag.
        is_set = bool(d.get('set'))
        exposure_raw = d.get('exposure')
        exposure = float(exposure_raw) if exposure_raw not in (None, '') else 0.0

        if not is_set:
            total_exposure += exposure
        if is_set or exposure == 0:
            continue

        severity = _severity_for_weight(exposure, is_exposed=True)
        findings.append(_finding(
            severity, f'{name} not restricted',
            f'{desc} (exposure weight {exposure}) — unit: {unit}',
        ))
    if not findings:
        findings.append(_finding('ok', f'systemd sandboxing for {unit} looks reasonably hardened'))
    return findings, round(total_exposure, 1)


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

    findings, computed_exposure = _to_findings(parsed, unit)

    counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
    for f in findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    return {
        'host': host,
        'unit': unit,
        # computed by summing exposure weights of unrestricted directives -
        # systemd-analyze itself only prints this in text mode, not --json.
        'overall_exposure': computed_exposure,
        'findings': findings,
        'summary': counts,
    }
