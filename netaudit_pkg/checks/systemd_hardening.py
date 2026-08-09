"""
systemd sandboxing audit of a remote service unit, over SSH.

Runs `systemd-analyze security <unit> --json=short` on the target host and
maps each failed/partial hardening directive to a finding. Also runs the
plain-text form of the same command to extract the exact official "Overall
exposure level" score/predicate, since --json=short doesn't include it and
doesn't expose the weight/badness/range values needed to recompute it (see
_parse_overall below for why we don't just sum per-directive exposure).

Requires systemd >= 246 (json output support) - older systemd (e.g. Ubuntu
18.04, Debian 10) either lacks --json or lacks the subcommand entirely.

Read-only: systemd-analyze security only inspects the unit file and running
process, it changes nothing.
"""

from __future__ import annotations

import json
import re

from ..registry import register
from ..findings import finding as _finding
from ..ssh import SSHExecutor, HostKeyMismatchError

try:
    import paramiko
except ImportError:
    paramiko = None

# Matches the trailing summary line systemd-analyze prints in text mode, e.g.
# "-> Overall exposure level for nginx.service: 9.6 UNSAFE (emoji)". The JSON
# output (--json=short) does NOT include this line, nor the weight/badness/
# range values the official formula needs (DIV_ROUND_UP(badness*weight*100,
# range) summed over weight_sum, per systemd's analyze-security.c) - only the
# final per-directive `exposure` survives, and naively summing those over-
# counts relative to the real score (verified empirically against a live
# nginx.service: 12.7 computed by summing exposure vs 9.6 actual). So the
# overall score is fetched from a second, plain-text invocation instead of
# being recomputed from --json=short data.
_OVERALL_RE = re.compile(r'Overall exposure level for [^:]+:\s*([\d.]+)\s+(\w+)')

# ===========================================================================
# Parsing systemd-analyze security --json=short
# ===========================================================================

# exposure contribution -> severity. systemd-analyze assigns each directive
# a weight (0.1-0.5); anything failed at >=0.4 is worth flagging as high,
# 0.2-0.3 as medium, smaller weights (NoNewPrivileges, RestrictSUIDSGID,
# etc. at 0.1) as low.
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
    is true when the directive IS configured (safe/restricted), false when
    it's left at its permissive default (exposed), and null for directives
    that don't apply to this unit type (e.g. SupplementaryGroups= for a
    root-run service) - those have exposure: null and are skipped.
    `exposure` is the per-directive contribution as a string, or null.
    """
    data = json.loads(raw)
    rows = data if isinstance(data, list) else data.get('entries', [])
    return {'directives': rows}


def _parse_overall(text_raw: str) -> tuple[float | None, str | None]:
    """Extract the exact overall exposure score + predicate (OK/MEDIUM/
    EXPOSED/UNSAFE) from the plain-text `systemd-analyze security <unit>`
    output. Returns (None, None) if the line isn't found (e.g. unexpected
    output format)."""
    m = _OVERALL_RE.search(text_raw)
    if not m:
        return None, None
    return float(m.group(1)), m.group(2)


def _to_findings(parsed: dict, unit: str) -> list[dict]:
    findings = []
    for d in parsed['directives']:
        name = d.get('name', '')
        desc = d.get('description', '')
        # 'set' is true when the directive is configured (restricted/safe),
        # false when it's at its permissive default - that's what we flag.
        # None (not applicable to this unit) is treated like "set" - nothing
        # to recommend.
        is_set = d.get('set') is not False
        exposure_raw = d.get('exposure')
        exposure = float(exposure_raw) if exposure_raw not in (None, '') else 0.0

        if is_set or exposure == 0:
            continue

        severity = _severity_for_weight(exposure, is_exposed=True)
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
        if 'could not be found' in status_out or ('Unit ' in status_out and 'not found' in status_out):
            return {'error': f'unit {unit!r} not found on {host}'}

        raw, err = ssh.sudo(f'systemd-analyze security {unit} --no-pager --json=short 2>&1')
        if not raw.strip():
            return {'error': 'empty output from systemd-analyze',
                    'hint': 'systemd-analyze security requires systemd >= 246'}
        if raw.lstrip().startswith('Unknown') or 'not installed' in raw or 'command not found' in raw:
            return {'error': 'systemd-analyze security not available on this host',
                    'detail': raw.strip()[:300],
                    'hint': 'requires systemd >= 246 (Ubuntu 20.04+, Debian 11+)'}

        # second call, plain text, purely to get the exact official overall
        # score/predicate line - see _OVERALL_RE comment for why this can't
        # be derived from the --json=short data above.
        text_raw, _ = ssh.sudo(f'systemd-analyze security {unit} --no-pager 2>&1')
    finally:
        ssh.close()

    try:
        parsed = _parse_json(raw)
    except json.JSONDecodeError as e:
        return {'error': 'failed to parse systemd-analyze output as JSON', 'detail': str(e),
                'raw_excerpt': raw.strip()[:500]}

    findings = _to_findings(parsed, unit)
    overall_score, overall_predicate = _parse_overall(text_raw)

    counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
    for f in findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    return {
        'host': host,
        'unit': unit,
        'overall_exposure': overall_score,
        'overall_predicate': overall_predicate,
        'findings': findings,
        'summary': counts,
    }
