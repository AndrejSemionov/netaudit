"""
One client's network audits from several places, merged into one view
(docs/research/network_audit.md §13): the auditor plugs in at the staff
desk, then on the guest Wi-Fi, then in accounting; each audit sees its own
segment fully and the others through the router. The merged view keeps the
latest audit per vantage subnet and joins them: segments by subnet with the
places each was seen from, devices by address, findings by id.
"""

from __future__ import annotations

from . import webprobe


def _vantage_subnet(result: dict) -> str:
    return (result.get('vantage') or {}).get('subnet') or result.get('scanned') or ''


def merge(reports: list[dict]) -> dict:
    """Merged view of the lan_audit results in `reports` (stored reports,
    any order). The shape is a lan_audit result plus 'merged' and 'vantages'."""
    latest: dict = {}
    for report in reports:
        result = (report.get('results') or {}).get('lan_audit')
        if not isinstance(result, dict) or not isinstance(result.get('devices'), list):
            continue
        stamp = str(report.get('timestamp') or '')
        key = _vantage_subnet(result)
        if key not in latest or stamp > latest[key][0]:
            latest[key] = (stamp, result)
    chosen = sorted(latest.values(), key=lambda item: item[0])
    if not chosen:
        return {'merged': True, 'verdict': 'not_started', 'error': 'no network audit of this client yet',
                'vantages': [], 'segments': [], 'devices': [], 'findings': [], 'checked': []}

    vantages, segments, devices, findings, checked, limits = [], {}, {}, {}, [], []
    loose = []
    for stamp, result in chosen:
        v = result.get('vantage') or {}
        subnet = _vantage_subnet(result)
        vantages.append({'subnet': subnet, 'address': v.get('address'), 'interface': v.get('interface'),
                         'wireless': v.get('wireless'), 'timestamp': stamp})
        own_segments = result.get('segments') or [{'cidr': subnet, 'own': True, 'gateway': v.get('gateway'),
                                                    'devices': [d['ip'] for d in result['devices']]}]
        for s in own_segments:
            merged = segments.setdefault(s['cidr'], {**s, 'own': False, 'seen_from': [], 'devices': []})
            merged.update({k: s[k] for k in ('suggestion', 'gateway', 'scanned') if s.get(k) is not None})
            # a label from an earlier audit is not hidden by a later, unlabelled view
            if s.get('labelled') or not merged.get('labelled'):
                merged.update({k: s.get(k) for k in ('name', 'labelled', 'sensitive')})
            if subnet not in merged['seen_from']:
                merged['seen_from'].append(subnet)
            merged['devices'] = sorted(set(merged['devices']) | set(s.get('devices', [])))
        for d in result['devices']:
            devices[d['ip']] = d            # the later audit's view of a device wins
        for f in result.get('findings', []):
            if f.get('id'):
                findings[f['id']] = f
            else:
                loose.append(f)
        checked += [{**c, 'detail': f"{subnet}: {c.get('detail', '')}"} for c in result.get('checked', [])]
        limits += [x for x in result.get('limits', []) if x not in limits]
    last = chosen[-1][1]
    all_findings = list(findings.values()) + loose
    # the vantage of the latest audit is "here" on the merged map
    for cidr, segment in segments.items():
        segment['own'] = cidr == _vantage_subnet(last)
    return {
        'merged': True, 'client': last.get('client', ''), 'vantages': vantages, 'vantage': last.get('vantage'),
        'scanned': ', '.join(v['subnet'] for v in vantages), 'scan_note': None, 'router': last.get('router'),
        'segments': list(segments.values()), 'devices': sorted(devices.values(), key=lambda d: d['ip']),
        'findings': all_findings, 'checked': checked, 'limits': limits,
        'stats': {'devices': len(devices)}, 'next_steps': last.get('next_steps', []),
        'score': webprobe.score(all_findings, checked), 'verdict': webprobe.verdict(all_findings, checked),
        'summary': webprobe.summary(all_findings),
    }


def apply_labels(view: dict, labels: dict) -> dict:
    """The client's current names and sensitive marks on a merged view: a
    segment named after the audits ran shows its name now."""
    for s in view.get('segments', []):
        label = labels.get(s.get('cidr'))
        if label:
            s.update(name=label.get('name') or None, labelled=bool(label.get('name')),
                     sensitive=bool(label.get('sensitive')))
    return view
