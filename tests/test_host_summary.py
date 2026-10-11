"""B2.4 read-only per-host summary and same-check comparison."""

from __future__ import annotations

import json

from netaudit_pkg.host_summary import compare_hosts, host_summary


def _finding(severity, **extra):
    return {'id': f'F-{severity}', 'severity': severity, **extra}


def test_summary_mixed_success_error_unknown_and_incomplete():
    report = {
        'results': {
            'server_audit': {'_multi_host': True, 'by_host': {
                'h2': {'error': 'connection failed'},
                'h1': {'findings': [_finding('high'),
                                    _finding('info', requires_manual_verification=True)],
                       'sections': {'duplicate': {'findings': [_finding('high')]}}},
            }},
            'dns_audit': {'sections': {'lookup': [_finding('low')]},
                          'warnings': ['partial lookup']},
            'metrics': {'value': 7},
        },
        'execution_context': {
            'server_audit': {'h2': {'host': 'h2'}, 'h1': {'host': 'h1'}},
            'dns_audit': {'host': 'h1'},
            'metrics': {'host': 'h1'},
        },
    }
    summary = host_summary(report)
    assert [row['host'] for row in summary['hosts']] == ['h2', 'h1']
    h2, h1 = summary['hosts']
    assert (h2['completed_checks'], h2['errored_checks']) == (0, 1)
    assert h2['observed_counts'] is None
    assert h2['error_checks'] == ['server_audit']
    assert (h1['completed_checks'], h1['errored_checks']) == (2, 0)
    assert h1['observed_counts'] == {'critical': 0, 'high': 1, 'medium': 0, 'low': 1}
    assert h1['incomplete_checks'] == ['server_audit', 'dns_audit']
    assert h1['unknown_checks'] == ['metrics']
    assert [c['check_id'] for c in h1['checks']] == ['server_audit', 'dns_audit', 'metrics']
    assert [c['status'] for c in h1['checks']] == ['incomplete', 'incomplete', 'unknown']


def test_comparison_preserves_input_order_and_real_host_not_suffix():
    report = {
        'results': {'check': {'_multi_host': True, 'by_host': {
            'z': {'findings': [_finding('critical')]},
            'h': {'findings': [_finding('low')]},
            'h#2': {'findings': [_finding('medium')]},
        }}},
        'execution_context': {'check': {
            'z': {'host': 'z'}, 'h': {'host': 'h'}, 'h#2': {'host': 'h'},
        }},
    }
    compared = compare_hosts(report, 'check')
    assert [r['host'] for r in compared['hosts']] == ['z', 'h', 'h']
    assert [r['instance_key'] for r in compared['hosts']] == ['z', 'h', 'h#2']
    assert all(r['check_id'] == 'check' for r in compared['hosts'])
    summary = host_summary(report)
    assert [r['host'] for r in summary['hosts']] == ['z', 'h']
    duplicate = summary['hosts'][1]
    assert duplicate['duplicate_checks'] == ['check']
    assert duplicate['observed_counts'] is None


def test_summary_never_copies_raw_secret_or_error_text():
    secret = 'TEST-SECRET-DO-NOT-EXPOSE'
    report = {
        'results': {'check': {'_multi_host': True, 'by_host': {
            'a': {'error': secret},
            'b': {'findings': [_finding('high', title=secret)], 'warnings': [secret]},
        }}},
        'execution_context': {'check': {
            'a': {'host': 'a', 'password': secret},
            'b': {'host': 'b', 'sudo_password': secret},
        }},
    }
    assert secret not in json.dumps(host_summary(report))
    assert secret not in json.dumps(compare_hosts(report, 'check'))


def test_unknown_form_has_no_comparable_counts_not_zero():
    report = {'results': {'check': {'summary': 'ok'}},
              'execution_context': {'check': {'host': 'h'}}}
    [host] = host_summary(report)['hosts']
    assert host['observed_counts'] is None
    assert host['unknown_checks'] == ['check']
    assert compare_hosts(report, 'other') == {'check_id': 'other', 'hosts': []}
