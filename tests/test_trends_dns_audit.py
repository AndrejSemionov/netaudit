"""
A4.1 - docs/research/a4_1_dns_audit_trends.md: dns_audit (sections are lists
of findings) is trended, and a collection gap - an `info` finding that
requires manual verification - means its scope was not evaluated, so a
missing id there is `not_evaluated`, never `resolved`.
"""

from __future__ import annotations

from argparse import Namespace
from unittest.mock import patch

import netaudit
from netaudit_pkg.checks.dns_audit import check_dns_audit
from netaudit_pkg.trends import compute_trend, snapshots_from_report

DIG_NOERROR_EMPTY = ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n'
DIG_SERVFAIL = ';; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1\n'


def _f(severity, fid=None, unverified=False):
    d = {'severity': severity, 'title': 't', 'detail': '', 'confidence': 'high'}
    if fid:
        d['id'] = fid
    if unverified:
        d['requires_manual_verification'] = True
    return d


def _report(ts, check_id, result, key='domain', value='example.com'):
    return {'timestamp': ts, 'results': {check_id: result}, 'timing': {}, 'meta': {},
            'execution_context': {check_id: {key: value}}, 'total_time': 0}


def _dns(**sections):
    full = {name: [] for name in ('spf', 'dkim', 'dmarc', 'dnssec', 'dangling_cname',
                                  'discovered_services')}
    full.update(sections)
    return {'domain': 'example.com', 'sections': full, 'summary': {}, 'collection_failures': 0}


def _trend(*reports):
    snaps = []
    for r in reports:
        snaps.extend(snapshots_from_report(r))
    return compute_trend(snaps)


def _run_dns_audit(dig_output):
    with patch('netaudit_pkg.checks.dns_audit.tool_available', return_value=True), \
         patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, dig_output, '')):
        return check_dns_audit(domain='example.com', subdomains_to_check='www')


# --- list-shaped sections ------------------------------------------------------

def test_dns_audit_report_gives_one_snapshot_over_all_sections():
    [snap] = snapshots_from_report(_report('t1', 'dns_audit', _dns(
        spf=[_f('high', 'DNS-SPF-001')],
        dmarc=[_f('high', 'DNS-DMARC-001'), _f('ok')],
        discovered_services=[_f('low', 'DNS-TXT-001-google')],
    )))
    assert (snap['check_id'], snap['key'], snap['value']) == ('dns_audit', 'domain', 'example.com')
    assert snap['error'] is None
    assert snap['counts'] == {'critical': 0, 'high': 2, 'medium': 0, 'low': 1}
    assert snap['finding_ids'] == {'DNS-SPF-001': 'high', 'DNS-DMARC-001': 'high',
                                   'DNS-TXT-001-google': 'low'}
    assert set(snap['scopes']) == {'spf', 'dkim', 'dmarc', 'dnssec', 'dangling_cname',
                                   'discovered_services'}


def test_section_of_unknown_shape_gives_no_snapshot():
    assert snapshots_from_report(_report('t1', 'x_check', {'sections': {'a': 'text'}})) == []


# --- a collection gap is not remediation ---------------------------------------

def test_dns_timeout_moves_section_ids_to_not_evaluated_and_other_sections_resolve():
    trend = _trend(
        _report('t1', 'dns_audit', _dns(spf=[_f('high', 'DNS-SPF-001')],
                                        dmarc=[_f('high', 'DNS-DMARC-001')])),
        _report('t2', 'dns_audit', _dns(spf=[_f('info', unverified=True)],
                                        dmarc=[_f('ok')])),
    )
    ch = trend['latest_change']
    assert ch['not_evaluated'] == ['DNS-SPF-001']
    assert ch['resolved'] == ['DNS-DMARC-001']
    assert trend['points'][-1]['unverified'] == 0  # an info gap is not an unverified problem


def test_flat_check_collection_gap_is_not_resolved():
    # web_security_external: "could not test TLSv1/TLSv1.1" is info + flag
    trend = _trend(
        _report('t1', 'web_security_external', {'findings': [_f('high', 'WEB-TLS-001')]},
                key='url', value='https://example.com'),
        _report('t2', 'web_security_external', {'findings': [_f('info', unverified=True)]},
                key='url', value='https://example.com'),
    )
    assert trend['latest_change']['not_evaluated'] == ['WEB-TLS-001']
    assert trend['latest_change']['resolved'] == []


def test_info_finding_without_the_flag_does_not_block_resolved():
    trend = _trend(
        _report('t1', 'dns_audit', _dns(spf=[_f('high', 'DNS-SPF-001')])),
        _report('t2', 'dns_audit', _dns(spf=[_f('ok')], dnssec=[_f('info')])),
    )
    assert trend['latest_change']['resolved'] == ['DNS-SPF-001']
    assert trend['latest_change']['not_evaluated'] == []


def test_instances_differing_only_in_a_gap_are_ambiguous():
    report = {'timestamp': 't1', 'timing': {}, 'meta': {}, 'total_time': 0,
              'execution_context': {'dns_audit': {'h': {'domain': 'example.com'},
                                                  'h#2': {'domain': 'example.com'}}},
              'results': {'dns_audit': {'_multi_host': True, 'by_host': {
                  'h': _dns(spf=[_f('ok')]),
                  'h#2': _dns(spf=[_f('ok')], dkim=[_f('info', unverified=True)])}}}}
    [snap] = snapshots_from_report(report)
    assert snap['error'].startswith('ambiguous: ')


# --- end to end: real check_dns_audit() output ---------------------------------

def test_real_dns_audit_resolver_failure_never_resolves_previous_ids():
    healthy_but_bare = _run_dns_audit(DIG_NOERROR_EMPTY)  # no SPF, no DMARC, ...
    broken_resolver = _run_dns_audit(DIG_SERVFAIL)
    first_ids = {f['id'] for sec in healthy_but_bare['sections'].values() for f in sec if f.get('id')}
    assert 'DNS-SPF-001' in first_ids

    trend = _trend(_report('t1', 'dns_audit', healthy_but_bare),
                   _report('t2', 'dns_audit', broken_resolver))
    ch = trend['latest_change']
    assert ch['resolved'] == []
    assert set(ch['not_evaluated']) == first_ids


def test_cli_trend_prints_dns_audit_runs(isolated_db, capsys):
    isolated_db.save_report(_report('2026-01-01 00:00:00', 'dns_audit',
                                    _dns(spf=[_f('high', 'DNS-SPF-001')])))
    isolated_db.save_report(_report('2026-01-02 00:00:00', 'dns_audit', _dns(spf=[_f('ok')])))

    netaudit.cmd_trend(Namespace(check_id='dns_audit', value='example.com', key=None, json=False))

    out = capsys.readouterr().out
    assert 'dns_audit  domain=example.com  (2 runs)' in out
    assert 'DNS-SPF-001' in out
