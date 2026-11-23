"""
laravel_data: versions read from a public composer.lock or installed.json,
their known vulnerabilities (OSV.dev, Packagist ecosystem) and Laravel's
security support (endoflife.date) - docs/research/laravel_audit.md §3,
contract L3.

No network: OSV's batch query is faked at laravel_data._query_osv (the
existing cve_audit.query_osv), the advisory and support answers at
laravel_data._get_json.
"""

from __future__ import annotations

import json
from datetime import date

import httpx
import pytest

from netaudit_pkg import laravel_data
from netaudit_pkg.checks import cve_audit

TODAY = date(2026, 11, 23)

EOL = [
    {'cycle': '13', 'eol': '2028-03-17', 'latest': '13.43.0'},
    {'cycle': '12', 'eol': '2027-02-24', 'latest': '12.73.0'},
    {'cycle': '11', 'eol': '2026-03-12', 'latest': '11.57.1'},
    {'cycle': '10', 'eol': '2025-02-04', 'latest': '10.50.4'},
    {'cycle': '6', 'eol': '2022-09-06', 'latest': '6.20.44'},
    {'cycle': '5.8', 'eol': '2020-02-26', 'latest': '5.8.38'},
    {'cycle': '5.5', 'eol': '2020-08-30', 'latest': '5.5.50'},
]


def _advisory(vid='GHSA-78fx-h6xr-vch4', severity='MODERATE', aliases=('CVE-2025-27515',), name='laravel/framework'):
    return {
        'id': vid, 'summary': 'Laravel has a File Validation Bypass', 'aliases': list(aliases),
        'database_specific': {'severity': severity} if severity else {},
        'affected': [
            {'package': {'name': name, 'ecosystem': 'Packagist'},
             'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '12.0.0'}, {'fixed': '12.1.1'}]}]},
            {'package': {'name': name, 'ecosystem': 'Packagist'},
             'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '11.0.0'}, {'fixed': '11.44.1'}]}]},
            {'package': {'name': name, 'ecosystem': 'Packagist'},
             'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '10.48.29'}]}]},
        ],
    }


@pytest.fixture
def answers(monkeypatch):
    """url -> (status, data) | Exception; returns the requested URLs."""
    table: dict = {}
    requested = []

    def get_json(url):
        requested.append(url)
        hit = table.get(url, (404, None))
        if isinstance(hit, Exception):
            raise hit
        return hit

    monkeypatch.setattr(laravel_data, '_get_json', get_json)
    table['requested'] = requested
    return table


def _vuln_url(vid):
    return laravel_data.OSV_VULN_URL.format(id=vid)


# --- lock_packages ------------------------------------------------------------

def test_lock_packages_reads_both_sections_and_strips_the_v():
    text = json.dumps({'packages': [{'name': 'laravel/framework', 'version': 'v11.0.0'}],
                       'packages-dev': [{'name': 'phpunit/phpunit', 'version': '10.5.1'}]})
    assert laravel_data.lock_packages(text) == [{'name': 'laravel/framework', 'version': '11.0.0'},
                                                {'name': 'phpunit/phpunit', 'version': '10.5.1'}]


def test_lock_packages_reads_installed_json_of_composer_2_and_1():
    two = json.dumps({'packages': [{'name': 'laravel/framework', 'version': 'v12.3.0'}], 'dev': True})
    one = json.dumps([{'name': 'laravel/framework', 'version': 'v5.8.38'}])
    assert laravel_data.lock_packages(two) == [{'name': 'laravel/framework', 'version': '12.3.0'}]
    assert laravel_data.lock_packages(one) == [{'name': 'laravel/framework', 'version': '5.8.38'}]


@pytest.mark.parametrize('text', ['<html>Not Found</html>', '', '{}', '{"packages": "x"}', '[1, 2]',
                                  '{"require": {"laravel/framework": "^12.0"}}'])
def test_lock_packages_is_none_for_anything_else(text):
    assert laravel_data.lock_packages(text) is None


def test_lock_packages_skips_entries_without_a_name_or_version():
    text = json.dumps({'packages': [{'name': 'a/b'}, {'version': '1.0'}, 'x', {'name': 'c/d', 'version': '2.0'}]})
    assert laravel_data.lock_packages(text) == [{'name': 'c/d', 'version': '2.0'}]


# --- advisory -------------------------------------------------------------------

def test_advisory_reads_title_severity_cve_link_and_the_fix_for_this_version(answers):
    answers[_vuln_url('GHSA-78fx-h6xr-vch4')] = (200, _advisory())
    a = laravel_data.advisory('GHSA-78fx-h6xr-vch4', 'laravel/framework', '11.0.0')
    assert a == {'id': 'GHSA-78fx-h6xr-vch4', 'title': 'Laravel has a File Validation Bypass',
                 'severity': 'medium', 'cve': 'CVE-2025-27515', 'fixed': ['11.44.1'],
                 'link': 'https://osv.dev/vulnerability/GHSA-78fx-h6xr-vch4', 'error': None}


@pytest.mark.parametrize(('given', 'expected'), [('CRITICAL', 'critical'), ('HIGH', 'high'),
                                                 ('MODERATE', 'medium'), ('LOW', 'low'), (None, 'medium')])
def test_advisory_severity_from_the_github_rating(answers, given, expected):
    answers[_vuln_url('GHSA-x')] = (200, _advisory('GHSA-x', severity=given))
    assert laravel_data.advisory('GHSA-x', 'laravel/framework', '11.0.0')['severity'] == expected


def test_advisory_lists_every_fix_when_the_version_is_in_no_range(answers):
    answers[_vuln_url('GHSA-x')] = (200, _advisory('GHSA-x'))
    a = laravel_data.advisory('GHSA-x', 'laravel/framework', 'dev-main')
    assert a['fixed'] == ['10.48.29', '11.44.1', '12.1.1']


def test_advisory_without_details_still_names_the_record(answers):
    answers[_vuln_url('GHSA-x')] = (500, None)
    a = laravel_data.advisory('GHSA-x', 'laravel/framework', '11.0.0')
    assert a['id'] == 'GHSA-x' and a['link'] == 'https://osv.dev/vulnerability/GHSA-x'
    assert a['severity'] == 'medium' and a['title'] is None
    assert 'HTTP 500' in a['error']


def test_advisory_network_error_is_a_reason_not_a_crash(answers):
    answers[_vuln_url('GHSA-x')] = httpx.ConnectError('down')
    a = laravel_data.advisory('GHSA-x', 'laravel/framework', '11.0.0')
    assert a['error'] and a['title'] is None


def test_advisory_id_is_quoted_in_the_url(answers):
    laravel_data.advisory('GHSA-x/../y', 'a/b', '1.0')
    assert answers['requested'] == [laravel_data.OSV_VULN_URL.format(id='GHSA-x%2F..%2Fy')]


# --- vulnerabilities ----------------------------------------------------------------

def test_vulnerabilities_asks_osv_for_packagist_and_reads_each_record(monkeypatch, answers):
    asked = []

    def query(packages):
        asked.append(packages)
        return {'laravel/framework': ['GHSA-78fx-h6xr-vch4'], 'guzzlehttp/guzzle': []}, set()

    monkeypatch.setattr(laravel_data, '_query_osv', query)
    answers[_vuln_url('GHSA-78fx-h6xr-vch4')] = (200, _advisory())
    data = laravel_data.vulnerabilities([{'name': 'laravel/framework', 'version': '11.0.0'},
                                         {'name': 'guzzlehttp/guzzle', 'version': '7.4.0'}])
    assert asked == [[{'name': 'laravel/framework', 'version': '11.0.0', 'ecosystem': 'Packagist'},
                      {'name': 'guzzlehttp/guzzle', 'version': '7.4.0', 'ecosystem': 'Packagist'}]]
    assert data['status'] == 'ok'
    assert [a['id'] for a in data['matches']['laravel/framework']] == ['GHSA-78fx-h6xr-vch4']
    assert data['matches']['guzzlehttp/guzzle'] == []
    assert data['unanswered'] == []
    assert data['checked'] == 2


def test_vulnerabilities_names_packages_osv_did_not_answer_for(monkeypatch, answers):
    monkeypatch.setattr(laravel_data, '_query_osv',
                        lambda packages: ({'a/b': []}, {'c/d'}))
    data = laravel_data.vulnerabilities([{'name': 'a/b', 'version': '1.0'}, {'name': 'c/d', 'version': '2.0'}])
    assert data['status'] == 'ok'
    assert data['unanswered'] == ['c/d']
    assert 'c/d' not in data['matches']


def test_vulnerabilities_without_any_answer_is_an_error(monkeypatch, answers):
    monkeypatch.setattr(laravel_data, '_query_osv', lambda packages: ({}, {'a/b', 'c/d'}))
    data = laravel_data.vulnerabilities([{'name': 'a/b', 'version': '1.0'}, {'name': 'c/d', 'version': '2.0'}])
    assert data['status'] == 'error'
    assert 'OSV' in data['error']


def test_vulnerabilities_reads_at_most_max_advisories(monkeypatch, answers):
    ids = [f'GHSA-{i}' for i in range(laravel_data.MAX_ADVISORIES + 3)]
    monkeypatch.setattr(laravel_data, '_query_osv', lambda packages: ({'a/b': ids}, set()))
    for vid in ids:
        answers[_vuln_url(vid)] = (200, _advisory(vid, name='a/b'))
    data = laravel_data.vulnerabilities([{'name': 'a/b', 'version': '11.0.0'}])
    found = data['matches']['a/b']
    assert len(found) == len(ids)                      # every one is reported
    assert len(answers['requested']) == laravel_data.MAX_ADVISORIES
    assert all(a['error'] for a in found[laravel_data.MAX_ADVISORIES:])


def test_query_osv_is_the_cve_audit_one(monkeypatch):
    seen = []
    monkeypatch.setattr(cve_audit, 'query_osv', lambda packages: seen.append(packages) or ({}, set()))
    laravel_data._query_osv([{'name': 'a/b', 'version': '1.0', 'ecosystem': 'Packagist'}])
    assert seen == [[{'name': 'a/b', 'version': '1.0', 'ecosystem': 'Packagist'}]]


def test_notices_name_osv_github_and_endoflife_with_their_licences():
    names = {n['name']: n for n in laravel_data.NOTICES}
    assert 'CC BY 4.0' in names['GitHub Advisory Database']['license']
    assert names['endoflife.date']['license'] == 'MIT'
    for n in laravel_data.NOTICES:
        assert n['license_url'].startswith('https://')


# --- support --------------------------------------------------------------------------

@pytest.mark.parametrize(('version', 'status', 'cycle', 'eol'), [
    ('12.3.0', 'supported', '12', '2027-02-24'),
    ('13.0.0', 'supported', '13', '2028-03-17'),
    ('11.44.1', 'ended', '11', '2026-03-12'),
    ('5.8.38', 'ended', '5.8', '2020-02-26'),
    ('5.5.50', 'ended', '5.5', '2020-08-30'),
])
def test_support_by_release_line(answers, version, status, cycle, eol):
    answers[laravel_data.EOL_URL] = (200, EOL)
    s = laravel_data.support(version, TODAY)
    assert (s['status'], s['cycle'], s['eol']) == (status, cycle, eol)
    assert s['error'] is None


def test_support_older_than_every_listed_line_has_ended(answers):
    answers[laravel_data.EOL_URL] = (200, EOL)
    s = laravel_data.support('4.2.22', TODAY)
    assert s['status'] == 'ended' and s['cycle'] is None


@pytest.mark.parametrize('version', ['dev-main', '14.0.0', '7.30.0'])
def test_support_unknown_line_is_unknown_not_supported(answers, version):
    answers[laravel_data.EOL_URL] = (200, EOL)
    assert laravel_data.support(version, TODAY)['status'] == 'unknown'


def test_support_ends_on_its_eol_day(answers):
    answers[laravel_data.EOL_URL] = (200, EOL)
    assert laravel_data.support('12.0.0', date(2027, 2, 24))['status'] == 'ended'
    assert laravel_data.support('12.0.0', date(2027, 2, 23))['status'] == 'supported'


@pytest.mark.parametrize('answer', [(503, None), (200, {'cycle': '12'}), (200, None), httpx.ConnectError('x')])
def test_support_without_an_answer_is_an_error(answers, answer):
    answers[laravel_data.EOL_URL] = answer
    s = laravel_data.support('12.0.0', TODAY)
    assert s['status'] == 'error' and 'endoflife.date' in s['error']


def test_support_eol_flags(answers):
    answers[laravel_data.EOL_URL] = (200, [{'cycle': '12', 'eol': False}, {'cycle': '11', 'eol': True}])
    assert laravel_data.support('12.1.0', TODAY)['status'] == 'supported'
    assert laravel_data.support('11.1.0', TODAY)['status'] == 'ended'
