"""
laravel_data: versions read from a public composer.lock or installed.json,
their known vulnerabilities (OSV.dev, Packagist ecosystem) and Laravel's
security support (endoflife.date) - docs/research/laravel_audit.md §3,
contract L3.

No network: OSV's batch query is faked at laravel_data._post_json, the
advisory and support answers at laravel_data._get_json. The SSH check's
cve_audit.query_osv is not used (review pass 1: its batch parsing and cache
stay as they are).
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
    assert laravel_data.lock_packages(text) == {
        'packages': [{'name': 'laravel/framework', 'version': '11.0.0'},
                     {'name': 'phpunit/phpunit', 'version': '10.5.1'}],
        'unreadable': 0}


def test_lock_packages_reads_installed_json_of_composer_2_and_1():
    two = json.dumps({'packages': [{'name': 'laravel/framework', 'version': 'v12.3.0'}], 'dev': True})
    one = json.dumps([{'name': 'laravel/framework', 'version': 'v5.8.38'}])
    assert laravel_data.lock_packages(two)['packages'] == [{'name': 'laravel/framework', 'version': '12.3.0'}]
    assert laravel_data.lock_packages(one)['packages'] == [{'name': 'laravel/framework', 'version': '5.8.38'}]


@pytest.mark.parametrize('text', ['<html>Not Found</html>', '', '{}', '{"packages": "x"}', '[1, 2]',
                                  '{"require": {"laravel/framework": "^12.0"}}'])
def test_lock_packages_is_none_for_anything_else(text):
    assert laravel_data.lock_packages(text) is None


def test_lock_packages_counts_the_entries_it_could_not_read():
    # review pass 1: a skipped entry is a gap, never a package with no vulnerabilities
    text = json.dumps({'packages': [{'name': 'a/b'}, {'version': '1.0'}, 'x', {'name': 'c/d', 'version': '2.0'}]})
    assert laravel_data.lock_packages(text) == {'packages': [{'name': 'c/d', 'version': '2.0'}], 'unreadable': 3}


@pytest.mark.parametrize('entry', [
    {'name': 'evil/pkg; rm -rf ~', 'version': '1.0.0'},
    {'name': 'Evil/Pkg', 'version': '1.0.0'},
    {'name': 'no-vendor', 'version': '1.0.0'},
    {'name': 'a/b', 'version': '1.0.0 $(id)'},
    {'name': 'a/b', 'version': '`id`'},
])
def test_lock_packages_takes_only_names_and_versions_in_composers_format(entry):
    # review pass 1 (P1): what comes from the site is checked before it is asked about or shown
    text = json.dumps({'packages': [entry, {'name': 'c/d', 'version': '2.0'}]})
    assert laravel_data.lock_packages(text) == {'packages': [{'name': 'c/d', 'version': '2.0'}], 'unreadable': 1}


def test_lock_packages_accepts_real_composer_names_and_versions():
    names = ['laravel/framework', 'symfony/polyfill-php83', 'nette/utils', 'league/flysystem-local',
             'phpdocumentor/reflection-docblock', 'psr/http-message', 'doctrine/dbal', 'a.b/c_d--e']
    versions = ['v12.3.0', '1.0.0-beta1', 'dev-main', '2.x-dev', 'dev-feature/login', '1.2.3+build.4']
    entries = [{'name': n, 'version': v} for n, v in zip(names, versions + ['1.0'] * len(names))]
    assert laravel_data.lock_packages(json.dumps({'packages': entries}))['unreadable'] == 0


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


def test_advisory_names_no_fix_when_the_version_is_in_no_range(answers):
    # review pass 1 (P4): a fix of another release line is not this version's fix
    answers[_vuln_url('GHSA-x')] = (200, _advisory('GHSA-x'))
    assert laravel_data.advisory('GHSA-x', 'laravel/framework', 'dev-main')['fixed'] == []


def test_advisory_never_offers_a_fix_of_another_branch(answers):
    record = {'id': 'GHSA-y', 'summary': 's', 'affected': [{
        'package': {'name': 'a/b', 'ecosystem': 'Packagist'},
        'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '1.0.0'}, {'fixed': '1.9.0'},
                                                    {'introduced': '2.0.0'}]}]}]}
    answers[_vuln_url('GHSA-y')] = (200, record)
    assert laravel_data.advisory('GHSA-y', 'a/b', '2.1.0')['fixed'] == []
    assert laravel_data.advisory('GHSA-y', 'a/b', '1.2.0')['fixed'] == ['1.9.0']


def test_advisory_last_affected_range_has_no_fix(answers):
    record = {'id': 'GHSA-z', 'summary': 's', 'affected': [{
        'package': {'name': 'a/b', 'ecosystem': 'Packagist'},
        'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'last_affected': '3.2.0'}]},
                   {'type': 'ECOSYSTEM', 'events': [{'introduced': '4.0.0'}, {'fixed': '4.1.0'}]}]}]}
    answers[_vuln_url('GHSA-z')] = (200, record)
    assert laravel_data.advisory('GHSA-z', 'a/b', '3.0.0')['fixed'] == []
    assert laravel_data.advisory('GHSA-z', 'a/b', '4.0.5')['fixed'] == ['4.1.0']


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

@pytest.fixture
def batch(monkeypatch):
    """The OSV batch answer: (status, data) | Exception; returns the request bodies."""
    state = {'answer': (200, {'results': []}), 'asked': []}

    def post_json(url, body):
        assert url == laravel_data.OSV_BATCH_URL
        state['asked'].append(body)
        if isinstance(state['answer'], Exception):
            raise state['answer']
        return state['answer']

    monkeypatch.setattr(laravel_data, '_post_json', post_json)
    return state


TWO = [{'name': 'laravel/framework', 'version': '11.0.0'}, {'name': 'guzzlehttp/guzzle', 'version': '7.4.0'}]


def test_vulnerabilities_asks_osv_for_packagist_and_reads_each_record(batch, answers):
    batch['answer'] = (200, {'results': [{'vulns': [{'id': 'GHSA-78fx-h6xr-vch4', 'modified': 'x'}]}, {}]})
    answers[_vuln_url('GHSA-78fx-h6xr-vch4')] = (200, _advisory())
    data = laravel_data.vulnerabilities(TWO)
    assert batch['asked'] == [{'queries': [
        {'package': {'name': 'laravel/framework', 'ecosystem': 'Packagist'}, 'version': '11.0.0'},
        {'package': {'name': 'guzzlehttp/guzzle', 'ecosystem': 'Packagist'}, 'version': '7.4.0'}]}]
    assert data['status'] == 'ok'
    assert [a['id'] for a in data['matches']['laravel/framework']] == ['GHSA-78fx-h6xr-vch4']
    assert data['matches']['guzzlehttp/guzzle'] == []      # {} is OSV's "none known"
    assert data['unanswered'] == []
    assert data['checked'] == 2


@pytest.mark.parametrize('element', [None, [], 'x', {'vulns': None}, {'vulns': 'x'}, {'vulns': [None]},
                                     {'vulns': [{'modified': 'x'}]}, {'vulns': [{'id': 'GHSA x;y'}]},
                                     {'next_page_token': 'abc'},
                                     {'vulns': [{'id': 'GHSA-a'}], 'next_page_token': 'abc'}])
def test_an_answer_osv_did_not_give_in_its_format_is_not_none_known(batch, answers, element):
    # review pass 1 (P2): only an element in OSV's format says "none known"; a
    # paged element is not the whole answer
    batch['answer'] = (200, {'results': [element, {}]})
    data = laravel_data.vulnerabilities(TWO)
    assert data['status'] == 'ok'
    assert data['unanswered'] == ['laravel/framework']
    assert 'laravel/framework' not in data['matches']
    assert data['matches']['guzzlehttp/guzzle'] == []


@pytest.mark.parametrize('answer', [(200, {'results': [{}]}), (200, {'results': [{}, {}, {}]}), (200, {}),
                                    (200, None), (500, None), (200, {'results': 'x'}),
                                    httpx.ConnectError('down')])
def test_vulnerabilities_without_a_whole_answer_is_an_error(batch, answer):
    batch['answer'] = answer
    data = laravel_data.vulnerabilities(TWO)
    assert data['status'] == 'error'
    assert 'OSV' in data['error']
    assert data['matches'] == {}


def test_the_ssh_checks_osv_path_is_not_used(batch, monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError('cve_audit.query_osv must stay the SSH check\'s own')

    monkeypatch.setattr(cve_audit, 'query_osv', refuse)
    batch['answer'] = (200, {'results': [{}, {}]})
    assert laravel_data.vulnerabilities(TWO)['status'] == 'ok'


def test_vulnerabilities_reads_at_most_max_advisories(batch, answers):
    ids = [f'GHSA-{i}' for i in range(laravel_data.MAX_ADVISORIES + 3)]
    batch['answer'] = (200, {'results': [{'vulns': [{'id': vid} for vid in ids]}]})
    for vid in ids:
        answers[_vuln_url(vid)] = (200, _advisory(vid, name='a/b'))
    data = laravel_data.vulnerabilities([{'name': 'a/b', 'version': '11.0.0'}])
    found = data['matches']['a/b']
    assert len(found) == len(ids)                      # every one is reported
    assert len(answers['requested']) == laravel_data.MAX_ADVISORIES
    assert all(a['error'] for a in found[laravel_data.MAX_ADVISORIES:])


def test_packages_past_the_limit_are_named_as_not_asked(batch):
    many = [{'name': f'v/p{i}', 'version': '1.0'} for i in range(laravel_data.MAX_PACKAGES + 2)]
    batch['answer'] = (200, {'results': [{} for _ in range(laravel_data.MAX_PACKAGES)]})
    data = laravel_data.vulnerabilities(many)
    assert data['unanswered'] == [f'v/p{laravel_data.MAX_PACKAGES}', f'v/p{laravel_data.MAX_PACKAGES + 1}']
    assert data['checked'] == laravel_data.MAX_PACKAGES


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
