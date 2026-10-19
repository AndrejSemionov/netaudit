"""
A changed check setting is not a fix (docs/research/trend_coverage_params.md):
when the settings that decide what a check looks at differ between the two
compared runs (dns_audit subdomains, backup_check directories, the systemd
unit, a threshold), a finding that disappeared is `not_evaluated`, never
`resolved` - in the CLI/Web trend, the AI context and the notification.
"""

from __future__ import annotations

import json
from argparse import Namespace
from unittest.mock import MagicMock, patch

import netaudit
from netaudit_pkg import notify
from netaudit_pkg.history import ai_analyze
from netaudit_pkg.trends import compute_trend, snapshots_from_report, trend_context

ROOT = __import__('pathlib').Path(__file__).resolve().parent.parent


def _f(severity, fid=None):
    d = {'severity': severity, 'title': 't', 'detail': '', 'confidence': 'high'}
    if fid:
        d['id'] = fid
    return d


def _report(ts, check_id, ctx, result):
    return {'timestamp': ts, 'results': {check_id: result}, 'timing': {}, 'meta': {},
            'execution_context': {check_id: ctx}, 'total_time': 0}


def _multi(ts, check_id, by_host):
    """by_host: {host: (extra params, result)}"""
    return {'timestamp': ts, 'timing': {}, 'meta': {}, 'total_time': 0,
            'results': {check_id: {'_multi_host': True,
                                   'by_host': {h: result for h, (_, result) in by_host.items()}}},
            'execution_context': {check_id: {h: {'host': h, **extra}
                                             for h, (extra, _) in by_host.items()}}}


def _change(*reports):
    snaps = []
    for r in reports:
        snaps.extend(snapshots_from_report(r))
    return compute_trend(snaps)['latest_change']


def _dns(**sections):
    full = {name: [] for name in ('spf', 'dkim', 'dmarc', 'dnssec', 'dangling_cname',
                                  'discovered_services')}
    full.update(sections)
    return {'domain': 'site.example', 'sections': full, 'summary': {}, 'collection_failures': 0}


BLOG = 'DNS-CNAME-001:blog.site.example'


def _dns_runs(subs_before, subs_after):
    before = _report('t1', 'dns_audit', {'domain': 'site.example', 'subdomains_to_check': subs_before},
                     _dns(dangling_cname=[_f('high', BLOG)]))
    after = _report('t2', 'dns_audit', {'domain': 'site.example', 'subdomains_to_check': subs_after},
                    _dns())
    return before, after


# --- the false "resolved" ------------------------------------------------------

def test_dns_audit_subdomain_dropped_from_the_list_is_not_resolved():
    ch = _change(*_dns_runs('www,blog', 'www'))
    assert ch['resolved'] == []
    assert ch['not_evaluated'] == [BLOG]
    assert ch['params_changed'] == ['subdomains_to_check']


def test_backup_directory_dropped_from_the_list_is_not_resolved():
    ch = _change(
        _report('t1', 'backup_check', {'host': '10.0.0.5', 'directories': '/var/backups,/srv/backup'},
                {'findings': [_f('high', 'BAK-AGE-001')]}),
        _report('t2', 'backup_check', {'host': '10.0.0.5', 'directories': '/var/backups'},
                {'findings': []}))
    assert (ch['resolved'], ch['not_evaluated']) == ([], ['BAK-AGE-001'])
    assert ch['params_changed'] == ['directories']


def test_a_relaxed_threshold_is_not_a_fix():
    ch = _change(
        _report('t1', 'backup_check', {'host': '10.0.0.5'}, {'findings': [_f('high', 'BAK-AGE-001')]}),
        _report('t2', 'backup_check', {'host': '10.0.0.5', 'max_age_hours': 1000}, {'findings': []}))
    assert (ch['resolved'], ch['not_evaluated']) == ([], ['BAK-AGE-001'])
    assert ch['params_changed'] == ['max_age_hours']


def test_another_systemd_unit_is_not_a_fix():
    ch = _change(
        _report('t1', 'systemd_hardening', {'host': '10.0.0.5', 'unit': 'nginx.service'},
                {'findings': [_f('medium', 'SYSD-001')]}),
        _report('t2', 'systemd_hardening', {'host': '10.0.0.5', 'unit': 'ssh.service'},
                {'findings': [_f('low', 'SYSD-002')]}))
    assert (ch['resolved'], ch['not_evaluated'], ch['new']) == ([], ['SYSD-001'], ['SYSD-002'])
    assert ch['params_changed'] == ['unit']


# --- unchanged -------------------------------------------------------------------

def test_same_settings_still_resolve():
    ch = _change(*_dns_runs('www,blog', 'www,blog'))
    assert (ch['resolved'], ch['not_evaluated'], ch['params_changed']) == ([BLOG], [], [])


def test_a_cli_run_and_a_web_run_with_the_same_values_compare_equal():
    """CLI saves only the flags given, Web saves every field, numbers as
    numbers; a missing setting is its registry default."""
    cli = _report('t1', 'backup_check', {'host': '10.0.0.5', 'max_age_hours': '26'},
                  {'findings': [_f('high', 'BAK-AGE-001')]})
    web = _report('t2', 'backup_check', {'host': '10.0.0.5', 'user': 'root', 'port': 22,
                                         'key_path': '~/.ssh/id_rsa', 'directories': '/var/backups',
                                         'max_age_hours': 26, 'min_copies': 2}, {'findings': []})
    ch = _change(cli, web)
    assert (ch['resolved'], ch['not_evaluated'], ch['params_changed']) == (['BAK-AGE-001'], [], [])


def test_a_checkbox_left_at_its_default_compares_equal():
    ch = _change(
        _report('t1', 'docker_audit', {'host': '10.0.0.5'}, {'findings': [_f('high', 'DOCKER-001')]}),
        _report('t2', 'docker_audit', {'host': '10.0.0.5', 'include_stopped': False}, {'findings': []}))
    assert (ch['resolved'], ch['params_changed']) == (['DOCKER-001'], [])


def test_a_nan_number_setting_still_equals_itself():
    ch = _change(
        _report('t1', 'backup_check', {'host': '10.0.0.5', 'max_age_hours': 'nan'},
                {'findings': [_f('high', 'BAK-AGE-001')]}),
        _report('t2', 'backup_check', {'host': '10.0.0.5', 'max_age_hours': 'nan'}, {'findings': []}))
    assert (ch['resolved'], ch['params_changed']) == (['BAK-AGE-001'], [])


def test_how_to_connect_is_not_a_check_setting():
    ch = _change(
        _report('t1', 'lynis_audit', {'host': '10.0.0.5', 'user': 'root', 'port': 22},
                {'findings': [_f('high', 'LYNIS-001')]}),
        _report('t2', 'lynis_audit', {'host': '10.0.0.5', 'user': 'audit', 'port': 2222,
                                      'key_path': '/k', 'auto_install': True}, {'findings': []}))
    assert (ch['resolved'], ch['not_evaluated'], ch['params_changed']) == (['LYNIS-001'], [], [])


def test_a_check_unknown_to_the_registry_compares_its_saved_settings():
    ch = _change(
        _report('t1', 'x_check', {'host': '10.0.0.5', 'depth': 'full'}, {'findings': [_f('high', 'X-1')]}),
        _report('t2', 'x_check', {'host': '10.0.0.5', 'depth': 'quick'}, {'findings': []}))
    assert (ch['resolved'], ch['not_evaluated'], ch['params_changed']) == ([], ['X-1'], ['depth'])


# --- group runs and duplicate instances --------------------------------------

def test_group_run_only_the_host_with_changed_settings_is_not_evaluated():
    before = _multi('t1', 'backup_check', {
        '10.0.0.5': ({'directories': '/a,/b'}, {'findings': [_f('high', 'BAK-A')]}),
        '10.0.0.6': ({'directories': '/a'}, {'findings': [_f('high', 'BAK-B')]}),
    })
    after = _multi('t2', 'backup_check', {
        '10.0.0.5': ({'directories': '/a'}, {'findings': []}),
        '10.0.0.6': ({'directories': '/a'}, {'findings': []}),
    })
    snaps = snapshots_from_report(before) + snapshots_from_report(after)
    by_host = {h: compute_trend([s for s in snaps if s['value'] == h])['latest_change']
               for h in ('10.0.0.5', '10.0.0.6')}
    assert by_host['10.0.0.5']['not_evaluated'] == ['BAK-A']
    assert by_host['10.0.0.6']['resolved'] == ['BAK-B']


def test_two_instances_of_one_unit_with_different_settings_are_ambiguous():
    report = {'timestamp': 't1', 'timing': {}, 'meta': {}, 'total_time': 0,
              'results': {'backup_check': {'_multi_host': True, 'by_host': {
                  '10.0.0.5:22': {'findings': []}, '10.0.0.5:2222': {'findings': []}}}},
              'execution_context': {'backup_check': {
                  '10.0.0.5:22': {'host': '10.0.0.5', 'port': 22, 'directories': '/a'},
                  '10.0.0.5:2222': {'host': '10.0.0.5', 'port': 2222, 'directories': '/b'}}}}
    [snap] = snapshots_from_report(report)
    assert snap['error'].startswith('ambiguous: ')


# --- every consumer of the change ----------------------------------------------

def test_ai_trend_context_does_not_call_it_resolved(isolated_db):
    before, after = _dns_runs('www,blog', 'www')
    isolated_db.save_report(before)
    rid = isolated_db.save_report(after)
    [item] = trend_context(after, report_id=rid)
    ch = item['latest_change']
    assert (ch['resolved'], ch['not_evaluated'], ch['params_changed']) == ([], [BLOG], ['subdomains_to_check'])


def test_notification_lists_it_as_not_checked(isolated_db):
    before, after = _dns_runs('www,blog', 'www')
    isolated_db.save_report(before)
    changes = notify.collect_changes(after, isolated_db.save_report(after))
    [unit] = changes['units']
    assert unit['resolved'] == []
    assert [f['id'] for f in unit['not_checked']] == [BLOG]


def test_cli_trend_says_the_settings_changed(isolated_db, capsys):
    for report in _dns_runs('www,blog', 'www'):
        isolated_db.save_report(report)
    netaudit.cmd_trend(Namespace(check_id='dns_audit', value='site.example', key=None, json=False))
    out = capsys.readouterr().out
    assert 'check settings changed: subdomains_to_check' in out
    assert 'resolved: -' in out


def test_cli_trend_has_no_settings_line_when_nothing_changed(isolated_db, capsys):
    for report in _dns_runs('www,blog', 'www,blog'):
        isolated_db.save_report(report)
    netaudit.cmd_trend(Namespace(check_id='dns_audit', value='site.example', key=None, json=False))
    assert 'check settings changed' not in capsys.readouterr().out


def test_web_shows_the_settings_line_in_both_languages():
    html = (ROOT / 'web' / 'static' / 'index.html').read_text(encoding='utf-8')
    i18n = (ROOT / 'web' / 'static' / 'i18n.js').read_text(encoding='utf-8')
    assert 'ch.params_changed' in html and "t('trends.change.params_changed')" in html
    assert i18n.count("'trends.change.params_changed':") == 2


def test_ai_prompt_explains_params_changed(isolated_db):
    resp = MagicMock()
    resp.json.return_value = {'content': [{'type': 'text', 'text': '{"summary": "ok"}'}]}
    trends = [{'check_id': 'dns_audit', 'key': 'domain', 'value': 'site.example',
               'latest_change': {'not_evaluated': [BLOG], 'params_changed': ['subdomains_to_check']}}]
    with patch('httpx.post', return_value=resp) as post:
        ai_analyze({'timestamp': 't2', 'results': {}}, api_key='sk-test', language='en', trends=trends)
    prompt = post.call_args.kwargs['json']['messages'][0]['content']
    assert '"params_changed"' in prompt.split(json.dumps(trends, ensure_ascii=False, indent=2))[0]
