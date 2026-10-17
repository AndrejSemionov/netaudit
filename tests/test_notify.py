"""
C2 notifications (docs/research/c1_schedule_notifications.md §3-§4): the full
change set of a run decides whether a Telegram message is sent, the text is
plain and cut only after that decision, and the bot token never reaches a
log record or an error text.
"""

from __future__ import annotations

import json
import logging

import httpx
import pytest

from netaudit_pkg import notify, storage

TOKEN = '123456:FAKE-TOKEN-NEVER-LOGGED'
CHAT = '-1001234'


def _finding(fid, severity, title=None, **extra):
    f = {'severity': severity, 'title': title or f'title of {fid}'}
    if fid:
        f['id'] = fid
    f.update(extra)
    return f


def _single(check_id, host, result, ts):
    return {'timestamp': ts, 'results': {check_id: result}, 'timing': {}, 'meta': {},
            'execution_context': {check_id: {'host': host, 'user': 'audit'}}}


def _multi(check_id, by_host, ts):
    return {'timestamp': ts, 'timing': {}, 'meta': {},
            'results': {check_id: {'_multi_host': True, 'by_host': by_host}},
            'execution_context': {check_id: {h: {'host': h, 'user': 'audit'} for h in by_host}}}


def _save(report):
    return storage.save_report(report)


def _run(prev_findings, cur_findings, check_id='ssh_hardening', host='10.0.0.5'):
    if prev_findings is not None:
        _save(_single(check_id, host, {'findings': prev_findings}, '2026-10-16 03:00:00'))
    cur = _single(check_id, host, {'findings': cur_findings}, '2026-10-17 03:00:00')
    cur_id = _save(cur)
    return cur, cur_id, notify.collect_changes(cur, cur_id)


# --- decide: when a message is sent (§3.2) ----------------------------------

def test_error_and_unreachable_host_always_send(isolated_db):
    cur = _multi('ssh_hardening', {'10.0.0.5': {'error': 'could not connect: timed out'},
                                   '10.0.0.6': {'findings': []}}, '2026-10-17 03:00:00')
    changes = notify.collect_changes(cur, _save(cur))
    assert notify.decide(changes, 'high') is True
    text = notify.render(changes, 7, 'daily')
    assert '10.0.0.5' in text and 'ssh_hardening' in text


def test_incomplete_collection_always_sends(isolated_db):
    result = {'findings': [], 'meta': {'coverage': 'partial', 'events_parsed': 5}}
    cur = _single('kern_log_audit', '10.0.0.5', result, '2026-10-17 03:00:00')
    changes = notify.collect_changes(cur, _save(cur))
    assert notify.decide(changes, 'critical') is True
    assert 'kern_log_audit' in notify.render(changes, 1, None)


def test_a_missing_instance_result_counts_as_an_error(isolated_db):
    cur = _multi('ssh_hardening', {'10.0.0.5': {'findings': []}}, '2026-10-17 03:00:00')
    cur['execution_context']['ssh_hardening']['10.0.0.6'] = {'host': '10.0.0.6'}
    changes = notify.collect_changes(cur, _save(cur))
    assert notify.decide(changes, 'critical') is True
    assert '10.0.0.6' in notify.render(changes, 1, None)


def test_unknown_alone_sends_nothing(isolated_db):
    raw = {'host': '10.0.0.5', 'user': 'audit', 'checks': {'open_ports': '22/tcp'}}
    cur = _single('ssh_audit', '10.0.0.5', raw, '2026-10-17 03:00:00')
    changes = notify.collect_changes(cur, _save(cur))
    assert notify.decide(changes, 'low') is False


def test_new_id_at_or_above_threshold_sends(isolated_db):
    _, _, changes = _run([_finding('SSH-A-001', 'low')],
                         [_finding('SSH-A-001', 'low'), _finding('SSH-A-002', 'medium', 'Root login allowed')])
    assert notify.decide(changes, 'medium') is True
    assert notify.decide(changes, 'high') is False
    text = notify.render(changes, 2, 'daily')
    assert 'SSH-A-002' in text and 'Root login allowed' in text and 'MEDIUM' in text
    assert 'SSH-A-001' not in text  # persisting ids are not repeated


def test_new_id_below_threshold_sends_nothing(isolated_db):
    _, _, changes = _run([], [_finding('SSH-A-009', 'low')])
    assert notify.decide(changes, 'medium') is False


def test_idless_count_increase_sends(isolated_db):
    _, _, changes = _run([_finding(None, 'medium')], [_finding(None, 'medium'), _finding(None, 'high')])
    assert notify.decide(changes, 'medium') is True
    assert 'without id' in notify.render(changes, 2, None)


def test_resolved_only_sends_nothing(isolated_db):
    _, _, changes = _run([_finding('SSH-A-002', 'high')], [])
    assert notify.decide(changes, 'medium') is False


def test_resolved_and_not_checked_ids_are_listed_with_severity_without_title(isolated_db):
    prev = {'sections': {'nginx': {'findings': [_finding('NGX-001', 'high', 'old nginx title')]},
                         'ssh': {'findings': [_finding('SSH-B-001', 'medium', 'old ssh title')]}}}
    cur = {'sections': {'nginx': {'findings': [
        _finding('', 'info', 'could not read nginx config', requires_manual_verification=True)]},
        'ssh': {'findings': [_finding('SSH-B-002', 'high', 'new ssh title')]}}}
    _save(_single('server_audit', '10.0.0.5', prev, '2026-10-16 03:00:00'))
    report = _single('server_audit', '10.0.0.5', cur, '2026-10-17 03:00:00')
    changes = notify.collect_changes(report, _save(report))
    assert notify.decide(changes, 'medium') is True
    text = notify.render(changes, 2, None)
    assert 'SSH-B-002' in text and 'new ssh title' in text
    assert 'SSH-B-001' in text and 'old ssh title' not in text            # resolved: severity, no title
    assert 'NGX-001' in text and 'old nginx title' not in text            # not checked this time
    not_checked = next(line for line in text.splitlines() if 'NGX-001' in line)
    assert 'resolved' not in not_checked.lower()


def test_first_run_in_window_is_a_baseline_not_a_list_of_new(isolated_db):
    _, _, changes = _run(None, [_finding('SSH-A-001', 'high'), _finding('SSH-A-002', 'low')])
    assert notify.decide(changes, 'medium') is True
    assert notify.decide(changes, 'critical') is False
    text = notify.render(changes, 1, None)
    assert 'baseline' in text.lower() and 'last 200 reports' in text
    assert 'SSH-A-001' not in text


def test_a_unit_out_of_the_window_is_a_baseline(isolated_db, monkeypatch):
    monkeypatch.setattr(notify, 'HISTORY_WINDOW', 1)
    _save(_single('ssh_hardening', '10.0.0.5', {'findings': [_finding('SSH-A-001', 'high')]},
                  '2026-10-15 03:00:00'))
    _save(_single('kernel_hardening', '10.0.0.5', {'findings': []}, '2026-10-16 03:00:00'))
    cur = _single('ssh_hardening', '10.0.0.5', {'findings': [_finding('SSH-A-001', 'high')]},
                  '2026-10-17 03:00:00')
    changes = notify.collect_changes(cur, _save(cur))
    assert 'baseline' in notify.render(changes, 3, None).lower()


def test_event_checks_never_claim_new_findings(isolated_db):
    meta = {'coverage': 'complete', 'events_parsed': 10}
    _save(_single('kern_log_audit', '10.0.0.5', {'findings': [], 'meta': meta}, '2026-10-16 03:00:00'))
    cur = _single('kern_log_audit', '10.0.0.5',
                  {'findings': [_finding('KERN-OOM-001', 'high')], 'meta': meta}, '2026-10-17 03:00:00')
    changes = notify.collect_changes(cur, _save(cur))
    assert notify.decide(changes, 'low') is False


def test_nothing_to_report_sends_nothing(isolated_db):
    _, _, changes = _run([_finding('SSH-A-001', 'high')], [_finding('SSH-A-001', 'high')])
    assert notify.decide(changes, 'low') is False


# --- no cut before the decision (review pass 1) ----------------------------

def test_a_high_id_sorted_after_twenty_low_ids_still_sends(isolated_db):
    new = [_finding(f'A-LOW-{i:02d}', 'low') for i in range(20)] + [_finding('Z-HIGH', 'high')]
    _, _, changes = _run([], new)
    assert notify.decide(changes, 'high') is True
    assert 'Z-HIGH' in notify.render(changes, 2, None)


@pytest.mark.parametrize('hosts', [21, 64])
def test_a_new_high_only_on_the_last_host_still_sends(isolated_db, hosts):
    names = [f'h{i:02d}' for i in range(hosts)]
    _save(_multi('ssh_hardening', {h: {'findings': []} for h in names}, '2026-10-16 03:00:00'))
    by_host = {h: {'findings': []} for h in names}
    by_host[names[-1]] = {'findings': [_finding('SSH-A-777', 'high')]}
    cur = _multi('ssh_hardening', by_host, '2026-10-17 03:00:00')
    changes = notify.collect_changes(cur, _save(cur))
    assert notify.decide(changes, 'high') is True
    text = notify.render(changes, 2, None)
    assert 'SSH-A-777' in text and names[-1] in text


# --- render (§3.3) -----------------------------------------------------------

def test_text_is_cut_to_4096_and_keeps_errors_and_high_lines(isolated_db):
    names = [f'host-{i:03d}.example' for i in range(60)]
    _save(_multi('ssh_hardening', {h: {'findings': []} for h in names}, '2026-10-16 03:00:00'))
    by_host = {h: {'findings': [_finding(f'SSH-L-{i:03d}', 'low', 'x' * 300) for i in range(20)]}
               for h in names}
    by_host[names[0]] = {'error': 'could not connect: timed out'}
    by_host[names[-1]]['findings'].append(_finding('SSH-H-999', 'high', 'the important one'))
    cur = _multi('ssh_hardening', by_host, '2026-10-17 03:00:00')
    changes = notify.collect_changes(cur, _save(cur))
    text = notify.render(changes, 2, 'daily')
    assert len(text) <= 4096
    assert names[0] in text                       # the error line is kept
    assert 'SSH-H-999' in text                    # the HIGH line is kept
    assert 'more' in text                         # cut lists say so
    assert all(len(line) <= 300 for line in text.splitlines())
    assert 'x' * 121 not in text                  # titles are cut to 120


def test_titles_cannot_forge_lines_or_markup(isolated_db):
    title = 'evil\n[ERROR] fake line <b>bold</b>'
    _, _, changes = _run([], [_finding('WEB-X-001', 'high', title)])
    text = notify.render(changes, 2, None)
    line = next(line for line in text.splitlines() if 'WEB-X-001' in line)
    assert '[ERROR] fake line' in line            # same line: the newline was neutralised
    assert '<b>bold</b>' in line                  # kept as plain text, never parsed


# --- send_telegram (§3.3) ----------------------------------------------------

def _client(handler, requests=None):
    def wrapped(request):
        if requests is not None:
            requests.append(request)
        return handler(request)
    return httpx.Client(transport=httpx.MockTransport(wrapped))


def _ok(request):
    return httpx.Response(200, json={'ok': True, 'result': {}})


def test_request_is_plain_text_without_link_previews():
    requests = []
    notify.send_telegram('hello <b>x</b>', TOKEN, CHAT, client=_client(_ok, requests))
    [request] = requests
    body = json.loads(request.content)
    assert body['chat_id'] == CHAT and body['text'] == 'hello <b>x</b>'
    assert 'parse_mode' not in body
    assert body['link_preview_options'] == {'is_disabled': True}
    assert request.url.host == 'api.telegram.org'


def _raise(exc_type):
    def handler(request):
        raise exc_type('boom', request=request)
    return handler


def _status(code, **json_body):
    def handler(request):
        return httpx.Response(code, json={'ok': False, **json_body})
    return handler


@pytest.mark.parametrize('handler', [
    _ok, _status(401), _status(500), _status(429, parameters={'retry_after': 3600}),
    _raise(httpx.ReadTimeout), _raise(httpx.ConnectError),
], ids=['200', '401', '500', '429-long', 'read-timeout', 'connect-error'])
def test_the_token_is_in_no_log_record_and_no_error_text(handler, caplog):
    caplog.set_level(logging.DEBUG)
    error = None
    try:
        notify.send_telegram('text', TOKEN, CHAT, client=_client(handler), sleep=lambda s: None)
    except notify.NotifyError as e:
        error = e
    assert TOKEN not in caplog.text
    assert all(TOKEN not in r.getMessage() for r in caplog.records)
    if error is not None:
        assert TOKEN not in str(error) and TOKEN not in repr(error)
        # a traceback would print a chained httpx error with the URL in it
        assert error.__cause__ is None and error.__suppress_context__


def test_no_retry_after_a_read_timeout_or_a_5xx():
    for handler in (_raise(httpx.ReadTimeout), _status(500)):
        requests = []
        with pytest.raises(notify.NotifyError):
            notify.send_telegram('t', TOKEN, CHAT, client=_client(handler, requests), sleep=lambda s: None)
        assert len(requests) == 1


def test_one_retry_after_a_connection_error():
    requests, answers = [], iter([_raise(httpx.ConnectError), _ok])

    def handler(request):
        return next(answers)(request)

    notify.send_telegram('t', TOKEN, CHAT, client=_client(handler, requests), sleep=lambda s: None)
    assert len(requests) == 2


def test_429_is_retried_only_with_a_short_retry_after():
    slept = []
    answers = iter([_status(429, parameters={'retry_after': 5}), _ok])
    requests = []
    notify.send_telegram('t', TOKEN, CHAT, client=_client(lambda r: next(answers)(r), requests),
                         sleep=slept.append)
    assert len(requests) == 2 and slept == [5]

    requests = []
    with pytest.raises(notify.NotifyError):
        notify.send_telegram('t', TOKEN, CHAT,
                             client=_client(_status(429, parameters={'retry_after': 31}), requests),
                             sleep=slept.append)
    assert len(requests) == 1


def test_a_second_connection_error_fails():
    requests = []
    with pytest.raises(notify.NotifyError):
        notify.send_telegram('t', TOKEN, CHAT, client=_client(_raise(httpx.ConnectError), requests),
                             sleep=lambda s: None)
    assert len(requests) == 2


def test_telegram_config_needs_token_and_chat(isolated_db):
    with pytest.raises(notify.NotifyError):
        notify.telegram_config()
    storage.setting_set('telegram_token', TOKEN)
    with pytest.raises(notify.NotifyError) as exc:
        notify.telegram_config()
    assert TOKEN not in str(exc.value)
    storage.setting_set('telegram_chat', CHAT)
    assert notify.telegram_config() == (TOKEN, CHAT)
