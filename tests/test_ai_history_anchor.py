"""
Roadmap 2b, part 1 - docs/research/trend_layer_v1_2_web_ai.md, 2b.1-2b.4:
history for AI analysis comes strictly from runs BEFORE the analyzed report,
in the trend layer's total order (timestamp, id); the analyzed run is never
its own history and a later run is never "previous". ai_analyze() gains a
deterministic-trend block that leaves the prompt unchanged when empty.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from netaudit_pkg.history import ai_analyze


def _report(ts, host='10.0.0.1', findings=None, password=None):
    params = {'host': host}
    if password:
        params['password'] = password
    return {'timestamp': ts, 'timing': {}, 'meta': {}, 'total_time': 0,
            'execution_context': {'ssh_hardening': params},
            'results': {'ssh_hardening': {'findings': findings or []}}}


def _ts(related):
    return [r['timestamp'] for r in related]


# --- find_related_reports(): anchored strictly before the analyzed run ---------

def test_analyzing_a_saved_run_never_returns_itself(isolated_db):
    isolated_db.save_report(_report('2026-04-01 00:00:00'))
    current = _report('2026-04-02 00:00:00')
    rid = isolated_db.save_report(current)
    assert _ts(isolated_db.find_related_reports(current, report_id=rid)) == ['2026-04-01 00:00:00']


def test_analyzing_an_older_run_never_sees_later_runs(isolated_db):
    isolated_db.save_report(_report('2026-04-01 00:00:00'))
    b = isolated_db.save_report(_report('2026-04-02 00:00:00'))
    isolated_db.save_report(_report('2026-04-03 00:00:00'))
    b_report = isolated_db.load_report(b)
    assert _ts(isolated_db.find_related_reports(b_report, report_id=b)) == ['2026-04-01 00:00:00']


def test_distinct_run_saved_in_the_same_second_before_is_kept(isolated_db):
    """GPT/Codex contract review: identical results in the same second are
    still two runs - only the exact id identifies the analyzed one."""
    isolated_db.save_report(_report('2026-04-01 00:00:00', findings=[{'severity': 'high', 'title': 'x'}]))
    b = isolated_db.save_report(_report('2026-04-01 00:00:01'))
    c = isolated_db.save_report(_report('2026-04-01 00:00:01'))
    related = isolated_db.find_related_reports(isolated_db.load_report(c), report_id=c)
    assert _ts(related) == ['2026-04-01 00:00:01', '2026-04-01 00:00:00']
    assert b < c


def test_db_timestamp_of_report_id_is_authoritative(isolated_db):
    """A posted report body cannot move the anchor: with an id, the row's own
    timestamp decides what is "before"."""
    isolated_db.save_report(_report('2026-04-01 00:00:00'))
    b = isolated_db.save_report(_report('2026-04-02 00:00:00'))
    isolated_db.save_report(_report('2026-04-03 00:00:00'))
    forged = _report('2099-01-01 00:00:00')
    assert _ts(isolated_db.find_related_reports(forged, report_id=b)) == ['2026-04-01 00:00:00']


def test_unknown_report_id_falls_back_to_timestamp_anchor(isolated_db):
    isolated_db.save_report(_report('2026-04-01 00:00:00'))
    isolated_db.save_report(_report('2026-04-03 00:00:00'))
    current = _report('2026-04-02 00:00:00')
    assert _ts(isolated_db.find_related_reports(current, report_id=999)) == ['2026-04-01 00:00:00']


def test_inline_report_without_id_uses_strictly_earlier_timestamps(isolated_db):
    isolated_db.save_report(_report('2026-04-01 00:00:00'))
    isolated_db.save_report(_report('2026-04-02 00:00:00'))  # same second as the inline one
    isolated_db.save_report(_report('2026-04-03 00:00:00'))
    current = _report('2026-04-02 00:00:00')
    assert _ts(isolated_db.find_related_reports(current)) == ['2026-04-01 00:00:00']


def test_no_timestamp_and_no_id_means_no_history(isolated_db):
    isolated_db.save_report(_report('2026-04-01 00:00:00'))
    current = _report('2026-04-02 00:00:00')
    del current['timestamp']
    assert isolated_db.find_related_reports(current) == []


# --- report_data_before(): full reports for the trend context -------------------

def test_report_data_before_is_redacted_most_recent_first_and_anchored(isolated_db):
    isolated_db.save_report(_report('2026-04-01 00:00:00', password='FAKE-ANCHOR-PW'))
    isolated_db.save_report(_report('2026-04-02 00:00:00', host='other'))
    b = isolated_db.save_report(_report('2026-04-03 00:00:00'))
    isolated_db.save_report(_report('2026-04-04 00:00:00'))
    data = isolated_db.report_data_before(isolated_db.load_report(b), report_id=b)
    assert _ts(data) == ['2026-04-02 00:00:00', '2026-04-01 00:00:00']
    assert 'FAKE-ANCHOR-PW' not in json.dumps(data)
    assert 'execution_context' in data[0]  # full report, unlike find_related_reports()


def test_report_data_before_respects_window(isolated_db):
    for day in range(1, 6):
        isolated_db.save_report(_report(f'2026-04-0{day} 00:00:00'))
    current = _report('2026-04-09 00:00:00')
    assert len(isolated_db.report_data_before(current, window=2)) == 2


# --- ai_analyze(trends=...) -------------------------------------------------------

def _post(text='{"summary": "ok", "problems": [], "recommendations": []}'):
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {'content': [{'type': 'text', 'text': text}]}
    return resp


def _prompt(**kwargs):
    report = {'timestamp': 't', 'results': {'ping': {'loss_pct': 0}}}
    with patch('httpx.post', return_value=_post()) as mock_post:
        ai_analyze(report, api_key='sk-test', language='en', **kwargs)
    return mock_post.call_args.kwargs['json']['messages'][0]['content']


TREND_ITEM = {'check_id': 'server_audit', 'key': 'host', 'value': 'web1', 'latest_change': {
    'from': 't1', 'to': 't2', 'counts_delta': {'critical': 0, 'high': -2, 'medium': 0, 'low': 1},
    'total_delta': -1, 'score_delta': None, 'new': [], 'resolved': ['FW-UFW-001'],
    'persisting': [], 'not_evaluated': ['NGX-CONF-001']}}


@pytest.mark.parametrize('trends', [None, []])
def test_prompt_unchanged_without_trends(isolated_db, trends):
    assert _prompt(trends=trends) == _prompt()


def test_prompt_gains_deterministic_trend_block(isolated_db):
    prompt = _prompt(trends=[TREND_ITEM])
    assert prompt.startswith(_prompt())
    block = prompt[len(_prompt()):]
    assert 'computed by NetAudit' in block
    assert 'not_evaluated' in block and 'do not treat' in block
    assert 'observed' in block
    assert json.dumps([TREND_ITEM], ensure_ascii=False, indent=2) in block
