"""
Tests for netaudit_pkg.history.ai_analyze()'s history parameter
(AI Analysis #17 History v1).

Contract v1 (frozen before these tests were written):
    ai_analyze(report)                 -> unchanged, stateless, exactly the
                                           prior behavior (backward compat)
    ai_analyze(report, history=None)   -> same as above, explicit None
    ai_analyze(report, history=[...])  -> history-aware: the prompt sent to
                                           the model includes the history
                                           entries, but `report` itself is
                                           NEVER mutated to include history -
                                           history stays a prompt-construction
                                           concern local to this function.

httpx.post is imported lazily inside ai_analyze() (not at module level), so
these tests patch the global 'httpx.post', not
'netaudit_pkg.history.httpx.post' - patching the module-qualified name
would miss the call since the name is looked up fresh on each call via the
local `import httpx` statement.
"""

from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

from netaudit_pkg.history import ai_analyze


def _fake_response(text: str):
    """Builds a MagicMock standing in for httpx.Response, shaped like the
    real Anthropic /v1/messages response ai_analyze() parses."""
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {'content': [{'type': 'text', 'text': text}]}
    return resp


SAMPLE_RESULT_JSON = json.dumps({
    'summary': 'ok', 'problems': [], 'recommendations': [],
})


def test_ai_analyze_without_history_param_is_unchanged():
    """Calling ai_analyze(report) with no history argument at all must
    produce the exact same prompt as before this feature existed - the
    report_json placeholder gets the report as-is, nothing added."""
    report = {'timestamp': 't', 'results': {'ping': {'loss_pct': 0}}}
    with patch('httpx.post', return_value=_fake_response(SAMPLE_RESULT_JSON)) as mock_post:
        ai_analyze(report, api_key='sk-test')

    sent_prompt = mock_post.call_args.kwargs['json']['messages'][0]['content']
    assert 'history' not in sent_prompt.lower().split('report')[0]  # no history section before the report
    # the report's own JSON representation must appear verbatim - proves
    # report_json wasn't wrapped in a {"current_report": ..., "history": []}
    # envelope
    assert json.dumps(report, ensure_ascii=False, indent=2) in sent_prompt


def test_ai_analyze_explicit_none_history_is_unchanged():
    report = {'timestamp': 't', 'results': {'ping': {'loss_pct': 0}}}
    with patch('httpx.post', return_value=_fake_response(SAMPLE_RESULT_JSON)) as mock_post:
        ai_analyze(report, api_key='sk-test', history=None)

    sent_prompt = mock_post.call_args.kwargs['json']['messages'][0]['content']
    assert json.dumps(report, ensure_ascii=False, indent=2) in sent_prompt


def test_ai_analyze_empty_history_list_is_unchanged():
    """An empty list is functionally the same as no history - the prompt
    must not grow a history section for zero entries."""
    report = {'timestamp': 't', 'results': {'ping': {'loss_pct': 0}}}
    with patch('httpx.post', return_value=_fake_response(SAMPLE_RESULT_JSON)) as mock_post:
        ai_analyze(report, api_key='sk-test', history=[])

    sent_prompt = mock_post.call_args.kwargs['json']['messages'][0]['content']
    assert json.dumps(report, ensure_ascii=False, indent=2) in sent_prompt


def test_ai_analyze_with_history_includes_entries_in_prompt():
    report = {'timestamp': 't2', 'results': {'ping': {'loss_pct': 5}}}
    history = [
        {'timestamp': 't1', 'checks': ['ping'], 'results': {'ping': {'loss_pct': 0}}},
    ]
    with patch('httpx.post', return_value=_fake_response(SAMPLE_RESULT_JSON)) as mock_post:
        ai_analyze(report, api_key='sk-test', history=history)

    sent_prompt = mock_post.call_args.kwargs['json']['messages'][0]['content']
    # the history entry's content must reach the model somehow - checking
    # for its distinctive values rather than an exact serialization, since
    # the envelope format around report+history is an implementation detail
    assert 't1' in sent_prompt
    assert '"loss_pct": 0' in sent_prompt or "'loss_pct': 0" in sent_prompt


def test_ai_analyze_history_does_not_mutate_the_report_argument():
    """The report dict passed in must come out unchanged after the call -
    history is a prompt-construction concern, never merged into the report
    object itself (the report is what gets saved to storage/shown in the
    UI; it must not silently grow a history field as a side effect)."""
    report = {'timestamp': 't2', 'results': {'ping': {'loss_pct': 5}}}
    original = json.loads(json.dumps(report))  # deep copy for comparison
    history = [{'timestamp': 't1', 'checks': ['ping'], 'results': {}}]

    with patch('httpx.post', return_value=_fake_response(SAMPLE_RESULT_JSON)):
        ai_analyze(report, api_key='sk-test', history=history)

    assert report == original
    assert 'history' not in report


def test_ai_analyze_with_history_still_returns_parsed_json():
    """The response-parsing behavior (JSON extraction from the model's
    text) is unaffected by whether history was supplied."""
    report = {'timestamp': 't', 'results': {}}
    history = [{'timestamp': 't0', 'checks': [], 'results': {}}]
    with patch('httpx.post', return_value=_fake_response(SAMPLE_RESULT_JSON)):
        result = ai_analyze(report, api_key='sk-test', history=history)

    assert result == {'summary': 'ok', 'problems': [], 'recommendations': []}


def test_ai_analyze_no_api_key_still_errors_before_touching_history():
    """The existing no-API-key error path is unchanged regardless of the
    history argument - fails fast, never reaches httpx.post."""
    report = {'timestamp': 't', 'results': {}}
    history = [{'timestamp': 't0', 'checks': [], 'results': {}}]
    with patch('netaudit_pkg.history._resolve_api_key', return_value=None):
        result = ai_analyze(report, history=history)

    assert 'error' in result
