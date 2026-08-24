"""
Tests for netaudit_pkg.history.ai_analyze().

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


def test_ai_analyze_builds_prompt_without_crashing_on_literal_braces():
    """Regression test for a pre-existing bug: _PROMPT_INSTRUCTIONS itself
    contains a literal JSON example of the expected response format (e.g.
    '{"summary": "...", "problems": [...]}') as part of its instructional
    text. The old implementation built the prompt via
    `_PROMPT_INSTRUCTIONS[lang].format(report_json=report_json)` - but
    str.format() parses ALL brace-delimited tokens in the string as
    placeholders, not just the intended {report_json} one, so the literal
    '{"summary"...}' text in the prompt raised
    `KeyError: '"summary"'` on every real call. This never surfaced before
    because ai_analyze() had no prior test coverage and, per project
    history, had likely never been exercised end-to-end with a real API
    key. The fix must build the prompt without treating the instructional
    text's own braces as format placeholders."""
    report = {'timestamp': 't', 'results': {'ping': {'loss_pct': 0}}}
    with patch('httpx.post', return_value=_fake_response(SAMPLE_RESULT_JSON)):
        result = ai_analyze(report, api_key='sk-test')

    assert 'error' not in result
    assert result == {'summary': 'ok', 'problems': [], 'recommendations': []}


def test_ai_analyze_sends_the_actual_report_json_in_the_prompt():
    report = {'timestamp': 't', 'results': {'ping': {'loss_pct': 0}}}
    with patch('httpx.post', return_value=_fake_response(SAMPLE_RESULT_JSON)) as mock_post:
        ai_analyze(report, api_key='sk-test')

    sent_prompt = mock_post.call_args.kwargs['json']['messages'][0]['content']
    assert json.dumps(report, ensure_ascii=False, indent=2) in sent_prompt


def test_ai_analyze_prompt_still_contains_the_instructional_json_example():
    """The literal JSON-format example in the instructional text must
    still reach the model verbatim after the fix - the fix must stop
    str.format() from choking on it, not strip it out."""
    report = {'timestamp': 't', 'results': {}}
    with patch('httpx.post', return_value=_fake_response(SAMPLE_RESULT_JSON)) as mock_post:
        ai_analyze(report, api_key='sk-test')

    sent_prompt = mock_post.call_args.kwargs['json']['messages'][0]['content']
    assert '"summary"' in sent_prompt
    assert '"problems"' in sent_prompt


def test_ai_analyze_russian_prompt_also_builds_without_crashing():
    """The 'ru' prompt template has the identical structural issue (its
    own literal JSON example) - must be fixed the same way, not just the
    'en' one."""
    report = {'timestamp': 't', 'results': {}}
    with patch('httpx.post', return_value=_fake_response(SAMPLE_RESULT_JSON)):
        result = ai_analyze(report, api_key='sk-test', language='ru')

    assert 'error' not in result
