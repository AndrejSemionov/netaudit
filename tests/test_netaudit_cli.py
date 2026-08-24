"""
Tests for netaudit.py CLI caller integration with AI Analysis #17 history
(see netaudit_pkg/storage.py's find_related_reports() and
netaudit_pkg/history.py's ai_analyze(history=...)).

Contract under test: cmd_run() and cmd_analyze() must call
storage.find_related_reports(report, limit=3) and pass its result as the
history= argument to ai_analyze(), instead of calling ai_analyze(report)
with no history at all (the pre-integration behavior).

These are unit tests against the cmd_* functions directly with a hand-built
argparse.Namespace, not through main()/argparse - per project decision,
argparse itself is not part of this contract; only the caller's use of
find_related_reports() + ai_analyze(history=...) is.
"""

from __future__ import annotations

from argparse import Namespace
from unittest.mock import patch

import netaudit

SAMPLE_REPORT = {
    'timestamp': 't1',
    'results': {'ping': {'loss_pct': 0}},
    'execution_context': {'ping': {'host': '1.2.3.4'}},
}

FAKE_RELATED = [
    {'timestamp': 't0', 'checks': ['ping'], 'results': {'ping': {'loss_pct': 5}}},
]


def _namespace_run(**overrides):
    base = {'checks': ['ping'], 'quick': False, 'rest': [], 'ai': True}
    base.update(overrides)
    return Namespace(**base)


def test_cmd_run_passes_history_to_ai_analyze():
    with patch('netaudit.run_checks', return_value=SAMPLE_REPORT), \
         patch('netaudit.save_report', return_value=1), \
         patch('netaudit.storage.find_related_reports', return_value=FAKE_RELATED) as mock_find, \
         patch('netaudit.ai_analyze', return_value={'summary': 'ok'}) as mock_analyze:
        netaudit.cmd_run(_namespace_run())

    mock_find.assert_called_once_with(SAMPLE_REPORT, limit=3)
    mock_analyze.assert_called_once()
    _, kwargs = mock_analyze.call_args
    assert mock_analyze.call_args.args[0] == SAMPLE_REPORT
    assert kwargs.get('history') == FAKE_RELATED


def test_cmd_run_without_ai_flag_never_touches_history():
    """args.ai=False must not call find_related_reports or ai_analyze at
    all - the history lookup is only relevant when AI analysis actually
    runs."""
    with patch('netaudit.run_checks', return_value=SAMPLE_REPORT), \
         patch('netaudit.save_report', return_value=1), \
         patch('netaudit.storage.find_related_reports') as mock_find, \
         patch('netaudit.ai_analyze') as mock_analyze:
        netaudit.cmd_run(_namespace_run(ai=False))

    mock_find.assert_not_called()
    mock_analyze.assert_not_called()


def test_cmd_analyze_passes_history_to_ai_analyze():
    with patch('netaudit.load_report', return_value=SAMPLE_REPORT), \
         patch('netaudit.storage.find_related_reports', return_value=FAKE_RELATED) as mock_find, \
         patch('netaudit.ai_analyze', return_value={'summary': 'ok'}) as mock_analyze:
        netaudit.cmd_analyze(Namespace(id='1'))

    mock_find.assert_called_once_with(SAMPLE_REPORT, limit=3)
    mock_analyze.assert_called_once()
    assert mock_analyze.call_args.args[0] == SAMPLE_REPORT
    assert mock_analyze.call_args.kwargs.get('history') == FAKE_RELATED


def test_cmd_analyze_report_not_found_never_touches_history():
    with patch('netaudit.load_report', return_value=None), \
         patch('netaudit.storage.find_related_reports') as mock_find, \
         patch('netaudit.ai_analyze') as mock_analyze:
        netaudit.cmd_analyze(Namespace(id='999'))

    mock_find.assert_not_called()
    mock_analyze.assert_not_called()
