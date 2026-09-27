"""
Tests for `netaudit trend` (cmd_trend) - first consumer of the trend layer
(docs/research/trend_layer_research_summary.md, Contract v1 item 5).

Unit tests against cmd_trend() with a hand-built Namespace, against a real
isolated_db (not mocks) - the command's job is presenting trends.py output,
so the tests exercise the real read path end to end.

  netaudit trend                                -> list trend units
  netaudit trend <check_id> <value> [--key K]   -> trend of one unit
  ... --json                                    -> machine-readable output
"""

from __future__ import annotations

import json
from argparse import Namespace

import pytest

import netaudit
from netaudit_pkg import trends


def _ns(check_id=None, value=None, key=None, as_json=False):
    return Namespace(check_id=check_id, value=value, key=key, json=as_json)


def _f(severity, fid=None):
    d = {'severity': severity, 'title': 't', 'detail': '', 'confidence': 'high'}
    if fid:
        d['id'] = fid
    return d


def _save(db, ts, check_id, ctx, result):
    db.save_report({'timestamp': ts, 'results': {check_id: result}, 'timing': {}, 'meta': {},
                    'execution_context': {check_id: ctx}, 'total_time': 0})


def _seed_ssh(db):
    _save(db, '2026-01-01 00:00:00', 'ssh_hardening', {'host': '10.0.0.1'},
          {'findings': [_f('high', 'SSH-001'), _f('medium', 'SSH-004')],
           'hardening': {'score': 60, 'max': 100, 'components': []}})
    _save(db, '2026-01-02 00:00:00', 'ssh_hardening', {'host': '10.0.0.1'},
          {'error': 'connection refused'})
    _save(db, '2026-01-03 00:00:00', 'ssh_hardening', {'host': '10.0.0.1'},
          {'findings': [_f('medium', 'SSH-004')],
           'hardening': {'score': 75, 'max': 100, 'components': []}})


# ===========================================================================
# list mode
# ===========================================================================

def test_trend_list_empty_db(isolated_db, capsys):
    netaudit.cmd_trend(_ns())

    assert 'No trend history yet' in capsys.readouterr().out


def test_trend_list_shows_units(isolated_db, capsys):
    _seed_ssh(isolated_db)

    netaudit.cmd_trend(_ns())

    out = capsys.readouterr().out
    assert 'ssh_hardening' in out
    assert 'host=10.0.0.1' in out
    assert '3 runs' in out


def test_trend_list_json(isolated_db, capsys):
    _seed_ssh(isolated_db)

    netaudit.cmd_trend(_ns(as_json=True))

    assert json.loads(capsys.readouterr().out) == trends.list_units()


# ===========================================================================
# single-unit mode
# ===========================================================================

def test_trend_unit_text_output(isolated_db, capsys):
    _seed_ssh(isolated_db)

    netaudit.cmd_trend(_ns('ssh_hardening', '10.0.0.1'))

    out = capsys.readouterr().out
    assert 'ssh_hardening' in out and 'host=10.0.0.1' in out
    assert 'ERROR: connection refused' in out
    assert '60 -> 75 (+15)' in out           # hardening score change
    assert '2 -> 1 (-1)' in out              # problem total change
    assert 'resolved: SSH-001' in out
    assert 'persisting: SSH-004' in out


def test_trend_unit_json_matches_trend_for(isolated_db, capsys):
    _seed_ssh(isolated_db)

    netaudit.cmd_trend(_ns('ssh_hardening', '10.0.0.1', as_json=True))

    assert json.loads(capsys.readouterr().out) == trends.trend_for('ssh_hardening', 'host', '10.0.0.1')


def test_trend_unit_single_run_has_no_change_section(isolated_db, capsys):
    _save(isolated_db, '2026-01-01 00:00:00', 'ssh_hardening', {'host': '10.0.0.1'},
          {'findings': []})

    netaudit.cmd_trend(_ns('ssh_hardening', '10.0.0.1'))

    out = capsys.readouterr().out
    assert 'Not enough successful runs to compare' in out


def test_trend_unit_unknown(isolated_db, capsys):
    _seed_ssh(isolated_db)

    netaudit.cmd_trend(_ns('ssh_hardening', '10.9.9.9'))

    assert 'No trend history for ssh_hardening 10.9.9.9' in capsys.readouterr().out


def test_trend_unit_key_is_inferred_when_unambiguous(isolated_db, capsys):
    _save(isolated_db, '2026-01-01 00:00:00', 'dns_audit', {'domain': 'example.com'},
          {'findings': [_f('low')]})

    netaudit.cmd_trend(_ns('dns_audit', 'example.com'))

    assert 'domain=example.com' in capsys.readouterr().out


def test_trend_unit_ambiguous_key_asks_for_key(isolated_db, capsys):
    _save(isolated_db, '2026-01-01 00:00:00', 'x', {'host': 'a.example', 'domain': 'a.example'},
          {'findings': []})

    with pytest.raises(SystemExit) as exc:
        netaudit.cmd_trend(_ns('x', 'a.example'))

    assert exc.value.code == 2
    out = capsys.readouterr().out
    assert '--key' in out
    assert 'domain' in out and 'host' in out


def test_trend_unit_ambiguous_key_json_is_json_error_exit_2(isolated_db, capsys):
    """REVIEW pass 1, defect 3: --json must stay machine-readable even when
    the identity key is ambiguous, and signal failure via the exit status."""
    _save(isolated_db, '2026-01-01 00:00:00', 'x', {'host': 'a.example', 'domain': 'a.example'},
          {'findings': []})

    with pytest.raises(SystemExit) as exc:
        netaudit.cmd_trend(_ns('x', 'a.example', as_json=True))

    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out) == {
        'error': 'ambiguous_key', 'check_id': 'x', 'value': 'a.example', 'keys': ['domain', 'host'],
    }


def test_trend_unit_explicit_key(isolated_db, capsys):
    _save(isolated_db, '2026-01-01 00:00:00', 'x', {'host': 'a.example', 'domain': 'a.example'},
          {'findings': []})

    netaudit.cmd_trend(_ns('x', 'a.example', key='domain'))

    assert 'domain=a.example' in capsys.readouterr().out


def test_trend_is_registered_in_parser():
    args = netaudit.build_parser().parse_args(['trend', 'ssh_hardening', '10.0.0.1', '--key', 'host', '--json'])

    assert args.func is netaudit.cmd_trend
    assert (args.check_id, args.value, args.key, args.json) == ('ssh_hardening', '10.0.0.1', 'host', True)


def test_trend_unit_text_change_uses_run_order_not_timestamp(isolated_db, capsys):
    """REVIEW pass 1, defect 2: two different reports saved in the same second
    must not collapse - the printed from/to numbers must match the JSON diff."""
    _save(isolated_db, '2026-09-26 10:00:00', 'ssh_hardening', {'host': 'h'},
          {'findings': [_f('high')], 'hardening': {'score': 50, 'max': 100, 'components': []}})
    _save(isolated_db, '2026-09-26 10:00:00', 'ssh_hardening', {'host': 'h'},
          {'findings': [], 'hardening': {'score': 90, 'max': 100, 'components': []}})

    netaudit.cmd_trend(_ns('ssh_hardening', 'h'))

    out = capsys.readouterr().out
    assert '1 -> 0 (-1)' in out
    assert '50 -> 90 (+40)' in out
