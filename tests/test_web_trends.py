"""
Web trends (roadmap 2c) - docs/research/trend_layer_v1_2_web_ai.md, section 2c:

  GET /api/trends                          -> {"units": trends.list_units()}
  GET /api/trend?check_id=&key=&value=     -> trends.trend_for(...)
      400 when a parameter is missing or key is not an identity key,
      404 when the unit has no data.

Plus the page side: a Trends card that renders units and one unit's trend
(escaped like every other renderer - tests/test_web_frontend_escaping.py),
and a report opened from history keeps its _report_id for AI analysis (2b.1).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netaudit_pkg import trends
from web.app import app

INDEX = Path(__file__).resolve().parent.parent / 'web' / 'static' / 'index.html'


@pytest.fixture
def client():
    return TestClient(app)


def _f(severity, fid=None):
    d = {'severity': severity, 'title': 't', 'detail': '', 'confidence': 'high'}
    if fid:
        d['id'] = fid
    return d


def _seed(db):
    for ts, findings in (('2026-03-01 00:00:00', [_f('high', 'A'), _f('medium', 'B')]),
                         ('2026-03-02 00:00:00', [_f('medium', 'B')])):
        db.save_report({'timestamp': ts, 'timing': {}, 'meta': {}, 'total_time': 0,
                        'execution_context': {'ssh_hardening': {'host': '10.0.0.9',
                                                                'password': 'FAKE-TREND-PW'}},
                        'results': {'ssh_hardening': {'findings': findings}}})


def test_trends_empty(client, isolated_db):
    resp = client.get('/api/trends')
    assert resp.status_code == 200
    assert resp.json() == {'units': []}


def test_trends_lists_units(client, isolated_db):
    _seed(isolated_db)
    units = client.get('/api/trends').json()['units']
    assert units == json.loads(json.dumps(trends.list_units()))
    assert [(u['check_id'], u['key'], u['value'], u['runs']) for u in units] == [
        ('ssh_hardening', 'host', '10.0.0.9', 2)]


def test_trend_of_one_unit_matches_trend_for(client, isolated_db):
    _seed(isolated_db)
    resp = client.get('/api/trend', params={'check_id': 'ssh_hardening', 'key': 'host', 'value': '10.0.0.9'})
    assert resp.status_code == 200
    body = resp.json()
    assert body == json.loads(json.dumps(trends.trend_for('ssh_hardening', 'host', '10.0.0.9')))
    assert body['latest_change']['resolved'] == ['A']


@pytest.mark.parametrize('params', [
    {'key': 'host', 'value': '10.0.0.9'},
    {'check_id': 'ssh_hardening', 'value': '10.0.0.9'},
    {'check_id': 'ssh_hardening', 'key': 'host'},
    {'check_id': 'ssh_hardening', 'key': 'host', 'value': ''},
    {'check_id': 'ssh_hardening', 'key': 'password', 'value': 'x'},
])
def test_trend_bad_request_is_400(client, isolated_db, params):
    assert client.get('/api/trend', params=params).status_code == 400


def test_trend_unknown_unit_is_404(client, isolated_db):
    _seed(isolated_db)
    resp = client.get('/api/trend', params={'check_id': 'ssh_hardening', 'key': 'host', 'value': 'nope'})
    assert resp.status_code == 404


def test_trend_endpoints_never_return_params(client, isolated_db):
    _seed(isolated_db)
    for resp in (client.get('/api/trends'),
                 client.get('/api/trend', params={'check_id': 'ssh_hardening', 'key': 'host',
                                                  'value': '10.0.0.9'})):
        assert 'FAKE-TREND-PW' not in resp.text


def test_page_has_trend_units_card():
    html = INDEX.read_text(encoding='utf-8')
    assert 'id="trendUnits"' in html and 'id="trendUnitDetail"' in html
    assert re.search(r"^async function loadTrendUnits\(", html, re.MULTILINE)
    assert re.search(r"^function renderTrendUnit\(", html, re.MULTILINE)


def test_report_opened_from_history_keeps_its_id():
    html = INDEX.read_text(encoding='utf-8')
    body = html[html.index('async function openReport('):]
    body = body[:body.index('\n}\n')]
    assert re.search(r'_report_id\s*=\s*id\b', body)


def test_event_points_show_their_observation_label():
    """2d: a log-observation point says how its slice was collected (or that
    collection failed) instead of a bare status."""
    html = INDEX.read_text(encoding='utf-8')
    body = html[html.index('function renderTrendUnit('):]
    body = body[:body.index('\n}\n')]
    assert 'p.observation' in body and '.label' in body


def test_event_points_show_collection_metadata():
    """GPT/Codex review of 2c (pass 1): contract 2d asks for the available
    source/coverage/event counts/limits next to each observation."""
    html = INDEX.read_text(encoding='utf-8')
    body = html[html.index('function renderTrendUnit('):]
    body = body[:body.index('\n}\n')]
    for field in ('source', 'access_coverage', 'error_coverage', 'events_parsed',
                  'events_total', 'requested_lines', 'window_hours'):
        assert field in body, field
