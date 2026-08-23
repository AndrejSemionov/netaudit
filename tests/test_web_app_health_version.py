"""
RED tests for GET /api/health and GET /api/version (web/app.py).

Contract:
  GET /api/health  -> {"status": "ok", "service_started_at": <iso8601>,
                        "version": {"commit": <str|null>, "deployed_at": <iso8601|null>}}
  GET /api/version -> {"commit": <str|null>, "deployed_at": <iso8601|null>,
                        "service_started_at": <iso8601>}

Both routes must return 200 even when .deployed_manifest is missing (e.g. on
a fresh VM before the first deploy.sh run) - commit/deployed_at are null in
that case rather than raising. service_started_at reflects the real import
time of web/app.py (module-level, computed once at process start), not the
manifest's deployed_at.

These tests import the real `app` object exactly like the rest of
tests/test_web_app.py - append this content into that file (or a new
tests/test_web_app_health_version.py) rather than running standalone, so
fixtures/imports match project convention.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from web.app import app


@pytest.fixture
def client():
    return TestClient(app)


def test_health_endpoint_exists_and_returns_200(client):
    resp = client.get('/api/health')
    assert resp.status_code == 200


def test_health_response_shape(client):
    resp = client.get('/api/health')
    data = resp.json()
    assert data['status'] == 'ok'
    assert 'service_started_at' in data
    assert 'version' in data
    assert 'commit' in data['version']
    assert 'deployed_at' in data['version']


def test_version_endpoint_exists_and_returns_200(client):
    resp = client.get('/api/version')
    assert resp.status_code == 200


def test_version_response_shape(client):
    resp = client.get('/api/version')
    data = resp.json()
    assert 'commit' in data
    assert 'deployed_at' in data
    assert 'service_started_at' in data


def test_health_and_version_service_started_at_match(client):
    """Same process -> same service_started_at on both endpoints (it's a
    module-level constant, not recomputed per-request)."""
    health = client.get('/api/health').json()
    version = client.get('/api/version').json()
    assert health['service_started_at'] == version['service_started_at']


def test_health_and_version_commit_match(client):
    health = client.get('/api/health').json()
    version = client.get('/api/version').json()
    assert health['version']['commit'] == version['commit']
    assert health['version']['deployed_at'] == version['deployed_at']
