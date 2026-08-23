"""
Tests for netaudit_pkg/deployment.py: read_manifest().

read_manifest() parses the KEY=VALUE .deployed_manifest file written by
deploy.sh (two lines: DEPLOYED_COMMIT=..., DEPLOYED_AT=...) and returns a
dict with 'commit' and 'deployed_at' keys. It must never raise - if the
manifest is missing (e.g. before the first deploy.sh run, or on a desktop
checkout that was never deployed), it returns {'commit': None,
'deployed_at': None} instead.
"""
from __future__ import annotations

from netaudit_pkg import deployment


def test_read_manifest_parses_existing_file(tmp_path):
    manifest = tmp_path / '.deployed_manifest'
    manifest.write_text('DEPLOYED_COMMIT=a3767d7\nDEPLOYED_AT=2026-08-23T10:00:00Z\n')
    result = deployment.read_manifest(manifest_path=str(manifest))
    assert result == {'commit': 'a3767d7', 'deployed_at': '2026-08-23T10:00:00Z'}


def test_read_manifest_missing_file_returns_none_values(tmp_path):
    missing = tmp_path / 'does_not_exist' / '.deployed_manifest'
    result = deployment.read_manifest(manifest_path=str(missing))
    assert result == {'commit': None, 'deployed_at': None}


def test_read_manifest_handles_trailing_whitespace_and_blank_lines(tmp_path):
    manifest = tmp_path / '.deployed_manifest'
    manifest.write_text('DEPLOYED_COMMIT=a3767d7  \n\nDEPLOYED_AT=2026-08-23T10:00:00Z\n')
    result = deployment.read_manifest(manifest_path=str(manifest))
    assert result == {'commit': 'a3767d7', 'deployed_at': '2026-08-23T10:00:00Z'}


def test_read_manifest_default_path_uses_home_netaudit(monkeypatch, tmp_path):
    """With no manifest_path given, read_manifest() must default to
    ~/netaudit/.deployed_manifest (RUNTIME_DIR in deploy.sh), not the CWD or
    the git checkout dir - those can diverge (see ~/netaudit vs
    ~/netaudit-git in project methodology)."""
    monkeypatch.setenv('HOME', str(tmp_path))
    runtime_dir = tmp_path / 'netaudit'
    runtime_dir.mkdir()
    (runtime_dir / '.deployed_manifest').write_text('DEPLOYED_COMMIT=deadbee\nDEPLOYED_AT=2026-01-01T00:00:00Z\n')
    result = deployment.read_manifest()
    assert result == {'commit': 'deadbee', 'deployed_at': '2026-01-01T00:00:00Z'}


def test_read_manifest_ignores_unknown_keys(tmp_path):
    manifest = tmp_path / '.deployed_manifest'
    manifest.write_text('DEPLOYED_COMMIT=a3767d7\nDEPLOYED_AT=2026-08-23T10:00:00Z\nSOME_OTHER_KEY=ignored\n')
    result = deployment.read_manifest(manifest_path=str(manifest))
    assert result == {'commit': 'a3767d7', 'deployed_at': '2026-08-23T10:00:00Z'}


def test_read_manifest_partial_file_missing_deployed_at(tmp_path):
    manifest = tmp_path / '.deployed_manifest'
    manifest.write_text('DEPLOYED_COMMIT=a3767d7\n')
    result = deployment.read_manifest(manifest_path=str(manifest))
    assert result == {'commit': 'a3767d7', 'deployed_at': None}
