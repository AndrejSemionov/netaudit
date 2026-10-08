"""
One version for 1.0: pyproject.toml, the package, the CLI banner/--version and
the web app's OpenAPI version must agree (the web app used to say 2.0 while
the CLI said 0.2.0). netaudit_pkg.__version__ is the single source in code.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

import netaudit
import netaudit_pkg
from web.app import app

PYPROJECT = Path(__file__).resolve().parent.parent / 'pyproject.toml'


def test_package_version_matches_pyproject():
    project = tomllib.loads(PYPROJECT.read_text(encoding='utf-8'))['project']
    assert netaudit_pkg.__version__ == project['version']


def test_cli_and_web_use_the_package_version():
    assert netaudit.__version__ == netaudit_pkg.__version__
    assert app.version == netaudit_pkg.__version__


def test_cli_version_flag(capsys, monkeypatch):
    monkeypatch.setattr('sys.argv', ['netaudit', '--version'])
    with pytest.raises(SystemExit) as exc:
        netaudit.main()
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f'netaudit {netaudit_pkg.__version__}'
