"""
A4.2b - docs/research/a4_2b_deprecation_warnings.md: the project's own code
must not use the pydantic v1 `.dict()` API, and the requirements must give
pydantic 2 to the application and httpx2 to starlette's TestClient.

The requirement checks read the files instead of importing httpx2: a test
that needs httpx2 installed would fail wherever only requirements.txt is
installed - deploy.sh (layout B) runs pytest on the server and rolls back
on a failure.
"""

from __future__ import annotations

import re
import warnings
from pathlib import Path

from pydantic.warnings import PydanticDeprecatedSince20

ROOT = Path(__file__).resolve().parent.parent


def _requirements(name: str) -> list[str]:
    lines = (ROOT / name).read_text(encoding='utf-8').splitlines()
    return [line.split('#')[0].strip() for line in lines if line.split('#')[0].strip()]


def test_history_capture_settings_do_not_use_pydantic_v1_api(isolated_db):
    from fastapi.testclient import TestClient

    from web.app import app

    client = TestClient(app)
    with warnings.catch_warnings():
        warnings.simplefilter('error', PydanticDeprecatedSince20)
        resp = client.post('/api/history_capture/settings', json={'target_ip': '192.168.88.10'})
    assert resp.status_code == 200


def test_runtime_requirements_pin_pydantic_2():
    # fastapi>=0.100 alone still allows pydantic v1, which has no model_dump()
    assert any(re.fullmatch(r'pydantic\s*>=\s*2(\.\d+)*', r) for r in _requirements('requirements.txt'))


def test_dev_requirements_give_the_testclient_httpx2():
    # starlette 1.x's TestClient imports httpx2 first and warns on plain httpx
    assert any(re.match(r'httpx2\b', r) for r in _requirements('requirements-dev.txt'))
