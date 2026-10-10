# pytest deprecation warnings: pydantic `.dict()`, httpx TestClient (A4.2b)

Status: USER approved (2026-10-10: A4.2 «Сейчас, всё», pydantic together with
pinning its version in `requirements.txt`). Implementer: Claude. Reviewer:
GPT/Codex.

## Evidence

pytest on `main` `6203c75` (fresh venv from `requirements*.txt`: fastapi
0.143.0, pydantic 2.14.0, starlette 1.7.0, httpx 0.28.1) prints two
warnings that do not come from the tests:

1. `web/app.py:502` `api_history_capture_settings_set()` calls `req.dict()` →
   `PydanticDeprecatedSince20` (removed in Pydantic V3). `requirements.txt`
   pins only `fastapi>=0.100`, which still allows pydantic v1, where
   `model_dump()` does not exist.
2. `fastapi.testclient` → `StarletteDeprecationWarning: Using httpx with
   starlette.testclient is deprecated; install httpx2 instead`. Starlette
   1.7.0 imports `httpx2` first and falls back to `httpx` with this warning.
   Its own metadata lists `httpx2>=2.0.0` for the TestClient. `httpx2` is
   maintained by Pydantic Services (github.com/pydantic/httpx2, author Tom
   Christie), `requires_python >=3.10`.

## Design

1. `req.dict()` → `req.model_dump()`. `requirements.txt` and package metadata
   in `pyproject.toml` gain `pydantic>=2.0`. FastAPI ≥ 0.100 allowed pydantic
   v1, so the bound is what guarantees `model_dump()` for both `pip install
   -r requirements.txt` and `pip install .`. Nothing else uses the v1 API
   (grep: `.dict(`, `parse_obj`, `class Config`, validators).
2. `requirements-dev.txt` and `pyproject.toml`'s dev extra gain `httpx2>=2.0`
   (tests only). The application
   keeps `httpx` in `requirements.txt`: `history.py` and the checks use it at
   runtime. Tests that patch `httpx` for the application are unaffected,
   because the TestClient no longer goes through that module.
3. No global `filterwarnings = error`: dependencies are not pinned, and a new
   upstream deprecation would turn CI red without a code change. The guards
   target these two warnings only.

## Tests (RED first)

1. Posting to `/api/history_capture/settings` with
   `PydanticDeprecatedSince20` as an error succeeds (fails today).
2. `requirements.txt` has `pydantic>=2…` and `requirements-dev.txt` has
   `httpx2` (both fail today). The check reads the files and does **not**
   import `httpx2`. A test that needs `httpx2` installed would fail in any
   environment without the new dev requirements, including `deploy.sh`
   (layout B), which runs pytest on the server, and `install.sh`, which
   installs only `requirements.txt`. A failed test there means a rollback.
3. The same bounds exist in `pyproject.toml`'s runtime and dev dependencies;
   `pip install .` and `pip install -e .[dev]` otherwise bypass the text
   requirements. RED for these two paths was added after reviewer pass 1.

Verification: full pytest with no warnings from these two sources; full
Ruff; bandit; `pip-audit -r requirements.txt` and `-r requirements-dev.txt`.
