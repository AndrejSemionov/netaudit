"""
NetAudit FastAPI backend. Smart sync/async, AI analysis, history, settings/presets/targets.
All storage - SQLite via netaudit_pkg.storage.
Run: netaudit.py web  (or uvicorn web.app:app)
"""

from __future__ import annotations

import sys
import threading
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from netaudit_pkg.engine import list_available, run_checks_multi
from netaudit_pkg.history import save_report, list_reports, load_report, ai_analyze, verify_api_key
from netaudit_pkg import timing, storage, tools
from netaudit_pkg import streaming
from netaudit_pkg import history_capture
from netaudit_pkg import deployment
from netaudit_pkg.web_auth import BasicAuthMiddleware, ensure_auth_configured

app = FastAPI(title='NetAudit', version='2.0')

# Real process start time - computed once at import (module load = uvicorn
# process start), not per-request. Lets /api/health detect a stale process
# (old service_started_at surviving past a failed restart).
from datetime import datetime, timezone as _timezone
_SERVICE_STARTED_AT = datetime.now(_timezone.utc).isoformat()
STATIC_DIR = Path(__file__).resolve().parent / 'static'

# host is set to its real value in cmd_web() (netaudit.py) before uvicorn starts -
# we read it here from the env var that cmd_web itself sets, since at the time
# this module is imported the host isn't always directly known otherwise.
import os as _os
_WEB_HOST = _os.environ.get('NETAUDIT_WEB_HOST', '127.0.0.1')
ensure_auth_configured(_WEB_HOST)
app.add_middleware(BasicAuthMiddleware, host=_WEB_HOST)


@app.on_event('startup')
def _start_history_watcher() -> None:
    # always starts, but only actually does something if enabled=true in
    # settings (see history_capture.get_settings) - otherwise it just sleeps.
    history_capture.start()

_tasks: dict[str, dict] = {}
_tasks_lock = threading.Lock()


class CheckItem(BaseModel):
    id: str
    params: dict = {}
    instances: list[dict] | None = None


class RunRequest(BaseModel):
    checks: list[CheckItem]
    force_async: bool = False


class AnalyzeRequest(BaseModel):
    report_id: int | None = None
    report: dict | None = None
    language: str | None = None  # 'en' / 'ru' - overrides the ai_language setting for this call


class SettingsRequest(BaseModel):
    settings: dict


class VerifyKeyRequest(BaseModel):
    api_key: str


class WebAuthRequest(BaseModel):
    user: str
    password: str


class PresetRequest(BaseModel):
    name: str
    checks: list[CheckItem]


class TargetRequest(BaseModel):
    value: str
    label: str = ''
    kind: str = 'ip'


class InstallToolRequest(BaseModel):
    tool: str


class RepListRequest(BaseModel):
    pattern: str
    list_type: str  # 'allow' | 'block'
    note: str = ''


def _to_selected_item(c: CheckItem) -> dict:
    """CheckItem -> engine.run_checks_multi()/timing.decide_mode() item shape.
    'instances' (multi-host) takes precedence when set; otherwise falls back
    to the legacy flat 'params' form, unchanged."""
    if c.instances is not None:
        return {'id': c.id, 'instances': c.instances}
    return {'id': c.id, 'params': c.params}


def _per_check_estimate(item: dict) -> float:
    """Single-number estimate for one selected item, for the /api/estimate
    per_check breakdown. For 'instances' items this is the max across
    instances (mirrors decide_mode()'s own per-check contribution) rather
    than a misleading estimate(id, {}) on empty params."""
    if 'instances' in item:
        estimates = [timing.estimate(item['id'], inst) for inst in item['instances']]
        return round(max(estimates), 2) if estimates else 0.0
    return round(timing.estimate(item['id'], item.get('params', {})), 2)


def _execute_task(task_id: str, selected: list[dict]) -> None:
    try:
        report = run_checks_multi(selected)
        rid = save_report(report)
        report['_report_id'] = rid
        with _tasks_lock:
            _tasks[task_id] = {'status': 'done', 'report': report}
    except Exception as e:
        with _tasks_lock:
            _tasks[task_id] = {'status': 'error', 'error': f'{type(e).__name__}: {e}'}


# --- Page ---
@app.get('/', response_class=HTMLResponse)
def index() -> str:
    return (STATIC_DIR / 'index.html').read_text(encoding='utf-8')


# --- Checks ---
@app.get('/api/checks')
def api_checks() -> list[dict]:
    return list_available()


# --- Health / version ---
@app.get('/api/health')
def api_health() -> dict:
    manifest = deployment.read_manifest()
    return {
        'status': 'ok',
        'service_started_at': _SERVICE_STARTED_AT,
        'version': {
            'commit': manifest['commit'],
            'deployed_at': manifest['deployed_at'],
        },
    }


@app.get('/api/version')
def api_version() -> dict:
    manifest = deployment.read_manifest()
    return {
        'commit': manifest['commit'],
        'deployed_at': manifest['deployed_at'],
        'service_started_at': _SERVICE_STARTED_AT,
    }


@app.post('/api/estimate')
def api_estimate(req: RunRequest) -> dict:
    selected = [_to_selected_item(c) for c in req.checks]
    mode, est = timing.decide_mode(selected, force_async=req.force_async)
    per = {item['id']: _per_check_estimate(item) for item in selected}
    return {'mode': mode, 'estimate': est, 'per_check': per}


@app.post('/api/run')
def api_run(req: RunRequest) -> dict:
    if not req.checks:
        raise HTTPException(400, 'no checks selected')
    selected = [_to_selected_item(c) for c in req.checks]
    mode, est = timing.decide_mode(selected, force_async=req.force_async)

    if mode == 'sync':
        report = run_checks_multi(selected)
        rid = save_report(report)
        report['_report_id'] = rid
        return {'mode': 'sync', 'estimate': est, 'report': report}

    task_id = uuid.uuid4().hex
    with _tasks_lock:
        _tasks[task_id] = {'status': 'running'}
    threading.Thread(target=_execute_task, args=(task_id, selected), daemon=True).start()
    return {'mode': 'async', 'estimate': est, 'task_id': task_id}


@app.get('/api/status/{task_id}')
def api_status(task_id: str) -> dict:
    with _tasks_lock:
        task = _tasks.get(task_id)
    if task is None:
        raise HTTPException(404, 'task not found')
    return task


# --- History ---
@app.get('/api/history')
def api_history() -> list[dict]:
    return list_reports()


@app.get('/api/report')
def api_report(id: int) -> dict:
    r = load_report(id)
    if r is None:
        raise HTTPException(404, 'report not found')
    return r


@app.get('/api/timeseries/mtr')
def api_timeseries_mtr(target: str) -> dict:
    """mtr loss trend for a target over time - for the chart."""
    return {'target': target, 'points': storage.timeseries_mtr_loss(target)}


@app.get('/api/timeseries/targets')
def api_timeseries_targets() -> list[str]:
    """Targets that have mtr history."""
    return storage.distinct_mtr_targets()


# --- AI analysis ---
@app.post('/api/analyze')
def api_analyze(req: AnalyzeRequest) -> dict:
    if req.report is not None:
        report = req.report
    elif req.report_id is not None:
        report = load_report(req.report_id)
        if report is None:
            raise HTTPException(404, 'report not found')
    else:
        raise HTTPException(400, 'report or report_id is required')
    related = storage.find_related_reports(report, limit=3)
    return ai_analyze(report, language=req.language, history=related)


# --- Settings ---
# keys never sent back to the frontend in the clear
SECRET_KEYS = {'anthropic_api_key', 'telegram_token', 'hibp_api_key'}


@app.get('/api/settings')
def api_get_settings() -> dict:
    """Returns settings. Secrets are masked - only a set/not-set flag."""
    raw = storage.settings_all()
    out = {}
    for k, v in raw.items():
        if k in SECRET_KEYS:
            out[k] = {'set': bool(v)}  # never return the actual value
        else:
            out[k] = v
    # defaults, if not set
    out.setdefault('sync_threshold_sec', str(timing.DEFAULT_SYNC_THRESHOLD_SEC))
    out.setdefault('ema_alpha', str(timing.DEFAULT_EMA_ALPHA))
    from netaudit_pkg.history import DEFAULT_AI_LANGUAGE
    out.setdefault('ai_language', DEFAULT_AI_LANGUAGE)
    out['web_auth_user'] = storage.setting_get('web_auth_user') or ''
    out['web_auth_configured'] = bool(storage.setting_get('web_auth_password_hash'))
    return out


@app.post('/api/settings')
def api_set_settings(req: SettingsRequest) -> dict:
    """Saves settings. Empty secret values are ignored (to avoid wiping them out)."""
    for k, v in req.settings.items():
        if k in SECRET_KEYS and (v is None or v == ''):
            continue  # don't overwrite a secret with an empty value
        storage.setting_set(k, str(v))
    return {'ok': True}


@app.post('/api/settings/verify-key')
def api_verify_key(req: VerifyKeyRequest) -> dict:
    return verify_api_key(req.api_key)


@app.post('/api/settings/web-auth')
def api_set_web_auth(req: WebAuthRequest) -> dict:
    """Changes the built-in Basic Auth login/password (see netaudit_pkg/web_auth.py).
    Always available, even if the server is currently running on localhost - so
    credentials can be prepared ahead of time, before switching to 0.0.0.0."""
    if not req.user or not req.password:
        raise HTTPException(400, 'user and password are required')
    if len(req.password) < 8:
        raise HTTPException(400, 'password must be at least 8 characters')
    from netaudit_pkg.web_auth import _hash_password
    storage.setting_set('web_auth_user', req.user)
    storage.setting_set('web_auth_password_hash', _hash_password(req.password))
    return {'ok': True}


# --- Presets ---
@app.get('/api/presets')
def api_presets() -> list[dict]:
    return storage.presets_list()


@app.post('/api/presets')
def api_save_preset(req: PresetRequest) -> dict:
    checks = [_to_selected_item(c) for c in req.checks]
    pid = storage.preset_save(req.name, checks)
    return {'ok': True, 'id': pid}


@app.delete('/api/presets/{preset_id}')
def api_delete_preset(preset_id: int) -> dict:
    storage.preset_delete(preset_id)
    return {'ok': True}


# --- Default targets ---
@app.get('/api/targets')
def api_targets() -> list[dict]:
    return storage.targets_list()


@app.post('/api/targets')
def api_add_target(req: TargetRequest) -> dict:
    tid = storage.target_add(req.value, req.label, req.kind)
    return {'ok': True, 'id': tid}


@app.delete('/api/targets/{target_id}')
def api_delete_target(target_id: int) -> dict:
    storage.target_delete(target_id)
    return {'ok': True}


# --- Tools ---
@app.get('/api/tools')
def api_tools() -> list[dict]:
    return tools.tools_status()


@app.post('/api/tools/install')
def api_install_tool(req: InstallToolRequest) -> dict:
    return tools.install_tool(req.tool)


# --- Reputation lists (allow/block) ---
@app.get('/api/reputation')
def api_reputation(list_type: str = '') -> list[dict]:
    return storage.rep_list(list_type or None)


@app.post('/api/reputation')
def api_add_reputation(req: RepListRequest) -> dict:
    if req.list_type not in ('allow', 'block'):
        raise HTTPException(400, 'list_type must be allow or block')
    rid = storage.rep_add(req.pattern, req.list_type, req.note)
    return {'ok': True, 'id': rid}


@app.delete('/api/reputation/{rep_id}')
def api_delete_reputation(rep_id: int) -> dict:
    storage.rep_delete(rep_id)
    return {'ok': True}


# --- Streaming execution (live chart + stop) ---
import asyncio
import json as _json
import uuid as _uuid

_stream_tasks: dict[str, streaming.StreamTask] = {}
_stream_lock = threading.Lock()


@app.post('/api/stream/start')
def api_stream_start(req: RunRequest) -> dict:
    if not req.checks:
        raise HTTPException(400, 'no checks selected')
    selected = [_to_selected_item(c) for c in req.checks]
    task_id = _uuid.uuid4().hex
    task = streaming.StreamTask(task_id, selected)
    with _stream_lock:
        _stream_tasks[task_id] = task
    threading.Thread(target=streaming.run_stream, args=(task,), daemon=True).start()
    return {'task_id': task_id}


@app.get('/api/stream/{task_id}')
async def api_stream(task_id: str):
    with _stream_lock:
        task = _stream_tasks.get(task_id)
    if task is None:
        raise HTTPException(404, 'task not found')

    async def event_gen():
        while True:
            try:
                event = await asyncio.to_thread(task.q.get, True, 30)
            except Exception:
                # queue timeout - a heartbeat so the connection doesn't drop
                yield ': keep-alive\n\n'
                continue
            if event.get('type') == '_end':
                break
            yield f'data: {_json.dumps(event, ensure_ascii=False)}\n\n'
        # clean up the task once it's finished
        with _stream_lock:
            _stream_tasks.pop(task_id, None)

    return StreamingResponse(event_gen(), media_type='text/event-stream',
                             headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.post('/api/stream/{task_id}/stop')
def api_stream_stop(task_id: str) -> dict:
    with _stream_lock:
        task = _stream_tasks.get(task_id)
    if task is None:
        raise HTTPException(404, 'task not found or already finished')
    task.stop()
    return {'ok': True}


class HistoryCaptureSettingsRequest(BaseModel):
    enabled: bool | None = None
    router: str | None = None
    user: str | None = None
    password: str | None = None
    port: int | None = None
    target_ip: str | None = None
    interval_sec: int | None = None
    retention_hours: int | None = None


@app.get('/api/history_capture/settings')
def api_history_capture_settings_get() -> dict:
    s = history_capture.get_settings()
    s.pop('password', None)  # never return the password to the frontend
    return s


@app.post('/api/history_capture/settings')
def api_history_capture_settings_set(req: HistoryCaptureSettingsRequest) -> dict:
    data = {k: v for k, v in req.dict().items() if v is not None}
    history_capture.save_settings(data)
    return {'ok': True}


@app.get('/api/history_capture/status')
def api_history_capture_status() -> dict:
    return history_capture.get_status()


@app.get('/api/history_capture/query')
def api_history_capture_query(target_ip: str, hours: float = 1.0) -> dict:
    from datetime import datetime, timedelta
    since = (datetime.now() - timedelta(hours=hours)).isoformat()
    rows = storage.traffic_history_query(target_ip, since)
    return {'target_ip': target_ip, 'since': since, 'total': len(rows), 'rows': rows}


if STATIC_DIR.exists():
    app.mount('/static', StaticFiles(directory=str(STATIC_DIR)), name='static')
