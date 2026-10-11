"""
NetAudit FastAPI backend. Smart sync/async, AI analysis, history, settings/presets/targets.
All storage - SQLite via netaudit_pkg.storage.
Run: netaudit.py web  (or uvicorn web.app:app)
"""

from __future__ import annotations

import sys
import threading
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from netaudit_pkg import (
    __version__,
    deployment,
    history_capture,
    hosts,
    storage,
    streaming,
    timing,
    tools,
    trends,
)
from netaudit_pkg.engine import (
    DEFAULT_MAX_PARALLEL,
    MAX_INSTANCES_PER_CHECK,
    PROCESS_MAX_PARALLEL,
    list_available,
    run_checks_multi,
    validate_multi_request,
)
from netaudit_pkg.history import (
    ai_analyze,
    list_reports,
    load_report,
    save_report,
    verify_api_key,
)
from netaudit_pkg.web_auth import BasicAuthMiddleware, ensure_auth_configured


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    # always starts, but only actually does something if enabled=true in
    # settings (see history_capture.get_settings) - otherwise it just sleeps.
    history_capture.start()
    try:
        yield
    finally:
        history_capture.stop()


app = FastAPI(title='NetAudit', version=__version__, lifespan=_lifespan)

# Real process start time - computed once at import (module load = uvicorn
# process start), not per-request. Lets /api/health detect a stale process
# (old service_started_at surviving past a failed restart).
from datetime import UTC, datetime

_SERVICE_STARTED_AT = datetime.now(UTC).isoformat()
STATIC_DIR = Path(__file__).resolve().parent / 'static'

# host is set to its real value in cmd_web() (netaudit.py) before uvicorn starts -
# we read it here from the env var that cmd_web itself sets, since at the time
# this module is imported the host isn't always directly known otherwise.
import os as _os

_WEB_HOST = _os.environ.get('NETAUDIT_WEB_HOST', '127.0.0.1')
ensure_auth_configured(_WEB_HOST)
app.add_middleware(BasicAuthMiddleware, host=_WEB_HOST)

_tasks: dict[str, dict] = {}
_tasks_lock = threading.Lock()


class CheckItem(BaseModel):
    id: str
    params: dict = {}
    instances: list[dict] | None = None


class RunRequest(BaseModel):
    checks: list[CheckItem]
    force_async: bool = False
    max_parallel: int = DEFAULT_MAX_PARALLEL


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


def _per_check_estimate(item: dict, max_parallel: int = DEFAULT_MAX_PARALLEL) -> float:
    """Single-number estimate for one selected item, for the /api/estimate
    per_check breakdown. Instances use the same bounded groups as
    decide_mode(), rather than estimate(id, {}) on empty params."""
    return round(timing.estimate_item(item, max_parallel), 2)


def _execute_task(task_id: str, selected: list[dict], max_parallel: int) -> None:
    try:
        report = run_checks_multi(selected, max_parallel=max_parallel, shared_pool=True)
        rid = save_report(report)
        report['_report_id'] = rid
        with _tasks_lock:
            _tasks[task_id] = {'status': 'done', 'report': report}
    except Exception as e:  # noqa: BLE001 - background task boundary: any failure becomes the task's error status
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
    try:
        validate_multi_request(selected, req.max_parallel)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    effective_parallel = min(req.max_parallel, PROCESS_MAX_PARALLEL)
    mode, est = timing.decide_mode(selected, force_async=req.force_async,
                                   max_parallel=effective_parallel)
    per = {item['id']: _per_check_estimate(item, effective_parallel) for item in selected}
    return {'mode': mode, 'estimate': est, 'per_check': per}


@app.post('/api/run')
def api_run(req: RunRequest) -> dict:
    if not req.checks:
        raise HTTPException(400, 'no checks selected')
    selected = [_to_selected_item(c) for c in req.checks]
    try:
        validate_multi_request(selected, req.max_parallel)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    mode, est = timing.decide_mode(selected, force_async=req.force_async,
                                   max_parallel=min(req.max_parallel, PROCESS_MAX_PARALLEL))

    if mode == 'sync':
        report = run_checks_multi(selected, max_parallel=req.max_parallel, shared_pool=True)
        rid = save_report(report)
        report['_report_id'] = rid
        return {'mode': 'sync', 'estimate': est, 'report': report}

    task_id = uuid.uuid4().hex
    with _tasks_lock:
        _tasks[task_id] = {'status': 'running'}
    threading.Thread(target=_execute_task, args=(task_id, selected, req.max_parallel), daemon=True).start()
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


# --- Trend layer (docs/research/trend_layer_v1_2_web_ai.md, 2c) ---
@app.get('/api/trends')
def api_trends() -> dict:
    """Every object with finding/score history."""
    return {'units': trends.list_units()}


@app.get('/api/trend')
def api_trend(check_id: str = '', key: str = '', value: str = '') -> dict:
    """Trend of one object: points + latest change. Same shape as `netaudit trend --json`."""
    if not (check_id and key and value) or key not in storage.IDENTITY_PARAM_KEYS:
        raise HTTPException(400, 'check_id, key (an identity key) and value are required')
    trend = trends.trend_for(check_id, key, value)
    if trend is None:
        raise HTTPException(404, 'no trend data for this object')
    return trend


# --- AI analysis ---
@app.post('/api/analyze')
def api_analyze(req: AnalyzeRequest) -> dict:
    if req.report is not None:
        report = req.report
        # anchor (2b.1): an explicit report_id, else the DB id a saved run
        # carries (/api/run, the stream, a report opened from history),
        # else the report's timestamp
        posted_id = report.get('_report_id')
        report_id = (req.report_id if req.report_id is not None
                     else posted_id if type(posted_id) is int else None)
    elif req.report_id is not None:
        report = load_report(req.report_id)
        if report is None:
            raise HTTPException(404, 'report not found')
        report_id = req.report_id
    else:
        raise HTTPException(400, 'report or report_id is required')
    related = storage.find_related_reports(report, limit=3, report_id=report_id)
    return ai_analyze(report, language=req.language, history=related,
                      trends=trends.trend_context(report, report_id=report_id))


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


# --- Saved SSH hosts (B2.3) ---
@app.get('/api/hosts')
def api_hosts() -> list[dict]:
    return storage.ssh_hosts_list()


@app.post('/api/hosts/validate-selection')
async def api_validate_host_selection(request: Request) -> dict:
    """Refuse ambiguous saved-host picks using the same identity as the CLI.
    Only integer IDs cross this boundary; stored host strings stay unchanged
    for SSH host-key lookup.
    """
    try:
        payload = await request.json()
    except ValueError:
        raise HTTPException(400, 'ids must be a JSON array of saved host IDs') from None
    ids = payload.get('ids') if isinstance(payload, dict) else None
    if (not isinstance(ids, list) or not ids or len(ids) > MAX_INSTANCES_PER_CHECK
            or any(type(host_id) is not int or host_id <= 0 for host_id in ids)):
        raise HTTPException(400, f'ids must be a JSON array of 1-{MAX_INSTANCES_PER_CHECK} saved host IDs')
    by_id = {row['id']: row for row in storage.ssh_hosts_list()}
    seen_ids = set()
    seen_hosts = set()
    for host_id in ids:
        if host_id in seen_ids or host_id not in by_id:
            raise HTTPException(400, 'ids must name distinct saved hosts')
        seen_ids.add(host_id)
        identity = hosts.host_identity(by_id[host_id]['host'])
        if identity in seen_hosts:
            raise HTTPException(409, {'duplicate_id': host_id})
        seen_hosts.add(identity)
    return {'ok': True}


@app.post('/api/hosts')
async def api_add_host(request: Request) -> dict:
    # a raw JSON body, not a pydantic model: FastAPI's 422 echoes the submitted
    # input back, and a password sent here by mistake must not come back
    try:
        payload = await request.json()
    except ValueError:
        raise HTTPException(400, 'the body must be a JSON object') from None
    if not isinstance(payload, dict):
        raise HTTPException(400, 'the body must be a JSON object')
    record = dict(payload)
    label = record.pop('label', '')
    try:
        host_id = storage.ssh_host_add(record, label=label)
    except hosts.HostRecordError as e:
        # The shared CLI validator may quote an invalid value. Keep the Web
        # boundary field-only, even when a secret was pasted into user/host.
        reason = str(e)
        field = next((name for name in ('host', 'user', 'port', 'key_path', 'label',
                                        'password', 'sudo_password')
                      if reason.startswith((name + ' ', name + ':'))), None)
        detail = (f'{field}: invalid value' if field else
                  'unknown field; allowed: host, user, port, key_path, label'
                  if reason.startswith('unknown field') else 'invalid host record')
        raise HTTPException(400, detail) from None
    return {'ok': True, 'id': host_id}


@app.delete('/api/hosts/{host_id}')
def api_delete_host(host_id: int) -> dict:
    storage.ssh_host_delete(host_id)
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
import queue
import uuid as _uuid

_stream_tasks: dict[str, streaming.StreamTask] = {}
_stream_lock = threading.Lock()


@app.post('/api/stream/start')
def api_stream_start(req: RunRequest) -> dict:
    if not req.checks:
        raise HTTPException(400, 'no checks selected')
    selected = [_to_selected_item(c) for c in req.checks]
    try:
        validate_multi_request(selected, req.max_parallel)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    task_id = _uuid.uuid4().hex
    task = streaming.StreamTask(task_id, selected, max_parallel=req.max_parallel)
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
            except queue.Empty:
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
    data = {k: v for k, v in req.model_dump().items() if v is not None}
    try:
        history_capture.save_settings(data)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    return {'ok': True}


@app.get('/api/history_capture/status')
def api_history_capture_status() -> dict:
    return history_capture.get_status()


@app.get('/api/history_capture/query')
def api_history_capture_query(target_ip: str, hours: float = 1.0) -> dict:
    from datetime import datetime, timedelta
    # naive local time on purpose: storage.traffic_history_add() stores seen_at that way
    since = (datetime.now() - timedelta(hours=hours)).isoformat()  # noqa: DTZ005
    rows = storage.traffic_history_query(target_ip, since)
    return {'target_ip': target_ip, 'since': since, 'total': len(rows), 'rows': rows}


if STATIC_DIR.exists():
    app.mount('/static', StaticFiles(directory=str(STATIC_DIR)), name='static')
