"""
Фоновый сборщик истории трафика. Раз в N секунд опрашивает MikroTik
(тот же connection tracking, что и check_mikrotik_sniffer в checks/capture.py),
оценивает назначения через threat.score_destinations и складывает снимок
в storage.traffic_history — чтобы потом можно было "отмотать назад" и
посмотреть, куда устройство стучалось за прошедший период, а не только
в момент, когда чек был запущен вручную.

Настройки хранятся в общей settings-таблице (ключи с префиксом history_capture_*),
управляются через /api/history_capture/* эндпоинты в web/app.py.

Работает в отдельном daemon-потоке (threading, не asyncio — так же, как и остальной
рантайм проверок в engine.py), стартует/останавливается вместе с процессом веб-сервера.
"""

from __future__ import annotations

import re
import socket
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta

from . import storage, threat

try:
    import paramiko
except ImportError:
    paramiko = None

DEFAULT_INTERVAL_SEC = 60
DEFAULT_RETENTION_HOURS = 24

_watcher_thread: threading.Thread | None = None
_stop_event = threading.Event()
_status_lock = threading.Lock()
_status = {'running': False, 'last_run': None, 'last_error': None, 'snapshots_taken': 0}


def get_settings() -> dict:
    return {
        'enabled': storage.setting_get('history_capture_enabled', 'false') == 'true',
        'router': storage.setting_get('history_capture_router', '192.168.88.1'),
        'user': storage.setting_get('history_capture_user', 'admin'),
        'password': storage.setting_get('history_capture_password', ''),
        'port': int(storage.setting_get('history_capture_port', '22')),
        'target_ip': storage.setting_get('history_capture_target_ip', ''),
        'interval_sec': int(storage.setting_get('history_capture_interval_sec', str(DEFAULT_INTERVAL_SEC))),
        'retention_hours': int(storage.setting_get('history_capture_retention_hours', str(DEFAULT_RETENTION_HOURS))),
    }


def save_settings(s: dict) -> None:
    storage.setting_set('history_capture_enabled', 'true' if s.get('enabled') else 'false')
    if 'router' in s: storage.setting_set('history_capture_router', s['router'])
    if 'user' in s: storage.setting_set('history_capture_user', s['user'])
    if 'password' in s: storage.setting_set('history_capture_password', s['password'])
    if 'port' in s: storage.setting_set('history_capture_port', str(s['port']))
    if 'target_ip' in s: storage.setting_set('history_capture_target_ip', s['target_ip'])
    if 'interval_sec' in s: storage.setting_set('history_capture_interval_sec', str(s['interval_sec']))
    if 'retention_hours' in s: storage.setting_set('history_capture_retention_hours', str(s['retention_hours']))


def get_status() -> dict:
    with _status_lock:
        return dict(_status)


def _take_snapshot(s: dict) -> None:
    """Один снимок connection tracking — идентичная логика check_mikrotik_sniffer,
    но пишет результат в traffic_history вместо возврата в отчёт."""
    if paramiko is None:
        raise RuntimeError('paramiko not installed')
    if not s['target_ip']:
        raise RuntimeError('target_ip not specified')

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=s['router'], port=s['port'], username=s['user'],
                   password=s['password'], timeout=10, look_for_keys=False, allow_agent=False)
    try:
        cmd = f'/ip firewall connection print terse where src-address~"{s["target_ip"]}"'
        _, stdout, stderr = client.exec_command(cmd, timeout=20)
        out = stdout.read().decode(errors='replace')
        err = stderr.read().decode(errors='replace')
    finally:
        client.close()

    if err.strip():
        raise RuntimeError(f'router returned an error: {err.strip()[:300]}')

    by_dst = defaultdict(lambda: {'connections': 0, 'protocols': set(), 'ports': set()})
    for line in out.splitlines():
        dst_m = re.search(r'dst-address=([\d.]+):?(\d+)?', line)
        proto_m = re.search(r'protocol=(\S+)', line)
        if not dst_m:
            continue
        dst_ip = dst_m.group(1)
        dst_port = dst_m.group(2)
        by_dst[dst_ip]['connections'] += 1
        if proto_m:
            by_dst[dst_ip]['protocols'].add(proto_m.group(1))
        if dst_port:
            by_dst[dst_ip]['ports'].add(dst_port)

    dests = [{'ip': ip, 'connections': v['connections'],
              'protocols': sorted(v['protocols']), 'ports': sorted(v['ports'])}
             for ip, v in by_dst.items()]
    if not dests:
        return

    scored = threat.score_destinations(dests, do_whois=False)['scored']

    rows = []
    for d in scored:
        ports = d.get('ports') or ['']
        for port in ports:
            rows.append({
                'ip': d['ip'], 'port': port or None,
                'protocol': (d.get('protocols') or [None])[0],
                'risk_level': d.get('risk_level'), 'risk_score': d.get('risk_score'),
            })
    storage.traffic_history_add(s['target_ip'], rows)


def _watch_loop() -> None:
    while not _stop_event.is_set():
        s = get_settings()
        if not s['enabled']:
            _stop_event.wait(5)
            continue
        try:
            _take_snapshot(s)
            with _status_lock:
                _status['last_run'] = datetime.now().isoformat()
                _status['last_error'] = None
                _status['snapshots_taken'] += 1
        except Exception as e:
            with _status_lock:
                _status['last_run'] = datetime.now().isoformat()
                _status['last_error'] = str(e)[:300]

        # чистка старых записей — раз в проходе, дёшево при индексе на seen_at
        try:
            cutoff = (datetime.now() - timedelta(hours=s['retention_hours'])).isoformat()
            storage.traffic_history_prune(cutoff)
        except Exception:
            pass

        _stop_event.wait(max(10, s['interval_sec']))


def start() -> None:
    """Запускается один раз при старте веб-сервера (см. web/app.py lifespan)."""
    global _watcher_thread
    if _watcher_thread and _watcher_thread.is_alive():
        return
    _stop_event.clear()
    with _status_lock:
        _status['running'] = True
    _watcher_thread = threading.Thread(target=_watch_loop, daemon=True, name='traffic-history-watcher')
    _watcher_thread.start()


def stop() -> None:
    _stop_event.set()
    with _status_lock:
        _status['running'] = False
