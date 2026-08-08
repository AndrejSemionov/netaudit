"""
Streaming engine: runs checks while emitting intermediate results in real time
(for the live chart), and supports early cancellation.

Model:
  - mtr/ping/tcptraceroute checks stream over time - read output line by line (Popen),
    parse incrementally, and emit points as they arrive.
  - Other checks run through the regular engine and return a single result at the end.
  - Any check can be stopped (kill the process / cancellation flag).

Events (pushed into the task queue, read by the SSE endpoint):
  check_start / point / check_done / all_done / error / stopped
"""

from __future__ import annotations

import queue
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime

from .registry import registry
from .utils import log
from . import checks  # noqa: F401 - registration
from . import timing, storage

# Checks with a live stream: id -> (command builder, incremental line parser)
STREAMING_IDS = {'mtr', 'ping', 'tcptraceroute'}


def _mtr_cmd(params):
    target = params.get('target', '8.8.8.8')
    duration = float(params.get('duration_sec', 15))
    if duration <= 60:
        interval = 1.0
    elif duration <= 600:
        interval = 5.0
    elif duration <= 3600:
        interval = 15.0
    else:
        interval = 30.0
    count = max(1, round(duration / interval))
    # --raw gives a machine-readable line stream as pings happen (vs -r report - final only)
    return ['mtr', '--raw', '-n', '-c', str(count), '-i', str(interval), target], count


def _ping_cmd(params):
    target = params.get('target', '8.8.8.8')
    count = int(params.get('count', 10))
    return ['ping', '-c', str(count), '-i', '1', target], count


def _tcptr_cmd(params):
    target = params.get('target', '8.8.8.8')
    port = int(params.get('port', 80))
    max_hops = int(params.get('max_hops', 8))
    return ['tcptraceroute', '-n', '-m', str(max_hops), '-w', '2', target, str(port)], max_hops


class StreamTask:
    def __init__(self, task_id, selected):
        self.id = task_id
        self.selected = selected
        self.q: queue.Queue = queue.Queue()
        self.process: subprocess.Popen | None = None
        self.cancelled = threading.Event()
        self.status = 'running'

    def emit(self, event: dict):
        self.q.put(event)

    def stop(self):
        self.cancelled.set()
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                time.sleep(0.3)
                if self.process.poll() is None:
                    self.process.kill()
            except (ProcessLookupError, OSError):
                pass


def _stream_mtr(task, params, out_lines):
    """Reads mtr --raw line by line, emits per-hop latency points."""
    cmd, count = _mtr_cmd(params)
    if not shutil.which('mtr'):
        task.emit({'type': 'error', 'message': 'mtr is not installed'})
        return
    hosts = {}
    task.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for line in task.process.stdout:
        if task.cancelled.is_set():
            break
        out_lines.append(line)
        parts = line.split()
        if len(parts) >= 3 and parts[0] == 'h':
            hosts[parts[1]] = parts[2]
        elif len(parts) >= 3 and parts[0] == 'p':
            idx = parts[1]
            try:
                usec = float(parts[2])
            except ValueError:
                continue
            task.emit({'type': 'point', 'check': 'mtr',
                       'hop': int(idx), 'host': hosts.get(idx, f'hop{idx}'),
                       'ms': round(usec / 1000, 2), 't': time.time()})
    task.process.wait()


def _stream_ping(task, params, out_lines):
    cmd, count = _ping_cmd(params)
    if not shutil.which('ping'):
        task.emit({'type': 'error', 'message': 'ping not found'})
        return
    task.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    seq = 0
    for line in task.process.stdout:
        if task.cancelled.is_set():
            break
        out_lines.append(line)
        m = re.search(r'icmp_seq=(\d+).*time=([\d.]+)\s*ms', line)
        if m:
            seq = int(m.group(1))
            task.emit({'type': 'point', 'check': 'ping',
                       'seq': seq, 'ms': float(m.group(2)), 't': time.time()})
    task.process.wait()


def _stream_tcptr(task, params, out_lines):
    cmd, max_hops = _tcptr_cmd(params)
    if not shutil.which('tcptraceroute'):
        task.emit({'type': 'error', 'message': 'tcptraceroute is not installed'})
        return
    task.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for line in task.process.stdout:
        if task.cancelled.is_set():
            break
        out_lines.append(line)
        m = re.match(r'\s*(\d+)\s+(\S+)\s+([\d.]+)\s*ms', line)
        if m:
            task.emit({'type': 'point', 'check': 'tcptraceroute',
                       'hop': int(m.group(1)), 'host': m.group(2), 'ms': float(m.group(3)),
                       't': time.time()})
        elif re.match(r'\s*\d+\s+\*', line):
            hop_m = re.match(r'\s*(\d+)\s+\*', line)
            if hop_m:
                task.emit({'type': 'point', 'check': 'tcptraceroute',
                           'hop': int(hop_m.group(1)), 'host': '* (no response)', 'ms': None,
                           't': time.time()})
    task.process.wait()


STREAM_FUNCS = {'mtr': _stream_mtr, 'ping': _stream_ping, 'tcptraceroute': _stream_tcptr}


def run_stream(task: StreamTask):
    """Runs all selected checks, emitting events into the task queue."""
    report = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'results': {}, 'timing': {}, 'meta': {},
    }
    try:
        for item in task.selected:
            if task.cancelled.is_set():
                break
            check_id = item['id']
            params = item.get('params', {})
            spec = registry.get(check_id)
            if spec is None:
                report['results'][check_id] = {'error': 'check not found'}
                continue

            task.emit({'type': 'check_start', 'id': check_id,
                       'label': spec.label, 'streaming': check_id in STREAMING_IDS})
            start = time.monotonic()

            if check_id in STREAM_FUNCS:
                # live stream + a final parse of the full output by the regular parser
                out_lines: list[str] = []
                try:
                    STREAM_FUNCS[check_id](task, params, out_lines)
                except Exception as e:
                    report['results'][check_id] = {'error': f'{type(e).__name__}: {e}'}
                    task.emit({'type': 'check_done', 'id': check_id,
                               'result': report['results'][check_id]})
                    continue
                # final authoritative result via the regular check function
                # (full report with loss etc), if not cancelled
                if not task.cancelled.is_set():
                    try:
                        result = spec.func(**params)
                    except Exception as e:
                        result = {'error': f'{type(e).__name__}: {e}'}
                else:
                    result = _partial_from_lines(check_id, out_lines)
                    result['stopped'] = True
            else:
                # regular (instant/non-streaming) check
                try:
                    result = spec.func(**params)
                except Exception as e:
                    result = {'error': f'{type(e).__name__}: {e}'}

            elapsed = round(time.monotonic() - start, 2)
            if not (isinstance(result, dict) and result.get('error')):
                try:
                    timing.record(check_id, params, elapsed)
                except Exception:
                    pass
            report['results'][check_id] = result
            report['timing'][check_id] = elapsed
            report['meta'][check_id] = {'label': spec.label, 'category': spec.category}
            task.emit({'type': 'check_done', 'id': check_id, 'result': result, 'elapsed': elapsed})

        report['total_time'] = round(sum(report['timing'].values()), 2)
        try:
            rid = storage.save_report(report)
            report['_report_id'] = rid
        except Exception as e:
            log.error(f'save_report: {e}')

        if task.cancelled.is_set():
            task.status = 'stopped'
            task.emit({'type': 'stopped', 'report': report})
        else:
            task.status = 'done'
            task.emit({'type': 'all_done', 'report': report})
    except Exception as e:
        task.status = 'error'
        task.emit({'type': 'error', 'message': f'{type(e).__name__}: {e}'})
    finally:
        task.emit({'type': '_end'})  # SSE stream close marker


def _partial_from_lines(check_id, lines):
    """Builds a structured partial result from the lines received so far, on cancellation."""
    text = ''.join(lines)
    if check_id == 'mtr':
        # aggregate raw 'p' lines per hop: average/worst latency, count
        hosts, stats = {}, {}
        for line in lines:
            parts = line.split()
            if len(parts) >= 3 and parts[0] == 'h':
                hosts[parts[1]] = parts[2]
            elif len(parts) >= 3 and parts[0] == 'p':
                idx = parts[1]
                try:
                    ms = float(parts[2]) / 1000
                except ValueError:
                    continue
                s = stats.setdefault(idx, {'count': 0, 'sum': 0.0, 'worst': 0.0})
                s['count'] += 1
                s['sum'] += ms
                s['worst'] = max(s['worst'], ms)
        hops = []
        for idx in sorted(stats, key=lambda x: int(x)):
            s = stats[idx]
            hops.append({
                'hop': int(idx), 'host': hosts.get(idx, f'hop{idx}'),
                'loss_pct': 0.0,  # can't compute exact loss on a partial run
                'avg_ms': round(s['sum'] / s['count'], 2) if s['count'] else 0.0,
                'worst_ms': round(s['worst'], 2),
            })
        if hops:
            return {'partial': True, 'stopped': True, 'hops': hops}

    if check_id == 'ping':
        times = [float(m) for m in re.findall(r'time=([\d.]+)\s*ms', text)]
        if times:
            return {'partial': True, 'stopped': True, 'target': None,
                    'loss_pct': 0.0, 'avg_ms': round(sum(times) / len(times), 2),
                    'worst_ms': round(max(times), 2)}

    if check_id == 'tcptraceroute':
        hops = []
        for line in lines:
            m = re.match(r'\s*(\d+)\s+(\S+)\s+([\d.]+)\s*ms', line)
            if m:
                hops.append({'hop': int(m.group(1)), 'host': m.group(2), 'ms': float(m.group(3))})
        if hops:
            return {'partial': True, 'stopped': True, 'hops': hops}

    return {'partial': True, 'stopped': True, 'raw': text.strip()[-2000:]}
