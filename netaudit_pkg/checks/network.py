"""Сетевые проверки-плагины: mtr, tcptraceroute, ping, dig, arping."""

from __future__ import annotations

import json
import re
import socket
import time

from ..registry import register
from ..utils import run_cmd, tool_available


@register(
    id='mtr', label='MTR (ICMP-трассировка)', category='network',
    params=[
        {'name': 'target', 'type': 'text', 'label': 'Цель (IP/хост)', 'default': '8.8.8.8'},
        {'name': 'duration_sec', 'type': 'number', 'label': 'Продолжительность, сек', 'default': 15},
    ],
    required_tools=['mtr'],
    description='Потери и задержки по каждому хопу. Задай время работы в секундах напрямую: '
                '45 = 45 сек, 300 = 5 минут, 3600 = 1 час, 7200 = 2 часа.',
)
def check_mtr(target: str = '8.8.8.8', duration_sec: float = 15) -> dict:
    if not tool_available('mtr'):
        return {'target': target, 'error': 'mtr не установлен (apt install mtr-tiny)'}
    duration_sec = float(duration_sec)
    if duration_sec < 1:
        return {'target': target, 'error': 'продолжительность должна быть ≥ 1 сек'}

    # Раскладываем продолжительность на count*interval для mtr. Интервал не делаем меньше 1с
    # (это дефолт mtr и разумный минимум для ICMP), а для длинных периодов увеличиваем интервал,
    # чтобы не заваливать сеть тысячами пакетов зря — раз в 1..30 сек вполне достаточно
    # для отслеживания деградации на длинном окне.
    if duration_sec <= 60:
        interval = 1.0
    elif duration_sec <= 600:
        interval = 5.0
    elif duration_sec <= 3600:
        interval = 15.0
    else:
        interval = 30.0
    count = max(1, round(duration_sec / interval))

    # Текстовый вывод (-j на некоторых сборках 0.95 глючит: не даёт валидный JSON и тормозит).
    # -r report-режим, -w wide, -b показывать имя+IP, -i интервал между пакетами.
    # Таймаут процесса — с запасом сверх заданной продолжительности, чтобы не оборвать
    # длинный мониторинг раньше времени (реальный mtr может идти дольше формальной оценки
    # на молчащих/нестабильных сетях).
    timeout = max(90, int(duration_sec * 1.5) + 60)
    code, out, err = run_cmd(
        ['mtr', '-r', '-w', '-b', '-c', str(count), '-i', str(interval), target],
        timeout=timeout,

    )
    if code != 0:
        return {'target': target, 'error': f'mtr ошибка: {err.strip() or out.strip()[-300:]}'}
    if not out.strip():
        return {'target': target, 'error': 'mtr не вернул вывод (пусто)'}

    hops = []
    for line in out.splitlines():
        # формат: "  1.|-- _gateway (192.168.88.1)    0.0%    15    5.0   5.6   1.5  23.3   6.6"
        m = re.match(
            r'\s*(\d+)\.\|--\s+(\S+)(?:\s+\(([\d.:a-fA-F]+)\))?\s+'
            r'([\d.]+)%\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)',
            line
        )
        if not m:
            continue
        hop_num, host, ip, loss, snt, last, avg, best, wrst, stdev = m.groups()
        display_host = host if host != '???' else (ip or '???')
        if ip and host != ip:
            display_host = f'{host} ({ip})'
        hops.append({
            'hop': int(hop_num), 'host': display_host,
            'loss_pct': float(loss), 'avg_ms': float(avg), 'worst_ms': float(wrst),
        })

    if not hops:
        return {'target': target, 'error': f'не удалось распарсить вывод mtr: {out.strip()[-300:]}'}

    return {'target': target, 'hops': hops, 'duration_sec': round(duration_sec, 1)}


@register(
    id='tcptraceroute', label='TCP-трассировка', category='network',
    params=[
        {'name': 'target', 'type': 'text', 'label': 'Цель (IP/хост)', 'default': '8.8.8.8'},
        {'name': 'port', 'type': 'number', 'label': 'Порт', 'default': 80},
        {'name': 'max_hops', 'type': 'number', 'label': 'Макс. хопов', 'default': 8},
    ],
    required_tools=['tcptraceroute'],
    description='TCP SYN вместо ICMP — опровергает отговорку ISP "у нас ICMP так настроен". По умолчанию 8 хопов: обычно достаточно, чтобы поймать провайдера, а дальше в интернете узлы часто молчат на TCP-трассировку и только тратят время.',
)
def check_tcptraceroute(target: str = '8.8.8.8', port: int = 80, max_hops: int = 8) -> dict:
    if not tool_available('tcptraceroute'):
        return {'error': 'tcptraceroute не установлен (apt install tcptraceroute)'}
    port = int(port)
    max_hops = int(max_hops)
    # -m ограничивает число хопов, -w таймаут ожидания ответа на хоп (сек).
    # На молчащих хопах (частая ситуация — транзитные узлы не отвечают TTL-exceeded на TCP SYN,
    # хотя ICMP у mtr работает) tcptraceroute может пробовать несколько раз, реально тратя
    # заметно больше чем hops*wait. Таймаут процесса берём с большим запасом.
    per_hop_wait = 2
    timeout = max_hops * per_hop_wait * 3 + 20
    code, out, err = run_cmd(
        ['tcptraceroute', '-n', '-m', str(max_hops), '-w', str(per_hop_wait), target, str(port)],
        timeout=timeout,
    )
    if code not in (0, 1):
        return {'error': err.strip() or out.strip()[-300:] or 'нет ответа'}
    hops = []
    for line in out.splitlines():
        m = re.match(r'\s*(\d+)\s+(\S+)\s+([\d.]+)\s*ms', line)
        if m:
            hops.append({'hop': int(m.group(1)), 'host': m.group(2), 'ms': float(m.group(3))})
        elif re.match(r'\s*\d+\s+\*', line):
            hop_m = re.match(r'\s*(\d+)\s+\*', line)
            if hop_m:
                hops.append({'hop': int(hop_m.group(1)), 'host': '* (нет ответа)', 'ms': None})
    if not hops:
        return {'target': target, 'port': port, 'error': f'не удалось распарсить вывод: {out.strip()[-300:]}'}
    return {'target': target, 'port': port, 'hops': hops, 'raw': out.strip()}


@register(
    id='ping', label='Ping', category='network',
    params=[
        {'name': 'target', 'type': 'text', 'label': 'Цель', 'default': '8.8.8.8'},
        {'name': 'count', 'type': 'number', 'label': 'Пакетов', 'default': 10},
    ],
    required_tools=['ping'],
    description='Базовая проверка потерь и RTT.',
)
def check_ping(target: str = '8.8.8.8', count: int = 10) -> dict:
    if not tool_available('ping'):
        return {'target': target, 'error': 'ping не найден'}
    count = int(count)
    code, out, err = run_cmd(['ping', '-c', str(count), '-i', '0.3', target], timeout=count + 10)
    if code not in (0, 1):
        return {'target': target, 'error': err.strip() or 'нет ответа'}
    loss = re.search(r'(\d+)% packet loss', out)
    rtt = re.search(r'= ([\d.]+)/([\d.]+)/([\d.]+)', out)
    return {
        'target': target,
        'loss_pct': float(loss.group(1)) if loss else None,
        'avg_ms': float(rtt.group(2)) if rtt else None,
        'worst_ms': float(rtt.group(3)) if rtt else None,
    }


@register(
    id='dig', label='DNS (dig)', category='network',
    params=[
        {'name': 'hostname', 'type': 'text', 'label': 'Домен', 'default': 'google.com'},
        {'name': 'record_type', 'type': 'text', 'label': 'Тип записи', 'default': 'A'},
    ],
    required_tools=['dig'],
    description='Детальный DNS: сервер, TTL, время запроса.',
)
def check_dig(hostname: str = 'google.com', record_type: str = 'A') -> dict:
    if not tool_available('dig'):
        return {'error': 'dig не установлен (apt install dnsutils)'}
    code, out, err = run_cmd(['dig', '+noall', '+answer', '+stats', record_type, hostname], timeout=10)
    if code != 0:
        return {'error': err.strip() or 'dig ошибка'}
    answers, query_time, server = [], None, None
    for line in out.splitlines():
        if line.startswith(';;'):
            if 'Query time' in line:
                m = re.search(r'Query time:\s*(\d+)\s*msec', line)
                if m: query_time = int(m.group(1))
            elif 'SERVER' in line:
                m = re.search(r'SERVER:\s*(\S+)', line)
                if m: server = m.group(1)
        elif line.strip():
            parts = line.split()
            if len(parts) >= 5:
                answers.append({'name': parts[0], 'ttl': parts[1], 'type': parts[3], 'value': parts[4]})
    return {'hostname': hostname, 'record_type': record_type, 'answers': answers,
            'query_time_ms': query_time, 'dns_server': server}


@register(
    id='arping', label='ARPing (L2, локальная сеть)', category='network',
    params=[
        {'name': 'target', 'type': 'text', 'label': 'IP в локальной подсети', 'default': '192.168.88.1'},
        {'name': 'count', 'type': 'number', 'label': 'Пакетов', 'default': 5},
    ],
    required_tools=['arping'],
    description='L2-проверка внутри локальной подсети (не через интернет).',
)
def check_arping(target: str = '192.168.88.1', count: int = 5) -> dict:
    if not tool_available('arping'):
        return {'error': 'arping не установлен (apt install iputils-arping)'}
    count = int(count)
    code, out, err = run_cmd(['arping', '-c', str(count), target], timeout=count + 10)
    if code != 0:
        return {'error': err.strip() or 'нет ответа (цель не в локальной подсети?)'}

    # Современный iputils-arping пишет "Sent N probes ..." / "Received N response(s)"
    # (без явного "% unanswered", это только в старых версиях). Считаем потери сами.
    sent_m = re.search(r'Sent (\d+) probe', out)
    recv_m = re.search(r'Received (\d+) response', out)
    loss_pct = None
    if sent_m and recv_m:
        sent, recv = int(sent_m.group(1)), int(recv_m.group(1))
        loss_pct = round((1 - recv / sent) * 100, 1) if sent else None
    else:
        # fallback на старый формат на случай другой версии arping
        loss_m = re.search(r'(\d+)% unanswered', out)
        loss_pct = float(loss_m.group(1)) if loss_m else None

    times = [float(m) for m in re.findall(r'(\d+\.\d+)ms', out)]
    avg_ms = round(sum(times) / len(times), 2) if times else None
    mac_m = re.search(r'\[([0-9A-Fa-f:]{17})\]', out)

    return {
        'target': target, 'loss_pct': loss_pct, 'avg_ms': avg_ms,
        'mac': mac_m.group(1) if mac_m else None,
        'sent': int(sent_m.group(1)) if sent_m else None,
        'received': int(recv_m.group(1)) if recv_m else None,
        'raw': out.strip(),
    }
