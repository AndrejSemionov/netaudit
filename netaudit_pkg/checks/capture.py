"""
Плагины захвата/анализа трафика:
  tshark_capture   — пассивный захват на интерфейсе машины (движок Wireshark).
                     Видит только трафик, физически проходящий через эту машину.
  mikrotik_sniffer — трафик конкретного устройства (телефона) через роутер MikroTik по SSH.
                     Видит ВЕСЬ трафик устройства, т.к. роутер — точка его прохождения.

Оба возвращают единый формат: топ назначений по объёму + разбивка по протоколам,
чтобы дашборд рисовал их одинаково.

TLS не расшифровывается: видно КУДА (IP/домен) и СКОЛЬКО, но не содержимое.
"""

from __future__ import annotations

import re
import socket
from collections import defaultdict

from ..registry import register
from ..utils import run_cmd, tool_available
from .. import threat

try:
    import paramiko
except ImportError:
    paramiko = None


def _reverse_dns(ip: str) -> str | None:
    """Обратный DNS для обогащения: 142.250.1.1 -> *.1e100.net. Лучший effort, с таймаутом."""
    try:
        socket.setdefaulttimeout(1.5)
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None


def _enrich_top(dests: list[dict], limit: int = 15) -> list[dict]:
    """Добавляет обратный DNS к топ-N назначений (только к топу, чтобы не тормозить)."""
    for d in dests[:limit]:
        d['host'] = _reverse_dns(d['ip'])
    return dests


@register(
    id='tshark_capture', label='Захват трафика (tshark)', category='capture',
    params=[
        {'name': 'interface', 'type': 'text', 'label': 'Интерфейс', 'default': 'any'},
        {'name': 'duration', 'type': 'number', 'label': 'Длительность, сек', 'default': 15},
        {'name': 'bpf_filter', 'type': 'text', 'label': 'BPF-фильтр (напр. host 192.168.88.55)', 'default': ''},
        {'name': 'analyze_threats', 'type': 'select', 'label': 'Анализ угроз',
         'options': ['да', 'да+whois', 'нет'], 'default': 'да'},
    ],
    required_tools=['tshark'],
    description='Пассивный захват движком Wireshark + оценка подозрительности назначений. Нужен root.',
)
def check_tshark_capture(interface: str = 'any', duration: int = 15, bpf_filter: str = '',
                         analyze_threats: str = 'да') -> dict:
    if not tool_available('tshark'):
        return {'error': 'tshark не установлен (apt install tshark). Для захвата нужен root.'}
    duration = int(duration)

    cmd = ['tshark', '-i', interface, '-a', f'duration:{duration}', '-n', '-l',
           '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'frame.len',
           '-e', '_ws.col.Protocol', '-E', 'separator=|']
    if bpf_filter.strip():
        cmd += ['-f', bpf_filter.strip()]

    code, out, err = run_cmd(cmd, timeout=duration + 20)
    if code != 0:
        low = err.lower()
        if 'permission' in low or 'are you root' in low or 'couldn\'t run' in low:
            return {'error': 'нет прав на захват — запусти под root/sudo, или дай tshark CAP_NET_RAW'}
        return {'error': err.strip()[-400:] or f'tshark код {code}'}

    by_dst = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'protocols': set()})
    total_packets = total_bytes = 0
    for line in out.splitlines():
        parts = line.split('|')
        if len(parts) < 4:
            continue
        src, dst, length, proto = parts[0], parts[1], parts[2], parts[3]
        if not dst:
            continue
        try:
            blen = int(length) if length else 0
        except ValueError:
            blen = 0
        by_dst[dst]['packets'] += 1
        by_dst[dst]['bytes'] += blen
        if proto:
            by_dst[dst]['protocols'].add(proto)
        total_packets += 1
        total_bytes += blen

    dests = [{'ip': dst, 'packets': v['packets'], 'bytes': v['bytes'],
              'protocols': sorted(v['protocols'])}
             for dst, v in by_dst.items()]
    dests.sort(key=lambda x: x['bytes'], reverse=True)
    dests = _enrich_top(dests)

    result = {
        'interface': interface, 'duration': duration, 'filter': bpf_filter or None,
        'total_packets': total_packets, 'total_bytes': total_bytes,
        'destinations': dests,
    }
    if analyze_threats != 'нет':
        scored = threat.score_destinations(dests, do_whois=(analyze_threats == 'да+whois'))
        result['destinations'] = scored['scored']
        result['threat_summary'] = scored['summary']
    return result


# ВНИМАТЕЛЬНО: arp_capture (ARP-spoofing MITM) НЕ зарегистрирован как веб-чек.
# Причина: требует root, а сервис netaudit работает под непривилегированным
# пользователем. Дать ему sudo NOPASSWD на arpspoof/tshark означало бы, что
# любая уязвимость в самом веб-сервисе (напр. command injection) автоматически
# конвертируется в root + возможность MITM всей локальной сети без пароля —
# слишком широкая привилегия для кнопки в браузере.
#
# check_arp_capture() ниже оставлен как рабочая, протестированная функция —
# используй её только вручную, с явным вводом sudo-пароля каждый раз:
#
#   sudo python3 -c "
#   from netaudit_pkg.checks.capture import check_arp_capture
#   import json
#   print(json.dumps(check_arp_capture(
#       target_ip='192.168.88.3', gateway_ip='192.168.88.1',
#       interface='enp0s3', duration=30), indent=2, ensure_ascii=False))
#   "
#
# (запускать из корня проекта netaudit/, под sudo — как ты уже делал руками
# через arpspoof+tshark и это сработало)
def check_arp_capture(target_ip: str = '', gateway_ip: str = '', interface: str = 'eth0',
                      duration: int = 30, analyze_threats: str = 'да') -> dict:
    if not tool_available('tshark'):
        return {'error': 'tshark не установлен (apt install tshark)'}
    if not tool_available('arpspoof'):
        return {'error': 'arpspoof не установлен (apt install dsniff)'}
    if not target_ip:
        return {'error': 'укажи IP устройства (target_ip), чей трафик перехватываем'}
    if not gateway_ip:
        return {'error': 'укажи IP роутера (gateway_ip) — обычно совпадает со шлюзом сети'}
    duration = int(duration)

    # включаем IP forwarding — без этого устройство потеряет интернет во время
    # захвата вместо прозрачного MITM (пакеты будут доходить до нас, но не дальше)
    _, ip_fwd_before, _ = run_cmd(['cat', '/proc/sys/net/ipv4/ip_forward'], timeout=5)
    run_cmd(['sysctl', '-w', 'net.ipv4.ip_forward=1'], timeout=5)

    # два arpspoof-процесса: телефон думает что мы роутер, роутер думает что мы телефон —
    # это и есть MITM, без этого только половина трафика попадёт к нам
    proc_to_target = None
    proc_to_gateway = None
    try:
        import subprocess
        proc_to_target = subprocess.Popen(
            ['arpspoof', '-i', interface, '-t', target_ip, gateway_ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc_to_gateway = subprocess.Popen(
            ['arpspoof', '-i', interface, '-t', gateway_ip, target_ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # tshark слушает только трафик нужного устройства, пока спуфинг активен
        cmd = ['tshark', '-i', interface, '-a', f'duration:{duration}', '-n', '-l',
               '-f', f'host {target_ip}',
               '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'frame.len',
               '-e', '_ws.col.Protocol', '-E', 'separator=|']
        code, out, err = run_cmd(cmd, timeout=duration + 20)
    finally:
        # восстановление — КРИТИЧНО: без этого устройство останется без интернета
        # (или ещё хуже — трафик продолжит идти через нас без захвата) после выхода
        for proc in (proc_to_target, proc_to_gateway):
            if proc:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    proc.kill()
        # arpspoof без -r обычно сам не шлёт корректирующие пакеты при явном terminate,
        # поэтому вручную восстанавливаем настоящие ARP-записи в обе стороны
        run_cmd(['arping', '-c', '3', '-A', '-I', interface, target_ip], timeout=10)
        run_cmd(['arping', '-c', '3', '-A', '-I', interface, gateway_ip], timeout=10)
        if ip_fwd_before.strip() != '1':
            run_cmd(['sysctl', '-w', 'net.ipv4.ip_forward=0'], timeout=5)

    if code != 0:
        low = err.lower()
        if 'permission' in low or 'are you root' in low:
            return {'error': 'нет прав — arpspoof и tshark требуют root'}
        return {'error': err.strip()[-400:] or f'tshark код {code}'}

    by_dst = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'protocols': set()})
    total_packets = total_bytes = 0
    for line in out.splitlines():
        parts = line.split('|')
        if len(parts) < 4:
            continue
        src_field, dst_field, length, proto = parts[0], parts[1], parts[2], parts[3]
        if not dst_field or not src_field:
            continue
        # в MITM-режиме tshark иногда схлопывает несколько адресов в одном фрейме
        # через запятую (напр. '192.168.88.20,192.168.88.3' — VM форвардит пакет
        # телефона дальше) — берём все part'ы и проверяем, участвует ли наш target
        srcs = src_field.split(',')
        dsts = dst_field.split(',')
        if target_ip not in srcs:
            continue
        # назначение — первый dst, который не совпадает с самим устройством и не VM
        dst = next((d for d in dsts if d not in (target_ip,)), dsts[-1])
        try:
            blen = int(length) if length else 0
        except ValueError:
            blen = 0
        by_dst[dst]['packets'] += 1
        by_dst[dst]['bytes'] += blen
        if proto:
            by_dst[dst]['protocols'].add(proto)
        total_packets += 1
        total_bytes += blen

    dests = [{'ip': dst, 'packets': v['packets'], 'bytes': v['bytes'],
              'protocols': sorted(v['protocols'])}
             for dst, v in by_dst.items()]
    dests.sort(key=lambda x: x['bytes'], reverse=True)
    dests = _enrich_top(dests)

    result = {
        'target_ip': target_ip, 'gateway_ip': gateway_ip, 'duration': duration,
        'total_packets': total_packets, 'total_bytes': total_bytes,
        'destinations': dests,
        'note': 'ARP-spoofing MITM — работает с любым роутером независимо от вендора. '
                'ARP-таблицы восстановлены после захвата.',
    }
    if analyze_threats != 'нет':
        scored = threat.score_destinations(dests, do_whois=(analyze_threats == 'да+whois'))
        result['destinations'] = scored['scored']
        result['threat_summary'] = scored['summary']
    return result


@register(
    id='mikrotik_sniffer', label='Трафик устройства через MikroTik', category='capture',
    params=[
        {'name': 'router', 'type': 'text', 'label': 'IP роутера', 'default': '192.168.88.1'},
        {'name': 'user', 'type': 'text', 'label': 'Пользователь', 'default': 'admin'},
        {'name': 'password', 'type': 'password', 'label': 'Пароль', 'default': ''},
        {'name': 'target_ip', 'type': 'text', 'label': 'IP устройства (телефона)', 'default': ''},
        {'name': 'port', 'type': 'number', 'label': 'SSH-порт', 'default': 22},
        {'name': 'analyze_threats', 'type': 'select', 'label': 'Анализ угроз',
         'options': ['да', 'да+whois', 'нет'], 'default': 'да'},
    ],
    required_tools=[],
    description='Куда идёт трафик устройства через роутер + оценка подозрительности назначений. Видит ВЕСЬ трафик устройства.',
)
def check_mikrotik_sniffer(router: str = '192.168.88.1', user: str = 'admin',
                           password: str = '', target_ip: str = '', port: int = 22,
                           analyze_threats: str = 'да') -> dict:
    if paramiko is None:
        return {'error': 'paramiko не установлен (pip install paramiko --break-system-packages)'}
    if not target_ip:
        return {'error': 'укажи IP устройства (target_ip), чей трафик смотрим'}
    port = int(port)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=router, port=port, username=user, password=password, timeout=10,
                       look_for_keys=False, allow_agent=False)
    except (paramiko.AuthenticationException, paramiko.SSHException, socket.error, OSError) as e:
        return {'error': f'не подключиться к роутеру: {e}'}

    # terse — одна строка на запись, легко парсить.
    # connection tracking показывает активные соединения устройства: куда и по какому протоколу.
    cmd = f'/ip firewall connection print terse where src-address~"{target_ip}"'
    try:
        _, stdout, stderr = client.exec_command(cmd, timeout=20)
        out = stdout.read().decode(errors='replace')
        err = stderr.read().decode(errors='replace')
    except (paramiko.SSHException, socket.timeout) as e:
        client.close()
        return {'error': f'ошибка выполнения на роутере: {e}'}
    finally:
        client.close()

    if err.strip():
        return {'error': f'роутер вернул ошибку: {err.strip()[:300]}'}

    # парсим dst-address=IP:port и protocol=
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
    dests.sort(key=lambda x: x['connections'], reverse=True)
    dests = _enrich_top(dests)

    result = {
        'router': router, 'target_ip': target_ip,
        'total_destinations': len(dests),
        'destinations': dests,
        'note': 'Снимок активных соединений. TLS-содержимое не видно — только адреса назначения.',
    }
    if analyze_threats != 'нет':
        scored = threat.score_destinations(dests, do_whois=(analyze_threats == 'да+whois'))
        result['destinations'] = scored['scored']
        result['threat_summary'] = scored['summary']
    return result
