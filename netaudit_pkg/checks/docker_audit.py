"""
Аудит безопасности Docker-контейнеров по SSH.

В отличие от server_audit (смотрит на хост-уровень — nginx, firewall, SSH),
этот чек смотрит именно на то, КАК запущены контейнеры — отдельная категория
рисков, которую хостовый аудит физически не видит.

Проверяется для каждого запущенного контейнера через `docker inspect`:
  - запущен ли процесс внутри контейнера от root (Config.User пусто/'root'/'0') —
    при container escape атакующий сразу получает root на хосте;
  - --privileged (HostConfig.Privileged) — почти полный доступ к хосту,
    оправдан редко (Docker-in-Docker, низкоуровневый мониторинг);
  - опасные добавленные capabilities (HostConfig.CapAdd) — список того, что
    реально считается рискованным при добавлении без явной необходимости
    (SYS_ADMIN, SYS_PTRACE, SYS_MODULE и т.д.), а не "любой CapAdd — плохо"
    (NET_RAW для ping-подобных инструментов — нормальный, обоснованный кейс);
  - публично торчащие порты — контейнер слушает 0.0.0.0 вместо 127.0.0.1
    или внутренней docker-сети (HostConfig.PortBindings[].HostIp);
  - широкие volume-монтирования — весь корень хоста, /etc, docker.sock
    внутрь контейнера (HostConfig.Binds);
  - тег образа 'latest' без пиннинга версии — не баг сам по себе, но
    сигнал, что нет контроля версий и накопленных патчей CVE.

Отдельно — доступность самого Docker daemon socket без защиты (TCP без TLS
или предоставленный контейнеру `/var/run/docker.sock` bind) — фактически
root-доступ к хосту, один из самых частых и опасных косяков в реальных
деплоях.
"""

from __future__ import annotations

import json

from ..registry import register

try:
    import paramiko
except ImportError:
    paramiko = None


def _ssh_connect(host, user, port, key_path, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {'hostname': host, 'port': int(port), 'username': user, 'timeout': 10,
              'look_for_keys': bool(key_path), 'allow_agent': bool(key_path)}
    if key_path and key_path.strip():
        from pathlib import Path
        kwargs['key_filename'] = str(Path(key_path).expanduser())
    elif password:
        kwargs['password'] = password
    client.connect(**kwargs)
    return client


def _run(client, cmd, timeout=20):
    _, so, se = client.exec_command(cmd, timeout=timeout)
    return so.read().decode(errors='replace'), se.read().decode(errors='replace')


def _run_sudo(client, cmd, sudo_password, timeout=20):
    stdin, so, se = client.exec_command(f'sudo -S -p "" {cmd}', timeout=timeout)
    stdin.write((sudo_password or '') + '\n')
    stdin.flush()
    stdin.channel.shutdown_write()
    return so.read().decode(errors='replace'), se.read().decode(errors='replace')


def _finding(severity, title, detail=''):
    return {'severity': severity, 'title': title, 'detail': detail}


# capabilities, добавление которых расширяет атаку сильнее, чем типичные
# легитимные кейсы (NET_RAW для сетевых утилит, NET_BIND_SERVICE для портов
# < 1024 — намеренно не включены сюда, это частые и обоснованные добавления)
DANGEROUS_CAPS = {
    'SYS_ADMIN', 'SYS_MODULE', 'SYS_PTRACE', 'SYS_RAWIO', 'SYS_BOOT',
    'DAC_READ_SEARCH', 'ALL',
}

# пути, монтирование которых внутрь контейнера практически всегда избыточно
# для обычного приложения (не системного инструмента мониторинга/бэкапа)
DANGEROUS_BIND_TARGETS = ('/', '/etc', '/root', '/var/run/docker.sock', '/boot')


def _parse_container(raw_json: str) -> dict | None:
    try:
        data = json.loads(raw_json)
    except (json.JSONDecodeError, ValueError):
        return None
    return data


def _audit_one_container(info: dict) -> list[dict]:
    findings = []
    name = (info.get('Name') or '').lstrip('/')
    config = info.get('Config') or {}
    host_config = info.get('HostConfig') or {}
    image = config.get('Image', '?')

    # --- запущен от root ---
    user = (config.get('User') or '').strip()
    if user in ('', 'root', '0', '0:0'):
        findings.append(_finding(
            'medium', f'{name}: процесс внутри контейнера запущен от root',
            f'image {image} — при container escape атакующий сразу получает root-доступ к хосту; '
            'задай USER в Dockerfile или --user при запуске, если приложению не нужен root'
        ))

    # --- privileged ---
    if host_config.get('Privileged'):
        findings.append(_finding(
            'high', f'{name}: запущен с --privileged',
            'почти полный доступ к хосту (устройства, ядро) — оправдано редко '
            '(Docker-in-Docker, низкоуровневый мониторинг); проверь, действительно ли нужно'
        ))

    # --- опасные capabilities ---
    cap_add = host_config.get('CapAdd') or []
    dangerous = [c for c in cap_add if c.upper() in DANGEROUS_CAPS]
    if dangerous:
        findings.append(_finding(
            'high', f'{name}: добавлены рискованные capabilities: {", ".join(dangerous)}',
            f'полный список CapAdd: {", ".join(cap_add)} — убедись, что каждая реально нужна приложению'
        ))

    # --- публичные порты ---
    port_bindings = host_config.get('PortBindings') or {}
    public_ports = []
    for container_port, bindings in port_bindings.items():
        for b in (bindings or []):
            host_ip = b.get('HostIp', '')
            if host_ip in ('', '0.0.0.0', '::'):
                public_ports.append(f'{container_port} -> {b.get("HostPort", "?")}')
    if public_ports:
        findings.append(_finding(
            'low', f'{name}: порты слушают на всех интерфейсах (0.0.0.0)',
            ', '.join(public_ports) + ' — норм для веб-сервисов за reverse-proxy, '
            'но для внутренних служб (БД, admin-панели) обычно должно быть 127.0.0.1'
        ))

    # --- docker.sock смонтирован внутрь ---
    binds = host_config.get('Binds') or []
    for bind in binds:
        # формат "host_path:container_path[:mode]"
        parts = bind.split(':')
        host_path = parts[0] if parts else bind
        normalized = host_path.rstrip('/') or '/'  # '/'.rstrip('/') даёт '' - возвращаем обратно в '/'
        if normalized == '/var/run/docker.sock':
            findings.append(_finding(
                'high', f'{name}: docker.sock смонтирован внутрь контейнера',
                f'{bind} — это фактически root-доступ к хосту через Docker API; '
                'убедись, что это осознанное решение (напр. Portainer/CI-раннер), не случайность'
            ))
        elif normalized in DANGEROUS_BIND_TARGETS:
            findings.append(_finding(
                'medium', f'{name}: смонтирован чувствительный путь хоста: {normalized}',
                f'{bind} — избыточный доступ для обычного приложения, '
                'проверь, действительно ли контейнеру нужен весь этот путь'
            ))

    # --- тег latest / без тега ---
    if image.endswith(':latest') or ':' not in image.split('/')[-1]:
        findings.append(_finding(
            'low', f'{name}: образ без пиннинга версии ({image})',
            'без фиксированной версии сложно контролировать, какие патчи CVE применены — '
            'при следующем pull образ может незаметно смениться'
        ))

    return findings


@register(
    id='docker_audit', label='Аудит Docker-контейнеров (SSH)', category='server',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Хост', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'Пользователь', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH-порт', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Путь к ключу', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Пароль (если без ключа)', 'default': ''},
        {'name': 'include_stopped', 'type': 'checkbox', 'label': 'Включать остановленные контейнеры',
         'default': False},
    ],
    required_tools=[],
    description='Аудит того, КАК запущены Docker-контейнеры (не что внутри): root-процессы, '
                '--privileged, опасные capabilities, публичные порты, docker.sock и другие '
                'чувствительные volume-монтирования, непиннутые образы. Readonly — только '
                '`docker ps`/`docker inspect`, ничего не меняет.',
)
def check_docker_audit(host='', user='root', port=22, key_path='', password='',
                        include_stopped=False) -> dict:
    if paramiko is None:
        return {'error': 'paramiko не установлен'}
    if not host:
        return {'error': 'не указан host'}

    try:
        client = _ssh_connect(host, user, port, key_path, password)
    except Exception as e:
        return {'error': f'не подключиться: {e}'}

    try:
        which_out, _ = _run(client, 'which docker || echo NOTFOUND')
        if 'NOTFOUND' in which_out:
            return {'error': 'docker не установлен на сервере'}

        # docker обычно требует быть в группе docker или root — пробуем без sudo сначала,
        # это самый частый рабочий вариант (пользователь добавлен в группу docker)
        ps_out, ps_err = _run(client, 'docker ps -q' + (' -a' if include_stopped else ''))
        needs_sudo = 'permission denied' in (ps_out + ps_err).lower()

        if needs_sudo:
            sudo_check, _ = _run(client, 'sudo -n true 2>&1 && echo OK || echo NOPASS')
            no_sudo_pass = 'NOPASS' in sudo_check
            if no_sudo_pass and not password:
                return {'error': 'docker недоступен без sudo, а passwordless sudo не настроен и пароль не передан',
                        'hint': 'добавь пользователя в группу docker (usermod -aG docker <user>), '
                                'или укажи «Пароль (если без ключа)» для sudo -S'}
            if no_sudo_pass:
                ps_out, ps_err = _run_sudo(client, 'docker ps -q' + (' -a' if include_stopped else ''), password)
            else:
                ps_out, ps_err = _run(client, 'sudo docker ps -q' + (' -a' if include_stopped else ''))

        container_ids = [c.strip() for c in ps_out.splitlines() if c.strip()]

        # проверяем незащищённый TCP-сокет Docker daemon независимо от того, есть ли
        # сейчас запущенные контейнеры — сокет опасен сам по себе, даже когда всё остановлено
        socket_check_cmd = (
            "grep -rE 'tcp://.*2375' /etc/docker/daemon.json /lib/systemd/system/docker.service "
            "/etc/systemd/system/docker.service.d/*.conf 2>/dev/null || true"
        )
        socket_out, _ = _run(client, socket_check_cmd)

        all_findings = []
        if socket_out.strip():
            all_findings.append(_finding(
                'high', 'Docker daemon слушает TCP без явного TLS (порт 2375)',
                socket_out.strip()[:300] + ' — незащищённый TCP-сокет Docker API = root-доступ '
                'для любого, кто до него достучится по сети'
            ))

        if not container_ids:
            if not all_findings:
                all_findings.append(_finding('ok', 'запущенных контейнеров не найдено'))
            counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
            for f in all_findings:
                counts[f['severity']] = counts.get(f['severity'], 0) + 1
            return {'host': host, 'containers_checked': 0, 'findings': all_findings, 'summary': counts}

        for cid in container_ids:
            inspect_cmd = f"docker inspect '{cid}' 2>&1" if not needs_sudo else None
            if needs_sudo:
                if no_sudo_pass:
                    raw, _ = _run_sudo(client, f"docker inspect '{cid}'", password, timeout=15)
                else:
                    raw, _ = _run(client, f"sudo docker inspect '{cid}'", timeout=15)
            else:
                raw, _ = _run(client, inspect_cmd, timeout=15)

            try:
                data = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                continue  # пропускаем контейнер, если вывод не распарсился, не роняем весь чек
            info = data[0] if isinstance(data, list) and data else (data if isinstance(data, dict) else None)
            if not info:
                continue
            all_findings.extend(_audit_one_container(info))

    finally:
        client.close()

    if not all_findings:
        all_findings.append(_finding('ok', 'заметных проблем в конфигурации контейнеров не найдено'))

    counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
    for f in all_findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    return {
        'host': host,
        'containers_checked': len(container_ids),
        'findings': all_findings,
        'summary': counts,
    }
