"""
Управление внешними инструментами: какие нужны, какие установлены, установка по запросу.

Установка идёт через apt по белому списку (только известные пакеты) — никакого
произвольного ввода в shell. Требует прав (sudo или root); если их нет, возвращает
понятную ошибку с командой для ручного запуска.
"""

from __future__ import annotations

import shutil

from .registry import registry
from .utils import run_cmd, tool_available
from . import checks  # noqa: F401  — импорт регистрирует проверки в реестре

# Белый список: инструмент -> apt-пакет. Только эти можно ставить из веба.
TOOL_PACKAGES: dict[str, str] = {
    'mtr': 'mtr-tiny',
    'tcptraceroute': 'tcptraceroute',
    'traceroute': 'traceroute',
    'ping': 'iputils-ping',
    'dig': 'dnsutils',
    'arping': 'iputils-arping',
    'iperf3': 'iperf3',
    'curl': 'curl',
    'openssl': 'openssl',
    'ss': 'iproute2',
    'nmap': 'nmap',
    'whois': 'whois',
    'tshark': 'tshark',
    'sqlmap': 'sqlmap',
}

# Инструменты, которые проверки используют внутри, но не объявляют в required_tools
# (например openssl/curl — есть fallback, поэтому не обязательны, но полезны).
OPTIONAL_TOOLS = ['openssl', 'curl', 'traceroute', 'nmap', 'whois']


def all_referenced_tools() -> list[str]:
    """Все инструменты, упоминаемые проверками (required) + опциональные."""
    tools = set(OPTIONAL_TOOLS)
    for spec in registry.all():
        tools.update(spec.required_tools)
    return sorted(tools)


def tools_status() -> list[dict]:
    """Статус каждого инструмента: установлен ли, путь, пакет для установки, кто использует."""
    used_by: dict[str, list[str]] = {}
    for spec in registry.all():
        for t in spec.required_tools:
            used_by.setdefault(t, []).append(spec.id)

    out = []
    for tool in all_referenced_tools():
        path = shutil.which(tool)
        out.append({
            'tool': tool,
            'installed': path is not None,
            'path': path,
            'package': TOOL_PACKAGES.get(tool),
            'used_by': used_by.get(tool, []),
            'installable': tool in TOOL_PACKAGES,
        })
    return out


def install_tool(tool: str) -> dict:
    """
    Устанавливает инструмент через apt. Только из белого списка.
    Пробует sudo -n (без пароля); если недоступно — сообщает команду для ручного запуска.
    """
    if tool not in TOOL_PACKAGES:
        return {'ok': False, 'error': f'инструмент {tool} не в белом списке установки'}

    package = TOOL_PACKAGES[tool]

    if tool_available(tool):
        return {'ok': True, 'already': True, 'tool': tool}

    manual_cmd = f'sudo apt install -y {package}'

    # пробуем через sudo без пароля (типично для настроенных серверов)
    if shutil.which('sudo'):
        run_cmd(['sudo', '-n', 'apt-get', 'update'], timeout=120)  # свежий индекс
        code, out, err = run_cmd(['sudo', '-n', 'apt-get', 'install', '-y', package], timeout=180)
        if code == 0:
            return {'ok': True, 'tool': tool, 'package': package, 'output': out.strip()[-500:]}
        # sudo без пароля не сработал
        if 'password is required' in err.lower() or 'a terminal is required' in err.lower():
            return {'ok': False, 'error': 'нужен пароль sudo — запусти вручную',
                    'manual_command': manual_cmd}
        return {'ok': False, 'error': err.strip()[-500:] or f'apt код {code}',
                'manual_command': manual_cmd}

    # sudo нет — возможно мы root
    run_cmd(['apt-get', 'update'], timeout=120)  # свежий индекс
    code, out, err = run_cmd(['apt-get', 'install', '-y', package], timeout=180)
    if code == 0:
        return {'ok': True, 'tool': tool, 'package': package, 'output': out.strip()[-500:]}
    return {'ok': False, 'error': err.strip()[-500:] or f'apt код {code}',
            'manual_command': manual_cmd}
