"""
Lynis-аудит удалённого сервера по SSH.

Запускает `lynis audit system` на целевом хосте, читает машиночитаемый
/var/log/lynis-report.dat и мапит warnings/suggestions в тот же формат
findings (severity/title/detail), что и server_audit.

Требует: lynis установлен на удалённом сервере, sudo без пароля
(либо запуск под root) — иначе покрытие проверок сильно урезано.
Ничего не меняет на сервере — сам lynis в audit-режиме readonly.
"""

from __future__ import annotations

import re

from ..registry import register

try:
    import paramiko
except ImportError:
    paramiko = None


# ===========================================================================
# Вспомогательное (тот же паттерн, что в server_security.py)
# ===========================================================================

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


def _run(client, cmd, timeout=15):
    _, so, se = client.exec_command(cmd, timeout=timeout)
    return so.read().decode(errors='replace'), se.read().decode(errors='replace')


def _run_sudo(client, cmd, sudo_password, timeout=15):
    """
    sudo без TTY: обычный `sudo cmd` падает 'a terminal is required to
    authenticate', если для пользователя не настроен NOPASSWD (частый
    случай на чужих/клиентских серверах, где sudoers не подкрутить).
    `sudo -S` читает пароль из stdin — работает без TTY, не требует
    предварительной настройки sudoers на целевой машине.
    Если passwordless sudo всё же есть, пустой stdin тоже пройдёт.
    """
    stdin, so, se = client.exec_command(f'sudo -S -p "" {cmd}', timeout=timeout)
    stdin.write((sudo_password or '') + '\n')
    stdin.flush()
    stdin.channel.shutdown_write()
    return so.read().decode(errors='replace'), se.read().decode(errors='replace')


def _finding(severity, title, detail=''):
    return {'severity': severity, 'title': title, 'detail': detail}


# ===========================================================================
# Парсинг lynis-report.dat
# ===========================================================================

def _parse_report(raw: str) -> dict:
    """
    Формат report.dat — плоский key=value, повторяющиеся ключи (warning[],
    suggestion[]) идут списком строк. Значения внутри — Test:ID|текст|доп.
    """
    hardening_index = None
    warnings = []
    suggestions = []
    tests_performed = 0
    os_name = ''

    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '=' not in line:
            continue
        key, _, value = line.partition('=')

        if key == 'hardening_index':
            try:
                hardening_index = int(value)
            except ValueError:
                pass
        elif key == 'tests_executed':
            try:
                tests_performed = int(value)
            except ValueError:
                pass
        elif key == 'os_fullname' or key == 'os_name':
            os_name = os_name or value
        elif key == 'warning[]':
            parts = value.split('|')
            text = parts[1] if len(parts) > 1 else value
            test_id = parts[0] if parts else ''
            warnings.append((test_id, text))
        elif key == 'suggestion[]':
            parts = value.split('|')
            text = parts[1] if len(parts) > 1 else value
            test_id = parts[0] if parts else ''
            suggestions.append((test_id, text))

    return {
        'hardening_index': hardening_index,
        'os_name': os_name,
        'tests_performed': tests_performed,
        'warnings': warnings,
        'suggestions': suggestions,
    }


def _to_findings(parsed: dict) -> list[dict]:
    findings = []
    # warnings у Lynis — реальные проблемы, маппим в high
    for test_id, text in parsed['warnings']:
        findings.append(_finding('high', text.strip(), f'Lynis [{test_id}]'))
    # suggestions — рекомендации по улучшению, маппим в low
    for test_id, text in parsed['suggestions']:
        findings.append(_finding('low', text.strip(), f'Lynis [{test_id}]'))
    if not findings:
        findings.append(_finding('ok', 'Lynis не выявил замечаний'))
    return findings


# ===========================================================================
# Проверка
# ===========================================================================

@register(
    id='lynis_audit', label='Lynis security-аудит (SSH)', category='server',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Хост', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'Пользователь', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH-порт', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Путь к ключу', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Пароль (если без ключа)', 'default': ''},
        {'name': 'auto_install', 'type': 'checkbox', 'label': 'Установить lynis, если отсутствует',
         'default': False},
    ],
    required_tools=[],
    description='Security-аудит сервера через Lynis (hardening index + findings) по SSH. Readonly.',
)
def check_lynis_audit(host='', user='root', port=22, key_path='', password='',
                       auto_install=False) -> dict:
    if paramiko is None:
        return {'error': 'paramiko не установлен'}
    if not host:
        return {'error': 'не указан host'}
    try:
        client = _ssh_connect(host, user, port, key_path, password)
    except Exception as e:
        return {'error': f'не подключиться: {e}'}

    try:
        which_out, _ = _run(client, 'which lynis || echo NOTFOUND')
        if 'NOTFOUND' in which_out:
            if not auto_install:
                return {'error': 'lynis не установлен на сервере',
                        'hint': 'apt install lynis -y (или включи auto_install)'}
            install_out, install_err = _run(
                client, 'sudo apt-get install -y lynis 2>&1', timeout=90
            )
            which_out, _ = _run(client, 'which lynis || echo NOTFOUND')
            if 'NOTFOUND' in which_out:
                return {'error': 'не удалось установить lynis',
                        'detail': (install_out + install_err)[-500:]}

        # sudo без пароля? если нет — используем sudo -S с паролем через stdin,
        # это работает без TTY и без предварительной настройки sudoers на
        # целевой машине (актуально для чужих/клиентских серверов)
        sudo_check, _ = _run(client, 'sudo -n true 2>&1 && echo OK || echo NOPASS')
        no_sudo = 'NOPASS' in sudo_check

        if no_sudo and not password:
            return {'error': 'нужен sudo, но passwordless sudo не настроен и пароль не передан',
                    'hint': 'укажи «Пароль (если без ключа)» — он будет использован и для sudo -S'}

        if no_sudo:
            _run_sudo(client, 'lynis audit system --quiet --no-colors', password, timeout=180)
            report_raw, report_err = _run_sudo(client, 'cat /var/log/lynis-report.dat', password)
        else:
            _run(client, 'sudo lynis audit system --quiet --no-colors', timeout=180)
            # файл всегда root:root с правами 640, читаем через sudo вне зависимости
            # от того, каким запускался сам аудит — иначе cat молча падает Permission denied
            report_raw, report_err = _run(client, 'sudo cat /var/log/lynis-report.dat 2>&1')

        if not report_raw.strip() or 'hardening_index' not in report_raw:
            return {'error': 'не удалось прочитать /var/log/lynis-report.dat',
                    'detail': report_err.strip()[:500] or report_raw.strip()[:500],
                    'hint': 'проверь пароль sudo или права: ls -la /var/log/lynis-report.dat'}

    finally:
        client.close()

    parsed = _parse_report(report_raw)
    findings = _to_findings(parsed)

    counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
    for f in findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    result = {
        'host': host,
        'os_name': parsed['os_name'],
        'hardening_index': parsed['hardening_index'],
        'tests_performed': parsed['tests_performed'],
        'findings': findings,
        'summary': counts,
    }
    return result
