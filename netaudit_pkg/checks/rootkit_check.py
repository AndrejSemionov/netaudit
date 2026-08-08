"""
Проверка на руткиты через rkhunter и/или chkrootkit по SSH.

Оба инструмента делают похожую работу (ищут известные сигнатуры руткитов,
подменённые системные команды, скрытые процессы), но с разными базами
сигнатур и разными ложноположительными паттернами — поэтому по умолчанию
гоняем оба и не дедуплицируем находки, чтобы не потерять то, что заметил
только один из них.

rkhunter: `--check --skip-keypress --report-warnings-only --nocolors` —
неинтерактивно, только Warning-строки, без ANSI-кодов (иначе парсинг
ломается на escape-последовательностях).

chkrootkit: построчный вывод "Checking `name'... STATUS", где STATUS один
из: not infected / INFECTED / not tested / not found / Vulnerable but disabled.
Интересуют только строки с INFECTED.

ВАЖНО про ложные срабатывания: оба инструмента известны false positives —
например chkrootkit иногда путает легитимный bindshell (Exim TLS) с реальным
бэкдором, а на некоторых VPS/контейнерах даёт "hidden processes" из-за
особенностей виртуализации, а не потому что там реально руткит. Находки
здесь — повод разобраться, не подтверждённый факт компрометации.
"""

from __future__ import annotations

import re

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


def _run(client, cmd, timeout=15):
    _, so, se = client.exec_command(cmd, timeout=timeout)
    return so.read().decode(errors='replace'), se.read().decode(errors='replace')


def _run_sudo(client, cmd, sudo_password, timeout=15):
    """sudo -S читает пароль из stdin — работает без TTY (см. lynis_audit.py, тот же паттерн)."""
    stdin, so, se = client.exec_command(f'sudo -S -p "" {cmd}', timeout=timeout)
    stdin.write((sudo_password or '') + '\n')
    stdin.flush()
    stdin.channel.shutdown_write()
    return so.read().decode(errors='replace'), se.read().decode(errors='replace')


def _finding(severity, title, detail=''):
    return {'severity': severity, 'title': title, 'detail': detail}


# ===========================================================================
# rkhunter
# ===========================================================================

def _parse_rkhunter(raw: str) -> list[dict]:
    """С флагом --report-warnings-only в выводе остаются практически только
    строки 'Warning: ...' (плюс шапка версии и системные сообщения)."""
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith('Warning:'):
            text = line[len('Warning:'):].strip()
            findings.append(_finding('medium', text))
    return findings


def _run_rkhunter(client, sudo_password, no_sudo) -> tuple[list[dict], str | None]:
    """Возвращает (findings, error). error не None если инструмент не найден/не смог отработать."""
    which_out, _ = _run(client, 'which rkhunter || echo NOTFOUND')
    if 'NOTFOUND' in which_out:
        return [], 'rkhunter не установлен'

    cmd = 'rkhunter --check --skip-keypress --report-warnings-only --nocolors 2>&1'
    if no_sudo:
        out, _ = _run_sudo(client, cmd, sudo_password, timeout=300)
    else:
        out, _ = _run(client, f'sudo {cmd}', timeout=300)

    if not out.strip():
        return [], 'rkhunter не вернул вывод (проверь права sudo)'

    return _parse_rkhunter(out), None


# ===========================================================================
# chkrootkit
# ===========================================================================

CHKROOTKIT_LINE_RE = re.compile(r"^Checking `([^']+)'\.\.\.\s*(.+)$")


def _parse_chkrootkit(raw: str) -> list[dict]:
    findings = []
    for line in raw.splitlines():
        m = CHKROOTKIT_LINE_RE.match(line.strip())
        if not m:
            continue
        name, status = m.group(1), m.group(2).strip()
        if status.startswith('INFECTED'):
            findings.append(_finding('high', f'{name}: {status}',
                                      'проверь вручную перед выводами — известны ложные срабатывания '
                                      '(например легитимный bindshell на нестандартных портах)'))
        elif status.startswith('Vulnerable but disabled'):
            findings.append(_finding('low', f'{name}: {status}',
                                      'команда уязвима, но не используется (не запущена/не в конфиге)'))
    return findings


def _run_chkrootkit(client, sudo_password, no_sudo) -> tuple[list[dict], str | None]:
    which_out, _ = _run(client, 'which chkrootkit || echo NOTFOUND')
    if 'NOTFOUND' in which_out:
        return [], 'chkrootkit не установлен'

    cmd = 'chkrootkit 2>&1'
    if no_sudo:
        out, _ = _run_sudo(client, cmd, sudo_password, timeout=300)
    else:
        out, _ = _run(client, f'sudo {cmd}', timeout=300)

    if not out.strip():
        return [], 'chkrootkit не вернул вывод (проверь права sudo)'

    return _parse_chkrootkit(out), None


# ===========================================================================
# Проверка
# ===========================================================================

@register(
    id='rootkit_check', label='Проверка на руткиты (rkhunter/chkrootkit, SSH)', category='server',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Хост', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'Пользователь', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH-порт', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Путь к ключу', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Пароль (если без ключа)', 'default': ''},
        {'name': 'use_rkhunter', 'type': 'checkbox', 'label': 'Запускать rkhunter', 'default': True},
        {'name': 'use_chkrootkit', 'type': 'checkbox', 'label': 'Запускать chkrootkit', 'default': True},
        {'name': 'auto_install', 'type': 'checkbox', 'label': 'Установить недостающие инструменты',
         'default': False},
    ],
    required_tools=[],
    description='Поиск известных руткитов и подменённых системных команд через rkhunter и/или '
                'chkrootkit по SSH. Readonly, только чтение системы. Оба инструмента дают '
                'ложные срабатывания — находки нужно проверять вручную, не как готовый вердикт.',
)
def check_rootkit(host='', user='root', port=22, key_path='', password='',
                   use_rkhunter=True, use_chkrootkit=True, auto_install=False) -> dict:
    if paramiko is None:
        return {'error': 'paramiko не установлен'}
    if not host:
        return {'error': 'не указан host'}
    if not use_rkhunter and not use_chkrootkit:
        return {'error': 'выбери хотя бы один инструмент (rkhunter или chkrootkit)'}

    try:
        client = _ssh_connect(host, user, port, key_path, password)
    except Exception as e:
        return {'error': f'не подключиться: {e}'}

    try:
        sudo_check, _ = _run(client, 'sudo -n true 2>&1 && echo OK || echo NOPASS')
        no_sudo = 'NOPASS' in sudo_check
        if no_sudo and not password:
            return {'error': 'нужен sudo, но passwordless sudo не настроен и пароль не передан',
                    'hint': 'укажи «Пароль (если без ключа)» — он будет использован и для sudo -S'}

        def _ensure_installed(tool, package):
            which_out, _ = _run(client, f'which {tool} || echo NOTFOUND')
            if 'NOTFOUND' not in which_out:
                return True
            if not auto_install:
                return False
            install_cmd = f'apt-get install -y {package} 2>&1'
            if no_sudo:
                _run_sudo(client, install_cmd, password, timeout=120)
            else:
                _run(client, f'sudo {install_cmd}', timeout=120)
            which_out, _ = _run(client, f'which {tool} || echo NOTFOUND')
            return 'NOTFOUND' not in which_out

        tools_status = {}
        all_findings = []
        errors = []

        if use_rkhunter:
            if not _ensure_installed('rkhunter', 'rkhunter'):
                errors.append('rkhunter не установлен' + (' и не удалось поставить' if auto_install else ''))
                tools_status['rkhunter'] = {'ran': False}
            else:
                findings, err = _run_rkhunter(client, password, no_sudo)
                if err:
                    errors.append(f'rkhunter: {err}')
                    tools_status['rkhunter'] = {'ran': False}
                else:
                    for f in findings:
                        f['source'] = 'rkhunter'
                    all_findings.extend(findings)
                    tools_status['rkhunter'] = {'ran': True, 'findings_count': len(findings)}

        if use_chkrootkit:
            if not _ensure_installed('chkrootkit', 'chkrootkit'):
                errors.append('chkrootkit не установлен' + (' и не удалось поставить' if auto_install else ''))
                tools_status['chkrootkit'] = {'ran': False}
            else:
                findings, err = _run_chkrootkit(client, password, no_sudo)
                if err:
                    errors.append(f'chkrootkit: {err}')
                    tools_status['chkrootkit'] = {'ran': False}
                else:
                    for f in findings:
                        f['source'] = 'chkrootkit'
                    all_findings.extend(findings)
                    tools_status['chkrootkit'] = {'ran': True, 'findings_count': len(findings)}

    finally:
        client.close()

    if not any(s.get('ran') for s in tools_status.values()):
        return {'error': 'ни один инструмент не запустился', 'detail': '; '.join(errors)}

    if not all_findings:
        all_findings.append(_finding('ok', 'признаков руткитов не найдено'))

    counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
    for f in all_findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    result = {
        'host': host,
        'tools': tools_status,
        'findings': all_findings,
        'summary': counts,
    }
    if errors:
        result['warnings'] = errors
    return result
