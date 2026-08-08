"""
File Integrity Monitoring через AIDE (Advanced Intrusion Detection Environment) по SSH.

В отличие от rkhunter/chkrootkit (просто запустил — увидел результат), AIDE
требует состояния: сначала строится база "эталонных" хэшей всех файлов
(`aide --init`), и только после этого `aide --check` имеет с чем сравнивать.
Без инициализированной базы AIDE ничего не проверяет — базы попросту нет.

Поэтому здесь два режима работы (параметр `mode`, значения из выпадающего
списка на фронте — 'проверить изменения' / 'инициализировать базу заново',
внутри маппятся на 'check'/'init'):
  - 'check' (по умолчанию) — сравнить текущее состояние файловой системы с уже
    существующей базой. Это основной повседневный сценарий: "изменились ли
    системные бинарники с прошлого раза".
  - 'init' — (пере)инициализировать базу текущим состоянием как эталоном.
    Нужно запустить один раз при первой настройке, и заново после каждого
    легитимного обновления системы (иначе штатные apt upgrade будут
    постоянно всплывать как "изменения").

AIDE выводит сводку вида:
    Summary:
      Total number of entries:    54832
      Added entries:               2
      Removed entries:             1
      Changed entries:             5
Это единственное, что парсим напрямую — детальный построчный список изменённых
файлов (при report_level=list_entries) забираем отдельно как texт для отчёта,
не пытаясь разобрать позиционные строки атрибутов (YlZbpugamcinHAXSEC...) —
для целей аудита достаточно знать, что и сколько изменилось, конкретные
атрибуty можно посмотреть в детальном выводе на сервере при необходимости.
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
    stdin, so, se = client.exec_command(f'sudo -S -p "" {cmd}', timeout=timeout)
    stdin.write((sudo_password or '') + '\n')
    stdin.flush()
    stdin.channel.shutdown_write()
    return so.read().decode(errors='replace'), se.read().decode(errors='replace')


def _finding(severity, title, detail=''):
    return {'severity': severity, 'title': title, 'detail': detail}


SUMMARY_RE = re.compile(
    r'Total number of entries:\s*(\d+).*?'
    r'Added entries:\s*(\d+).*?'
    r'Removed entries:\s*(\d+).*?'
    r'Changed entries:\s*(\d+)',
    re.DOTALL,
)

# после 'Added entries' AIDE обычно перечисляет добавленные файлы построчно
# (report_level по умолчанию list_entries+), захватываем несколько первых
# для контекста, не весь список — на большой системе он может быть огромным
CHANGED_FILE_RE = re.compile(r'^(?:f|d|l)\S*\s+(\S+)\s*$', re.MULTILINE)


def _parse_summary(raw: str) -> dict | None:
    m = SUMMARY_RE.search(raw)
    if not m:
        return None
    return {
        'total_entries': int(m.group(1)),
        'added': int(m.group(2)),
        'removed': int(m.group(3)),
        'changed': int(m.group(4)),
    }


@register(
    id='aide_check', label='File Integrity Monitoring (AIDE, SSH)', category='server',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Хост', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'Пользователь', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH-порт', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Путь к ключу', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Пароль (если без ключа)', 'default': ''},
        {'name': 'mode', 'type': 'select', 'label': 'Режим',
         'options': ['проверить изменения', 'инициализировать базу заново'],
         'default': 'проверить изменения'},
        {'name': 'auto_install', 'type': 'checkbox', 'label': 'Установить aide, если отсутствует',
         'default': False},
    ],
    required_tools=[],
    description='File Integrity Monitoring через AIDE по SSH — отслеживает изменения системных '
                'файлов вне обычных обновлений (алерт, если бинарники поменялись не через '
                'unattended-upgrades). Режим "check" сравнивает с существующей базой, "init" '
                'создаёт новую базу-эталон.',
)
def check_aide(host='', user='root', port=22, key_path='', password='',
                mode='проверить изменения', auto_install=False) -> dict:
    if paramiko is None:
        return {'error': 'paramiko не установлен'}
    if not host:
        return {'error': 'не указан host'}
    mode_map = {'проверить изменения': 'check', 'инициализировать базу заново': 'init',
                'check': 'check', 'init': 'init'}  # 'check'/'init' - для вызова из кода/CLI напрямую
    mode = mode_map.get(mode)
    if mode is None:
        return {'error': f'неизвестный режим: {mode}'}

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

        def _sudo_run(cmd, timeout=15):
            if no_sudo:
                return _run_sudo(client, cmd, password, timeout=timeout)
            return _run(client, f'sudo {cmd}', timeout=timeout)

        which_out, _ = _run(client, 'which aide || echo NOTFOUND')
        if 'NOTFOUND' in which_out:
            if not auto_install:
                return {'error': 'aide не установлен на сервере',
                        'hint': 'apt install aide -y (или включи auto_install)'}
            _sudo_run('apt-get install -y aide 2>&1', timeout=120)
            which_out, _ = _run(client, 'which aide || echo NOTFOUND')
            if 'NOTFOUND' in which_out:
                return {'error': 'не удалось установить aide'}

        # AIDE на Debian/Ubuntu обычно кладёт базу в /var/lib/aide/aide.db
        # (и пишет новую как aide.db.new при --init) — эти пути стандартны
        # для пакета из репозитория, кастомные aide.conf могут отличаться
        if mode == 'init':
            out, err = _sudo_run('aide --init 2>&1', timeout=600)
            # --init пишет новую базу как aide.db.new, её нужно явно
            # активировать переименованием — иначе следующий --check
            # будет сравнивать со старой (или отсутствующей) базой
            _sudo_run('mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>&1 '
                       '|| mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>&1', timeout=30)
            if 'error' in out.lower() and 'Total number of entries' not in out:
                return {'error': 'ошибка при инициализации базы AIDE', 'detail': out.strip()[-500:]}
            return {'host': host, 'mode': 'init', 'output_tail': out.strip()[-800:],
                    'findings': [_finding('ok', 'база AIDE инициализирована — теперь можно запускать mode=check')],
                    'summary': {'high': 0, 'medium': 0, 'low': 0, 'ok': 1}}

        # mode == 'check'
        db_check, _ = _run(client, 'test -f /var/lib/aide/aide.db || test -f /var/lib/aide/aide.db.gz '
                                    '&& echo EXISTS || echo MISSING')
        if 'MISSING' in db_check:
            return {'error': 'база AIDE не найдена — сначала запусти этот же чек с mode=init',
                    'hint': '/var/lib/aide/aide.db не существует'}

        out, err = _sudo_run('aide --check 2>&1', timeout=300)

    finally:
        client.close()

    summary = _parse_summary(out)
    if summary is None:
        # AIDE возвращает "no changes" другим текстом, если файлы не менялись вовсе —
        # либо реально нет Summary-блока, тогда честно не притворяемся, что распарсили
        if 'no differences' in out.lower() or 'looks okay' in out.lower():
            return {'host': host, 'mode': 'check',
                    'findings': [_finding('ok', 'изменений не найдено — файловая система соответствует базе')],
                    'summary': {'high': 0, 'medium': 0, 'low': 0, 'ok': 1}}
        return {'error': 'не удалось распарсить вывод aide --check', 'detail': out.strip()[-500:]}

    findings = []
    if summary['added'] > 0:
        findings.append(_finding('medium', f"добавлено файлов: {summary['added']}",
                                  'новые файлы вне обновлений — стоит проверить, откуда'))
    if summary['removed'] > 0:
        findings.append(_finding('medium', f"удалено файлов: {summary['removed']}"))
    if summary['changed'] > 0:
        findings.append(_finding('high', f"изменено файлов: {summary['changed']}",
                                  'если это не результат штатного apt upgrade — разберись, что именно '
                                  'изменилось и почему; после легитимного обновления пере-инициализируй '
                                  'базу (mode=init), иначе она будет постоянно шуметь'))
    if not findings:
        findings.append(_finding('ok', 'изменений не найдено — файловая система соответствует базе'))

    counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
    for f in findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    return {
        'host': host,
        'mode': 'check',
        'total_entries': summary['total_entries'],
        'added': summary['added'],
        'removed': summary['removed'],
        'changed': summary['changed'],
        'findings': findings,
        'summary': counts,
    }
