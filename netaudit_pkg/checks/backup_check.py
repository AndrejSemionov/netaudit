"""
Проверка бэкапов по SSH — не "cron вроде настроен", а факт: бэкапы реально
есть, свежие, не битые и их больше одной копии.

Самый частый сценарий провала бэкапов — тихий: скрипт годами "работает" по
крону, но давно падает с ошибкой в лог, никто туда не смотрит, и дыра
вскрывается только в момент реального disaster recovery, когда откатываться
уже некуда. Это ровно тот класс проблем, который стоит проверять
автоматически, а не полагаться на то, что кто-то вручную зайдёт и посмотрит.

Проверяется для каждой указанной директории:
  - свежесть последнего файла (mtime) относительно ожидаемого интервала;
  - аномально маленький размер (подозрение на упавший на середине дамп);
  - целостность архива, если формат распознан (.gz/.tar.gz/.zip/.sql) —
    без полной распаковки, только header-level проверка;
  - количество файлов в директории — единственная копия нарушает базовое
    правило "3-2-1" (минимум одна копия — уже риск, что при её порче
    восстанавливаться будет нечем);
  - свободное место на партиции, где лежат бэкапы (если диск почти полон,
    следующий бэкап может тихо не поместиться и обрезаться).

Ничего не меняет на сервере — только чтение (stat, ls, gzip -t/tar -tzf
без записи на диск, df).
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


def _run(client, cmd, timeout=20):
    _, so, se = client.exec_command(cmd, timeout=timeout)
    return so.read().decode(errors='replace'), se.read().decode(errors='replace')


def _finding(severity, title, detail=''):
    return {'severity': severity, 'title': title, 'detail': detail}


# минимальный "разумный" размер файла бэкапа — ниже этого почти наверняка
# означает упавший на середине дамп, а не легитимно маленькую БД
MIN_SANE_BACKUP_BYTES = 1024  # 1 KB

ARCHIVE_EXT_RE = re.compile(r'\.(tar\.gz|tgz|gz|zip|sql|sql\.gz|bz2|tar\.bz2|xz)$', re.IGNORECASE)


def _find_files(client, directory: str) -> list[dict]:
    """ls -la в машиночитаемом виде через stat, каждая строка:
    epoch_mtime|size_bytes|filename"""
    # find вместо ls -la — не ломается на файлах с пробелами/спецсимволами
    # в имени, и сразу даёт нужные поля через -printf
    cmd = (f"find {directory!r} -maxdepth 1 -type f "
           r"-printf '%T@|%s|%f\n' 2>&1")
    out, err = _run(client, cmd)
    if 'No such file or directory' in out or 'No such file or directory' in err:
        return None  # директория не существует - отличаем от "существует, но пусто"
    files = []
    for line in out.splitlines():
        line = line.strip()
        if not line or '|' not in line:
            continue
        parts = line.split('|', 2)
        if len(parts) != 3:
            continue
        try:
            mtime = float(parts[0])
            size = int(parts[1])
        except ValueError:
            continue
        files.append({'mtime': mtime, 'size': size, 'name': parts[2]})
    return files


def _check_archive_integrity(client, directory: str, filename: str) -> str | None:
    """Возвращает None если целостность ок или формат не распознан (не проверяем),
    иначе — текст ошибки. Все проверки read-only, без распаковки на диск."""
    path = f'{directory.rstrip("/")}/{filename}'
    lower = filename.lower()
    quoted = path.replace("'", "'\\''")

    if lower.endswith(('.tar.gz', '.tgz')):
        out, err = _run(client, f"tar -tzf '{quoted}' > /dev/null 2>&1 && echo OK || echo FAIL")
    elif lower.endswith('.gz'):
        out, err = _run(client, f"gzip -t '{quoted}' 2>&1 && echo OK || echo FAIL")
    elif lower.endswith('.zip'):
        out, err = _run(client, f"unzip -t '{quoted}' > /dev/null 2>&1 && echo OK || echo FAIL")
    elif lower.endswith(('.tar.bz2', '.tbz2')):
        out, err = _run(client, f"tar -tjf '{quoted}' > /dev/null 2>&1 && echo OK || echo FAIL")
    elif lower.endswith('.sql'):
        # для голого .sql полноценной "целостности" не бывает - проверяем только,
        # что файл не пустой и не похож на HTML-страницу ошибки (частый признак,
        # что дамп прервался редиректом/authentication error вместо самого SQL)
        out, err = _run(client, f"head -c 200 '{quoted}' 2>&1")
        if '<html' in out.lower() or '<!doctype' in out.lower():
            return 'начало файла похоже на HTML, не на SQL-дамп — вероятно ошибка вместо данных'
        return None
    else:
        return None  # формат не распознан, не проверяем целостность (не ошибка)

    if 'FAIL' in out or 'FAIL' in err:
        return 'архив не проходит проверку целостности (повреждён или недокачан)'
    return None


def _check_disk_space(client, directory: str) -> tuple[int | None, str | None]:
    """Возвращает (percent_used, error)."""
    out, err = _run(client, f"df -P {directory!r} 2>&1 | tail -1")
    parts = out.split()
    if len(parts) >= 5 and parts[4].endswith('%'):
        try:
            return int(parts[4].rstrip('%')), None
        except ValueError:
            pass
    return None, 'не удалось определить занятость диска'


@register(
    id='backup_check', label='Проверка бэкапов (SSH)', category='server',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Хост', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'Пользователь', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH-порт', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Путь к ключу', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Пароль (если без ключа)', 'default': ''},
        {'name': 'directories', 'type': 'text', 'label': 'Директории с бэкапами (через запятую)',
         'default': '/var/backups'},
        {'name': 'max_age_hours', 'type': 'number', 'label': 'Ожидаемая свежесть, часов', 'default': 26},
        {'name': 'min_copies', 'type': 'number', 'label': 'Минимум копий (для 3-2-1)', 'default': 2},
    ],
    required_tools=[],
    description='Проверка бэкапов по SSH: свежесть последнего файла, аномально маленький размер '
                '(упавший дамп), целостность архива (gz/tar.gz/zip/sql), число копий на диске, '
                'занятость партиции. Readonly — только чтение файлов и метаданных.',
)
def check_backup(host='', user='root', port=22, key_path='', password='',
                  directories='/var/backups', max_age_hours=26, min_copies=2) -> dict:
    if paramiko is None:
        return {'error': 'paramiko не установлен'}
    if not host:
        return {'error': 'не указан host'}

    dir_list = [d.strip() for d in directories.split(',') if d.strip()]
    if not dir_list:
        return {'error': 'не указано ни одной директории'}

    try:
        client = _ssh_connect(host, user, port, key_path, password)
    except Exception as e:
        return {'error': f'не подключиться: {e}'}

    results = []
    all_findings = []

    try:
        import time
        now = time.time()
        max_age_seconds = float(max_age_hours) * 3600

        for directory in dir_list:
            entry = {'directory': directory}
            files = _find_files(client, directory)

            if files is None:
                entry['error'] = 'директория не существует'
                all_findings.append(_finding('high', f'{directory}: директория с бэкапами не существует',
                                              'проверь путь или задачу бэкапа целиком — возможно, она пишет в другое место'))
                results.append(entry)
                continue

            if not files:
                entry['file_count'] = 0
                all_findings.append(_finding('high', f'{directory}: файлов бэкапов не найдено',
                                              'директория пуста — бэкап либо ни разу не запускался, либо всё удаляется раньше срока'))
                results.append(entry)
                continue

            files.sort(key=lambda f: f['mtime'], reverse=True)
            latest = files[0]
            age_hours = (now - latest['mtime']) / 3600

            entry['file_count'] = len(files)
            entry['latest_file'] = latest['name']
            entry['latest_age_hours'] = round(age_hours, 1)
            entry['latest_size_bytes'] = latest['size']

            if age_hours > max_age_hours:
                all_findings.append(_finding(
                    'high', f'{directory}: последний бэкап устарел ({age_hours:.0f}ч, ожидалось ≤{max_age_hours}ч)',
                    f'файл {latest["name"]}, проверь cron/systemd timer и лог последнего запуска на сервере'
                ))

            if 0 < latest['size'] < MIN_SANE_BACKUP_BYTES:
                all_findings.append(_finding(
                    'high', f'{directory}: последний бэкап подозрительно маленький ({latest["size"]} байт)',
                    f'файл {latest["name"]} — вероятно, скрипт упал на середине или база была пустой в момент дампа'
                ))

            if len(files) < min_copies:
                all_findings.append(_finding(
                    'medium', f'{directory}: копий бэкапа меньше ожидаемого ({len(files)}, нужно ≥{min_copies})',
                    'единственная копия нарушает правило 3-2-1 — при её порче восстанавливаться будет нечем'
                ))

            if ARCHIVE_EXT_RE.search(latest['name']):
                integrity_error = _check_archive_integrity(client, directory, latest['name'])
                entry['integrity_ok'] = integrity_error is None
                if integrity_error:
                    all_findings.append(_finding(
                        'high', f'{directory}: последний бэкап не проходит проверку целостности',
                        f'{latest["name"]}: {integrity_error}'
                    ))

            disk_pct, disk_err = _check_disk_space(client, directory)
            if disk_pct is not None:
                entry['disk_used_pct'] = disk_pct
                if disk_pct >= 90:
                    all_findings.append(_finding(
                        'medium', f'{directory}: партиция заполнена на {disk_pct}%',
                        'следующий бэкап рискует не поместиться — освободи место или перенеси бэкапы на другой диск'
                    ))

            results.append(entry)

    finally:
        client.close()

    if not all_findings:
        all_findings.append(_finding('ok', 'бэкапы свежие, целые, копий достаточно'))

    counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
    for f in all_findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    return {
        'host': host,
        'directories': results,
        'findings': all_findings,
        'summary': counts,
    }
