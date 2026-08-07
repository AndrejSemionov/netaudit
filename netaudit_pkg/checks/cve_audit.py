"""
CVE-аудит установленного ПО через SSH. Два шага:
  1. Сбор фактов о сервисах (версия + релевантный конфиг) — переиспользует
     логику из server_security.py (_ssh_connect/_run).
  2. Матчинг версий через OSV.dev (https://osv.dev, без ключа, batch-запрос).

Результат — список найденных CVE по каждому сервису с severity (если есть CVSS)
и данными для fix (affected/fixed версии). Финальный вердикт "что делать" даёт
общий ai_analyze() из history.py — сюда просто попадает секция 'cve' с фактами
и конфигом, чтобы AI мог сопоставить уязвимость с реальной конфигурацией, а не
пересказывать голый CVSS-скор.

Кэш: cve_cache в storage.py, TTL 24ч — чтобы не долбить OSV.dev на каждый прогон.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

import httpx

from ..registry import register
from .. import storage
from .server_security import _ssh_connect, _run, paramiko

OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch'
OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/{id}'
CACHE_TTL_HOURS = 24


# ===========================================================================
# Сбор версий сервисов по SSH
# ===========================================================================

def _parse_version(text: str) -> str | None:
    m = re.search(r'(\d+\.\d+(?:\.\d+)?)', text)
    return m.group(1) if m else None


def collect_packages(client) -> list[dict]:
    """
    Возвращает список {name, version, ecosystem, raw} для известных сервисов,
    плюс общий срез установленных deb-пакетов (для ecosystem='Debian' в OSV).
    """
    packages = []

    # --- nginx ---
    out, _ = _run(client, 'nginx -v 2>&1')
    ver = _parse_version(out)
    if ver:
        packages.append({'name': 'nginx', 'version': ver, 'ecosystem': 'Debian', 'raw': out.strip()})

    # --- OpenSSH ---
    out, _ = _run(client, 'ssh -V 2>&1')
    ver = _parse_version(out)
    if ver:
        packages.append({'name': 'openssh', 'version': ver, 'ecosystem': 'Debian', 'raw': out.strip()})

    # --- MySQL / MariaDB ---
    out, _ = _run(client, 'mysql --version 2>/dev/null || mariadb --version 2>/dev/null')
    ver = _parse_version(out)
    if ver:
        name = 'mariadb' if 'mariadb' in out.lower() else 'mysql'
        packages.append({'name': name, 'version': ver, 'ecosystem': 'Debian', 'raw': out.strip()})

    # --- PHP ---
    out, _ = _run(client, 'php -v 2>/dev/null')
    ver = _parse_version(out)
    if ver:
        packages.append({'name': 'php', 'version': ver, 'ecosystem': 'Debian', 'raw': out.strip().splitlines()[0] if out.strip() else ''})

    # --- kernel ---
    out, _ = _run(client, 'uname -r')
    if out.strip():
        packages.append({'name': 'linux', 'version': out.strip(), 'ecosystem': 'Debian', 'raw': out.strip()})

    # --- WordPress (если найдём wp-config.php в стандартных местах) ---
    out, _ = _run(client, "find /var/www -maxdepth 3 -iname 'wp-includes' -type d 2>/dev/null | head -1")
    wp_dir = out.strip()
    if wp_dir:
        base = wp_dir.rsplit('/wp-includes', 1)[0]
        ver_out, _ = _run(client, f"grep -m1 \"\\$wp_version = \" {base}/wp-includes/version.php 2>/dev/null")
        ver = _parse_version(ver_out)
        if ver:
            packages.append({'name': 'wordpress', 'version': ver, 'ecosystem': 'WordPress', 'raw': ver_out.strip()})

    return packages


# ===========================================================================
# OSV.dev — матчинг + детали
# ===========================================================================

def _cache_get(name: str, version: str) -> list | None:
    row = storage.cve_get(f'{name}::{version}')
    if not row:
        return None
    updated = datetime.fromisoformat(row['updated_at'])
    if datetime.now() - updated > timedelta(hours=CACHE_TTL_HOURS):
        return None
    return row['data']


def _cache_set(name: str, version: str, data: list) -> None:
    storage.cve_set(f'{name}::{version}', data)


def query_osv(packages: list[dict]) -> dict[str, list]:
    """Возвращает {pkg_name: [vuln_ids...]} используя batch-запрос, с кэшем."""
    to_query = []
    result: dict[str, list] = {}

    for p in packages:
        cached = _cache_get(p['name'], p['version'])
        if cached is not None:
            result[p['name']] = cached
        else:
            to_query.append(p)

    if not to_query:
        return result

    try:
        resp = httpx.post(
            OSV_BATCH_URL,
            json={'queries': [
                {'package': {'name': p['name'], 'ecosystem': p['ecosystem']}, 'version': p['version']}
                for p in to_query
            ]},
            timeout=20,
        )
        resp.raise_for_status()
        batch = resp.json().get('results', [])
    except httpx.HTTPError:
        # OSV недоступен — не валим весь чек, просто без CVE-данных по неопрошенным
        for p in to_query:
            result.setdefault(p['name'], [])
        return result

    for p, r in zip(to_query, batch):
        ids = [v['id'] for v in r.get('vulns', [])]
        result[p['name']] = ids
        _cache_set(p['name'], p['version'], ids)

    return result


def fetch_vuln_details(vuln_id: str) -> dict:
    try:
        resp = httpx.get(OSV_VULN_URL.format(id=vuln_id), timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError:
        return {'id': vuln_id, 'error': 'не удалось получить детали'}

    severity = None
    for sev in data.get('severity', []):
        if sev.get('type') == 'CVSS_V3':
            severity = sev.get('score')

    fixed_versions = []
    for aff in data.get('affected', []):
        for rng in aff.get('ranges', []):
            for ev in rng.get('events', []):
                if 'fixed' in ev:
                    fixed_versions.append(ev['fixed'])

    return {
        'id': vuln_id,
        'summary': data.get('summary') or data.get('details', '')[:200],
        'severity': severity,
        'fixed_versions': sorted(set(fixed_versions)),
        'references': [r['url'] for r in data.get('references', [])[:3]],
    }


# ===========================================================================
# Комбинированный чек
# ===========================================================================

@register(
    id='cve_audit', label='CVE-аудит установленного ПО (SSH)', category='security',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Хост', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'Пользователь', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH-порт', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Путь к ключу', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Пароль (если без ключа)', 'default': ''},
    ],
    required_tools=[],
    description='Собирает версии установленного ПО (nginx, ssh, mysql/mariadb, php, kernel, wordpress) '
                'по SSH и сверяет с базой уязвимостей OSV.dev. AI-анализ (общий ai_analyze) сопоставит '
                'найденные CVE с реальным конфигом сервиса и скажет, что действительно нужно обновить.',
)
def check_cve_audit(host='', user='root', port=22, key_path='', password='') -> dict:
    if paramiko is None:
        return {'error': 'paramiko не установлен'}
    if not host:
        return {'error': 'не указан host'}
    try:
        client = _ssh_connect(host, user, port, key_path, password)
    except Exception as e:
        return {'error': f'не подключиться: {e}'}

    try:
        packages = collect_packages(client)
    finally:
        client.close()

    if not packages:
        return {'host': host, 'packages': [], 'findings': [],
                'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'ok': 0}}

    vuln_ids_by_pkg = query_osv(packages)

    findings = []
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'ok': 0}

    for p in packages:
        ids = vuln_ids_by_pkg.get(p['name'], [])
        if not ids:
            findings.append({
                'package': p['name'], 'version': p['version'],
                'severity': 'ok', 'cve': None, 'title': 'известных CVE не найдено',
            })
            counts['ok'] += 1
            continue
        for vid in ids[:10]:  # ограничение, чтобы не заDDoS-ить OSV на пакет с сотней CVE
            details = fetch_vuln_details(vid)
            score = details.get('severity')
            try:
                score_f = float(score.split('/')[0]) if score else None
            except (ValueError, AttributeError):
                score_f = None
            if score_f is not None:
                sev = 'critical' if score_f >= 9 else 'high' if score_f >= 7 else 'medium' if score_f >= 4 else 'low'
            else:
                sev = 'medium'  # неизвестный score — не занижаем
            counts[sev] = counts.get(sev, 0) + 1
            findings.append({
                'package': p['name'], 'version': p['version'], 'severity': sev,
                'cve': vid, 'title': details.get('summary', ''),
                'fixed_versions': details.get('fixed_versions', []),
                'references': details.get('references', []),
            })

    return {
        'host': host,
        'packages': packages,
        'findings': findings,
        'summary': counts,
    }
