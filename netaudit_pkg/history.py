"""История отчётов + AI-анализ. Хранение — через storage (SQLite)."""

from __future__ import annotations

import json
import os

from .utils import log
from . import storage

MODEL = 'claude-sonnet-4-6'


def save_report(report: dict) -> int:
    return storage.save_report(report)


def list_reports(limit: int = 50) -> list[dict]:
    return storage.list_reports(limit)


def load_report(report_id: int) -> dict | None:
    return storage.load_report(int(report_id))


def _resolve_api_key(explicit: str | None = None) -> str | None:
    """Приоритет: явно переданный -> настройка в БД -> переменная окружения."""
    if explicit:
        return explicit
    from_db = storage.setting_get('anthropic_api_key')
    if from_db:
        return from_db
    return os.environ.get('ANTHROPIC_API_KEY')


def ai_analyze(report: dict, api_key: str | None = None) -> dict:
    """AI-анализ: проблемы + рекомендации что делать."""
    api_key = _resolve_api_key(api_key)
    if not api_key:
        return {'error': 'API-ключ не задан (настройки -> Anthropic API key, или переменная ANTHROPIC_API_KEY)'}

    try:
        import httpx
    except ImportError:
        return {'error': 'httpx не установлен'}

    prompt = (
        "Ты старший сетевой инженер и специалист по безопасности. Проанализируй JSON-отчёт "
        "сетевого аудита и верни СТРОГО валидный JSON (без markdown, без ```), формат:\n"
        '{"summary": "краткое резюме 2-3 предложения", '
        '"problems": [{"severity": "high|medium|low", "title": "...", "detail": "..."}], '
        '"recommendations": [{"priority": 1, "action": "что конкретно сделать", "why": "почему"}]}\n\n'
        "Обрати особое внимание:\n"
        "- если mtr (ICMP) и tcptraceroute (TCP) расходятся - это важно для спора с провайдером;\n"
        "- потери на хопе 2+ = проблема провайдера, на хопе 1 = локальная;\n"
        "- открытые порты без firewall, устаревший SSL, PermitRootLogin yes, PasswordAuthentication yes - риски;\n"
        "- высокий CPU/RAM/диск - проблемы производительности;\n"
        "- если есть анализ трафика (destinations с risk_level): оцени назначения помеченные high/suspicious, "
        "объясни куда уходит трафик и почему это подозрительно, но НЕ паникуй по легитимным сервисам (Google, CDN). "
        "Прямой IP без DNS + необычный порт + постоянные соединения = возможный C2/шпионское ПО;\n"
        "- если есть server_audit или web_security_external (findings с severity): собери все high/medium в приоритетные "
        "рекомендации, объясни каждую находку простым языком и что конкретно исправить (какую директиву, где).\n"
        "- если есть cve_audit (findings с package/version/cve/severity): для каждой найденной CVE посмотри на её "
        "summary и сопоставь с реальным конфигом сервиса, если он есть в отчёте (например nginx.conf из server_audit) - "
        "если уязвимый модуль/директива не используется, явно скажи 'риск отсутствует, не критично'; если применимо - "
        "дай КОНКРЕТНОЕ действие: 'обновить nginx до X.Y.Z' (используй fixed_versions) или 'временный workaround без "
        "обновления: ...'. Не пересказывай голый CVSS-score без вывода что делать.\n"
        "Пиши на русском, конкретно, по делу.\n\n"
        f"ОТЧЁТ:\n{json.dumps(report, ensure_ascii=False, indent=2)}"
    )

    try:
        resp = httpx.post(
            'https://api.anthropic.com/v1/messages',
            headers={'x-api-key': api_key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json'},
            json={'model': MODEL, 'max_tokens': 2000, 'messages': [{'role': 'user', 'content': prompt}]},
            timeout=45,
        )
        resp.raise_for_status()
        data = resp.json()
        text = '\n'.join(b['text'] for b in data.get('content', []) if b.get('type') == 'text')
        cleaned = text.replace('```json', '').replace('```', '').strip()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            return {'summary': text, 'problems': [], 'recommendations': [], 'raw': True}
    except httpx.HTTPError as e:
        log.error(f'Anthropic API: {e}')
        return {'error': str(e)}


def verify_api_key(api_key: str) -> dict:
    """Проверяет, что ключ рабочий - минимальный запрос к API."""
    if not api_key:
        return {'ok': False, 'error': 'пустой ключ'}
    try:
        import httpx
    except ImportError:
        return {'ok': False, 'error': 'httpx не установлен'}
    try:
        resp = httpx.post(
            'https://api.anthropic.com/v1/messages',
            headers={'x-api-key': api_key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json'},
            json={'model': MODEL, 'max_tokens': 5, 'messages': [{'role': 'user', 'content': 'hi'}]},
            timeout=15,
        )
        if resp.status_code == 200:
            return {'ok': True}
        if resp.status_code == 401:
            return {'ok': False, 'error': 'ключ отклонён (401)'}
        return {'ok': False, 'error': f'HTTP {resp.status_code}'}
    except httpx.HTTPError as e:
        return {'ok': False, 'error': str(e)}
