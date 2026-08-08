"""
Certificate Transparency мониторинг через crt.sh.

crt.sh агрегирует публичные CT-логи (обязательные с RFC 6962 — каждый публично
доверенный TLS-сертификат обязан туда попасть). Полезно для:
  - обнаружения поддоменов, о которых забыли (staging/dev/old-admin и т.д.) —
    они не появляются в обычном DNS-брутфорсе, но сертификат на них выдавался,
    а значит запись в CT-логах есть;
  - обнаружения левых/неожиданных сертификатов на домен — если кто-то выпустил
    сертификат на твой домен без твоего ведома (скомпрометированный аккаунт у
    вашего CA, ошибка валидации DV и т.п.), это будет видно здесь раньше, чем
    где-либо ещё.

ВАЖНО (из живого фидбека): crt.sh нестабилен, hit-or-miss по доступности и
скорости ответа. Поэтому здесь короткий timeout и graceful skip — при таймауте/
ошибке возвращаем понятный error, а не роняем/зависаем весь аудит.

Без API-ключа, простой JSON-эндпоинт: https://crt.sh/?q=%.domain.com&output=json
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone

import httpx

from ..registry import register

CRTSH_URL = 'https://crt.sh/'
# crt.sh известен нестабильностью — не ждём долго, лучше честный skip чем зависший аудит
REQUEST_TIMEOUT = 12

# CA, о которых стоит явно предупредить, если сертификат выпущен НЕ от них,
# а домен предположительно ожидает конкретного провайдера — здесь пока не используется
# напрямую, но полезно для будущего сравнения "ожидаемый CA vs фактический"

WILDCARD_RE = re.compile(r'^\*\.')


def _finding(severity, title, detail=''):
    return {'severity': severity, 'title': title, 'detail': detail}


def _fetch_certs(query: str) -> list[dict]:
    """Запрашивает crt.sh, возвращает список записей или бросает исключение
    (обрабатывается в вызывающем коде — тут держим чисто сетевой слой)."""
    resp = httpx.get(CRTSH_URL, params={'q': query, 'output': 'json'},
                      timeout=REQUEST_TIMEOUT,
                      headers={'User-Agent': 'NetAudit (github.com/AndrejSemionov/netaudit)'})
    resp.raise_for_status()
    return resp.json()


def _extract_hostnames(cert: dict) -> set[str]:
    """У одного сертификата name_value может содержать несколько строк (SAN)."""
    raw = cert.get('name_value', '')
    return {line.strip().lower() for line in raw.split('\n') if line.strip()}


def _parse_crtsh_date(s: str) -> datetime | None:
    """crt.sh отдаёт даты вида '2024-01-01T00:00:00' (иногда с дробными секундами)."""
    if not s:
        return None
    for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M:%S.%f'):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


@register(
    id='cert_transparency', label='Certificate Transparency мониторинг', category='site',
    params=[
        {'name': 'domain', 'type': 'text', 'label': 'Домен', 'default': 'example.com'},
        {'name': 'expected_issuer_contains', 'type': 'text',
         'label': 'Ожидаемый издатель содержит (опционально, напр. "Let\'s Encrypt")', 'default': ''},
        {'name': 'include_expired', 'type': 'checkbox', 'label': 'Включать истёкшие сертификаты', 'default': False},
    ],
    required_tools=[],
    description='Поиск сертификатов и поддоменов домена через публичные Certificate '
                'Transparency логи (crt.sh) — обнаруживает забытые поддомены (staging/dev/old-admin) '
                'и сертификаты, выпущенные неожиданным издателем. Без доступа к серверу.',
)
def check_cert_transparency(domain: str = 'example.com', expected_issuer_contains: str = '',
                             include_expired: bool = False) -> dict:
    if not domain:
        return {'error': 'не указан domain'}
    domain = domain.strip().lower().rstrip('.')

    try:
        certs = _fetch_certs(f'%.{domain}')
    except httpx.TimeoutException:
        return {'error': f'crt.sh не ответил за {REQUEST_TIMEOUT}с — сервис нестабилен, попробуй ещё раз позже'}
    except httpx.HTTPStatusError as e:
        return {'error': f'crt.sh вернул HTTP {e.response.status_code} — сервис может быть временно перегружен'}
    except httpx.HTTPError as e:
        return {'error': f'crt.sh недоступен: {e}'}
    except ValueError:
        return {'error': 'crt.sh вернул не-JSON ответ (сервис нестабилен) — попробуй ещё раз позже'}

    if not certs:
        return {'domain': domain, 'total_certificates': 0, 'subdomains': [], 'findings': [],
                'summary': {'high': 0, 'medium': 0, 'low': 0, 'ok': 1},
                'note': 'сертификатов не найдено — либо домен не использует HTTPS, либо ещё не в CT-логах'}

    now = datetime.now(timezone.utc)
    findings = []

    # ---- поддомены: собираем уникальные хосты, помечаем "интересные" по ключевым словам ----
    hostnames_seen = defaultdict(list)  # host -> [cert_id, ...]
    issuers_by_host = defaultdict(set)
    active_count = 0

    INTERESTING_KEYWORDS = ('staging', 'stage', 'dev', 'test', 'admin', 'internal',
                             'vpn', 'backup', 'old', 'legacy', 'beta', 'demo', 'preprod',
                             'uat', 'sandbox', 'debug', 'api-internal', 'private')

    for cert in certs:
        not_after = _parse_crtsh_date(cert.get('not_after', ''))
        is_expired = not_after is not None and not_after < now
        if is_expired and not include_expired:
            continue
        if not is_expired:
            active_count += 1

        issuer = cert.get('issuer_name', '?')
        for host in _extract_hostnames(cert):
            # убираем wildcard-префикс для сравнения с ключевыми словами, но храним как есть в выводе
            bare = WILDCARD_RE.sub('', host)
            if not bare.endswith(domain):
                continue  # SAN на левый домен в том же сертификате (бывает у мультидоменных серт.)
            hostnames_seen[host].append(cert.get('id'))
            issuers_by_host[host].add(issuer)

    subdomains = sorted(hostnames_seen.keys())
    interesting = [h for h in subdomains if any(kw in h for kw in INTERESTING_KEYWORDS)]

    if interesting:
        findings.append(_finding(
            'medium',
            f'найдены потенциально забытые/внутренние поддомены ({len(interesting)})',
            ', '.join(interesting[:20]) + (' …' if len(interesting) > 20 else '')
        ))

    # ---- неожиданный издатель ----
    if expected_issuer_contains:
        needle = expected_issuer_contains.strip().lower()
        unexpected = {h: iss for h, iss in issuers_by_host.items()
                      if not any(needle in i.lower() for i in iss)}
        if unexpected:
            sample = list(unexpected.items())[:10]
            detail = '; '.join(f'{h}: {", ".join(iss)}' for h, iss in sample)
            findings.append(_finding(
                'high',
                f'сертификаты от неожиданного издателя ({len(unexpected)} хост(ов))',
                detail + (' …' if len(unexpected) > 10 else '')
            ))

    # ---- wildcard-сертификаты — не находка сама по себе, но полезно знать ----
    wildcard_hosts = [h for h in subdomains if WILDCARD_RE.match(h)]
    if wildcard_hosts:
        findings.append(_finding(
            'low',
            f'используются wildcard-сертификаты ({len(wildcard_hosts)})',
            ', '.join(wildcard_hosts) + ' — компрометация приватного ключа затрагивает все поддомены сразу'
        ))

    if not findings:
        findings.append(_finding('ok', 'подозрительных сертификатов или неожиданных поддоменов не найдено'))

    counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
    for f in findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    return {
        'domain': domain,
        'total_certificates': len(certs),
        'active_certificates': active_count,
        'subdomains': subdomains,
        'findings': findings,
        'summary': counts,
    }
