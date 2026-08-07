"""
DNS-аудит домена: SPF, DKIM, DMARC, DNSSEC, висящие CNAME.

Все проверки через `dig` (без прямого доступа к серверу — чисто DNS-запросы,
работает для любого домена). Каждая находка — severity (high/medium/low/ok).
"""

from __future__ import annotations

import re

from ..registry import register
from ..utils import run_cmd, tool_available

# частые DKIM-селекторы — DKIM не публикует список селекторов нигде в DNS,
# так что приходится перебирать самые распространённые (mail-провайдеры и
# популярные ESP используют предсказуемые имена)
COMMON_DKIM_SELECTORS = [
    'default', 'selector1', 'selector2', 'google', 'k1', 'k2',
    'dkim', 'mail', 's1', 's2', 'smtp', 'mx',
]

# verification-токены в TXT-записях домена выдают, какими сторонними сервисами
# пользуется владелец — полезно для профилирования инфраструктуры цели
# (Atlassian/Jira, Google Workspace, DocuSign, MS 365, Facebook Business и т.д.)
TXT_SERVICE_PATTERNS = [
    (r'google-site-verification=', 'Google (Search Console / Workspace)'),
    (r'atlassian-domain-verification=', 'Atlassian (Jira/Confluence)'),
    (r'docusign=', 'DocuSign'),
    (r'MS=ms\d+', 'Microsoft 365'),
    (r'facebook-domain-verification=', 'Facebook Business'),
    (r'stripe-verification=', 'Stripe'),
    (r'zoom-domain-verification=', 'Zoom'),
    (r'apple-domain-verification=', 'Apple (Business Manager)'),
    (r'shopify-verification-code=', 'Shopify'),
    (r'hubspot-developer-verification=', 'HubSpot'),
    (r'AFDVERIFICATION=|AFDVALIDATION=', 'Azure Front Door'),
    (r'MSFT=', 'Microsoft (generic)'),
    (r'v=spf1', None),   # уже разбирается отдельно как SPF, не дублируем
    (r'v=DMARC1', None),  # уже разбирается отдельно как DMARC
]


def _finding(severity, title, detail=''):
    return {'severity': severity, 'title': title, 'detail': detail}


def _dig_txt(name: str) -> list[str]:
    """TXT-записи для имени, возвращает список сырых строк (без кавычек)."""
    code, out, _ = run_cmd(['dig', '+short', 'TXT', name], timeout=10)
    if code != 0:
        return []
    records = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        # dig отдаёт значения в кавычках, склеенные части — убираем кавычки
        records.append(line.strip('"').replace('" "', ''))
    return records


def _dig_cname(name: str) -> str | None:
    code, out, _ = run_cmd(['dig', '+short', 'CNAME', name], timeout=10)
    if code != 0 or not out.strip():
        return None
    return out.strip().splitlines()[0].rstrip('.')


def _resolves(name: str) -> bool:
    """Есть ли хоть какой-то A/AAAA/CNAME-ответ для имени."""
    for rtype in ('A', 'AAAA'):
        code, out, _ = run_cmd(['dig', '+short', rtype, name], timeout=10)
        if code == 0 and out.strip():
            return True
    return False


# ===========================================================================
# SPF
# ===========================================================================

def _check_spf(domain: str) -> list[dict]:
    findings = []
    txts = _dig_txt(domain)
    spf_records = [t for t in txts if t.startswith('v=spf1')]

    if not spf_records:
        findings.append(_finding('high', 'нет SPF-записи',
                                 f'домен {domain} не публикует SPF — письма легко подделать (спуфинг)'))
        return findings

    if len(spf_records) > 1:
        findings.append(_finding('high', 'несколько SPF-записей',
                                 'RFC разрешает только одну TXT со spf1 — приёмники должны игнорировать все, почта может не проходить'))

    spf = spf_records[0]
    # приблизительный подсчёт DNS-lookup-механизмов (include/a/mx/exists/redirect
    # без параметра IP) — лимит RFC 7208 — 10, превышение ломает всю SPF-проверку
    lookup_mechanisms = re.findall(r'(?:include|a|mx|exists|redirect)(?::\S+)?(?=\s|$)', spf)
    lookup_count = len(lookup_mechanisms)
    if lookup_count > 10:
        findings.append(_finding('high', f'SPF превышает лимит DNS-lookup ({lookup_count}/10)',
                                 'RFC 7208: >10 lookup — приёмники обязаны считать SPF ошибочным, вся защита отключается'))
    elif lookup_count > 7:
        findings.append(_finding('medium', f'SPF близко к лимиту lookup ({lookup_count}/10)',
                                 'запас небольшой — добавление ещё одного include может сломать SPF'))

    if not spf.rstrip().endswith(('-all', '~all')):
        if spf.rstrip().endswith('?all') or spf.rstrip().endswith('+all'):
            findings.append(_finding('high', 'SPF заканчивается на +all/?all',
                                     'фактически разрешает слать от имени домена откуда угодно — SPF бесполезен'))
        else:
            findings.append(_finding('low', 'SPF не завершён явным all',
                                     'без -all/~all политика неопределённая для приёмника'))

    if not findings:
        findings.append(_finding('ok', 'SPF настроен корректно', spf))
    return findings


# ===========================================================================
# DKIM
# ===========================================================================

def _check_dkim(domain: str) -> list[dict]:
    found = []
    for selector in COMMON_DKIM_SELECTORS:
        name = f'{selector}._domainkey.{domain}'
        txts = _dig_txt(name)
        dkim_txt = next((t for t in txts if 'p=' in t), None)
        if dkim_txt:
            found.append((selector, dkim_txt))

    if not found:
        return [_finding('medium', 'DKIM не обнаружен (по частым селекторам)',
                         'проверены стандартные имена: ' + ', '.join(COMMON_DKIM_SELECTORS) +
                         ' — реальный селектор может отличаться, спроси у провайдера почты')]

    findings = []
    for selector, txt in found:
        if 'p=' in txt and re.search(r'p=\s*;', txt):
            findings.append(_finding('high', f'DKIM-селектор {selector} отозван (пустой p=)',
                                     'ключ отозван или ещё не сгенерирован — подпись не работает'))
        else:
            findings.append(_finding('ok', f'DKIM-селектор {selector} найден и активен'))
    return findings


# ===========================================================================
# DMARC
# ===========================================================================

def _check_dmarc(domain: str) -> list[dict]:
    name = f'_dmarc.{domain}'
    txts = _dig_txt(name)
    dmarc_txt = next((t for t in txts if t.startswith('v=DMARC1')), None)

    if not dmarc_txt:
        return [_finding('high', 'нет DMARC-записи',
                         'без DMARC приёмники не знают, что делать с письмами, не прошедшими SPF/DKIM')]

    findings = []
    policy_m = re.search(r'p=(\w+)', dmarc_txt)
    policy = policy_m.group(1) if policy_m else None

    if policy == 'none':
        has_rua = 'rua=' in dmarc_txt
        if has_rua:
            findings.append(_finding('low', 'DMARC p=none (только мониторинг)',
                                     'отчёты собираются (rua настроен), но реальной защиты от спуфинга нет — план перехода на quarantine/reject'))
        else:
            findings.append(_finding('medium', 'DMARC p=none без отчётов (rua)',
                                     'ни защиты, ни видимости — DMARC фактически бесполезен в этом виде'))
    elif policy in ('quarantine', 'reject'):
        findings.append(_finding('ok', f'DMARC активен: p={policy}', dmarc_txt))
    else:
        findings.append(_finding('medium', 'DMARC без распознанной политики p=', dmarc_txt))

    return findings


# ===========================================================================
# DNSSEC
# ===========================================================================

def _check_dnssec(domain: str) -> list[dict]:
    code, out, _ = run_cmd(['dig', '+dnssec', '+short', 'DNSKEY', domain], timeout=10)
    if code != 0 or not out.strip():
        return [_finding('medium', 'DNSSEC не включён',
                         'зона не подписана — DNS-ответы можно подделать (cache poisoning), особенно на открытых резолверах')]

    code_ds, out_ds, _ = run_cmd(['dig', '+short', 'DS', domain], timeout=10)
    if code_ds == 0 and out_ds.strip():
        return [_finding('ok', 'DNSSEC включён, DS-запись у родительской зоны присутствует')]
    return [_finding('medium', 'DNSKEY есть, но нет DS-записи у регистратора',
                     'зона подписана, но цепочка доверия не замкнута — добавь DS-запись у регистратора домена')]


# ===========================================================================
# Висящие CNAME (subdomain takeover risk)
# ===========================================================================

# частые "мусорные" цели, оставшиеся от закрытых сервисов — если CNAME
# указывает сюда, а сам таргет не резолвится в этот сервис активно, это
# классический subdomain takeover
DANGLING_TARGET_HINTS = [
    'github.io', 'herokuapp.com', 'azurewebsites.net', 's3.amazonaws.com',
    'cloudfront.net', 'netlify.app', 'vercel.app', 'wordpress.com',
    'shopify.com', 'fastly.net', 'pantheonsite.io',
]


def _check_dangling_cnames(domain: str, subdomains: list[str]) -> list[dict]:
    findings = []
    checked = 0
    for sub in subdomains:
        full = f'{sub}.{domain}' if sub else domain
        cname = _dig_cname(full)
        if not cname:
            continue
        checked += 1
        if not _resolves(cname):
            hint = next((h for h in DANGLING_TARGET_HINTS if h in cname), None)
            severity = 'high' if hint else 'medium'
            findings.append(_finding(severity, f'висящий CNAME: {full} → {cname}',
                                     'цель не резолвится — риск subdomain takeover, если сервис-платформа свободно раздаёт такие имена'
                                     + (f' (похоже на {hint})' if hint else '')))
    if checked and not findings:
        findings.append(_finding('ok', f'проверено CNAME-целей: {checked}, висящих не найдено'))
    return findings


# ===========================================================================
# Обнаруженные сторонние сервисы (через verification-токены в TXT)
# ===========================================================================

def _check_discovered_services(domain: str) -> list[dict]:
    txts = _dig_txt(domain)
    found = []
    for txt in txts:
        for pattern, label in TXT_SERVICE_PATTERNS:
            if label is None:
                continue  # SPF/DMARC — не дублируем, у них своя секция
            if re.search(pattern, txt, re.IGNORECASE):
                found.append(label)

    if not found:
        return [_finding('ok', 'сторонних verification-токенов в TXT не обнаружено')]

    findings = []
    for label in sorted(set(found)):
        findings.append(_finding('low', f'обнаружен сервис: {label}',
                                 'verification-токен в TXT-записи — раскрывает используемую инфраструктуру'))
    return findings


# ===========================================================================
# Комбинированная проверка
# ===========================================================================

@register(
    id='dns_audit', label='DNS-аудит домена', category='site',
    params=[
        {'name': 'domain', 'type': 'text', 'label': 'Домен', 'default': 'example.com'},
        {'name': 'subdomains_to_check', 'type': 'text', 'label': 'Поддомены для CNAME-проверки (через запятую)',
         'default': 'www,mail,blog,shop,cdn,static'},
    ],
    required_tools=['dig'],
    description='SPF/DKIM/DMARC/DNSSEC + поиск висящих CNAME (subdomain takeover). Только DNS-запросы, без доступа к серверу.',
)
def check_dns_audit(domain: str = 'example.com', subdomains_to_check: str = 'www,mail,blog,shop,cdn,static') -> dict:
    if not tool_available('dig'):
        return {'error': 'dig не установлен (apt install dnsutils)'}
    if not domain:
        return {'error': 'не указан domain'}

    domain = domain.strip().rstrip('.')
    subs = [s.strip() for s in subdomains_to_check.split(',') if s.strip()]

    sections = {
        'spf': _check_spf(domain),
        'dkim': _check_dkim(domain),
        'dmarc': _check_dmarc(domain),
        'dnssec': _check_dnssec(domain),
        'dangling_cname': _check_dangling_cnames(domain, subs),
        'discovered_services': _check_discovered_services(domain),
    }

    counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
    for findings in sections.values():
        for f in findings:
            counts[f['severity']] = counts.get(f['severity'], 0) + 1

    return {'domain': domain, 'sections': sections, 'summary': counts}
