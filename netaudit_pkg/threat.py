"""
Оценка подозрительности трафика. Каждому назначению ставит risk_score (0..100),
risk_level (ok / suspicious / high) и список причин (reasons).

Сигналы:
  РЕПУТАЦИЯ:
    - чёрный список пользователя -> высокий риск
    - белый список / известные хорошие организации -> риск снят
    - ASN/организация через whois (кэш) — для контекста
  ПОВЕДЕНИЕ:
    - прямой IP без обратного DNS (частый признак malware/C2)
    - нестандартный порт (не 80/443/53 и т.п.)
    - известные «плохие» порты (IRC C2, telnet и т.п.)
    - незашифрованный HTTP к неизвестному хосту
    - аномально много соединений к одному не-белому адресу (маячок/beacon)
  СПИСКИ: allow/block из БД (пользовательские).

Всё offline-эвристики (whois опционально). Итог отдаётся в AI для человеческой оценки.
"""

from __future__ import annotations

import ipaddress
import re

from .utils import run_cmd, tool_available
from . import storage

# Известные «хорошие» организации/домены — их трафик обычно легитимен.
KNOWN_GOOD_PATTERNS = [
    'google', 'gstatic', '1e100.net', 'cloudflare', 'amazonaws', 'akamai',
    'microsoft', 'apple.com', 'icloud', 'facebook', 'fbcdn', 'instagram', 'whatsapp',
    'fastly.net', 'youtube', 'ytimg', 'doubleclick', 'gvt1', 'gvt2',
    'telegram', 'cdninstagram', 'windowsupdate', 'office365', 'azureedge',
]

# IP-диапазоны известных сервисов, у которых часто НЕТ публичного reverse DNS
# (обычная практика для мессенджеров/CDN ради приватности) — без этого списка
# такие адреса ложно попадали бы в 'suspicious' только из-за отсутствия PTR-записи.
# Источник: official Telegram DC ranges (core.telegram.org/resources/cidr.txt).
KNOWN_GOOD_CIDRS = [
    '149.154.160.0/20',   # Telegram DC
    '91.108.4.0/22',      # Telegram DC
    '91.108.8.0/22',      # Telegram DC
    '91.108.12.0/22',     # Telegram DC
    '91.108.16.0/22',     # Telegram DC
    '91.108.56.0/22',     # Telegram DC
    '109.239.140.0/24',   # Telegram DC
]


def _is_known_good_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in KNOWN_GOOD_CIDRS:
        if addr in ipaddress.ip_network(cidr):
            return True
    return False

# Обычные порты — их наличие само по себе не подозрительно.
COMMON_PORTS = {'80', '443', '53', '123', '993', '995', '587', '465', '853', '5223'}

# Порты, часто ассоциируемые с угрозами / нежелательными сервисами.
SUSPICIOUS_PORTS = {
    '23': 'telnet (незашифрованный удалённый доступ)',
    '6667': 'IRC (частый C2-канал ботнетов)',
    '6666': 'IRC/C2',
    '4444': 'Metasploit default / бэкдор',
    '1337': 'частый порт бэкдоров',
    '31337': 'классический бэкдор (elite)',
    '9001': 'Tor / C2',
    '9030': 'Tor',
}


def _is_known_good(host: str | None) -> bool:
    if not host:
        return False
    h = host.lower()
    return any(p in h for p in KNOWN_GOOD_PATTERNS)


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _match_rep_lists(ip: str, host: str | None):
    """Проверяет IP/домен по пользовательским allow/block спискам."""
    allow = storage.rep_list('allow')
    block = storage.rep_list('block')
    hay = f'{ip} {host or ""}'.lower()

    def matches(pattern: str) -> bool:
        p = pattern.lower().strip()
        if not p:
            return False
        # подсеть?
        if '/' in p:
            try:
                return ipaddress.ip_address(ip) in ipaddress.ip_network(p, strict=False)
            except ValueError:
                return False
        return p in hay

    blocked = next((r for r in block if matches(r['pattern'])), None)
    allowed = next((r for r in allow if matches(r['pattern'])), None)
    return allowed, blocked


def enrich_asn(ip: str) -> dict:
    """ASN/организация через whois (с кэшем в БД). Лучший effort — если whois нет, пропускаем."""
    if _is_private(ip):
        return {'org': 'private/LAN', 'country': None}
    cached = storage.asn_get(ip)
    if cached:
        return cached
    if not tool_available('whois'):
        return {'org': None, 'country': None}
    code, out, err = run_cmd(['whois', ip], timeout=10)
    if code != 0:
        storage.asn_set(ip, None, None)
        return {'org': None, 'country': None}
    org = country = None
    for line in out.splitlines():
        l = line.lower()
        if org is None and (l.startswith('orgname:') or l.startswith('org-name:') or l.startswith('organization:') or l.startswith('descr:')):
            org = line.split(':', 1)[1].strip()
        if country is None and l.startswith('country:'):
            country = line.split(':', 1)[1].strip()
    storage.asn_set(ip, org, country)
    return {'org': org, 'country': country}


def score_destination(dest: dict, do_whois: bool = False) -> dict:
    """
    Оценивает одно назначение. Возвращает копию с добавленными
    risk_score, risk_level, reasons, (org/country если whois).
    dest: {'ip', 'host'?, 'ports'?, 'protocols'?, 'connections'?/'packets'?}
    """
    ip = dest.get('ip', '')
    host = dest.get('host')
    ports = set(dest.get('ports', []))
    protocols = set(p.lower() for p in dest.get('protocols', []))
    conns = dest.get('connections') or dest.get('packets') or 0

    reasons: list[str] = []
    score = 0

    # пользовательские списки — высший приоритет
    allowed, blocked = _match_rep_lists(ip, host)
    if blocked:
        return {**dest, 'risk_score': 100, 'risk_level': 'high',
                'reasons': [f'в чёрном списке: {blocked["pattern"]}' + (f' ({blocked["note"]})' if blocked.get('note') else '')]}
    if allowed:
        return {**dest, 'risk_score': 0, 'risk_level': 'ok',
                'reasons': [f'в белом списке: {allowed["pattern"]}']}

    # приватный/LAN — обычно не интересен
    if _is_private(ip):
        return {**dest, 'risk_score': 0, 'risk_level': 'ok', 'reasons': ['локальная сеть']}

    # известная хорошая организация по DNS или по IP-диапазону (для сервисов
    # без публичного reverse DNS, напр. Telegram DC)
    good = _is_known_good(host) or _is_known_good_ip(ip)
    if good and not _is_known_good(host):
        reasons.append('известный сервис (по IP-диапазону, без reverse DNS — обычная практика для мессенджеров)')
    elif good:
        reasons.append('известный сервис (по DNS)')

    # прямой IP без обратного DNS — подозрительный сигнал
    if not host and not good:
        score += 30
        reasons.append('нет обратного DNS (прямой IP)')

    # порты
    non_common = ports - COMMON_PORTS
    for p in ports:
        if p in SUSPICIOUS_PORTS:
            score += 45
            reasons.append(f'порт {p}: {SUSPICIOUS_PORTS[p]}')
    if non_common and not (ports & COMMON_PORTS) and not good:
        score += 20
        reasons.append(f'только нестандартные порты: {", ".join(sorted(non_common))}')

    # незашифрованный HTTP (порт 80) к неизвестному хосту
    if '80' in ports and '443' not in ports and not good:
        score += 15
        reasons.append('только незашифрованный HTTP (80) к неизвестному адресу')

    # аномально много соединений к одному не-белому адресу — возможный beacon
    if conns and conns >= 20 and not good:
        score += 20
        reasons.append(f'много соединений ({conns}) к одному адресу — возможен маячок/beacon')

    # whois-обогащение (по запросу, для не-хороших — чтобы не тормозить)
    if do_whois and not good:
        info = enrich_asn(ip)
        if info.get('org'):
            dest = {**dest, 'org': info['org'], 'country': info.get('country')}
            reasons.append(f'ASN: {info["org"]}' + (f' ({info["country"]})' if info.get('country') else ''))

    if good:
        score = max(0, score - 40)  # известный сервис сильно снижает риск

    score = min(100, score)
    level = 'high' if score >= 60 else ('suspicious' if score >= 25 else 'ok')
    return {**dest, 'risk_score': score, 'risk_level': level, 'reasons': reasons or ['без явных сигналов']}


def score_destinations(dests: list[dict], do_whois: bool = False) -> dict:
    """
    Оценивает все назначения. Возвращает {'scored': [...], 'summary': {...}}.
    whois применяется только к подозрительным (чтобы не тормозить на легитимных).
    """
    scored = []
    for d in dests:
        # первый проход без whois — чтобы понять, подозрительно ли
        s = score_destination(d, do_whois=False)
        # если подозрительно и разрешён whois — обогащаем
        if do_whois and s['risk_level'] != 'ok':
            s = score_destination(d, do_whois=True)
        scored.append(s)

    scored.sort(key=lambda x: x['risk_score'], reverse=True)
    high = [s for s in scored if s['risk_level'] == 'high']
    susp = [s for s in scored if s['risk_level'] == 'suspicious']
    return {
        'scored': scored,
        'summary': {
            'total': len(scored),
            'high': len(high),
            'suspicious': len(susp),
            'ok': len(scored) - len(high) - len(susp),
        },
    }
