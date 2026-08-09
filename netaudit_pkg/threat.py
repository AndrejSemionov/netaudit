"""
Traffic suspiciousness scoring. Assigns each destination a risk_score (0..100),
risk_level (ok / suspicious / high), and a list of reasons.

Signals:
  REPUTATION:
    - user blocklist -> high risk
    - user allowlist / known-good organizations -> risk cleared
    - ASN/organization via whois (cached) - for context
  BEHAVIOR:
    - direct IP with no reverse DNS (common malware/C2 indicator)
    - non-standard port (not 80/443/53 etc)
    - known "bad" ports (IRC C2, telnet, etc)
    - unencrypted HTTP to an unknown host
    - anomalously many connections to one non-whitelisted address (beacon-like)
  LISTS: user's allow/block from the DB.

All heuristics are offline (whois is optional). The result feeds into the AI for
a human-facing assessment.
"""

from __future__ import annotations

import ipaddress

from .utils import run_cmd, tool_available
from . import storage

# Known-good organizations/domains - their traffic is usually legitimate.
KNOWN_GOOD_PATTERNS = [
    'google', 'gstatic', '1e100.net', 'cloudflare', 'amazonaws', 'akamai',
    'microsoft', 'apple.com', 'icloud', 'facebook', 'fbcdn', 'instagram', 'whatsapp',
    'fastly.net', 'youtube', 'ytimg', 'doubleclick', 'gvt1', 'gvt2',
    'telegram', 'cdninstagram', 'windowsupdate', 'office365', 'azureedge',
]

# IP ranges of known services that often have NO public reverse DNS (common
# practice for messengers/CDNs for privacy) - without this list, such
# addresses would falsely land in 'suspicious' just for lacking a PTR record.
# Source: official Telegram DC ranges (core.telegram.org/resources/cidr.txt).
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

# Common ports - their presence alone isn't suspicious.
COMMON_PORTS = {'80', '443', '53', '123', '993', '995', '587', '465', '853', '5223'}

# Ports often associated with threats / unwanted services.
SUSPICIOUS_PORTS = {
    '23': 'telnet (unencrypted remote access)',
    '6667': 'IRC (common botnet C2 channel)',
    '6666': 'IRC/C2',
    '4444': 'Metasploit default / backdoor',
    '1337': 'common backdoor port',
    '31337': 'classic backdoor (elite)',
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
    """Checks the IP/domain against the user's allow/block lists."""
    allow = storage.rep_list('allow')
    block = storage.rep_list('block')
    hay = f'{ip} {host or ""}'.lower()

    def matches(pattern: str) -> bool:
        p = pattern.lower().strip()
        if not p:
            return False
        # subnet?
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
    """ASN/organization via whois (cached in the DB). Best-effort - skipped if whois is absent."""
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
    Scores a single destination. Returns a copy with added
    risk_score, risk_level, reasons, (org/country if whois was used).
    dest: {'ip', 'host'?, 'ports'?, 'protocols'?, 'connections'?/'packets'?}
    """
    ip = dest.get('ip', '')
    host = dest.get('host')
    ports = set(dest.get('ports', []))
    conns = dest.get('connections') or dest.get('packets') or 0

    reasons: list[str] = []
    score = 0

    # user lists - highest priority
    allowed, blocked = _match_rep_lists(ip, host)
    if blocked:
        return {**dest, 'risk_score': 100, 'risk_level': 'high',
                'reasons': [f'on the blocklist: {blocked["pattern"]}' + (f' ({blocked["note"]})' if blocked.get('note') else '')]}
    if allowed:
        return {**dest, 'risk_score': 0, 'risk_level': 'ok',
                'reasons': [f'on the allowlist: {allowed["pattern"]}']}

    # private/LAN - usually not interesting
    if _is_private(ip):
        return {**dest, 'risk_score': 0, 'risk_level': 'ok', 'reasons': ['local network']}

    # known-good organization via DNS or IP range (for services with no public
    # reverse DNS, e.g. Telegram DC)
    good = _is_known_good(host) or _is_known_good_ip(ip)
    if good and not _is_known_good(host):
        reasons.append('known service (by IP range, no reverse DNS - normal practice for messengers)')
    elif good:
        reasons.append('known service (by DNS)')

    # direct IP with no reverse DNS - a suspicious signal
    if not host and not good:
        score += 30
        reasons.append('no reverse DNS (direct IP)')

    # ports
    non_common = ports - COMMON_PORTS
    for p in ports:
        if p in SUSPICIOUS_PORTS:
            score += 45
            reasons.append(f'port {p}: {SUSPICIOUS_PORTS[p]}')
    if non_common and not (ports & COMMON_PORTS) and not good:
        score += 20
        reasons.append(f'only non-standard ports: {", ".join(sorted(non_common))}')

    # unencrypted HTTP (port 80) to an unknown host
    if '80' in ports and '443' not in ports and not good:
        score += 15
        reasons.append('only unencrypted HTTP (80) to an unknown address')

    # anomalously many connections to one non-whitelisted address - possible beacon
    if conns and conns >= 20 and not good:
        score += 20
        reasons.append(f'many connections ({conns}) to one address - possible beacon')

    # whois enrichment (on demand, only for non-good ones - to avoid slowing things down)
    if do_whois and not good:
        info = enrich_asn(ip)
        if info.get('org'):
            dest = {**dest, 'org': info['org'], 'country': info.get('country')}
            reasons.append(f'ASN: {info["org"]}' + (f' ({info["country"]})' if info.get('country') else ''))

    if good:
        score = max(0, score - 40)  # a known service significantly lowers the risk

    score = min(100, score)
    level = 'high' if score >= 60 else ('suspicious' if score >= 25 else 'ok')
    return {**dest, 'risk_score': score, 'risk_level': level, 'reasons': reasons or ['no explicit signals']}


def score_destinations(dests: list[dict], do_whois: bool = False) -> dict:
    """
    Scores all destinations. Returns {'scored': [...], 'summary': {...}}.
    whois is only applied to suspicious ones (to avoid slowing down on legitimate traffic).
    """
    scored = []
    for d in dests:
        # first pass without whois - to figure out if it's suspicious at all
        s = score_destination(d, do_whois=False)
        # if suspicious and whois is allowed - enrich
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
