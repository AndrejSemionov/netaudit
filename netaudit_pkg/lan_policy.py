"""
The owner's access rules for a client's network and how one observation is
judged by them (docs/research/network_access_policy.md §3).

A rule says that from a source (a private subnet or address, or any) to a
destination, a service (a named group of ports, one TCP port, or any) is
allowed or forbidden. An observation is (NetAudit's own address, a device,
an open TCP port): its source is always the machine the audit ran on.

- The most specific matching rule decides: destination first (an address,
  then a longer prefix), then the source, then the service (a port, a named
  group, any).
- Two matching rules of equal specificity that disagree are a conflict.
- No matching rule is unknown - the owner said nothing; never "forbidden".

Rules are data the audit judges against. Nothing here touches a device.
"""

from __future__ import annotations

import ipaddress
import re

MAX_RULES = 200
NOTE_MAX = 200
MAX_EXTRA_PORTS = 20
DECISIONS = ('allow', 'forbid')
_PRIVATE = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
_ID = re.compile(r'r\d{1,6}')
_PORT = re.compile(r'tcp/(\d{1,5})')

# the named services: the ones isolation knows (checks/lan_audit.SENSITIVE_SERVICES)
SERVICES = {
    'SMB': (139, 445), 'RDP': (3389,), 'WinRM': (5985,), 'VNC': (5900,), 'SSH': (22,), 'NFS': (2049,),
    'rsync': (873,), 'SQL Server': (1433,), 'Oracle': (1521,), 'MySQL': (3306,), 'PostgreSQL': (5432,),
    'Redis': (6379,), 'Elasticsearch': (9200,), 'memcached': (11211,), 'MongoDB': (27017,),
}
_BY_LOWER = {name.lower(): name for name in SERVICES}


def _address(value, field: str, n: int) -> str:
    """'any', one private address, or a private subnet; '/32' is an address."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f'rule {n}: {field} is empty or not text')
    value = value.strip()
    if value.lower() == 'any':
        return 'any'
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise ValueError(f'rule {n}: {field} is not an address or a subnet: {value[:60]!r}') from None
    if net.version != 4 or not any(net.subnet_of(p) for p in _PRIVATE):
        raise ValueError(f'rule {n}: {field} must be private (10/8, 172.16/12, 192.168/16)')
    return str(net.network_address) if net.prefixlen == 32 else str(net)


def _service(value, n: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f'rule {n}: service is empty or not text')
    value = value.strip()
    if value.lower() == 'any':
        return 'any'
    m = _PORT.fullmatch(value.lower())
    if m:
        number = int(m.group(1))
        if not 1 <= number <= 65535:
            raise ValueError(f'rule {n}: port {number} is out of range')
        return f'tcp/{number}'
    if value.lower() in _BY_LOWER:
        return _BY_LOWER[value.lower()]
    raise ValueError(f'rule {n}: unknown service {value[:40]!r} (any, tcp/<port> or one of '
                     f'{", ".join(SERVICES)})')


def _net(address: str):
    return None if address == 'any' else ipaddress.ip_network(address)


def _within(inner: str, outer: str) -> bool:
    if outer == 'any':
        return True
    if inner == 'any':
        return False
    return _net(inner).subnet_of(_net(outer))


def _ports(service: str) -> tuple | None:
    """The ports of a service; None is any port."""
    if service == 'any':
        return None
    if service.startswith('tcp/'):
        return (int(service[4:]),)
    return SERVICES[service]


def _service_within(inner: str, outer: str) -> bool:
    if outer == 'any':
        return True
    if inner == 'any':
        return False
    return set(_ports(inner)) <= set(_ports(outer))


def _rank(address: str) -> int:
    if address == 'any':
        return -1
    net = _net(address)
    return 33 if net.prefixlen == 32 else net.prefixlen


def specificity(rule: dict) -> tuple:
    """Destination, then source, then service (§3.3)."""
    service = 0 if rule['service'] == 'any' else 2 if rule['service'].startswith('tcp/') else 1
    return (_rank(rule['destination']), _rank(rule['source']), service)


def _covers(rule: dict, other: dict) -> bool:
    return (_within(other['source'], rule['source']) and _within(other['destination'], rule['destination'])
            and _service_within(other['service'], rule['service']))


def validate(rules) -> list[dict]:
    """The rules normalized, or ValueError naming the first bad one. An
    allow more specific than a forbid it sits inside is an exception and
    must say why (§3.1)."""
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise ValueError(f'rules: a list of at most {MAX_RULES} rules per client')
    out = []
    for n, rule in enumerate(rules, 1):
        if not isinstance(rule, dict) or not rule:
            raise ValueError(f'rule {n}: an object with source, destination, service and decision')
        decision = rule.get('decision')
        if not isinstance(decision, str) or decision.strip().lower() not in DECISIONS:
            raise ValueError(f'rule {n}: decision is allow or forbid')
        note = rule.get('note', '')
        if note is None:
            note = ''
        if not isinstance(note, str) or len(note.strip()) > NOTE_MAX:
            raise ValueError(f'rule {n}: a note of at most {NOTE_MAX} characters')
        clean = {'source': _address(rule.get('source'), 'source', n),
                 'destination': _address(rule.get('destination'), 'destination', n),
                 'service': _service(rule.get('service'), n), 'decision': decision.strip().lower(),
                 'note': note.strip()}
        if 'id' in rule:
            if not isinstance(rule['id'], str) or not _ID.fullmatch(rule['id']):
                raise ValueError(f'rule {n}: an id like r1')
            clean = {'id': rule['id'], **clean}
        out.append(clean)
    for n, rule in enumerate(out, 1):
        if rule['decision'] != 'allow' or rule['note']:
            continue
        for m, other in enumerate(out, 1):
            if (other['decision'] == 'forbid' and _covers(other, rule)
                    and specificity(rule) != specificity(other) and not _covers(rule, other)):
                raise ValueError(f'rule {n}: an exception to rule {m} needs a note - why this access is allowed')
    return out


def applies_from(rule: dict, source: str) -> bool:
    return rule['source'] == 'any' or ipaddress.ip_address(source) in _net(rule['source'])


def _matches(rule: dict, source: str, destination: str, number: int) -> bool:
    if not applies_from(rule, source):
        return False
    if rule['destination'] != 'any' and ipaddress.ip_address(destination) not in _net(rule['destination']):
        return False
    ports = _ports(rule['service'])
    return ports is None or number in ports


def evaluate(rules: list[dict], source: str, destination: str, number: int) -> dict:
    """{'decision': allow | forbid | conflict | unknown, 'rules': [ids]}."""
    matching = [r for r in rules if _matches(r, source, destination, number)]
    if not matching:
        return {'decision': 'unknown', 'rules': []}
    best = max(specificity(r) for r in matching)
    top = [r for r in matching if specificity(r) == best]
    decisions = {r['decision'] for r in top}
    return {'decision': decisions.pop() if len(decisions) == 1 else 'conflict',
            'rules': [r.get('id', '') for r in top]}


def destination_contains(rule: dict, ip: str) -> bool:
    return rule['destination'] == 'any' or ipaddress.ip_address(ip) in _net(rule['destination'])


def destination_overlaps(rule: dict, cidr: str) -> bool:
    return rule['destination'] == 'any' or _net(rule['destination']).overlaps(ipaddress.ip_network(cidr))


def destination_within(rule: dict, cidr: str) -> bool:
    return rule['destination'] != 'any' and _net(rule['destination']).subnet_of(ipaddress.ip_network(cidr))


def rule_ports(rule: dict) -> tuple | None:
    return _ports(rule['service'])


def extra_ports(rules: list[dict], source: str, probed) -> tuple[list[int], list[int]]:
    """(ports to probe besides `probed`, ports over the cap): the single
    ports of the forbid rules that apply from `source` (§3.5)."""
    wanted = sorted({int(r['service'][4:]) for r in rules
                     if r['decision'] == 'forbid' and r['service'].startswith('tcp/') and applies_from(r, source)}
                    - set(probed))
    return wanted[:MAX_EXTRA_PORTS], wanted[MAX_EXTRA_PORTS:]


def extra_targets(rules: list[dict], source: str, hosts, ports) -> dict[str, list[int]]:
    """{host: [extra ports]}: each host gets the extra ports of the forbid
    rules whose destination holds it - nothing else is probed."""
    allowed = set(ports)
    out: dict[str, list[int]] = {}
    for ip in hosts:
        mine = {int(r['service'][4:]) for r in rules
                if r['decision'] == 'forbid' and r['service'].startswith('tcp/') and applies_from(r, source)
                and destination_contains(r, ip)} & allowed
        if mine:
            out[ip] = sorted(mine)
    return out
