"""
Certificate Transparency monitoring via crt.sh.

crt.sh aggregates public CT logs (mandatory since RFC 6962 - every publicly
trusted TLS certificate must be logged there). Useful for:
  - discovering forgotten subdomains (staging/dev/old-admin etc) - they don't
    show up in a normal DNS brute-force, but a certificate was issued for
    them at some point, so there's a CT log entry;
  - discovering rogue/unexpected certificates for the domain - if someone
    issued a certificate for your domain without your knowledge (a
    compromised CA account, a DV validation bug, etc), this is where it
    surfaces first, ahead of anywhere else.

IMPORTANT (from real-world feedback): crt.sh is unstable, hit-or-miss on
availability and response time. Hence the short timeout and graceful skip
here - on a timeout/error we return a clear error instead of dragging down
or hanging the whole audit.

No API key needed, plain JSON endpoint: https://crt.sh/?q=%.domain.com&output=json
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone

import httpx

from ..registry import register

CRTSH_URL = 'https://crt.sh/'
# crt.sh is known to be unstable - don't wait long, a clean skip beats a hung audit
REQUEST_TIMEOUT = 12

# CAs worth an explicit warning about if a certificate was issued by someone
# else and the domain is expected to use a specific provider - not used
# directly yet, but useful for a future "expected CA vs actual" comparison

WILDCARD_RE = re.compile(r'^\*\.')


def _finding(severity, title, detail='', confidence='high', id=None):
    f = {'severity': severity, 'title': title, 'detail': detail, 'confidence': confidence}
    if id:
        f['id'] = id
    return f


def _fetch_certs(query: str) -> list[dict]:
    """Queries crt.sh, returns a list of records or raises an exception
    (handled by the caller - this keeps a purely network-layer function)."""
    resp = httpx.get(CRTSH_URL, params={'q': query, 'output': 'json'},
                      timeout=REQUEST_TIMEOUT,
                      headers={'User-Agent': 'NetAudit (github.com/AndrejSemionov/netaudit)'})
    resp.raise_for_status()
    return resp.json()


def _extract_hostnames(cert: dict) -> set[str]:
    """A single certificate's name_value can contain multiple lines (SAN)."""
    raw = cert.get('name_value', '')
    return {line.strip().lower() for line in raw.split('\n') if line.strip()}


def _parse_crtsh_date(s: str) -> datetime | None:
    """crt.sh returns dates like '2024-01-01T00:00:00' (sometimes with fractional seconds)."""
    if not s:
        return None
    for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M:%S.%f'):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


@register(
    id='cert_transparency', label='Certificate Transparency monitoring', category='site',
    params=[
        {'name': 'domain', 'type': 'text', 'label': 'Domain', 'default': 'example.com'},
        {'name': 'expected_issuer_contains', 'type': 'text',
         'label': 'Expected issuer contains (optional, e.g. "Let\'s Encrypt")', 'default': ''},
        {'name': 'include_expired', 'type': 'checkbox', 'label': 'Include expired certificates', 'default': False},
    ],
    required_tools=[],
    description='Searches for the domain\'s certificates and subdomains via public Certificate '
                'Transparency logs (crt.sh) - discovers forgotten subdomains (staging/dev/old-admin) '
                'and certificates issued by an unexpected authority. No server access needed.',
)
def check_cert_transparency(domain: str = 'example.com', expected_issuer_contains: str = '',
                             include_expired: bool = False) -> dict:
    if not domain:
        return {'error': 'domain not specified'}
    domain = domain.strip().lower().rstrip('.')

    try:
        certs = _fetch_certs(f'%.{domain}')
    except httpx.TimeoutException:
        return {'error': f'crt.sh did not respond within {REQUEST_TIMEOUT}s — the service is unstable, try again later'}
    except httpx.HTTPStatusError as e:
        return {'error': f'crt.sh returned HTTP {e.response.status_code} — the service may be temporarily overloaded'}
    except httpx.HTTPError as e:
        return {'error': f'crt.sh is unreachable: {e}'}
    except ValueError:
        return {'error': 'crt.sh returned a non-JSON response (the service is unstable) — try again later'}

    if not certs:
        return {'domain': domain, 'total_certificates': 0, 'subdomains': [], 'findings': [],
                'summary': {'high': 0, 'medium': 0, 'low': 0, 'ok': 1},
                'note': 'no certificates found — either the domain doesn\'t use HTTPS, or it\'s not in the CT logs yet'}

    now = datetime.now(timezone.utc)
    findings = []

    # ---- subdomains: collect unique hosts, flag "interesting" ones by keyword ----
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
            # strip the wildcard prefix for keyword matching, but keep it as-is in the output
            bare = WILDCARD_RE.sub('', host)
            if not bare.endswith(domain):
                continue  # a SAN for an unrelated domain on the same cert (happens with multi-domain certs)
            hostnames_seen[host].append(cert.get('id'))
            issuers_by_host[host].add(issuer)

    subdomains = sorted(hostnames_seen.keys())
    interesting = [h for h in subdomains if any(kw in h for kw in INTERESTING_KEYWORDS)]

    if interesting:
        findings.append(_finding(
            'medium',
            f'potentially sensitive hostname(s) discovered ({len(interesting)})',
            ', '.join(interesting[:20]) + (' …' if len(interesting) > 20 else '') +
            ' — a hostname matching a keyword like staging/dev/admin doesn\'t by itself mean it was '
            'forgotten or is exposed; verify whether it\'s still needed and properly access-controlled',
            confidence='low'
        ))

    # ---- unexpected issuer ----
    if expected_issuer_contains:
        needle = expected_issuer_contains.strip().lower()
        unexpected = {h: iss for h, iss in issuers_by_host.items()
                      if not any(needle in i.lower() for i in iss)}
        if unexpected:
            sample = list(unexpected.items())[:10]
            detail = '; '.join(f'{h}: {", ".join(iss)}' for h, iss in sample)
            findings.append(_finding(
                'high',
                f'certificates from an unexpected issuer ({len(unexpected)} host(s))',
                detail + (' …' if len(unexpected) > 10 else '')
            ))

    # ---- wildcard certificates - not a finding on its own, but useful to know ----
    wildcard_hosts = [h for h in subdomains if WILDCARD_RE.match(h)]
    if wildcard_hosts:
        findings.append(_finding(
            'low',
            f'wildcard certificates in use ({len(wildcard_hosts)})',
            ', '.join(wildcard_hosts) + ' — a compromised private key affects all subdomains at once'
        ))

    if not findings:
        findings.append(_finding('ok', 'no suspicious certificates or unexpected subdomains found'))

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
