"""
DNS domain audit: SPF, DKIM, DMARC, DNSSEC, dangling CNAME.

All checks via `dig` (no direct server access needed - pure DNS queries,
works for any domain). Each finding gets a severity (high/medium/low/ok).
"""

from __future__ import annotations

import re

from ..registry import register
from ..utils import run_cmd, tool_available

# common DKIM selectors - DKIM doesn't publish a list of selectors anywhere in
# DNS, so the most common ones have to be brute-forced (mail providers and
# popular ESPs use predictable names)
COMMON_DKIM_SELECTORS = [
    'default', 'selector1', 'selector2', 'google', 'k1', 'k2',
    'dkim', 'mail', 's1', 's2', 'smtp', 'mx',
]

# verification tokens in domain TXT records reveal which third-party services
# the owner uses - useful for profiling a target's infrastructure
# (Atlassian/Jira, Google Workspace, DocuSign, MS 365, Facebook Business, etc)
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
    (r'v=spf1', None),   # already handled separately as SPF, don't duplicate
    (r'v=DMARC1', None),  # already handled separately as DMARC
]


def _finding(severity, title, detail='', confidence='high', id=None):
    f = {'severity': severity, 'title': title, 'detail': detail, 'confidence': confidence}
    if id:
        f['id'] = id
    return f


def _dig_txt(name: str) -> list[str]:
    """TXT records for a name, returns a list of raw strings (unquoted)."""
    code, out, _ = run_cmd(['dig', '+short', 'TXT', name], timeout=10)
    if code != 0:
        return []
    records = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        # dig returns values quoted, with parts concatenated - strip the quotes
        records.append(line.strip('"').replace('" "', ''))
    return records


def _dig_cname(name: str) -> str | None:
    code, out, _ = run_cmd(['dig', '+short', 'CNAME', name], timeout=10)
    if code != 0 or not out.strip():
        return None
    return out.strip().splitlines()[0].rstrip('.')


def _resolves(name: str) -> bool:
    """Whether there's any A/AAAA/CNAME response for the name."""
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
        findings.append(_finding('high', 'no SPF record',
                                 f'domain {domain} doesn\'t publish SPF — emails are easy to spoof'))
        return findings

    if len(spf_records) > 1:
        findings.append(_finding('high', 'multiple SPF records',
                                 'RFC allows only one spf1 TXT — receivers should ignore all of them, mail may not go through'))

    spf = spf_records[0]
    # rough count of DNS-lookup mechanisms (include/a/mx/exists/redirect
    # without an IP argument) - the RFC 7208 limit is 10, exceeding it breaks the whole SPF check
    lookup_mechanisms = re.findall(r'(?:include|a|mx|exists|redirect)(?::\S+)?(?=\s|$)', spf)
    lookup_count = len(lookup_mechanisms)
    if lookup_count > 10:
        findings.append(_finding('high', f'SPF exceeds the DNS-lookup limit ({lookup_count}/10)',
                                 'RFC 7208: >10 lookups — receivers must treat SPF as an error, all protection is disabled'))
    elif lookup_count > 7:
        findings.append(_finding('medium', f'SPF is close to the lookup limit ({lookup_count}/10)',
                                 'not much headroom left — adding one more include could break SPF'))

    if not spf.rstrip().endswith(('-all', '~all')):
        if spf.rstrip().endswith('?all') or spf.rstrip().endswith('+all'):
            findings.append(_finding('high', 'SPF ends with +all/?all',
                                     'effectively allows sending as this domain from anywhere — SPF is useless'))
        else:
            findings.append(_finding('low', 'SPF has no explicit all mechanism at the end',
                                     'without -all/~all the policy is undefined for the receiver'))

    if not findings:
        findings.append(_finding('ok', 'SPF is configured correctly', spf))
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
        return [_finding('medium', 'no DKIM found (checked common selectors)',
                         'checked standard names: ' + ', '.join(COMMON_DKIM_SELECTORS) +
                         ' — the real selector may differ, ask your mail provider')]

    findings = []
    for selector, txt in found:
        if 'p=' in txt and re.search(r'p=\s*;', txt):
            findings.append(_finding('high', f'DKIM selector {selector} is revoked (empty p=)',
                                     'the key was revoked or hasn\'t been generated yet — signing isn\'t working'))
        else:
            findings.append(_finding('ok', f'DKIM selector {selector} found and active'))
    return findings


# ===========================================================================
# DMARC
# ===========================================================================

def _check_dmarc(domain: str) -> list[dict]:
    name = f'_dmarc.{domain}'
    txts = _dig_txt(name)
    dmarc_txt = next((t for t in txts if t.startswith('v=DMARC1')), None)

    if not dmarc_txt:
        return [_finding('high', 'no DMARC record',
                         'without DMARC, receivers don\'t know what to do with emails that fail SPF/DKIM')]

    findings = []
    policy_m = re.search(r'p=(\w+)', dmarc_txt)
    policy = policy_m.group(1) if policy_m else None

    if policy == 'none':
        has_rua = 'rua=' in dmarc_txt
        if has_rua:
            findings.append(_finding('low', 'DMARC p=none (monitoring only)',
                                     'reports are being collected (rua is set), but there\'s no real spoofing protection — plan a move to quarantine/reject'))
        else:
            findings.append(_finding('medium', 'DMARC p=none with no reporting (rua)',
                                     'neither protection nor visibility — DMARC is effectively useless in this state'))
    elif policy in ('quarantine', 'reject'):
        findings.append(_finding('ok', f'DMARC is active: p={policy}', dmarc_txt))
    else:
        findings.append(_finding('medium', 'DMARC has no recognized p= policy', dmarc_txt))

    return findings


# ===========================================================================
# DNSSEC
# ===========================================================================

def _check_dnssec(domain: str) -> list[dict]:
    code, out, _ = run_cmd(['dig', '+dnssec', '+short', 'DNSKEY', domain], timeout=10)
    if code != 0 or not out.strip():
        return [_finding('medium', 'DNSSEC is not enabled',
                         'the zone is unsigned — DNS responses can be forged (cache poisoning), especially on open resolvers')]

    code_ds, out_ds, _ = run_cmd(['dig', '+short', 'DS', domain], timeout=10)
    if code_ds == 0 and out_ds.strip():
        return [_finding('ok', 'DNSSEC is enabled, a DS record is present at the parent zone')]
    return [_finding('medium', 'DNSKEY exists but no DS record at the registrar',
                     'the zone is signed, but the chain of trust isn\'t closed — add a DS record at the domain registrar')]


# ===========================================================================
# Dangling CNAME (subdomain takeover risk)
# ===========================================================================

# common "orphaned" targets left over from decommissioned services - if a
# CNAME points here and the target itself doesn't actively resolve into this
# service, it's a classic subdomain takeover
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
            findings.append(_finding(severity, f'dangling CNAME: {full} → {cname}',
                                     'the target doesn\'t resolve — subdomain takeover risk if the platform freely gives out such names'
                                     + (f' (looks like {hint})' if hint else '')))
    if checked and not findings:
        findings.append(_finding('ok', f'checked {checked} CNAME target(s), no dangling ones found'))
    return findings


# ===========================================================================
# Discovered third-party services (via verification tokens in TXT)
# ===========================================================================

def _check_discovered_services(domain: str) -> list[dict]:
    txts = _dig_txt(domain)
    found = []
    for txt in txts:
        for pattern, label in TXT_SERVICE_PATTERNS:
            if label is None:
                continue  # SPF/DMARC — don't duplicate, they have their own section
            if re.search(pattern, txt, re.IGNORECASE):
                found.append(label)

    if not found:
        return [_finding('ok', 'no third-party verification tokens found in TXT')]

    findings = []
    for label in sorted(set(found)):
        findings.append(_finding('low', f'service detected: {label}',
                                 'a verification token in a TXT record — reveals infrastructure in use'))
    return findings


# ===========================================================================
# Combined check
# ===========================================================================

@register(
    id='dns_audit', label='DNS domain audit', category='site',
    params=[
        {'name': 'domain', 'type': 'text', 'label': 'Domain', 'default': 'example.com'},
        {'name': 'subdomains_to_check', 'type': 'text', 'label': 'Subdomains for CNAME check (comma-separated)',
         'default': 'www,mail,blog,shop,cdn,static'},
    ],
    required_tools=['dig'],
    description='SPF/DKIM/DMARC/DNSSEC + dangling CNAME detection (subdomain takeover). DNS queries only, no server access.',
)
def check_dns_audit(domain: str = 'example.com', subdomains_to_check: str = 'www,mail,blog,shop,cdn,static') -> dict:
    if not tool_available('dig'):
        return {'error': 'dig is not installed (apt install dnsutils)'}
    if not domain:
        return {'error': 'domain not specified'}

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
