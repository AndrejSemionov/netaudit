"""
DNS domain audit: SPF, DKIM, DMARC, DNSSEC, dangling CNAME.

All checks via `dig` (no direct server access needed - pure DNS queries,
works for any domain). Each finding gets a severity (high/medium/low/ok).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from ..registry import register
from ..findings import finding as _finding
from ..utils import run_cmd, tool_available

DNSStatus = Literal['NOERROR', 'NXDOMAIN', 'SERVFAIL', 'REFUSED', 'TIMEOUT', 'TOOL_ERROR', 'UNKNOWN_STATUS']

# The set of statuses under which this module MUST NOT treat an empty
# `records` list as "the record doesn't exist" - a DNS collection failure
# is not evidence of absence. See _dig_query()'s docstring and
# docs/checks/dns_audit.md (quality-audit addendum) for the full
# rationale: `dig` itself returns exit code 0 for NXDOMAIN and for
# NOERROR-with-no-data alike (confirmed - a lookup that returns NXDOMAIN
# is, from dig's own perspective, a *successful* lookup), so an
# exit-code-only check (this module's original approach) cannot tell
# "record absent" apart from "couldn't determine." Consumers of
# DNSQueryResult check `result.status in UNRESOLVED_STATUSES` before ever
# treating `not result.records` as a FAIL-worthy absence.
UNRESOLVED_STATUSES: frozenset[DNSStatus] = frozenset({
    'SERVFAIL', 'REFUSED', 'TIMEOUT', 'TOOL_ERROR', 'UNKNOWN_STATUS',
})


@dataclass(frozen=True)
class DNSQueryResult:
    """Result of one `dig` query, carrying enough of the response to let a
    caller distinguish "this record genuinely doesn't exist" from "DNS
    resolution didn't tell us." `records` is the parsed ANSWER section (one
    string per resource record, in `dig`'s master-file presentation format -
    same shape `_dig_txt()`'s old TXT-only extraction produced, generalized
    to any record type this module needs).

    `status` is the RCODE `dig` printed in its header (`status: NOERROR`,
    etc.), or one of this module's own synthetic values for cases `dig`
    never got far enough to print a status for at all (`TIMEOUT` - the
    subprocess itself timed out; `TOOL_ERROR` - `dig` wasn't found or some
    other exec-level failure; `UNKNOWN_STATUS` - `dig` ran and returned
    output, but the header didn't contain a `status:` line this parser
    recognizes, e.g. an unexpected `dig` version/output format this module
    hasn't been verified against).

    Deliberately does NOT collapse `NOERROR-with-no-records` and
    `NXDOMAIN` into one "absent" value: for every one of this module's own
    controls (SPF/DMARC/DNSSEC/dangling-CNAME) the two currently produce
    the same verdict (a record genuinely isn't there, either because the
    specific type is missing or because the whole name doesn't exist), so
    a consumer that wants "is any authoritative absence" can simply check
    `not records and status not in UNRESOLVED_STATUSES` - but the two
    remain distinguishable in this dataclass in case a future control
    needs to tell them apart (e.g. NXDOMAIN on `_dmarc.<domain>` while
    `<domain>` itself resolves is a stronger signal than a merely-empty
    TXT set).
    """

    status: DNSStatus
    records: list[str] = field(default_factory=list)


_STATUS_RE = re.compile(r';;\s*->>HEADER<<-.*\bstatus:\s*([A-Z]+)', re.IGNORECASE)


def _dig_query(rtype: str, name: str, *, extra_args: list[str] | None = None, timeout: int = 10) -> DNSQueryResult:
    """Run `dig <rtype> <name>` (full output, NOT `+short` - see this
    module's UNRESOLVED_STATUSES docstring for why `+short` cannot supply
    what this function needs) and parse both the RCODE status and the
    ANSWER section records. This is the ONE place `dig` is invoked and its
    output interpreted for every one of this module's checks - SPF, DKIM,
    DMARC, DNSSEC, and dangling-CNAME all call this rather than running
    their own `run_cmd(['dig', ...])` and re-deriving (inconsistently)
    what a `[]`/`None` result means.

    Every non-TXT/CNAME/DNSKEY/DS caller still gets a `records` list of
    the same shape `_dig_txt()` used to produce (raw ANSWER-section RDATA
    strings, TXT-quoting collapsed) - callers that only care about
    presence/absence, not content, can keep using `bool(result.records)`
    exactly as before; the difference this function makes is that
    `result.status` is now available too, and MUST be checked before
    `not result.records` is treated as "the record doesn't exist."
    """
    args = ['dig', rtype, name]
    if extra_args:
        args = ['dig', *extra_args, rtype, name]
    code, out, err = run_cmd(args, timeout=timeout)

    if code == -1 and err == 'timeout':
        return DNSQueryResult(status='TIMEOUT')
    if code == -1:
        return DNSQueryResult(status='TOOL_ERROR')

    status_match = _STATUS_RE.search(out)
    status: DNSStatus = status_match.group(1).upper() if status_match else 'UNKNOWN_STATUS'
    if status not in ('NOERROR', 'NXDOMAIN', 'SERVFAIL', 'REFUSED'):
        status = 'UNKNOWN_STATUS'

    records = _parse_answer_section(out)
    return DNSQueryResult(status=status, records=records)


def _parse_answer_section(dig_output: str) -> list[str]:
    """Extract RDATA (the value after `IN <TYPE>`) from `dig`'s
    ANSWER SECTION - the same master-file-format lines
    `_dig_txt()`/`_dig_cname()` used to get from `+short`, but reached by
    scanning the full non-`+short` output instead, since `+short` is what
    made status/records inseparable in the first place (see
    UNRESOLVED_STATUSES's docstring).

    Only lines between `;; ANSWER SECTION:` and the next blank line or the
    next `;;`-prefixed section header are considered - AUTHORITY/ADDITIONAL
    section records are deliberately not returned, matching what `+short`
    only ever surfaced (answer-section data for the queried name/type).

    TXT records: `dig`'s master-file format quotes each string component
    (e.g. `"v=spf1 " "include:_spf.google.com " "~all"`) - these are
    rejoined the same way `_dig_txt()` always has (strip quotes, drop the
    space `dig` inserts between adjacent quoted segments).
    """
    lines = dig_output.splitlines()
    in_answer = False
    records: list[str] = []
    for raw_line in lines:
        line = raw_line.strip()
        if line.startswith(';; ANSWER SECTION:'):
            in_answer = True
            continue
        if in_answer:
            if not line or line.startswith(';;'):
                break
            parts = line.split(None, 4)
            if len(parts) < 5:
                continue
            rdata = parts[4].strip()
            if rdata.startswith('"'):
                rdata = rdata.strip('"').replace('" "', '')
            else:
                rdata = rdata.rstrip('.')
            records.append(rdata)
    return records

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

# ===========================================================================
# SPF
# ===========================================================================

def _check_spf(domain: str) -> list[dict]:
    findings = []
    result = _dig_query('TXT', domain)

    if result.status in UNRESOLVED_STATUSES:
        findings.append(_finding('info', 'could not determine SPF status',
                                 f'DNS query for {domain} TXT records did not resolve '
                                 f'(status={result.status}) — this is a collection failure, '
                                 'not evidence that SPF is absent; retry or check resolver availability'))
        return findings

    spf_records = [t for t in result.records if t.startswith('v=spf1')]

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
    unresolved_selectors = []
    for selector in COMMON_DKIM_SELECTORS:
        name = f'{selector}._domainkey.{domain}'
        result = _dig_query('TXT', name)
        if result.status in UNRESOLVED_STATUSES:
            unresolved_selectors.append(selector)
            continue
        dkim_txt = next((t for t in result.records if 'p=' in t), None)
        if dkim_txt:
            found.append((selector, dkim_txt))

    findings = []
    if unresolved_selectors:
        findings.append(_finding('info', f'{len(unresolved_selectors)} DKIM selector check(s) did not resolve',
                                 f'DNS collection failure (not "no record") for: {", ".join(unresolved_selectors)} '
                                 '— these were not confirmed absent, just unchecked'))

    if not found:
        checked_selectors = [s for s in COMMON_DKIM_SELECTORS if s not in unresolved_selectors]
        if checked_selectors:
            findings.append(_finding('medium', 'no DKIM found (checked common selectors)',
                             'checked standard names: ' + ', '.join(checked_selectors) +
                             ' — the real selector may differ, ask your mail provider'))
        return findings

    for selector, txt in found:
        # revoked key: empty p= tag - per RFC 6376 §3.6.1 and every DKIM
        # guide consulted, the canonical revoked form is `p=` at the END
        # of the record (`v=DKIM1; k=rsa; p=`), not necessarily followed
        # by a semicolon - pre-existing bug found during a post-freeze
        # quality audit: the original `r'p=\s*;'` pattern only matched
        # `p=;` (p= followed by another tag), missing the far more common
        # `p=` with nothing after it at all.
        if 'p=' in txt and re.search(r'p=\s*(?:;|$)', txt):
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
    result = _dig_query('TXT', name)

    if result.status in UNRESOLVED_STATUSES:
        return [_finding('info', 'could not determine DMARC status',
                         f'DNS query for {name} TXT records did not resolve '
                         f'(status={result.status}) — this is a collection failure, '
                         'not evidence that DMARC is absent; retry or check resolver availability')]

    dmarc_txt = next((t for t in result.records if t.startswith('v=DMARC1')), None)

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
    dnskey_result = _dig_query('DNSKEY', domain, extra_args=['+dnssec'])

    if dnskey_result.status in UNRESOLVED_STATUSES:
        return [_finding('info', 'could not determine DNSSEC status',
                         f'DNS query for {domain} DNSKEY records did not resolve '
                         f'(status={dnskey_result.status}) — this is a collection failure, '
                         'not evidence that DNSSEC is disabled; retry or check resolver availability')]

    if not dnskey_result.records:
        return [_finding('medium', 'DNSSEC is not enabled',
                         'the zone is unsigned — DNS responses can be forged (cache poisoning), especially on open resolvers')]

    ds_result = _dig_query('DS', domain)

    if ds_result.status in UNRESOLVED_STATUSES:
        return [_finding('info', 'DNSKEY present, but could not determine DS record status',
                         f'DNS query for {domain} DS records did not resolve '
                         f'(status={ds_result.status}) — the zone appears signed, but whether '
                         'the parent-zone chain of trust is closed could not be determined')]

    if ds_result.records:
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
    unresolved = []
    for sub in subdomains:
        full = f'{sub}.{domain}' if sub else domain
        cname_result = _dig_query('CNAME', full)

        if cname_result.status in UNRESOLVED_STATUSES:
            unresolved.append(full)
            continue
        if not cname_result.records:
            continue

        cname = cname_result.records[0].rstrip('.')
        checked += 1

        # Resolve the CNAME target's own A/AAAA - a target that itself
        # fails to resolve (rather than the query simply not succeeding)
        # is the actual dangling-CNAME signal.
        a_result = _dig_query('A', cname)
        aaaa_result = _dig_query('AAAA', cname)
        target_unresolved = (a_result.status in UNRESOLVED_STATUSES
                              and aaaa_result.status in UNRESOLVED_STATUSES)
        if target_unresolved:
            unresolved.append(f'{full} (target {cname} could not be queried)')
            continue

        target_resolves = bool(a_result.records) or bool(aaaa_result.records)
        if not target_resolves:
            hint = next((h for h in DANGLING_TARGET_HINTS if h in cname), None)
            severity = 'high' if hint else 'medium'
            findings.append(_finding(severity, f'dangling CNAME: {full} → {cname}',
                                     'the target doesn\'t resolve — subdomain takeover risk if the platform freely gives out such names'
                                     + (f' (looks like {hint})' if hint else '')))

    if unresolved:
        findings.append(_finding('info', f'{len(unresolved)} subdomain(s) could not be checked for dangling CNAME',
                                 f'DNS collection failure (not "no record"), so these subdomains were skipped rather than '
                                 f'reported as clean: {", ".join(unresolved)}'))
    has_dangling = any(f['severity'] in ('high', 'medium') for f in findings)
    if checked and not has_dangling:
        findings.append(_finding('ok', f'checked {checked} CNAME target(s), no dangling ones found'))
    return findings

# ===========================================================================
# Discovered third-party services (via verification tokens in TXT)
# ===========================================================================

def _check_discovered_services(domain: str) -> list[dict]:
    result = _dig_query('TXT', domain)

    if result.status in UNRESOLVED_STATUSES:
        return [_finding('info', 'could not check TXT records for third-party services',
                         f'DNS query for {domain} TXT records did not resolve (status={result.status})')]

    found = []
    for txt in result.records:
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
    id='dns_audit', label='DNS domain audit', category='site', risk_level='PASSIVE',
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
    collection_failures = 0
    for findings in sections.values():
        for f in findings:
            counts[f['severity']] = counts.get(f['severity'], 0) + 1
            # This module's own convention (not a Finding-API contract):
            # every finding this module produces with severity='info' is,
            # specifically, a DNS collection failure (SERVFAIL/TIMEOUT/
            # TOOL_ERROR/UNKNOWN_STATUS) - see UNRESOLVED_STATUSES and the
            # _check_*() functions above, none of which use 'info' for
            # anything else. Surfaced as its own top-level count so a
            # collection failure is visible in the report shape itself,
            # not just buried in a per-section finding a reader or the AI
            # summary prompt might skim past - see docs/checks/dns_audit.md's
            # quality-audit addendum for why 'info' alone isn't enough here.
            # This is a local convention for this module ONLY; it is not a
            # general Finding.severity=='info' => collection-failure rule -
            # other modules use 'info' for ordinary informational findings.
            if f['severity'] == 'info':
                collection_failures += 1

    return {
        'domain': domain,
        'sections': sections,
        'summary': counts,
        'collection_failures': collection_failures,
    }
