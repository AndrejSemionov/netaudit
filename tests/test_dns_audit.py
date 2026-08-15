"""
Tests for netaudit_pkg.checks.dns_audit — closes a real gap found during a
post-freeze quality audit: this module had zero test coverage despite
security-relevant semantic parsing across 5 independent mechanisms
(SPF, DKIM, DMARC, DNSSEC, dangling CNAME).

The central invariant these tests exist to protect: a DNS collection
failure (SERVFAIL, timeout, tool error) must never be classified the same
way as a genuine, provable absence of a record (NOERROR-empty, NXDOMAIN).
Before the audit, all of these collapsed into the same `[]`/`None` result,
producing a false high-severity "no SPF record" (etc.) finding on a
transient resolver problem. See docs/checks/dns_audit.md's quality-audit
addendum for the full writeup.
"""

from __future__ import annotations

from unittest.mock import patch

from netaudit_pkg.checks.dns_audit import (
    UNRESOLVED_STATUSES,
    DNSQueryResult,
    _check_dangling_cnames,
    _check_discovered_services,
    _check_dkim,
    _check_dmarc,
    _check_dnssec,
    _check_spf,
    _dig_query,
    _parse_answer_section,
    check_dns_audit,
)


# ===========================================================================
# _parse_answer_section() — raw dig output parsing
# ===========================================================================

DIG_TXT_SPF = '''
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; ANSWER SECTION:
example.com.		300	IN	TXT	"v=spf1 " "include:_spf.google.com " "~all"

;; Query time: 24 msec
'''

DIG_TXT_MULTI = '''
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
;; ANSWER SECTION:
example.com.		300	IN	TXT	"v=spf1 -all"
example.com.		300	IN	TXT	"google-site-verification=abc123"
'''

DIG_CNAME = '''
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
;; ANSWER SECTION:
www.example.com.	300	IN	CNAME	target.example.net.
'''

DIG_NOERROR_EMPTY = '''
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 0
'''

DIG_NXDOMAIN = '''
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 0
'''

DIG_SERVFAIL = '''
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1
'''

DIG_REFUSED = '''
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 1
'''


def test_parse_answer_section_txt_rejoins_quoted_parts():
    records = _parse_answer_section(DIG_TXT_SPF)
    assert records == ['v=spf1 include:_spf.google.com ~all']


def test_parse_answer_section_multiple_records():
    records = _parse_answer_section(DIG_TXT_MULTI)
    assert records == ['v=spf1 -all', 'google-site-verification=abc123']


def test_parse_answer_section_cname_strips_trailing_dot():
    records = _parse_answer_section(DIG_CNAME)
    assert records == ['target.example.net']


def test_parse_answer_section_empty_answer_returns_empty_list():
    records = _parse_answer_section(DIG_NOERROR_EMPTY)
    assert records == []


# ===========================================================================
# _dig_query() — status classification (the core of the fix)
# ===========================================================================

def test_dig_query_noerror_with_records():
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, DIG_TXT_SPF, '')):
        result = _dig_query('TXT', 'example.com')
    assert result.status == 'NOERROR'
    assert result.records == ['v=spf1 include:_spf.google.com ~all']


def test_dig_query_noerror_empty():
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, DIG_NOERROR_EMPTY, '')):
        result = _dig_query('TXT', 'example.com')
    assert result.status == 'NOERROR'
    assert result.records == []


def test_dig_query_nxdomain():
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, DIG_NXDOMAIN, '')):
        result = _dig_query('TXT', 'nonexistent.invalid')
    assert result.status == 'NXDOMAIN'
    assert result.status not in UNRESOLVED_STATUSES


def test_dig_query_servfail_is_unresolved():
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, DIG_SERVFAIL, '')):
        result = _dig_query('TXT', 'broken.test')
    assert result.status == 'SERVFAIL'
    assert result.status in UNRESOLVED_STATUSES


def test_dig_query_refused_is_unresolved():
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, DIG_REFUSED, '')):
        result = _dig_query('TXT', 'refused.test')
    assert result.status == 'REFUSED'
    assert result.status in UNRESOLVED_STATUSES


def test_dig_query_timeout_is_unresolved():
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(-1, '', 'timeout')):
        result = _dig_query('TXT', 'slow.test')
    assert result.status == 'TIMEOUT'
    assert result.status in UNRESOLVED_STATUSES
    assert result.records == []


def test_dig_query_tool_not_found_is_unresolved():
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(-1, '', 'not found')):
        result = _dig_query('TXT', 'example.com')
    assert result.status == 'TOOL_ERROR'
    assert result.status in UNRESOLVED_STATUSES


def test_dig_query_unrecognized_output_is_unknown_status():
    # dig ran, produced output, but no status: line this parser recognizes
    # (e.g. unexpected dig version/format) - must not silently treat this
    # as NOERROR.
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, 'garbage output no header', '')):
        result = _dig_query('TXT', 'example.com')
    assert result.status == 'UNKNOWN_STATUS'
    assert result.status in UNRESOLVED_STATUSES


# ===========================================================================
# _check_spf() — the primary case this audit was about
# ===========================================================================

def test_spf_ok_when_well_formed():
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, DIG_TXT_SPF, '')):
        findings = _check_spf('example.com')
    assert any(f['severity'] == 'ok' for f in findings)


def test_spf_nxdomain_is_genuine_high_severity_fail():
    # Domain genuinely doesn't exist - "no SPF record" is an honest,
    # provable claim here.
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, DIG_NXDOMAIN, '')):
        findings = _check_spf('nonexistent.invalid')
    assert any(f['severity'] == 'high' and 'no SPF' in f['title'] for f in findings)


def test_spf_noerror_empty_is_genuine_high_severity_fail():
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, DIG_NOERROR_EMPTY, '')):
        findings = _check_spf('example.com')
    assert any(f['severity'] == 'high' and 'no SPF' in f['title'] for f in findings)


def test_spf_servfail_is_info_not_high():
    # THE regression this whole audit was about: a collection failure
    # must never produce the same high-severity "no SPF record" claim a
    # genuine absence does.
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, DIG_SERVFAIL, '')):
        findings = _check_spf('broken-resolver.test')
    assert len(findings) == 1
    assert findings[0]['severity'] == 'info'
    assert 'could not determine' in findings[0]['title']
    assert not any(f['severity'] == 'high' for f in findings)


def test_spf_timeout_is_info_not_high():
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(-1, '', 'timeout')):
        findings = _check_spf('slow-resolver.test')
    assert len(findings) == 1
    assert findings[0]['severity'] == 'info'
    assert not any(f['severity'] == 'high' for f in findings)


def test_spf_multiple_records_is_high():
    conf = '''
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
    ;; ANSWER SECTION:
    example.com.	300	IN	TXT	"v=spf1 -all"
    example.com.	300	IN	TXT	"v=spf1 include:foo.com ~all"
    '''
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, conf, '')):
        findings = _check_spf('example.com')
    assert any(f['severity'] == 'high' and 'multiple SPF' in f['title'] for f in findings)


def test_spf_plus_all_is_high():
    conf = '''
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
    ;; ANSWER SECTION:
    example.com.	300	IN	TXT	"v=spf1 +all"
    '''
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, conf, '')):
        findings = _check_spf('example.com')
    assert any(f['severity'] == 'high' and '+all' in f['title'] for f in findings)


# ===========================================================================
# _check_dmarc()
# ===========================================================================

def test_dmarc_reject_is_ok():
    conf = '''
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
    ;; ANSWER SECTION:
    _dmarc.example.com.	300	IN	TXT	"v=DMARC1; p=reject; rua=mailto:d@example.com"
    '''
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, conf, '')):
        findings = _check_dmarc('example.com')
    assert any(f['severity'] == 'ok' for f in findings)


def test_dmarc_p_none_no_rua_is_medium():
    conf = '''
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
    ;; ANSWER SECTION:
    _dmarc.example.com.	300	IN	TXT	"v=DMARC1; p=none"
    '''
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, conf, '')):
        findings = _check_dmarc('example.com')
    assert any(f['severity'] == 'medium' for f in findings)


def test_dmarc_absent_is_high():
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, DIG_NOERROR_EMPTY, '')):
        findings = _check_dmarc('example.com')
    assert findings[0]['severity'] == 'high'
    assert 'no DMARC' in findings[0]['title']


def test_dmarc_servfail_is_info_not_high():
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, DIG_SERVFAIL, '')):
        findings = _check_dmarc('broken-resolver.test')
    assert len(findings) == 1
    assert findings[0]['severity'] == 'info'


# ===========================================================================
# _check_dnssec()
# ===========================================================================

DIG_DNSKEY_PRESENT = '''
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
;; ANSWER SECTION:
example.com.	300	IN	DNSKEY	257 3 13 abc123
'''

DIG_DS_PRESENT = '''
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
;; ANSWER SECTION:
example.com.	300	IN	DS	12345 13 2 abcdef
'''


def test_dnssec_no_dnskey_is_medium():
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, DIG_NOERROR_EMPTY, '')):
        findings = _check_dnssec('example.com')
    assert findings[0]['severity'] == 'medium'
    assert 'not enabled' in findings[0]['title']


def test_dnssec_dnskey_servfail_is_info_not_medium():
    # This is the DNSSEC-specific instance of the same bug: the original
    # code used `if code != 0 or not out.strip()` which conflated
    # tool-failure with "unsigned zone."
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, DIG_SERVFAIL, '')):
        findings = _check_dnssec('broken-resolver.test')
    assert len(findings) == 1
    assert findings[0]['severity'] == 'info'
    assert not any(f['severity'] == 'medium' for f in findings)


def test_dnssec_dnskey_present_ds_present_is_ok():
    responses = [
        (0, DIG_DNSKEY_PRESENT, ''),
        (0, DIG_DS_PRESENT, ''),
    ]
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', side_effect=responses):
        findings = _check_dnssec('example.com')
    assert findings[0]['severity'] == 'ok'


def test_dnssec_dnskey_present_ds_absent_is_medium():
    responses = [
        (0, DIG_DNSKEY_PRESENT, ''),
        (0, DIG_NOERROR_EMPTY, ''),
    ]
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', side_effect=responses):
        findings = _check_dnssec('example.com')
    assert findings[0]['severity'] == 'medium'
    assert 'no DS record' in findings[0]['title']


def test_dnssec_dnskey_present_ds_servfail_is_info():
    # DNSKEY resolved fine, but the second query (DS) hit a collection
    # failure - must not claim "no DS record" (medium), must say
    # "couldn't determine."
    responses = [
        (0, DIG_DNSKEY_PRESENT, ''),
        (0, DIG_SERVFAIL, ''),
    ]
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', side_effect=responses):
        findings = _check_dnssec('example.com')
    assert findings[0]['severity'] == 'info'
    assert not any(f['severity'] == 'medium' for f in findings)


# ===========================================================================
# _check_dkim()
# ===========================================================================

def test_dkim_found_active_selector_is_ok():
    def side_effect(cmd, *a, **kw):
        name = cmd[2]
        if name.startswith('default._domainkey'):
            return (0, '''
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
            ;; ANSWER SECTION:
            default._domainkey.example.com.	300	IN	TXT	"v=DKIM1; p=abc123"
            ''', '')
        return (0, DIG_NOERROR_EMPTY, '')

    with patch('netaudit_pkg.checks.dns_audit.run_cmd', side_effect=side_effect):
        findings = _check_dkim('example.com')
    assert any(f['severity'] == 'ok' and 'default' in f['title'] for f in findings)


def test_dkim_all_selectors_noerror_empty_is_medium():
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, DIG_NOERROR_EMPTY, '')):
        findings = _check_dkim('example.com')
    assert any(f['severity'] == 'medium' and 'no DKIM found' in f['title'] for f in findings)
    assert not any(f['severity'] == 'info' for f in findings)


def test_dkim_all_selectors_servfail_is_info_not_medium():
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, DIG_SERVFAIL, '')):
        findings = _check_dkim('broken-resolver.test')
    assert any(f['severity'] == 'info' for f in findings)
    assert not any(f['severity'] == 'medium' for f in findings)


def test_dkim_revoked_selector_is_high():
    def side_effect(cmd, *a, **kw):
        name = cmd[2]
        if name.startswith('default._domainkey'):
            return (0, '''
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
            ;; ANSWER SECTION:
            default._domainkey.example.com.	300	IN	TXT	"v=DKIM1; p="
            ''', '')
        return (0, DIG_NOERROR_EMPTY, '')

    with patch('netaudit_pkg.checks.dns_audit.run_cmd', side_effect=side_effect):
        findings = _check_dkim('example.com')
    assert any(f['severity'] == 'high' and 'revoked' in f['title'] for f in findings)


# ===========================================================================
# _check_dangling_cnames()
# ===========================================================================

def test_dangling_cname_no_cname_is_silently_skipped():
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, DIG_NOERROR_EMPTY, '')):
        findings = _check_dangling_cnames('example.com', ['www'])
    # No CNAME at all -> nothing to check, no finding, no false "ok" either
    assert findings == []


def test_dangling_cname_target_resolves_is_ok():
    def side_effect(cmd, *a, **kw):
        rtype = cmd[1]
        if rtype == 'CNAME':
            return (0, DIG_CNAME, '')
        if rtype == 'A':
            return (0, '''
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
            ;; ANSWER SECTION:
            target.example.net.	300	IN	A	1.2.3.4
            ''', '')
        return (0, DIG_NOERROR_EMPTY, '')

    with patch('netaudit_pkg.checks.dns_audit.run_cmd', side_effect=side_effect):
        findings = _check_dangling_cnames('example.com', ['www'])
    assert any(f['severity'] == 'ok' for f in findings)


def test_dangling_cname_target_does_not_resolve_is_medium_or_high():
    def side_effect(cmd, *a, **kw):
        rtype = cmd[1]
        if rtype == 'CNAME':
            return (0, DIG_CNAME, '')
        return (0, DIG_NXDOMAIN, '')  # target genuinely doesn't resolve

    with patch('netaudit_pkg.checks.dns_audit.run_cmd', side_effect=side_effect):
        findings = _check_dangling_cnames('example.com', ['www'])
    assert any(f['severity'] in ('high', 'medium') and 'dangling CNAME' in f['title'] for f in findings)


def test_dangling_cname_servfail_on_subdomain_query_is_info_not_silent():
    # THE regression this function's migration was about: a DNS timeout
    # while checking a subdomain must surface as "couldn't check", not
    # silently disappear into "no CNAME, nothing to check."
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, DIG_SERVFAIL, '')):
        findings = _check_dangling_cnames('example.com', ['www', 'mail'])
    assert len(findings) == 1
    assert findings[0]['severity'] == 'info'
    assert 'could not be checked' in findings[0]['title']
    assert 'www.example.com' in findings[0]['detail']
    assert 'mail.example.com' in findings[0]['detail']


def test_dangling_cname_target_query_servfail_is_info_not_false_dangling():
    # CNAME resolves fine, but checking whether the TARGET resolves hits
    # SERVFAIL - must not claim "dangling" (that would be a false
    # positive: the target might resolve fine, we just couldn't check).
    def side_effect(cmd, *a, **kw):
        rtype = cmd[1]
        if rtype == 'CNAME':
            return (0, DIG_CNAME, '')
        return (0, DIG_SERVFAIL, '')  # can't check the target's A/AAAA

    with patch('netaudit_pkg.checks.dns_audit.run_cmd', side_effect=side_effect):
        findings = _check_dangling_cnames('example.com', ['www'])
    assert not any(f['severity'] in ('high', 'medium') for f in findings)
    assert any(f['severity'] == 'info' for f in findings)


def test_dangling_cname_mixed_ok_and_unresolved():
    # One subdomain resolves and is clean, another SERVFAILs - both facts
    # should be visible, not one masking the other.
    def side_effect(cmd, *a, **kw):
        name = cmd[2]
        rtype = cmd[1]
        if name == 'www.example.com' and rtype == 'CNAME':
            return (0, DIG_CNAME, '')
        if name == 'target.example.net' and rtype in ('A', 'AAAA'):
            if rtype == 'A':
                return (0, '''
                ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
                ;; ANSWER SECTION:
                target.example.net.	300	IN	A	1.2.3.4
                ''', '')
            return (0, DIG_NOERROR_EMPTY, '')
        if name == 'mail.example.com' and rtype == 'CNAME':
            return (0, DIG_SERVFAIL, '')
        return (0, DIG_NOERROR_EMPTY, '')

    with patch('netaudit_pkg.checks.dns_audit.run_cmd', side_effect=side_effect):
        findings = _check_dangling_cnames('example.com', ['www', 'mail'])
    assert any(f['severity'] == 'ok' for f in findings)
    assert any(f['severity'] == 'info' and 'mail.example.com' in f['detail'] for f in findings)


# ===========================================================================
# _check_discovered_services()
# ===========================================================================

def test_discovered_services_finds_known_pattern():
    conf = '''
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
    ;; ANSWER SECTION:
    example.com.	300	IN	TXT	"google-site-verification=abc123"
    '''
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, conf, '')):
        findings = _check_discovered_services('example.com')
    assert any(f['severity'] == 'low' and 'Google' in f['title'] for f in findings)


def test_discovered_services_none_found_is_ok():
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, DIG_NOERROR_EMPTY, '')):
        findings = _check_discovered_services('example.com')
    assert findings[0]['severity'] == 'ok'


def test_discovered_services_servfail_is_info_not_false_ok():
    # Must not claim "no third-party tokens found" (ok) when we simply
    # couldn't check - that's a false claim of a clean scan.
    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, DIG_SERVFAIL, '')):
        findings = _check_discovered_services('broken-resolver.test')
    assert findings[0]['severity'] == 'info'


# ===========================================================================
# check_dns_audit() — full integration
# ===========================================================================

def test_check_dns_audit_healthy_domain_no_high_severity():
    healthy_txt = '''
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
    ;; ANSWER SECTION:
    example.com.	300	IN	TXT	"v=spf1 -all"
    '''

    def side_effect(cmd, *a, **kw):
        name = cmd[2]
        if '_dmarc' in name:
            return (0, '''
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
            ;; ANSWER SECTION:
            _dmarc.example.com.	300	IN	TXT	"v=DMARC1; p=reject"
            ''', '')
        return (0, healthy_txt, '')

    with patch('netaudit_pkg.checks.dns_audit.tool_available', return_value=True), \
         patch('netaudit_pkg.checks.dns_audit.run_cmd', side_effect=side_effect):
        result = check_dns_audit(domain='example.com', subdomains_to_check='')
    assert result['domain'] == 'example.com'
    assert 'sections' in result


def test_check_dns_audit_resolver_down_produces_no_false_high_severity():
    # The end-to-end version of the central regression test: an entirely
    # unreachable/broken resolver must not produce a single high-severity
    # security finding across all 6 sections.
    with patch('netaudit_pkg.checks.dns_audit.tool_available', return_value=True), \
         patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, DIG_SERVFAIL, '')):
        result = check_dns_audit(domain='broken-resolver.test', subdomains_to_check='www,mail')

    all_findings = [f for sec in result['sections'].values() for f in sec]
    assert not any(f['severity'] in ('high', 'medium', 'critical') for f in all_findings), (
        'A DNS collection failure must never produce a security-severity finding - '
        f'got: {[(f["severity"], f["title"]) for f in all_findings if f["severity"] not in ("info", "ok")]}'
    )
    assert all(f['severity'] in ('info', 'ok') for f in all_findings)


def test_check_dns_audit_tool_missing():
    with patch('netaudit_pkg.checks.dns_audit.tool_available', return_value=False):
        result = check_dns_audit(domain='example.com')
    assert 'error' in result


def test_check_dns_audit_no_domain():
    with patch('netaudit_pkg.checks.dns_audit.tool_available', return_value=True):
        result = check_dns_audit(domain='')
    assert 'error' in result


def test_dns_query_result_frozen_dataclass_defaults():
    r = DNSQueryResult(status='NOERROR')
    assert r.records == []


# ===========================================================================
# collection_failures summary field — the explicit visibility requirement
# from the quality audit (info-severity findings must not be silently
# invisible in the aggregate report shape).
# ===========================================================================

def test_collection_failures_field_present_and_zero_when_all_resolve():
    healthy_txt = '''
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
    ;; ANSWER SECTION:
    example.com.	300	IN	TXT	"v=spf1 -all"
    '''
    with patch('netaudit_pkg.checks.dns_audit.tool_available', return_value=True), \
         patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, healthy_txt, '')):
        result = check_dns_audit(domain='example.com', subdomains_to_check='')
    assert 'collection_failures' in result
    assert result['collection_failures'] == 0


def test_collection_failures_field_counts_info_findings():
    with patch('netaudit_pkg.checks.dns_audit.tool_available', return_value=True), \
         patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, DIG_SERVFAIL, '')):
        result = check_dns_audit(domain='broken-resolver.test', subdomains_to_check='')
    all_info = [f for sec in result['sections'].values() for f in sec if f['severity'] == 'info']
    assert result['collection_failures'] == len(all_info)
    assert result['collection_failures'] > 0


# ===========================================================================
# Anti-regression: the exact original bug this audit fixed
# ===========================================================================

def test_regression_collection_failure_never_produces_high_severity_absence_claim():
    """This is THE test that must fail if someone reintroduces the
    original bug: treating `not records` (from a `+short`-style empty
    result) as proof a record is absent, without checking `status` first.
    Every one of SPF/DMARC/DNSSEC/DKIM/dangling-CNAME must route a
    SERVFAIL/TIMEOUT/TOOL_ERROR/UNKNOWN_STATUS response to an 'info'
    finding, never the same high/medium-severity "record absent"
    conclusion a genuine NOERROR-empty or NXDOMAIN produces.
    """
    for bad_status_output in (DIG_SERVFAIL, DIG_REFUSED):
        with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(0, bad_status_output, '')):
            spf = _check_spf('example.com')
            dmarc = _check_dmarc('example.com')
            dnssec = _check_dnssec('example.com')
            dkim = _check_dkim('example.com')
            cname = _check_dangling_cnames('example.com', ['www'])

        for section_name, findings in [('spf', spf), ('dmarc', dmarc), ('dnssec', dnssec),
                                        ('dkim', dkim), ('dangling_cname', cname)]:
            assert not any(f['severity'] in ('high', 'medium', 'critical') for f in findings), (
                f'{section_name} produced a security-severity finding from a collection '
                f'failure ({bad_status_output.strip()[:40]}...): {findings}'
            )

    with patch('netaudit_pkg.checks.dns_audit.run_cmd', return_value=(-1, '', 'timeout')):
        spf = _check_spf('example.com')
        dmarc = _check_dmarc('example.com')
        dnssec = _check_dnssec('example.com')
    for section_name, findings in [('spf', spf), ('dmarc', dmarc), ('dnssec', dnssec)]:
        assert not any(f['severity'] in ('high', 'medium', 'critical') for f in findings), (
            f'{section_name} produced a security-severity finding from a timeout: {findings}'
        )
