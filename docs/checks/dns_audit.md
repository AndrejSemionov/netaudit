# `dns_audit` specification (quality-audit addendum)

Status: **implemented and deployed** (`netaudit_pkg/checks/dns_audit.py`).
This document did not exist before this quality audit — `dns_audit` shipped
originally without a spec file, verified only informally. This addendum
records what the audit found and fixed, and is the first formal semantics
reference for this module.

## 1. Why this document exists

A post-freeze quality audit (see the project's broader quality-audit
initiative, covering `nginx_hardening`, `ssh_hardening`, and this module in
sequence) found `dns_audit` had **zero test coverage** and a real,
consistently-repeated architectural defect: **a DNS collection failure
(the resolver couldn't answer, timed out, or the tool itself failed to
run) was indistinguishable from a genuine, provable absence of a DNS
record.**

Concretely, the module's original `dig` invocations all used `+short`,
which — confirmed against `dig`'s own exit-code behavior (a lookup that
returns NXDOMAIN is, from `dig`'s own perspective, a *successful* lookup,
so it exits 0 just like a genuine no-answer or a real record does) —
cannot distinguish "the record doesn't exist" from "we couldn't find out."
Every one of this module's five independent security-relevant checks
(SPF, DKIM, DMARC, DNSSEC, dangling-CNAME) built its verdict on `not
records`, without ever checking *why* the list was empty. A transient
resolver SERVFAIL or a `dig` timeout therefore produced the exact same
`high`-severity "no SPF record" (etc.) finding a genuinely unprotected
domain would — a false positive with real consequences for anyone acting
on the report.

## 2. The core invariant this module now enforces

> **A DNS collection failure MUST NOT be interpreted as absence of a DNS
> record.**

Every check in this module must be able to tell "the record provably
doesn't exist" (NOERROR-with-empty-answer, or NXDOMAIN) apart from "DNS
resolution didn't tell us" (SERVFAIL, REFUSED, timeout, tool failure, or
unrecognized `dig` output) — and must never let the second case produce
the same verdict the first one would.

## 3. Data source: `_dig_query()` and `DNSQueryResult`

Single source of truth for every DNS query this module makes:
`_dig_query(rtype, name, extra_args=None)` in `dns_audit.py`, returning a
`DNSQueryResult(status, records)`.

**Why `+short` had to go:** `+short` only prints record data, deliberately
omitting the response code — there is no way to recover NXDOMAIN vs.
SERVFAIL vs. a real empty answer from `+short` output alone. `_dig_query()`
runs the full (non-`+short`) `dig` output and parses two things out of it:

- The RCODE from the header line (`;; ->>HEADER<<- ... status: NOERROR`,
  etc.) via a regex anchored on the `->>HEADER<<-` marker — this format is
  stable across `dig` versions and is the only reliable way to recover the
  response code.
- The ANSWER SECTION records, in the same master-file-format shape
  `+short` used to provide (TXT quoting collapsed, trailing dots on names
  stripped) — so callers that only cared about content, not status, see no
  behavior change.

### 3.1 `DNSQueryResult.status` values and their meaning

| Status | Meaning | In `UNRESOLVED_STATUSES`? |
|---|---|---|
| `NOERROR` | The query succeeded; `records` reflects whatever the ANSWER section actually contained (empty is a valid, meaningful `NOERROR` outcome — RCODE 0, per RFC 1035) | No |
| `NXDOMAIN` | The queried name does not exist at all (RCODE 3) — a stronger negative than `NOERROR`-empty, but for every check in this module both currently mean "the specific thing we're checking for isn't there" | No |
| `SERVFAIL` | The resolver attempted to answer and failed (RCODE 2) — network problem, broken delegation, DNSSEC validation failure, or any of several other underlying causes this module does not attempt to distinguish | **Yes** |
| `REFUSED` | The server declined to answer (RCODE 5, policy-based) | **Yes** |
| `TIMEOUT` | The `dig` subprocess itself timed out (`run_cmd`'s own `subprocess.TimeoutExpired` handling — not a DNS-protocol-level response at all) | **Yes** |
| `TOOL_ERROR` | `dig` could not be executed (not found, or another exec-level failure) | **Yes** |
| `UNKNOWN_STATUS` | `dig` ran and returned output, but no recognized `status:` line was found in it — an unexpected `dig` version/output format this module hasn't been verified against | **Yes** |

`UNRESOLVED_STATUSES` (a module-level `frozenset`) is the single place
this classification is decided. Every `_check_*()` function checks
`result.status in UNRESOLVED_STATUSES` before ever treating an empty
`records` list as a provable absence — this is the mechanical enforcement
of section 2's invariant, not a convention repeated independently in five
places.

## 4. Per-check semantics

For every check below: `status in UNRESOLVED_STATUSES` → an `info`-severity
finding stating a collection failure occurred (never the check's normal
FAIL finding); otherwise, the original logic applies unchanged (this audit
did not alter what counts as a well-formed SPF record, a closed DNSSEC
chain of trust, etc. — only how "we don't have data" is handled).

### 4.1 SPF (`_check_spf`)

- `UNRESOLVED_STATUSES` → `info`: "could not determine SPF status"
- No TXT record starting `v=spf1` (whether from `NOERROR`-empty or
  `NXDOMAIN`) → `high`: "no SPF record"
- More than one `v=spf1` record → `high`: "multiple SPF records" (RFC 7208
  requires receivers to treat this as a permanent error)
- `>10` DNS-lookup mechanisms (`include`/`a`/`mx`/`exists`/`redirect`) →
  `high` (RFC 7208's hard limit; SPF becomes a permanent error past this)
- `8`–`10` lookup mechanisms → `medium` (approaching the limit)
- No terminal `-all`/`~all` → `high` if it ends `+all`/`?all` (SPF made
  useless), else `low` (policy left undefined for the receiver)
- Otherwise → `ok`

### 4.2 DKIM (`_check_dkim`)

Brute-forces `COMMON_DKIM_SELECTORS` (DKIM does not publish a
discoverable list of selectors anywhere in DNS) — this is a known,
inherent limitation of DKIM auditing in general, not something this
module's collection-failure fix addresses.

- Per selector, `UNRESOLVED_STATUSES` → the selector is excluded from both
  the "found" and "confirmed absent" buckets and listed in a separate
  `info` finding ("N DKIM selector check(s) did not resolve") — a selector
  this module couldn't check is neither reported as present nor as
  absent.
- If no selector's TXT record was found among those that *did* resolve →
  `medium`: "no DKIM found (checked common selectors)" — explicitly lists
  only the selectors actually checked, not the ones that timed out.
- Found records with an empty `p=` tag (revoked key, per RFC 6376 §3.6.1)
  → `high`. **Bug fixed during this audit** (pre-existing, unrelated to
  the collection-failure work): the original regex `r'p=\s*;'` only
  matched `p=` followed by another tag (`p=;...`), missing the far more
  common canonical revoked form — `p=` with nothing after it at all
  (`v=DKIM1; k=rsa; p=`). Fixed to `r'p=\s*(?:;|$)'`.
- Otherwise → `ok` per active selector found.

### 4.3 DMARC (`_check_dmarc`)

Same structure as SPF: `UNRESOLVED_STATUSES` on the `_dmarc.<domain>` TXT
query → `info`. Otherwise: no `v=DMARC1` record → `high`; `p=none` with no
`rua=` → `medium`; `p=none` with `rua=` set → `low`; `p=quarantine` or
`p=reject` → `ok`; unrecognized `p=` value → `medium`.

### 4.4 DNSSEC (`_check_dnssec`)

Two sequential queries — `DNSKEY` (with `+dnssec`) then `DS`, both against
the domain itself. **Pre-existing bug fixed during this audit:** the
original code used `if code != 0 or not out.strip()`, which — like the
other checks — conflated a tool/collection failure with "the zone is
unsigned."

- `DNSKEY` query in `UNRESOLVED_STATUSES` → `info`: "could not determine
  DNSSEC status" (returned immediately; the `DS` query is not attempted).
- `DNSKEY` resolves with no records → `medium`: "DNSSEC is not enabled".
- `DNSKEY` present, `DS` query in `UNRESOLVED_STATUSES` → `info`: "DNSKEY
  present, but could not determine DS record status" — deliberately
  distinct wording from the DNSKEY-unresolved case, since a reader needs
  to know the zone *is* signed, just that this module couldn't confirm
  the parent-zone delegation.
- `DNSKEY` present, `DS` present → `ok`.
- `DNSKEY` present, `DS` absent (provably, not unresolved) → `medium`:
  "DNSKEY exists but no DS record at the registrar" (chain of trust isn't
  closed).

**Explicit scope limitation, not fixed by this audit:** this check
verifies *presence* of `DNSKEY`/`DS` records — that the zone is signed and
the parent-zone delegation exists — not that a resolver *currently
successfully validates* the chain (which would require inspecting the `ad`
flag on a live, validating resolver's response, and would also catch
expired `RRSIG` signatures or algorithm mismatches this presence-only
check cannot see). This is the same class of distinction as
`docs/checks/nginx_hardening.md` section 7.1's server-block-vs-location
scope limitation: a deliberate boundary, not an oversight, and not
something to infer has been closed just because this document exists.
Extending to live-validation checking is a separate, future scope item.

### 4.5 Dangling CNAME (`_check_dangling_cnames`)

For each candidate subdomain: query its `CNAME`; if `UNRESOLVED_STATUSES`,
add it to an `unresolved` list and move on (**not** silently `continue` as
the original code did — see below). If no CNAME record, skip silently
(this is a legitimate "nothing to check here," not a collection failure —
most of the default candidate subdomains, e.g. `blog`/`shop`/`cdn`, won't
have one on a typical domain). If a CNAME is found, query the target's `A`
and `AAAA`; if *both* are `UNRESOLVED_STATUSES`, the subdomain goes into
`unresolved` (querying the target failed, not "the target doesn't
resolve"). Otherwise, if the target has no `A`/`AAAA` records at all
(genuinely, not from a query failure), that's the dangling-CNAME finding
(`high` if the target matches a known abandoned-service hint like
`github.io`/`herokuapp.com`, else `medium`).

**Bug fixed during this audit:** the original `if not cname: continue`
could not distinguish "no CNAME record" (legitimate skip) from "the CNAME
query failed" (silent loss of coverage) — both produced the same `None`
from the old `_dig_cname()` helper. In practice this rarely produced a
false *negative* finding (most candidate subdomains legitimately have no
CNAME, so most `None` results were already correct to skip), but it did
produce silent incompleteness: a user reading "checked N CNAME target(s),
no dangling ones found" had no way to know some subdomains were never
actually checked. Fixed: unresolved subdomains are now collected
separately and surfaced in their own `info` finding, naming exactly which
subdomains couldn't be checked and why.

### 4.6 Discovered services (`_check_discovered_services`)

Purely informational (never above `low` severity) — scans TXT records for
known third-party verification-token patterns (Google, Microsoft,
Atlassian, etc.). `UNRESOLVED_STATUSES` on the domain's TXT query → `info`
("could not check TXT records for third-party services"), rather than the
prior behavior of silently reporting `ok` ("no third-party verification
tokens found") on a query that never actually completed.

## 5. Severity representation for collection failures: `info`, not a new state

This module's `Finding.severity` for every collection-failure case above
is `'info'` — an explicit, considered compromise, not an oversight.

**Why not a new `unknown`/`UNKNOWN` severity value:** `Finding.severity`
(`netaudit_pkg/findings.py`) is a fixed enum (`critical`, `high`, `medium`,
`low`, `info`, `ok`), validated in `__post_init__`. Introducing a seventh
value is a project-wide `Finding`-model change — it would need auditing
every consumer of `Finding.severity` across the whole codebase (report
JSON shape, the web UI's severity-to-pill-color mapping, the AI-analysis
system prompt in `history.py`, and any other module that might one day
assume the six-value enum is exhaustive), not just this module. That is a
legitimate future improvement (see section 6) but is explicitly out of
scope for this quality-audit pass.

**Why not reuse the existing `confidence='low'` + `requires_manual_
verification=True` pattern** (`rootkit_check.py`'s precedent for
"uncertain finding"): that pattern exists for a different situation — a
*positive* signal of uncertain reliability (e.g. an rkhunter warning that
might be a known false positive). A DNS collection failure is not an
uncertain positive signal; it is the *absence* of any signal at all. Using
`confidence='low'` with a `high`/`medium` severity here would still show
the user a colored high/medium-severity pill in the UI (`confidence` is
not read by the web UI at all — confirmed by inspection, `web/static/
index.html` has no reference to it), which is exactly the false alarm this
audit exists to prevent.

**Why `info` specifically:** of the six existing severity values, `info`
is the only one that does not assert either "a problem was found"
(`critical`/`high`/`medium`/`low`) or "the check ran and found nothing
wrong" (`ok`). Every collection-failure finding's `title` explicitly says
so in plain language ("could not determine ... status", "could not be
checked") — never phrased as if the check had actually run and passed.

**This is a local convention for `dns_audit` specifically, not a
general rule.** Other modules' `info`-severity findings (where they exist)
are ordinary informational notes, not collection-failure markers. A
future reader must not assume `severity == 'info'` means "collection
failure" outside this module.

**Visibility safeguard — `collection_failures` in the report shape:**
because `info` findings are not specially highlighted anywhere (the web
UI's severity-pill mapping has no styling for `info`, falling through to
plain unstyled text; the AI-analysis system prompt in `history.py`
explicitly instructs the model to "roll all high/medium into prioritized
recommendations," with no equivalent instruction for `info`), a DNS
collection failure could realistically go unmentioned in an AI-generated
summary even though it's technically present in the raw JSON. To prevent
that, `check_dns_audit()`'s return value includes a top-level
`collection_failures: int` count (the number of `info`-severity findings
across all six sections) — this makes a collection failure visible in the
report's shape itself, not just buried in per-section finding text a
reader or the AI prompt might skim past.

## 6. Backlog: a first-class collection-failure state in the `Finding` model

This audit's local fix (`severity='info'` + the `collection_failures`
count, both specific to `dns_audit`) resolves the concrete problem found
here, but the underlying need — "this check could not determine a
verdict, distinct from both 'problem found' and 'no problem found'" — is
plausibly not unique to DNS auditing. A proper fix, if this pattern
recurs elsewhere, is a project-wide addition to the `Finding` model (e.g.
a first-class `unknown` severity, or splitting `severity` — "how bad" —
from a separate `status` field — "did the check actually produce a
verdict") with every existing consumer (UI, AI prompt, report JSON
contract, other modules) audited and updated together. That is
deliberately not attempted here — see this project's established
methodology of not mixing a scoped bug fix with a system-wide redesign.

## 7. Test coverage

`tests/test_dns_audit.py` (0 tests before this audit, 49 after) covers:
`_dig_query()`'s status classification for all seven states; each of the
five checks' collection-failure path independently; a dedicated
regression test (`test_regression_collection_failure_never_produces_
high_severity_absence_claim`) asserting no `SERVFAIL`/`REFUSED`/`TIMEOUT`
response can produce a `high`/`medium`/`critical` finding across any of
the five checks — this is the test that must fail if the original bug is
ever reintroduced; and the `collection_failures` summary field.
