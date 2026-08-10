# `nginx_hardening` specification

Status: **specification only, no code yet**. This document exists to answer, before
a single line of `nginx_hardening.py` is written: *"if nginx scores 82/100, does
that actually mean what we want to tell the user?"* — per `docs/scoring.md`'s
Component contract. If a control here can't honestly answer PASS/FAIL/N/A from data
NetAudit already collects, it does not go into v1.

## 1. Scope

`nginx_hardening` is a **hardening module** (`docs/scoring.md`, `category='hardening'`)
scoring nginx's own HTTP-layer configuration: TLS, security headers, request-handling
directives, and public exposure. It explicitly does **not** score:

- **Filesystem / process ownership** (config file permissions, private key
  permissions, worker process user, master process privileges) — this is
  OS/process-level hardening, already the responsibility of Lynis (`lynis_audit`)
  and `systemd_hardening` (`ProtectSystem=`, `ProtectHome=`, `User=`/`DynamicUser=`,
  etc.). Re-scoring the same facts under a different module name would not add
  nginx-specific value — it would just be a second, redundant opinion about a file
  permission.
- Anything `NginxConfig` (`netaudit_pkg/nginx_config.py`) doesn't already expose as a
  parsed field. `nginx_hardening` consumes `NginxConfig`, it does not run its own
  independent SSH commands or its own regex over `nginx -T` output — see
  `nginx_config.py`'s module docstring for why parsing lives in exactly one place.

This keeps the four groups originally proposed down to what nginx's own config can
actually answer: **TLS, Security Headers, Configuration, Exposure.** A fifth
Filesystem group was considered and deliberately dropped — see above.

## 2. Data source

Single source of truth: `netaudit_pkg.nginx_config.NginxConfig`, produced by
`collect_nginx_config(ssh)`. Today's fields (2026-08-09):

| Field | Type | Notes |
|---|---|---|
| `installed` | `bool` | |
| `version` | `str` | |
| `readable` | `bool` | `False` when `nginx -T` needed root and didn't have it |
| `server_tokens` | `str \| None` | `'off'` / `'on'` / `None` if not explicitly set |
| `ssl_protocols` | `list[str]` | e.g. `['TLSv1.2', 'TLSv1.3']`; `[]` if not set |
| `has_ssl_certificate` | `bool` | |
| `headers_present` | `set[str]` | lowercased header names found via `add_header` |
| `autoindex_on` | `bool` | |

**Every control below cites which field(s) it reads.** A control that needs a field
`NginxConfig` doesn't have yet is marked Tier 2 (section 7) rather than silently
assumed into existence.

## 3. Control model

Each control is specified as:

```yaml
id: NGX-XXX-NNN
name: short_slug
category: tls | security_headers | configuration | exposure
data_source: NginxConfig field(s) this reads
states:
  pass: {condition, score}
  fail: {condition, score}
  n/a: {condition}              # only if genuinely inapplicable, not just "unknown"
severity: critical | high | medium | low     # for the Finding, if FAIL
weight: <share within its category>
finding:
  title: <Finding.title when FAIL>
```

`score`/`max` per control are `0`/`1` (binary pass/fail) unless stated otherwise —
per `docs/scoring.md`'s "binary controls" convention. A control with genuine partial
credit (e.g. "3 of 4 recommended headers present") says so explicitly; it does not
default to binary out of laziness.

## 4. PASS / FAIL / N/A semantics — the `server_tokens` example in full

This is the control worked through in full ambiguity-free detail, per the
requirement to fix the methodology of *one* control before writing the other 14.

```yaml
id: NGX-CONF-001
name: server_tokens
category: configuration
data_source: NginxConfig.server_tokens

description: >
  nginx's Server response header and default error pages disclose the exact
  nginx version when server_tokens is not explicitly turned off. This helps an
  attacker match known CVEs to the running version without any other probing.

states:
  pass:
    condition: "server_tokens == 'off'"
    score: 1
  fail:
    condition: "server_tokens == 'on' OR server_tokens is None"
    score: 0
  n/a:
    condition: never — server_tokens always has a determinate effective value

severity: medium
weight: 0.10   # placeholder, see section 6 for final configuration-group weights

finding:
  title: "Server version disclosure enabled"
  # reuses the existing audit_nginx() finding, see section 5
```

**Why `server_tokens is None` is FAIL, not N/A:** nginx's own documented default is
`server_tokens on` when the directive isn't set at all — this is a known, stable
fact about nginx's behavior, not something NetAudit is guessing at. "Not configured"
here has a determinate real-world effect (the version leaks), so it scores as FAIL
with the same severity as an explicit `server_tokens on;`. **N/A is reserved for
when a control's effective state genuinely cannot be determined** — e.g. `nginx -T`
returned nothing because of insufficient permissions (see section 4.1), not for
"the directive wasn't found" when the software's own default is documented and
known.

### 4.1 The one real N/A case: unreadable config

Every control in this catalogue that reads `NginxConfig` fields is `applicable=False`
as a **whole component group** when `NginxConfig.readable == False` — not
individually per-control. If `nginx -T` needed root and didn't have it, nothing was
parsed, so no control in this module has a legitimate opinion. `nginx_hardening`
should return the standard `docs/scoring.md` N/A shape (`applicable: false, reason:
"nginx -T requires root — no read access to the config"`) for the affected
component(s) rather than a synthetic FAIL across the board, mirroring how
`audit_nginx()` already handles this same case with a single `low` finding instead
of firing every other check with fabricated failures.

## 5. Finding ↔ Component relationship

`nginx_hardening` does **not** re-derive its own findings from scratch where
`audit_nginx()` already produces one for the same control — it reuses/references
the existing `Finding` and links via `Component.finding_id`
(`docs/scoring.md` "The Component contract"). Concretely:

- `audit_nginx()` already returns a finding titled *"server_tokens is not
  disabled"* for `server_tokens != 'off'`. `nginx_hardening`'s `NGX-CONF-001`
  component scores the same fact and sets `finding_id` to reference it (see
  section 8 for exactly how the id is threaded through, since `audit_nginx()`'s
  findings currently don't carry stable `id`s — this is the one small gap the
  implementation step will need to close).
- Controls that don't have an existing `audit_nginx()` counterpart (e.g. some
  Security Headers or Exposure controls) get findings generated directly by
  `nginx_hardening` itself, same shape (`severity`, `title`, `detail`), no
  `audit_nginx()` involvement needed.

Either way, the user-visible result always contains **both** the finding (what's
wrong, in plain language) and the component (its numeric weight/contribution) — per
the explicit requirement that a `server_tokens on` fact must never collapse into a
bare `score: 0` with no accompanying explanation.

## 6. Control catalogue — Tier 1 (implementable today from existing `NginxConfig`)

Honest inventory: with today's five parsed fields, this is what can actually be
scored without inventing data. This is deliberately shorter than 15-25 — a longer
list would mean scoring facts `NginxConfig` doesn't have, which is exactly the
"looks precise, means nothing" trap this whole exercise exists to avoid.

### 6.0 Status matrix (all 9 controls, at a glance)

Full detail (data source, exact conditions, Finding text) lives in the per-group
tables below (6.1 TLS onward) — this table is the overview. Only `NGX-TLS-002` is
a genuine three-state control; the other eight are binary (PASS/FAIL) with no WARN,
because a WARN state was not artificially added where the underlying fact has no
real middle ground — see the `NGX-TLS-002` rationale below for why that one control
earned a third state and the rest didn't.

| ID | Control | PASS | WARN | FAIL | N/A |
|---|---|---|---|---|---|
| NGX-CONF-001 | server_tokens | `== 'off'` | — | `== 'on'` or not set | never (§4) |
| NGX-CONF-002 | autoindex | disabled | — | enabled | never |
| NGX-TLS-001 | Legacy TLS disabled | TLSv1/1.1 both absent | — | either present | no TLS configured at all |
| NGX-TLS-002 | Modern protocol level | TLSv1.3 present | only TLSv1.2 (no 1.3) | neither 1.2 nor 1.3 | `ssl_protocols` empty |
| NGX-TLS-003 | `ssl_protocols` explicit | non-empty | — | empty + has cert | no TLS configured at all |
| NGX-HDR-001 | HSTS | present | — | absent | never |
| NGX-HDR-002 | X-Frame-Options | present | — | absent | never |
| NGX-HDR-003 | X-Content-Type-Options | present | — | absent | never |
| NGX-EXP-001 | TLS available | has cert | — | no cert | never |

### 6.1 TLS (data: `ssl_protocols`, `has_ssl_certificate`)

| ID | Name | PASS (score) | WARN (score) | FAIL (score) | N/A | Severity |
|---|---|---|---|---|---|---|
| NGX-TLS-001 | Legacy protocols disabled | `TLSv1` and `TLSv1.1` both absent from `ssl_protocols` (100) | — | either present (0) | `ssl_protocols` empty AND no `ssl_certificate` (plain HTTP vhost — TLS controls don't apply) | high |
| NGX-TLS-002 | Modern protocol level | `TLSv1.3` present (100) | only `TLSv1.2` present, no `TLSv1.3` (80) | neither `TLSv1.2` nor `TLSv1.3` present, but `ssl_protocols` non-empty (0) | `ssl_protocols` empty (see NGX-TLS-001 N/A) | low |

**NGX-TLS-002 rationale (2026-08-09):** three-state, not binary — per OWASP's
Transport Layer Security Cheat Sheet, web applications should default to TLS 1.3
and *may* support TLS 1.2 for compatibility, while TLS 1.0/1.1 are formally
deprecated (RFC 8996) and must be disabled. TLS 1.2-only is therefore a real,
distinct middle state: not a failure (it's still an actively supported, broadly
recommended protocol — NIST SP 800-52 Rev. 2 requires TLS 1.2 support for the
relevant government profile), but not the preferred modern baseline either. `80`
was chosen deliberately over a plain average (`75`) of PASS/FAIL: the score should
reflect security posture, not the arithmetic midpoint between two endpoints - TLS
1.2 sits closer to "acceptable" than to "broken". Severity is `low` (not `medium`)
because a TLS 1.2-only Finding describes a suboptimal-but-not-broken state, distinct
from NGX-TLS-001's `high` severity for genuinely deprecated protocols being enabled.

**Guarding against double-penalizing the same fact:** NGX-TLS-001 and NGX-TLS-002
score two different properties of `ssl_protocols` (legacy-protocol *absence* vs.
modern-protocol *level*), not the same fact twice. A config with `['TLSv1',
'TLSv1.1', 'TLSv1.2']` correctly gets NGX-TLS-001=FAIL (legacy present) and
NGX-TLS-002=WARN (1.2 present but not 1.3) — two distinct, real shortcomings, not
duplicate punishment for one. A config with only `['TLSv1']` gets both controls at
FAIL — also not duplication, since it genuinely lacks both legacy-protocol
avoidance *and* any modern protocol at all; both facts are independently true.

Note: `ssl_protocols` empty but `has_ssl_certificate == True` means TLS is
configured but the protocol list wasn't explicitly set (relying on nginx's build
default) — this is the existing `audit_nginx()` "ssl_protocols is not set
explicitly" (`low`) finding's territory, not a hardening PASS/FAIL by itself
(nginx's build-time default varies by distro/version, so NetAudit can't assert a
specific default the way it can for `server_tokens`). Modeled as its own control
below rather than folded into NGX-TLS-001/002's N/A branch, since it's a distinct,
actionable state.

| NGX-TLS-003 | Protocols explicitly configured | `ssl_protocols` non-empty (any value) | `ssl_protocols` empty AND `has_ssl_certificate` | `has_ssl_certificate == False` (no TLS vhost at all — see NGX-EXP group) | low |

### 6.2 Security Headers (data: `headers_present`)

Each of the four headers `audit_nginx()` already checks for gets its own control
(not folded into one "headers score") so the AI analysis and the web UI can point
at the specific missing header, per `docs/scoring.md`'s auditability goal.

| ID | Name | PASS | FAIL | N/A | Severity |
|---|---|---|---|---|---|
| NGX-HDR-001 | Strict-Transport-Security | `'strict-transport-security'` in `headers_present` | absent | never | medium |
| NGX-HDR-002 | X-Frame-Options | `'x-frame-options'` in `headers_present` | absent | never | low |
| NGX-HDR-003 | X-Content-Type-Options | `'x-content-type-options'` in `headers_present` | absent | never | low |

`NginxConfig.headers_present` is currently `bool`-only per header (present or not) —
**not** whether the header's *value* is actually secure (e.g. `Strict-Transport-Security`
with a `max-age=0` would still count as "present"). This is a known limitation
carried over unchanged from `audit_nginx()`'s existing behavior; it is not silently
fixed here, since doing so would require expanding `NginxConfig` to capture header
values, which is Tier 2 work (section 7) and out of scope for a first version that's
supposed to reuse existing data, not extend the collector.

### 6.3 Configuration

| ID | Name | PASS | FAIL | N/A | Severity |
|---|---|---|---|---|---|
| NGX-CONF-001 | server_tokens | see section 4 in full | see section 4 | never (see 4.1) | medium |
| NGX-CONF-002 | autoindex disabled | `autoindex_on == False` | `autoindex_on == True` | never | medium |

### 6.4 Exposure

| ID | Name | PASS | FAIL | N/A | Severity |
|---|---|---|---|---|---|
| NGX-EXP-001 | TLS available | `has_ssl_certificate == True` | `has_ssl_certificate == False` | never | high |

**9 controls total** across 4 groups (3 TLS, 3 Headers, 2 Configuration, 1
Exposure). This is fewer than the 15-25 originally proposed, on purpose — see the
opening of this section.

### 6.5 Why fewer controls than originally sketched

The original proposal (`NGX-TLS-001..005`, `NGX-HDR-001..005`, `NGX-CONF-001..006`,
`NGX-EXP-001..004`) listed ~20 controls including weak-cipher detection, CSP,
Referrer-Policy, Permissions-Policy, `client_max_body_size`, HTTP method
restrictions, `server_name` validation, and multiple exposure/port checks. **None
of these are implementable from today's `NginxConfig`** — cipher suites, CSP/
Referrer-Policy/Permissions-Policy header values, body size limits, allowed
methods, and listening ports are none of them currently parsed. They're catalogued
honestly in Tier 2 (section 7) as concrete collector extension work, rather than
padding this table with controls that would have to fake their PASS/FAIL logic.

## 7. Control catalogue — Tier 2 (requires extending `NginxConfig` first)

Not implemented in v1. Each entry names the `NginxConfig` field that would need to
be added and by which regex/parsing logic, so this is ready to pick up later
without re-deriving the design:

| ID | Name | Requires new `NginxConfig` field |
|---|---|---|
| NGX-TLS-004 | Weak cipher suites disabled | `ssl_ciphers: str` — parse `ssl_ciphers` directive |
| NGX-HDR-004 | Content-Security-Policy present (and non-trivial) | `header_values: dict[str, str]` — capture `add_header` values, not just presence |
| NGX-HDR-005 | Referrer-Policy present | same as above |
| NGX-HDR-006 | Permissions-Policy present | same as above |
| NGX-CONF-003 | `client_max_body_size` set to a sane bound | `client_max_body_size: str \| None` |
| NGX-CONF-004 | Dangerous HTTP methods disabled (TRACE, etc.) | `limit_except` / method restriction parsing |
| NGX-EXP-002 | HTTP→HTTPS redirect enforced | needs per-`server{}` block parsing, not just global directives — `NginxConfig` currently only captures the flattened `conf` text, not a structured server-block model |
| NGX-EXP-003 | No unintended default server exposure | same per-block parsing gap as above |

The per-`server{}`-block gap (NGX-EXP-002/003) is the largest one: `NginxConfig`
today treats the whole `nginx -T` output as one flat blob, which is enough for
global directives (`server_tokens`, `ssl_protocols`) but not for "does *this specific*
vhost redirect HTTP to HTTPS" when a host runs multiple server blocks. Extending
`NginxConfig` to a structured multi-block model is a bigger parser rewrite than
adding one new field, and is called out here rather than attempted inside this
first version.

## 8. Open implementation gap: `Finding.id` stability

Section 5 assumes `audit_nginx()`'s findings can be referenced by a stable id via
`Component.finding_id`, but as of this document, `audit_nginx()`'s findings (like
most existing findings across the codebase) don't set the optional `Finding.id`
field (`findings.py`) — `id` defaults to `None` everywhere it's not explicitly
passed. Before `nginx_hardening.py` is written, `audit_nginx()` needs `id=` set on
each finding it produces (e.g. `id='NGX-CONF-001'` on the server_tokens finding),
so `nginx_hardening`'s components can set the matching `finding_id` and have it mean
something. This is a small, additive change (findings.py already supports `id`) and
should land as a discrete step in the implementation checklist (section 9), not
bundled invisibly into the first nginx_hardening.py commit.

**Status (2026-08-09): done.** `audit_nginx()` now sets `id=` on every finding that
corresponds to a Tier 1 control (`NGX-CONF-001/002`, `NGX-TLS-001/003`,
`NGX-HDR-001/002/003`); the "no access to the config" and "no obvious issues found"
findings deliberately have no id, since neither corresponds to one specific control
(see `audit_nginx()`'s docstring in `server_security.py`). Covered by
`tests/test_nginx_finding_ids.py` (id correctness, uniqueness within a run, and no
id outside the documented catalogue) plus the existing `test_server_security_nginx.py`
backward-compat suite (finding title/severity content unchanged by the id addition).

### 8.1 Weights and synthetic validation

Per this document's own principle (section 1: "if a control can't honestly answer
PASS/FAIL/N/A ... it does not go into v1"), weights are not chosen by feel — they're
fixed only after running synthetic configurations through the actual
`weighted_score()` engine and checking the resulting scores make sense as a security
assessment, not just as arithmetic. This section records that process and its
result, since the weights below are the ones `nginx_hardening.py` implements.

#### Group weights

| Group | Weight | Rationale |
|---|---|---|
| TLS | 40% | The most consequential cryptographic portion of the config |
| Security Headers | 20% | Real browser-side protection, but partly redundant with application-level controls |
| Configuration | 20% | `server_tokens`/`autoindex` directly affect information disclosure and exposure |
| Exposure | 20% | Whether TLS exists at all is a prerequisite security property, not a minor check — see the "No TLS" finding below for why this isn't 10% |

#### Control weights within each group

| ID | Control | Weight | Rationale |
|---|---|---|---|
| NGX-TLS-001 | Legacy protocols disabled | 0.20 | TLS 1.0/1.1 present is a direct, unambiguous configuration defect |
| NGX-TLS-002 | Modern protocol level | 0.10 | TLS 1.2-without-1.3 is a real but comparatively minor degradation — TLS 1.2 remains an actively recommended fallback (OWASP/NIST, section 6.1) |
| NGX-TLS-003 | Explicit `ssl_protocols` | 0.10 | Explicit configuration matters for policy control, but doesn't by itself prove protocol quality |
| NGX-HDR-001 | HSTS | 0.10 | Directly enforces HTTPS use — more consequential than the other two headers |
| NGX-HDR-002 | X-Frame-Options | 0.05 | Protects against a narrower attack class (clickjacking) |
| NGX-HDR-003 | X-Content-Type-Options | 0.05 | Protects against a narrower attack class (MIME sniffing) |
| NGX-CONF-001 | `server_tokens` | 0.08 | Reduces information disclosure, doesn't expose data directly |
| NGX-CONF-002 | `autoindex` | 0.12 | Can expose actual file contents/structure — a more direct exposure risk than a version string |
| NGX-EXP-001 | TLS available | 0.20 | See "No TLS" finding below |

Sum: `0.20+0.10+0.10 + 0.10+0.05+0.05 + 0.08+0.12 + 0.20 = 1.00`.

**Why `NGX-TLS-001` and `NGX-TLS-002` are not equal weight despite both being TLS
protocol controls:** an earlier draft weighted them equally (0.15 each). Synthetic
testing (below) showed that with equal weight, the fact "no TLS 1.3" competed too
closely in impact with the fact "legacy TLS enabled" — two synthetic servers, one
with `[TLSv1, TLSv1.1, TLSv1.2]` and one with just `[TLSv1.2]`, should score very
differently (one has an active defect, the other is merely not-yet-optimal), and
equal weighting didn't produce that gap clearly enough. `weight` and Finding
`severity` remain independent per `docs/scoring.md` — NGX-TLS-001 is weighted
higher not because its severity is `high` (weight and severity are deliberately not
derived from each other), but because the underlying fact it checks is judged more
consequential to the module's own hardening assessment.

#### Synthetic validation results

Ran through the actual `weighted_score()` implementation (not hand-computed), nine
scenarios, everything held constant except the property under test. **Exact input
`NginxConfig` fields for each scenario** (fixed 2026-08-10, after an implementation
session found the original prose labels alone were ambiguous enough to reconstruct
incorrectly — see note below):

| Scenario | `server_tokens` | `ssl_protocols` | `has_ssl_certificate` | `headers_present` | `autoindex_on` | Score |
|---|---|---|---|---|---|---|
| A. Fully hardened | `off` | `[TLSv1.3]` | `True` | all 3 | `False` | 100 |
| B. TLS 1.2 only, everything else PASS | `off` | `[TLSv1.2]` | `True` | all 3 | `False` | 98 |
| C. Legacy TLS present, everything else PASS | `off` | `[TLSv1, TLSv1.2]` | `True` | all 3 | `False` | 78 |
| C2. Legacy present, no modern protocol at all | `off` | `[TLSv1, TLSv1.1]` | `True` | all 3 | `False` | 70 |
| D. No security headers, TLS good | `off` | `[TLSv1.3]` | `True` | none | `False` | 80 |
| E. Bad configuration + bad TLS | `on` | `[TLSv1, TLSv1.1]` | `True` | `{x-frame-options, x-content-type-options}` (no HSTS) | `True` | 40 |
| F. No TLS configured at all | `off` | `[]` | `False` | `{x-frame-options, x-content-type-options}` (no HSTS) | `False` | 50 |
| G. Realistic mixed server (TLS 1.2 only, no HSTS, `server_tokens on`) | `on` | `[TLSv1.2]` | `True` | `{x-frame-options, x-content-type-options}` | `False` | 80 |

**Note on E and F's `headers_present`:** both scenarios deliberately omit HSTS (not
"all 3 headers present" as an earlier draft of this table implied) — HSTS is what
makes the arithmetic land exactly on 40/50 given the fixed component weights, and it
is also the realistic case: a server with no TLS, or with legacy-only TLS and poor
config hygiene, would not plausibly be sending `Strict-Transport-Security` either.
**Note on E specifically:** `NGX-TLS-003` (protocols explicitly configured) scores
PASS here, not FAIL — `ssl_protocols` is non-empty (`[TLSv1, TLSv1.1]`), which is
NGX-TLS-003's PASS condition regardless of *which* protocols are listed (section
6.1: NGX-TLS-003 checks explicitness, not protocol quality — that's NGX-TLS-001/002's
job). A config where NGX-TLS-001, 002, *and* 003 are simultaneously FAIL is not
reachable: 003's FAIL condition (`ssl_protocols` empty) is mutually exclusive with
001/002's FAIL conditions (which require `ssl_protocols` non-empty to evaluate at
all) — see the 6.0 status matrix.

**The "No TLS" finding.** The first weight iteration (Exposure at 10%, matching the
group weights originally proposed) scored scenario F at **67/100** — implausibly
high for a site with no TLS at all. The cause wasn't the TLS weights; it was `N/A`
weight redistribution (`docs/scoring.md` "Handling N/A"): when all three TLS
components become inapplicable (no `ssl_protocols` to evaluate), their combined 40%
weight redistributes across the remaining six components, and the module ends up
scoring "the rest of the configuration" while effectively omitting TLS from the
assessment — which rewards the *absence* of a security capability rather than
correctly penalizing it. Raising `NGX-EXP-001` (the one control that stays
applicable and directly asks "does TLS exist at all") from 0.10 to 0.20 brought
scenario F down to 50 — squarely in a "serious degradation" range instead of a
misleadingly middling one. This is a **weights fix, not an engine fix**:
`weighted_score()`'s N/A redistribution logic is unchanged and is not nginx-specific
— see `docs/scoring.md` for why baking nginx semantics into the generic engine was
deliberately rejected as an option (section "8.2" below has the fuller reasoning
this document borrowed from).

**Known limitation, accepted for v1:** scenario B (TLS 1.2-only, otherwise perfect)
scores 98/100 — a smaller penalty than might be expected for "missing the preferred
modern protocol". This is mathematically correct given `NGX-TLS-002`'s weight
(0.10) and WARN score (80): `0.10 × (100-80)/100 × 100 = 2` points. Deliberately
not fixed by inflating `NGX-TLS-002`'s weight or lowering its WARN score, per the
principle above (component score reflects security posture, not a target output;
weight reflects genuine relative importance, not a knob for hitting a "feels right"
number). If real-world usage later shows 98 is too forgiving, the fix belongs in
`NGX-TLS-002`'s weight specifically — not in inflating WARN's severity, which would
misrepresent the actual state (TLS 1.2 alone is a recognized, non-broken
configuration per OWASP/NIST, section 6.1).

### 8.2 `mandatory` was considered and rejected for v1

An earlier discussion considered adding a `mandatory: bool` flag to `Component`
(`scoring.py`) — the idea being that some controls should be able to cap or
dominate the overall score regardless of weight, the way "no TLS at all" seemed to
require before the Exposure re-weighting above fixed it through weights alone.

Rejected for now, because:

- **`weight` and `mandatory` would be two different concepts wearing the same
  hat.** `weight` says how much a control counts toward the weighted average.
  `mandatory` would mean something structurally different — one control able to
  override or cap the result independent of the arithmetic (e.g. "if SSH root
  login is permitted, hardening score cannot exceed 50 regardless of everything
  else"). That's not a weight at all; it's a policy/cap rule layered on top of the
  score, and deserves its own design once there's a real control that needs it,
  not a boolean bolted onto `Component` speculatively.
- **The actual problem (scenario F) was solved by weights alone**, once Exposure
  was correctly weighted at 20% instead of 10%. No control in this catalogue
  currently needs to violate the "N/A redistributes proportionally" rule that
  `weighted_score()` already implements.
- **Keeping `weighted_score()` free of nginx-specific (or any module-specific)
  logic is the whole point of the `docs/scoring.md` split** between the generic
  engine and per-module semantics (`docs/scoring.md`'s closing line: "the scoring
  engine doesn't know anything about nginx, SSH, kernel, or Docker; modules define
  only their own controls, states, and weights"). Adding `mandatory` now, for a
  problem already solved without it, would be exactly the kind of premature
  engine complexity that split was meant to avoid.

If a genuine `mandatory`/cap use case appears in a future module, it should be
designed against that concrete case (what should the cap be, does it apply before
or after weight redistribution, does it interact with `applicable=False`) rather
than speculatively generalized from this one resolved scenario.

## 9. Implementation checklist (for when this spec is approved)

1. Add `id=` to the relevant `audit_nginx()` findings (server_tokens, TLS, each
   header, autoindex) matching the control IDs in section 6 — see section 8.
   **Done** (2026-08-09).
2. Weight assignment for the 4 groups and the controls within each, validated
   against synthetic configurations run through the real `weighted_score()`.
   **Done** (2026-08-09) — see section 8.1 for the final weights and the
   synthetic-validation results that shaped them (notably: Exposure raised from
   10% to 20% after synthetic testing caught an implausible score for
   "no TLS at all").
3. `netaudit_pkg/checks/nginx_hardening.py`: new check, `category='hardening'`,
   consumes `collect_nginx_config(ssh)` (not a second independent `nginx -T` call).
4. Tests: pure-function tests for each control's PASS/FAIL/N/A logic (no SSH mock
   needed, same pattern as `test_scoring.py`), plus `FakeSSHExecutor` tests for the
   full check like `test_server_security_nginx.py`.
5. `docs/scoring.md` "Status" section update once `nginx_hardening` ships — it
   currently says no hardening module exists yet.

## 10. Explicit exclusions (recap)

- Filesystem/process ownership — Lynis / `systemd_hardening`'s territory (section 1).
- Anything not in today's `NginxConfig` — Tier 2, not silently assumed (section 7).
- Header *value* quality (only presence is checked in v1) — Tier 2 (section 7).
- Per-`server{}`-block distinctions (HTTP→HTTPS redirect, default server behavior) —
  Tier 2, requires a parser rewrite (section 7).
- `overall.score` combining `nginx_hardening` with other native metrics or
  hardening scores — out of scope per `docs/scoring.md`, revisited only once 4-5
  hardening modules exist.
