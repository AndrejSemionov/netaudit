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

### TLS (data: `ssl_protocols`, `has_ssl_certificate`)

| ID | Name | PASS | FAIL | N/A | Severity |
|---|---|---|---|---|---|
| NGX-TLS-001 | Legacy protocols disabled | `TLSv1` and `TLSv1.1` both absent from `ssl_protocols` | either present | `ssl_protocols` empty AND no `ssl_certificate` (plain HTTP vhost — TLS controls don't apply) | high |
| NGX-TLS-002 | Modern protocol present | `TLSv1.2` or `TLSv1.3` in `ssl_protocols` | neither present, but `ssl_protocols` non-empty | `ssl_protocols` empty (see NGX-TLS-001 N/A) or already covered by NGX-TLS-001's FAIL | medium |

Note: `ssl_protocols` empty but `has_ssl_certificate == True` means TLS is
configured but the protocol list wasn't explicitly set (relying on nginx's build
default) — this is the existing `audit_nginx()` "ssl_protocols is not set
explicitly" (`low`) finding's territory, not a hardening PASS/FAIL by itself
(nginx's build-time default varies by distro/version, so NetAudit can't assert a
specific default the way it can for `server_tokens`). Modeled as its own control
below rather than folded into NGX-TLS-001/002's N/A branch, since it's a distinct,
actionable state.

| NGX-TLS-003 | Protocols explicitly configured | `ssl_protocols` non-empty (any value) | `ssl_protocols` empty AND `has_ssl_certificate` | `has_ssl_certificate == False` (no TLS vhost at all — see NGX-EXP group) | low |

### Security Headers (data: `headers_present`)

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

### Configuration

| ID | Name | PASS | FAIL | N/A | Severity |
|---|---|---|---|---|---|
| NGX-CONF-001 | server_tokens | see section 4 in full | see section 4 | never (see 4.1) | medium |
| NGX-CONF-002 | autoindex disabled | `autoindex_on == False` | `autoindex_on == True` | never | medium |

### Exposure

| ID | Name | PASS | FAIL | N/A | Severity |
|---|---|---|---|---|---|
| NGX-EXP-001 | TLS available | `has_ssl_certificate == True` | `has_ssl_certificate == False` | never | high |

**9 controls total** across 4 groups (3 TLS, 3 Headers, 2 Configuration, 1
Exposure). This is fewer than the 15-25 originally proposed, on purpose — see the
opening of this section.

### 6.1 Why fewer controls than originally sketched

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

## 9. Implementation checklist (for when this spec is approved)

1. Add `id=` to the relevant `audit_nginx()` findings (server_tokens, TLS, each
   header, autoindex) matching the control IDs in section 6 — see section 8.
2. `netaudit_pkg/checks/nginx_hardening.py`: new check, `category='hardening'`,
   consumes `collect_nginx_config(ssh)` (not a second independent `nginx -T` call).
3. Weight assignment for the 4 groups and the controls within each — **not yet
   decided**, deliberately left out of this document per the "structure first,
   weights after review" ordering. A follow-up pass fills in section 6's table
   with final `weight` values and a short justification for each, before code.
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
