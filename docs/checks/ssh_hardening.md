# `ssh_hardening` specification

Status: **implemented and deployed** (`netaudit_pkg/checks/ssh_hardening.py`,
14 Tier-1 controls, severity-weighted per-control). This document exists to answer, before
a single line of `ssh_hardening.py` is written: *"if a server scores 82/100, does
that actually mean what we want to tell the user?"* — per `docs/scoring.md`'s
Component contract. If a control here can't honestly answer PASS/FAIL/N/A from data
NetAudit already collects, it does not go into v1.

This document follows the same methodology `docs/checks/nginx_hardening.md`
established, with one important divergence forced by a live VM verification pass
done *before* any scoring code was written (see section 2): unlike nginx, sshd
already resolves `Include` precedence and directive-repetition order in its own
effective configuration, so this module's collector does no comment-parsing or
Include-precedence logic at all — that specific class of bug nginx_hardening had
to discover and fix post-hoc simply doesn't apply here, by construction. A
related but distinct limitation — `sshd -T`'s effective config is for the
*global*/no-specific-connection context only, not any per-user/per-group/
per-host `Match` block override — still applies here exactly as `NginxConfigV2`'s
server-vs-location distinction applies to nginx; see section 4.5.

## 1. Scope

`ssh_hardening` is a **hardening module** (`docs/scoring.md`, `category='hardening'`)
scoring sshd's own configuration: authentication, authentication limits, session
forwarding, and cryptography. It explicitly does **not** score:

- **Filesystem / process ownership** (host key file permissions, sshd binary
  ownership) — OS-level hardening, Lynis's and `systemd_hardening`'s territory,
  same reasoning as `nginx_hardening`'s exclusion of this category.
- **Access restrictions** (`AllowUsers`/`AllowGroups`/`DenyUsers`/`DenyGroups`) —
  collected by `SSHConfig` but not scored in v1. See section 6.5 for why: unlike
  every other control in this catalogue, "restriction absent" is not inherently a
  defect for a general-purpose hardening tool to assert.
- **`RequiredRSASize`** — collected as a candidate but deferred to Tier 2 (section
  7). It has a fundamentally different shape (numeric threshold) from the other
  three crypto controls (allowed/forbidden algorithm sets), and mixing the two
  models in v1 was judged premature — see section 7.1.
- Anything `SSHConfig` (`netaudit_pkg/ssh_config.py`) doesn't already expose as a
  parsed field. `ssh_hardening` consumes `SSHConfig`; it does not run its own
  independent SSH commands or its own parsing of `sshd -T` output.

## 2. Data source — and why it's simpler than nginx's

Single source of truth: `netaudit_pkg.ssh_config.SSHConfig`, produced by
`collect_ssh_config(ssh)`, which runs `sshd -T` (effective configuration) over
`ssh.sudo()`.

**This was verified empirically on a live VM before any of this document was
written** (2026-08-10), following the exact lesson `nginx_hardening` learned only
after shipping: don't assume collector behavior by analogy, prove it on a real
server first.

| Question | Finding | How verified |
|---|---|---|
| Does `sshd -T` need root? | **Yes** — without sudo, `sshd -T` fails outright (`Permission denied` on a restricted `sshd_config.d/*.conf` file) and returns **zero** directives, not a partial result. | `ssh.run('sshd -T')` on the VM: exit 1, one line of stderr, no usable output. `ssh.sudo('sshd -T')`: 103 directives. |
| Does raw `/etc/ssh/sshd_config` parsing (à la nginx's old approach) give the right answer? | **No, and demonstrably so.** The VM's `sshd_config.d/50-cloud-init.conf` (mode `600`, root-only) sets `PasswordAuthentication yes`, overriding the main file where it's left commented out. A naive `cat sshd_config; cat sshd_config.d/*.conf` concatenation followed by "first regex match wins" parsing (which is exactly what the *existing* `audit_ssh_hardening()` in `server_security.py` does today) gets the right answer on this particular VM only by coincidence — the default value it falls back to when the main file's directive is commented out happens to match the Include override. A config where the main file *explicitly* sets a value and an Include file overrides it the other way would be parsed wrong. | Reconstructed and confirmed via a controlled regex trace (see PR discussion / session notes) — `re.search` finds the first occurrence in a `main + include` concatenation, which is not the same thing as "whichever file OpenSSH actually gives precedence to." |
| Does `sshd -T` solve this correctly? | **Yes.** `sshd -T` prints the fully-resolved effective value for `passwordauthentication` — one line, no ambiguity, no precedence logic for this module to reimplement. | Confirmed: `sshd -T`'s `passwordauthentication yes` matches the Include file's value, not the commented-out main-file default, because sshd resolved it correctly server-side. |
| Does `sshd -T` need comment-stripping, like `nginx_config.py` had to add? | **No — not applicable.** `sshd -T` output has no comments, no braces, no Include markers; it's already `key value` per line for every effective directive. | Directly observed in the 103-line real output — no `#` characters, no blank explanatory lines. |
| Are `AllowUsers`/`AllowGroups`/etc. printed when unset? | **No** — confirmed via `sshd -T -o AllowUsers=testuser`, which produced an `allowusers testuser` line that is otherwise completely absent from the baseline output. Absence in the output is a real fact ("no restriction configured"), not a parser gap. | Controlled `-o` override test against the live VM, not inferred. |
| Does `sshd -T` (no `-C`) reflect a `Match User`/`Match Group`/`Match Host`/`Match Address` block's overrides? | **No — this is a real, currently-uncovered limitation, found during a post-freeze quality audit, not verified against the live VM at the time this document was first written.** `sshd -T` without `-C <criteria>` prints the effective configuration for the *global*, no-specific-connection case only; any directive this catalogue scores (e.g. `PasswordAuthentication`) that a `Match` block overrides for a specific user/group/host is invisible to this collector. A config with `PasswordAuthentication no` globally but `Match User admin — PasswordAuthentication yes` would score SSH-AUTH-002 as PASS while the `admin` account is actually exempt. | Confirmed via independent third-party documentation of `sshd -T` vs `sshd -T -C user=<x>` behavior (a controlled connection-specific query returning a *different* effective value than the bare `sshd -T` call for the same directive) — not yet reproduced against this project's own VM, which currently has no `Match` blocks in `sshd_config`/`sshd_config.d/` (confirmed via `grep -RniE '^\s*Match\s'`, empty result, 2026-08-15). See the note below for what this means in practice today vs. what it would take to close. |

**What the `Match`-block limitation means in practice today:** on infrastructure
with no `Match` blocks at all (this project's own VM, confirmed above), this
limitation has zero practical effect — global and per-connection effective
config are identical when there's nothing conditional to diverge. On
infrastructure that *does* use `Match` (a real and common pattern — restricting
forwarding for a specific group, or, more security-relevant, loosening auth for
an admin/service account), this module's score is potentially describing a
connection context that doesn't correspond to any real user's actual
experience connecting to the server. This is architecturally the same shape as
`docs/checks/nginx_hardening.md` section 7.1's location-level scope limitation
— a real, deliberate, currently-uncovered gap between "what this module can see"
and "the full space of configuration this server could apply," not a bug in
the collector's `sshd -T` call itself. **Closing it properly is not simply
"run `sshd -T -C` too"** — a single arbitrary `-C user=X` doesn't answer the
question either; it would require deciding *which* connection contexts are
worth auditing (all local shell users? sudoers? a configured list?), which is
a policy decision this document doesn't have grounds to make unilaterally and
is deferred as a Tier-2 candidate (section 7) if and when `Match` usage is
confirmed on infrastructure this tool is actually used against.

**Consequence for this module's architecture:** `ssh_config.py`'s `_parse_sshd_t()`
is a single generic `key, value = line.split(None, 1)` loop — no per-directive
regex, no comment handling, no Include-precedence reimplementation. Every field
below cites which `SSHConfig` field it reads; a control needing a field
`SSHConfig` doesn't have yet is Tier 2 (section 7), not silently assumed.

**VM verification baseline:** all of the above was confirmed against
`OpenSSH_10.2p1 Ubuntu-2ubuntu3.5` (`sshd -V`). Directive availability in `sshd -T`
output can vary by OpenSSH version (e.g. `persourcepenalties`, `channeltimeout`,
and `unusedconnectiontimeout` are recent additions not present on older releases).
None of the 14 controls in this document's Tier-1 catalogue depend on a
version-specific directive — all 14 fields exist in OpenSSH releases going back
well over a decade — but this is worth stating explicitly rather than silently
assumed, since `ssh_hardening` has only been verified against one specific version
so far.

### 2.1 `SSHConfig` fields this module reads

| Field | Type | Notes |
|---|---|---|
| `readable` | `bool` | `False` when `sshd -T` needed root and didn't have it, or `sshd` isn't installed |
| `permit_root_login` | `str \| None` | e.g. `'prohibit-password'`, `'yes'`, `'no'`, `'forced-commands-only'` — deliberately not a bool, see `ssh_config.py` |
| `password_authentication` | `bool \| None` | |
| `permit_empty_passwords` | `bool \| None` | |
| `pubkey_authentication` | `bool \| None` | |
| `kbd_interactive_authentication` | `bool \| None` | |
| `hostbased_authentication` | `bool \| None` | |
| `max_auth_tries` | `int \| None` | |
| `login_grace_time` | `int \| None` | seconds |
| `x11_forwarding` | `bool \| None` | |
| `allow_tcp_forwarding` | `str \| None` | `'yes'`/`'no'`/`'local'`/`'remote'` — not a bool, see `ssh_config.py` |
| `allow_agent_forwarding` | `bool \| None` | |
| `ciphers` | `list[str]` | |
| `macs` | `list[str]` | |
| `kex_algorithms` | `list[str]` | |

Not read by any Tier-1 control: `allow_users`/`allow_groups`/`deny_users`/
`deny_groups` (collected, not scored — section 6.5) and `version` (informational
only, surfaced in the check's output but not itself a control input).

## 3. Control model

Same shape as `nginx_hardening`'s (`docs/checks/nginx_hardening.md` section 3):

```yaml
id: SSH-XXX-NNN
name: short_slug
category: authentication | auth_limits | forwarding | crypto
data_source: SSHConfig field(s) this reads
states:
  pass: {condition, score}
  fail: {condition, score}
  n/a: {condition}
severity: critical | high | medium | low
weight: <share within its category>
finding:
  title: <Finding.title when FAIL>
```

`score`/`max` per control are `0`/`1` (binary) unless stated otherwise, per
`docs/scoring.md`'s binary-controls convention.

## 4. PASS / FAIL / N/A semantics — worked example: `PasswordAuthentication`

Same requirement as `nginx_hardening.md` section 4: fix the methodology of one
control in full detail before writing the other 13.

```yaml
id: SSH-AUTH-002
name: password_authentication
category: authentication
data_source: SSHConfig.password_authentication

description: >
  Password authentication is the primary target for brute-force and credential-
  stuffing attacks against SSH. Key-based authentication is not vulnerable to
  either class of attack the same way.

states:
  pass:
    condition: "password_authentication == False"
    score: 1
  fail:
    condition: "password_authentication == True OR password_authentication is None"
    score: 0
  n/a:
    condition: never — sshd -T always resolves this to an effective True/False;
      SSHConfig.password_authentication is None only when the whole config was
      unreadable, which is a group-level N/A (section 4.1), not a per-control one.

severity: medium
weight: 0.15  # see section 8 for final authentication-group weights

finding:
  title: "PasswordAuthentication is enabled"
```

**Why `password_authentication is None` is FAIL, not N/A:** this can only happen
if `SSHConfig.readable == False` (the whole collection failed) — and that case is
handled at the group level (section 4.1), not by this control individually. If
`readable == True`, `sshd -T` has *always* resolved `passwordauthentication` to an
explicit `yes` or `no` in every OpenSSH version and configuration observed — unlike
nginx's `server_tokens`, there is no "directive genuinely absent from output"
case to reason about, because `sshd -T` prints every directive's effective value
unconditionally. So in practice this control's `None` branch is unreachable once
`readable == True`; it's included in `SSHConfig`'s type for defensive parsing
(section 2.1), not because the spec expects it to fire.

### 4.1 The one real N/A case: unreadable config

Identical shape to `nginx_hardening.md` section 4.1. Every control in this
catalogue is `applicable=False` as a **whole component group** when
`SSHConfig.readable == False` — not individually per-control. If `sshd -T`
needed root and didn't have it, nothing was resolved, so no control has a
legitimate opinion. `ssh_hardening` returns the standard `docs/scoring.md` N/A
shape for the affected component(s), mirroring `nginx_hardening`'s handling of
the same case.

## 5. Finding ↔ Component relationship

**Unlike `nginx_hardening`, this section describes a two-phase plan, not
completed work.** `nginx_hardening` could link `Component.finding_id` to
`audit_nginx()`'s findings because `audit_nginx()` already had stable `id=` values
on every relevant finding, added specifically in preparation (see
`docs/checks/nginx_hardening.md` section 8). The existing `audit_ssh_hardening()`
(`server_security.py`) has **no finding ids at all today**, and — per the decision
recorded in this project's working notes — is not being refactored until *after*
this specification and its synthetic validation are complete, so that the existing
check's findings aren't silently absorbed into a scoring contract before the
contract itself is settled.

**Sequencing, to be carried out in this order:**

1. This document is finalized and synthetic-validated (this document, sections
   6–8) — **no code changes yet**.
2. `audit_ssh_hardening()` is refactored to consume `SSHConfig` (via
   `collect_ssh_config()`) instead of its own raw-text parsing, with its existing
   external behavior preserved and pinned by regression tests written *before*
   the refactor lands.
3. Stable `id=` values are added to `audit_ssh_hardening()`'s findings, matching
   this document's control IDs, exactly as was done for `audit_nginx()`.
4. Only then is `ssh_hardening.py` written, with `Component.finding_id`
   referencing the now-stable ids from step 3 for every control that has an
   existing finding to reuse.

Of this catalogue's 14 controls, the existing `audit_ssh_hardening()` only
produces findings for 3 today (`PermitRootLogin yes`, `PasswordAuthentication
yes`, `PermitEmptyPasswords yes`) — the other 11 will need findings authored
either as part of step 2/3 (extending the existing check) or as `ssh_hardening`
self-generated findings (`nginx_hardening`'s pattern for controls with no
pre-existing finding — see `docs/checks/nginx_hardening.md` section 5). Which
path each of the 11 takes is a step-2 decision, not fixed here.

## 6. Control catalogue — Tier 1

**14 controls**, four groups: 6 Authentication, 2 Authentication limits,
3 Forwarding, 3 Cryptography.

### 6.0 Status matrix (all 14 controls, at a glance)

| ID | Control | PASS | FAIL | N/A |
|---|---|---|---|---|
| SSH-AUTH-001 | Root password/keyboard-interactive auth disabled | `'no'`, `'prohibit-password'`, `'forced-commands-only'` | `'yes'` | never (§4.1 only) |
| SSH-AUTH-002 | PasswordAuthentication | `False` | `True` | never |
| SSH-AUTH-003 | PermitEmptyPasswords | `False` | `True` | never |
| SSH-AUTH-004 | PubkeyAuthentication | `True` | `False` | never |
| SSH-AUTH-005 | KbdInteractiveAuthentication | `False` | `True` | never |
| SSH-AUTH-006 | HostbasedAuthentication | `False` | `True` | never |
| SSH-AUTH-007 | MaxAuthTries | `<= 4` | `> 4` | never |
| SSH-AUTH-008 | LoginGraceTime | `<= 60` | `> 60` | never |
| SSH-FWD-001 | X11Forwarding | `False` | `True` | never |
| SSH-FWD-002 | AllowTcpForwarding | `'no'` | anything else | never |
| SSH-FWD-003 | AllowAgentForwarding | `False` | `True` | never |
| SSH-CRYPTO-001 | Ciphers | no weak cipher present | any weak cipher present | `ciphers` empty |
| SSH-CRYPTO-002 | MACs | no weak MAC present | any weak MAC present | `macs` empty |
| SSH-CRYPTO-003 | KexAlgorithms | no weak KEX present | any weak KEX present | `kex_algorithms` empty |

All 14 are binary (PASS/FAIL), no WARN state — unlike `nginx_hardening`'s
`NGX-TLS-002`, no control here was judged to have a genuine, non-arbitrary middle
state. See section 6.6 for why `PermitRootLogin`'s several non-`'no'` values are
not split into a PASS/WARN/FAIL three-state despite `prohibit-password` being
arguably less bad than plain `yes`.

### 6.1 Authentication (data: `permit_root_login`, `password_authentication`,
`permit_empty_passwords`, `pubkey_authentication`, `kbd_interactive_authentication`,
`hostbased_authentication`)

| ID | Name | PASS | FAIL | Severity |
|---|---|---|---|---|
| SSH-AUTH-001 | Root password/keyboard-interactive auth disabled | `'no'`, `'prohibit-password'`, `'forced-commands-only'` | `'yes'` | high |
| SSH-AUTH-002 | PasswordAuthentication disabled | `False` | `True` | medium |
| SSH-AUTH-003 | PermitEmptyPasswords disabled | `False` | `True` | critical |
| SSH-AUTH-004 | PubkeyAuthentication enabled | `True` | `False` | high |
| SSH-AUTH-005 | KbdInteractiveAuthentication disabled | `False` | `True` | medium |
| SSH-AUTH-006 | HostbasedAuthentication disabled | `False` | `True` | low |

**SSH-AUTH-001's semantics, precisely — this took a revision to get right.** An
earlier draft of this control was named "PermitRootLogin disabled," PASS only on
`'no'`. That's a defensible but *different* security property from what OpenSSH's
own `sshd_config(5)` man page documents `prohibit-password` as guaranteeing:

> If this option is set to `prohibit-password` (or its deprecated alias,
> `without-password`), password and keyboard-interactive authentication are
> disabled for root. If this option is set to `forced-commands-only`, root login
> with public key authentication will be allowed, but only if the `command`
> option has been specified [...] All other authentication methods are disabled
> for root.

That's a directly-cited, unambiguous OpenSSH guarantee, not this document's
inference: `prohibit-password` and `forced-commands-only` both **provably**
eliminate root password/credential-guessing attacks — the property this control
actually cares about, matching the same brute-force/credential-stuffing threat
model as SSH-AUTH-002/003. Scoring `prohibit-password` as FAIL, as the earlier
draft did, would have penalized a server that has already eliminated the
practical attack this control exists to catch, just because it hasn't also
disabled root login outright — a stricter, different property.

**Renamed accordingly**, to describe what it actually measures: "root password/
keyboard-interactive auth disabled," not "root login disabled." PASS on `'no'`,
`'prohibit-password'` (and its deprecated alias `'without-password'`, which
`SSHConfig`/`sshd -T` may surface depending on OpenSSH version — see note below),
and `'forced-commands-only'`; FAIL only on `'yes'`, the one value under which
OpenSSH does *not* disable password/keyboard-interactive auth for root.

**"Root login completely disabled" is a genuinely different, stricter property**
— deferred as its own Tier-2 control (section 7) rather than conflated with this
one. That control would score `'no'` as its only PASS, everything else FAIL —
worth having, but as an explicitly separate, explicitly stricter assertion, not
smuggled into SSH-AUTH-001's semantics.

**No WARN introduced for this control.** The three-way distinction between `'no'`
/`'prohibit-password'`/`'forced-commands-only'` was resolved by giving the
control an accurately narrower name (above), not by adding a middle severity
tier — consistent with section 6.6's general policy against inventing WARN states
without an authoritative ranking to justify them. Here, unlike the case section
6.6 originally described, OpenSSH's own documentation *does* draw a bright,
citable line — just not the line "closer to `no` is better than further from
it" the earlier draft assumed. The line is "does this value disable root
password guessing, yes or no," which is exactly a binary PASS/FAIL question.

**Version note:** `'without-password'` is documented as a deprecated alias for
`'prohibit-password'` with identical behavior — `SSHConfig.permit_root_login`
passes through whatever `sshd -T` prints verbatim (no normalization in the
collector, per its data-only design), so this control's PASS condition lists
both spellings explicitly rather than assuming only one appears.

**SSH-AUTH-003 severity rationale:** `critical`, the highest severity in this
catalogue. Empty passwords combined with password authentication enabled is a
direct, trivial authentication bypass — distinct from every other control here,
which weakens defense-in-depth rather than removing authentication outright.

**SSH-AUTH-005 rationale:** `KbdInteractiveAuthentication` is a commonly
overlooked password-equivalent path — PAM-backed keyboard-interactive
authentication can prompt for a password exactly like `PasswordAuthentication`
does, so disabling only the latter while leaving this enabled doesn't achieve the
intended hardening. Scored as its own control (not folded into SSH-AUTH-002)
because the two are independently configurable and independently exploitable.

### 6.2 Authentication limits (data: `max_auth_tries`, `login_grace_time`)

| ID | Name | PASS | FAIL | Severity |
|---|---|---|---|---|
| SSH-AUTH-007 | MaxAuthTries bounded | `<= 4` | `> 4` (including sshd's default of 6) | low |
| SSH-AUTH-008 | LoginGraceTime bounded | `<= 60` | `> 60` (including sshd's default of 120) | low |

**Threshold rationale — not arbitrary round numbers:** `MaxAuthTries` default
(6) permits more brute-force attempts per connection than a hardened profile
should allow; `4` is the commonly-cited CIS/hardening-guide threshold balancing
usability (a human mistyping a passphrase twice) against attack surface.
`LoginGraceTime` default (120s) is the window an unauthenticated connection can
hold a slot open; `60` halves it while remaining generous for slow interactive
key selection. Both thresholds are deliberately conservative (not the tightest
possible value) — a v1 control here should not require an unusual value that
would make an otherwise well-configured, ordinary server fail for no
practical benefit. **This is a threshold-based control, same numeric-comparison
shape as the deferred `RequiredRSASize` (section 7.1)** — included in v1 here
(unlike RequiredRSASize) because the PASS/FAIL threshold is well-established in
existing hardening guidance, not something this document had to invent.

### 6.3 Forwarding (data: `x11_forwarding`, `allow_tcp_forwarding`,
`allow_agent_forwarding`)

| ID | Name | PASS | FAIL | Severity |
|---|---|---|---|---|
| SSH-FWD-001 | X11Forwarding disabled | `False` | `True` | low |
| SSH-FWD-002 | AllowTcpForwarding disabled | `'no'` | anything else (`'yes'`, `'local'`, `'remote'`) | medium |
| SSH-FWD-003 | AllowAgentForwarding disabled | `False` | `True` | medium |

**SSH-FWD-002's PASS is strict (`'no'` only), not "not `'yes'`":** `'local'` and
`'remote'` are partial-forwarding modes, each still enabling a real tunneling
capability that most hardening guidance recommends disabling entirely unless
specifically needed. Treating them as PASS would understate the exposure; giving
them their own WARN state was considered and rejected for v1 to keep this
control binary like the rest of the catalogue (see section 6.6) — a future
revision could reconsider this specific case if real-world usage shows the binary
split too coarse.

### 6.4 Cryptography (data: `ciphers`, `macs`, `kex_algorithms`)

| ID | Name | PASS | FAIL | N/A | Severity |
|---|---|---|---|---|---|
| SSH-CRYPTO-001 | No weak ciphers | none of `ciphers` matches the weak-cipher policy (6.4.1) | at least one match | `ciphers` empty | high |
| SSH-CRYPTO-002 | No weak MACs | none of `macs` matches the weak-MAC policy (6.4.1) | at least one match | `macs` empty | medium |
| SSH-CRYPTO-003 | No weak KEX | none of `kex_algorithms` matches the weak-KEX policy (6.4.1) | at least one match | `kex_algorithms` empty | high |

**N/A condition rationale:** an empty list from `SSHConfig` means `sshd -T`
either wasn't reached (group-level N/A, section 4.1 — shouldn't co-occur with a
non-empty result for other fields) or, defensively, that a future OpenSSH change
stops printing one of these three lines under some circumstance this document
hasn't anticipated. Scoring an empty list as FAIL would be asserting "no
algorithms are configured," which is not a claim this module has evidence for;
N/A is the honest state when there's nothing to evaluate.

**Why three independent controls, not one combined "crypto" control:** a server
with excellent KEX but one weak MAC algorithm still enabled is a different,
more specific problem than a server weak across the board — collapsing the three
into one control would hide which class of algorithm needs fixing, the same
reasoning `nginx_hardening`'s NGX-TLS-001/002 split follows (protocol-legacy vs.
protocol-modernness are different facts about the same field). A future
`SSH-CRYPTO-004` (host-key/pubkey-accepted algorithms) was considered and
explicitly deferred — see section 7.

#### 6.4.1 Weak-algorithm policy

**This is a deny-list (blocklist), not an allow-list.** An OpenSSH maintainer's
explicit guidance against positive allow-lists (jtesta/ssh-audit#324) was the
deciding factor: specifying "only these exact algorithms are PASS" silently
penalizes any future algorithm OpenSSH introduces that happens not to appear on
the list — including algorithms *more* secure than everything on it. A deny-list
of *specifically named, established-weak* algorithms doesn't have this problem:
a new algorithm is PASS by default unless it's later added to the deny-list for a
documented reason.

**Ciphers — FAIL if any of these appears in `ciphers` (substring match on
family, not full exact-string list, since vendors append suffixes):**
- Any `*-cbc` mode cipher (`3des-cbc`, `aes128-cbc`, `aes192-cbc`, `aes256-cbc`,
  `blowfish-cbc`, `cast128-cbc`, `twofish*-cbc`) — CBC-mode ciphers in SSH are
  vulnerable to plaintext-recovery attacks and are consistently flagged weak
  across every source consulted (F5, RHEL/kifarunix, EnterpriseDT).
- Any `arcfour*` (RC4-family) — broken stream cipher, deprecated industry-wide.

**MACs — FAIL if any of these appears in `macs` (substring match, not exact
name, because both plain and `-etm@openssh.com` variants of the same weak hash
are equally weak — confirmed via cross-referenced sources; the ETM construction
changes encrypt/MAC ordering, not the underlying hash's collision resistance):**
- Anything containing `md5`.
- Anything containing `sha1` (covers `hmac-sha1`, `hmac-sha1-96`, and their
  `-etm@openssh.com` variants alike).
- Anything containing `ripemd`.
- Anything containing `-96` (truncated-MAC variants, flagged weak by F5/RHEL
  regardless of underlying hash).
- Anything containing `umac-64` (covers `umac-64@openssh.com` and its
  `-etm@openssh.com` variant, not `umac-128`/`umac-128-etm@openssh.com` —
  found missing from the deny-list during a post-freeze quality audit of
  this module: `umac-64`'s 64-bit authentication tag is the same class of
  weakness the `-96` rule already targets (a short, truncated tag with
  more practical collision resistance than a full-length MAC), just at a
  different bit-length this document hadn't separately named. Confirmed
  weak by multiple independent, cross-referenced sources (ManageEngine's
  misconfiguration catalogue, Trend Micro/IMSVA's vulnerability-scan
  guidance, a macOS/Jamf hardening writeup noting `umac-64@openssh.com`
  ships enabled by default on macOS's sshd, and the `ssh-audit` tool's own
  weak-algorithm classification) — the same majority-source bar this
  section already applies to every other entry on this list.

**KEX — FAIL if any of these appears in `kex_algorithms` (substring match):**
- Anything containing `group1-sha1` (`diffie-hellman-group1-sha1` — 1024-bit
  DH group, RFC 9142 formally moves this to "SHOULD NOT").
- Anything containing `group14-sha1` (SHA-1-based, superseded by the
  `-sha256`/`-sha512` variants of the same group).
- `diffie-hellman-group-exchange-sha1` specifically (SHA-1-based group
  exchange; the `-sha256` variant is fine and must not match this rule).

**Match strategy note for implementation (not yet code, but constraining the
future implementation):** matching must be substring/family-based, not an exact
list of full algorithm strings, precisely because the deny-list approach's whole
point is resilience to naming variants (`@openssh.com` suffixes, `-etm` suffixes,
future vendor-specific suffixes on the same weak primitive) — an exact-string
list would need updating every time a vendor ships a new suffix on an
already-known-weak algorithm, which defeats the reason a deny-list was chosen
over an allow-list in the first place.

**What is deliberately NOT on this deny-list, and why:** `hmac-sha2-256`/
`hmac-sha2-512` (non-etm) — flagged as "deprecated" by exactly one source
(Oracle/Connector-NET) among six consulted, and specifically because SHA-2 in
non-ETM mode is still considered acceptable by the majority view (RHEL, F5,
EnterpriseDT all list only sha1/md5/ripemd/96-bit-truncated as weak, not plain
sha2). Including it would make this policy stricter than mainstream hardening
guidance without a clear consensus justification — the ETM-preference case is a
best-practice preference, not a weak-algorithm classification, and belongs in a
future refinement of SSH-CRYPTO-002 (WARN for non-etm SHA-2, FAIL for actual
SHA-1/MD5/RIPEMD/truncated), not v1's binary PASS/FAIL.

### 6.5 Why AllowUsers/AllowGroups/DenyUsers/DenyGroups are collected but not scored

`SSHConfig` exposes all four fields (`ssh_config.py`, confirmed empirically that
`sshd -T` only prints them when actually configured). None becomes a Tier-1
control in this document, for a reason distinct from every Tier-2 deferral in
section 7: **this isn't a data gap, it's a policy-applicability gap.**

A server with `PermitRootLogin no`, `PasswordAuthentication no`, and
`PubkeyAuthentication yes` — genuinely well-hardened by every other control in
this catalogue — is not automatically worse for having no `AllowUsers`
restriction. Many legitimate, properly-hardened deployments never set it (e.g.
single-purpose servers with exactly one SSH-capable account already governed by
key-based auth). Asserting "restriction absent → FAIL" the way `nginx_hardening`
asserts "no TLS certificate → FAIL" (`NGX-EXP-001`) doesn't hold the same logical
shape: TLS absence is *always* worse than TLS presence for a public HTTPS site,
but `AllowUsers` absence is not *always* worse than `AllowUsers` presence — it
depends on the account/access model the server actually uses, which
`ssh_hardening` has no way to know. Scoring it would therefore be asserting a
policy this module doesn't have grounds for, not measuring a fact.

If a future version wants to score this, it needs a narrower, defensible
condition than "field is empty" — e.g. "server has more than N login-capable
accounts AND no AllowUsers/AllowGroups restriction," which requires data
`SSHConfig` doesn't currently collect (the account list). Left as a documented
non-goal for v1, not a Tier-2 item, since it's not a "collect more data later"
problem — it's a "decide the policy" problem.

### 6.6 Why no WARN states in this catalogue (contrast with `nginx_hardening`)

`nginx_hardening` has exactly one three-state control (`NGX-TLS-002`, TLS 1.2
present-but-not-1.3) because that specific case has a well-established, named
middle ground ("acceptable fallback, not preferred baseline" per OWASP/NIST —
see `docs/checks/nginx_hardening.md` section 6.1). Two candidates for a WARN
state were considered here and rejected for v1:

- **`PermitRootLogin`'s non-`'no'` values** (`'prohibit-password'`,
  `'without-password'`, `'forced-commands-only'`, `'yes'`) are not equally bad —
  `'prohibit-password'` (this project's own VM's actual value) still permits
  root login via a key, which is a meaningfully different risk than plain
  `'yes'`. A three/four-state split was considered but rejected for v1: unlike
  TLS 1.2-vs-1.3 (where "acceptable fallback" has an external standards
  citation), there's no equally authoritative source this document found that
  ranks `'prohibit-password'` vs `'forced-commands-only'` vs `'without-password'`
  against each other — inventing that ranking here would be exactly the kind of
  unsupported judgment call this methodology exists to avoid (contrast the
  `docs/checks/nginx_hardening.md` section 1 principle: "if a control can't
  honestly answer PASS/FAIL/N/A ... it does not go into v1" — extended here to
  "an honest 3+-state ranking," not just PASS/FAIL). Binary (`'no'` = PASS,
  everything else = FAIL) is the defensible v1 answer; a future revision citing
  a specific authoritative ranking could split this further.
- **`AllowTcpForwarding`'s `'local'`/`'remote'` partial modes** — see section
  6.3's SSH-FWD-002 note. Same reasoning: no citation-backed ranking of
  `'local'` vs `'remote'` risk was found, so both are FAIL rather than
  inventing a WARN tier between them and `'no'`.

## 7. Control catalogue — Tier 2

Not implemented in v1. Each entry names why it's deferred rather than
implemented today.

| ID | Name | Why deferred |
|---|---|---|
| SSH-CRYPTO-004 | Weak host-key / pubkey-accepted algorithms | `SSHConfig` doesn't currently expose `hostkeyalgorithms`/`pubkeyacceptedalgorithms`/`casignaturealgorithms` as parsed fields (collector reads them from `sshd -T` no differently than ciphers/macs/kex, so adding them is a small collector extension, not a redesign) — deferred to keep v1's crypto scope to the three most commonly-cited algorithm classes, not because the data is hard to get. |
| SSH-RSA-001 | RequiredRSASize below policy threshold | See section 7.1 — different control shape (numeric threshold vs. algorithm-set membership) than SSH-CRYPTO-001/002/003; deliberately not mixed into v1's model. |
| SSH-ACCESS-001+ | AllowUsers/AllowGroups/DenyUsers/DenyGroups-based restriction scoring | See section 6.5 — not a data gap, a policy-applicability gap; needs a narrower condition than "field empty" that this document doesn't have grounds to assert yet. |
| SSH-PROTO-001 | SSH protocol version (Protocol 1 vs 2) | Not present in modern `sshd -T` output at all — OpenSSH has not supported SSHv1 for many years; this directive is effectively extinct on any server modern enough to be running the OpenSSH version this document's VM verification used. Listed for completeness, not because it's a live gap. |
| SSH-AUTH-00X | Root SSH login completely disabled (`'no'` only) | A genuinely stricter property than SSH-AUTH-001 (section 6.1) — SSH-AUTH-001 asserts "root password-guessing is impossible," which `'prohibit-password'`/`'forced-commands-only'` both satisfy per OpenSSH's own documentation; this control would assert "root cannot log in via SSH at all," which only `'no'` satisfies. Deferred rather than merged into SSH-AUTH-001 specifically to avoid the mistake an earlier draft of this document made (see 6.1's note) — conflating two different, both-legitimate security postures into one control that can only score one of them correctly. A future revision can add this as its own control once there's a case for scoring both postures simultaneously; v1 scores the narrower, more universally-applicable one (password-guessing elimination) since a hardened server that still permits key-based root access for automation/backup purposes, per the man page's own stated rationale for `forced-commands-only`, shouldn't be penalized by a general-purpose hardening tool for a legitimate operational choice. |

### 7.1 `RequiredRSASize` — deferred, not rejected

Unlike `nginx_hardening`'s `mandatory` flag (rejected outright,
`docs/checks/nginx_hardening.md` section 8.2, because the problem it would solve
was already solved by weights alone), `RequiredRSASize` is a genuinely
plausible v1 candidate that's deferred for a narrower reason: it needs a
policy decision (what's the PASS threshold — 2048? 3072?) this document hasn't
made, and mixing a threshold-based control into a catalogue of three
set-membership controls (Ciphers/MACs/KEX) without first establishing whether
`ssh_hardening`'s Cryptography group should have a consistent internal model is
premature. `SSH-AUTH-007`/`008` (section 6.2) are threshold-based and *are* in
v1 — the distinction is that their thresholds cite established, uncontested
hardening-guide numbers (CIS-style 4 attempts, halved grace time), whereas
`RequiredRSASize`'s threshold search turned up genuine disagreement in sources
consulted (2048 vs. 3072 vs. "no consensus, depends on threat model") that this
document isn't resolving by fiat. Revisit once a specific threshold has a
citation this document can stand behind, the same bar section 6.2 met.

## 8. Weights and synthetic validation

**Run against the actual `weighted_score()` engine** (2026-08-10, spike script),
following the same process that caught `nginx_hardening`'s Exposure-weight
problem. The resulting weights below are hardcoded as-is in
`netaudit_pkg/checks/ssh_hardening.py` (e.g. `_W_PERMIT_ROOT_LOGIN = 0.0900`).

### 8.1 Severity multiplier — the weighting mechanism

Per-control weight within each group is not equal-split. A first synthetic pass
using equal weights within the Authentication group revealed a real
inconsistency: `SSH-AUTH-001` (declared `severity: high`) and `SSH-AUTH-002`
(declared `severity: medium`) produced an *identical* score penalty (7.5 points
each) — the severity metadata claimed one control mattered more, but the
arithmetic didn't reflect that at all.

**Fix: severity multiplier, normalized within each group.**

| Severity | Multiplier |
|---|---:|
| `critical` | 2.0 |
| `high` | 1.5 |
| `medium` | 1.0 |
| `low` | 0.5 |

This is **NetAudit scoring policy, not an OpenSSH or industry standard** — no
citation is claimed or needed for the multiplier values themselves, unlike the
weak-algorithm deny-list (section 6.4.1) which does cite external sources. What
*is* fixed by this policy: `critical=2.0` does not mean "this control is worth
20% of the total score" — it means the control gets twice the weight of a
`medium`-severity control **relative to other controls in the same group**, with
group weights (section 8.2) unchanged. Per-control weight formula:

```
control_weight = group_weight * (severity_multiplier / sum_of_multipliers_in_group)
```

Applied to Authentication (group weight 45%, severities: high, medium, critical,
high, medium, low — sum of multipliers = 1.5+1.0+2.0+1.5+1.0+0.5 = 7.5):

| Control | Severity | Weight |
|---|---|---:|
| `permit_root_login` (SSH-AUTH-001) | high | 0.0900 |
| `password_authentication` (SSH-AUTH-002) | medium | 0.0600 |
| `permit_empty_passwords` (SSH-AUTH-003) | critical | 0.1200 |
| `pubkey_authentication` (SSH-AUTH-004) | high | 0.0900 |
| `kbd_interactive_authentication` (SSH-AUTH-005) | medium | 0.0600 |
| `hostbased_authentication` (SSH-AUTH-006) | low | 0.0300 |

Authentication limits (group 10%, both `low` — equal split, since equal
severity legitimately means equal weight, not a case the multiplier needed to
fix):

| Control | Severity | Weight |
|---|---|---:|
| `max_auth_tries` (SSH-AUTH-007) | low | 0.0500 |
| `login_grace_time` (SSH-AUTH-008) | low | 0.0500 |

Forwarding (group 20%, severities: low, medium, medium — sum = 2.5):

| Control | Severity | Weight |
|---|---|---:|
| `x11_forwarding` (SSH-FWD-001) | low | 0.0400 |
| `allow_tcp_forwarding` (SSH-FWD-002) | medium | 0.0800 |
| `allow_agent_forwarding` (SSH-FWD-003) | medium | 0.0800 |

Cryptography (group 25%, severities: high, medium, high — sum = 4.0):

| Control | Severity | Weight |
|---|---|---:|
| `ciphers` (SSH-CRYPTO-001) | high | 0.09375 |
| `macs` (SSH-CRYPTO-002) | medium | 0.0625 |
| `kex_algorithms` (SSH-CRYPTO-003) | high | 0.09375 |

**Sum of all 14 control weights: 1.000000** (verified programmatically, not by
hand).

### 8.2 Group weights (unchanged from initial draft)

| Group | Weight |
|---|---:|
| Authentication | 45% |
| Authentication limits | 10% |
| Forwarding | 20% |
| Cryptography | 25% |

### 8.3 Synthetic scenario results

All scores below are `weighted_score()`'s actual output against the section 8.1
weights, cross-checked by hand for every scenario (not just spot-checked) before
being recorded here.

| Scenario | Score | Manual check |
|---|---:|---|
| 1. Fully hardened (every control PASS) | 100 | 100 − 0 |
| 2. `PasswordAuthentication yes` only | 94 | 100 − 6.0 (medium, weight 0.06) |
| 3. `PermitRootLogin yes` only | 91 | 100 − 9.0 (high, weight 0.09) |
| 3b. `PermitRootLogin prohibit-password` only | 100 | PASS per revised SSH-AUTH-001 semantics (section 6.1) |
| 3c. `PermitRootLogin forced-commands-only` only | 100 | PASS, same reasoning |
| 3d. `PermitRootLogin no` only | 100 | PASS, strictest case |
| 4. All three forwarding controls enabled | 80 | 100 − 20.0 (4+8+8, full Forwarding group) |
| 5a. Weak cipher only (`3des-cbc` present) | 91 | 100 − 9.375 = 90.625 → round-even → 91 (high, weight 0.09375) |
| 5b. Weak MAC only (`hmac-sha1-etm@openssh.com` present) | 94 | 100 − 6.25 → round → 94 (medium, weight 0.0625) — **confirms the deny-list's `-etm` variant matching works, not just the plain name** |
| 5c. Weak KEX only (`diffie-hellman-group14-sha1` present) | 91 | 100 − 9.38 → round → 91 |
| 5d. All three crypto controls weak | 75 | 100 − 25.0 (full Cryptography group) |
| 6. Mixed — this session's actual VM config | 58 | see breakdown below |
| 7. Crypto fields empty (`ciphers`/`macs`/`kex_algorithms` all `[]`) | 100 | all three N/A, redistributed across the other 11 (all PASS) — **confirms an empty/missing field does not silently become FAIL** |

**Scenario 6 breakdown** (this session's VM: `permit_root_login=prohibit-password`,
`password_authentication=True`, `max_auth_tries=6`, `login_grace_time=120`,
`x11_forwarding=True`, `allow_tcp_forwarding=yes`, `allow_agent_forwarding=True`,
`macs` includes `hmac-sha1-etm@openssh.com`, everything else hardened):

| Control | Status | Weight lost |
|---|---|---:|
| `permit_root_login` | PASS (revised semantics) | 0 |
| `password_authentication` | FAIL | 0.0600 |
| `max_auth_tries` | FAIL (6 > 4) | 0.0500 |
| `login_grace_time` | FAIL (120 > 60) | 0.0500 |
| `x11_forwarding` | FAIL | 0.0400 |
| `allow_tcp_forwarding` | FAIL | 0.0800 |
| `allow_agent_forwarding` | FAIL | 0.0800 |
| `macs` | FAIL (`hmac-sha1-etm@openssh.com`) | 0.0625 |
| everything else | PASS | 0 |

Total weight lost: 0.4225 → score = round(100 × (1 − 0.4225)) = 58. This is a
real, unmodified VM — not a synthetic worst-case — and it scores 58, a
mid-range result that plausibly matches "reasonably but not fully hardened,"
which is the kind of sanity check this whole validation process exists to run.

### 8.4 What this validation confirmed

- Severity multiplier produces the intended differentiation: `high`-severity
  `permit_root_login` (91) now costs more than `medium`-severity
  `password_authentication` (94) when each fails alone — the inconsistency
  that motivated section 8.1 in the first place is resolved.
- The weak-algorithm deny-list's substring matching correctly catches
  `-etm@openssh.com` suffix variants (scenario 5b), not just bare algorithm
  names — this was a specific, deliberate test of the matching strategy
  described in section 6.4.1, not incidental.
- N/A redistribution behaves correctly when all three crypto fields are empty
  (scenario 7) — no silent FAIL.
- The revised SSH-AUTH-001 semantics (section 6.1) were validated against all
  four `PermitRootLogin` values individually (scenarios 3/3b/3c/3d) before
  being accepted, not just spot-checked on the one value this session's VM
  happens to use.
- `weighted_score()` itself was not modified at any point in this process —
  every result above came from the existing, unmodified scoring engine.

## 9. Implementation checklist (for when this spec is approved)

1. Synthetic validation: run the scenarios listed in section 8 through
   `weighted_score()` with draft control weights, adjust weights until results
   make sense as a security assessment (mirrors `nginx_hardening.md` section
   8.1's process). **Done — section 8, 2026-08-10.** Discovered and fixed two
   issues before any production code existed: (a) equal-weight-within-group
   ignored declared severity, fixed via the severity multiplier (section 8.1);
   (b) SSH-AUTH-001's original "PermitRootLogin disabled" semantics penalized
   `prohibit-password`/`forced-commands-only` despite OpenSSH's own
   documentation showing both eliminate root password-guessing, fixed by
   renaming the control to match what it actually measures (section 6.1).
2. Refactor `audit_ssh_hardening()` (`server_security.py`) to consume
   `collect_ssh_config()`/`SSHConfig` instead of its own raw-text `directive()`
   parsing, with existing external behavior pinned by regression tests written
   *before* the refactor. **Not started — deliberately sequenced after step 1,
   see section 5.**
3. Add stable `id=` to `audit_ssh_hardening()`'s findings, matching this
   document's control IDs (`SSH-AUTH-001` etc.), for the 3 controls it already
   covers (`PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`).
4. Write findings (either extending `audit_ssh_hardening()` or as
   `ssh_hardening`-self-generated, per the `nginx_hardening` pattern) for the
   remaining 11 controls.
5. `netaudit_pkg/checks/ssh_hardening.py`: **`_build_components(cfg)` done**
   (2026-08-10) — pure scoring layer only, all 14 controls, weights
   transcribed as exact fractions (not the rounded `0.0938` an earlier draft
   of this document used — `0.09375`, matching what the code actually
   computes). Verified against all 13 section 8.3 synthetic scenarios via
   `weighted_score()`, exact score match on every one. **Not yet done:** SSH
   I/O (`audit_ssh_hardening_score(ssh)` — naming still TBD to avoid
   colliding with the existing `audit_ssh_hardening()` findings function),
   registry entry, `_build_findings()`. `netaudit_pkg/checks/ssh_hardening.py`
   is deliberately not yet imported by `netaudit_pkg/checks/__init__.py` —
   it has no registry entry to trigger, and importing it prematurely would
   suggest it's wired up when it isn't.
6. Tests: pure-function tests for each control's PASS/FAIL/N/A logic (no SSH
   mock needed, same pattern as `test_nginx_hardening_components.py`), plus
   `FakeSSHExecutor` tests for the full check.
7. Full suite + VM verification against a live `sshd -T`, same rigor as
   `nginx_hardening`'s VM pass — including deliberately toggling at least one
   setting (e.g. temporarily via `sshd -T -o` overrides, not editing the live
   config) to confirm the score moves the expected direction, not just that a
   fully-hardened baseline scores well.

## 10. Explicit exclusions (recap)

- Filesystem/process ownership — Lynis / `systemd_hardening`'s territory
  (section 1).
- `AllowUsers`/`AllowGroups`/`DenyUsers`/`DenyGroups` — collected, not scored;
  policy-applicability gap, not a data gap (section 6.5).
- `RequiredRSASize` — Tier 2, different control shape, deferred pending a
  citable threshold (section 7.1).
- Host-key/pubkey-accepted/CA-signature algorithms — Tier 2, small collector
  extension away, deferred to keep v1's crypto scope bounded (section 7).
- SSH protocol version (v1 vs v2) — Tier 2, effectively extinct on any
  OpenSSH version modern enough to matter (section 7).
- Weight finalization and synthetic validation — **Done**; see section 8 for
  the shipped weights.
