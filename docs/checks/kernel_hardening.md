# `kernel_hardening` specification

Status: **implemented and deployed** — see section 10 for the current
implementation status. This spec follows the same methodology
`docs/checks/ssh_hardening.md` and `docs/checks/nginx_hardening.md`
established — every control below must honestly answer PASS/FAIL/N/A from
data NetAudit can actually collect, per `docs/scoring.md`'s Component
contract, before any scoring code is written.

This is the **NetAudit kernel hardening policy** — informed by the Linux
kernel documentation (`kernel.org/doc/html/latest/admin-guide/sysctl/`,
`.../networking/ip-sysctl.html`) and general CIS Benchmark guidance, but
deliberately **not** a reproduction or version-pinned mapping of any specific
CIS Benchmark release. CIS revises its Ubuntu/RHEL benchmarks substantially
between versions (the 24.04 LTS v2.0.0 revision alone added, removed, and
changed well over a hundred recommendations combined); pinning this module's
scoring to "N of CIS's M controls" would tie NetAudit's API/scoring contract
to a document NetAudit doesn't control and can't track version-for-version.
Every control below cites its own kernel-documentation rationale instead.

## 1. Scope

`kernel_hardening` is a **hardening module** (`docs/scoring.md`,
`category='hardening'`) scoring Linux kernel runtime parameters exposed via
`sysctl`: ASLR, kernel pointer/dmesg exposure, IP forwarding, ICMP/redirect
handling, reverse-path filtering, SYN flood protection, and process-dump
safety. It explicitly does **not** score:

- **Filesystem permissions, mount options, or module blacklisting** —
  separate concerns from runtime sysctl values; Lynis's and `aide_check`'s
  territory (some overlap exists — Lynis's own kernel checks — but this
  module is NetAudit's own independent scoring, same relationship
  `ssh_hardening` has to `audit_ssh_hardening()`).
- **`auditd` rules, AppArmor/SELinux policy state** — different subsystems
  entirely; out of scope for a sysctl-focused module. (AppArmor sysctl keys
  under `kernel.apparmor_*` were also excluded from the VM baseline read
  because they required root and are policy-engine-specific, not general
  kernel hardening — see section 2.)
- **Host-role detection (router vs. plain host).** `ip_forward`,
  `net.ipv6.conf.all.forwarding`, and `send_redirects` are scored as plain
  host controls in v1 with **no automatic exception for routers/NAT
  gateways** — see section 4.3. This is a conscious, documented v1 scope
  cut, not a silent gap.
- Any sysctl key not listed in section 3. The candidate list below was
  deliberately kept to 16 controls (matching the same "how many controls
  earn their place" discipline `ssh_hardening.md` applied at 14) — more keys
  exist in `sysctl -a`'s ~1080 lines than any hardening tool should score in
  v1.

## 2. Data source

Single source of truth: a new `netaudit_pkg.kernel_config.KernelConfig`,
produced by `collect_kernel_config(ssh)`, which runs `sysctl -a` (or targeted
`sysctl -n <key>` reads — see 2.2) over `ssh.sudo()`.

**Verified empirically on a live VM before this document was written**
(2026-08-10), following the same discipline `ssh_hardening.md` and
`nginx_hardening.md` established: don't assume collector behavior by
analogy, prove it on a real server first.

| Question | Finding | How verified |
|---|---|---|
| Does `sysctl -a` need root? | **Partially.** Without sudo: 1084 lines returned, 3 `permission denied` errors — all on `kernel.apparmor_*` keys (AppArmor policy-engine internals, out of this module's scope regardless). With `sudo -S`: 1081 lines, 0 permission-denied errors. | Direct comparison on the VM: `sysctl -a 2>&1 \| wc -l` (1084, 3 denied) vs `sudo -S sysctl -a <<< PASS 2>&1 \| wc -l` (1081, 0 denied). |
| Do all 16 candidate keys (section 3) read successfully without sudo? | **Yes**, on this VM. | Every key in the `for k in ...; do sysctl -n "$k"; done` baseline read returned a value, no errors. |
| Does the module use `ssh.sudo()` anyway? | **Yes — deliberate, not redundant.** Matches `ssh_config.py`'s `sshd -T` reasoning: today's 16 keys happen to be unrestricted on this VM, but relying on "these particular keys are unrestricted today" is exactly the kind of by-analogy assumption this methodology exists to avoid. A different LSM configuration, a locked-down `/proc/sys` mount, or a future added control could restrict any of them without warning. `ssh.sudo()` is the only path that's verified to return the full, error-free set unconditionally. | Policy decision following the `sudo`-by-default precedent in `ssh_config.py`/`nginx_config.py`, cross-checked against the VM's own 0-permission-denied result under sudo. |
| Is there config-file drop-in precedence to resolve, like nginx's `Include` or sshd's `sshd_config.d/`? | **No — moot on this VM, and moot by design regardless.** `/etc/sysctl.d/` contained only the stock `README.sysctl` (no `.conf` files); `/etc/sysctl.conf` was empty. But even where drop-ins exist, `sysctl -a` / `sysctl -n <key>` always reads the **kernel's own runtime effective value** directly from `/proc/sys/` — never the on-disk config files — so there is no precedence logic for this collector to reimplement, by construction (same shape of simplification `sshd -T` gave `ssh_config.py`, for the same underlying reason: ask the authority that already resolved it, don't re-resolve it yourself). | `ls -la /etc/sysctl.d/` + `cat /etc/sysctl.conf /etc/sysctl.d/*.conf` on the VM; kernel behavior (`/proc/sys` reads reflect current runtime state regardless of on-disk config) is documented kernel behavior, not VM-specific, but the VM check confirms there's nothing hiding in a drop-in this module would need to account for. |

**Consequence for this module's architecture:** `kernel_config.py`'s parser
is simpler than either `nginx_config.py` or `ssh_config.py` — `sysctl -a`
already prints one `key = value` per line (space-padded `=`), no comments,
no braces, no multi-line directives. No Include-precedence logic, no
comment-stripping.

**VM verification baseline:** confirmed against the primary test VM
(`192.168.88.20`, Ubuntu, kernel `7.0.0-29-generic`, confirmed 2026-08-11).
All 16 candidate keys in section 3 were read directly; values are recorded
in section 3's "VM baseline" column for synthetic-test reference.

### 2.1 Collection method

`sysctl -a` over `ssh.sudo()`, parsed into a flat `dict[str, str]` first
(same "generic parse, then extract typed fields" shape as
`_parse_sshd_t()`), then `KernelConfig` pulls its 16 typed fields from that
dict. Using `sysctl -a` (not 16 separate `sysctl -n` calls) is deliberate:
one SSH round-trip instead of 16, same reasoning `nginx -T`/`sshd -T`
single-call collection already established for the other two hardening
modules.

### 2.2 `KernelConfig` fields this module will read

| Field | Type | Sysctl key | Notes |
|---|---|---|---|
| `readable` | `bool` | — | `False` if `sysctl -a` returned nothing usable via sudo |
| `randomize_va_space` | `int \| None` | `kernel.randomize_va_space` | 0/1/2 |
| `dmesg_restrict` | `bool \| None` | `kernel.dmesg_restrict` | |
| `kptr_restrict` | `int \| None` | `kernel.kptr_restrict` | 0/1/2 — not bool, see 4.2 |
| `yama_ptrace_scope` | `int \| None` | `kernel.yama.ptrace_scope` | 0/1/2/3 |
| `suid_dumpable` | `int \| None` | `fs.suid_dumpable` | 0/1/2 — graded, see 4.4 |
| `ip_forward` | `bool \| None` | `net.ipv4.ip_forward` | |
| `ipv6_forwarding` | `bool \| None` | `net.ipv6.conf.all.forwarding` | |
| `tcp_syncookies` | `bool \| None` | `net.ipv4.tcp_syncookies` | |
| `icmp_echo_ignore_broadcasts` | `bool \| None` | `net.ipv4.icmp_echo_ignore_broadcasts` | |
| `accept_source_route` | `bool \| None` | `net.ipv4.conf.all.accept_source_route` | |
| `accept_redirects` | `bool \| None` | `net.ipv4.conf.all.accept_redirects` | |
| `secure_redirects` | `bool \| None` | `net.ipv4.conf.all.secure_redirects` | |
| `send_redirects` | `bool \| None` | `net.ipv4.conf.all.send_redirects` | |
| `log_martians` | `bool \| None` | `net.ipv4.conf.all.log_martians` | |
| `rp_filter_all` | `int \| None` | `net.ipv4.conf.all.rp_filter` | 0/1/2 — not bool, see 4.2 |
| `rp_filter_default` | `int \| None` | `net.ipv4.conf.default.rp_filter` | 0/1/2 |

`bool` fields parse `'0'` → `False`, `'1'` → `True`, anything else → `None`
(unexpected value, treated as unreadable for that field — same defensive
pattern `_yes_no()` uses in `ssh_config.py`, adapted from `yes`/`no` strings
to `0`/`1` strings since that's what `sysctl` prints).

## 3. Controls — VM baseline and policy

VM baseline column is the actual value observed on `192.168.88.20`
(2026-08-10) — recorded here so synthetic tests have a real reference point,
not just theoretical PASS/FAIL fixtures.

### 3.1 Binary controls (strict 0/1)

| ID | Key | PASS | FAIL | Severity | VM baseline | Rationale |
|---|---|---|---|---|---|---|
| KRN-001 | `kernel.randomize_va_space` | `2` | `0`, `1` | high | `2` (PASS) | Full ASLR (`2`) randomizes stack, heap, and mmap base; `1` omits heap; `0` disables entirely. Standard, uncontested recommendation. |
| KRN-002 | `kernel.dmesg_restrict` | `1` | `0` | medium | `1` (PASS) | Restricts `dmesg` ring buffer to `CAP_SYSLOG` — hides kernel addresses/pointers from unprivileged users, closing an info-leak used to defeat KASLR. |
| KRN-003 | `net.ipv4.tcp_syncookies` | `1` | `0` | high | `1` (PASS) | SYN flood mitigation. No legitimate reason to disable on any host role. |
| KRN-004 | `net.ipv4.icmp_echo_ignore_broadcasts` | `1` | `0` | low | `1` (PASS) | Smurf-attack mitigation (broadcast ICMP echo amplification). No downside on any host role. |
| KRN-005 | `net.ipv4.conf.all.accept_source_route` | `0` | `1` | high | `0` (PASS) | Source-routed packets let the sender dictate return path — a classic spoofing/bypass vector. No legitimate host role needs this enabled. |
| KRN-006 | `net.ipv4.conf.all.secure_redirects` | `0` | `1` | low | `1` (**FAIL**) | Even "secure" (from-known-gateway) ICMP redirects are still a MITM vector on an untrusted L2 segment; kernel docs don't distinguish trust level of the L2 itself. |
| KRN-007 | `net.ipv4.conf.all.accept_redirects` | `0` | `1` | high | `1` (**FAIL**) | ICMP redirect MITM vector. v1 applies this strictly with no router-in-trusted-network exception (see 4.3's reasoning — same scope cut as forwarding controls). |
| KRN-008 | `net.ipv4.ip_forward` | `0` | `1` | medium | `0` (PASS) | See 4.3 — no host-role auto-detection in v1. |
| KRN-009 | `net.ipv6.conf.all.forwarding` | `0` | `1` | medium | `0` (PASS) | IPv6 equivalent of KRN-008. |
| KRN-010 | `net.ipv4.conf.all.send_redirects` | `0` | `1` | medium | `1` (**FAIL**) | Kernel docs: "send redirects, if router" — default is enabled system-wide regardless of actual role. v1: no auto-detect, see 4.3. |
| KRN-011 | `net.ipv4.conf.all.log_martians` | `1` | `0` | low | `0` (**FAIL**) | Detective, not preventive — logs packets with impossible source/destination addresses (spoofing/misconfiguration signal). Severity `low` specifically because it blocks nothing by itself. |

### 3.2 Range-tolerant controls (multiple PASS values — finding text must state the actual value, not collapse it)

| ID | Key | PASS | FAIL | Severity | VM baseline | Rationale |
|---|---|---|---|---|---|---|
| KRN-012 | `net.ipv4.conf.all.rp_filter` | `1` or `2` | `0` | medium | `2` (PASS) | RFC 3704 reverse-path filtering. `1`=strict, `2`=loose — both are enabled source-address validation; `0` is disabled entirely (the real FAIL). `1` is preferable on a simple host, `2` is a legitimate choice under asymmetric routing — this module does not penalize `2` relative to `1`. See 4.1. |
| KRN-013 | `net.ipv4.conf.default.rp_filter` | `1` or `2` | `0` | low | `2` (PASS) | Secondary to `all` (applies to interfaces created after boot) — same PASS range, lower weight. |
| KRN-014 | `kernel.kptr_restrict` | `1` or `2` | `0` | medium | `1` (PASS) | `1` hides `/proc` kernel pointers from unprivileged users; `2` hides them from everyone without `CAP_SYSLOG`, including root-owned processes. Both count as "restricted" for v1; `0` (unrestricted) is the only FAIL. |
| KRN-015 | `kernel.yama.ptrace_scope` | `1`, `2`, or `3` | `0` | low | `1` (PASS) | `1`=restricted (only direct descendants ptraceable), `2`=admin-only (`CAP_SYS_PTRACE`), `3`=no attach at all. Any value >0 is a real restriction relative to the unrestricted default (`0`); v1 doesn't rank 1 vs 2 vs 3 against each other. |

### 3.3 Graded control (non-binary scoring)

| ID | Key | Score mapping | Severity | VM baseline | Rationale |
|---|---|---|---|---|---|
| KRN-016 | `fs.suid_dumpable` | `0`→100, `2`→60, `1`→0 | medium | `2` (score 60) | Kernel docs are explicit these three values are not a simple on/off: `0` disables core dumps for SUID/privileged processes entirely (best); `1` (`debug`) makes the core dump world-readable and dumpable, letting unprivileged users inspect a privileged process's memory (the real security defect — this is what the control is actually guarding against); `2` (`suidsafe`) allows the dump but restricts it to a defined, root-owned path — no cross-user information leak, but a dump is still produced. Collapsing `2` into either PASS or FAIL would misstate what actually happened; see section 4.4 for why this is the one control in this catalogue that uses a `Component` with an intermediate `score` value rather than 0/100. |

## 4. Design notes on the four disputed controls

### 4.1 `rp_filter` — range, not a strict value

Both `1` (strict) and `2` (loose) leave reverse-path filtering **on**. The
kernel network documentation (`ip-sysctl.html`) describes strict mode as
preferred for typical hosts but explicitly documents loose mode as the
correct choice under asymmetric/multi-path routing — a topology this module
has no way to detect from a single SSH session to one host. Scoring `2` as a
FAIL would be a false positive on any asymmetrically-routed host; scoring
both `1` and `2` identically without stating which is in effect in the
finding text would hide real information from the reader. Resolution:
**both `1` and `2` PASS**, and `_build_findings()`/the Component's `reason`
field must always include the actual observed value (e.g. `"rp_filter=2
(loose reverse-path filtering)"`), never a bare "PASS".

### 4.2 `kptr_restrict` — same shape as `rp_filter`, different reason

Not a routing-topology question this time — `1` and `2` are just two
different strengths of the *same* protection (hide kernel pointers), and `2`
is strictly stronger than `1`. Still resolved as a range (`1` or `2` = PASS)
rather than picking one exact value, because penalizing `1` relative to `2`
would imply `1` is a defect when it's a legitimate, commonly-deployed
baseline (many distros ship `1` by default; requiring `2` specifically would
make this control fail on a large fraction of otherwise well-hardened
hosts for no security-relevant reason at this scope).

### 4.3 Forwarding controls — no host-role auto-detection in v1

`ip_forward`, `net.ipv6.conf.all.forwarding`, and `send_redirects` are all
controls whose "correct" value genuinely depends on whether the host is a
router/NAT gateway or a plain host — the kernel documentation itself
describes `send_redirects` as "send redirects, if router." A real
router/NAT box will legitimately score FAIL on these three controls under
this module's v1 policy.

This is a **deliberate, documented scope cut**, not an oversight or a
silent gap papered over with a vague N/A: building host-role detection
(inspecting nftables NAT tables, checking for multiple non-loopback
interfaces with distinct subnets, etc.) is a real feature with its own
false-positive/false-negative surface, and mixing it into this module's
first version would significantly expand scope beyond "read 16 sysctl
values and score them" into "infer what kind of server this is." It belongs
on the roadmap as its own follow-up (a `host_role` detection helper other
modules could eventually consume too), not smuggled into `kernel_hardening`
v1's collector.

Consequence for `_build_components()`: these three controls use the plain
binary PASS/FAIL builder like any other control in section 3.1 — no special
`applicable=False` branch, no role-sniffing logic. A user auditing a known
router/NAT host should expect (and can be told, via documentation/UI copy)
that these three findings are expected and can be treated as accepted risk
for that host's role, same as any other context-dependent finding a
general-purpose hardening tool produces.

### 4.4 `suid_dumpable` — the one graded control

Every other control in this catalogue (including the range-tolerant ones in
3.2) is fundamentally binary once you look past the surface-level multiple
PASS values: "is source-validation on or off," "is ptrace restricted or
not." `suid_dumpable` is different — its three values represent three
*qualitatively different outcomes* (no dump / unsafe world-readable dump /
safe root-only dump), and `1` is the actual defect this control exists to
catch (an unprivileged user reading a privileged process's memory via its
core dump), not merely "less strict than `0`."

Modeling this as `0`/`2` both-PASS (matching the 3.2 pattern) would hide
that `2` still produces a dump at all. Modeling it as strict binary (only
`0` = PASS) would score `2` identically to `1` — the actual vulnerable
state — despite `2` having no cross-user leak. Neither binary shape tells
the truth. This is the one control where `Component.score` is set to an
intermediate value (`60`, not `0` or `100`) for the `2` case, per
`docs/scoring.md`'s explicit design for `score`/`max` supporting any scale,
not just pass/fail. `60` (not, say, `50`) reflects that `suidsafe` is closer
to the safe end of the spectrum than the midpoint — it fully closes the
information-leak vector the control cares about, it just doesn't achieve
the stricter "no dump at all" posture of `0`.

## 5. N/A conditions

Only one group-level N/A case, matching the shape both `nginx_hardening`
and `ssh_hardening` already established: if `sysctl -a` under `ssh.sudo()`
returns nothing usable (`KernelConfig.readable is False`), the whole
hardening score is omitted for that run — no partial score, no per-control
N/A within `_build_components()`. None of the 16 controls has an
individual-level N/A condition of its own (unlike `ssh_hardening`'s crypto
controls, which go N/A when their specific field is empty) — every sysctl
key here is either present with a valid value or the entire collection
already failed upstream.

## 6. Weights (severity-multiplier method, per `ssh_hardening.md` section 8.1's precedent)

Same method: severity multiplier (critical=2.0, high=1.5, medium=1.0,
low=0.5) applied per control, normalized so all 16 weights sum to exactly
`1.0` (validated by `weighted_score()` itself, not just asserted here — see
`scoring.py`'s strict tolerance). No `critical`-severity control in this
catalogue (unlike ssh_hardening's `permit_empty_passwords`) — kernel sysctl
misconfigurations are all defense-in-depth or detection controls at this
scope, none is a direct auth-bypass-grade issue.

Distribution: 4 high, 7 medium, 5 low (16 total). Unit weight = `1/15.5`
(sum of multipliers: 4×1.5 + 7×1.0 + 5×0.5 = 15.5).

| Severity | Count | Per-control weight | Controls |
|---|---|---|---|
| high | 4 | `0.096774` | KRN-001, KRN-003, KRN-005, KRN-007 |
| medium | 7 | `0.064516` | KRN-002, KRN-008, KRN-009, KRN-010, KRN-012, KRN-014, KRN-016 |
| low | 4 | `0.032258` | KRN-004, KRN-006, KRN-013, KRN-015 |
| low (remainder) | 1 | `0.032260` | KRN-011 |

The `0.032260` on KRN-011 (`log_martians`) absorbs the floating-point
rounding remainder so the 16 weights sum to exactly `1.0` within
`weighted_score()`'s `1e-6` tolerance (four `0.032258` low-severity weights
plus a plain unrounded fifth would leave a `~2e-6` gap — verified by direct
calculation, not assumed). This mirrors `ssh_hardening.md`'s own
non-round weights (`0.09375`, etc.) — a deliberate arithmetic fit, not a
typo.

```
0.096774 × 4  (high)
+ 0.064516 × 7  (medium)
+ 0.032258 × 4  (low)
+ 0.032260 × 1  (low, KRN-011, absorbs rounding remainder)
= 1.000000
```

## 7. Findings coverage

Unlike `ssh_hardening` (which references `audit_ssh_hardening()`'s
pre-existing SSH-AUTH-001/002/003 findings via `Component.finding_id`
instead of re-deriving them), no pre-existing kernel-sysctl findings
function exists in NetAudit today. `_build_findings()` for this module will
generate all 16 findings itself (for controls currently FAILing, or scoring
below 100 for KRN-016), each linked via `finding_id` to its Component,
following the exact `_f_*()` per-control builder pattern established in
`checks/ssh_hardening.py` lines ~300-420.

## 8. Synthetic validation plan (before implementation)

Per the methodology, before writing `checks/kernel_hardening.py`, synthetic
`KernelConfig` fixtures must be constructed and run through
`weighted_score()` to catch scoring-shape bugs the way `nginx_hardening`'s
own synthetic pass caught the "N/A weight redistribution makes a plain HTTP
server score too high" issue. Minimum fixture set:

1. **All-PASS fixture** (every field at its best value, `rp_filter=1`,
   `kptr_restrict=2`, `suid_dumpable=0`) → must score `100`.
2. **All-FAIL fixture** (every field at its worst value) → must score `0`.
3. **VM-baseline fixture** (the actual 2026-08-10 values from section 3) →
   sanity-check the score is "reasonable" for a stock Ubuntu VM with no
   hardening applied yet (expect a mid-range score given `accept_redirects`,
   `send_redirects`, `log_martians` all FAIL on this VM, everything else
   PASS) — this is the same "does a real server produce a score that
   matches intuition" check `nginx_hardening`'s edge-case validation did.
4. **`rp_filter=2` / `kptr_restrict=1` fixture** (both range-tolerant
   controls at their weaker-but-still-PASS value) → must score identically
   to the same fixture with `rp_filter=1`/`kptr_restrict=2`, confirming
   section 4.1/4.2's "both values PASS equally" design is actually what the
   code does, not just what the spec says.
5. **`suid_dumpable=1` vs `=2` vs `=0` fixture**, all other fields held at
   PASS → three scores that must be strictly ordered `0 < 60 < 100` at the
   Component level, and the resulting `weighted_score()` outputs must differ
   by exactly `KRN-016`'s weight × (score delta / 100) — confirms the graded
   control's arithmetic lands where section 4.4/6 says it should, not just
   "some number lower than the others."
6. **Router-shaped fixture** (`ip_forward=1`, `ipv6_forwarding=1`,
   `send_redirects=1`, everything else PASS) → confirms this scores lower
   than the all-PASS fixture by exactly those three controls' combined
   weight, demonstrating section 4.3's documented limitation is visible and
   quantifiable in the actual score, not hidden.

## 9. Open items before implementation

All resolved as of 2026-08-11:

- ~~Capture `uname -r`~~ — `7.0.0-29-generic`, recorded in section 2.
- ~~Re-verify `secure_redirects`~~ — `1` (FAIL), recorded in section 3.1.
- Collector module name: `netaudit_pkg/kernel_config.py` (matching
  `ssh_config.py`/`nginx_config.py` naming) — no objection raised, final.

Spec is now implementation-ready. VM baseline summary (2026-08-11,
`7.0.0-29-generic`): 4 of 16 controls currently FAIL on the stock test VM —
`accept_redirects`, `send_redirects`, `secure_redirects`, `log_martians`
— everything else PASSes at its current default. This becomes fixture #3
in section 8's synthetic validation plan.

## 10. Implementation status

Complete as of 2026-08-11. `netaudit_pkg/kernel_config.py` (collector),
`netaudit_pkg/checks/kernel_hardening.py` (`_build_components()`,
`_build_findings()`, `audit_kernel_hardening_score()`,
`check_kernel_hardening()`), and registration in
`netaudit_pkg/checks/__init__.py` are all merged and deployed. Verified on
a real server: scored 75/100 against the VM baseline in section 3, later
94/100 on a server with partial hardening already applied (only
`log_martians` and `suid_dumpable=2` short of full marks) — both results
matched section 8's synthetic validation predictions exactly.
