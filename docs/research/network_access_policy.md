# Network access policy, manual remediation, verification: research and draft contract

Status: **research and draft contract for USER approval** (2026-11-27). No
production code until USER approves the contract in §12. Implementer: Claude;
reviewer: GPT/Codex. Mode: MANUAL.

Review pass 1 (GPT/Codex) returned three points, all taken in:

- **R1**: an audit from another place never proves closure; it is context
  (§2, §6.3).
- **R2**: undo by a unique instance tag with an exact match (§5).
- **R3**: `policy_changed` is decided from the effective decision under both
  revisions (§6.6).

The test matrix (§11) has cases for each.

Source of the task: `.ai/TASK.md` "NEW USER TASK — access policy, manual
remediation, verification" and `.ai/DECISIONS.md` 2026-11-27. USER, about
protecting accounting:

> применять не стоит. это надо сделать только вручную

The flow is therefore fixed:

1. NetAudit **finds** a problem.
2. It **explains** the risk and the correction.
3. **The operator changes the settings by hand.**
4. A repeat audit **checks what can be observed**.

NetAudit never changes a target, never runs a suggested command and has no
"apply" button, not even behind a confirmation.

Base: `main` `784f8d2` (v1.4.0). Labels as in `network_audit.md`:

- **FACT**: read in the code or measured;
- **HYPOTHESIS**: to be measured on the stand before it is relied on;
- **UNKNOWN**: not known yet.

The scenario this contract must handle:

- The auditor plugs a laptop into the guest (or staff) network. Accounting
  answers over SMB and RDP, although the owner's rules forbid that path.
- The fact that a service answers is evidence of **access to the service**.
  It does not prove a login, an exploit, or that anyone can change
  payments.

---

## 1. What NetAudit has today — FACT (`784f8d2`)

### 1.1 Intent: names and a "sensitive" mark, no rules

- `lan_segments (client, cidr, name, sensitive)` is the only place where the
  operator says what a segment is for. It comes from migration `_m6`
  (`netaudit_pkg/storage.py:204-215`). Only private IPv4 subnets are
  accepted, and a name is at most 60 characters (`storage.py:797-815`).
- The labels are reached through `GET/PUT /api/lan/segments`
  (`web/app.py:514-536`).
- There is **no source, no service and no allow/forbid**. "Sensitive" only
  raises the severity of `NET-SEG-001` (`checks/lan_audit.py:603-608`).
- Segment names are guessed from device names and kinds (`_suggest`,
  `lan_audit.py:546-561`). They are suggestions and are never used as intent.

### 1.2 What "isolation" means today

**`NET-SEG-001:<own>:<segment>:<port>`** (`lan_audit.py:580-608`):

- It fires when a service from `SENSITIVE_SERVICES` (`lan_audit.py:530-541`)
  of a device in another scanned segment answers from the vantage segment:
  - SMB 139/445, RDP 3389, WinRM 5985, VNC 5900, SSH 22, NFS 2049, rsync
    873, and the database ports.
- The answer must be a port whose protocol is not "other".
- Severity: high when the target segment is marked sensitive, medium
  otherwise.
- The router and this machine are skipped: router management is covered by
  `RTR-*`.

**`NET-SEG-002`**: no other subnet answered, and workstations or servers
share the segment with phones or printers (`lan_audit.py:611-624`).

Both are **configuration observations**. Neither can tell an allowed path
(an admin PC reaching accounting RDP) from a forbidden one.

### 1.3 Where the audit runs from

- `check_lan_audit` runs in the NetAudit process (`lan_audit.py:1024`).
  `nmap` starts on the machine where NetAudit runs and uses that machine's
  interface: `lan.vantage()` returns its interface, address, subnet,
  gateway, wireless flag and DNS (`lan.py:102-127`).
- The browser only starts the run and shows the result. **The source of
  every observation is the NetAudit host's address**, not the browser's.
- Devices of another segment are known only by their IP: MAC addresses do
  not cross the router.

### 1.4 What a probe keeps

- Ports are probed with `nmap -sT -Pn -sV --version-light`, on the fixed
  list `lan.SCAN_PORTS` (49 TCP ports), with a per-host timeout of 180 s
  (`lan.py:48-50, 246-256`).
- `parse_nmap_xml` keeps **open ports only** (`lan.py:320-322`). Closed and
  filtered ports, `extraports`, and the reasons nmap gives are dropped.
- The per-device markers `_scanned` and `_timedout` are removed from the
  saved result (`lan_audit.py:962-963`). What survives in the saved result:
  - the open ports;
  - `answered`, i.e. how the device answered: tcp, neighbour, dns or
    announced;
  - the device's gaps in text.
- Measured on this machine, against `127.0.0.1` only:
  `nmap -sT -Pn --reason` (unprivileged) reports a closed port as
  `state="closed" reason="conn-refused"`. The device sent a TCP reset, so it
  is up and the packet reached it.

### 1.5 Comparison between audits: none for the network

- Trends pick a unit only from parameters in
  `storage.IDENTITY_PARAM_KEYS = {target, url, hostname, host, server,
  domain}` (`storage.py:339`, `trends.py:259-273`).
- `lan_audit` has `client, authorization, level2, interface, share_with_ai,
  vuln_lookup`, so **it never gets a trend**.
- `lan_merge.merge` keeps the newest audit per vantage subnet and joins the
  vantages (`lan_merge.py:19-76`). A finding from an older audit simply
  vanishes once a newer audit from that vantage exists. Nothing ever says
  "resolved", "still there" or "could not be compared".

### 1.6 Fix texts

- Every fix text is one static string per control id: `lan.fix.<ID>` in
  `web/static/i18n.js`, RU and EN. It is chosen by `lanFindingHtml`
  (`web/static/index.html:2146-2155`), whatever device is actually there.
- `lan.fix.NET-SEG-001` (`i18n.js:98, 743`) always shows a MikroTik
  `/ip firewall filter` command with example subnets, **even when the
  router is not a MikroTik or is unknown**.
- No text says which access must be kept, how to avoid locking yourself out,
  how to undo the change, or how to confirm the fix.

---

## 2. One audit with rules, step by step (the scenario)

1. The operator opens the Network audit tab for the client `Office`. In
   "Access rules" they enter:
   - Guests `192.168.50.0/24` → Accounting `192.168.30.0/24`, any service:
     **forbidden**.
   - Staff `192.168.10.0/24` → Accounting, SMB: **forbidden**.
   - The admin PC `192.168.10.5` → Accounting, RDP and SMB: **allowed**.
     Note: "1C administration".

   Revision 1 is saved.
2. The auditor plugs in on the guest Wi-Fi and runs the audit. The vantage
   is `192.168.50.77`. `192.168.30.20` answers SMB 445 (confirmed) and
   RDP 3389 (confirmed).
3. Result: two `NET-POL-001` **violations**: Guests → 192.168.30.20 SMB, and
   the same for RDP. Each one carries:
   - the rule it breaks;
   - the evidence: port, protocol evidence, vantage, time;
   - what it does *not* prove: no login was tried.
4. The fix guidance says where the change belongs: the device that routes
   between `192.168.50.0/24` and `192.168.30.0/24`, here the identified
   MikroTik.
   - Before the drop rule it puts allow lines that keep the paths the
     policy allows.
   - It tells the operator to use Safe Mode and how to undo the change.
   - It ends with: re-run the audit from the guest Wi-Fi, with an audit from
     the admin PC just before and just after it.
5. The operator changes the router by hand. The auditor runs the audit from
   the admin PC, then from the guest Wi-Fi, then from the admin PC again.
   - From the guest Wi-Fi, 192.168.30.20 answers nothing at all.
   - From the admin PC it answers RDP both times, and that path is
     **allowed**, so it is not a problem.
6. The retest view says **"not verified — probably blocked"** for the
   guest→accounting items. It shows both admin-side answers and their times.
   - It does *not* say "closed". Nothing seen from the guest Wi-Fi during
     that probe proves the server was up at that moment. It might have been
     switched off and back on in between (review R1, §6.3).
   - A block of the whole host can only be proven from inside the path:
     the router's own counters or ARP table at that moment. That is phase B
     (`network_audit.md` §9), not this contract.
   - Had the fix blocked only SMB and RDP while the server still answered
     another port to guests, the same guest-side probe would prove it up,
     and the two items would be **closed**.
   - SMBv1 on that server (`NET-SMB-001`) is **not** "fixed": it is
     "not reachable from Guests". The software is unchanged until a scan
     shows otherwise.

---

## 3. Access policy model (proposal)

### 3.1 A rule

| Field | Values |
|---|---|
| `id` | stable per client (`r1`, `r2`…), never reused |
| `source` | a private CIDR (segment) or one private address (host); `any` |
| `destination` | a private CIDR or one private address; `any` |
| `service` | a named group (`SMB` = 139,445; `RDP` = 3389; `WinRM` = 5985; `VNC`; `SSH`; `NFS`; `rsync`; each database), `tcp/<port>` (1–65535), or `any` |
| `decision` | `allow` or `forbid` |
| `note` | ≤ 200 characters; **required for an `allow` that is more specific than a `forbid`** (an exception must say why) |

Limits:

- at most 200 rules per client;
- private IPv4 only, the same check as for labels;
- the rule list is saved whole, and each save makes a new **revision**.

### 3.2 When a rule applies to an observation

An observation is *(source address, destination address, TCP port, protocol
evidence, time, vantage)*, where:

- the source address is **always the NetAudit host's own address** in that
  run (§1.3);
- the destination is a device that answered, and the port is one of its
  open ports.

A rule matches when:

- its source contains the vantage address;
- its destination contains the device;
- its service contains the port.

Consequence (deterministic, and shown in the UI): a host-level source rule
for `192.168.10.5` matches only an audit that runs **at** `192.168.10.5`.
From `192.168.10.77` the broader Staff rule applies, because a firewall may
well treat the two addresses differently.

### 3.3 Precedence

1. **The most specific matching rule wins.** Specificity is compared in this
   order:
   1. destination: host > longer prefix > shorter prefix > `any`;
   2. then source, the same way;
   3. then service: `tcp/<port>` > named group > `any`.
2. **Two matching rules of equal specificity with different decisions** give
   a `conflict`. The path is not called allowed or forbidden.
   - A policy error `NET-POL-002` (medium) names both rules and the evidence.
   - The fix is to correct the rules.
   - (Alternative for USER, default 3: "forbid wins" on a tie.)
3. **No matching rule** gives `unknown`: the owner said nothing. This is
   never a violation.
   - The existing `NET-SEG-001` and `NET-SEG-002` still report what they
     report today. These are configuration observations, not policy
     violations.
4. **A sensitive mark is not a rule.** It still raises `NET-SEG-001` to high
   and makes a violation into that segment high. On its own it never makes a
   violation.

### 3.4 How policy and configuration findings meet

- A **forbidden** path that answers is `NET-POL-001:<source>:<dest-ip>:<port>`:
  - high when the service is in `SENSITIVE_SERVICES` or the destination
    segment is sensitive, medium otherwise;
  - confidence from the protocol evidence: confirmed → high, possible →
    medium;
  - `requires_manual_verification` when the evidence is only "possible".
- An **allowed** path that answers is an `allowed` row in the policy table.
  The devices and ports it covers leave `NET-SEG-001`. If every answering
  device and port of a `NET-SEG-001` item is allowed, the item disappears;
  the policy table still lists the paths.
- An **unknown** path stays exactly as today (`NET-SEG-001` / `NET-SEG-002`).
- Device findings (`NET-SMB-001`, `NET-VULN-*`…) are about the device itself.
  The policy never hides them.

**As built in PR A:**

- Every (device, port) a rule **decides** leaves `NET-SEG-001`: allowed,
  forbidden (it becomes `NET-POL-001`) and conflict (`NET-POL-002`). The
  same exposure is never counted twice. `NET-SEG-001` is the observation
  for paths the owner has said nothing about.
- The router is a destination like any device (a forbid on WinBox from the
  guests is a violation); this machine never is.
- A source rule is judged only when it contains the vantage address; the
  other rules are listed as "for other places".
- Each host gets only the extra ports of the forbid rules whose destination
  holds it: one extra `nmap -sT` run per set of ports, no scripts.

### 3.5 What the policy cannot see

- Internet exposure: "external" in this tab means **the source segment that
  was observed**. Exposure to the internet needs a separate, authorized
  observation from outside and is never inferred from LAN tests.
- UDP services.
- Ports outside the probe list. The ports named in `forbid` rules are added
  to the probe of their destinations: at most 20 extra ports per run, and
  the rest are a gap (§4.3).
- Paths from sources where NetAudit did not run.
- Any proof of login, of exploitability, or of what an account inside the
  service may do.

---

## 4. Result semantics

### 4.1 Per rule-relevant path in one audit

| State | Meaning |
|---|---|
| `violation` | forbidden, and the service answered (`NET-POL-001`) |
| `allowed` | allowed, and the service answered |
| `conflict` | equal-specificity rules disagree (`NET-POL-002`) |
| `unknown` | answered; no rule covers it |
| `not_observed` | a forbidden path whose service did not answer in a **complete probe** (§4.3); this is not proof of a block, see §6 |
| `not_checked` | the destination was not scanned, timed out, or sits in a cut segment; or the port was not probed; the reason is given |

### 4.2 Coverage item `access_policy`

| Status | When |
|---|---|
| `not_checked` | at least one `forbid` rule has a destination that was not fully probed, or a port that was not probed; the item is named |
| `ok` | rules exist, every forbid rule was probed, and no violation or conflict |
| `warn` / `danger` | taken from the worst `NET-POL-*` finding, as everywhere |
| no item | the client has no rules: the limit `access_policy` says "no rules: allowed and forbidden paths are not judged" |

### 4.3 A complete probe of a device (new evidence kept in the result)

Per device, the result gets a `probe` field:

- `ports`: the ports probed;
- `open`: the open ports;
- `closed`: ports that answered with a reset (`conn-refused`);
- `filtered`: ports with no answer;
- `timed_out`: whether the scan timed out;
- `complete`: scanned, not timed out, and the nmap run had no error.

The `extraports` summary of nmap is kept as counts, with its reasons.

A probe of port P on device D is complete when:

- D's probe is complete, and
- P is in `probe.ports`.

Older reports have no `probe` field, so every comparison that needs one is
`not_verified: an older report without probe detail`.

### 4.4 Revisions in the report

The report stores:

- `policy.revision`;
- a copy of the rules it was judged by;
- the per-path states;
- the policy errors.

An old report therefore keeps showing what it was judged against, even after
the rules change.

---

## 5. Manual remediation guidance (proposal)

For each `NET-POL-001`, `NET-SEG-001` and `NET-SEG-002` the guidance is built
from the observation itself, not from a static string. It has nine parts:

1. **What and where**: the source and destination (names, subnets,
   addresses), the service and the port.
2. **Evidence and uncertainty**:
   - what answered, and the protocol evidence;
   - when it was seen and from which address;
   - "access to the service, not a login".
3. **Why it matters**, one sentence per service. SMB: files and shares. RDP:
   a desktop login prompt. Database: direct data access.
4. **Where to change it**:
   - The path crosses the gateway: the device that routes between the two
     subnets, i.e. the vantage gateway or the found gateway.
   - Same segment: the destination's own firewall, or Wi-Fi client
     isolation.
   - Unknown router: "find the device that routes between these subnets".
5. **Steps tailored to the platform**, in two cases:
   - The router is **positively identified** as MikroTik (vendor from MNDP,
     banner or MAC, `router.version_source`). Then exact RouterOS lines with
     the real subnets, addresses and ports. Every line of one guidance
     carries the same **instance tag** as its whole comment:
     `comment="netaudit-fix-<10 hex>"`.
     - The tag is the first 10 hex characters of SHA-256 over (client,
       finding id, vantage address, run time). It is unique per finding and
       per run, so two devices or two runs never share one.
     - A catalog id alone (`NET-POL-001`) or a finding id alone would be
       shared by several fixes (review R2). The tag contains only
       `[a-z0-9-]`, so it needs no quoting.

     The `allow` lines from the policy come **before** the `drop` line, and
     they are tagged with the same instance tag. Text only: there is a copy
     button and nothing ever runs.
   - **Anything else**: no device-specific command. A checklist instead:
     - which subnets or addresses and which port to block;
     - which allowed paths to keep;
     - "check this in your router's or firewall's own manual".

   The destination's own firewall gets commands only when its platform is
   known. A Windows command (`New-NetFirewallRule … -RemoteAddress
   <source subnet>`) is shown only when the device was identified as
   Windows from its SMB or RDP answers.
6. **Prerequisites and exceptions**:
   - The allow rules from the policy that must stay working (e.g. admin PC →
     accounting RDP).
   - If the policy has **no** allow rule for that destination: "who still
     needs accounting? add them as allowed first", so the operator does not
     cut off the accountants' own work.
   - Make a backup first. On MikroTik: `/export file=before-netaudit` on the
     router, kept on the router.
   - Use Safe Mode (Ctrl+X in the terminal), so that a lost session undoes
     the change.
7. **Verify**:
   - re-run the audit from the same place;
   - for a block of the whole host, run an audit from an allowed place
     right before and right after it. That shows "probably blocked" with its
     limits; it is not proof (§6.3).
8. **Undo** exactly this fix and nothing else, by its own tag, with an
   exact match and never a pattern (review R2):
   - first `/ip firewall filter print where comment="netaudit-fix-3f9a2c41d0"`,
     to see the lines;
   - then `/ip firewall filter remove [find where comment="netaudit-fix-3f9a2c41d0"]`.

   Lines of other NetAudit fixes and the operator's own rules are untouched.
   Platforms other than MikroTik get generic text: remove the rules you added
   for this finding.
9. **What it does not fix**: a vulnerable service stays vulnerable. A block
   reduces who can reach it; updating it is a separate finding.

In the backend the guidance is built as structured data (`guidance: {where,
steps[], keep[], verify[], undo[], platform}`) with RU/EN keys and
parameters. The Web renders it escaped, and the CLI prints it as text.

The existing static `lan.fix.NET-SEG-001` loses its hard-coded MikroTik
command whenever the router is not identified as MikroTik.

---

## 6. Verification after manual changes (proposal)

### 6.1 Which audits are compared

A **retest** compares the newest audit of a client with the previous
**comparable** audit from the same place. Two audits are comparable when all
of these hold:

- same client;
- same vantage subnet **and** the same vantage address;
- same scanned range;
- same level;
- both have a verdict other than `not_started`.

Anything else gives `not_comparable`, with the reason:

- the vantage changed;
- the address changed: "a firewall may treat the new address differently";
- the range changed;
- the level changed.

### 6.2 States per item

| State | When |
|---|---|
| `still_present` | the same finding id, or the same violating path, appears again |
| `closed` | it is gone **and** the closure is proven (§6.3) |
| `new` | present now, absent before |
| `not_verified` | gone, but not proven. Reasons: no answer at all, timeout, nmap error, port not probed, segment cut, older report without probe detail |
| `policy_changed` | the **effective decision** for the item changed between the two revisions (§6.6). The item is judged anew in the new audit, never "closed" |
| `not_comparable` | §6.1 |

A failed scan, a timeout, a device that vanished, lost credentials, a missing
version or incomplete collection **never** becomes `closed`.

### 6.3 What proves that an exposure is closed

A previously answering path is `closed` only on evidence from **the same new
probe from V**. The path is device D, port P, seen from vantage V. The new
audit from V must have made a **complete probe of P on D** (§4.3), and one of
these must be true:

- **(a)** P did not answer, and a TCP connection to another port of D
  completed from V in the same run. D was up and reachable from here during
  this probe, so P is blocked or stopped.
- **(b)** P itself answered with a reset (`conn-refused`). The path is
  refused, either because the service stopped or because a router rejects
  it with a reset. The exposure is closed either way.
  - A reset on *another* port does not prove that D is up, because a router
    may send resets on D's behalf. It does not count.

Otherwise the item is `not_verified`.

**Audits from other places are context, never proof** (review R1). A device
seen answering from an admin vantage earlier or later can have been off
during the probe from V. The same is true if it was switched on after that
probe while no firewall changed. Reducing a time window does not remove
this.

**Coordinated verification** gives context only. Audits of the same client
from places allowed to reach D may have seen D answer **both before and
after** the probe from V, each within **30 minutes** of it. Then:

- the item stays `not_verified`, with the context "probably blocked —
  answered from <vantage> at <t1> and <t2>";
- its limit is stated: "the device could have been off during this probe;
  only evidence from the path itself (the router's counters or ARP table,
  phase B) would prove it";
- it never counts as `closed` or "resolved", and never changes the verdict
  or the score.

Without such a bracket, the text is: "the device did not answer at all — it
may be switched off, or blocked entirely".

### 6.4 Exposure versus the software itself

- A device finding gone because its port no longer answers from V is
  `not_reachable_from_here`, never `closed`. This covers `NET-SMB-001`,
  `NET-VULN-*`, `NET-TEL-001` and similar.
- The software is called fixed only when a scan (from any vantage) sees the
  same service again with the condition gone. Examples: the new version is
  no longer affected, or SMBv1 is now refused.
- The retest view keeps two columns: **reachable from here** and **fixed on
  the device**.

### 6.5 Timestamps and identity

- Each row shows the time of both observations and their vantages.
- A device is identified by IP in other segments. In the own segment it is
  also identified by MAC; if the MAC differs, the state is `not_comparable`
  with the reason "another device has this address now".

### 6.6 Effective decision under both revisions (review R3)

Comparing only the rule that decided the old item misses changes made by
other rules:

- a more specific `allow` added under an unchanged broad `forbid`;
- an override removed;
- a new rule of equal specificity that makes a conflict.

So every compared item is judged under **both** saved rule sets:

- the old report's copy of the rules, and the new report's copy (§4.4);
- the item is the tuple *(vantage address, device, port)*;
- precedence is applied in full (§3.3) under each set.

Each side gives an effective decision (`allow`, `forbid`, `unknown` or
`conflict`) and the rule or rules that decided it.

| Old → new decision | Comparison |
|---|---|
| the same, and not `conflict` | compared as usual (§6.2–6.3); if a different rule now decides it, the row says so ("now decided by r5 instead of r1") |
| different (e.g. `forbid` → `allow`, `allow` → `forbid`, `unknown` → `forbid`) | `policy_changed` |
| either side `conflict` | `policy_changed` |

Edits to rules that do not match the tuple change nothing for it, so an
unrelated edit does not invalidate the whole comparison. `NET-SEG-001` rows
depend on the policy too (§3.4), so they are judged the same way. Device
findings (`NET-SMB-001`, `NET-VULN-*`…) do not depend on the policy.

---

## 7. Data model and migration (proposal)

- **Migration `_m7`** adds one table:
  `lan_policy (client TEXT, revision INTEGER, rules TEXT /* JSON */, saved_at
  TEXT, PRIMARY KEY (client, revision))`.
  - Revisions are immutable, and the current policy is the highest revision.
  - Nothing existing changes: labels stay in `lan_segments`, and reports are
    untouched.
- **Validation** is in `storage`, like the labels: private CIDR or address,
  known service, decision, note length, at most 200 rules, and a required
  note for an exception.
- **Result fields** (new, optional):
  - `policy {revision, rules, paths, errors}`;
  - `devices[].probe` (§4.3);
  - `findings[].guidance` (§5);
  - the coverage item `access_policy` and the limit `access_policy`.
- **Retest**:
  - computed from saved reports on demand, with no new table;
  - `GET /api/lan/retest?client=` returns the comparison of the newest audit
    with its previous comparable audit, plus the other-place audits used
    as context.
- **API**: `GET /api/lan/policy?client=` returns the current revision.
  `PUT /api/lan/policy` takes `{client, rules}`, validates them, saves a new
  revision and returns it. Both have the same JSON checks as
  `/api/lan/segments`.
- **CLI**:
  - `netaudit lan-policy show --client X`;
  - `netaudit lan-policy set --client X --file rules.json`, which validates,
    saves a new revision and prints the diff;
  - `netaudit lan-retest --client X`, which prints the table of §6.2;
  - `run lan_audit` prints the policy states and the guidance in its report.
- **AI analysis**: as today, the network report is sent only if the run
  allows it. Rules and notes are part of that report.

---

## 8. Web, RU/EN (proposal)

- **The "Access rules" panel in the Network audit tab, per client**:
  - a table with From, To, Service, Allowed/Forbidden and Note;
  - add, edit and delete;
  - the current revision, and "saved — the next audit is judged by
    revision N".
- **The result**:
  - a "Policy" section that lists violations, conflicts, unknown paths and
    allowed paths, each with its evidence and time;
  - the guidance of §5 for each finding.
- **The map**:
  - a violation is a red arrow from the vantage segment to the destination;
  - an allowed path is a grey dashed arrow;
  - unknown paths keep the current `NET-SEG-001` look.
- **A "Retest" section**:
  - the §6.2 table, with both timestamps and vantages, and the
    other-place audits shown as context ("probably blocked", never proof);
  - a short legend: "closed means proven, not verified means we could not
    see".
- **Fixed texts**, shown once on the tab and the report:
  - "The scan starts from the computer where NetAudit runs (<address>,
    <interface>), not from this browser."
  - "'From another segment' means from <vantage subnet>. Exposure to the
    internet is not tested here."

---

## 9. Safety

- Rules are data that NetAudit judges observations against. They are never
  sent to a device.
- Guidance is text. There is no apply button, no command execution, and no
  SSH, API or WinBox session to the router for this feature.
- No new scan types. The only change to probing: the ports named in forbid
  rules are added for their destinations (≤ 20 per run, private addresses
  only, under the existing confirmation).
- No logins, no credential use, no exploitation, and no testing of payment
  or accounting applications.
- No new secrets are stored. Notes are free text: the UI warns "do not put
  passwords here", and the storage refuses notes longer than 200 characters.

---

## 10. Rollout — three PRs, each RED → GREEN with its own review

- **PR A — the policy model and its evaluation**:
  - storage `_m7` and validation;
  - the API and CLI `lan-policy`;
  - extra probe ports from forbid rules;
  - `probe` evidence in the result (closed and filtered kept);
  - path states, `NET-POL-001` and `NET-POL-002`, and the coverage item and
    limit `access_policy`;
  - NET-SEG-001 minus the allowed paths;
  - the Web rules panel, the Policy section and the map arrows;
  - RU/EN, the catalog `docs/checks/finding_ids.md`, and tests.
- **PR B — manual guidance**:
  - structured guidance for `NET-POL-001`, `NET-SEG-001` and `NET-SEG-002`;
  - MikroTik lines only for an identified MikroTik, otherwise checklists;
  - allow-before-drop from the policy, backup, Safe Mode, verify and undo;
  - the Web copy button; CLI text; RU/EN.
- **PR C — retest**:
  - comparable audits, the §6.2 states, the effective decision under both
    revisions (§6.6) and the "probably blocked" context;
  - exposure versus software (§6.4);
  - `/api/lan/retest`, `lan-retest`, and the Web Retest section;
  - E2E fix and retest on the stand.

---

## 11. Test matrix

Unit tests use synthetic nmap XML and reports, with a temporary database
(the `isolated_db` fixture).

| # | Case | Expected |
|---|---|---|
| 1 | Guests→Accounting any: forbid; SMB 445 answers from guests | `NET-POL-001` high, confidence high |
| 2 | the same from the admin PC address with allow SMB, RDP (note) | `allowed`; no `NET-POL-001`; no `NET-SEG-001` for those ports |
| 3 | the same from another Staff address | the Staff rule applies, not the admin host rule |
| 4 | no rules | `unknown`; `NET-SEG-001` as today; limit `access_policy` |
| 5 | sensitive mark, no rules | `NET-SEG-001` high; **no** `NET-POL-001` |
| 6 | equal-specificity allow + forbid | `conflict`, `NET-POL-002`; neither violation nor allowed |
| 7 | host destination forbid inside a segment allow | the host rule wins |
| 8 | `tcp/8443` forbid inside an `any` allow | the port rule wins |
| 9 | exception without a note | refused by validation (API 400, CLI error) |
| 10 | two clients with the same subnets | rules never cross clients |
| 11 | forbid rule port outside `SCAN_PORTS` | probed; over the cap → `not_checked` naming it |
| 12 | destination timed out / segment cut | `not_checked`, coverage `not_checked` |
| 13 | port only "possible" protocol | `NET-POL-001` with `requires_manual_verification` |
| 14 | guidance, router identified MikroTik | RouterOS lines with real subnets, allow lines first, every line with the one instance tag |
| 15 | guidance, router unknown | no device command; checklist |
| 16 | guidance, no allow rule for the destination | the "who still needs it" prerequisite |
| 17 | retest: port gone, other port of D open in the same run from V | `closed` |
| 18 | retest: port now `conn-refused` | `closed` |
| 18a | retest: port silent, only *another* port `conn-refused` | `not_verified` (a router may reset on D's behalf) |
| 19 | retest: device silent, no other audit | `not_verified` |
| 20 | retest: device silent; an admin audit yesterday saw it; today it is switched off (R1) | `not_verified`, never `closed` |
| 20a | retest: device off during the probe from V, switched on later; an admin audit after the probe sees it; no firewall change (R1) | `not_verified`, never `closed` |
| 20b | retest: admin audits within 30 min before **and** after the silent probe from V both see D | `not_verified` with "probably blocked" context and its limit; verdict and score unchanged |
| 21 | retest: an admin audit only before, or only after, or outside 30 min | `not_verified`, no "probably blocked" context |
| 22 | retest: nmap error / timeout / port not probed | `not_verified` with the reason |
| 23 | retest: other vantage address, same subnet | `not_comparable` |
| 24 | retest: the deciding rule changed (forbid → allow) | `policy_changed` |
| 24a | retest: R1 (broad forbid) unchanged, a more specific allow R2 added for the path; P silent, another port open (R3) | `policy_changed`, not `closed` |
| 24b | retest: an override allow removed, the broad forbid now decides (R3) | `policy_changed` |
| 24c | retest: R1 unchanged, a new equal-specificity allow makes a conflict (R3) | `policy_changed` |
| 24d | retest: an unrelated rule for another destination added | compared as usual; `closed` still possible |
| 24e | retest: same decision, another rule now decides (a narrower forbid added) | compared as usual; the row names both rules |
| 25 | retest: SMBv1 gone because 445 blocked | `not_reachable_from_here`, not fixed |
| 26 | retest: an older report without `probe` | `not_verified` (older report) |
| 27 | retest: own-segment MAC changed | `not_comparable` |
| 28 | Web: rule text, note and guidance with `<script>` | escaped everywhere |
| 29 | guidance for fix A and fix B (two devices, same catalog id) | different instance tags; A's undo line matches A's tag exactly and nothing of B or the operator's own rules (R2) |
| 30 | the same finding in two runs | two different tags; each undo matches only its own run's lines |
| 31 | undo text | exact `comment="…"` match; never `~` or a prefix pattern |

**E2E on the CI stand (PR A, PR C):**

- Policy: segment A (`172.30.10.0/24`) → segment B (`172.30.20.0/24`), SMB
  forbidden. The current stand already answers 445 on `172.30.20.20`, so the
  audit gives `NET-POL-001`.
- The test applies an `iptables -I FORWARD` drop or reject on `gw`. This
  changes the stand, never the system under test. Then it runs the audit
  again:
  - Drop SMB only (`-p tcp --dport 445`): the server still answers Redis
    6379 to segment A in the same run, so the SMB item is `closed` (§6.3 a).
  - Drop all of 172.30.20.20: the result is `not_verified`. With scanner
    runs from segment B right before and after, it is `not_verified` with
    the "probably blocked" context, never `closed`.
  - Remove the drop again with no other change, and stop the server during
    the segment A run: the result is `not_verified` (R1).
- The `quiet` device (drops everything) stays `not_verified`.

---

## 12. Draft contract (for USER approval)

- **P1. Access rules per client**: source → destination (segment or host),
  service, allow/forbid, note. Revisions. Precedence: most specific wins; a
  tie is a conflict; no rule means unknown; a sensitive mark is not a rule
  (§3).
- **P2. Policy findings**:
  - `NET-POL-001` violation and `NET-POL-002` conflict;
  - allowed paths leave `NET-SEG-001`;
  - device findings are never hidden;
  - the coverage item and limit `access_policy`;
  - evidence and time on every item (§3.4, §4).
- **P3. Probe evidence**:
  - closed and filtered ports with their reasons, and probe completeness per
    device;
  - the ports named in forbid rules are probed too (≤ 20 per run) (§4.3).
- **P4. Manual guidance** built from the observation (§5):
  - where the change belongs, the steps, which access to keep, backup and
    Safe Mode, how to verify, how to undo, what it does not fix;
  - device commands only for a positively identified platform;
  - every line of one fix carries a unique instance tag, and undo matches
    exactly that tag;
  - text only, nothing applied.
- **P5. Retest** (§6):
  - comparable audits only;
  - the states `still_present`, `closed`, `new`, `not_verified`,
    `policy_changed` and `not_comparable`;
  - `closed` only with proof from the same probe (§6.3); audits from other
    places are context;
  - `policy_changed` from the effective decision under both revisions (§6.6);
  - exposure kept apart from the software being fixed.
- **P6. Web and CLI, RU/EN** (§7–8):
  - the rules panel, Policy and Retest sections, and map arrows;
  - the texts about where the scan starts and what "from another segment"
    means;
  - `lan-policy` and `lan-retest`.
- **P7. Tests**: §11. Unit tests use a temporary database; E2E runs on the
  stand.

**Not in this contract:**

- applying anything to a device;
- reading the router's configuration (phase B, `network_audit.md` §9);
- internet-side scans;
- UDP;
- MFA or workflow enforcement;
- testing accounting applications.

**Defaults chosen by Claude (USER may change any):**

1. Order: PR A → PR B → PR C (§10).
2. Audits from other places are **context only** (§6.3). The "probably
   blocked" bracket needs allowed-place audits **both before and after** the
   probe, each within **30 minutes** of it.
3. A tie between allow and forbid is a **conflict** (alternative: forbid
   wins).
4. `NET-POL-001` severity is **high** for a service from
   `SENSITIVE_SERVICES` or a sensitive destination, **medium** otherwise.
5. At most **20** extra probe ports from rules per run, and at most **200**
   rules per client.
6. Guidance names a device command only for MikroTik (router) and Windows
   (host firewall). Other platforms get a checklist until they are
   researched.
7. A host-level source rule matches only an audit run from that address
   (§3.2).

---

## 13. FACT / HYPOTHESIS / UNKNOWN

**FACT:**

- §1, from the code at `784f8d2`.
- Unprivileged `nmap -sT --reason` reports a closed port as `conn-refused`
  (measured on `127.0.0.1`).

**HYPOTHESIS, to be measured on the stand in PR A:**

- With an `iptables REJECT --reject-with icmp-admin-prohibited` on the
  router, an unprivileged connect scan reports the port as `filtered` with
  the reason `host-unreach` or `admin-prohibited`.
  - Linux maps ICMP code 13 to `EHOSTUNREACH`, so a connect scan may not
    tell an administrative block from an unreachable host.
  - Until measured, a reject counts as "no answer". It is not proof.
- A `tcp-reset` reject on the router gives `conn-refused`, which looks the
  same as a stopped service. §6.3 (b) treats both as "closed", which is
  right for exposure either way.

**UNKNOWN:**

- Whether operators want host-level destinations for many devices, or mostly
  segment rules. The UI starts with both.
- Which router platforms beyond MikroTik matter most for guidance; phase B
  research would answer that.
- How often DHCP address changes block a retest on a real network. §6.1
  refuses to compare across a changed address; the first live audit will
  show it.
