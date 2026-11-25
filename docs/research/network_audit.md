# Network section: research and draft contract

Status: research and draft contract, MODE: MANUAL. Nothing here is approved
yet: no code before USER approves the contract (§10). Researcher: Claude.
Reviewer: GPT/Codex. Base: `main` @ `7788983`. Dates and versions are as of
2026-11-25.

USER's words: "I have a network, it must be checked as a whole — where the
staff are, where the office is, where accounting is, and so on; find the
vulnerabilities and close them; draw the network that was scanned — a map."

This is a different kind of check from everything NetAudit has. Today every
check looks at **one** target the user names (a host, a URL, a server over
SSH). A network audit first has to **find** the targets, sort them into the
segments the user cares about, look at each of them from the network, and
show the result as a map. It also sends packets to every address in a range,
so it is ACTIVE by the project's own definition (§5).

Labels used below: **FACT** — checked in code, docs, or a command run on
2026-11-25 (only against `127.0.0.1` and public data APIs; no LAN was
scanned); **HYPOTHESIS** — expected, to be proven on the CI stand (§8);
**UNKNOWN** — needs USER's answer or a measurement.

## 1. What NetAudit has today (`7788983`) — FACT

- **Category `network`** — `mtr`, `tcptraceroute`, `ping`, `dig`, `arping`,
  `speedtest` (`netaudit_pkg/checks/network.py:12–291`): diagnostics of one
  named target. None of them finds devices, open services or vulnerabilities.
- **`ports` and `firewall`** (`checks/system.py:23–62`) look only at the
  NetAudit machine itself (`ss -tulnp`, `ufw status`, `nft list ruleset`).
- **`mikrotik_sniffer`** (`checks/capture.py:253–300`) already logs in to a
  MikroTik router over SSH (password given at run time) and reads
  `/ip firewall connection` for one device. Its default router is
  `192.168.88.1`, the MikroTik factory LAN address. `history_capture.py:94`
  uses the same router command on a timer.
- **`arp_capture`** (ARP-spoofing MITM, `capture.py:124–143`) is kept on
  purpose **unregistered**: it needs root, and the comment says a web button
  must never be able to MITM the whole LAN. This research keeps that line.
- **nmap** is in the install allowlist (`tools.py:31`, apt package `nmap`) and
  in `OPTIONAL_TOOLS` (`tools.py:44`), but no check uses it.
- **Risk levels** (`registry.py:19–40`): "port scans" are named as ACTIVE.
  ACTIVE runs are gated by an explicit select, as in `sql_injection`
  (`AUTH_CONFIRM`, `checks/sqli.py:111–125, 160–175`); MODIFYING by
  `confirm_param()` (`registry.py:46–58`).
- **Multi-host (B2)**: saved hosts without secrets (`hosts.py:1–12`, fields
  `host`/`user`/`port`/`key_path`), passwords only at run time; host summary;
  SSH with a pinned `known_hosts`.
- **Web**: tabs Audit, WordPress, Laravel, Trends, Settings, Help
  (`web/static/index.html:177–182`); the only library is Chart.js 4.4.0 from
  cdnjs (`index.html:7`); display values go through `esc()`
  (`index.html:923`).
- **Service** runs as the unprivileged user `netaudit`; the only capability
  the guide grants is `cap_net_raw` on `mtr` (`docs/guide.md:119–146`).
- **AI analysis** sends the report to `api.anthropic.com`
  (`netaudit_pkg/history.py:167`).
- **Finding ids**: prefixes in use `AIDE BKP CT CVE DCK DNS F2B FW LOG LV LYN
  RKT SQL SQLI SYS WEB WP` (+ `KRN NGX SSH`); `NET-` and `RTR-` are free.

## 2. What "check the whole network" can and cannot mean

| Layer | What it answers | Source | Seen by a scan? |
|---|---|---|---|
| Inventory | which devices exist, their names, type, MAC | scan + router tables | partly (§3) |
| Segments | which device is staff / office / accounting | **USER** + router VLANs/subnets | no — a scan sees addresses, not departments |
| Exposure | which services each device offers to the network | port scan + service detection | yes, from where NetAudit stands |
| Misconfiguration | SMBv1, Telnet, anonymous FTP, RDP without NLA… | service negotiation | yes, with high confidence (§4.1) |
| Known vulnerabilities | CVEs of the detected versions | version → databases | only "possible", rarely proven (§4.2) |
| Isolation | can staff reach accounting's file server? | scan from a segment + router rules | only from NetAudit's own segment, or from the router rules |
| Router | management exposed, firmware age, rules | router config (read only) | needs SSH to the router |
| Map | a picture of segments, devices, problems | all of the above | logical, not physical (§7) |

## 3. Finding devices and sorting them into segments

### 3.1 nmap without root — FACT (nmap 7.94SVN, user uid 1000, target `127.0.0.1` only)

- `nmap -sn 127.0.0.1` works: host up, `reason="conn-refused"` — discovery
  through `connect()`.
- `nmap -sS …`, `nmap -sU …` → `You requested a scan type which requires root
  privileges. QUITTING!`; `nmap -O …` → `TCP/IP fingerprinting (for OS scan)
  requires root privileges.`; `nmap --privileged -sS …` → `Couldn't open a raw
  socket. Error: Operation not permitted (1)`.
- `nmap -sT -sV --version-light --top-ports 100 -oX -` gives machine-readable
  XML: `<port … portid="631"><service name="ipp" product="CUPS" version="2.4"
  method="probed" conf="10"><cpe>cpe:/a:apple:cups:2.4</cpe>`. Another port:
  `<service name="realserver" tunnel="ssl" method="table" conf="3"/>` — a guess
  **from the port number only**. The run took 11.3 s for one host.
- `man nmap`: for an unprivileged user host discovery is only a `connect()` to
  ports **80 and 443**; ARP discovery on the local Ethernet is used only "when
  a privileged user" scans. Hosts behind a firewall that drops probes "could be
  missed".

So, as the service runs today (no root, no capabilities): TCP connect scan
only; no UDP (SNMP 161, NetBIOS 137, mDNS 5353), no OS detection, no MAC
addresses from nmap; a device that drops all probes looks like no device.

### 3.2 MAC addresses without root — HYPOTHESIS

A `connect()` to an address on a directly attached subnet makes the Linux
kernel resolve it by ARP first. A device that answers ARP but drops TCP (a
Windows PC with its firewall on) should then appear in the kernel neighbour
table (`ip neigh`, state REACHABLE/STALE with its MAC), unknown addresses as
FAILED/INCOMPLETE. This would give MACs and catch firewalled devices on
NetAudit's own segment without raw sockets. It works only on subnets the
NetAudit machine is attached to; other segments are behind the router (L3),
where MACs are never seen. To prove on the CI stand (§8).

### 3.3 The router as the best inventory source

The router sees every segment: its ARP table, DHCP leases (MAC + the name the
device gave itself), its own addresses per VLAN, and its firewall rules. If
USER's router is MikroTik (UNKNOWN; the existing checks' default
`192.168.88.1` suggests it), read-only RouterOS commands give:

| Command (read only) | Gives |
|---|---|
| `/ip address print terse`, `/interface vlan print terse` | subnets and VLANs → a **proposed** segment list |
| `/ip dhcp-server print terse`, `/ip dhcp-server lease print terse` | DHCP server names per network (often "office", "guest"), device names and MACs |
| `/ip arp print terse` | all live devices in all segments with MAC |
| `/ip firewall filter print terse` | whether segments are isolated from each other; what reaches the router |
| `/ip service print terse` | telnet / ftp / www / api / winbox / ssh enabled, and from which addresses |
| `/system resource print`, `/system routerboard print` | RouterOS version, model |
| `/user print terse` | user names (is a default `admin` still there) |
| `/ip neighbor print terse` | neighbouring devices (MNDP/LLDP/CDP) — a start for physical topology |

Secrets: the commands above print no passwords; `/export` and wireless
security profiles can (HYPOTHESIS: in RouterOS v7 `export` hides sensitive
values unless `show-sensitive`; a user with the `sensitive` policy may see Wi-Fi
keys in `print`). Rule: never run `/export`, never print wireless or
user-secret tables; read only named fields with `proplist=`.

### 3.4 Names and device type

| Signal | Reliability | Note |
|---|---|---|
| DHCP lease host name (router) | good | what the device calls itself, e.g. `ACCOUNTING-PC2` |
| Reverse DNS | fair | often the router's DHCP names |
| NetBIOS name (`nbstat`, UDP 137) | good for Windows | UNKNOWN if it runs unprivileged |
| MAC vendor (OUI) | fair | printer / camera / NAS vendors are telling; the IEEE registry is public |
| Random MAC (locally administered bit set) | FACT of IEEE 802 | almost always a phone or laptop with a private Wi-Fi address; vendor unknown |
| Open services (`-sV`, `http-title`) | good | 9100 → printer, 554 → camera, 5000/5001 → NAS, 3389 → Windows |

All of these are **attacker-controlled strings** (a device chooses its own
name): they are display data, escaped like every other value.

### 3.5 Segments come from USER — UNKNOWN today

A scan cannot know that `192.168.20.0/24` is "accounting". Two cases:

- **Separate subnets/VLANs** per department: a segment = name + one or more
  CIDRs (+ VLAN id), proposed from the router (§3.3) and confirmed by USER.
- **One flat network** (common in small offices, MikroTik default
  `192.168.88.0/24`): a segment = USER's label on devices (by IP or MAC). Here
  the main finding is the network itself: accounting shares one network with
  staff phones and guests — nothing stops one infected PC from reaching the
  accounting PC. Advice: VLANs + firewall between them.

Also UNKNOWN: where NetAudit runs. The `arp_capture` comment says USER already
ran ARP spoofing from the VM's `enp0s3` successfully, which does not work
behind VirtualBox NAT — HYPOTHESIS: the VM is bridged into one LAN segment.
What NetAudit sees depends on it: its own segment fully, other segments only
as far as the router lets it through.

## 4. Vulnerabilities, and how to close them

### 4.1 Misconfigurations seen directly — high confidence

Each item reads a protocol negotiation or banner; nmap script names and their
own categories are FACT (`/usr/share/nmap/scripts`, 606 scripts).

| Proposed id | Problem | How seen | nmap categories | Level |
|---|---|---|---|---|
| NET-SMB-001 | SMBv1 enabled (WannaCry class) | `smb-protocols` | safe, discovery | 1 |
| NET-SMB-002 | SMB signing not required (relay attacks) | `smb2-security-mode` | safe, discovery, default | 1 |
| NET-SMB-003 | MS17-010 not patched | `smb-vuln-ms17-010` | vuln, safe | 2 |
| NET-TEL-001 | Telnet open (passwords in clear text) | port 23 + banner | — | 1 |
| NET-FTP-001 | FTP open (clear text) | port 21 + banner | — | 1 |
| NET-FTP-002 | anonymous FTP login allowed | `ftp-anon` (logs in as anonymous) | default, auth, safe | 2 |
| NET-RDP-001 | RDP open to the segment | port 3389 | — | 1 |
| NET-RDP-002 | RDP without NLA | `rdp-enum-encryption` | safe, discovery | 1 |
| NET-VNC-001 | VNC without password | `vnc-info` (security types) | default, discovery, safe | 1 |
| NET-DB-001 | database / cache port open to the segment (3306, 5432, 1433, 27017, 6379, 9200, 11211) | port + `-sV` | — | 1 |
| NET-DB-002 | Redis / MongoDB answer without a password | `redis-info`, `mongodb-info` | discovery, safe | 2 |
| NET-WEB-001 | admin page over plain HTTP (router, printer, camera, NAS) | `http-title` on 80/8080/… | default, discovery, safe | 1 |
| NET-TLS-001 | expired / self-signed / weak certificate | `ssl-cert` | default, safe, discovery | 1 |
| NET-SSH-001 | SSH with weak algorithms | `ssh2-enum-algos` | safe, discovery | 1 |
| NET-IPMI-001 | IPMI cipher zero (server BMC login bypass) | `ipmi-cipher-zero` | vuln, safe | 2 (UDP → needs root) |

Level 1 reads what any client sees when it connects. Level 2 tries anonymous
access or sends a vulnerability probe that nmap itself marks `safe`; it needs a
second, separate confirmation. Never: scripts in `intrusive`, `brute`,
`exploit`, `dos` (e.g. `http-default-accounts`, `smb-enum-shares`,
`ssl-enum-ciphers` are `intrusive` — excluded or replaced). Scripts are named
one by one in code, never by category, so an nmap update cannot add one.

### 4.2 Known vulnerabilities by version — live requests, 2026-11-25

| Source | Request and answer | Verdict |
|---|---|---|
| **NVD CVE API 2.0** (`virtualMatchString`) | `cpe:2.3:o:mikrotik:routeros:7.20` → 200, 7 CVEs, among them CVE-2021-3014 (published 2021) — whether 7.20 is really affected is UNKNOWN | usable, results are **"possible"**, never proven; rate-limited without a key (limits not re-measured) |
| **OSV, Debian ecosystem** | `Debian:12` `openssh` `1:9.2p1-2+deb12u3` → 42 records (incl. `DEBIAN-CVE-2007-2243`), `…+deb12u7` → 39 | the raw list is mostly old/unimportant; **actionable = fixed in a newer package revision** (3 here). Works only when the banner carries the distro revision (HYPOTHESIS: `OpenSSH_9.2p1 Debian-2+deb12u3`) |
| **CISA KEV** (JSON, 1.9 MB) | catalog `2026.11.25`, 1805 entries; MikroTik RouterOS entries added Sept 2026 (CVE-2026-67279, CVE-2026-86060, CVE-2026-67277); 391 Microsoft | **use** to mark "exploited in the wild"; terms of use not re-read (UNKNOWN) |
| **endoflife.date** `api/routeros.json` | 7.25 current (7.25.2), 7.24 EOL 2026-10-23, 7.23 LTS (7.23.8) | **use** for "router firmware no longer supported"; MIT, already used for Laravel |
| **MikroTik update channel** `upgrade.mikrotik.com/routeros/NEWESTa7.stable` | `7.25.2 1795173070` | the latest stable version, no key |
| **vulners.com** (nmap `vulners.nse`, category `external`) | `api/v3/burp/software/` → 403, Cloudflare "Just a moment…" | **do not use**: blocked for automated clients and it sends the whole inventory to a third party |

Why "possible": `-sV` versions are coarse (`cups:2.4` — no patch level) and
distributions backport fixes without changing the upstream version, which is
the same false-positive class `cve_audit` already fixed for Debian. A version
match is reported as "possible, check the device", with the source and the
version it was based on; a KEV hit raises priority, never certainty.

### 4.3 "Close them" — three levels

1. **Advice** (this contract): each finding id has RU/EN text — what it is,
   why it matters, how to fix on the usual platforms (Windows: PowerShell /
   Group Policy; MikroTik: exact commands; Linux: config line), and how to
   confirm (scan again).
2. **Ready commands** (this contract, as text only): for router findings, the
   exact RouterOS commands to paste, e.g. disable `telnet,ftp,www,api`, limit
   `winbox`/`ssh` to the admin segment, add a drop rule between two segments.
   USER applies them; NetAudit runs nothing.
3. **Automatic fixing** (not proposed now): NetAudit applying changes itself
   is MODIFYING (router config, Windows hosts) — a wrong firewall rule can cut
   the office off. Separate research and an explicit USER decision.

## 5. Safety and legality

- **Only USER's networks.** Segment ranges must be private (RFC 1918
  `10/8`, `172.16/12`, `192.168/16`); a public address is refused. Size cap
  per segment (proposed /22, 1024 addresses) and per scan.
- **Confirmation per scan**, like `sql_injection`: "yes — this is my network /
  I have written permission", recorded in the report. Level 2 needs its own.
- **Risk level ACTIVE**; gentle timing (`-T3`, a `--max-rate`, `--host-timeout`),
  scan targets passed as an argument list after `ipaddress` validation, no
  user-supplied nmap options or `--script-args`.
- **No attacks**: no ARP spoofing, no brute force or default-password logins,
  no exploit/DoS scripts, no OS fingerprinting.
- **Privileges**: unprivileged, as the service runs today. Giving nmap
  `cap_net_raw` (setcap) would let **every** local user open raw sockets
  through nmap, i.e. sniff the machine's traffic; NSE Lua runs with those
  capabilities. Not recommended; a separate decision if UDP/SNMP is wanted.
- **Endpoint alerts**: antivirus / EDR on office PCs may report the scan.
  USER should expect it (UNKNOWN which products are in use).
- **Personal data**: names like `Ona-iPhone` and MACs of staff devices are
  personal data (GDPR). Stored only in the local database; the network
  inventory is **not** sent to AI analysis unless USER allows it.
- **Router access**: read-only commands only (§3.3), password at run time,
  pinned host key, never `/export`.

## 6. Result model and ids

- Per segment: name, CIDRs, VLAN, sensitivity; addresses scanned, devices
  found, devices that did not answer (**"no answer" ≠ "no device"**).
- Per device: IP; MAC with its source (neighbour table / router) or unknown;
  vendor; names with their source; segment; open ports with service, product,
  version and confidence (`method="table"` = guessed from the port, shown as
  unknown); findings; a "not checked" list (UDP, scripts skipped, timeout).
- Outcomes as in the WordPress/Laravel tabs: problem / ok within what was
  checked / not checked (with reason) / error. A filtered port is not a closed
  port; an empty scan of a range is "nothing answered", never "network is
  clean".
- Ids (draft): `NET-DISC-001` device did not answer, `NET-DISC-002:<mac>` new
  device since the last scan, the table in §4.1, `NET-SEG-001:<from>:<to>:<port>`
  a service reachable across segments that USER said must be isolated,
  `NET-SEG-002` flat network with a sensitive segment,
  `NET-VULN-001:<cpe>:<cve>` possible known vulnerability (+ KEV flag),
  `RTR-VER-001` firmware unsupported / outdated, `RTR-SVC-001:<service>`
  insecure management service on, `RTR-SVC-002:<service>` management reachable
  from every segment, `RTR-FW-001:<from>:<to>` no rule separating segments,
  `RTR-USR-001` default `admin` user present.
- Trends (existing layer): identity = segment; a new device in accounting is
  a change worth a Telegram message.

## 7. Map in the Web

A new tab **"Сеть" / "Network"**: segments editor (name, CIDRs, VLAN,
sensitivity, which segments may talk to which), "Scan" with the
confirmation, live progress through the existing stream, then a map and a
table.

```
                         [ Internet ]
                              |
                  [ Router 192.168.88.1 ]  RTR: telnet on, 7.20 EOL
         ┌────────────────────┼────────────────────┐
 [ Staff 10.0.10.0/24 ]  [ Office 10.0.20.0/24 ]  [ Accounting 10.0.30.0/24 ]
   ● ● ● ● ○ ○             ● ● ■                    ● ●
                 ╌╌╌╌ red dashed: Staff → Accounting 445 reachable ╌╌╌╌▶
 ● ok   ● problem (colour = worst severity)   ○ not checked / no answer   ■ printer
```

- **Logical map**, not physical: a scan does not see which switch port a PC
  is on. Physical links could come later from the router's bridge host table
  and `/ip neighbor` (§3.3).
- Clicking a device opens its card: ports, services, findings, advice.
- Drawn as **SVG by the tab's own code** — no new library: the layout is a
  fixed hierarchy (router → segments → device grid), not a free graph, it
  works offline and every label goes through `esc()`. Cytoscape.js or
  vis-network would add a CDN dependency for force layouts this map does not
  need. Hundreds of devices: grid per segment, collapse beyond a limit.

## 8. E2E stand in CI

GitHub Actions has Docker (the SSH stand already uses it):

- Two Docker networks = two segments, a small Linux router container
  (forwarding + iptables) between them; NetAudit runs **as a non-root user**
  in segment A, as in production.
- Targets: Samba with SMB1 and signing off; telnetd; vsftpd with anonymous
  login; Redis without a password; nginx "admin page" over HTTP; a clean host
  with SSH only; a host that drops all TCP (proves §3.2).
- Isolation: an iptables rule on the router toggles "Staff → Accounting 445"
  between reachable (finding) and blocked (no finding).
- RouterOS: fixtures of `print terse` output. A live RouterOS CHR in CI is
  UNKNOWN (VM image, not a container); or USER's own router output.

## 9. Not checked yet (UNKNOWN)

- USER's network: router model, subnets/VLANs, departments, Wi-Fi, number of
  devices, where the NetAudit VM sits. **No LAN was scanned** — that needs
  USER's confirmation (§5).
- §3.2 neighbour-table behaviour; `nbstat` without root; time for a /24 with
  the port list (one host took 11.3 s with `--top-ports 100 -sV`); OS-banner
  format for the OSV Debian path.
- NVD rate limits and KEV terms of use were not re-read; RouterOS secret
  display rules (§3.3) are from memory.

## 10. Draft contract (for USER approval)

- **N1. Segments** (`network` inventory, no secrets): name, private CIDRs,
  VLAN, sensitivity, allowed flows between segments; or device labels for a
  flat network.
- **N2. `lan_scan`** (ACTIVE, confirmation): unprivileged nmap — discovery
  with a wider TCP probe set + neighbour table, a curated port list, `-sV`
  light, level-1 scripts (§4.1); limits and timing (§5); result model (§6).
- **N3. Known vulnerabilities**: KEV + endoflife.date + OSV for distro
  banners + NVD as "possible"; no vulners.
- **N4. `router_mikrotik`** (SSH, READ_ONLY), only if the router is MikroTik:
  §3.3 → proposed segments, device names, router findings, RouterOS commands
  as advice.
- **N5. Isolation**: reachability from NetAudit's segment against the allowed
  flows (N1) + router firewall rules (N4).
- **N6. Tab "Network"**: editor, scan, map (own SVG), device card, advice
  RU/EN, "not checked" always visible.
- **N7. Tests**: RED/GREEN on nmap XML and RouterOS fixtures; E2E stand (§8).
- **Not in this contract**: automatic fixing; root/capabilities for nmap (UDP,
  SNMP, OS detection); password checks; Wi-Fi radio audit; physical topology;
  scanning from other segments through saved SSH hosts; IPv6 sweeps.

Questions for USER, recommended answer first:
1. **Router.** Which model? If MikroTik: N4 with read-only SSH (password at run
   time). Otherwise N4 is dropped and segments are entered by hand.
2. **Segments.** Separate subnets/VLANs for staff / office / accounting, or one
   network? Names and ranges (can be entered in the tab later).
3. **Where NetAudit runs.** The VM is bridged into which segment?
4. **Depth.** Level 1 only (recommended), or level 1 + level 2 behind a second
   confirmation.
5. **Privileges.** Unprivileged nmap (recommended), or grant nmap raw sockets
   for UDP/SNMP and faster discovery, with the risk in §5.
6. **Closing.** Advice + ready commands (recommended); automatic fixing later,
   separately.
7. **AI.** Keep the network inventory out of AI analysis (recommended), or allow.
8. **Order.** PR 1 = N1 + N2 + N6 + N7 (scan and map of what NetAudit sees),
   PR 2 = N4 + N5 (router and isolation), PR 3 = N3 (known vulnerabilities).
   Alternative: router first if it is MikroTik — it gives segments and names
   before any scan.
9. **Live check.** CI stand during development; the first scan of USER's own
   network is run by USER after the PR is merged, on one segment.
