# Network section: research and draft contract

Status: contract approved, rev. 2, MODE: MANUAL (USER 2026-11-25 clarified
the scenario - NetAudit finds everything itself - then answered «Утверждаю»
to §11 with the defaults chosen by Claude); PR 1 is built as §12 says. Researcher and
executor: Claude. Reviewer: GPT/Codex. Base: `main` @ `7788983`. Dates and
versions are as of 2026-11-25.

USER's request: "I have a network, it must be checked as a whole — where the
staff are, where the office is, where accounting is, and so on; find the
vulnerabilities and close them; draw the network that was scanned — a map."

USER's clarification (rev. 2): **NetAudit must find out everything itself** —
which router, which networks, which devices. The scenario is an invited
audit: "I am invited to check a network. I start the audit. You do the whole
audit. Then we see what to do next — log in over SSH or whatever." So:

- **Phase A (this contract)** — the auditor plugs a machine with NetAudit into
  the client's network and starts one audit. With no passwords and no prior
  knowledge, NetAudit finds where it is, the router and its model, the
  networks it can reach, the devices, their services and problems, and draws
  the map with advice.
- **Phase B (decided after the report)** — checks with the owner's
  credentials: SSH into the router or servers (§9). Phase A's report says
  what each credential would unlock.

This differs from every check NetAudit has: they look at **one** target the
user names. A network audit first **finds** the targets, and it sends packets
to every address in a range, so it is ACTIVE by the project's own definition
(§6).

Labels: **FACT** — checked in code, local files, or commands run on
2026-11-25 (nmap only against `127.0.0.1`; local state of the development
machine read without sending probes; public data APIs; **no LAN was
scanned**); **HYPOTHESIS** — expected, to be proven on the CI stand (§10);
**UNKNOWN** — needs a measurement.

## 1. What NetAudit has today (`7788983`) — FACT

- **Category `network`** — `mtr`, `tcptraceroute`, `ping`, `dig`, `arping`,
  `speedtest` (`netaudit_pkg/checks/network.py:12–291`): diagnostics of one
  named target. None finds devices, services or vulnerabilities.
- **`ports` and `firewall`** (`checks/system.py:23–62`) look only at the
  NetAudit machine itself.
- **`mikrotik_sniffer`** (`checks/capture.py:253–300`) already logs in to a
  MikroTik router over SSH (password at run time) and reads
  `/ip firewall connection` for one device; `history_capture.py:94` does the
  same on a timer. Useful for phase B.
- **`arp_capture`** (ARP-spoofing MITM, `capture.py:124–143`) is kept
  **unregistered** on purpose: it needs root, and a web button must never MITM
  the LAN. This research keeps that line.
- **nmap** is in the install allowlist (`tools.py:31`) and `OPTIONAL_TOOLS`
  (`tools.py:44`); no check uses it.
- **Risk levels** (`registry.py:19–40`): "port scans" are ACTIVE. ACTIVE runs
  are gated by an explicit select, as `sql_injection` does (`AUTH_CONFIRM`,
  `checks/sqli.py:111–125, 160–175`).
- **Multi-host (B2)**: saved hosts without secrets (`hosts.py:1–12`),
  passwords only at run time, pinned `known_hosts` — the base for phase B.
- **Web**: tabs Audit, WordPress, Laravel, Trends, Settings, Help
  (`web/static/index.html:177–182`); the only library is Chart.js 4.4.0 from
  cdnjs (`index.html:7`); display values go through `esc()` (`index.html:923`).
- **Service** runs as the unprivileged user `netaudit` (`docs/guide.md:119–146`).
- **AI analysis** sends the report to `api.anthropic.com` (`history.py:167`).
- **Finding id prefixes** in use: `AIDE BKP CT CVE DCK DNS F2B FW LOG LV LYN
  RKT SQL SQLI SYS WEB WP` (+ `KRN NGX SSH`); `NET-` and `RTR-` are free.

## 2. One audit, step by step

| Step | What NetAudit does | Needs |
|---|---|---|
| 1. Where am I | own address, subnet, interface (cable / Wi-Fi), gateway and its MAC, DNS servers, search domain | nothing (§3.1) |
| 2. This segment | every live device here: address, MAC, vendor, name | TCP probes + kernel neighbour table (§3.2–3.3) |
| 3. Router | vendor, model, firmware version, which management services it shows | MAC vendor + service signatures (§4) |
| 4. Other networks | which other private subnets answer through the router; names from internal DNS | bounded probes + DNS (§5) |
| 5. Services | open ports, products, versions on every device found | TCP connect + `-sV` |
| 6. Problems | misconfigurations, router exposure, firmware support, possible known CVEs | §7 |
| 7. Segments | groups proposed by NetAudit (subnet, names, device types); the auditor renames them ("Accounting") | §5.4 |
| 8. Isolation | which segments and services are reachable **from where the auditor stands** | §5.5 |
| 9. Report and map | map, findings with advice, "not checked", next steps (phase B) | §8 |

No question is asked before the scan. The only input is the confirmation that
the owner allowed the audit (§6).

## 3. Where NetAudit is, and its own segment

### 3.1 Self-location — FACT (development machine, read without root)

- `ip route show default` → gateway, interface (`wlp1s0` = Wi-Fi), `proto
  dhcp`. `ip -o addr` → own address and prefix.
- `ip neigh show <gateway>` → the gateway's MAC, state `REACHABLE`, without
  root. The gateway is always on the local link, so **its MAC (and vendor) is
  always known**.
- `/etc/resolv.conf` (world-readable) → DNS servers and the search domain the
  client's DHCP handed out (an Active Directory domain shows up here).

Each scan records this as its **vantage point**: the auditor may plug in at
several places (staff cable, guest Wi-Fi, accounting room); the map merges the
scans and says what was visible from where.

### 3.2 nmap without root — FACT (nmap 7.94SVN, uid 1000, target `127.0.0.1` only)

- `nmap -sn 127.0.0.1` works: host up, `reason="conn-refused"` — discovery by
  `connect()`.
- `-sS`, `-sU` → `You requested a scan type which requires root privileges.
  QUITTING!`; `-O` → `TCP/IP fingerprinting (for OS scan) requires root
  privileges.`; `--privileged -sS` → `Couldn't open a raw socket. Error:
  Operation not permitted (1)`.
- `-sT -sV --version-light --top-ports 100 -oX -` gives XML:
  `<service name="ipp" product="CUPS" version="2.4" method="probed" conf="10">
  <cpe>cpe:/a:apple:cups:2.4</cpe>`; another port `method="table" conf="3"` —
  a guess **from the port number only**. 11.3 s for one host.
- `man nmap`: unprivileged host discovery is only `connect()` to ports **80 and
  443**; ARP discovery only for "a privileged user"; firewalled hosts "could be
  missed".

So without root: TCP only; no UDP (SNMP, NetBIOS), no OS detection, no MACs
from nmap; discovery must probe more ports than 80/443.

### 3.3 MACs of the whole segment without root — FACT (CI stand)

A `connect()` to an address on the local subnet makes the kernel ARP for it
first. A device that answers ARP but drops TCP (Windows with its firewall on)
should then be in `ip neigh` as REACHABLE/STALE with its MAC; empty addresses
as FAILED/INCOMPLETE. That would find firewalled devices and give every MAC on
the auditor's segment. The gateway case above is FACT; the whole-subnet case is
FACT since CI run 45892042011 (§10): the stand's host that drops every TCP and
ICMP packet was found by an unprivileged scan, with its MAC, from the
neighbour table only. Other segments are behind the router: their MACs are
never seen from here.

### 3.4 Listening and asking on the local segment

| Method | What it gives | Rights — FACT | Works? |
|---|---|---|---|
| mDNS / DNS-SD (`broadcast-dns-service-discovery`) | printers, Apple devices, NAS, names | multicast from a normal socket; the script has no privilege check | HYPOTHESIS |
| SSDP/UPnP (`broadcast-upnp-info`, then `upnp-info`) | **manufacturer, model** of routers, TVs, NAS | as above; bind UDP 1900 as uid 1000 — ok | HYPOTHESIS |
| WS-Discovery (`broadcast-wsdd-discover`) | Windows PCs, network printers | as above | HYPOTHESIS |
| MikroTik MNDP, listen on UDP 5678 | router identity, RouterOS version, board | bind UDP 5678 as uid 1000 — ok | HYPOTHESIS that RouterOS announces it by default |
| LLMNR, listen on UDP 5355 | Windows names; **LLMNR in use is itself a finding** (§7.1) | bind UDP 5355 as uid 1000 — ok | HYPOTHESIS |
| NetBIOS name service, UDP 137 | Windows names, workgroup | bind UDP 137 as uid 1000 → `Permission denied` (`ip_unprivileged_port_start=1024`) | needs root |
| ARP / LLDP / CDP frames | everything on the link, switch names | raw sockets (`broadcast-listener`, `lltd-discovery` check `nmap.is_privileged()`) | needs root |

NetAudit only listens and asks; it never **answers** LLMNR/NetBIOS queries
(answering is the Responder poisoning attack).

## 4. Identifying the router without passwords

| Signal | FACT in nmap's own data (`/usr/share/nmap`) | What it tells |
|---|---|---|
| Gateway MAC vendor | `nmap-mac-prefixes`: 15 MikroTik/Routerboard prefixes, 176 TP-Link, 27 Ubiquiti, 49 Keenetic/Zyxel, 13 Fortinet, 1135 Cisco | vendor (a replaced or virtual MAC lies) |
| SSH banner | `SSH-2.0-ROSSSH` → "MikroTik RouterOS sshd"; `OpenSSH_<v>_Mikrotik_v<version>` → **RouterOS version** | model family, v7 version |
| FTP banner | `220 … FTP server (MikroTik <version>) ready` | **RouterOS version** |
| WinBox `8291/tcp`, API, bandwidth test | `match winbox …` (`cpe:/a:mikrotik:winbox`), `MikroTik bandwidth-test server` | MikroTik, and management open |
| Web admin page | `<title>mikrotik routeros > administration`, "MikroTik router config httpd", HotSpot redirect | MikroTik, admin over HTTP |
| UPnP description, MNDP | §3.4 | model, version |

`nmap-service-probes` has 25 MikroTik/RouterOS lines among 11 723 `match`
rules, and similar ones for other vendors. The result reads e.g. "router:
MikroTik, RouterOS 7.x (from the SSH banner), WinBox and HTTP admin reachable
from the staff network", each with its source; "vendor unknown" when nothing
matches. The version then goes to §7.2 (support end, known-exploited CVEs).

## 5. Other networks and segments

### 5.1 Probing private subnets through the router — HYPOTHESIS

From one segment the auditor does not know the other subnets. Bounded probe:
for candidate /24s — every /24 of the /16 the auditor is in, plus all of
`192.168.0.0/16` (256 subnets) — try a `connect()` to `.1` and `.254` on a few
router ports (22, 53, 80, 443, 8291).
An answer = "subnet exists, its gateway is here". Then sweep that /24. Hundreds
of probes, not millions; the candidate list and the cap are in the report.
A subnet the router filters stays invisible: "not found" is not "does not
exist".

### 5.2 Internal DNS — HYPOTHESIS

Asking only the client's DNS server, touching no device: reverse (PTR)
lookups for found subnets; in a Windows domain, `_ldap._tcp.dc._msdcs.<search
domain>` lists domain controllers. Many MikroTik-only offices have no PTR
records (UNKNOWN per client).

### 5.3 Traceroute

The existing `tcptraceroute` logic shows the hop that routes to a found
subnet (the router, or a second router behind it).

### 5.4 Naming segments

A scan never knows a department. NetAudit **proposes** segments: one per
subnet, with a suggested name from what is inside (DHCP/DNS names like
`BUH-PC1`, `ACCOUNTING-*`; mostly printers; cameras; guest Wi-Fi = only phones
with random MACs). The auditor renames them in the tab and may mark one as
sensitive. In **one flat network** NetAudit proposes groups by device type and
the auditor moves devices between groups; the main finding there is the flat
network itself (`NET-SEG-002`).

### 5.5 Isolation, from where the auditor stands

From each vantage point: which other segments answer, and which sensitive
services there (SMB 445, RDP 3389, databases, admin pages) are reachable. "From
the guest Wi-Fi, the accounting file server's 445 is open" is the key result.
A second vantage = plug in elsewhere and run again; the map shows both.

## 6. Safety and legality

- **Permission first.** The scan starts only after the auditor confirms "the
  network owner gave me written permission for this audit", like
  `sql_injection`; the confirmation, client name and vantage go into the
  report. Level 2 checks (§7.1) need their own confirmation.
- **Private addresses only** (RFC 1918 `10/8`, `172.16/12`, `192.168/16`); a
  public address is refused. Caps: candidate subnets per run, addresses per
  subnet (/22), total.
- **Risk level ACTIVE**; gentle timing (`-T3`, `--max-rate`, `--host-timeout`);
  targets passed as an argument list after `ipaddress` validation; no
  user-supplied nmap options or `--script-args`; scripts named one by one in
  code, never by category.
- **No attacks**: no ARP spoofing, no answering LLMNR/NetBIOS, no brute force
  or default-password logins, no exploit/DoS scripts.
- **Privileges**: unprivileged, as the service runs today. `setcap
  cap_net_raw` on nmap would let **every** local user open raw sockets through
  nmap (sniff the machine's traffic; NSE Lua runs with it). Not in this
  contract; a separate decision if UDP/NetBIOS/ARP-level discovery is wanted.
- **Endpoint alerts**: the client's antivirus/EDR may report the scan; the
  confirmation text says so.
- **Client data**: names and MACs of staff devices are personal data (GDPR).
  The report stays in the local database and is **not** sent to AI analysis
  unless the auditor turns that on for the run.
- **Strings from the network are attacker-controlled** (device names, page
  titles, banners): escaped like every other display value.

## 7. Vulnerabilities, and how to close them

### 7.1 Misconfigurations seen directly — high confidence

nmap script names and categories are FACT (`/usr/share/nmap/scripts`, 606).

| Proposed id | Problem | How seen | nmap categories | Level |
|---|---|---|---|---|
| NET-SMB-001 | SMBv1 enabled (WannaCry class) | `smb-protocols` | safe, discovery | 1 |
| NET-SMB-002 | SMB signing not required (relay) | `smb2-security-mode` | safe, discovery, default | 1 |
| NET-SMB-003 | MS17-010 not patched | `smb-vuln-ms17-010` | vuln, safe | 2 |
| NET-NAME-001 | LLMNR in use (name poisoning risk) | heard queries, §3.4 | — (passive) | 1 |
| NET-TEL-001 | Telnet open (clear-text passwords) | port 23 + banner | — | 1 |
| NET-FTP-001 | FTP open (clear text) | port 21 + banner | — | 1 |
| NET-FTP-002 | anonymous FTP allowed | `ftp-anon` (logs in as anonymous) | default, auth, safe | 2 |
| NET-RDP-001 | RDP reachable from this segment | port 3389 | — | 1 |
| NET-RDP-002 | RDP without NLA | `rdp-enum-encryption` | safe, discovery | 1 |
| NET-VNC-001 | VNC without password | `vnc-info` | default, discovery, safe | 1 |
| NET-DB-001 | database / cache port reachable (3306, 5432, 1433, 27017, 6379, 9200, 11211) | port + `-sV` | — | 1 |
| NET-DB-002 | Redis / MongoDB answer without a password | `redis-info`, `mongodb-info` | discovery, safe | 2 |
| NET-WEB-001 | admin page over plain HTTP (router, printer, camera, NAS) | `http-title` | default, discovery, safe | 1 |
| NET-TLS-001 | expired / self-signed certificate | `ssl-cert` | default, safe, discovery | 1 |
| NET-SSH-001 | SSH with weak algorithms | `ssh2-enum-algos` | safe, discovery | 1 |
| RTR-SVC-001:<service> | router management reachable from this segment (WinBox, Telnet, FTP, HTTP, API) | §4 | — | 1 |
| RTR-UPNP-001 | UPnP on the router (devices can open ports to the internet) | `upnp-info` | default, discovery, safe | 1 |

Level 1 reads what any client sees when it connects. Level 2 tries anonymous
access or sends a vulnerability probe nmap marks `safe`; off by default, own
confirmation. Never: `intrusive`, `brute`, `exploit`, `dos` scripts
(`http-default-accounts`, `smb-enum-shares`, `ssl-enum-ciphers` are
`intrusive` — excluded). UDP-only checks (SNMP, IPMI) need root — not in phase A.

### 7.2 Known vulnerabilities by version — live requests, 2026-11-25

| Source | Request and answer | Verdict |
|---|---|---|
| **endoflife.date** `api/routeros.json` | 7.25 current (7.25.2), 7.24 EOL 2026-10-23, 7.23 LTS (7.23.8) | **use**: "router firmware no longer supported" (`RTR-VER-001`); MIT, already used for Laravel |
| **MikroTik update channel** `upgrade.mikrotik.com/routeros/NEWESTa7.stable` | `7.25.2 1795173070` | latest stable, no key |
| **CISA KEV** (JSON, 1.9 MB) | catalog `2026.11.25`, 1805 entries; MikroTik RouterOS entries added Sept 2026 (CVE-2026-67279, CVE-2026-86060, CVE-2026-67277); 391 Microsoft | **use** to mark "exploited in the wild"; terms not re-read (UNKNOWN) |
| **NVD CVE API 2.0** (`virtualMatchString`) | `cpe:2.3:o:mikrotik:routeros:7.20` → 7 CVEs, incl. CVE-2021-3014 (published 2021) — whether 7.20 is affected is UNKNOWN | usable only as **"possible"**; rate-limited without a key |
| **OSV, Debian ecosystem** | `Debian:12` `openssh` `1:9.2p1-2+deb12u3` → 42 records, `…+deb12u7` → 39 | raw list mostly old/unimportant; actionable = **fixed in a newer package revision**; needs the distro revision in the banner (HYPOTHESIS) |
| **vulners.com** (nmap `vulners.nse`, category `external`) | `api/v3/burp/software/` → 403 Cloudflare "Just a moment…" | **do not use**: blocked, and it sends the whole inventory to a third party |

A version match is "possible, check the device" with its source and the
version it was based on (`-sV` versions are coarse, `cups:2.4`; distributions
backport fixes — the false-positive class `cve_audit` already fixed for
Debian). A KEV hit raises priority, never certainty.

### 7.3 "Close them" — three levels

1. **Advice** (this contract): per finding id, RU/EN — what, why, how to fix on
   the usual platforms (Windows: PowerShell / Group Policy; MikroTik: exact
   commands; Linux: config line), how to confirm (scan again).
2. **Ready commands** (this contract, text only): e.g. RouterOS commands to
   disable `telnet,ftp,www,api`, limit WinBox/SSH to the admin segment, drop
   traffic from guests to accounting. The auditor or the client applies them.
3. **Automatic fixing** — not proposed: changing a client's router or PCs is
   MODIFYING and a wrong rule cuts the office off. Separate research and an
   explicit USER decision.

## 8. Report and map in the Web

A new tab **"Сеть" / "Network"**: client name, permission confirmation, level
2 on/off, **Start audit**; live progress through the existing stream; then the
map, the device table, findings with advice, "not checked", and **next steps**.

```
                          [ Internet ]
                               |
        [ Router 192.168.10.1 — MikroTik, RouterOS 7.20 (SSH banner) ]
          RTR: WinBox + HTTP admin reachable from staff; 7.20 unsupported
          ┌────────────────────┼─────────────────────┐
 [ 192.168.10.0/24 ]     [ 192.168.20.0/24 ]     [ 192.168.30.0/24 ]
   "Staff" ★ you are here   "Office"               "Accounting" (sensitive)
   ● ● ● ● ○ ○              ● ● ■                  ● ●
           ╌╌╌╌ red dashed: Staff → Accounting 445 reachable ╌╌╌╌▶
 ● ok  ● problem (colour = worst severity)  ○ no answer / not checked  ■ printer
```

- **Logical map**: router → segments found → devices; the auditor's vantage
  marked; a segment seen only through its gateway is drawn empty with "devices
  not visible from here". Physical links (switch ports) are not seen by a
  scan — phase B (router bridge table, `/ip neighbor`).
- Clicking a device opens its card: names (with source), MAC/vendor, ports,
  services, findings, advice.
- **Next steps** list what phase B would add, e.g. "router is MikroTik: with an
  SSH login NetAudit can read its firewall rules, DHCP names of every segment
  and the exact version"; "3 Linux servers with SSH: add them as saved hosts".
- Drawn as **SVG by the tab's own code**, no new library: a fixed hierarchy,
  works offline, every label through `esc()`. Cytoscape.js / vis-network would
  add a CDN dependency for force layouts this map does not need.

## 9. Phase B — with credentials (after the report, not in this contract)

| Target | How | Gives |
|---|---|---|
| MikroTik router | SSH, read-only RouterOS commands; password at run time | `/ip address`, `/interface vlan`, `/ip dhcp-server lease`, `/ip arp` (devices and names in **all** segments), `/ip firewall filter` (isolation by rules), `/ip service`, `/system resource`, `/user` names, `/ip neighbor` (topology) |
| Linux servers | existing SSH checks + saved hosts | the server audits NetAudit already has |
| Windows PCs / domain | UNKNOWN (WinRM / SMB with credentials) | separate research |

Router secrets: never `/export`, never print Wi-Fi or user-secret tables; read
named fields with `proplist=` (HYPOTHESIS: a user with the `sensitive` policy
can see keys in some `print` output).

## 10. E2E stand in CI

GitHub Actions has Docker (the SSH stand already uses it):

- Two Docker networks = two segments with a Linux router container
  (forwarding + iptables) between them; NetAudit runs **as a non-root user**
  in segment A.
- Targets: Samba with SMB1 and signing off; telnetd; vsftpd with anonymous
  login; Redis without a password; nginx "admin page" over HTTP; a clean host
  with SSH only; a host that drops all TCP (proves §3.3); an mDNS/SSDP
  announcer (§3.4).
- Router identification: fixtures of real banners/pages (§4) and nmap XML;
  a router container answering with a MikroTik-like SSH banner.
- Subnet probing (§5.1) finds segment B through the router; an iptables rule
  toggles "A → B 445" between reachable (finding) and blocked.

## 11. Draft contract (for USER approval)

Phase A — one audit, no passwords, no prior knowledge:

- **N1. Vantage point**: own address, subnet, interface, gateway + MAC/vendor,
  DNS, search domain (§3.1), recorded per scan.
- **N2. Own segment**: discovery with a wider TCP probe set + kernel neighbour
  table; mDNS / SSDP / WS-Discovery; listening for MNDP and LLMNR (§3.2–3.4).
- **N3. Router identification** and router findings without passwords (§4,
  `RTR-SVC`, `RTR-UPNP`, `RTR-VER` via endoflife.date / KEV).
- **N4. Services and misconfigurations**: TCP connect, `-sV` light, level-1
  scripts; level 2 behind its own confirmation, off by default (§7.1).
- **N5. Other subnets**: bounded probing through the router, internal DNS,
  traceroute (§5.1–5.3).
- **N6. Segments and isolation**: proposed segments, renaming and sensitivity
  in the tab, reachability per vantage point (§5.4–5.5).
- **N7. Known vulnerabilities**: KEV, endoflife.date, OSV for distro banners,
  NVD as "possible"; no vulners (§7.2).
- **N8. Tab "Network"**: start, progress, map, device card, findings with
  advice and ready commands (RU/EN), "not checked", next steps (§8).
- **N9. Tests**: RED/GREEN on fixtures; E2E stand (§10).

Not in this contract: phase B (§9), automatic fixing, root/capabilities for
nmap, password attempts, Wi-Fi radio audit, physical topology, IPv6 sweeps.

Defaults chosen by Claude (USER may change any):
1. Order: **PR 1** = N1 + N2 + N3 + N4 + N8 (basic) + N9 — one audit of the
   auditor's own segment with the router identified and a map; **PR 2** = N5 +
   N6 — other subnets, segments, isolation, merged vantage points; **PR 3** =
   N7 — known vulnerabilities by version.
2. Level 2 checks: present, off by default, own confirmation.
3. nmap unprivileged; root mode — a later decision once PR 1 shows what is
   missed.
4. Network reports are not sent to AI analysis unless turned on for the run.
5. Live check: the CI stand during development; the first real audit is run
   by USER after the PR is merged.

## 12. PR 1 — how the contract is built

USER approved §11 on 2026-11-25 («Утверждаю»). PR 1 = N1 + N2 + N3 + N4 +
N8 (basic) + N9.

- **Check `lan_audit`**, category `lan` (tab "Аудит сети" / "Network audit"),
  ACTIVE, tools `nmap` and `ip`. Params: `client` (name for the report),
  `authorization` (nothing is sent without "yes — the network owner gave me
  written permission"), `level2` (own confirmation, off), `interface`
  (empty = the interface of the default route), `share_with_ai` (no).
- **Range**: the subnet of that interface, if private and at most /22; a
  larger one is cut to the /24 around this machine and the rest is named as
  not checked; a public subnet is refused.
- **Steps**: vantage (`ip -j route/addr/neigh`, resolv.conf) → discovery
  (`nmap -sn -n -PS<ports>`) while listening for MNDP (UDP 5678) and LLMNR
  (UDP 5355) and running the three broadcast scripts → the neighbour table →
  ports, `-sV --version-light` and the level-1 scripts on every device found
  (`-Pn`, so a device seen only by ARP is scanned too) → judgment. `-T3`,
  `--max-rate`, `--host-timeout`; every command has a process timeout.
- **Two kinds of "not checked"**: *gaps* (something this run should have
  done and could not: a listener port busy, nmap failed, a host timed out,
  the range was cut, support lookup failed) make the verdict "incomplete";
  *limits* (what this kind of run never covers: UDP, OS detection, other
  subnets — PR 2, known vulnerabilities by version — PR 3, level 2 when off)
  are always listed and do not change the verdict.
- **Refinements of §7.1** (to check in review): `mongodb-info` is not used —
  its first query, `buildInfo`, is answered without a login even when MongoDB
  requires one (HYPOTHESIS), so it proves nothing; NET-DB-002 is Redis only.
  NET-WEB-001 = a plain-HTTP web interface without a redirect to HTTPS on a
  device NetAudit takes for a printer, camera, NAS or network device; the
  gateway's own is `RTR-SVC-001:http`, never both. NET-TLS-001: expired =
  medium, self-signed = low. LLMNR not heard = ok "none heard in N s", which
  does not prove it is off. `RTR-VER-001` in PR 1 is the support status from
  endoflife.date only; KEV and NVD need version ranges and come with N7.
- **AI**: the stored report is unchanged; `ai_analyze` replaces a
  `lan_audit` result with a note unless the run had `share_with_ai = yes`.
- **Not in PR 1**: other subnets, segments and isolation (PR 2), known
  vulnerabilities by version (PR 3), trends for this check (no identity yet).
