# Firewall: "iptables INPUT is open" only when nftables does not filter input either

Status: USER asked to finish the remaining list autonomously (2026-10-22:
«докончим уже все и закроем дыры работаем автономно»); this is item 4 of it,
`FINDINGS.md` 2026-10-08 (5) "firewall does not tell iptables-nft from
legacy". Implementer: Claude. Reviewer: GPT/Codex.

## Evidence

Live, in an isolated namespace (`unshare -rn`, no root, no effect on the
host), iptables 1.8.10:

```
$ iptables -V
iptables v1.8.10 (nf_tables)

# native nftables, input filtered:
$ nft add table inet filter
$ nft add chain inet filter input '{ type filter hook input priority 0; policy drop; }'
$ nft add rule inet filter input tcp dport 22 accept
$ iptables -S
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT

# legacy tables, input filtered (iptables-legacy -P INPUT DROP):
$ iptables-legacy -S
-P INPUT DROP
...
$ iptables -S          # the nf_tables view
-P INPUT ACCEPT
...
```

`iptables -S` with the nf_tables backend shows only the iptables-nft tables
(`table ip filter`), and with no such table it prints the three default
`ACCEPT` policies. `_iptables_verdict()` (`checks/server_security.py`) reads
"policy ACCEPT, no rules" as `OPEN`, and `audit_firewall()` reports
**HIGH FW-IPT-001 "iptables INPUT is effectively open"**, although the
kernel drops the traffic in the nftables chain. The same happens when the
filtering is in iptables-legacy tables. So every host with the `iptables`
package (nf_tables backend, the Debian and Ubuntu default) and a native
nftables or firewalld firewall gets a false HIGH.

How the kernel decides: a packet passes every base chain on the input hook
(iptables-legacy, the iptables-nft `ip filter INPUT` chain, native nftables
chains). `accept` ends only the chain it is in; `drop` is final. Input is
open only if none of them filters.

iptables-nft also warns when legacy tables exist: the binary carries
`# Warning: %stables-legacy tables present, use %stables-legacy%s to see them`
(`strings /usr/sbin/xtables-nft-multi`). It reads `/proc/net/ip_tables_names`,
which only real root can read, so the warning could not be produced in the
namespace; which stream it goes to is UNKNOWN, so both are read.

## Design

1. **Evidence** (`firewall_config.py`):
   - `CommandResult` gets `stderr: str = ''`; `_run_sudo_with_exit_code()`
     fills it (the helper already returns stderr).
   - `FirewallEvidence` gets `iptables_version: CommandResult | None = None`:
     `iptables -V` without sudo (it needs none and changes nothing).
2. **Which nftables chains filter input** (`server_security.py`, pure
   function on the `nft list ruleset` text). The question is narrow: is
   there an IPv4 packet that the chain surely drops? If so, "everything is
   allowed" is false. The packet is a **witness**: a new TCP connection
   (`ct state new`), arriving on an external interface, from a public
   address that no `ip saddr` in the ruleset names, to a TCP port that no
   `tcp dport`/`th dport` in the ruleset names. When no such address or port
   is left (`tcp dport 0-65535`), nothing is proven.
   Every expression of a rule is read as true, false or unknown for the
   witness: `ct state`, `ct status`, `meta nfproto`/`protocol`/`l4proto`/
   `pkttype`, `ip protocol`/`version`/`saddr`, `ip daddr` (only `0.0.0.0/0`
   (true) and multicast/broadcast (false) are known; the host's own address
   is not), `tcp dport`/`th dport`, `udp`/`icmp`/`icmpv6`/`sctp`/`ip6`
   (false: the witness is IPv4 TCP), `iifname`/`iif` (false only for `lo`
   and container/bridge names such as `docker0`, `br-*`, `veth*`; any other
   name may be the external interface), `fib daddr type`, `!=` forms, sets
   `{ ... }` and verdict maps keyed by `ct state`, `tcp dport`,
   `meta l4proto`. Anything else (`limit`, named sets `@name`, marks, ...)
   is unknown. A rule with a false expression does not match; one with only
   true expressions matches; otherwise both outcomes are followed. `jump`,
   `goto`, `return` are followed the same way; a missing chain or a loop is
   unknown. The chain **filters** only when every path ends in `drop`/
   `reject` (its policy at the end). A rule that may accept everything
   (`ip saddr 0.0.0.0/0 accept`, `ct state new accept`, `iifname "eth0"
   accept`) therefore never gives a false "filtered" (review #51 R1).
   When the evaluation is not certain, the iptables verdict stays as it
   was (HIGH), which is no worse than before.
   **NAT** (review #51 R2): a DNAT or redirect in prerouting can give a new
   connection `ct status dnat` and another destination port before the input
   hook. So when any rule with `dnat`, `snat`, `masquerade`, `redirect` or
   `tproxy` (in an `ip`/`inet` table) may match the witness - its own
   conditions are read the same way -, `ct status` and `tcp dport` are
   unknown for it. Without such a rule a new connection has none of the
   `ct status` flags `dnat`, `snat`, `expected`, `seen-reply`, `assured`,
   `confirmed`, `dying`; any other flag is unknown.
3. **`_iptables_verdict()`**, when the iptables view is open (policy ACCEPT
   and no rules, or an unconditional ACCEPT):
   - the output (stdout or stderr) carries the iptables-legacy warning →
     `UNKNOWN`, reason "iptables-legacy tables are present and were not read
     (read them with iptables-legacy -S)" → FW-IPT-002, low, manual
     verification;
   - the live nftables ruleset was read and an input chain filters →
     new verdict `FILTERED_BY_NFTABLES` → `ok`: "iptables: INPUT has no
     filtering of its own; input is filtered by nftables", detail names the
     chain(s), e.g. `inet filter input`;
   - otherwise → `OPEN` → HIGH FW-IPT-001, as before. When the nftables
     ruleset could not be read, the detail says so (the nftables part is
     already reported as FW-NFT-003).
4. The backend from `iptables -V` (`nf_tables` / `legacy`) is named in the
   iptables finding's detail; when `iptables -V` fails, nothing is named and
   nothing else changes.
5. **Unchanged**: one finding per backend (UFW, nftables, iptables); the
   UFW and nftables findings; the iptables `FILTERED`/`UNKNOWN` cases; the
   ids (FW-IPT-001 stays the "open" finding, FW-IPT-002 the "could not
   determine" one); IPv6 (`ip6tables` is not read, as before).

   The `audit_firewall()` docstring said there is no link between backends,
   so that a good result of one never hides a problem in another. That
   stays true for the findings: an inactive UFW or an empty nftables
   ruleset is still reported. What changes is one statement, "iptables
   INPUT is effectively open": it is a claim about the input path, and the
   nftables evidence shows when it is wrong.

## Tests (RED first)

- The live case above: nftables `inet filter input` with `policy drop`, and
  `iptables -S` with the three ACCEPT policies → no HIGH, the iptables
  finding is `ok` and names `inet filter input`.
- Filtering: firewalld style (base chain policy accept, `jump
  filter_INPUT_ZONES`, `goto filter_IN_public`, then the final `reject` of
  the base chain), also with a trusted zone reached by a conditional `goto`
  whose chain is a bare `accept`; an unconditional `reject` in a chain
  reached by `jump`; a final `counter ... drop` or `log prefix "..." drop`
  in a policy-accept chain; `policy drop` with conditional accepts.
- Not proven (HIGH as before): `policy drop` with `ip saddr 0.0.0.0/0
  accept`, `ip daddr 0.0.0.0/0 accept`, `ip saddr { 0.0.0.0/1, 128.0.0.0/1 }
  accept`, `tcp dport 0-65535 accept`, `ct state new accept`,
  `meta l4proto tcp accept`, `iifname "*" accept`, `iifname "eth0" accept`,
  `ip saddr @allowed accept`, `limit rate ... accept`, a vmap that accepts
  `new`, `ip daddr <an address> accept`. Filtering: `ct state vmap` without
  `new`, LAN-only sources plus loopback plus listed ports, a port vmap, only
  udp/icmp accepted.
- Not filtering (HIGH as before): policy accept with only conditional rules,
  including `ct state invalid drop`, `meta nfproto ipv6 drop`,
  `ip6 saddr ::1 drop`; `drop` only in a comment or a quoted name;
  `accept` (or `counter accept`, `meta nfproto ipv4 accept`) before the drop
  or the drop policy; a conditional reject in a jumped-to chain; chains on
  `forward`/`output`; an `ip6` table; a regular chain nobody jumps to; a
  jump to a missing chain or a jump loop; nat-only (docker); the existing
  "backends do not suppress each other" test.
- The iptables-legacy warning in stdout, and in stderr → FW-IPT-002 with the
  reason, not HIGH.
- nftables ruleset not readable → HIGH as before, the detail says the
  nftables ruleset was not checked.
- `iptables -V` `(nf_tables)` / `(legacy)` → named in the detail; `iptables -V`
  not completed → no backend named, verdict unchanged.
- `_run_sudo_with_exit_code()` keeps stderr.
