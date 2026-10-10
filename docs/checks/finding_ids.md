# Finding ID catalogue

Contract: `docs/research/stable_finding_ids_research.md` (rev.3, approved
2026-09-27). This file is **machine-read** by `tests/test_finding_ids.py`:
every table row below is a control, and every `_finding(...)` call in the
in-scope modules must use one of these control ids.

Format: `PREFIX-GROUP-NNN`, uppercase. Controls with a **Subject** emit
`CONTROL_ID:part[:part...]`, each part `urllib.parse.quote(part, safe='')`,
built by `netaudit_pkg.findings.subject_id()`. Severities: the set the control
may emit (the rule itself stays in the check).

**Stability rule:** a released id is never renamed, renumbered or reused for
another control. A removed control retires its number; a control whose meaning
changes materially gets a new number. The trend layer diffs findings by id —
a rename would read as "fixed + new problem".

Existing catalogues (`KRN-*`, `NGX-*`, `SSH-*`) live in `kernel_hardening.md`,
`nginx_hardening.md`, `ssh_hardening.md` and are unchanged.

## server_audit — fail2ban section (`audit_fail2ban`)

| Control id | Severities | Subject | Control |
|---|---|---|---|
| F2B-INST-001 | medium | — | fail2ban is not installed |
| F2B-INST-002 | low | — | could not determine whether fail2ban is installed |
| F2B-STAT-001 | low | — | could not determine fail2ban status |
| F2B-STAT-002 | low | — | fail2ban status returned but could not be parsed |
| F2B-STAT-003 | low | — | fail2ban status could not be confirmed even with sudo |
| F2B-STAT-004 | low | — | fail2ban status command failed |
| F2B-JAIL-001 | medium | — | no jail for SSH |
| F2B-JAIL-002 | low | — | could not fully determine fail2ban jail status |

## server_audit — firewall section (`audit_firewall`)

| Control id | Severities | Subject | Control |
|---|---|---|---|
| FW-UFW-001 | high | — | ufw is installed but disabled |
| FW-UFW-002 | low | — | could not determine ufw status |
| FW-NFT-001 | high | — | nftables config has rules, but the live ruleset is empty |
| FW-NFT-002 | low | — | nftables: no rules loaded and no config file found |
| FW-NFT-003 | low | — | could not determine nftables live ruleset state |
| FW-IPT-001 | high | — | iptables INPUT is effectively open |
| FW-IPT-002 | low | — | could not determine iptables status |

## server_audit — SQL section (`audit_sql`)

| Control id | Severities | Subject | Control |
|---|---|---|---|
| SQL-INST-001 | low | — | could not determine whether MySQL/MariaDB is installed |
| SQL-NET-001 | high | — | MySQL is listening on a non-loopback address |
| SQL-NET-002 | low | — | could not determine MySQL listener state |
| SQL-BIND-001 | high | — | bind-address in the MySQL config allows non-loopback connections |
| SQL-BIND-002 | low | — | could not fully determine MySQL bind-address configuration |

## web_security_external

| Control id | Severities | Subject | Control |
|---|---|---|---|
| WEB-HDR-001 | low | — | the server discloses its version |
| WEB-HDR-002 | medium | — | missing header strict-transport-security |
| WEB-HDR-003 | low | — | missing header x-frame-options |
| WEB-HDR-004 | low | — | missing header x-content-type-options |
| WEB-HDR-005 | low | — | missing header content-security-policy |
| WEB-HDR-006 | low | — | header x-powered-by discloses the technology |
| WEB-HDR-007 | low | — | header x-aspnet-version discloses the technology |
| WEB-HDR-008 | low | — | header x-aspnetmvc-version discloses the technology |
| WEB-COOKIE-001 | high | cookie name | cookie: SameSite=None without Secure |
| WEB-COOKIE-002 | high, medium | cookie name | cookie: missing flag(s) Secure/HttpOnly/SameSite |
| WEB-CORS-001 | high | — | CORS: Allow-Origin=* together with Allow-Credentials=true |
| WEB-CORS-002 | high | — | CORS: the server reflects any Origin back |
| WEB-ERR-001 | medium | — | verbose error page |
| WEB-TLS-001 | high | — | outdated TLS versions are supported |
| WEB-PATH-001 | high | — | sensitive paths are exposed |

## docker_audit

| Control id | Severities | Subject | Control |
|---|---|---|---|
| DCK-API-001 | high | — | Docker daemon is listening on TCP without explicit TLS (port 2375) |
| DCK-USER-001 | medium | container | the process inside the container runs as root |
| DCK-PRIV-001 | high | container | running with --privileged |
| DCK-CAP-001 | high | container | risky capabilities added |
| DCK-NET-001 | low | container | ports listening on all interfaces |
| DCK-SOCK-001 | high | container | docker.sock mounted inside the container |
| DCK-MNT-001 | medium | container, host path | a sensitive host path is mounted |
| DCK-IMG-001 | low | container | image with no version pin |
| DCK-INS-001 | low | — | container inspection incomplete |

## systemd_hardening

| Control id | Severities | Subject | Control |
|---|---|---|---|
| SYS-SBX-001 | high, medium, low | unit, directive | sandboxing directive not restricted |
| SYS-SCORE-001 | low | unit | could not extract the overall exposure score |
| SYS-SCORE-002 | low | unit | could not determine the overall exposure score |

## backup_check

| Control id | Severities | Subject | Control |
|---|---|---|---|
| BKP-DIR-001 | high | directory | backup directory does not exist |
| BKP-DIR-002 | high | directory | no backup files found |
| BKP-COL-001 | low | directory | backup directory listing could not be confirmed |
| BKP-AGE-001 | high | directory | the latest backup is stale |
| BKP-SIZE-001 | high | directory | the latest backup is suspiciously small |
| BKP-COPY-001 | medium | directory | fewer local backup copies than expected |
| BKP-INT-001 | high | directory | the latest backup fails the integrity check |
| BKP-INT-002 | low | directory | latest backup integrity could not be verified |
| BKP-INT-003 | low | directory | latest backup integrity check was skipped |
| BKP-DISK-001 | medium | directory | backup partition is ≥90% full |
| BKP-DISK-002 | low | directory | backup partition usage could not be determined |

## dns_audit

| Control id | Severities | Subject | Control |
|---|---|---|---|
| DNS-SPF-001 | high | — | no SPF record |
| DNS-SPF-002 | high | — | multiple SPF records |
| DNS-SPF-003 | high | — | SPF exceeds the DNS-lookup limit |
| DNS-SPF-004 | medium | — | SPF is close to the lookup limit |
| DNS-SPF-005 | high | — | SPF ends with +all/?all |
| DNS-SPF-006 | low | — | SPF has no explicit all mechanism |
| DNS-DKIM-001 | medium | — | no DKIM found (checked common selectors) |
| DNS-DKIM-002 | high | selector | DKIM selector is revoked (empty p=) |
| DNS-DMARC-001 | high | — | no DMARC record |
| DNS-DMARC-002 | low | — | DMARC p=none (monitoring only) |
| DNS-DMARC-003 | medium | — | DMARC p=none with no reporting (rua) |
| DNS-DMARC-004 | medium | — | DMARC has no recognized p= policy |
| DNS-SEC-001 | medium | — | DNSSEC is not enabled |
| DNS-SEC-002 | medium | — | DNSKEY exists but no DS record at the registrar |
| DNS-CNAME-001 | high, medium | subdomain | dangling CNAME (subject is the subdomain, never the target) |
| DNS-TXT-001 | low | service label | third-party service detected via TXT |

`ok` and `info` findings carry no id: the trend layer does not count them.
