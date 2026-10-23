# A4.1 — audit of check parameters (CLI and Web API)

Status: research, no code. USER approved the stabilization plan step A4.1
(2026-10-23: «давай как предлагаешь»): inventory every parameter, reproduce
every hole, then fix by a contract USER approves. Author: Claude. Review:
GPT/Codex.

USER decision on §4 (2026-10-23): «Всё, включая диапазоны чисел
(Recommended)» — every rule below, number ranges included.

Base: `main` `da2c9d6` (after #49-#52). All runs below on a temporary HOME,
no audited server, no network unless stated.

## 1. What already holds

| Area | How it is protected | Where |
|---|---|---|
| checkbox, number, select | one type check for CLI and the three Web run endpoints; the value is never printed | #49, `registry.param_value()` |
| unknown flags, missing target | refused before anything runs | #46, #47 |
| repeated flags | last wins; `--host` twice is refused | B2.2 |
| secrets in messages and reports | names only in errors; `password`-type values redacted from `execution_context` | tasks 3, #46, #49 |
| SSH parameters (`host`, `user`, `port`, `key_path`, passwords) | go to Paramiko, never to a shell; sudo password via stdin | `ssh.py` |
| remote paths | `shlex.quote` / argv (`cve_audit` WordPress and composer paths, `backup_check` directories, `journalctl -n`) | task 8, #49 |
| `backup_check` `directories` | must be absolute (so `-delete` cannot reach `find`) | `backup_check.py:181` |
| `systemd_hardening` `unit` | validated name | task 8 |
| MikroTik `target_ip` | validated IPv4 | task 8 |
| `cert_transparency` `domain` | sent as an encoded query parameter | `httpx` `params=` |
| local commands | always an argument list, never a shell | `utils.run_cmd()` |

## 2. Inventory of the free-text parameters

The 15 `text` parameters that are not SSH fields:

| Parameter | Checks | Where the value goes | Protection today |
|---|---|---|---|
| `target` | `ping`, `mtr`, `tcptraceroute`, `arping` | last argument of a local tool | **none** |
| `hostname`, `record_type` | `dig` | last two arguments of `dig` | **none** |
| `domain`, `subdomains_to_check` | `dns_audit` | last argument of `dig` | **none** |
| `domain` | `cert_transparency` | crt.sh query parameter | encoded |
| `url` | `ssl`, `http`, `security_headers`, `sql_injection` | `curl`/`openssl`/`sqlmap`, `https://` added when there is no `://` | scheme not checked |
| `url` | `web_security_external` | rebuilt as `https://{hostname}` | safe |
| `server` | `iperf` | value of `iperf3 -c` | safe (option argument) |
| `interface`, `bpf_filter` | `tshark_capture` | values of `-i`, `-f` | safe (option arguments) |
| `router` | `mikrotik_sniffer` | Paramiko host | safe |
| `target_ip` | `mikrotik_sniffer` | RouterOS command | validated |
| `emails` | `breach_check` | path of the XposedOrNot / HIBP URL, not encoded | none (host is fixed) |
| `expected_issuer_contains` | `cert_transparency` | substring match only | not needed |
| `directories` | `backup_check` | remote `find`, quoted | absolute paths |
| `unit` | `systemd_hardening` | remote command | validated |

## 3. Findings

**P1 — SECURITY: `dig` reads a local file and shows its lines.** `check_dig()`
runs `dig +noall +answer +stats +comments <record_type> <hostname>`
(`checks/network.py:170`). A value that starts with `-` is an option;
`-f <file>` is dig's batch mode, which reads the file and runs each line as a
query. A line that is not a legal name comes back in dig's error, which the
check returns as `error`, so it reaches the CLI, the Web page, the report in
SQLite and the AI request.

```
run_checks([{'id': 'dig', 'params': {'hostname': '-f<file>', 'record_type': 'A'}}])
-> {'error': "dig: 'SECRETMARKERaaaa…' is not a legal name (label too long)"}
```

(test file in the scratchpad, a 72-character label so that nothing is sent;
`main` `d815f86`.) Every file the NetAudit service account can read is
reachable this way. Through the Web it crosses the boundary of #43: a Web
user is not meant to see stored secrets or files of the service account.
`record_type` is free text in the same position.

**P2 — a target can be an option of the local tool.** Same cause in `ping`
(`target='-V'` printed ping's version: the option ran), `mtr` (`-F<file>`
read the file; nothing reached the output in the test), `tcptraceroute`,
`arping`, and `dns_audit` (`domain` is the last argument of `dig`; no leak
reproduced). None of these values is checked to be a host or an address.

**P3 — the URL scheme is not checked.** `ssl`, `http`, `security_headers`
and `sql_injection` keep any value that contains `://`. Checked live (test
files in the scratchpad):
- `sql_injection` with `file://<page.html>` reads the local file and lists
  its form fields in the report (`"inputs": ["SECRETFIELD"]`);
- `security_headers` with `file://…` fetches the file (`curl -I`) but
  shows nothing of it;
- `--url=file://…` (it contains `://`) reached `curl` as an option; curl
  rejected that spelling (`option --url=…: is unknown`), so no harm was
  shown, but the value is read as an option.
`web_security_external` is not affected (it rebuilds `https://{host}`).

**P4 — `dig` `record_type` is free text** although only DNS types make sense;
it should be a select.

**P5 — `breach_check` `emails` are not validated** and go unencoded into the
path of the API URL. The host is fixed, so this can only change the path on
the same API. Low.

**P6 — numbers have no range.** `port` 99999, `count` 10⁹ or `duration`
10⁶ are accepted; the check fails late or runs for a very long time
(`ping -c 1000000000` with a timeout of `count + 10` seconds). The operator
chooses these, so this is robustness, not a hole. Low.

## 4. Proposed fix (for USER approval)

One rule per kind of value, checked by the existing `registry.param_value()`
(so the CLI and the three Web endpoints get it at once, before anything
runs, the value never printed):

- a `format` key on the 15 text parameters' specs:
  - `host` (`target`, `hostname`, `server`, `router`): an IPv4/IPv6 address or a
    host name — letters, digits, `.`, `-`, `:`, `_`, at most 253 characters,
    **not starting with `-`**;
  - `domains` (`dns_audit` `domain`, `subdomains_to_check`,
    `cert_transparency` `domain`): comma list of host names, same rule;
  - `url` (`ssl`, `http`, `security_headers`, `sql_injection`,
    `web_security_external`): after the existing `https://` default, the scheme
    must be `http` or `https` and the host must pass the `host` rule;
  - `emails`: comma list of `local@domain` without `/`, `?`, `#`, spaces;
  - `interface`: letters, digits, `.`, `-`, `_`, `:`, not starting with `-`;
- `dig` `record_type` becomes a select (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `PTR`,
  `SOA`, `SRV`, `TXT`, `CAA`) — the CLI keeps `--record_type MX`;
- numbers get ranges where a wrong value is clearly a mistake (P6, optional):
  `port` 1–65535, `count` 1–1000, `duration`/`duration_sec` 1–3600, `lines`
  1–100000, `max_hops` 1–64, `window_hours` 1–720, `max_age_hours` 1–8760,
  `min_copies` 0–1000.

Unchanged: `bpf_filter` and `expected_issuer_contains` (free text by design,
never a command argument position), SSH fields, `directories`, `unit`,
`target_ip` (already validated), the Web form (its defaults pass every rule).

## 5. Tests (RED first)

- P1: `dig` with `hostname='-f<file>'` is refused before `dig` runs (CLI and
  Web API), and the file's content appears nowhere; the same for
  `record_type`.
- P2: `ping`, `mtr`, `tcptraceroute`, `arping` with `-V` / `-F<file>` and
  `dns_audit` with `domain='-f<file>'` → refused; real hosts, IPv4, IPv6 and
  the registry defaults pass.
- P3: `file:///etc/hostname`, `--url=file:///x`, `ftp://h` → refused for the
  four checks; `example.com`, `https://h/p?q=1`, `http://h:8080` pass.
- P4/P5/P6: a record type outside the list, a malformed email, `port 0` /
  `65536`, `count 0` → refused; each default passes.
- Every registry default passes its own rule (a new parameter must fit).
