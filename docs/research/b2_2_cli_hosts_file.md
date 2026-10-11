# B2.2 — CLI group run from a hosts file

Status: B2 approved by USER (2026-10-11: «Да, автономно») on the contract
`b1_multi_host_contract.md` (§3.1). Implementer: Claude. Reviewer: GPT/Codex.
This note fixes the CLI details §3.1 leaves open. The concurrency limits and the
64/256 input limits belong to B2.1 (engine); B2.2 passes them through once
B2.1 is merged.

## Command

```
netaudit run <check> [<check> ...] --hosts-file hosts.json [--user U] [--port P]
             [--key_path K] [--password -] [--sudo_password -] [other check params]
```

`hosts.json` is a JSON array of host records:

```json
[{"host": "10.0.0.5"}, {"host": "web-2.example", "user": "audit", "port": 2222,
  "key_path": "~/.ssh/audit_ed25519"}]
```

- **Fields:** `host` is required. `user`, `port` and `key_path` are optional.
  Any other key is an error, and `password` / `sudo_password` get their own
  message: secrets never go in the file.
- **Validation** (`netaudit_pkg/hosts.py`, reused by the inventory in B2.3):
  - `host`: 1–253 characters from letters, digits, `.`, `-`, `_` and `:`
    (IPv6), not starting with `-`;
  - `user`: 1–32 characters, a letter or `_` first, then letters, digits, `.`,
    `_`, `-`;
  - `port`: a JSON integer in 1–65535, not a boolean or a string;
  - `key_path`: a non-empty string with no NUL byte. It must be a readable
    file when the run starts; the error names the path only.
- **Duplicates:** two records with the same host are an error before anything
  runs, even when user or port differ (B1 §3.1). Hosts are compared
  case-insensitively, and IP addresses in normalised form.
- **Empty files:** an empty array, a file that is not JSON, or JSON that is
  not an array of objects is an error.

## Parameters

- **Common flags** apply to every host. A record's own `user` / `port` /
  `key_path` win over them.
- **Checks:** every selected check must have a `host` parameter. A check
  without one (e.g. `ssl`, `ping`) is an error that names it; run it
  separately. `--quick` is not allowed with `--hosts-file`: pick the checks.
- **`--host`:** not allowed together with `--hosts-file`.
- **Secrets:** in the group form every secret flag (any password-type
  parameter name) is checked before the first prompt. It must be `-`: a
  literal value is an error, because `ps` and shell history would see it. It
  must also be used by at least one selected check; for example
  `--sudo_password` with only `backup_check` is an error rather than silently
  ignored (review #35). `-` asks once per name, without echo, and keeps the
  value in memory only.
- **Engine call:** the run calls `run_checks_multi()` with one `instances`
  entry per host. One host gives the flat result shape, several give
  `by_host`, exactly as the Web path today.

## Repeated flags

- **Group form:** the same `--param` twice is an error.
- **Single-host form:** only a repeated `--host` is an error, and its message
  points to `--hosts-file` (B1 §3.1). Any other repeated parameter keeps the
  old behaviour, where the last value wins, so scripts that append an
  overriding flag keep working (review #35). Otherwise
  `netaudit run <check> --host H ...` behaves exactly as before.

## Tests (RED first)

1. Two records plus common `--user` and `--password -`: each check gets one
   instance per host, a record's `user` / `port` win, the prompt is asked once,
   and the port is an `int`.
2. `password` or `sudo_password` in a record, or an unknown key, is refused
   before anything runs.
3. Duplicate hosts (`WEB-1` / `web-1`, or the same IP with different ports)
   are refused.
4. `--host` with `--hosts-file`, `--quick` with `--hosts-file`, and a non-host
   check are refused.
5. A literal `--password secret` in the group form is refused; `-` is accepted.
6. An unreadable `key_path` is refused and the message holds only the path.
7. A bad host (`-oProxyCommand`, whitespace, empty), a bad port (`0`,
   `70000`, `"22"`, `true`), or a bad file (not JSON, not an array, `[]`) is
   refused.
8. `--host a --host b` is refused with a hint about `--hosts-file`. A single
   `--host a` still runs `run_checks()` as before. In the single form,
   `--port 22 --port 2222` uses 2222; in the group form it is refused.
10. A secret flag that no selected check uses is refused, whether its value
    is a literal or `-`. No prompt is shown, and nothing runs.
9. End to end with a stubbed check function: the saved report row contains
   neither password, and `execution_context` holds one entry per host.
