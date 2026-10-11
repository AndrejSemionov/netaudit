# B2.5 — E2E: several hosts in one run on the real SSH stand

Status: B2 approved by USER (2026-10-11: «Да, автономно») on the contract
`b1_multi_host_contract.md` (§4 step 5). Implementer: Claude. Reviewer:
GPT/Codex. It extends the A3 stand (`e2e_ssh_stand.md`), runs in the CI job
`e2e-ssh` only, and does not change product code.

## Stand

- The job starts a second container from the same image, `stand2`, on
  `127.0.0.1:2223`, next to `stand` on `127.0.0.1:2222`. It waits for both and
  exports `NETAUDIT_E2E_PORT2=2223`.
- A "refused" host is a local port nothing listens on: the test binds an
  ephemeral port and closes it. It is named `localhost` so its `by_host` key
  differs from `127.0.0.1`.

## Scenarios (tests/e2e/test_multi_host.py)

1. **Engine.** `run_checks_multi()` runs `ssh_hardening` on two instances:
   the stand (user `pwsudo`, sudo password) and the refused host.
   - `by_host` holds both. The stand has a hardening score, and the refused
     host has a `could not connect` error.
   - After `save_report()` / `load_report()` both are still there, and
     `execution_context` has both keys without `password` / `sudo_password`.
2. **Web streaming path.** `streaming.run_stream()` gets the same two
   instances.
   - There is one `check_done` per host, the refused one with its error, and
     then `all_done`.
   - The per-run password appears in none of the SSE events, the SQLite
     files (`netaudit.db*`), the captured log, or the request body
     `ai_analyze()` would send (`httpx.post` faked, no network).
3. **TOFU on real servers (#34).** With an empty `known_hosts`, one
   `run_checks_multi()` connects to `:2222` and `:2223` in parallel.
   - Both audits succeed, and `known_hosts` holds both `[127.0.0.1]:2222` and
     `[127.0.0.1]:2223`.
   - A second run verifies both pins strictly and succeeds.

The CLI `--hosts-file` path (B2.2) and the saved-host picker (B2.3) reach the
same `run_checks_multi()` / `run_stream()`. Their own tests cover what they
add, and an E2E case for the CLI comes once B2.2 is merged.
