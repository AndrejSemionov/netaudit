# B2.3 — saved SSH hosts (inventory) without secrets

Status: B2 approved by USER (2026-10-11: «Да, автономно») on the contract
`b1_multi_host_contract.md` (§3.1). Implementer: Claude. Reviewer: GPT/Codex.
Stacked on B2.2, whose `netaudit_pkg/hosts.py` validates the records. This
note fixes what §3.1 leaves open.

## Storage

- **Table.** A new migration `_m5` creates `ssh_hosts(id, label, host, user,
  port, key_path)`. There is no column that could hold a secret. The existing
  `targets` table (`label/value/kind`) is untouched: it is not turned into an
  SSH inventory.
- **Functions.** `storage.ssh_host_add(record)`, `ssh_hosts_list()` and
  `ssh_host_delete(id)`.
- **Storage-level barrier.** `ssh_host_add()` itself runs
  `hosts.validate_host_record()`, which refuses `password` / `sudo_password`
  and unknown fields, plus a label check: at most 100 characters, no control
  characters. A direct caller cannot store a secret either.
- **Same host twice.** Two records with the same host but a different `user`
  or `port` are allowed (§3.1). A run that would use both for one check is
  refused in the Web UI (below). IPv4/IPv6 literals are stored in canonical
  form so equivalent spellings have the same picker key; DNS spelling is
  preserved for SSH host-key lookup.

## API

- `GET /api/hosts` returns exactly `{id, label, host, user, port, key_path}`
  per record. `user`, `port` and `key_path` are `null` when unset.
- `POST /api/hosts` takes a JSON object and returns `{ok, id}`. An invalid or
  secret-carrying payload gets **400** with a message that names fields, never
  values (including invalid `host`, `user` and `port` values). It is not
  FastAPI's 422, whose body echoes the submitted input back, secret included.
- `DELETE /api/hosts/{id}` deletes the record.
- `/api/targets`, `/api/presets`, `/api/run` and `/api/stream/start` do not
  change. The run API keeps its `#2` handling for duplicate hosts (§2).

## Web UI

- **Settings.** A new group, "SSH hosts", lists the records and has an add form
  with label, host, user, port and key path. It has no password field.
- **Run tab: the saved-hosts picker.** It shows checkboxes for the saved hosts
  and a button, "Apply to selected checks". For every selected check with a
  `host` parameter that supports several hosts, the button replaces its host
  blocks with one block per chosen host. That block gets the record's `host`,
  `user`, `port` and `key_path`; every other field, passwords included, is
  copied from the check's first block. The user types the password once,
  before applying. Nothing is saved.
- **Refusals.** Two chosen records with the same host are refused, with a
  message, before anything changes: this is the new group scenario of §2. No
  selected check, no chosen host, or no selected check that takes a `host`
  each gives a message and changes nothing.
- **Escaping.** Every value from `/api/hosts` passes through `escDeep()`, and
  the new HTML writers are registered in `test_web_frontend_escaping.py`.

## Tests (RED first)

1. Storage: add, list and delete round-trip. `password` / `sudo_password` /
   an unknown field / a bad host or port / a bad label raise, and nothing is
   stored. The raw SQLite row never contains a test secret.
2. API:
   - POST a valid record → 200 with an id; GET returns exactly the six keys.
   - POST with `password` → 400, and neither the body nor the database holds
     the secret.
   - POST with an unknown field or a bad port → 400.
   - DELETE removes the record.
   - `/api/targets` behaves as before.
3. Migration: an existing database at version 4 gains the table, and its
   existing rows are kept.
4. Frontend guard: the new HTML writers are classified, and the escaping check
   passes.
