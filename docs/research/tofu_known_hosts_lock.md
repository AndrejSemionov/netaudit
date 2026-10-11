# TOFU: parallel first connections never lose or overwrite a pinned key

Status: USER approved as a separate task (2026-10-11: «Сейчас, отдельной
задачей»), from B1 §3.2 / §4 step 0. Implementer: Claude. Reviewer: GPT/Codex.

## Evidence

- `SSHExecutor.connect()` loads `~/.netaudit/known_hosts` only if the file
  exists. `TofuPolicy.missing_host_key()` adds the key to the client's own
  in-memory table and calls Paramiko `SSHClient.save_host_keys()`. That
  re-reads the file only when the client loaded it, and then rewrites it with
  `open(filename, "w")`. There is no lock.
- **Reproduced, deterministic, no network** (`main` `37a7c99`): on a fresh
  install two clients are created as in `connect()` before the file exists.
  They pin first keys for `host-a` and `host-b`; the file then holds only
  `host-b`. The log still says, for `host-a`, "future connections will verify
  against this key". The next connection to `host-a` is a "first connection"
  again and accepts any key.
- **Worse, by the same code path:** if two first connections to the **same**
  host see different keys (one of them a man-in-the-middle), whichever
  writes last becomes the pinned key. When the file exists, the second writer
  merges both keys for one host.
- Web `instances` already connects to every host of a check in parallel with
  no limit (`engine.run_instances()`), so this is reachable today.

## Design

1. `TofuPolicy.missing_host_key()` no longer calls `save_host_keys()`. It
   calls a module function `_pin_host_key(hostname, key)`.
2. `_pin_host_key()` holds an exclusive lock for local file work only. The
   lock is `fcntl.flock` on `known_hosts.lock` next to the file, which works
   between threads and between processes (CLI and Web), plus an in-process
   `threading.Lock`. The network handshake is not under the lock: Paramiko
   calls the policy after it has the server key.
   - It re-reads the file as it is now (`paramiko.HostKeys`).
   - The host already has **this** key: another worker pinned it meanwhile,
     and nothing is written.
   - The host already has **another** key: raise
     `paramiko.BadHostKeyException`. `connect()` already turns that into
     `HostKeyMismatchError`. The file is not touched. This is the same rule
     Paramiko applies to a host found at load time: any entry for the host
     that is not this key is a mismatch.
   - Otherwise it adds the key and writes the whole table atomically: a
     temporary file in the same directory, `fsync`, then `os.replace`. The
     existing file's mode is kept; a new file gets `0600`. On failure the
     temporary file is removed and the old file stays as it was.
3. The client's in-memory table still gets the key, as before. The file
   format is unchanged: Paramiko writes it and reads it back.
4. Log lines stay the same for a real first pin. "Already pinned by another
   connection" is logged at info level.

Out of scope: `connect()` logic other than the policy, `~/.ssh/known_hosts`,
key types, and B2.

## Tests (RED first)

1. Fresh install: two clients created before the file exists pin `host-a` and
   `host-b` → both are in the file. (Today only `host-b` is.)
2. Twenty threads pin twenty different hosts at once, starting from no file
   and from an existing file → all twenty and the old entry are in the file.
3. Two clients created before the file exists see different keys for the same
   host: the first one is pinned, the second raises `BadHostKeyException`, and
   the file still holds only the first key. (Today the second overwrites it.)
4. Same host, same key from two workers → no error, one entry.
5. The written file loads with `paramiko.HostKeys` and with
   `SSHClient.load_host_keys`, including `[host]:2222`.
6. A failing `os.replace` leaves the old file intact, removes the temporary
   file and releases the lock: the next pin succeeds.
7. Through `SSHExecutor.connect()`: a concurrent different key surfaces as
   `HostKeyMismatchError`.

`test_ssh.py::test_tofu_policy_saves_key_on_first_connection` used a fake key
without serialization and a fake `save_host_keys()`. It moves to a real key,
with the same assertion.
