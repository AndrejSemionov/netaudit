# E2E: an SSH failure is never reported as a clean result (A4.2 p. 7-9, A4.4)

Status: USER «да делайте автономно» (2026-10-23) to "E2E on the CI stand for
SSH failures: a timeout, a connection dropped during a check, a slow
server". Implementer: Claude. Reviewer: GPT/Codex.

## What exists

The stand (`tests/e2e`, CI job `e2e-ssh`) covers logins, sudo variants and,
for several hosts, a reachable host next to a refused port (B2.5). Nothing
covers a server that accepts the connection and then misbehaves.

## Design

A small TCP proxy inside the test sits between NetAudit and the stand
(`127.0.0.1:<random port>` → the stand). It can:

| Mode | What NetAudit sees |
|---|---|
| silent | the connection is accepted, no SSH banner ever comes |
| close | the connection is closed right after it is accepted |
| cut | a real SSH login to the stand, then every connection is closed |
| cut mid-reply | while a long command runs, the server's replies trickle through the proxy (512 bytes / 20 ms); right after NetAudit has read the first part of its output (`paramiko.Channel.recv`), every connection is cut — the rest is still on its way |
| stall | a real SSH login, then the server's replies are held back |

"cut" and "stall" switch on right after `SSHExecutor.connect()` returns, so
the failure falls after the login and before the check's commands; "cut
mid-reply" falls inside a command: the real `SSHExecutor.run()` result is
observed, and the test requires a non-empty partial stdout without the
completion marker (for the wrapper with a 200 KB output: no exit code), then
the check's error without a score; it fails if the cut did not happen inside
the output (review #58 pass 2). With several hosts: one dropped and one stalled host, each next to a
healthy one (review #58 E3).

The oracle (review #58 E2): a failed run has a non-empty `error`, no
hardening score and no `ok` finding; it is itself tested against
clean-looking results (`all clear`, an empty error, a score).
The stand itself is not changed. The proxy's threads end in the test's
teardown.

Expected: the check's result is an error (or has no score) — never a
hardening score or an "all clear" computed from nothing; with two hosts the
healthy host keeps its full result and the other carries the error.

"silent" and "close" need no stand and run in every test job; the other
three run in `e2e-ssh` only. If the current code already behaves this way,
the tests are regression guards, not fixes — the PR says which.
