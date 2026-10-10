# Low-severity reliability cleanup in Claude's half (A2 fix F7, part 1)

Status: stage A, MODE: AUTONOMOUS (USER: «Да, F1–F7 автономно»).
Implementer: Claude. Reviewer: GPT/Codex.
Source: `docs/research/result_reliability_audit.md` RA-07, RA-08, RA-09, RA-20
(all LOW; technical findings AGREED by GPT/Codex). RA-19
(`systemd_hardening`, GPT/Codex's half) is not part of this task.

## Evidence (`main` @ `ea68f97`) and design

- **RA-07 `ssh_audit` raw strings.** The result is text for the user and the
  AI, but three commands mislabel failures:
  - `failed_ssh_logins` drops journalctl's stderr and takes `tail`'s status,
    so an unreadable journal or a missing journalctl prints nothing — read as
    "no failed logins". **Design:** keep stderr, filter it like stdout (the
    permission hint stays visible) and append `journalctl exit <rc>` when
    journalctl itself failed.
  - `sshd_config` prints "no access" for grep exit 1 (no match). **Design:**
    grep's own error (exit 2) is shown as is; exit 1 prints "(no explicit
    PermitRootLogin/PasswordAuthentication/Port line in sshd_config)".
  - `unattended_upgrades` appends "not found" to "disabled". **Design:**
    print `systemctl is-enabled`'s own output (stderr included).
- **RA-08 `dig`.** `+noall +answer +stats` exits 0 for NXDOMAIN and SERVFAIL
  and hides the status. **Design:** add `+comments`, return `status`
  (NOERROR/NXDOMAIN/…); SERVFAIL, REFUSED or no status line → `error`.
  NXDOMAIN is an answer, not an error. Comment lines (`; EDNS …`, which
  `+comments` adds) are never read as records.
- **RA-09 local `firewall`.** `ufw status`'s exit code is ignored (non-root:
  "ERROR: You need to be root", on stderr → "no data"); any `nft` failure is
  labelled "no access (root)". **Design:** on a non-zero exit, show the
  tool's own message (`error: …`).
- **RA-20 measurement tools.** `ping` exit 0/1 with no recognisable statistics
  and `arping` exit 0 with none return `None` fields without an `error`;
  `tshark_capture` silently skips lines it cannot parse. **Design:** `ping`
  and `arping` add `error: could not parse … output` when the loss figure
  is missing; `tshark_capture` reports `unparsed_lines` when there are any.
  `mikrotik_sniffer` unchanged (its terse output has no reliable line
  format to count against).

## Tests (RED first, no network)

1. `dig`: NXDOMAIN → `status: NXDOMAIN`, no records, no error; SERVFAIL →
   `error`; NOERROR with an `; EDNS` line → exactly one record; the command
   has `+comments`.
2. Local `firewall`: `ufw status` exit 1 with the root error → the message
   is shown; `nft` failure → its message, not "no access (root)".
3. `ssh_audit` commands, run in a local `/bin/sh` with fake binaries first in
   `PATH`: journalctl that prints the permission hint → hint in the output;
   no journalctl → `journalctl exit 127`; grep exit 1 → "(no explicit …)";
   grep exit 2 with "Permission denied" → that message; systemctl printing
   `disabled` exit 1 → `disabled`, no "not found".
4. `ping` exit 0 without statistics → `error`; exit 1 with "100% packet
   loss" → `loss_pct: 100`, no error. `arping` exit 0 without statistics →
   `error`. `tshark_capture` with two unparsable lines → `unparsed_lines: 2`.
