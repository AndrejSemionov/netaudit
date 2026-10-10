# F6 — consistent `command -v` verdicts in server audit

Status: review pass 1 returned; PATH fix implemented locally, awaiting pass 2. USER approved
F1–F7 autonomous follow-up on 2026-10-09.
Implementer: GPT/Codex. Reviewer: Claude. Base: `codex/a1-command-presence`.

## Problem

`firewall_config.tool_is_present()`, `fail2ban_config.binary_verdict()` and
`server_security._sql_binary_verdict()` consider only exit 127 a confirmed
absence. Bash returns exit 1 for `command -v` when a binary is missing; an
otherwise healthy Bash target becomes UNKNOWN and may produce a manual
finding instead of a confirmed optional absence. Their current success rule
also accepts exit 0 with empty output, which is not evidence of a path.

## Contract

Use the same verdict rule as A1 `probe_remote_tool()`:

| completion | exit | stdout | verdict |
|---|---:|---|---|
| yes | 0 | nonempty | PRESENT |
| yes | 1 or 127 | empty | ABSENT |
| any other combination | any | any | UNKNOWN |

Use A1's system PATH prefix (`/usr/sbin:/sbin`) for these collectors as well:
a non-root SSH login can otherwise classify an installed `ufw` as absent.
Share the command builder and verdict classifier with A1's
`probe_remote_tool()` so all four call sites follow one rule. Apply this
rule only to the three `command -v` consumers above. Keep their
public result names (`True/False/None`, `PRESENT/NOT_PRESENT/UNKNOWN`,
`FOUND/NOT_FOUND/UNKNOWN`) and collector evidence shapes. `ufw` and
`fail2ban-client` presence is an unprivileged PATH lookup; there is no new
sudo attempt. SQL is absent only if both mysql and mariadb probes confirm
absence. If one succeeds, presence is established; if one is unknown and the
other absent, aggregate presence stays unknown. Unexpected output on a
failed command is not evidence of absence.

## RED cases

- Bash exit 1 + empty output means confirmed absent for UFW, Fail2Ban and
  both SQL binaries; no false unknown finding for an optional absent tool.
- dash exit 127 + empty output remains absent.
- Exit 1 or 127 with output, exit 0 without a path, and missing completion
  marker remain unknown; each semantic consumer exposes incomplete
  verification instead of a false clean/absence result.
- Exit 0 with a path remains present, including the original status checks.
- A binary in `/usr/sbin` remains present when a non-root login's PATH omits
  `/usr/sbin` and `/sbin` (UFW, Fail2Ban and both SQL probes).

Commit contract, RED tests, then GREEN separately. Run profile tests, broad
pytest excluding the known Web TestClient hang in Codex, Ruff, compileall,
Bandit and diff check. Claude performs independent review and the full Web
pytest before PR delivery. Merge remains USER.
