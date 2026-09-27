# Stable finding IDs — Research Phase Summary

Status: **Research CLOSED. Contract PROPOSED — awaiting GPT/Codex review and USER approval.**
Date: 2026-09-27

## Goal

The trend layer (`docs/research/trend_layer_research_summary.md`, Contract
v1) reports new / resolved / persisting findings **by explicit `id` only**.
Findings without an `id` count toward severity totals and nothing else.
Today only the three hardening checks and the nginx/SSH parts of
`server_audit` carry ids, so for every other check the trend can say "one
fewer high problem" but not *which* one was fixed.

This phase answers: what id scheme to use, what gets an id, and how ids stay
stable — before any check is changed.

Scope of the first migration (state checks, where "resolved" means the
configuration changed): `server_security.py` (fail2ban, firewall, SQL,
`web_security_external`), `docker_audit`, `systemd_hardening`,
`backup_check`, `dns_audit`. Log checks (ssh_auth, nginx_logs, kern_log,
fail2ban logs) are **out of scope**: their findings are events, and
"resolved" there needs its own semantics.

## Finding 1 — a convention already exists

All 39 distinct ids already in the code (49 occurrences) follow one pattern, uppercase:

```
PREFIX[-GROUP]-NNN        KRN-001, NGX-TLS-002, SSH-AUTH-005
```

They are not ad-hoc strings: each is the control ID of a documented
catalogue — `docs/checks/ssh_hardening.md`, `nginx_hardening.md`,
`kernel_hardening.md` — and `scoring.Component.finding_id` links a score
component to the finding that explains it. `server_security.audit_nginx()`
and `audit_ssh_hardening()` reuse the same catalogue ids (`NGX-CONF-001`,
`SSH-AUTH-001`...), so one control has one id across checks.

**Consequence:** the new ids should extend this convention, not invent a
second one. This reduces the "format" decision to prefixes and to the one
genuinely new question below (Finding 3).

## Finding 2 — five kinds of findings

Inventory of the ~100 finding call sites in the five in-scope modules:

| Kind | Example | Id? |
|---|---|---|
| A. Static control | `ufw is installed but disabled`, `no jail for SSH`, `no DMARC record`, `Docker daemon is listening on TCP without explicit TLS` | one fixed id per control |
| B. Finite parameter | `missing header {hdr}` (fixed header list), `SPF exceeds the DNS-lookup limit ({n}/10)` | one fixed id per value of the finite set / per control; the number stays in the title |
| C. Open-ended subject | `{name}: running with --privileged` (container), `{unit} not restricted` (systemd unit), `{directory}: the latest backup is stale` (path), `DKIM selector {s} is revoked`, `dangling CNAME: {sub} → {target}`, `cookie "{name}": …` | see Finding 3 |
| D. Could not determine | `could not determine ufw status` (severity `low`, `requires_manual_verification`) | yes — it is counted as a problem, so an operator should see it appear/disappear |
| E. `ok` / `info` | `ufw is active`, `could not determine SPF status` (`info` in dns_audit) | not needed — not counted by the trend layer (`PROBLEM_SEVERITIES`) |

Kind B precedent: `server_security.audit_nginx()` already maps each header
to its own catalogue id (`header_control_ids[hdr]`).

## Finding 3 — open-ended subjects (the real decision)

For kind C the same control fires once per subject. Options:

1. **Control id only** (`DCK-PRIV-001` for every privileged container).
   Two privileged containers → two findings with the same id; the trend's
   `finding_ids` dict collapses them. If one is fixed and one is not, the
   trend shows the id as *persisting* — the fix is invisible. Counts stay
   correct.
2. **Control id + subject**: `DCK-PRIV-001:web`, `SYS-SBX-001:nginx.service`,
   `BKP-AGE-001:/var/backups/db`. Per-subject new / resolved / persisting.
   A renamed subject (container recreated under another name) shows as
   resolved + new — which is what actually happened to that subject.
3. **Hash of the title.** Rejected: titles carry volatile numbers
   (`({age}h …)`), the same reason title matching was rejected in the trend
   contract.

**Proposed: option 2**, with rules:

- Format `CONTROL_ID:subject`; `:` is not used inside control ids, so the
  control id is always recoverable (`id.split(':', 1)[0]`).
- The subject is the object the check itself names in the title (container
  name, unit name, directory path, selector, subdomain, cookie name), taken
  verbatim — no normalisation that could merge two subjects.
- Values that change between runs (ages, sizes, counts, percentages) are
  never part of the id.

## Proposed contract

1. **Format.** `PREFIX-GROUP-NNN`, uppercase, three-digit number;
   `CONTROL_ID:subject` for kind C. Proposed prefixes (new): `F2B`
   (fail2ban), `FW` (firewall: ufw / nftables / iptables), `SQL`, `WEB`
   (`web_security_external`), `DCK` (docker), `SYS` (systemd), `BKP`
   (backup), `DNS`. Existing `KRN`, `NGX`, `SSH` unchanged.
2. **Coverage.** Every finding of kind A–D in the five modules gets an id.
   Kind E may stay without one.
3. **Stability (the actual promise).** Once released, an id is never
   renamed, renumbered or reused for a different control. A removed control
   retires its number. If a control's meaning changes materially, it gets a
   new number. Rationale: the trend layer diffs by id — a rename reads as
   "fixed + new problem".
4. **Catalogue.** Every id is listed in `docs/checks/finding_ids.md` (one
   table per module: id, severity, control, title) — the same role the
   existing per-check catalogues play for `KRN`/`NGX`/`SSH`.
5. **Tests.**
   - per module: each finding of kind A–D carries an id, and the ids match
     the catalogue;
   - a project-wide guard: every id emitted by the in-scope modules matches
     `^[A-Z]{2,4}(-[A-Z]+)?-\d{3}(:.+)?$` and is listed in the catalogue;
   - kind C: two subjects → two distinct ids; fixing one subject → the
     trend reports it resolved and the other persisting.
6. **No behaviour change** besides the added `id` key: severities, titles,
   details, ordering unchanged (existing tests must pass untouched).

## Out of scope

- Log-based checks (events, not state).
- Changing existing `KRN`/`NGX`/`SSH` ids.
- Retrofitting ids into already saved reports.
