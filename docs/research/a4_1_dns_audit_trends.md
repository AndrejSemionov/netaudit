# `dns_audit` in trends; a collection gap is never `resolved` (A4.1)

Status: USER approved as a separate task (2026-10-10: «Да, автономно»).
Implementer: Claude. Reviewer: GPT/Codex. Extends trend layer v1.2 (2a,
`trend_layer_v1_2_web_ai.md`).

## Evidence

- **E1. `dns_audit` is never trended.** Its result is
  `{'domain', 'sections': {spf: [findings], dkim: [...], dmarc, dnssec,
  dangling_cname, discovered_services}, 'summary', 'collection_failures'}`:
  each section is a list of findings. `trends._scoped_findings()` accepts only
  the `server_audit` shape (`{name: {'findings': [...]}}`) and returns `None`,
  so `_snapshot()` returns `None`. Live, `main` `6203c75`, temporary HOME: two
  runs `netaudit run ssl http dns_audit --url https://github.com --domain
  github.com` save reports with `execution_context.dns_audit = {'domain':
  'github.com'}`, yet `snapshots_from_report()` → `[]` and
  `trends.list_units()` → `[]`. `domain` is an identity key, and task 4 gave
  `dns_audit` findings stable ids for trends.
- **E2. A naive fix would claim false remediation.** A DNS collection failure
  (SERVFAIL, timeout, tool error) is an `info` finding without
  `requires_manual_verification` ("could not determine SPF status", …;
  `docs/checks/dns_audit.md` §5). The trend layer counts only *problem*
  findings (`critical`…`low`) with that flag, so after an SPF timeout the
  previous run's SPF id would be `resolved`.
- **E3. The same hole exists today for flat checks.** These checks already
  report a collection gap as `info` + `requires_manual_verification=True`, which
  the trend layer ignores:
  - `web_security_external`: "could not test TLSv1/TLSv1.1" next to
    `WEB-TLS-001`. A run that could not test TLS turns the previous
    `WEB-TLS-001` into `resolved`;
  - `cve_audit` ("CVE matching could not be completed for this package"),
    `sqli` ("the page could not be fetched"), `log_discovery_audit` ("could not
    determine whether … exists").
  Contract v1.2 states the intent ("a could-not-determine finding means that
  scope's missing ids were not evaluated, not fixed"), but its rule counted
  problem severities only.

## Design

1. **Sections of either shape** (`_scoped_findings()`). A section value is a
   dict (its `findings` list, `[]` if absent, as today) or a list of findings
   (`dns_audit`). Any other value means the result has no recognised shape
   (`None`, unchanged). Top-level `findings` still win over `sections`.
2. **A collection gap marks its scope as not evaluated.** Per scope the
   snapshot keeps `ids`, `unverified` (problem findings with the flag, as in
   v1.2) and a new `gaps`: non-problem findings (`info`, `ok`) with
   `requires_manual_verification: true`. `_was_evaluated()` is true only if the
   scope is present and has `unverified == 0` **and** `gaps == 0`. Scopes are
   internal: the public point keeps its fields and meanings — `unverified`
   still counts problem findings only, and `counts` never include `info`.
   `gaps` takes part in the v1.1 in-report ambiguity comparison (through
   `scopes`).
3. **`dns_audit` flags its collection failures.** Each of its seven
   collection-failure findings (all `info`) gets
   `requires_manual_verification=True`. Severity, title, detail, id (none) and
   `collection_failures` stay the same. §5 of `docs/checks/dns_audit.md`
   rejected the flag together with a `high`/`medium` severity, because of the
   colored pill. With `info` that objection does not apply, and the flag is
   how other checks already mark a collection gap. §5 gets a short addendum.
4. **Effect on other checks — conservative only.** For the checks in E3, an id
   that disappears in a run with a collection gap moves from `resolved` to
   `not_evaluated` (for a flat check: every missing id, as in v1.2 rule 3).
   `new`, `persisting`, counts and points do not change. No check gains or loses a
   trend.

## Known limitation (not changed here)

Trend units are keyed by identity params only. A non-identity param that
changes coverage changes the scope's content: if `subdomains_to_check` drops
`blog`, the previous dangling-CNAME id for `blog` becomes `resolved`. The same
applies to other checks (e.g. `backup_check` `directory`). Recorded in
`FINDINGS.md` as a trend-layer issue; out of A4.1 scope.

## Tests (RED first)

1. A `dns_audit` report gives one snapshot per domain: counts over all
   sections, ids from all sections, one scope per section.
2. Run 1: an SPF problem with an id and a DMARC problem with an id. Run 2: SPF
   timeout (`info` + flag) and DMARC fixed. The SPF id is `not_evaluated`; the
   DMARC id is `resolved`. The point's `unverified` is 0.
3. Flat check (`web_security_external` shape): `WEB-TLS-001` in run 1; run 2
   has only "could not test …" (`info` + flag) → `WEB-TLS-001` is
   `not_evaluated`, not `resolved`.
4. An `info` finding **without** the flag does not block `resolved`.
5. A section whose value is neither a dict nor a list → no snapshot
   (unchanged).
6. `check_dns_audit()` with a broken resolver: every `info` finding has
   `requires_manual_verification=True`; with a healthy resolver no finding has
   it.
7. Two instances of one unit that differ only in a gap → ambiguous.
8. CLI: two saved `dns_audit` reports → `netaudit trend dns_audit <domain>`
   prints both runs.

Live check: two runs `netaudit run dns_audit --domain github.com` with a
temporary HOME, then `netaudit trend dns_audit github.com`.
