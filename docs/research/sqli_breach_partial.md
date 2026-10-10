# sql_injection and breach_check: missing data is not a clean result (A2 fix F5)

Status: stage A, MODE: AUTONOMOUS (USER: «Да, F1–F7 автономно»).
Implementer: Claude. Reviewer: GPT/Codex.
Source: `docs/research/result_reliability_audit.md` RA-05 (MEDIUM), RA-06
(LOW); technical findings AGREED by GPT/Codex (A2 pass 1).

## Evidence (`main` @ `ea68f97`)

- **RA-05.** `_fetch_html()` returns `None` when both curl and httpx fail.
  With no GET parameters in the URL, `check_sql_injection()` then reports
  `ok` "no input points found — injection is unlikely here".
  Reproduced: `check_sql_injection('https://does-not-exist.invalid/')` →
  `[{'severity': 'ok', 'title': 'no input points found', …}]`.
- **RA-06.** With two sources selected, one failing and the other answering
  "not found" gives `severity: 'ok'`, "not found in known breaches", counted
  as `clean`; the failure is only inside `sources`.

## Design

- **D1 `sql_injection`.** When the page could not be fetched, an `info`
  finding "the page could not be fetched — its forms were not inspected"
  (`requires_manual_verification`) is added, and the `ok` "no input points
  found" is **not** produced. GET parameters from the URL are still listed,
  and the authorization gate in front of sqlmap is unchanged (it does not
  depend on the page).
- **D2 `breach_check`.** No breach found, at least one source answered and at
  least one failed → `severity: 'info'`, summary "not found via
  <answered sources>; not checked: <source>: <error>", counted in a new
  summary key `partial` (the existing `exposed` / `clean` / `error` keys stay).
  All sources failed → `error`, as now. A breach found in any source → `high`,
  as now.

## Tests (RED first, no network)

1. `sql_injection`, page not fetched, no GET parameters → no `ok` finding, one
   `info` "could not be fetched".
2. Page not fetched, GET parameter present → `low` "input points found" plus
   the `info`.
3. Page fetched but empty, no parameters → `ok` (unchanged).
4. `breach_check`, XposedOrNot "not found" + HIBP 429 → `info`, counted as
   `partial`, `clean` is 0, the HIBP error is in the summary.
5. Both sources "not found" → `ok` (unchanged); both failed → `error`
   (unchanged).
