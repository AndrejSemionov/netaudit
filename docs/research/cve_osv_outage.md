# cve_audit: an unanswered OSV query is not "no known CVEs" (A2 fix F1)

Status: stage A, MODE: AUTONOMOUS. Implementer: Claude. Reviewer: GPT/Codex.
Source: `docs/research/result_reliability_audit.md` RA-02 (HIGH) and RA-10
(LOW), branch `docs/a2-result-reliability`.

## Evidence (`main` @ `ea68f97`)

- **RA-02.** `query_osv()` catches `httpx.HTTPError` — connection error,
  timeout, and HTTP 4xx/5xx via `raise_for_status()` — and sets every package
  it was about to query to `[]`. `check_cve_audit()` reads `[]` as "OSV
  answered, no vulnerabilities" and reports severity `ok`, "no known CVEs
  found". Reproduced: `httpx.post` raising `ConnectError` →
  `({'nginx': []}, set())`. `tests/test_cve_audit.py::
  test_query_osv_network_failure_does_not_raise` pins exactly this.
  A `200` whose body is not JSON raises `ValueError` from `resp.json()`, which
  is not caught: the whole check ends as an exception.
- **RA-10.** When nothing is detected the result is `packages: []`, all
  counters 0, no `error`. The running kernel (`uname -r`) is always collected
  on a reachable Linux host, so an empty list means the collection itself
  failed.

## Design

- **D1.** A batch query that fails (`httpx.HTTPError`, or a body that is not
  JSON) puts every package of that batch into `collection_errors`, the
  existing "asked, got no answer" channel. They are not cached and not set in
  the result dict. Packages answered from the cache keep their cached answer.
  `check_cve_audit()` already turns `collection_errors` into an `info` finding
  "CVE matching could not be completed … no answer received from the
  vulnerability database (this does NOT mean no CVEs were found)",
  `requires_manual_verification`, counted as `collection_error`.
- **D2.** No package detected → the same result shape plus
  `error: "no packages detected, not even the running kernel (uname -r) —
  package collection failed; this is not a clean result"`.

Unchanged: ecosystem resolution, the short-batch handling, caching of real
answers, `fetch_vuln_details()`, finding texts and severities otherwise.

## Tests (RED first)

1. `query_osv` with `httpx.post` raising `HTTPError`: no package in the
   result dict, all in `collection_errors` (replaces
   `test_query_osv_network_failure_does_not_raise`, which pinned the bug).
2. Same with a `200` whose `json()` raises `ValueError`.
3. A cached package plus an uncached one, OSV down: the cached one keeps its
   answer, only the uncached one is a collection error; nothing new cached.
4. Full flow, OSV down: no `ok` finding, `collection_error` equals the number
   of queried packages.
5. Full flow, nothing detected: `error` set, `packages == []`, summary keys
   unchanged.
