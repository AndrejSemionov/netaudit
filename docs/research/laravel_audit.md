# Laravel section: research and draft contract

Status: contract approved, MODE: MANUAL (USER 2026-11-23: «Да, research»,
then «Утверждаю, делайте» with the recommended answers: PR 1 = L1 + L2 +
L3 + L5, PR 2 = L4 as a separate `laravel_server`, the live check on the
CI stand only). Researcher and executor: Claude. Reviewer: GPT/Codex.
Base: `main` @ `b5f00cf`. Dates and versions are as of 2026-11-23.

USER asked for a Laravel check like the WordPress one. The difference
matters: a WordPress site shows its version and plugins to any visitor; a
Laravel site does not. From outside we can see **misconfigurations**; the
**versions** of Laravel and its packages live in `composer.lock` on the
server, so known vulnerabilities come from an SSH check — or from outside
only when the site exposes `composer.lock` by mistake.

## 1. What NetAudit has today (`b5f00cf`)

- `cve_audit` (SSH) reads **one** `composer.lock` — the first found under
  `/var/www` and `/home`, `head -1` (`netaudit_pkg/checks/cve_audit.py:401–454`)
  — and checks its packages against OSV (`query_osv`, `:598`), which has
  Laravel data (§3). A server with several projects is checked for one.
- `web_security_external` (URL) probes `/.env` among `SENSITIVE_PATHS`
  (`server_security.py:1481`) and counts a path as exposed on **HTTP 200
  alone** (`:1683`); the verbose-error check looks for `whoops`/`laravel`
  in an error page (`:1593–1609`).
- From the WordPress section (#59, #61), reusable as is: the safe fetch
  (`wordpress.py:116`, redirects checked per hop, body cap, retry once),
  `_answered` (5xx/429 are not answers, `:186`), the HTTPS / redirect /
  certificate / header checks (`:205–225`), the score and verdict
  (`:688–694`), the tab view (`web/static/index.html:1771`).

## 2. Facts from the Laravel and package sources

Read from GitHub (`laravel/laravel` 12.x, `laravel/framework` 12.x,
`spatie/laravel-ignition` main, `laravel/telescope` 5.x, `laravel/horizon`
5.x, `barryvdh/laravel-debugbar` master).

| Fact | Where | What it means for a check from outside |
|---|---|---|
| Session cookie `Str::slug(APP_NAME).'-session'` (older versions `…_session`) | skeleton `config/session.php:130–133` | a cookie ending in `-session`/`_session` is a hint, its name depends on the app |
| `XSRF-TOKEN` cookie set on web responses | `VerifyCsrfToken.php:88–89, 204` | the strongest passive sign of Laravel |
| Debug page only for non-HTTP exceptions (500) when `app.debug`; 404/405 render the error views | `Foundation/Exceptions/Handler.php:849–858, 933–937` | `APP_DEBUG` **cannot be told from a normal page** or a 404; only from a tool below, or an error a visitor already sees |
| JSON error bodies carry `exception` and `trace` when debug | `Handler.php:1031–1036` | same: visible only on an error |
| Skeleton `.env.example`: `APP_ENV=local`, `APP_DEBUG=true` | `laravel/laravel` 12.x `.env.example:2,4` | a copied example on a server turns debug on — a common real mistake |
| Skeleton has no Ignition, Telescope, Horizon or Debugbar | skeleton `composer.json` | these are added by the developer; finding one open is a finding, not finding one is no proof |
| Ignition `GET /_ignition/health-check` answers only when `app.debug` **and** (explicit `IGNITION_ENABLE_RUNNABLE_SOLUTIONS`, or `APP_ENV` local/development); else 404 | `ignition-routes.php`, `RunnableSolutionsGuard::check()` | a 200 JSON `{"can_execute_commands": true/false}` proves the route is open, so debug mode with runnable solutions on - high; its boolean is the result of an internal diagnostic, and running a solution (a POST) is never tried, so neither running code nor an old CVE is claimed (review pass 1) |
| Telescope at `/telescope`; outside `local` only the `viewTelescope` gate | `TelescopeApplicationServiceProvider.php:25–31`, `config/telescope.php:45` | the UI answering a visitor = requests, queries and data open |
| Horizon at `/horizon`; default auth `environment('local')` | `Horizon.php:81–84` | same |
| Debugbar: on when `debugbar.enabled`, or else `app.debug`, never in `production`/`testing` unless forced; injects `<!-- Laravel Debugbar Widget -->` | `LaravelDebugbar.php:566–592, 781` | the marker in the home page = debug on and the bar shown to visitors |

## 3. Vulnerability and support data (requests made 2026-11-23)

| Source | Covers | Access | Terms | Verdict |
|---|---|---|---|---|
| OSV `querybatch`, ecosystem `Packagist` | Composer packages (data from the GitHub Advisory Database) | free, no key, already used by `cve_audit` | GHSA data CC BY 4.0 (attribution) | **use** |
| Packagist security advisories API (what `composer audit` reads) | the same packages, GitHub + FriendsOfPHP | free, no key, one GET for many packages | FriendsOfPHP data Unlicense, GHSA CC BY 4.0 | second source, if OSV is short |
| endoflife.date `api/laravel.json` | Laravel releases and their security-support end | free, no key | MIT | **use** for "this Laravel no longer gets security fixes" |

Evidence: OSV `laravel/framework` 5.5.0 → 18, 8.0.0 → 13, 11.0.0 → 7
vulnerabilities; `livewire/livewire` 3.0.0 → 3; a batch of three
(`laravel/framework` 11.0.0, `guzzlehttp/guzzle` 7.4.0, `facade/ignition`
2.5.1) → 7, 14, 1. Packagist: `laravel/framework` 31 advisories,
`livewire/livewire` 6, with affected versions, CVE, severity, link.
endoflife.date: 13 (security until 2028-03-17), 12 (until 2027-02-24),
**11 ended 2026-03-12**, 10 and older ended — a site on Laravel 11 today
gets no security fixes.

## 4. From outside (URL): what can be checked

- **Is it Laravel:** the `XSRF-TOKEN` cookie, a `…-session`/`…_session`
  cookie next to it. Without them the check says "no sign of Laravel" (as
  `not_wp`), with the same rule for a server that did not answer.
- **`.env` public:** `GET /.env` counts only when the body has
  `APP_KEY=` or `DB_PASSWORD=` lines (a soft-404 page does not); the
  content is never kept. Critical: the app key and database password.
- **Ignition open:** `GET /_ignition/health-check` → 200 JSON with
  `can_execute_commands` true or false → high (the route open: debug on,
  runnable solutions on; running one not tried); another value → not
  checked.
- **Debug bar shown:** the home page has the Debugbar marker → high.
- **Telescope / Horizon open:** `/telescope`, `/horizon` answer with their
  UI (title/markers in the HTML) → high; 401/403/404 → fine.
- **Logs and project files public** (a webroot set to the project folder
  instead of `public/`): `storage/logs/laravel.log` (log lines),
  `composer.json`/`composer.lock` (JSON with `packages`),
  `vendor/composer/installed.json`, `.git/config` — content-checked.
- **Versions from a public `composer.lock` or `installed.json`:** the only
  way to name vulnerabilities from outside; otherwise "not visible from
  outside". `installed.json` names what is installed, the lock what was
  locked: the installed versions are used, a disagreement is "not
  checked", a lock alone is said to be locked versions. Read up to 4 MB (a
  real lock is larger than a page); larger → public, not read. A name or
  version not in Composer's format is not used and is a gap (the name is
  checked in linear time and bounded in length). A name listed with two
  versions is not compared and is a gap; an exact repeat is one package; a
  file with nothing to compare says so. The two files are said to agree
  only for the packages both name, and only when both were read in full.
  OSV's batch is asked directly and read strictly: only `{}` or
  `{"vulns": [{"id": ...}]}` is an answer; any other shape, a page token or
  a count that differs is no answer — the SSH check's `cve_audit.query_osv`
  and its cache stay as they are. A fix is named only from the range the
  version is in (review pass 1-2).
- **The session cookie's flags** (Secure, HttpOnly, SameSite) and the
  shared HTTPS / redirect / certificate / header items.
- GET only; no POST (`execute-solution` is never called).

## 5. On the server (SSH)

- Find **every** Laravel project: `artisan` next to a `composer.json` that
  requires `laravel/framework`, under `/var/www`, `/home`, `/srv`, bounded
  depth and count, `vendor/` excluded — not `head -1`.
- Per project: `laravel/framework` version from `composer.lock` → support
  status (endoflife.date); all locked packages → OSV (the existing
  `query_osv` path).
- `.env`: its mode and owner (readable by others → high); **only** the
  values of `APP_DEBUG` and `APP_ENV` are read (a `grep` of those two
  keys) — never `APP_KEY`, passwords or other lines; `APP_DEBUG=true` →
  high, `APP_ENV=local` → medium.
- `storage/` and `bootstrap/cache` writable by others (777) → medium.
- Nothing is run in the project (no `php artisan`): reading files only.

## 6. Result model and the tab

- The same outcomes, verdicts, `checked` items and score as WordPress;
  "not checked" never reads as "fine".
- Ids `LV-ENV-001`, `LV-IGN-001`, `LV-DBG-001`, `LV-TEL-001`,
  `LV-HRZ-001`, `LV-FILE-00x`, `LV-VULN-001:<package>:<id>`,
  `LV-EOL-001`, `LV-SRV-…`.
- A **Laravel tab** next to WordPress: site address, Check, the same view;
  for SSH a second form (a host from the saved hosts) or the Audit tab.
- Shared code: the safe fetch, `_answered`, transport/header checks, score
  and verdict move from `wordpress.py` into a shared module used by both;
  the WordPress tests stay as they are and guard the move.

## 7. E2E stand in CI

`php:8.3-cli` + `composer create-project laravel/laravel` (CI has network):
one site served from `public/` with `APP_DEBUG=false` (clean), one served
from the project folder with the example `.env` (`APP_DEBUG=true`,
`APP_ENV=local`) and Telescope or Debugbar installed — ground truth for
§4, like the WordPress stand. The SSH part reuses the SSH stand with a
Laravel project copied in.

## 8. Not checked yet

- No live Laravel site was probed (USER: the CI stand only).
- Telescope (`<title>Telescope`, `<div id="telescope"`), Horizon
  (`<title>Horizon`, `<div id="horizon"`), the Debugbar marker and
  Ignition's `health-check` route are read from the package sources
  (2026-11-23); they meet a running Laravel on the CI stand (§7), first in
  the PR's CI run - there is no PHP or Docker on the development machine.
- The per-package Packagist API vs OSV coverage gap: UNKNOWN, measured on
  the stand's lock file.

## 9. Draft contract (for USER approval)

- **L1. Category and tab `laravel`** (RU/EN), like WordPress.
- **L2. `laravel_external`** (PASSIVE, GET only): §4; shared items.
- **L3. Versions from a public `composer.lock` / `installed.json`** → OSV,
  endoflife.date, attribution; as refined in §4 by review pass 1.
- **L4. `laravel_server`** (SSH, READ_ONLY): §5.
- **L5. Shared module** for the WordPress and Laravel web probes.
- **L6. Tests**: RED/GREEN on fixtures; E2E stand (§7).

Questions for USER, with the recommended answer first:
1. Order. Recommended: PR 1 = L1 + L2 + L3 + L5 (the tab works by URL),
   PR 2 = L4 (SSH). Alternative: both at once.
2. SSH part: a separate `laravel_server` check (recommended), or extend
   `cve_audit` to read every project.
3. Live check: name a Laravel site you own for a few GET requests, or rely
   on the CI stand only.
