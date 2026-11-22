# WordPress section: research and draft contract

Status: research, MODE: MANUAL (USER 2026-11-22: «Да, research»). The
contract below is a draft for USER approval; no RED/GREEN before that.
Researcher: Claude. Reviewer: GPT/Codex.
Base: `main` @ `5427d0f`. Dates and versions below are as of 2026-11-22.

USER asked for a separate WordPress menu, like the WordPress check on
`chornuy7.tech`: it checks a WordPress site and says which vulnerabilities
it has. In NetAudit that is a `wordpress` category (its own group in the Web
check list and in `netaudit list`) with WordPress checks behind it.

## 1. The reference: `chornuy7.tech/wordpress-security-check`

Read from the public page and its script only (the form was not submitted,
its API was not called).

- Input: a site address. "I only check what any visitor of the site can
  see": no login, no password guessing, about 20 seconds.
- Checks: does the site open and where does it lead; WordPress version
  against the latest; plugins visible from outside (table: version, latest,
  outdated, known vulnerabilities); exposed admin usernames; public service
  files and backups.
- Result: verdict `ok | warn | danger | not_wp | unreachable`; each finding
  has a title, detail and fix. Red findings are hidden behind "get the full
  report in Telegram" (lead capture).
- Free monitoring: the site is checked once a day, an alert goes to Telegram.
- Its own FAQ: malware inside the site "needs access to the files and the
  database", which the external check does not have.

## 2. What NetAudit has today (`5427d0f`)

- `cve_audit` (SSH): finds the first `wp-includes` under `/var/www`
  (maxdepth 3, `head -1`), reads `$wp_version` from `version.php` and queries
  OSV with `ecosystem: 'WordPress'` (`netaudit_pkg/checks/cve_audit.py:382–396`).
- **W0, false clean (FACT, recorded in FINDINGS).** OSV has no WordPress
  data: `{"ecosystem":"WordPress","name":"wordpress"}` at `4.7.0` → `200 {}`;
  a made-up ecosystem → `400 invalid ecosystem`, so the name is accepted but
  `ecosystems.txt` (48 lines) has no WordPress. `wpackagist-plugin/*` and
  `johnpbloch/wordpress-core` under `Packagist` → `{}` as well, while the
  control `laravel/framework 5.5.0` → 18 vulnerabilities. The empty answer
  becomes `severity: 'ok'`, "no known CVEs found" (`cve_audit.py:878–882`)
  for any WordPress version. wordpress.org says `"4.7": "insecure"`.
- `web_security_external` (URL): `SENSITIVE_PATHS` includes
  `/wp-config.php.bak` and `/wp-config.php~` (`server_security.py:1480`).
- Nothing detects WordPress, plugins, themes or users from outside; there is
  no `wordpress` category.
- Plumbing to reuse: `register(id, label, category, params, required_tools,
  description, risk_level)` (`registry.py:228`); the Web groups checks by
  `category` (`web/static/index.html:892`) with labels `cat.*` in
  `web/static/i18n.js:20–26, 362–368`; a third-party API key already lives
  in settings and is redacted by the settings API (`hibp_api_key`,
  `web/app.py:350`); stable ids via `findings.subject_id()`; plan runs and
  Telegram alerts via `setup-timer` and `run --notify --job`.

## 3. Vulnerability data

| Source | Covers | Access | Terms (as read) | Verdict |
|---|---|---|---|---|
| OSV | nothing for WordPress (§2, W0) | free, no key | — | not usable |
| `api.wordpress.org/core/stable-check/1.0/` | core: every version → `latest`/`outdated`/`insecure` | free, no key | official WordPress.org API | **use for core** |
| `api.wordpress.org/plugins/info/1.2/` | latest plugin version | free, no key | official | **use for "outdated"** |
| Wordfence Intelligence v3 | core, plugins, themes; CVE, CVSS, affected ranges, patched versions, remediation | free account key, `Authorization: Bearer`; full feed only, no per-slug query; 429 on too many requests | "free for personal and commercial use"; licence allows to reproduce, sublicense and distribute with Defiant's copyright notice, the licence and a link to the record; MITRE notice for CVE text; the key must not be shared with a third party | **use for vulnerabilities, key per user** |
| WPScan API | core, plugins, themes | token; free tier 25 calls/day | free tier non-commercial; "API vulnerability data caching is not permitted"; integrating the data into a service needs Enterprise | excluded |
| Patchstack | core, plugins, themes | custom pricing, on request | licence only for the customer's own operations; no third-party use | excluded |

Evidence (all requests made 2026-11-22):
- stable-check: 1009 versions, `insecure` 984, `outdated` 24, `latest` 1
  (`7.1.5`); `"4.7"`, `"6.0"`, `"6.8.3"`, `"6.9"` → `insecure`; the key for
  4.7.0 is `"4.7"` (a trailing `.0` must be dropped before lookup).
- version-check 1.7: first offer `upgrade 7.1.5`.
- plugins/info: `contact-form-7` → `version 6.2.5`; unknown slug → 404
  `{"error":"Plugin not found."}` (premium plugins such as WPML are not on
  wordpress.org: "latest" unknown, not "up to date").
- Wordfence: v2 production → HTTP 410 (v1/v2 disabled 2026-03-09 per their
  notice); v3 production without a key → 401 JSON. Feed size: UNKNOWN (needs
  a key; an account is the USER's to create). Docs:
  `wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/`,
  terms `wordfence.com/wordfence-intelligence-terms-and-conditions/` (updated
  2026-01-26).
- WPScan/Patchstack: their pricing, API and terms pages (wpscan.com/api,
  /pricing, /terms; docs.patchstack.com threat-intelligence API,
  patchstack.com/terms-and-conditions §3).

Consequences: the Wordfence feed is downloaded whole and cached locally
(`~/.netaudit`, refreshed at most daily); without a key the check still
reports core status and outdated plugins, and says plugin vulnerabilities
were **not checked** — never "none found". The key is a secret: settings
redaction like `hibp_api_key`, never in reports, logs or the AI prompt.

## 4. Signals from outside (URL), from WordPress core source

Source: `github.com/WordPress/WordPress` master (`$wp_version =
'7.2-RC2-65738'`). Not yet seen on a live site (§7).

| Signal | Where in core | What it gives | Limits |
|---|---|---|---|
| `Link: <…/wp-json/>; rel="https://api.w.org/"`, `<link rel="https://api.w.org/">` | `default-filters.php:338–339` | WordPress detected | removable by a plugin or theme |
| `/wp-json/` root JSON with `namespaces` | REST API | WordPress detected, plugin namespaces | REST can be restricted |
| `<meta name="generator" content="WordPress X">` | `default-filters.php:367` (`wp_generator`) | core version | often removed |
| feed `<generator>https://wordpress.org/?v=X</generator>` | `general-template.php:5571` | core version | removed together with the meta in most hardening plugins: HYPOTHESIS |
| `readme.html` | `readme.html` | nothing: no WordPress version in it any more, only PHP/MySQL requirements | — |
| `/wp-content/plugins/<slug>/` in page HTML | — | visible plugin slugs | only plugins that load assets on that page |
| plugin `generator` meta, `readme.txt` `Stable tag`, `?ver=` on assets | — | plugin version | each one is a HYPOTHESIS until checked on the stand; a wrong version is worse than "unknown" |
| `/wp-json/wp/v2/users` | `class-wp-rest-users-controller.php:330–331`: without `list_users` the list is limited to users with published posts | author slugs | admin is exposed only if the admin has published posts |
| `/wp-sitemap-users-1.xml` | `class-wp-sitemaps-users.php:157` (`has_published_posts`) | author slugs | sitemaps can be off |
| `/?author=N` → `/author/<nicename>/` | `canonical.php:333–341` (only an author with a published post) | author slug | redirect can be blocked |
| `/xmlrpc.php` (GET only) | — | XML-RPC enabled | text of the GET answer: HYPOTHESIS; no POST (`system.multicall` is an active probe) |
| `debug.log`, backups, `uploads/` listing | — | public files | overlaps `web_security_external`: one list, not two |

Reported names are author slugs, not proven logins (`user_nicename` is
derived from the login by default: HYPOTHESIS). The finding says "author
usernames are public", not "admin login exposed", unless shown.

## 5. On the server (SSH)

Facts gathered:
- core checksums: `api.wordpress.org/core/checksums/1.0/?version=7.1.5&locale=en_US`
  → md5 for 3783 files; `ru_RU` → 3872 files, 3 of them differ from `en_US`,
  so the locale of the install must be used.
- plugin checksums: `downloads.wordpress.org/plugin-checksums/contact-form-7/6.2.5.json`
  → md5 and sha256 for 218 files.

Design notes:
- Find every install (`*/wp-includes/version.php` under `/var/www`, `/home`,
  `/srv`, bounded depth and count), not `head -1`.
- Versions by reading files only: `version.php`; plugin headers in
  `wp-content/plugins/<slug>/*.php` (`Version:`); theme `style.css`.
- Integrity: compare `md5sum` of core (and wordpress.org plugin) files with
  the checksum APIs; extra `.php` files in core directories and any `.php`
  under `wp-content/uploads` are findings.
- `wp-config.php`: mode/owner, and only the values of named constants
  (`WP_DEBUG`, `WP_DEBUG_DISPLAY`, `DISALLOW_FILE_EDIT`). Its content never
  leaves the server: it holds the database password and salts.
- No `wp-cli` in this task: it runs the site's own PHP (`wp-config.php`,
  and plugins unless skipped) as the audit user; on a hacked site that runs
  the attacker's code, often under sudo. Admin users need the database (and
  its password): out of scope.

## 6. Result model

Follows the project's outcomes (`result_reliability_audit.md`): problem /
ok within the check / not enough data / not applicable / error.

- Site does not answer → `error`, no score. Not WordPress → not applicable
  (`not_wp`), not "ok".
- Core version hidden → "core version unknown", never "core up to date".
- Plugin vulnerabilities without a Wordfence key or with a failed feed
  download → "not checked" with the reason; a stale cache says its age.
- Only visible plugins are judged; the report says so.
- Proposed ids: `WP-CORE-001` insecure core, `WP-CORE-002` outdated core,
  `WP-PLG-001:<slug>` outdated plugin, `WP-VULN-001:<slug>:<wordfence-id>`
  known vulnerability (severity from the CVSS rating), `WP-USR-001` public
  author usernames, `WP-XMLRPC-001`, `WP-FILE-…` public files,
  `WP-SRV-…` server-side findings.

## 7. Not checked yet

- No live WordPress site was probed: the request to USER's site was refused
  by the session's access rules (ownership not confirmed). Ground truth for
  tests: the official `wordpress` Docker image on a CI stand, like `e2e-ssh`,
  with known plugin versions, hidden-version and REST-restricted variants.
- Wordfence feed size and real-world 429 limit: UNKNOWN without a key.

## 8. Draft contract (for USER approval)

- **C1. Category `wordpress`.** `cat.wordpress` (RU «WordPress», EN
  "WordPress"), shown as its own group in the Web check list and in
  `netaudit list`; RU texts covered by `tests/test_i18n_checks_ru.py`.
- **C1a. WordPress tab in the Web** (USER 2026-11-22: «в web окно для ввода
  сайта и он проверит», like the reference). A top-level tab «WordPress»
  next to «Аудит»: one field «Адрес сайта» (accepts `site.com` and adds
  `https://`; other schemes refused, as the `url` format already does) and
  a «Проверить» button. It runs `wordpress_external` through the existing
  `/api/stream/start` (no new API); the report is saved to history and
  trends like any run. The result view:
  - a verdict banner: OK / есть замечания / опасно / не WordPress / сайт не
    открывается;
  - "what was checked": site opens, core version, plugins, usernames,
    public files — each with its own status, including "not checked" and
    why (for example no Wordfence key);
  - findings with title, detail and how to fix — the full report, nothing
    hidden behind a contact form;
  - a plugins table: plugin, version, latest, status, vulnerabilities, with
    the note that only plugins visible from outside are listed.
  The tab is for the NetAudit operator, behind the existing Web login. A
  public page where anyone checks any site (the reference's lead form) is
  not in this contract: it would make the NetAudit server an open scanner.
- **C2. `wordpress_external`** (PASSIVE, param `url`, GET requests only):
  §4 signals; core status from stable-check, outdated plugins from
  plugins/info; one sensitive-path list shared with `web_security_external`;
  result model §6.
- **C3. Known vulnerabilities via Wordfence v3**: optional setting
  `wordfence_api_key` (secret), feed cached and refreshed at most daily,
  attribution shown with each vulnerability; without a key — "not checked".
- **C4. `wordpress_server`** (SSH, READ_ONLY): §5, every install, no
  `wp-cli`, no database.
- **C5. W0**: `cve_audit` stops reporting WordPress as "no known CVEs
  found" (either drop WordPress from it and point to the new check, or use
  stable-check there) — USER picks.
- **C6. Tests**: RED unit tests on recorded fixtures without network; E2E
  stand with the official `wordpress` image in GitHub Actions.
- Monitoring needs no new code: `setup-timer` + `run --notify --job`.

Questions for USER, with the recommended answer first:
1. Wordfence needs a free wordfence.com account and key per NetAudit user.
   Recommended: yes, an optional key in Settings; without it the tab says
   plugin vulnerabilities were not checked. Alternative: no plugin
   vulnerabilities for now.
2. Order. Recommended: PR 1 = C1 + C1a + C2 + C5 (the tab works, core
   status and outdated plugins), PR 2 = C3 (vulnerabilities), PR 3 = C4
   (SSH). Alternative: everything in one PR.
3. W0. Recommended: `cve_audit` takes core status from stable-check (one
   shared function with C2), so SSH users keep a real answer. Alternative:
   drop WordPress from `cve_audit`.
4. Live check. Recommended: the CI stand only; USER tries the tab on own
   sites after merge. Alternative: name a site you own and allow about ten
   GET requests to it now.
