# Web output escaping — stored XSS fix contract proposal

Status: **DRAFT** (2026-10-08). Roadmap 1.0 proposed item 2f. Claude owns
the Web implementation; GPT/Codex drafted this contract after Claude's
browser reproduction. Requires Claude's independent review and USER scope/
contract approval before RED/GREEN.

## Evidence and boundary

`web/static/index.html` has 29 `innerHTML`/`insertAdjacentHTML` assignments.
`renderResult()` interpolates finding `title`, `detail`, `error`, section
version, host and metadata into HTML; `renderAnalysis()` interpolates AI
text; history, targets, presets and settings views also use HTML templates.
Remote check output is not trusted HTML. A scanned site's `Set-Cookie`
header can reach finding detail. Claude reproduced execution of an image
`onerror` handler from a saved report in the browser with a temporary HOME
(`.ai/FINDINGS.md`, 2026-10-08). The same page has access to the NetAudit
origin and authenticated API requests.

## Required behavior

1. Treat every string from report data, remote command output, API responses,
   stored settings/presets/history, user-entered targets and AI responses as
   untrusted text. Render it via `textContent`/DOM node APIs or one shared
   escape function before insertion into an HTML template. Escape at least
   `& < > " '`. Preserve whitespace in `pre` without interpreting markup.
2. Audit every existing `innerHTML` and `insertAdjacentHTML` sink, including
   nested template builders returned by `renderResult()`. Static markup and
   application-owned translations can remain HTML. Dynamic values in quoted
   attributes must be escaped for that context. Do not put untrusted values
   into tag names, CSS classes, inline styles, event handlers or URL schemes;
   use fixed mappings or DOM property setters with validation.
3. Keep report meaning, layout, localization, charts, buttons and API
   behavior. Render payloads visibly as text so an operator can inspect the
   evidence; do not silently delete hostile-looking text from saved reports.
   Keep the previous security redaction of secrets before UI output.
4. New 2c Trends UI follows the same rule from its first implementation.
   The 2f fix is reviewed and integrated before 2c ships, so new trend fields
   cannot reintroduce the sink.

## RED and verification

- A saved report with hostile `finding.title`, `finding.detail`, `error`,
  section version, host and metadata displays the literal strings; no
  element/handler from them enters the DOM. Include `<img ... onerror=...>`,
  quote-breaking attribute text, and an ampersand/angle-bracket round trip.
- AI `summary`, `problems`, `recommendations` and error/raw fallbacks receive
  the same treatment; preset/target/history labels are covered at their
  display sites.
- Browser regression: opening the saved report and running the relevant
  result/AI views leaves a sentinel unchanged, while the escaped payload is
  visible. Use an isolated HOME and a local server; no external scan or key.
- A repeatable source/test guard inventories the HTML sinks and verifies that
  newly introduced dynamic values are handled safely. It should fail on an
  intentionally reintroduced raw interpolation; do not rely on a test that
  merely checks the presence of an `esc()` function.
- Run Web tests, full pytest, Ruff E9/F, Bandit and a final manual browser
  check. Reviewer independently inspects the diff for missed interpolation
  paths and dangerous attribute contexts.

## Out of scope

Changing report storage, the authentication model, external scan behavior,
or adding a large client framework/sanitizer dependency. Content Security
Policy may be considered separately as defense in depth; it does not replace
correct output encoding.
