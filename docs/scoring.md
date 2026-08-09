# Hardening scoring contract

This document defines the data shape every **hardening module** (`nginx_hardening`,
`ssh_hardening`, `kernel_hardening`, `docker_hardening`, ...) must produce, and the
one function (`weighted_score()`) that turns it into a 0-100 score. It exists so that
adding the 5th hardening module is a matter of filling in `components`, not inventing
a new scoring formula.

## Two different kinds of number

NetAudit surfaces two categories of metric, and **they are never mixed or averaged
together implicitly**:

- **Native metrics** — a number an external tool already computed (systemd's
  `9.6/10` exposure level, Lynis's `78/100` hardening index). NetAudit reports these
  verbatim: no rescaling, no rounding beyond what the source itself gives, no
  reinterpretation. A native metric answers *"what did the external tool say?"*
- **Hardening scores** — a number NetAudit itself computes, by combining several
  weighted checks into one score. A hardening score answers *"how did NetAudit
  itself judge this set of security controls?"*

These live in separate JSON keys (`metrics` vs `hardening`) precisely so a future
reader — human or AI analysis — never has to guess which kind of number they're
looking at, or accidentally average a 0-10 scale with a 0-100 scale.

```json
{
  "service": "nginx.service",
  "metrics": {
    "systemd.exposure": { "value": 9.6, "scale": "0-10", "source": "systemd-analyze" },
    "lynis.hardening_index": { "value": 78, "scale": "0-100", "source": "lynis" }
  },
  "hardening": {
    "score": 83,
    "max": 100
  }
}
```

There is intentionally **no `overall.score`** yet. An aggregate across native
metrics and hardening scores of different scales and different meanings is
mathematically easy to produce and methodologically meaningless — `9.6 + 78` divided
by anything is not a real number. `overall.score` gets introduced only once there
are 4-5 real hardening modules and a documented weighting for combining them (a
follow-up to this document, not a shortcut around it).

## The Component contract

A hardening module doesn't return a bare integer. It returns a list of
**components** — the named sub-checks that were weighted together — so the result
is auditable (a user can see *why* nginx scored 83, not just that it did).

```json
{
  "score": 83,
  "max": 100,
  "components": [
    { "name": "tls",              "weight": 0.30, "score": 94,  "max": 100 },
    { "name": "security_headers", "weight": 0.25, "score": 80,  "max": 100 },
    { "name": "configuration",    "weight": 0.25, "score": 75,  "max": 100 },
    { "name": "filesystem",       "weight": 0.10, "score": 100, "max": 100 },
    { "name": "exposure",         "weight": 0.10, "score": 60,  "max": 100 }
  ]
}
```

- `name` — short identifier for the sub-check, stable across runs (used for
  before/after comparison and for the AI analysis to reference specific weak areas).
- `weight` — this component's share of the total score, `0 < weight <= 1`. All
  weights in one `components` list must sum to `1.0` (within floating-point
  tolerance, see below) - this is validated against the *original* weights, before
  any `applicable=False` redistribution (see below), so it always reflects whether
  the module's own weighting design is correct.
- `score` / `max` — the sub-check's own result, on whatever scale makes sense for
  that sub-check (doesn't have to be 0-100 - `weighted_score()` normalizes it).
- `applicable` (optional, default `true`) — set to `false` when the check couldn't
  evaluate this control (an SSH session that dropped mid-audit, or a control that
  doesn't apply to this build - e.g. an HTTP/2 config check when nginx was compiled
  without the `http_v2` module). See "Handling N/A" below.
- `reason` (optional) — human-readable explanation, used together with
  `applicable: false` to say *why* (e.g. `"module not compiled in"`).
- `finding_id` (optional) — links this component to the specific `Finding` (see
  `findings.py`) the same check produced for the same control, so a reader can look
  up *why* a component scored what it did. This is deliberately an explicit link
  (the calling module sets a string id on both), not an implicit one inferred by
  matching `Component.name` against `Finding.title`/`id` - implicit matching is a
  naming convention that silently breaks the moment either side is renamed.
  Findings and Components stay two separate lists in a check's result either way -
  `finding_id` doesn't merge them, it lets the web UI or AI analysis join them.

### Control score scale

Hardening controls use a normalized **0-100 scale**: `max` is always `100`,
regardless of whether the underlying check is binary or has intermediate states.

```
PASS = 100
WARN = some intermediate value, chosen deliberately (not a midpoint average - see
        below)
FAIL = 0
```

**Binary controls do not get their own `0/1` scale just because the underlying
fact is a boolean.** An earlier version of this document recommended `score: 0/1,
max: 1` for binary controls (e.g. "container running as root: yes/no"); that
recommendation is superseded by this section once a real hardening module
(`nginx_hardening`) needed a genuine three-state control (`WARN`) alongside
several binary ones, and mixing `1/1` binary components with `80/100` three-state
components in the same result would mean `82/100` doesn't mean the same thing
consistently across components. A binary control still uses `score: 0` or
`score: 100`, just on the same `max: 100` scale as every other control in the
module - the result is a security assessment, not a restatement of the raw
boolean. The raw pass/fail state remains fully available through the
corresponding `Finding` (via `finding_id`), which is where "was this literally
true or false" belongs; `score`/`max` describes the control's contribution to the
hardening score, not the raw check outcome.

**Choosing an intermediate WARN value is a judgment call the module must justify**,
not a mechanical average of PASS and FAIL. `nginx_hardening`'s `NGX-TLS-002`
(TLS-1.2-only scores `80`, not `75`) is the reference example — the value reflects
where the state actually sits on a security-posture spectrum (TLS 1.2 is still an
actively recommended fallback per OWASP/NIST, closer to acceptable than to broken),
not the arithmetic midpoint between the two endpoints. Document the reasoning next
to the control's definition (in the module's own `docs/checks/*.md`), the same way
weights must be documented (see below).

**`weight` and `score` are independent dimensions, and so are `weight` and Finding
`severity`.** `weight` says how much a control matters to the *hardening score*;
`score` says how that control's check turned out; `severity` says how significant
the underlying issue is as a *Finding*, for a human reading the findings list. None
of the three should be derived from either of the others:

```
NGX-TLS-001 (legacy protocols enabled):
  Finding.severity = high
  Component.score = 0, max = 100, weight = 0.15

NGX-TLS-002 (TLS 1.2 only, no 1.3):
  Finding.severity = low
  Component.score = 80, max = 100, weight = 0.15
```

Both controls happen to share `weight = 0.15` here, but one is a `high`-severity
Finding at `score = 0` and the other is a `low`-severity Finding at `score = 80` -
a higher weight does not imply a higher severity, and a lower score does not imply
a higher severity either. A reader (the web UI, the AI analysis) can show "NGINX
Hardening: 82/100" and, separately, "HIGH — Legacy TLS enabled" without trying to
derive one from the other.

**Every hardening module must document its own weights** (why TLS is 40% and not
30%, why `NGX-CONF-002` is weighted higher than `NGX-CONF-001` within its group)
in its own module docstring or a section here, before being merged - the
weights are a design decision, not an implementation detail to be picked ad hoc
while writing the check.

## Handling N/A (`applicable: false`)

A check can fail to *evaluate* a control without that control having *failed* -
neither `score: 0` (looks like "failed", falsely lowering the result) nor
`score: max` (looks like "passed", hiding that part of the audit didn't run) is
correct. `applicable: false` is the explicit third option: the component is
excluded from the weighted average, and **its weight is redistributed
proportionally** across the remaining applicable components, so their weighting
relative to *each other* stays the same while together they cover the full 1.0.

```json
{ "name": "http2_config", "weight": 0.10, "score": 0, "max": 100,
  "applicable": false, "reason": "http_v2 module not compiled in",
  "finding_id": "NGX-CONF-005" }
```

`score`/`max` are still required and still validated even when `applicable: false`
(use `0`/`100` as a neutral placeholder, consistent with the 0-100 scale used
everywhere else - see "Control score scale" above) so every component keeps the
same shape for serialization - the `applicable: false` flag is what tells the
reader (and `weighted_score()`) to disregard the value, not the value itself.

If **every** component in a module's result is `applicable: false`,
`weighted_score()` raises `ValueError` rather than returning a fabricated `0/100` -
a score with zero evaluated controls is undefined, not zero. The calling module
should omit the hardening score for that run entirely (e.g. report only the raw
findings, with a note that the environment prevented scoring) rather than paper
over it with a fake number.

## `weighted_score()`

`netaudit_pkg/scoring.py` provides the single implementation of the math:

```python
from netaudit_pkg.scoring import weighted_score

result = weighted_score(components)
# -> {'score': 83, 'max': 100, 'components': [...]}
```

It exists so no hardening module hand-rolls its own weighted average (and no module
can silently produce `score = 137` from mistyped weights). It validates the input
and **raises `ValueError` rather than silently correcting bad data**:

- `components` must be a non-empty list.
- each component needs `name` (non-empty str), `weight` (number), `score` (number),
  `max` (number); `applicable` and `reason` are optional.
- `weight` must be `> 0` for every component (a `weight: 0` component should just be
  omitted, not included as dead weight).
- `max` must be `> 0` for every component.
- `score` must satisfy `0 <= score <= max` for every component (a sub-check that
  scored below zero or above its own max is a bug in that sub-check, not a value to
  clamp and hide) — this is checked even for `applicable: false` components.
- the sum of all `weight` values (across every component, applicable or not) must
  equal `1.0` within `1e-6` tolerance - this is deliberately strict. A module whose
  weights sum to `0.9` or `1.1` has a bug, and `weighted_score()` failing loudly is
  far cheaper than a hardening score that's quietly wrong for every run of that
  module until someone notices by hand.
- at least one component must have `applicable: true` — see "Handling N/A" above.

Given valid input, the result is:

```
score = round(100 * sum(weight_i * (score_i / max_i) for each component))
```

i.e. each component is normalized to a 0-1 fraction of its own max, weighted, summed,
then scaled to 0-100. `max` in the output is always `100` (the hardening score
contract is fixed at a 0-100 scale, regardless of what scale individual components
used internally).

## Registering a hardening module

Hardening modules use `category='hardening'` in `@register(...)`, not `'server'` or
whatever category the check would otherwise fall under. This is what lets the (future)
`overall.score` aggregation, the web UI, and the CLI find "all hardening modules"
by filtering on category, instead of maintaining a hardcoded list of module IDs that
has to be updated by hand every time a new one is added.

```python
@register(
    id='nginx_hardening', label='...', category='hardening',
    ...
)
```

## What this enables

Once a hardening module returns this shape, it's a drop-in participant in:
- **before/after comparison** — same `components[].name` across two runs of the
  same module diffs cleanly, without free-text parsing.
- **the future `overall.score`** — once 4-5 hardening modules exist, a documented
  cross-module weighting can combine their `hardening.score` values (never their
  native `metrics`) into one aggregate, itself following this same Component shape
  one level up.
- **AI analysis** — the AI prompt can reference `components[].name` directly
  ("your `security_headers` component scored 60/100 because...") instead of
  re-deriving structure from prose.

## Status

As of this document, no hardening module exists yet. `systemd_hardening` reports a
**native metric** (`metrics["systemd.exposure"]`), not a hardening score - it wraps
an external tool's own number and does not compute anything itself, so it stays in
`category='server'` and does not use `weighted_score()`. The first hardening module
(planned: `nginx_hardening`) will be the first real consumer of this contract.
