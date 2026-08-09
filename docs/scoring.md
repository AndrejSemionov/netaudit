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

**Binary controls** (pass/fail, no partial credit — e.g. Docker's "container running
as root: yes/no") use `score: 0, max: 1` for fail and `score: 1, max: 1` for pass.
Use this pattern consistently rather than inventing a per-module convention (some
modules using `0/1`, others `0/100`) - it keeps components comparable and keeps
`weighted_score()`'s normalization behaving the same way everywhere.

**Every hardening module must document its own weights** (why TLS is 30% and not
50%) in its own module docstring or a section here, before being merged - the
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
{ "name": "http2_config", "weight": 0.10, "score": 0, "max": 1,
  "applicable": false, "reason": "http_v2 module not compiled in",
  "finding_id": "NGX-CONF-005" }
```

`score`/`max` are still required and still validated even when `applicable: false`
(use `0`/`1` as a neutral placeholder) so every component keeps the same shape for
serialization - the `applicable: false` flag is what tells the reader (and
`weighted_score()`) to disregard the value, not the value itself.

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
