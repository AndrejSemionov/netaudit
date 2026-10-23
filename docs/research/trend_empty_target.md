# An empty target is not an object of trends or of the AI history

Status: USER «да» (2026-10-23) to "a run without a target must not become a
trend object". Implementer: Claude. Reviewer: GPT/Codex.

## Evidence

On the USER's real database `netaudit trend` lists
`systemd_hardening host= 1 run`: a Web run with an empty host field (the
check answered "host not specified"). `trends.snapshots_from_report()`
(`trends.py:264-270`) takes any value of an identity key, `''` included, and
`storage.identity_pairs()` does the same, so `find_related_reports()` treats
two runs with an empty host as the same object and hands one to the AI as
the other's history.

## Design

One rule, `storage.identity_value(value)`: a value is a target only when it
is not `None` and, as text, not empty or blank. `identity_pairs()` and
`trends.snapshots_from_report()` skip any other value. Old reports stay as
they are; their empty-target runs simply stop appearing as objects.

Unchanged: the report itself, the run's error in the CLI/Web result and in
a Telegram notification (`notify` reports a failed instance from the run,
not from trend units), targets that are given.

## Tests (RED first)

- `snapshots_from_report()` of a run with `host=''` or `host='  '` → no
  snapshot; with a host → one.
- `list_units()` on a database with such a run and a normal one lists only
  the normal one.
- `identity_pairs()` drops the empty value; `find_related_reports()` of an
  empty-host run returns nothing although another empty-host run exists.
- `notify.collect_changes()` still lists the empty-host run's error as a
  problem.
