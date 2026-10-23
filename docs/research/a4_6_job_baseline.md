# A4.6 — a scheduled job's notification compares with the job's own last run

Status: USER decision 2026-10-23 («Таймер сравнивает со своим прошлым
(Recommended)»). Amends `docs/research/c1_schedule_notifications.md` §1/§3,
where a notification is "the change from the previous run". Implementer:
Claude. Reviewer: GPT/Codex.

## Evidence

`main` `da2c9d6`, temporary HOME, the real `save_report`,
`notify.collect_changes` and `notify.decide`:

| Report | Source | `docker_audit` 192.0.2.10 |
|---|---|---|
| 1 | timer | clean |
| 2 | manual `run` (no `--notify`) or the Web | new HIGH `DCK-PRIV-001:web` |
| 3 | timer | the same HIGH |

`decide(collect_changes(report 3))` → **False**: report 2 is "the previous
run", so the HIGH is persisting and no message is sent — ever. Without
report 2 the timer run would send it (`True`). A manual audit, or one from
the Web, silently cancels the scheduled alert for whatever it found.

Concurrent runs, the original A4.6 concern, are not a problem: 2 processes ×
5 `run` on one database gave 10 reports and no error (WAL, `busy_timeout`
10 s); a timer never overlaps itself (`Type=oneshot`).

## Design

1. `run --notify --job NAME` (what `setup-timer` writes) stores
   `"job": NAME` at the top of the saved report. Nothing else is stored, and
   runs without `--job` (CLI or Web) store no `job` key. The name is the
   already validated `--job` value.
2. `notify.collect_changes()` for a report that has a `job`: for each unit
   (check, identity key, value), the earlier snapshots are those of reports
   with the **same job**, when the job has any snapshot of that unit in the
   window. If the job has never seen the unit (a new job, a host just added
   to the hosts file, the first run after this update), the earlier
   snapshots of any report are used, as before — so an update does not
   start with a "baseline" message for every unit.
3. A job snapshot of the unit that is an error still counts as "the job has
   seen it": the last good one is taken from the job's runs only (no good one
   → `baseline`, as today for "no earlier successful run").
4. Unchanged: runs without `--job`, the message text and threshold, the
   trend view in the CLI/Web/AI (they compare with any previous run, which is
   what a person looking at the history expects), the report shape apart
   from the added key.

## Tests (RED first)

- timer (clean) → manual (HIGH) → timer (HIGH): the timer run's message
  names the HIGH as new; `decide` is True.
- manual (HIGH) → first run of a job (HIGH): falls back to the manual run,
  so no message (as before the change).
- a job that runs host A; host B appears only in a manual run, then in the
  job: B falls back to the manual run.
- the job saw the unit only with an error, then a manual good run, then the
  job: the manual run is not used (`baseline`).
- a `--notify` run without `--job` behaves as before (False in the first
  scenario).
- CLI: `run … --notify --job nightly` saves `"job": "nightly"`; `--notify`
  alone and a plain `run` save no `job` key.
