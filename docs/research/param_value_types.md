# A parameter value is checked against its type: checkbox, number, select

Status: USER approved as an autonomous task (2026-10-22: «да давай начнем с
п1 докончим уже все и закроем дыры работаем автономно»). Item 1 of the list
was "CLI passes checkboxes as text, and `false` means yes". The number and
select cases below were found while researching it and are the same defect,
so they are fixed together (Claude's scope decision, recorded in `TASK.md`).
Implementer: Claude. Reviewer: GPT/Codex.

## Evidence

`main` `5d23f27`, temporary HOME.

**Checkbox.** `netaudit._typed()` converts only a `number` made of digits;
every other value reaches the check as the text that was typed. The checks
read a checkbox as `if auto_install:`, and any non-empty text is true.

| Command line | The check gets | What happens |
|---|---|---|
| `run rootkit_check --host 192.0.2.10 --auto_install false` | `auto_install='false'` | error "auto_install would modify the target system (install packages) but was not confirmed" (live run) |
| `run rootkit_check --host H --use_rkhunter false` | `use_rkhunter='false'` | rkhunter runs |
| `run docker_audit --host H --include_stopped no` | `include_stopped='no'` | `docker ps -a`, stopped containers included |
| `run docker_audit --host H --include_stopped` (last flag) | `include_stopped=''` | not included, although the flag was given |

The registry has 9 checkbox parameters: `auto_install` (`aide_check`,
`lynis_audit`, `rootkit_check`), `use_rkhunter`, `use_chkrootkit`
(`rootkit_check`), `include_stopped` (`docker_audit`), `include_expired`
(`cert_transparency`), `use_xposedornot`, `use_hibp` (`breach_check`).

**Number.** A number that is not only digits also stays text, and the Web
API takes any JSON in `params` (`CheckItem.params: dict`). One of them goes
into a remote shell command unquoted:
`log_collection.collect_journal()` builds
`f'journalctl -u {shlex.quote(unit_name)} -n {lines} --no-pager'`.
With `lines='5; id'` (fake SSH, no network) the server runs:

```
{ journalctl -u ssh -n 5; id --no-pager; rc=$?; printf ... }
```

`id` is a second command. The path is `ssh_auth_audit --lines`, when
`auth.log` cannot be read and the journal is the fallback. The operator
controls the value (CLI, or Web behind its password), and the command runs
as the audit's SSH user - the same class as `unit` in `systemd_hardening`
(task 8). The other number parameters do not reach a remote shell: `tail`
is built with `shlex.join`, local tools get an argument list. A text number
elsewhere fails later and less clearly (`backup_check --max_age_hours abc`
compares text with a float).

**Select.** Any text is passed on. `tshark_capture`/`mikrotik_sniffer`
`--analyze_threats no` runs the analysis (the check tests `!= 'нет'`);
`sql_injection --crawl true` does not crawl (`== 'yes'`). Nothing says that
the value is not one of the choices, and `netaudit list` does not show the
choices.

The Web form always sends the right types (checkbox → `true`/`false`,
number → `Number(...)`, select → one of its options), so the form is not
affected; only the CLI and direct API calls are.

## Design

1. **One function decides what a value means**, `registry.param_value(param,
   value)`. It returns the value the check expects, or raises `ValueError`
   whose text says what the parameter takes. The text never contains the
   value (a mistyped secret must not end up in a log).

   | Type | Accepted | Result |
   |---|---|---|
   | `checkbox` | `true`/`false`; text `true/false`, `yes/no`, `1/0`, `on/off` (any case, spaces around ignored); integer `1`/`0` | `True` / `False` |
   | `number` | an integer or a finite float (not `True`/`False`); text that Python reads as such a number | `int` when the value is whole, otherwise `float` |
   | `select` | one of `options`, exactly; or a name from the parameter's `aliases` | the option (an alias becomes its option) |
   | anything else (`text`, `password`, ...) | anything | unchanged |

   Everything else is refused, including an empty value and `None`. A select
   without `options` is not checked. A number's range (port 1-65535, lines
   above 0) stays the check's business, as before.

2. **`aliases`**: `aide_check` `mode` already accepts `check` and `init` "for
   direct calls from code/CLI", and the README shows `--mode init` and
   `--mode check`. The spec gets `'aliases': {'check': 'check for changes',
   'init': 'reinitialize the database'}`, so these keep working and are
   recorded as the option they mean. No other select has aliases.

3. **CLI** (`run`, single and group form, `--quick` included): every flag
   given for a selected check is checked with `param_value()` against that
   check's parameter **before the first password prompt and before anything
   runs**, right after the #46/#47 refusals. All wrong values are named in
   one message, in the order of the checks, e.g.

   `Wrong value: --auto_install (rootkit_check) takes true or false (also yes/no, 1/0, on/off); --lines (ssh_auth_audit) takes a number. Nothing was run`

   - The same flag name can have another type in another check (`mode` is a
     select in `aide_check` and in `sql_injection`, with other options), so
     each (check, flag) pair is checked; the check id is in the message.
   - Exit code is non-zero. `password` values are not checked (text, and
     `-` means "ask").
   - The values the check gets are the converted ones: `--auto_install
     false` → `False`, `--lines 50` → `50`, `--mode init` → `'reinitialize
     the database'`. `_typed()` is replaced by `param_value()`.

4. **Web API**: `/api/run`, `/api/estimate` and `/api/stream/start` convert
   the request's values with the same function (`engine.typed_params()`, every
   `params` and every `instances` entry) in the same `try` as
   `validate_multi_request()`; a wrong value → **400** with
   `rootkit_check: auto_install takes true or false (also yes/no, 1/0, on/off)`,
   nothing runs, nothing is saved. The run, the estimate and the stream then
   use the converted values.

5. **`collect_journal()`** builds its command with `shlex.join`, as
   `collect_file()` already does, so a value that reaches it by another
   path still cannot become a second command. For a normal value the text is
   the same as today (`journalctl -u ssh -n 200 --no-pager`).

6. **`netaudit list`** prints a select's choices:
   `└─ --mode (select: check for changes | reinitialize the database, default=check for changes)`.

7. **Unchanged**:
   - The Web form and what it sends; saved presets (a preset is checked when
     it is run, not when it is saved).
   - `text` and `password` values; unknown parameter names (the CLI refuses
     them since #46; the Web API passes them on and the check reports the
     error, as before); a check id the registry does not know.
   - Trends: `trends._setting()` keeps `bool(value)` for a checkbox. An old CLI
     report with `'false'` ran the check as `True`, so `bool('false') ==
     True` is what that run did; the first new run with a real `False`
     shows `params_changed` and moves the gone ids to `not_evaluated`
     (#48). The same for `--mode check` saved as `'check'` before and as
     `'check for changes'` now: one run shows a settings change.
   - `setup-timer` passes no check parameters (`_group_selection(..., {}, ...)`).
   - Report and API formats.

## Tests (RED first)

- `param_value()`:
  - checkbox: every accepted word in both cases and with spaces → the right
    bool; `True`/`False`, `1`/`0` → bool; `''`, `'maybe'`, `2`, `None`,
    `1.0` → `ValueError`.
  - number: `5`, `'5'`, `' 5 '`, `'2.5'`, `'1e3'`, `5.0`, `-3` → `5`, `5`,
    `5`, `2.5`, `1000`, `5`, `-3` (int when whole); `'5; id'`, `'abc'`,
    `''`, `'nan'`, `'inf'`, `True`, `None` → `ValueError`.
  - select: an option → itself; an alias → its option; another text, a
    different case, `None` → `ValueError`; a select without options → value
    unchanged.
  - text/password → unchanged.
  - the error text never contains the value.
- CLI single form: `--auto_install false`, `--use_rkhunter no`,
  `--include_stopped yes` reach the check as bools; `--lines 50` as `50`;
  `--mode init` as the option; `--duration_sec 2.5` as `2.5`.
- CLI refusals (nothing runs, non-zero exit, the value is not printed):
  `--auto_install maybe`; a checkbox given as the last flag with no value;
  `--lines '5; id'`; `--analyze_threats no`; two wrong values in one message;
  the same flag valid for one check and wrong for another
  (`aide_check sql_injection --mode init`); the refusal comes before the
  password prompt (`--password -` with a wrong value later on the line,
  also when the wrong value belongs to the last check of a mixed run).
- CLI group form (`--hosts-file`): a wrong value → refused before the prompt;
  a right one reaches every instance converted.
- `--quick --host H --lines 50`-style calls and runs without typed flags work
  as before.
- Web API: `/api/run`, `/api/estimate`, `/api/stream/start` with
  `"auto_install": "maybe"` or `"lines": "5; id"` → 400, the check function
  is not called, nothing is saved, the value is not in the response; with
  `"auto_install": "false"` / `"lines": "50"` the check gets `False` / `50`;
  the same in `instances`; the values the Web form sends (bool, number,
  option) are unchanged.
- `collect_journal(ssh, 'ssh', lines='5; id')` sends one command, with the
  value quoted; `lines=200` gives exactly `journalctl -u ssh -n 200 --no-pager`.
- Every `select` in the registry has `options`, and every alias points to one
  of them; every `checkbox` default is a bool and every `number` default a
  number (a new parameter must fit `param_value()`).
- `netaudit list` prints the choices of `aide_check --mode`.

## Docs

README EN/RU and the guide EN/RU: how to give a checkbox on the command line
(`--auto_install true`, also `yes/no`, `1/0`, `on/off`), that a select takes
one of the values `netaudit list` shows, and the new error in the guide's
table of errors. CHANGELOG under Unreleased (Fixed + Security).
