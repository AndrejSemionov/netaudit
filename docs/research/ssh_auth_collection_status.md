# SSH authentication log collection status — focused fix contract

Status: **DRAFT; Claude review and USER approval required before RED/GREEN**.
Part of 1.0 roadmap item 2e (log-analysis quality). Date: 2026-10-08.

## Evidence

`log_collection._to_command_result()` sets `completed=True` whenever a
process exit status was recovered, including a nonzero status. The other
three log checks explicitly require `completed=True` **and**
`exit_code==0` in their `_source_coverage()` helpers.

`checks/ssh_auth_audit.py` instead selects auth.log when
`file_result.result.completed` is true, and selects journal when
`journal_result.result.completed` is true. Both branches ignore a nonzero
exit status. `detection_succeeded` is then true and an empty stdout
produces an `ok` finding. A focused fake with auth.log exit 1 and empty
stdout returned `selected_source='file'` and `ok: no suspicious patterns
detected`; journal fallback was not attempted. This is a false success.

## Proposed behavior

1. A source is usable only when the collection command has confirmed
   completion **and** `exit_code == 0`.
2. If auth.log collection has a nonzero or unknown exit status, try the
   existing journal fallback. If journal succeeds, set
   `selected_source='journal'` and `fallback_used=True` when auth.log was
   attempted. Preserve the existing source-preference rule for a confirmed
   empty auth.log result (exit 0, stdout empty): it remains the selected
   file source, without journal fallback.
3. If both sources fail, keep `selected_source='none'` and
   `detection_succeeded=False`; do not emit an `ok` finding. Add a short
   top-level `error` saying that no SSH authentication source could be
   collected, without embedding command output. This prevents trend and
   generic report consumers from interpreting an empty `findings` list and
   zero summary as a successful scan. Keep the existing `selection_reason`
   for diagnosis. Do not reinterpret nonzero stdout as log events.
4. Preserve current parsing, detection thresholds, and behavior for
   successful collection. The added error key appears only when both
   sources fail. No real SSH target is contacted by tests.

## RED scenarios

- auth.log exit 1, journal exit 0 with a synthetic known failure line:
  journal selected; finding reflects the journal event, not `ok`.
- auth.log exit 1 and journal exit 1: `selected_source='none'`, no `ok`
  finding, and an explicit top-level error; trend counts become `None`.
- auth.log exit 0 with empty stdout: file selected and existing `ok`
  semantics preserved; journal not attempted.
- auth.log completion unconfirmed and journal exit 0: existing fallback
  still works.

## Review questions

Claude should verify whether a journal exit 1 should be retried or merely
reported as unavailable, and whether the proposed top-level `error`
interacts correctly with all report consumers. The contract deliberately
adds no retries; one journal attempt follows the existing behavior.
