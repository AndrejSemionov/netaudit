"""
Secret params never leave the check call.

report['execution_context'] records the params a check was run with (Report
Identity / Execution Context Contract v1) so history and trends can tell which
object a report is about. Some params are credentials - the SSH `password`
of 18 checks and the `sudo_password` of the SSH checks that use sudo (task
10) - and must not end up in the saved report, in /api/report, or in the
prompt ai_analyze() sends to the AI provider.

Redaction is by param NAME, not by CheckSpec metadata: reports saved before
this module existed carry no spec, and storage must not depend on the
registry. tests/test_redaction.py fails if a registered param with
{'type': 'password'} uses a name missing from SECRET_PARAM_NAMES.

Applied at every boundary (a report may reach any of them unredacted):
engine/streaming when the context is built, storage.save_report() as the last
barrier before SQLite, storage.load_report() for rows saved before the fix
(the DB itself is not rewritten), and ai_analyze() before the prompt.

Saved Web presets hold the same params and get the same treatment
(redact_preset_checks(): storage.preset_save() and presets_list()).
"""

from __future__ import annotations

SECRET_PARAM_NAMES = frozenset({'password', 'sudo_password'})


def redact_params(params: dict) -> dict:
    """Copy of `params` without secret keys. The input is not modified."""
    return {k: v for k, v in params.items() if k not in SECRET_PARAM_NAMES}


def _redact_check_context(ctx):
    """One execution_context entry: flat params, or the multi-host
    {host_key: params} map (every value a dict). Anything else is left as is."""
    if not isinstance(ctx, dict):
        return ctx
    if ctx and all(isinstance(v, dict) for v in ctx.values()):
        return {key: redact_params(params) for key, params in ctx.items()}
    return redact_params(ctx)


def redact_report(report: dict) -> dict:
    """Shallow copy of `report` with secret params removed from its
    execution_context. Reports without an execution_context are returned as
    an equal copy - no key is added. The input is not modified."""
    out = dict(report)
    ctx = report.get('execution_context')
    if isinstance(ctx, dict):
        out['execution_context'] = {
            check_id: _redact_check_context(entry) for check_id, entry in ctx.items()
        }
    return out


def _strip_secret_keys(value):
    if isinstance(value, dict):
        return {k: _strip_secret_keys(v) for k, v in value.items() if k not in SECRET_PARAM_NAMES}
    if isinstance(value, list):
        return [_strip_secret_keys(item) for item in value]
    return value


def redact_preset_checks(checks):
    """Copy of a preset's check list with every secret key removed from any
    dict inside it - flat `params`, each multi-host `instances[*]`, or
    anything nested. Presets are a list of check items, but any JSON value is
    accepted, so a malformed row read back from SQLite is stripped too. The
    input is not modified."""
    return _strip_secret_keys(checks)
