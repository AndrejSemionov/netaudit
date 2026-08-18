"""Regression test for netaudit_pkg.checks.ssh_auth_audit — ensures the
SSH auth orchestration check uses the targeted Discovery primitive
(probe_log_file) rather than the full-host collect_log_discovery().

Background (see project session notes, 2026-08-18): the original
version of check_ssh_auth_audit() called collect_log_discovery() just
to learn auth.log's availability — that function also globs every
nginx log file, checks journal state, and probes five other fixed
sources this check never uses. Confirmed wasteful in practice: the
nginx glob alone accounted for most of a ~45s run on 46.62.147.41
(94 files x 2 SSH round-trips). Fixed by switching to
log_discovery.probe_log_file() (a single-file probe) +
log_discovery_audit.file_verdict() (the same verdict logic, applied to
one file's evidence instead of a full report).

This test asserts the fix at the source level — it does not need a live
or even mocked SSH connection, since the property being verified
("does this module import/call the expensive full-discovery function at
all") is visible in the module's own source and import list.
"""

from __future__ import annotations

from netaudit_pkg.checks import ssh_auth_audit


def test_does_not_import_full_discovery_collector():
    """collect_log_discovery (the expensive, everything-at-once
    collector) must not even be imported by this module — only
    probe_log_file (the targeted single-file primitive) should be."""
    module_globals = vars(ssh_auth_audit)
    assert 'collect_log_discovery' not in module_globals, (
        'ssh_auth_audit.py must not import collect_log_discovery() — use '
        'log_discovery.probe_log_file() for a targeted auth.log-only probe instead.'
    )
    assert 'probe_log_file' in module_globals, (
        'ssh_auth_audit.py should import log_discovery.probe_log_file() for its Discovery step.'
    )
