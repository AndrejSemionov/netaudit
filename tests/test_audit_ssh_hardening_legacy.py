"""
Regression tests for the CURRENT (pre-refactor) behavior of
netaudit_pkg.checks.server_security.audit_ssh_hardening().

Written before any refactor to this function - these pin the existing
external behavior (return shape, default values, finding text, the
no-findings-means-'ok' fallback) so that a refactor to consume
collect_ssh_config()/SSHConfig instead of the current raw-text `directive()`
regex can be verified not to change anything a caller depends on, except
where the refactor is deliberately fixing a known bug (see the sudo-access
tests below, which document the CURRENT broken behavior explicitly, not
because it's correct, but because the refactor must be shown to fix it -
these particular assertions are expected to need updating once the refactor
lands, and that's the point: they're the signal the fix actually happened).

Command matching note: audit_ssh_hardening() issues one combined command
(`cat sshd_config; cat sshd_config.d/*.conf`) via ssh.run(), not ssh.sudo() -
FakeSSHExecutor's substring-match responses key on 'cat /etc/ssh/sshd_config'
to catch it, since the full command string includes both cat invocations.
"""

from __future__ import annotations

from netaudit_pkg.checks.server_security import audit_ssh_hardening
from tests.conftest import FakeSSHExecutor


SSHD_CONFIG_HARDENED = """\
port 22
permitrootlogin prohibit-password
passwordauthentication no
permitemptypasswords no
maxauthtries 6
"""

SSHD_CONFIG_ROOT_LOGIN_YES = """\
port 22
permitrootlogin yes
passwordauthentication no
permitemptypasswords no
maxauthtries 6
"""

SSHD_CONFIG_PASSWORD_AUTH_YES = """\
port 22
permitrootlogin prohibit-password
passwordauthentication yes
permitemptypasswords no
maxauthtries 6
"""

SSHD_CONFIG_EMPTY_PASSWORDS_YES = """\
port 22
permitrootlogin prohibit-password
passwordauthentication no
permitemptypasswords yes
maxauthtries 6
"""

SSHD_CONFIG_ALL_BAD = """\
port 2222
permitrootlogin yes
passwordauthentication yes
permitemptypasswords yes
maxauthtries 10
"""


def _ssh(conf: str) -> FakeSSHExecutor:
    """Builds a FakeSSHExecutor whose responses match the commands
    collect_ssh_config() actually issues (which sshd / sshd -V / sshd -T),
    not the pre-refactor cat-sshd_config command - audit_ssh_hardening()
    now goes through collect_ssh_config() for all of these.
    """
    return FakeSSHExecutor(responses={
        'which sshd': ('/usr/sbin/sshd', ''),
        'sshd -V': ('', 'OpenSSH_10.2p1 Ubuntu-2ubuntu3.5'),
        'sshd -T': (conf, ''),
    })


# ===========================================================================
# Unreadable config
# ===========================================================================

def test_current_behavior_unreadable_config_returns_low_finding():
    ssh = FakeSSHExecutor(responses={'cat /etc/ssh/sshd_config': ('', '')})
    result = audit_ssh_hardening(ssh)
    assert result == {'findings': [{'severity': 'low', 'title': 'no access to sshd_config',
                                     'detail': '', 'confidence': 'high'}]}


def test_current_behavior_unreadable_config_has_no_other_keys():
    # confirms the current shape doesn't include port/root_login/etc when
    # the config couldn't be read at all
    ssh = FakeSSHExecutor(responses={})
    result = audit_ssh_hardening(ssh)
    assert set(result.keys()) == {'findings'}


# ===========================================================================
# Fully hardened config
# ===========================================================================

def test_current_behavior_hardened_config_no_findings_gives_ok():
    result = audit_ssh_hardening(_ssh(SSHD_CONFIG_HARDENED))
    assert result['port'] == '22'
    assert result['root_login'] == 'prohibit-password'
    assert result['password_auth'] == 'no'
    assert result['max_auth_tries'] == '6'
    # current behavior: zero findings triggers a synthetic 'ok' finding
    assert len(result['findings']) == 1
    assert result['findings'][0]['severity'] == 'ok'
    assert result['findings'][0]['title'] == 'SSH is configured sensibly'


# ===========================================================================
# Individual findings - current text and severity, no id= yet
# ===========================================================================

def test_current_behavior_root_login_yes_finding():
    result = audit_ssh_hardening(_ssh(SSHD_CONFIG_ROOT_LOGIN_YES))
    titles = {f['title'] for f in result['findings']}
    assert 'PermitRootLogin yes' in titles
    f = next(f for f in result['findings'] if f['title'] == 'PermitRootLogin yes')
    assert f['severity'] == 'high'
    # POST-REFACTOR: stable finding id is now present, matching
    # docs/checks/ssh_hardening.md's SSH-AUTH-001 - this is a deliberate
    # change this refactor makes (see audit_ssh_hardening()'s docstring),
    # not a regression. The pre-refactor version of this test asserted
    # 'id' not in f; that assertion is exactly what changed.
    assert f['id'] == 'SSH-AUTH-001'
    assert result['root_login'] == 'yes'


def test_current_behavior_prohibit_password_no_finding():
    # current directive() default check: only 'yes' triggers a finding -
    # 'prohibit-password' does not, even though it's the non-default value
    # being explicitly set here
    result = audit_ssh_hardening(_ssh(SSHD_CONFIG_HARDENED))
    titles = {f['title'] for f in result['findings']}
    assert 'PermitRootLogin yes' not in titles


def test_current_behavior_password_auth_yes_finding():
    result = audit_ssh_hardening(_ssh(SSHD_CONFIG_PASSWORD_AUTH_YES))
    titles = {f['title'] for f in result['findings']}
    assert 'PasswordAuthentication yes' in titles
    f = next(f for f in result['findings'] if f['title'] == 'PasswordAuthentication yes')
    assert f['severity'] == 'medium'
    assert result['password_auth'] == 'yes'


def test_current_behavior_empty_passwords_yes_finding():
    result = audit_ssh_hardening(_ssh(SSHD_CONFIG_EMPTY_PASSWORDS_YES))
    titles = {f['title'] for f in result['findings']}
    assert 'PermitEmptyPasswords yes' in titles
    f = next(f for f in result['findings'] if f['title'] == 'PermitEmptyPasswords yes')
    assert f['severity'] == 'high'


def test_current_behavior_all_bad_produces_three_findings():
    result = audit_ssh_hardening(_ssh(SSHD_CONFIG_ALL_BAD))
    titles = {f['title'] for f in result['findings']}
    assert titles == {'PermitRootLogin yes', 'PasswordAuthentication yes', 'PermitEmptyPasswords yes'}
    assert result['port'] == '2222'
    assert result['max_auth_tries'] == '10'


# ===========================================================================
# Directive absence semantics changed by the refactor - documented, not
# silently dropped. Pre-refactor, directive() fell back to a hardcoded
# collector-side default (e.g. 'prohibit-password') when a regex match
# failed against raw config text. Post-refactor, "absent" can only mean
# SSHConfig.readable == False (an incomplete/garbage sshd -T that this
# function's own fallback below then handles) - a REAL `sshd -T` run always
# resolves every directive to its effective value, including OpenSSH's own
# default when nothing was explicitly configured, so there is no longer a
# "collector-side default" concept to test the same way. See
# collect_ssh_config()'s docstring for why raw sshd_config parsing (which
# is what could plausibly omit a directive) was replaced with sshd -T in
# the first place.
# ===========================================================================

def test_current_behavior_minimal_sshd_t_output_still_reads_present_directives():
    # a real sshd -T always includes every directive - this fixture is
    # intentionally minimal (not a realistic sshd -T) to confirm
    # audit_ssh_hardening() doesn't crash and correctly reads what IS
    # present, falling back sensibly for what SSHConfig leaves as None.
    result = audit_ssh_hardening(_ssh('permitrootlogin prohibit-password\n'))
    assert result['root_login'] == 'prohibit-password'
    # password_authentication not present in this minimal fixture ->
    # SSHConfig.password_authentication is None -> fail-safe default 'yes'
    # (see test_current_behavior_none_field_defaults_fail_safe below for
    # why this must NOT be 'no')
    assert result['password_auth'] == 'yes'
    titles = {f['title'] for f in result['findings']}
    assert 'PasswordAuthentication yes' in titles


def test_current_behavior_none_field_defaults_fail_safe():
    # The specific regression this test exists to catch: a naive
    # `'yes' if cfg.password_authentication else 'no'` would map None to
    # 'no' via ordinary Python falsiness - the SAFE-looking value - which
    # is backwards for a security report (a None here means "couldn't
    # confirm this is safe," not "confirmed safe"). The pre-refactor
    # directive() defaulted to 'yes' (pessimistic) when the directive
    # wasn't found in raw config text; this must still default to 'yes'
    # now that the collector is different, or a caller silently loses a
    # finding it used to get. Config text with no passwordauthentication
    # line at all -> cfg.password_authentication is None.
    conf_without_password_auth = 'permitrootlogin no\npermitemptypasswords no\n'
    result = audit_ssh_hardening(_ssh(conf_without_password_auth))
    assert result['password_auth'] == 'yes', (
        "password_auth defaulted to 'no' for an unresolved (None) field - "
        "this is the fail-open regression this test exists to catch. A None "
        "SSHConfig.password_authentication must produce the pessimistic "
        "'yes' default, matching pre-refactor behavior, not fall through to "
        "Python truthiness."
    )
    titles = {f['title'] for f in result['findings']}
    assert 'PasswordAuthentication yes' in titles


# ===========================================================================
# The known bug this refactor exists to fix: no sudo, so a root-only
# Include file (sshd_config.d/*.conf with restrictive permissions) is
# silently invisible to this function today. These tests document CURRENT
# (broken) behavior - the refactor is expected to change what these assert,
# by construction (that's what "fixed" means here). Kept as a marker so the
# refactor's own test suite can point back at exactly what changed and why.
# ===========================================================================

def test_current_behavior_does_not_use_sudo():
    # confirms today's implementation calls ssh.run(), not ssh.sudo() - a
    # FakeSSHExecutor response keyed only on a sudo-specific marker would
    # NOT be reachable by the current code, since run() and sudo() are
    # indistinguishable to FakeSSHExecutor's _match() (both just look up
    # substrings) - so this test instead confirms the actual command issued
    # doesn't request privilege escalation via any `sudo` prefix.
    ssh = _ssh(SSHD_CONFIG_HARDENED)
    audit_ssh_hardening(ssh)
    assert all('sudo' not in c for c in ssh.calls), (
        "audit_ssh_hardening() issued a command containing 'sudo' - if this now "
        "fails, the refactor has changed how the config is read (expected once "
        "the SSHConfig-based rewrite lands, since collect_ssh_config() uses "
        "ssh.sudo() for `sshd -T` - update/remove this test as part of that change)"
    )
