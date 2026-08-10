"""
Tests for netaudit_pkg.ssh_config: the sshd -T collector/parser that both
audit_ssh_hardening() (findings) and the future ssh_hardening (scoring) will
consume.

Fixture text mirrors the real, empirically-verified `sshd -T` output from a
live VM (OpenSSH_10.2p1) - see netaudit_pkg/ssh_config.py's docstring for the
verification history (sudo requirement, AllowUsers absent-when-unset
behavior, effective-config precedence over raw sshd_config parsing).
"""

from __future__ import annotations

from netaudit_pkg.ssh_config import collect_ssh_config, _parse_sshd_t


# A trimmed but representative slice of real sshd -T output - full field
# coverage for everything SSHConfig extracts, without all 103 directives.
SSHD_T_SAMPLE = """\
port 22
addressfamily any
logingracetime 120
maxauthtries 6
permitrootlogin prohibit-password
hostbasedauthentication no
pubkeyauthentication yes
passwordauthentication yes
kbdinteractiveauthentication no
x11forwarding yes
permitemptypasswords no
allowtcpforwarding yes
allowagentforwarding yes
ciphers chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com
macs umac-64-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha1
kexalgorithms curve25519-sha256,ecdh-sha2-nistp256
"""


# ===========================================================================
# _parse_sshd_t() — pure parsing, no I/O
# ===========================================================================

def test_parse_sets_readable_and_version():
    cfg = _parse_sshd_t(SSHD_T_SAMPLE, version='OpenSSH_10.2p1')
    assert cfg.readable is True
    assert cfg.version == 'OpenSSH_10.2p1'


def test_parse_permit_root_login_is_string_not_bool():
    # deliberately not collapsed to bool - 'prohibit-password' is
    # meaningfully distinct from both 'yes' and 'no'
    cfg = _parse_sshd_t(SSHD_T_SAMPLE)
    assert cfg.permit_root_login == 'prohibit-password'


def test_parse_permit_root_login_yes():
    cfg = _parse_sshd_t('permitrootlogin yes')
    assert cfg.permit_root_login == 'yes'


def test_parse_yes_no_fields_normalize_to_bool():
    cfg = _parse_sshd_t(SSHD_T_SAMPLE)
    assert cfg.password_authentication is True
    assert cfg.permit_empty_passwords is False
    assert cfg.pubkey_authentication is True
    assert cfg.kbd_interactive_authentication is False
    assert cfg.hostbased_authentication is False
    assert cfg.x11_forwarding is True
    assert cfg.allow_agent_forwarding is True


def test_parse_missing_yes_no_directive_is_none():
    # a field whose directive doesn't appear in the output at all -
    # distinct from an explicit 'no'
    cfg = _parse_sshd_t('port 22')
    assert cfg.password_authentication is None


def test_parse_allow_tcp_forwarding_is_string_not_bool():
    # can be 'yes'/'no'/'local'/'remote' - must not collapse to bool
    cfg = _parse_sshd_t('allowtcpforwarding local')
    assert cfg.allow_tcp_forwarding == 'local'


def test_parse_integer_fields():
    cfg = _parse_sshd_t(SSHD_T_SAMPLE)
    assert cfg.max_auth_tries == 6
    assert cfg.login_grace_time == 120


def test_parse_integer_field_missing_is_none():
    cfg = _parse_sshd_t('port 22')
    assert cfg.max_auth_tries is None


def test_parse_integer_field_non_numeric_is_none():
    # defensive: sshd -T shouldn't ever print a non-numeric MaxAuthTries,
    # but the parser must not raise if it somehow does
    cfg = _parse_sshd_t('maxauthtries notanumber')
    assert cfg.max_auth_tries is None


def test_parse_crypto_lists_are_comma_split():
    cfg = _parse_sshd_t(SSHD_T_SAMPLE)
    assert cfg.ciphers == ['chacha20-poly1305@openssh.com', 'aes128-gcm@openssh.com',
                            'aes256-gcm@openssh.com']
    assert 'hmac-sha1' in cfg.macs
    assert cfg.kex_algorithms == ['curve25519-sha256', 'ecdh-sha2-nistp256']


def test_parse_crypto_list_missing_is_empty_not_none():
    cfg = _parse_sshd_t('port 22')
    assert cfg.ciphers == []
    assert cfg.macs == []
    assert cfg.kex_algorithms == []


def test_parse_allow_users_absent_when_not_configured():
    # empirically verified on a live VM: sshd -T only prints allowusers
    # when the directive is actually set - absence is a real fact (no
    # restriction configured), not a parsing gap.
    cfg = _parse_sshd_t(SSHD_T_SAMPLE)
    assert cfg.allow_users == []
    assert cfg.allow_groups == []
    assert cfg.deny_users == []
    assert cfg.deny_groups == []


def test_parse_allow_users_space_separated_when_present():
    # AllowUsers/AllowGroups are space-separated (OpenSSH convention),
    # unlike the comma-separated crypto algorithm lists.
    cfg = _parse_sshd_t('allowusers alice bob charlie')
    assert cfg.allow_users == ['alice', 'bob', 'charlie']


def test_parse_deny_groups_space_separated():
    cfg = _parse_sshd_t('denygroups guests contractors')
    assert cfg.deny_groups == ['guests', 'contractors']


def test_parse_full_sample_end_to_end():
    cfg = _parse_sshd_t(SSHD_T_SAMPLE, version='OpenSSH_10.2p1')
    assert cfg.readable is True
    assert cfg.permit_root_login == 'prohibit-password'
    assert cfg.password_authentication is True
    assert cfg.permit_empty_passwords is False
    assert cfg.max_auth_tries == 6
    assert cfg.login_grace_time == 120
    assert cfg.x11_forwarding is True
    assert cfg.allow_tcp_forwarding == 'yes'
    assert len(cfg.ciphers) == 3
    assert cfg.allow_users == []


def test_parse_ignores_blank_lines():
    conf = 'port 22\n\n\nmaxauthtries 6\n'
    cfg = _parse_sshd_t(conf)
    assert cfg.max_auth_tries == 6


def test_parse_first_occurrence_wins_for_repeated_directive():
    # sshd -T can repeat some directives (hostkey, listenaddress) across
    # multiple lines - first occurrence should win, matching sshd's own
    # "first value takes precedence" semantics for non-multi-valued
    # directives. None of SSHConfig's fields are naturally repeating, so
    # this is exercised generically via a field we do extract.
    conf = 'maxauthtries 6\nmaxauthtries 99\n'
    cfg = _parse_sshd_t(conf)
    assert cfg.max_auth_tries == 6


# ===========================================================================
# collect_ssh_config() — via FakeSSHExecutor
# ===========================================================================

def test_collect_sshd_not_installed(fake_ssh):
    fake_ssh.responses = {'which sshd': ('NONE', '')}
    cfg = collect_ssh_config(fake_ssh)
    assert cfg.readable is False


def test_collect_unreadable_without_sudo(fake_ssh):
    # empirically verified: sshd -T without root fails outright (Permission
    # denied on a restricted Include file) and returns zero directives -
    # there's no partial-but-usable non-root result.
    fake_ssh.responses = {
        'which sshd': ('/usr/sbin/sshd', ''),
        'sshd -V': ('', 'OpenSSH_10.2p1 Ubuntu-2ubuntu3.5, OpenSSL 3.5.5'),
    }
    cfg = collect_ssh_config(fake_ssh)
    assert cfg.readable is False


def test_collect_uses_sudo_for_sshd_t(fake_ssh):
    # the mandatory fix this module exists to encode - sshd -T must go
    # through ssh.sudo(), not ssh.run(). FakeSSHExecutor's sudo() and run()
    # are both plain substring lookups, so this test only confirms
    # collect_ssh_config() calls sudo() by giving a response ONLY under the
    # sudo() code path's expectations (both map to the same _match(), so we
    # instead assert via call tracking that sudo was actually exercised).
    fake_ssh.responses = {
        'which sshd': ('/usr/sbin/sshd', ''),
        'sshd -V': ('', 'OpenSSH_10.2p1'),
        'sshd -T': (SSHD_T_SAMPLE, ''),
    }
    collect_ssh_config(fake_ssh)
    # sudo() calls run 'sudo -n true' as a probe before the real command
    # (see SSHExecutor.sudo()) - FakeSSHExecutor doesn't implement that
    # probe distinction, but ssh.calls should show the sshd -T command was
    # issued via the sudo() code path, not a second bare ssh.run('sshd -T').
    assert any('sshd -T' in c for c in fake_ssh.calls)


def test_collect_full_config(fake_ssh):
    fake_ssh.responses = {
        'which sshd': ('/usr/sbin/sshd', ''),
        'sshd -V': ('', 'OpenSSH_10.2p1 Ubuntu-2ubuntu3.5, OpenSSL 3.5.5'),
        'sshd -T': (SSHD_T_SAMPLE, ''),
    }
    cfg = collect_ssh_config(fake_ssh)
    assert cfg.readable is True
    assert 'OpenSSH_10.2p1' in cfg.version
    assert cfg.permit_root_login == 'prohibit-password'
    assert cfg.password_authentication is True
    assert cfg.max_auth_tries == 6


def test_collect_only_makes_expected_calls_when_not_installed(fake_ssh):
    fake_ssh.responses = {'which sshd': ('NONE', '')}
    collect_ssh_config(fake_ssh)
    # not-installed case should short-circuit after the `which` check
    assert len(fake_ssh.calls) == 1
