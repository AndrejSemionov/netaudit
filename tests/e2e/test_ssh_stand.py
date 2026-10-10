"""A3 (docs/research/e2e_ssh_stand.md): NetAudit against a real sshd + sudo.

Runs only in the CI job `e2e-ssh`, which starts tests/e2e/Dockerfile and sets
NETAUDIT_E2E_HOST / _PORT / _KEY / _PASSWORD (a throwaway key and a random
per-run password). Skipped everywhere else.
"""

from __future__ import annotations

import json
import logging
import os

import pytest

HOST = os.environ.get('NETAUDIT_E2E_HOST', '')
PORT = int(os.environ.get('NETAUDIT_E2E_PORT', '22'))
KEY = os.environ.get('NETAUDIT_E2E_KEY', '')
PASSWORD = os.environ.get('NETAUDIT_E2E_PASSWORD', '')

pytestmark = pytest.mark.skipif(not (HOST and KEY and PASSWORD),
                                reason='needs the CI SSH stand (NETAUDIT_E2E_* variables)')


def _key(user: str, sudo_password: str = '') -> dict:
    return {'host': HOST, 'user': user, 'port': PORT, 'key_path': KEY, 'password': '',
            'sudo_password': sudo_password}


def _check(check_id: str):
    from netaudit_pkg.checks.kernel_hardening import check_kernel_hardening
    from netaudit_pkg.checks.nginx_hardening import check_nginx_hardening
    from netaudit_pkg.checks.ssh_hardening import check_ssh_hardening
    return {'nginx_hardening': check_nginx_hardening, 'ssh_hardening': check_ssh_hardening,
            'kernel_hardening': check_kernel_hardening}[check_id]


def _score(result: dict) -> int:
    assert 'error' not in result, result
    assert isinstance(result['hardening']['score'], int), result
    return result['hardening']['score']


# 1. the condition of the A1 hypothesis -------------------------------------

def test_stand_non_root_ssh_path_lacks_usr_sbin():
    """Evidence, not a product assertion: Debian's sshd gives a non-root user
    a PATH without /usr/sbin, where nginx and sshd live."""
    from netaudit_pkg.ssh import SSHExecutor
    ssh = SSHExecutor(HOST, 'pwsudo', PORT, KEY, '').connect()
    try:
        out, _ = ssh.run('echo "$PATH"; command -v nginx || echo NO_NGINX_IN_PATH')
    finally:
        ssh.close()
    path = out.splitlines()[0]
    assert '/usr/sbin' not in path.split(':'), path
    assert 'NO_NGINX_IN_PATH' in out


# 2-4. sudo with a password ---------------------------------------------------

@pytest.mark.parametrize('check_id', ['nginx_hardening', 'ssh_hardening', 'kernel_hardening'])
def test_key_login_with_sudo_password_gives_a_full_audit(check_id):
    result = _check(check_id)(**_key('pwsudo', PASSWORD))
    _score(result)
    assert not result.get('collected_without_sudo')


@pytest.mark.parametrize('check_id', ['nginx_hardening', 'ssh_hardening'])
def test_wrong_sudo_password_is_named(check_id):
    result = _check(check_id)(**_key('pwsudo', PASSWORD + '-wrong'))
    assert 'not accepted' in result['error'], result


@pytest.mark.parametrize('check_id', ['nginx_hardening', 'ssh_hardening'])
def test_missing_sudo_password_names_the_field(check_id):
    result = _check(check_id)(**_key('pwsudo'))
    assert '"Sudo password"' in result['error'], result


# 5. narrow NOPASSWD rules -----------------------------------------------------

@pytest.mark.parametrize('check_id', ['nginx_hardening', 'ssh_hardening'])
def test_scoped_nopasswd_rule_works_without_a_password(check_id):
    _score(_check(check_id)(**_key('scoped')))


# 6. no sudo at all ------------------------------------------------------------

@pytest.mark.parametrize('check_id', ['nginx_hardening', 'ssh_hardening'])
def test_user_without_sudo_rights_is_named(check_id):
    result = _check(check_id)(**_key('nosudo', PASSWORD))
    assert 'sudoers' in result['error'], result


def test_kernel_hardening_without_sudo_is_marked_or_an_error():
    result = _check('kernel_hardening')(**_key('nosudo', PASSWORD))
    if 'error' in result:
        assert 'sysctl' in result['error'], result
    else:
        _score(result)
        assert result['collected_without_sudo'] is True
        assert result['sudo_note']


# 7. SSH password login --------------------------------------------------------

def test_password_login_reaches_the_target():
    result = _check('ssh_hardening')(host=HOST, user='pwlogin', port=PORT, key_path='',
                                     password=PASSWORD, sudo_password='')
    # pwlogin has no sudo rights: the error must come from sudo, not from the login
    assert 'could not connect' not in result.get('error', ''), result
    assert 'sudoers' in result['error'], result


# 8. secrets -------------------------------------------------------------------

def test_password_reaches_neither_sqlite_nor_log_nor_ai_request(isolated_db, monkeypatch, caplog):
    import httpx

    from netaudit_pkg import engine, history, storage

    caplog.set_level(logging.DEBUG)
    report = engine.run_checks_multi([{'id': 'nginx_hardening', 'params': _key('pwsudo', PASSWORD)}])
    _score(report['results']['nginx_hardening'])
    history.save_report(report)  # commits

    db_bytes = b''.join(p.read_bytes() for p in storage.DB_PATH.parent.glob(storage.DB_PATH.name + '*'))
    assert db_bytes, 'the report was not written'
    assert PASSWORD.encode() not in db_bytes

    sent = {}

    def fake_post(url, **kwargs):
        sent['body'] = json.dumps(kwargs.get('json'))
        raise httpx.HTTPError('no network in this test')

    monkeypatch.setattr(httpx, 'post', fake_post)
    history.ai_analyze(report, api_key='test-key', language='en')
    assert sent['body'] and 'nginx_hardening' in sent['body']
    assert PASSWORD not in sent['body']

    assert PASSWORD not in caplog.text


# 9. F8: tools that live in /usr/sbin ----------------------------------------

@pytest.mark.parametrize('tool', ['lynis', 'chkrootkit'])
def test_usr_sbin_tool_is_found_for_a_non_root_user(tool):
    """On Debian lynis and chkrootkit are in /usr/sbin, outside a non-root
    SSH PATH: a bare `command -v` misses them, tool_presence() does not."""
    from netaudit_pkg.ssh import SSHExecutor
    ssh = SSHExecutor(HOST, 'pwsudo', PORT, KEY, '').connect()
    try:
        bare, _ = ssh.run(f'command -v {tool} || echo NOT_IN_PATH')
        presence = ssh.tool_presence(tool)
        installed = ssh.is_tool_installed(tool)
    finally:
        ssh.close()
    assert 'NOT_IN_PATH' in bare  # the condition F8 is about
    assert presence.status == 'present'
    assert installed is True


def test_missing_tool_is_absent():
    from netaudit_pkg.ssh import SSHExecutor
    ssh = SSHExecutor(HOST, 'pwsudo', PORT, KEY, '').connect()
    try:
        assert ssh.tool_presence('netaudit-no-such-tool').status == 'absent'
    finally:
        ssh.close()


def test_lynis_audit_without_sudo_rights_fails_on_sudo_not_on_presence():
    from netaudit_pkg.checks.lynis_audit import check_lynis_audit
    result = check_lynis_audit(**_key('nosudo', PASSWORD))
    assert 'error' in result, result
    assert 'not installed' not in result['error'], result
