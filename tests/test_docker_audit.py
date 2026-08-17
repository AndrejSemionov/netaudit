"""
Tests for netaudit_pkg.checks.docker_audit.

_audit_one_container is pure (dict in, list of findings out), so most of this
tests it directly without going through SSH at all. The full check_docker_audit
flow (needs SSH, sudo fallback, socket check) is covered separately at the bottom.
"""

from __future__ import annotations

import json


from netaudit_pkg.checks.docker_audit import (
    _audit_one_container, check_docker_audit,
)
from tests.conftest import FakeSSHExecutor


def _container(name='app', user='', image='myapp:latest', privileged=False,
               cap_add=None, port_bindings=None, binds=None):
    return {
        'Name': f'/{name}',
        'Config': {'User': user, 'Image': image},
        'HostConfig': {
            'Privileged': privileged,
            'CapAdd': cap_add,
            'PortBindings': port_bindings or {},
            'Binds': binds or [],
        },
    }


def test_clean_container_has_no_findings():
    c = _container(user='nginx', image='nginx:1.27.3-alpine',
                    port_bindings={'80/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '8080'}]},
                    binds=['/opt/app/static:/usr/share/nginx/html:ro'])
    findings = _audit_one_container(c)
    assert findings == []


def test_root_user_flagged():
    c = _container(user='')
    findings = _audit_one_container(c)
    assert any('root' in f['title'] for f in findings)


def test_root_user_variants_all_flagged():
    for user_value in ('', 'root', '0', '0:0'):
        c = _container(user=user_value)
        findings = _audit_one_container(c)
        assert any('root' in f['title'] for f in findings), f'user={user_value!r} should be flagged'


def test_privileged_mode_flagged_high():
    c = _container(privileged=True)
    findings = _audit_one_container(c)
    priv = next(f for f in findings if 'privileged' in f['title'].lower())
    assert priv['severity'] == 'high'


def test_dangerous_capability_flagged():
    c = _container(cap_add=['SYS_ADMIN'])
    findings = _audit_one_container(c)
    cap_finding = next(f for f in findings if 'SYS_ADMIN' in f['title'])
    assert cap_finding['severity'] == 'high'


def test_net_raw_capability_not_flagged():
    """NET_RAW is a legitimate, common addition for network diagnostic tools
    (e.g. NetAudit's own Docker build uses it) - must not be treated as dangerous."""
    c = _container(cap_add=['NET_RAW'])
    findings = _audit_one_container(c)
    assert not any('capabilities' in f['title'] for f in findings)


def test_public_port_flagged_low():
    c = _container(port_bindings={'80/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '80'}]})
    findings = _audit_one_container(c)
    port_finding = next(f for f in findings if '0.0.0.0' in f['title'])
    assert port_finding['severity'] == 'low'


def test_docker_sock_mount_flagged_high():
    c = _container(binds=['/var/run/docker.sock:/var/run/docker.sock'])
    findings = _audit_one_container(c)
    sock_finding = next(f for f in findings if 'docker.sock' in f['title'])
    assert sock_finding['severity'] == 'high'


def test_sensitive_path_etc_flagged():
    c = _container(binds=['/etc:/host/etc:ro'])
    findings = _audit_one_container(c)
    assert any('/etc' in f['title'] for f in findings)


def test_root_filesystem_mount_flagged():
    """Regression test: '/'.rstrip('/') == '' previously made this bind
    invisible to the DANGEROUS_BIND_TARGETS check - only non-root sensitive
    paths like /etc were being caught. Found and fixed during migration."""
    c = _container(binds=['/:/host/root:ro'])
    findings = _audit_one_container(c)
    assert any('sensitive host path' in f['title'] for f in findings)


def test_latest_tag_flagged_low():
    c = _container(image='myapp:latest')
    findings = _audit_one_container(c)
    assert any('version pin' in f['title'] for f in findings)


def test_pinned_version_not_flagged():
    c = _container(image='nginx:1.27.3-alpine')
    findings = _audit_one_container(c)
    assert not any('version pin' in f['title'] for f in findings)


def test_multiple_issues_all_reported():
    """The realistic 'bad' case: privileged + dangerous cap + docker.sock +
    public port + root, all on one container - every issue should surface,
    not just the first one found."""
    c = _container(user='root', image='portainer/portainer-ce:2.19', privileged=True,
                    cap_add=['SYS_ADMIN', 'NET_RAW'],
                    port_bindings={'9443/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '9443'}]},
                    binds=['/var/run/docker.sock:/var/run/docker.sock'])
    findings = _audit_one_container(c)
    titles = ' '.join(f['title'] for f in findings)
    assert 'root' in titles
    assert 'privileged' in titles.lower()
    assert 'SYS_ADMIN' in titles
    assert 'docker.sock' in titles
    assert '0.0.0.0' in titles
    assert len(findings) == 5


# ===========================================================================
# Full check_docker_audit flow (needs SSH)
# ===========================================================================

def _container_json(**kwargs):
    return json.dumps(_container(**kwargs))


def test_full_flow_no_sudo_needed(monkeypatch):
    fake = FakeSSHExecutor(
        installed_tools={'docker'},
        responses={
            'docker ps -q': ('abc123\n', ''),
            'docker inspect': (_container_json(user='nginx', image='nginx:1.27'), ''),
            'grep -rE': ('', ''),
        },
    )
    monkeypatch.setattr('netaudit_pkg.checks.docker_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_docker_audit(host='1.2.3.4', user='deploy')
    assert result['containers_checked'] == 1
    assert result['summary']['ok'] == 1


def test_full_flow_falls_back_to_sudo_when_needed(monkeypatch):
    """docker ps without sudo returns 'permission denied' - the check should
    detect that and retry via ssh.sudo() rather than failing outright."""
    call_log = []

    class SudoFallbackExecutor(FakeSSHExecutor):
        def run(self, cmd, timeout=20):
            call_log.append(('run', cmd))
            if 'docker ps -q' in cmd:
                return ('', 'permission denied')
            return super().run(cmd, timeout)

        def sudo(self, cmd, timeout=20):
            call_log.append(('sudo', cmd))
            if 'docker ps -q' in cmd:
                return ('abc123\n', '')
            if 'docker inspect' in cmd:
                return (_container_json(user='root', image='app:latest'), '')
            return super().sudo(cmd, timeout)

    fake = SudoFallbackExecutor(
        installed_tools={'docker'},
        responses={'grep -rE': ('', '')},
    )
    monkeypatch.setattr('netaudit_pkg.checks.docker_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_docker_audit(host='1.2.3.4', user='deploy')
    assert result['containers_checked'] == 1
    # confirms sudo() was actually exercised, not just available
    assert any('docker ps -q' in cmd for kind, cmd in call_log if kind == 'sudo')


def test_unprotected_daemon_socket_flagged_even_with_zero_containers(monkeypatch):
    """Regression test: the TCP socket check used to run AFTER the early
    return for zero running containers, so a dangerous unprotected daemon
    socket went unreported whenever nothing happened to be running at audit
    time. Found and fixed during development."""
    fake = FakeSSHExecutor(
        installed_tools={'docker'},
        responses={
            'docker ps -q': ('', ''),  # no running containers
            'grep -rE': ('/etc/docker/daemon.json:  "hosts": ["tcp://0.0.0.0:2375"]\n', ''),
        },
    )
    monkeypatch.setattr('netaudit_pkg.checks.docker_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_docker_audit(host='1.2.3.4')
    assert result['containers_checked'] == 0
    assert result['summary']['high'] == 1
    assert any('TCP' in f['title'] for f in result['findings'])


def test_docker_not_installed(monkeypatch):
    fake = FakeSSHExecutor()  # installed_tools defaults to empty set - docker absent
    monkeypatch.setattr('netaudit_pkg.checks.docker_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_docker_audit(host='1.2.3.4')
    assert 'error' in result
    assert 'not installed' in result['error']


def test_empty_host_rejected():
    result = check_docker_audit(host='')
    assert 'error' in result


# ===========================================================================
# SSHExecutor.sudo() new contract integration (post-scoped-sudoers fix -
# see project session notes on the SSHExecutor.sudo() rewrite, and
# test_lynis_audit.py/test_aide_check.py/test_rootkit_check.py's matching
# tests for the same pattern). docker_audit.py is the one consumer of
# the four where a plain gate-removal is NOT enough - see this file's
# module docstring / project session notes: unlike lynis/aide/rootkit
# (which already had a downstream "no output" check that naturally
# absorbs a sudo denial), docker_audit's zero-containers path
# (`if not container_ids: ... 'no running containers found'`) cannot
# distinguish "sudo was denied, ps_out came back empty" from "there are
# genuinely zero running containers" without an explicit check - a
# false 'ok: no running containers found' would be actively misleading
# (hiding real containers instead of reporting inaccessible ones).
# ===========================================================================

def test_needs_sudo_password_no_longer_blocks_the_check(monkeypatch):
    """Direct regression for the upfront-gate removal: even when
    FakeSSHExecutor is configured to report needs_sudo_password()=True
    (no_password_sudo=False, password=''), check_docker_audit() must
    still attempt the real sudo docker ps/inspect commands rather than
    returning an error before trying."""
    class SudoFallbackExecutor(FakeSSHExecutor):
        def run(self, cmd, timeout=20):
            if 'docker ps -q' in cmd:
                return ('', 'permission denied')
            return super().run(cmd, timeout)

        def sudo(self, cmd, timeout=20):
            if 'docker ps -q' in cmd:
                return ('abc123\n', '')
            if 'docker inspect' in cmd:
                return (_container_json(user='root', image='app:latest'), '')
            return super().sudo(cmd, timeout)

    fake = SudoFallbackExecutor(
        installed_tools={'docker'},
        no_password_sudo=False,
        password='',
        responses={'grep -rE': ('', '')},
    )
    monkeypatch.setattr('netaudit_pkg.checks.docker_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_docker_audit(host='1.2.3.4')
    assert 'error' not in result
    assert result['containers_checked'] == 1


def test_sudo_denied_reports_access_error_not_zero_containers(monkeypatch):
    """The central risk this fix must close: when unprivileged docker ps
    is denied AND the sudo -n retry is ALSO denied (real scoped-sudoers
    refusal, not a missing password fallback), the check must report an
    explicit access error - it must NEVER report 'no running containers
    found' just because ps_out came back empty from a denied sudo
    attempt. A false 'zero containers, all clear' here would actively
    hide real containers from the audit."""
    class SudoDeniedExecutor(FakeSSHExecutor):
        def run(self, cmd, timeout=20):
            if 'docker ps -q' in cmd:
                return ('', 'permission denied')
            return super().run(cmd, timeout)

        def sudo(self, cmd, timeout=20):
            if 'docker ps -q' in cmd:
                return ('', 'sudo: a password is required')
            return super().sudo(cmd, timeout)

    fake = SudoDeniedExecutor(
        installed_tools={'docker'},
        no_password_sudo=False,
        password='',
    )
    monkeypatch.setattr('netaudit_pkg.checks.docker_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_docker_audit(host='1.2.3.4')
    assert 'error' in result
    assert 'containers_checked' not in result
    assert not any(w.get('severity') == 'ok' for w in result.get('findings', []))


def test_sudo_succeeds_after_unpriv_denied_with_scoped_sudoers(monkeypatch):
    """The realistic scoped-sudoers shape (session notes, 46.62.147.41-
    like host): unprivileged docker ps is denied, but sudo -n docker ps
    succeeds (scoped NOPASSWD permits it specifically). Containers found
    via sudo must be reported normally - this is the positive-path
    counterpart to test_sudo_denied_reports_access_error_not_zero_containers,
    confirming the fix doesn't overcorrect into treating every sudo
    attempt as suspect."""
    class ScopedSudoExecutor(FakeSSHExecutor):
        def run(self, cmd, timeout=20):
            if 'docker ps -q' in cmd:
                return ('', 'permission denied')
            return super().run(cmd, timeout)

        def sudo(self, cmd, timeout=20):
            if 'docker ps -q' in cmd:
                return ('abc123\n', '')
            if 'docker inspect' in cmd:
                return (_container_json(user='nginx', image='nginx:1.27'), '')
            return super().sudo(cmd, timeout)

    fake = ScopedSudoExecutor(
        installed_tools={'docker'},
        no_password_sudo=False,
        password='',
        responses={'grep -rE': ('', '')},
    )
    monkeypatch.setattr('netaudit_pkg.checks.docker_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_docker_audit(host='1.2.3.4')
    assert 'error' not in result
    assert result['containers_checked'] == 1


def test_genuine_zero_containers_still_reports_ok_when_sudo_not_needed(monkeypatch):
    """Regression guard: the fix for the sudo-denial-vs-zero-containers
    ambiguity must not break the ordinary, already-covered case (see
    test_unprotected_daemon_socket_flagged_even_with_zero_containers)
    where docker ps genuinely succeeds (no sudo involved at all) and
    genuinely returns zero containers - that must still produce the
    normal 'ok: no running containers found', not a false access
    error."""
    fake = FakeSSHExecutor(
        installed_tools={'docker'},
        responses={
            'docker ps -q': ('', ''),  # succeeds, genuinely empty - no sudo involved
            'grep -rE': ('', ''),
        },
    )
    monkeypatch.setattr('netaudit_pkg.checks.docker_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_docker_audit(host='1.2.3.4')
    assert 'error' not in result
    assert result['containers_checked'] == 0
    assert any(f['severity'] == 'ok' for f in result['findings'])


def test_docker_inspect_partial_failure_does_not_break_whole_audit(monkeypatch):
    """One container's docker inspect failing to parse (e.g. a partial
    sudo denial mid-loop, or genuinely malformed output) must not abort
    the whole audit - the existing per-container graceful degradation
    (continue on JSONDecodeError) must still apply after the gate
    removal. Two containers: one parses fine, one doesn't - the audit
    must still complete and report findings for the one that worked."""
    class PartialInspectExecutor(FakeSSHExecutor):
        def run(self, cmd, timeout=20):
            if 'docker ps -q' in cmd:
                return ('good\nbad\n', '')
            if "docker inspect 'good'" in cmd:
                return (_container_json(user='root', image='app:latest'), '')
            if "docker inspect 'bad'" in cmd:
                return ('not valid json', '')
            return super().run(cmd, timeout)

    fake = PartialInspectExecutor(
        installed_tools={'docker'},
        responses={'grep -rE': ('', '')},
    )
    monkeypatch.setattr('netaudit_pkg.checks.docker_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_docker_audit(host='1.2.3.4')
    assert 'error' not in result
    assert result['containers_checked'] == 2
    # the one container that parsed fine should still have contributed findings
    assert any('root' in f['title'] for f in result['findings'])
