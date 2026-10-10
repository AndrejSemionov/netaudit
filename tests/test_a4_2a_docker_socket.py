"""A4.2a: the Docker daemon socket probe has a confirmed three-way verdict."""

from __future__ import annotations

from netaudit_pkg.checks.docker_audit import check_docker_audit
from tests.conftest import ExitCodeFakeSSHExecutor


def _check(monkeypatch, *, socket_out='', socket_code=None, containers='', inspect_out=''):
    responses = {'docker ps -q': containers, 'grep -rE': socket_out}
    exit_codes = {'docker ps -q': 0}
    if socket_code is not None:
        exit_codes['grep -rE'] = socket_code
    if containers:
        responses['docker inspect'] = inspect_out
        exit_codes['docker inspect'] = 0
    fake = ExitCodeFakeSSHExecutor(
        installed_tools={'docker'}, responses=responses, exit_codes=exit_codes,
    )
    monkeypatch.setattr('netaudit_pkg.checks.docker_audit.SSHExecutor', lambda *a, **kw: fake)
    return check_docker_audit(host='example.test'), fake


def test_no_match_is_confirmed_only_on_exit_one(monkeypatch):
    result, fake = _check(monkeypatch, socket_code=1)
    assert result['socket_probe_status'] == 'no_match'
    assert any(f['severity'] == 'ok' for f in result['findings'])
    assert not any(f.get('requires_manual_verification') for f in result['findings'])
    command = next(c for c in fake.calls if 'grep -rE' in c)
    assert '|| true' not in command
    assert '/etc/docker/daemon.json' in command
    assert '/lib/systemd/system/docker.service' in command
    assert '/etc/systemd/system/docker.service.d/' in command


def test_missing_completion_marker_is_unknown_not_clean(monkeypatch):
    result, _ = _check(monkeypatch)
    assert result['socket_probe_status'] == 'unknown'
    assert result['warnings']
    assert any(f['severity'] == 'info' and f['requires_manual_verification']
               for f in result['findings'])
    assert not any(f['severity'] == 'ok' for f in result['findings'])


def test_grep_error_is_unknown_not_clean(monkeypatch):
    result, _ = _check(monkeypatch, socket_code=2)
    assert result['socket_probe_status'] == 'unknown'
    assert not any(f['severity'] == 'ok' for f in result['findings'])
    assert any('exit 2' in f['detail'] for f in result['findings'])


def test_socket_match_is_high_even_without_containers(monkeypatch):
    result, _ = _check(monkeypatch, socket_out='daemon.json: tcp://0.0.0.0:2375', socket_code=0)
    assert result['socket_probe_status'] == 'exposed'
    assert any(f.get('id') == 'DCK-API-001' for f in result['findings'])
    assert not any(f['severity'] == 'ok' for f in result['findings'])


def test_partial_match_and_error_keep_high_and_unknown(monkeypatch):
    result, _ = _check(monkeypatch, socket_out='daemon.json: tcp://0.0.0.0:2375', socket_code=2)
    assert result['socket_probe_status'] == 'unknown'
    assert any(f.get('id') == 'DCK-API-001' for f in result['findings'])
    assert any(f['severity'] == 'info' and f['requires_manual_verification']
               for f in result['findings'])


def test_container_finding_survives_socket_unknown(monkeypatch):
    inspect = ('[{"Name":"/app","Config":{"User":"root","Image":"app:1.0"},'
               '"HostConfig":{"Privileged":false,"CapAdd":[],"PortBindings":{},"Binds":[]}}]')
    result, _ = _check(monkeypatch, containers='abc123\n', inspect_out=inspect)
    assert result['socket_probe_status'] == 'unknown'
    assert result['containers_inspected'] == 1
    assert any(f.get('id') == 'DCK-USER-001:app' for f in result['findings'])
    assert any(f['severity'] == 'info' and f['requires_manual_verification']
               for f in result['findings'])


def test_ssh_exception_in_socket_probe_is_unknown(monkeypatch):
    class BrokenSocketProbe(ExitCodeFakeSSHExecutor):
        def run(self, cmd, timeout=20, stdin_data=None):
            if 'grep -rE' in cmd:
                raise TimeoutError('simulated socket probe timeout')
            return super().run(cmd, timeout=timeout, stdin_data=stdin_data)

    fake = BrokenSocketProbe(
        installed_tools={'docker'}, responses={'docker ps -q': ''},
        exit_codes={'docker ps -q': 0},
    )
    monkeypatch.setattr('netaudit_pkg.checks.docker_audit.SSHExecutor', lambda *a, **kw: fake)
    result = check_docker_audit(host='example.test')
    assert result['socket_probe_status'] == 'unknown'
    assert not any(f['severity'] == 'ok' for f in result['findings'])
    assert 'socket' in result['warnings'][0].lower()
