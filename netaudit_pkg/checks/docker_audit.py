"""
Docker container security audit over SSH.

Unlike server_audit (looks at the host level - nginx, firewall, SSH), this
check looks specifically at HOW containers are run - a separate risk
category a host-level audit physically can't see.

Checked for each running container via `docker inspect`:
  - whether the process inside the container runs as root (Config.User is
    empty/'root'/'0') - on container escape, the attacker immediately gets
    root on the host;
  - --privileged (HostConfig.Privileged) - near-full host access, rarely
    justified (Docker-in-Docker, low-level monitoring);
  - dangerous added capabilities (HostConfig.CapAdd) - a list of what's
    genuinely considered risky to add without an explicit need (SYS_ADMIN,
    SYS_PTRACE, SYS_MODULE etc), not "any CapAdd is bad" (NET_RAW for
    ping-like tools is a normal, justified case);
  - publicly exposed ports - the container listens on 0.0.0.0 instead of
    127.0.0.1 or an internal docker network (HostConfig.PortBindings[].HostIp);
  - broad volume mounts - the whole host root, /etc, docker.sock into the
    container (HostConfig.Binds);
  - the 'latest' image tag with no version pin - not a bug by itself, but a
    signal there's no version control or accumulated CVE patching.

Separately - whether the Docker daemon socket itself is exposed unprotected
(TCP without TLS, or `/var/run/docker.sock` bound into a container) -
effectively root access to the host, one of the most common and dangerous
mistakes in real deployments.
"""

from __future__ import annotations

import json

from ..registry import register
from ..findings import finding as _finding
from ..ssh import SSHExecutor, HostKeyMismatchError

try:
    import paramiko
except ImportError:
    paramiko = None

# capabilities whose addition widens the attack surface more than typical
# legitimate cases (NET_RAW for network utilities, NET_BIND_SERVICE for
# ports < 1024 are deliberately excluded here - those are common, justified additions)
DANGEROUS_CAPS = {
    'SYS_ADMIN', 'SYS_MODULE', 'SYS_PTRACE', 'SYS_RAWIO', 'SYS_BOOT',
    'DAC_READ_SEARCH', 'ALL',
}

# paths whose mounting into a container is almost always excessive for a
# regular application (not a system monitoring/backup tool)
DANGEROUS_BIND_TARGETS = ('/', '/etc', '/root', '/var/run/docker.sock', '/boot')

def _parse_container(raw_json: str) -> dict | None:
    try:
        data = json.loads(raw_json)
    except (json.JSONDecodeError, ValueError):
        return None
    return data

def _audit_one_container(info: dict) -> list[dict]:
    findings = []
    name = (info.get('Name') or '').lstrip('/')
    config = info.get('Config') or {}
    host_config = info.get('HostConfig') or {}
    image = config.get('Image', '?')

    # --- runs as root ---
    user = (config.get('User') or '').strip()
    if user in ('', 'root', '0', '0:0'):
        findings.append(_finding(
            'medium', f'{name}: the process inside the container runs as root',
            f'image {image} — on container escape, the attacker immediately gets root access '
            'to the host; set USER in the Dockerfile or --user at run time if root isn\'t needed'
        ))

    # --- privileged ---
    if host_config.get('Privileged'):
        findings.append(_finding(
            'high', f'{name}: running with --privileged',
            'near-full host access (devices, kernel) - rarely justified '
            '(Docker-in-Docker, low-level monitoring); check whether it\'s really needed'
        ))

    # --- dangerous capabilities ---
    cap_add = host_config.get('CapAdd') or []
    dangerous = [c for c in cap_add if c.upper() in DANGEROUS_CAPS]
    if dangerous:
        findings.append(_finding(
            'high', f'{name}: risky capabilities added: {", ".join(dangerous)}',
            f'full CapAdd list: {", ".join(cap_add)} — make sure each one is actually needed by the app'
        ))

    # --- public ports ---
    port_bindings = host_config.get('PortBindings') or {}
    public_ports = []
    for container_port, bindings in port_bindings.items():
        for b in (bindings or []):
            host_ip = b.get('HostIp', '')
            if host_ip in ('', '0.0.0.0', '::'):
                public_ports.append(f'{container_port} -> {b.get("HostPort", "?")}')
    if public_ports:
        findings.append(_finding(
            'low', f'{name}: ports listening on all interfaces (0.0.0.0)',
            ', '.join(public_ports) + ' — fine for web services behind a reverse proxy, '
            'but internal services (DBs, admin panels) usually should be 127.0.0.1'
        ))

    # --- docker.sock mounted inside ---
    binds = host_config.get('Binds') or []
    for bind in binds:
        # format "host_path:container_path[:mode]"
        parts = bind.split(':')
        host_path = parts[0] if parts else bind
        normalized = host_path.rstrip('/') or '/'  # '/'.rstrip('/') gives '' - restore to '/'
        if normalized == '/var/run/docker.sock':
            findings.append(_finding(
                'high', f'{name}: docker.sock mounted inside the container',
                f'{bind} — this is effectively root access to the host via the Docker API; '
                'make sure this is deliberate (e.g. Portainer/CI runner), not an accident'
            ))
        elif normalized in DANGEROUS_BIND_TARGETS:
            findings.append(_finding(
                'medium', f'{name}: a sensitive host path is mounted: {normalized}',
                f'{bind} — excessive access for a regular application, '
                'check whether the container really needs this whole path'
            ))

    # --- latest tag / no tag ---
    if image.endswith(':latest') or ':' not in image.split('/')[-1]:
        findings.append(_finding(
            'low', f'{name}: image with no version pin ({image})',
            'without a fixed version it\'s hard to track which CVE patches are applied — '
            'the image could silently change on the next pull'
        ))

    return findings

@register(
    id='docker_audit', label='Docker container audit (SSH)', category='server',
    params=[
        {'name': 'host', 'type': 'text', 'label': 'Host', 'default': ''},
        {'name': 'user', 'type': 'text', 'label': 'User', 'default': 'root'},
        {'name': 'port', 'type': 'number', 'label': 'SSH port', 'default': 22},
        {'name': 'key_path', 'type': 'text', 'label': 'Key path', 'default': '~/.ssh/id_rsa'},
        {'name': 'password', 'type': 'password', 'label': 'Password (if not using a key)', 'default': ''},
        {'name': 'include_stopped', 'type': 'checkbox', 'label': 'Include stopped containers',
         'default': False},
    ],
    required_tools=[],
    description='Audits HOW Docker containers are run (not what\'s inside): root processes, '
                '--privileged, dangerous capabilities, public ports, docker.sock and other '
                'sensitive volume mounts, unpinned images. Read-only — only '
                '`docker ps`/`docker inspect`, changes nothing.',
)
def check_docker_audit(host='', user='root', port=22, key_path='', password='',
                        include_stopped=False) -> dict:
    if paramiko is None:
        return {'error': 'paramiko not installed'}
    if not host:
        return {'error': 'host not specified'}

    try:
        ssh = SSHExecutor(host, user, port, key_path, password).connect()
    except HostKeyMismatchError as e:
        return {'error': str(e)}
    except Exception as e:
        return {'error': f'could not connect: {e}'}

    try:
        which_out, _ = ssh.run('which docker || echo NOTFOUND')
        if 'NOTFOUND' in which_out:
            return {'error': 'docker is not installed on the server'}

        # docker usually requires being in the docker group or root - try without
        # sudo first, that's the most common working case (user added to docker group)
        ps_out, ps_err = ssh.run('docker ps -q' + (' -a' if include_stopped else ''))
        needs_sudo = 'permission denied' in (ps_out + ps_err).lower()

        if needs_sudo:
            if ssh.needs_sudo_password():
                return {'error': 'docker isn\'t accessible without sudo, and passwordless sudo isn\'t set up and no password was given',
                        'hint': 'add the user to the docker group (usermod -aG docker <user>), '
                                'or set "Password (if not using a key)" for sudo -S'}
            ps_out, ps_err = ssh.sudo('docker ps -q' + (' -a' if include_stopped else ''))

        container_ids = [c.strip() for c in ps_out.splitlines() if c.strip()]

        # check for an unprotected Docker daemon TCP socket regardless of whether
        # any containers are currently running — the socket is dangerous on its
        # own, even when everything is stopped
        socket_check_cmd = (
            "grep -rE 'tcp://.*2375' /etc/docker/daemon.json /lib/systemd/system/docker.service "
            "/etc/systemd/system/docker.service.d/*.conf 2>/dev/null || true"
        )
        socket_out, _ = ssh.run(socket_check_cmd)

        all_findings = []
        if socket_out.strip():
            all_findings.append(_finding(
                'high', 'Docker daemon is listening on TCP without explicit TLS (port 2375)',
                socket_out.strip()[:300] + ' — an unprotected TCP Docker API socket means root access '
                'for anyone who can reach it over the network'
            ))

        if not container_ids:
            if not all_findings:
                all_findings.append(_finding('ok', 'no running containers found'))
            counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
            for f in all_findings:
                counts[f['severity']] = counts.get(f['severity'], 0) + 1
            return {'host': host, 'containers_checked': 0, 'findings': all_findings, 'summary': counts}

        for cid in container_ids:
            if needs_sudo:
                raw, _ = ssh.sudo(f"docker inspect '{cid}'", timeout=15)
            else:
                raw, _ = ssh.run(f"docker inspect '{cid}' 2>&1", timeout=15)

            try:
                data = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                continue  # skip the container if the output didn't parse, don't fail the whole check
            info = data[0] if isinstance(data, list) and data else (data if isinstance(data, dict) else None)
            if not info:
                continue
            all_findings.extend(_audit_one_container(info))

    finally:
        ssh.close()

    if not all_findings:
        all_findings.append(_finding('ok', 'no notable issues found in container configuration'))

    counts = {'high': 0, 'medium': 0, 'low': 0, 'ok': 0}
    for f in all_findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    return {
        'host': host,
        'containers_checked': len(container_ids),
        'findings': all_findings,
        'summary': counts,
    }
