"""
External tools management: what's needed, what's installed, install on demand.

Installation goes through apt with an allowlist (only known packages) - no
arbitrary shell input. Requires privileges (sudo or root); if unavailable,
returns a clear error with the command to run manually.
"""

from __future__ import annotations

import shutil

from .registry import registry
from .utils import run_cmd, tool_available
from . import checks  # noqa: F401  - importing registers the checks

# Allowlist: tool -> apt package. Only these can be installed from the web UI.
TOOL_PACKAGES: dict[str, str] = {
    'mtr': 'mtr-tiny',
    'tcptraceroute': 'tcptraceroute',
    'traceroute': 'traceroute',
    'ping': 'iputils-ping',
    'dig': 'dnsutils',
    'arping': 'iputils-arping',
    'iperf3': 'iperf3',
    'curl': 'curl',
    'openssl': 'openssl',
    'ss': 'iproute2',
    'nmap': 'nmap',
    'whois': 'whois',
    'tshark': 'tshark',
    'sqlmap': 'sqlmap',
}

# Tools that checks use internally but don't declare in required_tools
# (e.g. openssl/curl - there's a fallback, so they're not mandatory, but useful).
OPTIONAL_TOOLS = ['openssl', 'curl', 'traceroute', 'nmap', 'whois']


def all_referenced_tools() -> list[str]:
    """All tools referenced by checks (required) + optional ones."""
    tools = set(OPTIONAL_TOOLS)
    for spec in registry.all():
        tools.update(spec.required_tools)
    return sorted(tools)


def tools_status() -> list[dict]:
    """Status of each tool: installed or not, path, package to install, who uses it."""
    used_by: dict[str, list[str]] = {}
    for spec in registry.all():
        for t in spec.required_tools:
            used_by.setdefault(t, []).append(spec.id)

    out = []
    for tool in all_referenced_tools():
        path = shutil.which(tool)
        out.append({
            'tool': tool,
            'installed': path is not None,
            'path': path,
            'package': TOOL_PACKAGES.get(tool),
            'used_by': used_by.get(tool, []),
            'installable': tool in TOOL_PACKAGES,
        })
    return out


def install_tool(tool: str) -> dict:
    """
    Installs a tool via apt. Allowlist only.
    Tries sudo -n (passwordless) first; if unavailable, returns the command to run manually.
    """
    if tool not in TOOL_PACKAGES:
        return {'ok': False, 'error': f'{tool} is not on the install allowlist'}

    package = TOOL_PACKAGES[tool]

    if tool_available(tool):
        return {'ok': True, 'already': True, 'tool': tool}

    manual_cmd = f'sudo apt install -y {package}'

    # try passwordless sudo first (typical for pre-configured servers)
    if shutil.which('sudo'):
        run_cmd(['sudo', '-n', 'apt-get', 'update'], timeout=120)  # fresh package index
        code, out, err = run_cmd(['sudo', '-n', 'apt-get', 'install', '-y', package], timeout=180)
        if code == 0:
            return {'ok': True, 'tool': tool, 'package': package, 'output': out.strip()[-500:]}
        # passwordless sudo didn't work
        if 'password is required' in err.lower() or 'a terminal is required' in err.lower():
            return {'ok': False, 'error': 'sudo password required - run manually',
                    'manual_command': manual_cmd}
        return {'ok': False, 'error': err.strip()[-500:] or f'apt exit code {code}',
                'manual_command': manual_cmd}

    # no sudo - maybe we're already root
    run_cmd(['apt-get', 'update'], timeout=120)  # fresh package index
    code, out, err = run_cmd(['apt-get', 'install', '-y', package], timeout=180)
    if code == 0:
        return {'ok': True, 'tool': tool, 'package': package, 'output': out.strip()[-500:]}
    return {'ok': False, 'error': err.strip()[-500:] or f'apt exit code {code}',
            'manual_command': manual_cmd}
