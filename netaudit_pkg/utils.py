"""Shared utilities: subprocess execution without shell=True, binary availability check, logging,
IP address check, the final response of a `curl -I -L` header dump."""

from __future__ import annotations

import ipaddress
import logging
import re
import shutil
import subprocess  # nosec B404 - this module IS the shared safe-subprocess wrapper (never shell=True), see run_cmd() below
import sys

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger('netaudit')


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def run_cmd(cmd: list[str], timeout: int = 30, input_text: str | None = None) -> tuple[int, str, str]:
    """Runs a command as an argument list (never shell=True)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_text, check=False)  # nosec B603 - run_cmd() is the project-wide safe subprocess wrapper: list-form args, never shell=True
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        log.warning(f'Timeout: {" ".join(cmd)}')
        return -1, '', 'timeout'
    except FileNotFoundError:
        log.warning(f'Command not found: {cmd[0]}')
        return -1, '', 'not found'


def missing_tools(required: list[str]) -> list[str]:
    return [t for t in required if not tool_available(t)]


def is_ip_address(value: str) -> bool:
    """True for one IPv4/IPv6 address as text, nothing else (no hostnames,
    no surrounding spaces). Used before a value goes into a router command
    (task 8: MikroTik target_ip)."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


_HTTP_STATUS_LINE = re.compile(r'^HTTP/\S+\s+\d{3}', re.MULTILINE)


def last_response_headers(head: str) -> str:
    """The header block of the last response in a `curl -I -L` dump, which
    prints every response of the redirect chain (F2, RA-11: a header sent
    only by an intermediate redirect is not on the final page). The whole
    text when there is no status line."""
    starts = [m.start() for m in _HTTP_STATUS_LINE.finditer(head)]
    return head[starts[-1]:] if starts else head
