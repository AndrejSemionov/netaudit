"""Shared utilities: subprocess execution without shell=True, binary availability check, logging."""

from __future__ import annotations

import logging
import shutil
import subprocess
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
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_text)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        log.warning(f'Timeout: {" ".join(cmd)}')
        return -1, '', 'timeout'
    except FileNotFoundError:
        log.warning(f'Command not found: {cmd[0]}')
        return -1, '', 'not found'


def missing_tools(required: list[str]) -> list[str]:
    return [t for t in required if not tool_available(t)]
