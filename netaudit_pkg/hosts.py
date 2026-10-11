"""
Host records for multi-host runs (B2, docs/research/b1_multi_host_contract.md
§3.1; CLI details in b2_2_cli_hosts_file.md).

A host record says where and as whom to connect: `host`, and optionally `user`,
`port` and `key_path`. It never carries a secret. Passwords are asked for at
run time and live only in memory, so a record holding `password` or
`sudo_password` is refused rather than silently dropped.

The same validation serves the CLI hosts file (B2.2) and the saved-hosts
inventory (B2.3).
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path

from .redaction import SECRET_PARAM_NAMES

RECORD_FIELDS = ('host', 'user', 'port', 'key_path')

_HOST_RE = re.compile(r'[A-Za-z0-9._:-]{1,253}')
_USER_RE = re.compile(r'[A-Za-z_][A-Za-z0-9._-]{0,31}')


class HostRecordError(ValueError):
    """A host record or hosts file that cannot be used. The message never
    contains a secret value."""


def validate_host_record(raw) -> dict:
    """The record with only RECORD_FIELDS, validated. Raises HostRecordError."""
    if not isinstance(raw, dict):
        raise HostRecordError('each host record must be a JSON object')
    secrets = sorted(SECRET_PARAM_NAMES & raw.keys())
    if secrets:
        raise HostRecordError(f'{", ".join(secrets)}: secrets are not allowed in a host record; '
                              f'give them at run time (CLI: --password -)')
    unknown = sorted(raw.keys() - set(RECORD_FIELDS))
    if unknown:
        raise HostRecordError(f'unknown field(s) {", ".join(unknown)}; allowed: {", ".join(RECORD_FIELDS)}')

    host = raw.get('host')
    if not isinstance(host, str) or not _HOST_RE.fullmatch(host) or host.startswith('-'):
        raise HostRecordError(f'host {host!r} is not a host name or IP address')
    record = {'host': host}

    if 'user' in raw:
        user = raw['user']
        if not isinstance(user, str) or not _USER_RE.fullmatch(user):
            raise HostRecordError(f'user {user!r} is not a valid user name')
        record['user'] = user
    if 'port' in raw:
        port = raw['port']
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise HostRecordError(f'port {port!r} must be an integer from 1 to 65535')
        record['port'] = port
    if 'key_path' in raw:
        key_path = raw['key_path']
        if not isinstance(key_path, str) or not key_path or '\0' in key_path:
            raise HostRecordError('key_path must be a non-empty path')
        record['key_path'] = key_path
    return record


LABEL_MAX = 100


def validate_label(label) -> str:
    """A saved host's display label (B2.3): plain text, at most LABEL_MAX
    characters, no control characters."""
    if label is None:
        return ''
    if (not isinstance(label, str) or len(label) > LABEL_MAX
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in label)):
        raise HostRecordError(f'label must be text of at most {LABEL_MAX} characters without control characters')
    return label.strip()


def host_identity(host: str) -> str:
    """How two records are compared for "the same host": IP addresses in
    normalised form, names case-insensitively."""
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        return host.lower()


def reject_duplicate_hosts(records: list[dict]) -> None:
    """One host twice in one run is ambiguous even with a different user or
    port (B1 §3.1) - refused before anything runs."""
    seen = {}
    for record in records:
        ident = host_identity(record['host'])
        if ident in seen:
            raise HostRecordError(f'host {record["host"]!r} appears more than once '
                                  f'(also as {seen[ident]!r}); run each user/port separately')
        seen[ident] = record['host']


def readable_key_path(key_path: str) -> str:
    """The expanded path if it is a readable file. The error names the path
    only - never anything read from it."""
    path = Path(key_path).expanduser()
    if not path.is_file() or not os.access(path, os.R_OK):
        raise HostRecordError(f'key file {path} is not a readable file')
    return str(path)


def load_hosts_file(path: str) -> list[dict]:
    """Validated records from a JSON array of host records."""
    try:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
    except OSError as e:
        raise HostRecordError(f'cannot read hosts file {path}: {e.strerror or e}') from e
    except json.JSONDecodeError as e:
        raise HostRecordError(f'hosts file {path} is not valid JSON (line {e.lineno})') from e
    if not isinstance(data, list) or not data:
        raise HostRecordError(f'hosts file {path} must be a non-empty JSON array of host records')
    records = []
    for i, raw in enumerate(data, 1):
        try:
            records.append(validate_host_record(raw))
        except HostRecordError as e:
            raise HostRecordError(f'hosts file {path}, record {i}: {e}') from e
    try:
        reject_duplicate_hosts(records)
    except HostRecordError as e:
        raise HostRecordError(f'hosts file {path}: {e}') from e
    return records
