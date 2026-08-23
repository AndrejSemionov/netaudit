"""
Reads deploy.sh's .deployed_manifest (KEY=VALUE, two lines:
DEPLOYED_COMMIT=..., DEPLOYED_AT=...) for the /api/health and /api/version
endpoints. Never raises on a missing/malformed manifest - callers (web/app.py)
need a 200 response even on a fresh VM before the first deploy.sh run.
"""
from __future__ import annotations

from pathlib import Path

DEFAULT_MANIFEST_PATH = str(Path.home() / 'netaudit' / '.deployed_manifest')

_KEY_MAP = {
    'DEPLOYED_COMMIT': 'commit',
    'DEPLOYED_AT': 'deployed_at',
}


def read_manifest(manifest_path: str | None = None) -> dict:
    """Parses .deployed_manifest into {'commit': str|None, 'deployed_at': str|None}.

    manifest_path defaults to ~/netaudit/.deployed_manifest (RUNTIME_DIR in
    deploy.sh) - resolved at call time via Path.home(), not at import time,
    so tests can override HOME. Missing file, missing keys, or any parse
    error all fall back to None values rather than raising - the manifest
    may legitimately not exist yet (fresh checkout, pre-first-deploy).
    """
    result = {'commit': None, 'deployed_at': None}

    path = Path(manifest_path) if manifest_path is not None else Path.home() / 'netaudit' / '.deployed_manifest'

    try:
        text = path.read_text(encoding='utf-8')
    except OSError:
        return result

    for line in text.splitlines():
        line = line.strip()
        if not line or '=' not in line:
            continue
        key, _, value = line.partition('=')
        key = key.strip()
        value = value.strip()
        mapped = _KEY_MAP.get(key)
        if mapped is not None and value:
            result[mapped] = value

    return result
