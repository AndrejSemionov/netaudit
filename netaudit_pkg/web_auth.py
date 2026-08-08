"""
Mandatory web UI protection when it's listening beyond localhost.

The idea: if the server is started with --host 0.0.0.0 (or any non-127.0.0.1/::1
address), the interface is potentially reachable by someone other than the
machine's owner - from the local network, and sometimes from the internet if a
port is forwarded. NetAudit provides access to network/server audit results,
and some checks handle sensitive data (saved SSH credentials in command
history, report contents). Leaving this completely unprotected by default is
a real risk, not a hypothetical one (see feedback: someone exposes the panel
externally by mistake and doesn't realize it's open).

We don't rely on the admin ALWAYS setting up nginx with htpasswd here (that's
a separate, optional step, setup-nginx) - instead, built-in Basic Auth protects
the FastAPI app itself, regardless of whether anything sits in front of it. If
nginx with htpasswd is also configured, that's just two layers, not a problem.

Logic:
  - host == 127.0.0.1 / localhost / ::1  -> no auth required, same as before.
  - host != localhost and credentials are set (web_auth_user/web_auth_password
    in settings) -> Basic Auth is required on every request.
  - host != localhost and credentials are NOT set -> generate a random password
    once at startup, print it loudly to the log (only at that moment, never
    shown again), store the hash in the DB. Either way, the interface is
    never left open.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from fastapi import Request
from fastapi.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware

from . import storage
from .utils import log

LOCALHOST_HOSTS = {'127.0.0.1', 'localhost', '::1'}


def _hash_password(password: str) -> str:
    """Simple salted hash - good enough for a local web UI, not for a banking
    app. sha256(salt + password), the salt is stored alongside it."""
    salt = storage.setting_get('web_auth_salt')
    if not salt:
        salt = secrets.token_hex(16)
        storage.setting_set('web_auth_salt', salt)
    return hashlib.sha256((salt + password).encode()).hexdigest()


def ensure_auth_configured(host: str) -> None:
    """Called once when the server starts. If host isn't localhost and no
    credentials exist yet - generates them and prints the password to the log."""
    if host in LOCALHOST_HOSTS:
        return

    user = storage.setting_get('web_auth_user')
    pw_hash = storage.setting_get('web_auth_password_hash')
    if user and pw_hash:
        log.warning(f'Web UI is listening on {host} — Basic Auth is required (user: {user}).')
        return

    # first run beyond localhost with no credentials set - generate and show once
    generated_user = 'admin'
    generated_password = secrets.token_urlsafe(12)
    storage.setting_set('web_auth_user', generated_user)
    storage.setting_set('web_auth_password_hash', _hash_password(generated_password))
    log.warning('=' * 70)
    log.warning(f'Web UI is listening on {host} (beyond localhost).')
    log.warning('No auth was configured, so credentials were generated automatically:')
    log.warning(f'  user:     {generated_user}')
    log.warning(f'  password: {generated_password}')
    log.warning('This password is shown ONLY ONCE — save it now.')
    log.warning('Change it any time in the web UI: Settings tab -> Web UI access.')
    log.warning('=' * 70)


class BasicAuthMiddleware(BaseHTTPMiddleware):
    """Requires Basic Auth on every request, if the server is listening beyond localhost."""

    def __init__(self, app, host: str):
        super().__init__(app)
        self.enabled = host not in LOCALHOST_HOSTS

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)

        user = storage.setting_get('web_auth_user')
        pw_hash = storage.setting_get('web_auth_password_hash')
        if not user or not pw_hash:
            # safety net: shouldn't normally get here (ensure_auth_configured runs
            # at startup), but if the DB was cleared manually - better to refuse
            # than to silently stay open
            return Response('Auth not configured. Restart the server to generate credentials.',
                             status_code=503)

        auth_header = request.headers.get('authorization', '')
        if auth_header.startswith('Basic '):
            try:
                decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
                req_user, _, req_password = decoded.partition(':')
            except (ValueError, UnicodeDecodeError):
                req_user, req_password = '', ''

            user_ok = hmac.compare_digest(req_user, user)
            pass_ok = hmac.compare_digest(_hash_password(req_password), pw_hash)
            if user_ok and pass_ok:
                return await call_next(request)

        return Response('Authentication required', status_code=401,
                         headers={'WWW-Authenticate': 'Basic realm="NetAudit"'})
