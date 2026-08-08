"""
Обязательная защита веб-интерфейса, когда он слушает не только localhost.

Идея: если сервер поднят с --host 0.0.0.0 (или любым не-127.0.0.1/::1 адресом),
это значит интерфейс потенциально доступен кому-то ещё, кроме владельца машины —
из локальной сети, а иногда и из интернета, если проброшен порт. NetAudit даёт
доступ к результатам аудита сети/сервера, а часть проверок (сохранённые SSH-креды
в истории команд, содержимое отчётов) — чувствительные данные. Оставлять это
совсем без защиты по умолчанию — реальный риск, не гипотетический (см. фидбек:
человек по невнимательности выставляет панель наружу и не понимает, что она открыта).

Здесь не полагаемся на то, что администратор ОБЯЗАТЕЛЬНО настроит nginx с htpasswd
(это отдельный, необязательный шаг, setup-nginx) — вместо этого встроенная
Basic Auth защищает само FastAPI-приложение, независимо от того, стоит ли что-то
перед ним. Если nginx с htpasswd тоже настроен — это просто два слоя, не проблема.

Логика:
  - host == 127.0.0.1 / localhost / ::1  -> auth не требуется, всё как раньше.
  - host != localhost и учётные данные заданы (web_auth_user/web_auth_password
    в настройках) -> требуем Basic Auth на каждый запрос.
  - host != localhost и учётные данные НЕ заданы -> генерируем случайный пароль
    один раз при старте, громко печатаем его в лог (только в этот момент, дальше
    он не показывается), сохраняем хэш в БД. Так или иначе открытым интерфейс
    не остаётся никогда.
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
    """Простой salted hash — этого достаточно для локального веб-интерфейса,
    не для банковского приложения. sha256(salt + password), соль хранится рядом."""
    salt = storage.setting_get('web_auth_salt')
    if not salt:
        salt = secrets.token_hex(16)
        storage.setting_set('web_auth_salt', salt)
    return hashlib.sha256((salt + password).encode()).hexdigest()


def ensure_auth_configured(host: str) -> None:
    """Вызывается один раз при старте сервера. Если host не localhost и
    учётных данных ещё нет — генерирует их и печатает пароль в лог."""
    if host in LOCALHOST_HOSTS:
        return

    user = storage.setting_get('web_auth_user')
    pw_hash = storage.setting_get('web_auth_password_hash')
    if user and pw_hash:
        log.warning(f'Web UI is listening on {host} — Basic Auth is required (user: {user}).')
        return

    # первый запуск не на localhost без заданных credentials — генерируем и показываем один раз
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
    """Требует Basic Auth на каждый запрос, если сервер слушает не localhost."""

    def __init__(self, app, host: str):
        super().__init__(app)
        self.enabled = host not in LOCALHOST_HOSTS

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)

        user = storage.setting_get('web_auth_user')
        pw_hash = storage.setting_get('web_auth_password_hash')
        if not user or not pw_hash:
            # защитный барьер: до сюда в норме не должны дойти (ensure_auth_configured
            # вызывается на старте), но если БД очистили руками — лучше отказать,
            # чем тихо остаться открытыми
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
