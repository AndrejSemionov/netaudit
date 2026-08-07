"""Пакет проверок. Импорт модулей здесь регистрирует их в реестре."""
from . import network          # noqa: F401
from . import site             # noqa: F401
from . import system           # noqa: F401
from . import capture          # noqa: F401
from . import server_security  # noqa: F401
from . import sqli             # noqa: F401
from . import cve_audit        # noqa: F401
from . import lynis_audit      # noqa: F401
from . import dns_audit        # noqa: F401
