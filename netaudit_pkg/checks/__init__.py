"""Checks package. Importing modules here registers them in the registry."""
from . import (
    aide_check,  # noqa: F401
    backup_check,  # noqa: F401
    breach_check,  # noqa: F401
    capture,  # noqa: F401
    cert_transparency,  # noqa: F401
    cve_audit,  # noqa: F401
    dns_audit,  # noqa: F401
    docker_audit,  # noqa: F401
    fail2ban_logs_audit,  # noqa: F401
    kernel_hardening,  # noqa: F401
    log_discovery_audit,  # noqa: F401
    lynis_audit,  # noqa: F401
    network,  # noqa: F401
    nginx_hardening,  # noqa: F401
    nginx_logs_audit,  # noqa: F401
    rootkit_check,  # noqa: F401
    server_security,  # noqa: F401
    site,  # noqa: F401
    sqli,  # noqa: F401
    ssh_auth_audit,  # noqa: F401
    ssh_hardening,  # noqa: F401
    system,  # noqa: F401
    systemd_hardening,  # noqa: F401
)
