# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in NetAudit, please report it
privately rather than opening a public issue.

**Preferred**: use GitHub's private vulnerability reporting for this
repository (Security tab → "Report a vulnerability"), if enabled.

**Alternative**: open an issue with minimal detail (e.g. "Security issue
— details sent privately") and note in it how you'd like to be
contacted, without describing the vulnerability publicly.

Please include, where possible:
- A description of the vulnerability and its potential impact
- Steps to reproduce, or a proof-of-concept
- The affected version/commit
- Any suggested mitigation, if you have one

## Scope

NetAudit connects to remote hosts via SSH and runs security checks
against them, some of which (SQL injection testing, traffic capture,
active port scanning) are active security testing tools. Vulnerabilities
of interest include, but are not limited to:

- Authentication or authorization bypass in the web interface or API
- Command injection in any check (all external commands must go through
  `subprocess` with argument lists, never `shell=True` — see the
  project's `## Security` section in README.md)
- Credential handling issues (API keys, SSH passwords/keys stored or
  logged insecurely)
- Any check that could be triggered against a host without the explicit
  authorization NetAudit already requires (e.g. the SQL injection check's
  confirmation gate)
- Vulnerabilities in dependencies (also tracked via `pip-audit` in CI)

## Response

This is an actively maintained project. Reports will be acknowledged and
triaged; the timeline depends on severity and available time, since this
is not a funded security team — please be patient, and thank you for
reporting responsibly.

## Supported Versions

NetAudit does not currently maintain multiple released version branches.
Security fixes are applied to the `main` branch; there is no separate
long-term-support version.
