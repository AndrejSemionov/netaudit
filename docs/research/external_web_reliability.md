# TLS and external web checks: no clean result without the data (A2 fix F2)

Status: stage A, MODE: AUTONOMOUS (USER: «Да, F1–F7 автономно»).
Implementer: Claude. Reviewer: GPT/Codex.
Source: `docs/research/result_reliability_audit.md` RA-01, RA-03 (HIGH),
RA-04 (MEDIUM), RA-11 (LOW); technical findings AGREED by GPT/Codex (A2 pass 1).

## Evidence (`main` @ `ea68f97`; Ubuntu 24.04, OpenSSL 3.0.13)

- **RA-01 `ssl`.** With openssl installed (`method='auto'`), the result is
  `ok: True` as soon as `openssl s_client -brief` connects; the verifying
  stdlib connection that supplies expiry and issuer fails silently.
  `expired.badssl.com`, `self-signed.badssl.com`, `wrong.host.badssl.com` →
  `ok: True, days_left: None, issuer: None`.
- **RA-03 `web_security_external`.** `_check_tls_version()` uses
  `ssl.SSLContext(PROTOCOL_TLSv1 / PROTOCOL_TLSv1_1)`. At OpenSSL 3's default
  security level the client cannot offer those versions (`[SSL] internal
  error` before anything is sent), and that is read as "server does not
  support it". `WEB-TLS-001` cannot fire. Measured: with
  `PROTOCOL_TLS_CLIENT`, `set_ciphers('DEFAULT:@SECLEVEL=0')` and
  `minimum_version = maximum_version` the client can offer TLS 1.0/1.1
  (an in-memory handshake writes a ClientHello); `tls-v1-0.badssl.com:1010`
  accepts TLS 1.0, `tls-v1-2.badssl.com:1012` resets the connection,
  `tls-v1-0.badssl.com` answers TLS 1.1 with `UNSUPPORTED_PROTOCOL`.
- **RA-04 `web_security_external`.** The `curl -I` exit code is ignored. An
  unreachable site gives four "missing header" findings (one medium, three
  low, stable ids) and no `error`; the TLS and sensitive-path probes
  silently come back negative. A sensitive path whose request fails is
  counted as "not exposed".
- **RA-11 `security_headers` (and the header part of
  `web_security_external`).** `curl -I -L` prints the headers of every
  response in the redirect chain; a header sent only by an intermediate
  redirect counts as present on the final page.

## Design

- **D1 `ssl` (openssl path).** The verifying stdlib connection decides `ok`.
  When it fails, the result is `ok: False` with its `error` (for example
  "certificate verify failed: certificate has expired"), and keeps
  `protocol`, `cipher`, `cert_chain_length`, `tool_used: 'openssl'`. When it
  succeeds, the result is unchanged. The python path is unchanged (it already
  fails on verification).
- **D2 TLS probe.** `_check_tls_version(hostname, version)` returns one of:
  - `'accepted'`: the handshake at exactly that version completed.
  - `'refused'`: the connection opened, but the server ended the handshake
    (SSL error, connection reset or closed).
  - `'untested'`: this host's Python/OpenSSL cannot offer that version (an
    in-memory handshake does not get as far as a ClientHello, checked
    before any network traffic), or the TCP connection failed or timed out.
  The probe context is `PROTOCOL_TLS_CLIENT`, no certificate check,
  `DEFAULT:@SECLEVEL=0`, min = max = the tested version.
  `WEB-TLS-001` (high) is raised for every `'accepted'` version, as before.
  If any version is `'untested'`, an `info` finding is added: "could not test
  TLS 1.0/1.1" with the reason. That is an O3 result: with it, the result
  can no longer be "no external issues found".
- **D3 base fetch.** `web_security_external` runs `curl -sS -I -L` (`-S`, so
  curl's error reaches stderr). A non-zero exit returns
  `{'url': …, 'error': 'could not fetch <base>: <curl error>'}` with no
  findings, and the other probes are skipped. A missing `curl` is an `error`
  too (it is already in `required_tools`, so `engine` normally stops first).
- **D4 sensitive paths.** A path whose `curl` exits non-zero is "not
  checked", not "not exposed". When any path is not checked, an `info`
  finding lists them.
- **D5 final response.** The header presence checks — `security_headers`, and
  the "missing header" and technology-header checks in
  `web_security_external` — read only the last header block (the one after
  the last `HTTP/… <code>` status line). `Set-Cookie` and the `Server`
  version are still read from every response: a cookie set during a redirect
  is a real cookie.

Unchanged: finding ids and severities, the CORS and error-page probes
(they run only after a successful base fetch now), `http`, the python path of
`ssl`, the hardcoded port 443 of both TLS checks (outside A2).

## Tests (RED first, no network: `run_cmd`, `_ssl_stdlib`, the probe context and `socket` are faked)

1. `ssl` openssl path, stdlib verification fails → `ok: False`, the error
   names the cause, `protocol` kept.
2. `ssl` openssl path, stdlib ok → `ok: True` with `days_left` (unchanged).
3. TLS probe: client cannot offer the version → `'untested'`, no connection
   attempted.
4. TLS probe: TCP connect fails → `'untested'`; handshake SSL error or reset →
   `'refused'`; handshake completes → `'accepted'`.
5. `web_security_external`, `curl -I` fails → `error`, no findings, no TLS or
   path probes.
6. `web_security_external`, both TLS versions untested → `info` finding, no
   `ok` "no external issues found"; TLS 1.0 accepted → `WEB-TLS-001`.
7. `web_security_external`, a sensitive path request fails → `info` "not
   checked", not counted as clean.
8. HSTS only on the redirect response → reported missing by `security_headers`
   and `web_security_external`; a cookie set on the redirect is still audited.
