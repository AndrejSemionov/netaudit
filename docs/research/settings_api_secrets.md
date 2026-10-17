# `/api/settings`: no secret goes back, only known keys are written

Status: USER approved as an autonomous task (2026-10-17: contract → RED →
GREEN → review → PR; merge by USER). Including the write side is a USER
decision of the same day. Implementer: Claude. Reviewer: GPT/Codex, who
found the first leak (`FINDINGS.md` 2026-10-17).

## Evidence

`main` `e091e81`, FastAPI TestClient, temporary HOME, fake values only.

- `GET /api/settings` (`web/app.py` `api_get_settings`) walks the whole
  `settings` table and masks only `SECRET_KEYS = {anthropic_api_key,
  telegram_token, hibp_api_key}`. Everything else comes back as stored:
  - `history_capture_password` — the MikroTik password in clear. The
    dedicated `GET /api/history_capture/settings` drops it, but the general
    endpoint does not;
  - `web_auth_password_hash` and `web_auth_salt`. The hash is a single
    `sha256(salt + password)` (`web_auth._hash_password`), so with both
    values the Web password can be guessed offline at full speed.

  Any secret setting added later would leak the same way: the rule is a
  deny-list.
- `POST /api/settings` (`api_set_settings`) writes any key it is sent. With
  `{"web_auth_password_hash": "x"}` the stored hash became `x`. That skips the
  checks of `POST /api/settings/web-auth` (user and password required, at
  least 8 characters) and can lock the owner out. With
  `{"history_capture_target_ip": "1.2.3.4\"; /system reboot; \""}` the value
  was stored, skipping `history_capture.save_settings()`'s IP check. The
  capture re-checks the value before use (`_take_snapshot`), so no command
  ran, but the save-time rule is bypassed.
- Both endpoints sit behind the existing Web authentication. This is a
  "secrets never go back to the browser" and "each setting has one owner"
  boundary, not an authentication bypass. A script running in the page
  (stored XSS was fixed in 2f, but that is the case this boundary is for)
  could read the MikroTik password and the hash.
- The settings page reads exactly: `sync_threshold_sec`, `ema_alpha`,
  `telegram_chat`, `web_auth_user`, `web_auth_configured`, and `.set` of
  `anthropic_api_key`, `telegram_token`, `hibp_api_key`
  (`index.html` `loadSettings`). It writes exactly: `sync_threshold_sec`,
  `ema_alpha`, `telegram_chat`, and, when typed, the three secrets
  (`saveSettings`). `ai_language` has a default in the GET answer and is read
  by AI analysis. No test calls either endpoint.

## Design

Allow-lists in `web/app.py`, one place for both directions:

```
PUBLIC_SETTINGS = ('sync_threshold_sec', 'ema_alpha', 'ai_language', 'telegram_chat')
SECRET_KEYS     = {'anthropic_api_key', 'telegram_token', 'hibp_api_key'}
WRITABLE        = PUBLIC_SETTINGS + SECRET_KEYS
```

1. **GET** returns only:
   - `PUBLIC_SETTINGS`, with the existing defaults when unset;
   - `{"set": bool}` for each of `SECRET_KEYS`, always present;
   - `web_auth_user` and `web_auth_configured`, as now.

   Nothing else, whatever the table holds. `web_auth_*`, `history_capture_*`
   and any future key are never returned here: history capture has its own
   endpoint, which already drops the password.
2. **POST** checks every key first. If any key is not in `WRITABLE`, it
   answers **400** and writes nothing, not even the allowed keys of the same
   request. The message names the refused keys, sorted, each cut to 64
   characters, and never echoes a value. For example: "not a setting this
   endpoint changes: web_auth_password_hash; use /api/settings/web-auth".
   The existing rule stays: an empty value for a secret is ignored, so a
   secret is never wiped by an empty field.
3. Unchanged: `POST /api/settings/web-auth` is the only way to change the Web
   login, and `/api/history_capture/settings` the only way to change MikroTik
   capture. Values of allowed keys are stored as before (`str(v)`); checking
   their ranges is out of scope.
4. Compatibility: the settings page sends and reads only allowed keys, so it
   works as before. A script that read other keys from this endpoint, or
   wrote other keys through it, gets 400 or no value; CHANGELOG says so.

## Tests (RED first)

- GET, after every key the code knows has been stored with a fake marker
  (all `history_capture_*`, `web_auth_*`, the three secrets, the public ones,
  and an unknown future `x_secret_token`):
  - the answer has exactly the documented keys;
  - no marker appears anywhere in the JSON text;
  - secrets are `{"set": true}`.
- GET on an empty database: defaults, and `{"set": false}` for each secret.
- POST of each of `web_auth_password_hash`, `web_auth_salt`, `web_auth_user`,
  `history_capture_password`, `history_capture_target_ip` and an unknown key,
  together with an allowed key: 400, nothing stored or changed (the allowed
  key included), the key name in the message, the value not in it.
- POST of the allowed keys works, and an empty secret keeps the stored one.
- The two dedicated endpoints still work (web-auth change, history capture
  save with its IP check).
