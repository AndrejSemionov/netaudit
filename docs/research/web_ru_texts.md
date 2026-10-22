# Web: every check in Russian, and a Telegram hint that says what uses it

Status: USER asked to finish the remaining list autonomously (2026-10-22:
«докончим уже все и закроем дыры работаем автономно»); these are items 2
and 3 of it. Implementer: Claude. Reviewer: GPT/Codex.

## Evidence

`main` `5d23f27`, `web/static/i18n.js` read against the registry (37 checks):

- **Telegram hint.** Settings → Telegram says "For future background
  monitoring: bot token and chat_id." (RU: «Для будущих фоновых
  мониторингов…»). Since C2 (#42) the token and chat ID are used by
  `netaudit run --notify` and the timers of `netaudit setup-timer`; the Web
  service itself sends nothing.
- **Checks without a Russian name and description** (15): `aide_check`,
  `backup_check`, `breach_check`, `cert_transparency`, `docker_audit`,
  `log_discovery`, `fail2ban_logs_audit`, `kern_log_audit`,
  `kernel_hardening`, `speedtest`, `nginx_hardening`, `nginx_logs_audit`,
  `rootkit_check`, `ssh_auth_audit`, `ssh_hardening`. In the Russian UI their
  cards are in English.
- **Parameters without a Russian label** (no own entry, not in
  `COMMON_PARAM_RU`): `aide_check` `mode`, `auto_install`, `confirm_modify`;
  `backup_check` `directories`, `max_age_hours`, `min_copies`;
  `breach_check` `emails`, `use_xposedornot`, `use_hibp`; `cert_transparency`
  `domain`, `expected_issuer_contains`, `include_expired`; `docker_audit`
  `include_stopped`; `rootkit_check` `use_rkhunter`, `use_chkrootkit`,
  `auto_install`, `confirm_modify`; `lynis_audit` `confirm_modify`;
  `server_audit` `fail2ban_mode`.
- **Choices shown untranslated.** `tCheck().optLabel()` looks a choice up by
  its value. The `sql_injection` entries are keyed by Russian values
  (`'нет'`, `'пассив (только точки ввода)'`, ...), but the registry has sent
  English values since `66ff12e` (`'no'`, `'passive (input points only)'`,
  ...), so the Russian UI shows them in English. The confirmation choices of
  `aide_check`, `lynis_audit`, `rootkit_check` (`'no'`, `'yes — modify the
  target system'`) and `aide_check` `mode` have no translation at all.
- The UI strings themselves (`I18N.ru` / `I18N.en`) have the same 325 keys,
  and every key the page uses exists in both.

## Design

1. The Telegram hint, RU and EN (`i18n.js` and the default text in
   `index.html`): the bot token and chat ID are used by scheduled audits with
   notifications (`netaudit run --notify`, `netaudit setup-timer`); the Web
   interface does not send messages itself.
2. `I18N_CHECKS` gets an entry for each of the 15 checks: Russian name,
   description, and the labels of its own parameters. The meaning follows
   the English text of the registry; Read-only and similar notes are kept.
3. Missing parameter labels are added to the checks' entries.
4. Choices are keyed by the value the registry sends, with the translation
   for the other language: English values get `ru`, the Russian values of
   `tshark_capture`/`mikrotik_sniffer` keep their `en`. The dead
   Russian-keyed `sql_injection` entries are replaced. Tool names stay as
   they are and need no entry: `openssl`, `python`, `curl` (`ssl`/`http`
   `method`), `client`, `status-wrapper` (`server_audit` `fail2ban_mode`);
   `auto` gets «авто».
5. The comment above `tCheck()` says how choices are keyed now.
6. Unchanged: option values, parameter names, the registry, the API, the
   English UI (it shows the registry's English text, as before).

## Tests (RED first)

Static, like `tests/test_i18n_common_params.py` (the suite has no JS engine):

- every registered check has an `I18N_CHECKS` entry with `label` and `desc`
  in Russian;
- every parameter of every check has a Russian label: its own entry or
  `COMMON_PARAM_RU`;
- every choice of every select has an entry keyed by its exact value, with
  a translation for the other language, except the listed tool names;
- no `I18N_CHECKS` choice entry is keyed by a value the check no longer has
  (the dead `sql_injection` keys);
- the Telegram hint, RU and EN, in `i18n.js` and `index.html`, names
  `--notify` and `setup-timer` and no longer says "future".

Plus a browser check of the cards in RU and EN on a temporary HOME.
