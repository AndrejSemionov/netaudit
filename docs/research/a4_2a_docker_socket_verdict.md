# A4.2a — подтверждённый verdict socket-пробы Docker

Статус: контракт перед RED → GREEN. USER утвердил A4.2 «Сейчас, всё»
(2026-10-10). Исполнитель GPT/Codex, независимый ревьюер Claude.
База: `main` `5995292`; F4 уже подтвердил `docker ps`/`inspect`, но
socket-проба осталась вне F4 (`docs/research/f4_collection_verdict.md`).

## Факт

`docker_audit.check_docker_audit()` читает конфигурацию Docker daemon через
`grep -rE 'tcp://.*2375' ... 2>/dev/null || true`, затем вызывает только
`ssh.run()` без кода завершения. И отсутствие совпадений, и ошибка чтения,
и обрыв SSH дают пустой stdout. При пустом списке контейнеров результат
может сказать `ok: no running containers found`, хотя отдельная проба
опасного TCP socket не состоялась. При ненулевом числе контейнеров другие
findings могут быть достоверны, но socket-часть остаётся неизвестной.

## Контракт

1. Проверять те же три источника конфигурации: `/etc/docker/daemon.json`,
   `/lib/systemd/system/docker.service` и `*.conf` в
   `/etc/systemd/system/docker.service.d/`. Отсутствующий optional файл
   или пустой optional каталог допускают исход «нет совпадений»;
   существующий, но нечитаемый файл/каталог — ошибка сбора. Убирать
   `|| true` и не скрывать ошибки `grep`.
2. Использовать `run_command_with_exit_code()` с уникальным marker из
   `ssh_utils`. Подтверждённый `exit 0` с непустым совпадением → прежний
   high finding `DCK-API-001`; подтверждённый `exit 1` без вывода →
   совпадений в прочитанных файлах нет. Это только вывод по указанным
   конфигурационным файлам, не доказательство отсутствия всех возможных
   способов выставить Docker API.
3. Потеря marker, `exit >= 2`, противоречивая пара stdout/code или
   исключение SSH → socket status **unknown**: отдельная находка `info`
   `requires_manual_verification=True` и `warnings`; не добавлять
   глобальный `ok` при нуле контейнеров или при отсутствии иных findings.
   Уже подтверждённые findings от контейнеров сохранять. Если после
   частичного совпадения произошла ошибка чтения другого файла, сохранить
   high finding по полученному совпадению **и** `info` о неполном охвате.
4. Оба пути с нулём/ненулём контейнеров возвращают машинный
   `socket_probe_status`: `exposed`, `no_match` или `unknown`; при
   частичном совпадении + ошибке — `unknown` с high finding. `summary`
   отражает фактические findings. Не менять SSH credentials, sudo flow,
   `docker ps`/`inspect`, severity/title/id существующих findings.

## RED cases

- 0 контейнеров + `grep` exit 1 без stdout → прежний `ok`, status `no_match`.
- 0 контейнеров + нет marker / exit 2 / SSH exception → status `unknown`,
  `info` с manual flag и предупреждение, **без** `ok`.
- Контейнер с достоверным finding + socket unknown → finding сохранён,
  плюс collection gap.
- exit 0 с совпадением → `DCK-API-001`, status `exposed` даже без контейнеров.
- Совпадение до ошибки другого файла → high finding и unknown gap.
- Команда пропускает только отсутствующие optional пути и не содержит
  `|| true`; ошибка чтения существующего файла не превращается в exit 1.

Проверка: профильный pytest, широкая регрессия без локально зависающего Web
TestClient, полный Ruff, compileall, `git diff --check`; затем независимый
ревью Claude и CI включая Web/E2E SSH. Никаких изменений на целевом хосте.
