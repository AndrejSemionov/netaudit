# NetAudit — подробная инструкция

[🇬🇧 English](guide.md) · 🇷🇺 Русский · [README](../README.ru.md)

Пошагово: от установки до регулярных аудитов с уведомлениями. Справка по каждой проверке —
в [README](../README.ru.md) и на вкладке «Помощь» в интерфейсе.

> ⚠️ Проверяйте только свои системы или системы, владелец которых дал явное разрешение.

## Содержание

1. [Как это устроено](#1-как-это-устроено)
2. [Установка](#2-установка)
3. [Первый запуск в консоли](#3-первый-запуск-в-консоли)
4. [Web-интерфейс: запуск и вход из браузера](#4-web-интерфейс-запуск-и-вход-из-браузера)
5. [Что где в интерфейсе](#5-что-где-в-интерфейсе)
6. [Аудит сайта](#6-аудит-сайта)
7. [Подготовка SSH-доступа к серверу](#7-подготовка-ssh-доступа-к-серверу)
8. [Аудит сервера](#8-аудит-сервера)
9. [Несколько серверов сразу](#9-несколько-серверов-сразу)
10. [Настройки: AI, Telegram, пароль Web](#10-настройки-ai-telegram-пароль-web)
11. [Аудит по расписанию с уведомлениями](#11-аудит-по-расписанию-с-уведомлениями)
12. [История, сводка и динамика](#12-история-сводка-и-динамика)
13. [Обновление](#13-обновление)
14. [Где лежат данные и как сделать резервную копию](#14-где-лежат-данные-и-как-сделать-резервную-копию)
15. [Типичные ошибки](#15-типичные-ошибки)

## 1. Как это устроено

- **Машина NetAudit** — компьютер или сервер, на котором установлен NetAudit. Здесь хранятся
  отчёты, настройки, SSH-ключи для входа на проверяемые серверы и список их ключей хоста.
- **Проверяемые цели** — сайты (проверяются снаружи, без доступа) и серверы (проверяются по
  SSH, только чтение).
- Работать можно **в консоли** (`python3 netaudit.py …`) и **в браузере** (Web-интерфейс). Это
  одно и то же: оба пишут отчёты в одну базу.

Все пути к SSH-ключам, которые вы вводите (в консоли или в браузере), — это пути **на машине
NetAudit**, а не на компьютере, с которого вы открыли браузер.

## 2. Установка

Нужны Linux (проверено на Ubuntu 24.04, подходят Ubuntu 22.04+ и Debian 12), Python 3.11+, `git`
и `sudo`.

### 2.1 Попробовать на своём компьютере

```bash
git clone https://github.com/AndrejSemionov/netaudit.git
```

```bash
cd netaudit
```

```bash
./install.sh
```

`install.sh` ставит системные утилиты (mtr, tcptraceroute, dig, arping, iperf3, curl, openssl,
Speedtest CLI) и Python-зависимости. Проверьте, что всё импортируется:

```bash
python3 -c "import fastapi, uvicorn, psutil, paramiko, httpx; print('OK')"
```

Должно напечатать `OK`. Если `pip` установил программы в `~/.local/bin`, добавьте этот каталог
в `PATH`:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
```

```bash
source ~/.bashrc
```

### 2.2 Установить на сервер как службу

Так NetAudit работает постоянно, а Web-интерфейс доступен в любой момент.

**Шаг 1. Отдельный пользователь** (из аккаунта с sudo):

```bash
sudo adduser netaudit
```

```bash
sudo usermod -aG sudo netaudit
```

```bash
sudo -iu netaudit
```

Все следующие шаги — под пользователем `netaudit`.

**Шаг 2. Код и зависимости:**

```bash
sudo apt update
```

```bash
sudo apt install -y git python3 python3-pip unzip
```

```bash
git clone https://github.com/AndrejSemionov/netaudit.git ~/netaudit
```

```bash
cd ~/netaudit && ./install.sh
```

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```

**Шаг 3. Право на ICMP для mtr** (без него mtr зависает в службе):

```bash
sudo setcap cap_net_raw+ep $(which mtr)
```

**Шаг 4. Автозапуск через systemd.** Создайте файл `/etc/systemd/system/netaudit.service`:

```bash
sudo nano /etc/systemd/system/netaudit.service
```

Содержимое:

```ini
[Unit]
Description=NetAudit web interface
After=network.target

[Service]
Type=simple
User=netaudit
WorkingDirectory=/home/netaudit/netaudit
ExecStart=/usr/bin/python3 /home/netaudit/netaudit/netaudit.py web --host 127.0.0.1 --port 8000
Restart=on-failure
RestartSec=5
Environment=PATH=/home/netaudit/.local/bin:/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=multi-user.target
```

Включите и запустите:

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now netaudit
```

```bash
sudo systemctl status netaudit
```

В выводе должно быть `active (running)`. Служба слушает только `127.0.0.1:8000`: снаружи её не
видно. Как открыть её в браузере со своего компьютера — в [разделе 4.2](#42-netaudit-на-сервере-браузер-на-вашем-компьютере).

## 3. Первый запуск в консоли

Список всех проверок и их параметров:

```bash
python3 netaudit.py list
```

Первый аудит сайта (замените адрес на свой сайт):

```bash
python3 netaudit.py run ssl web_security_external --url https://example.com
```

В конце работы вы увидите строку вида `Report saved: 1` и отчёт в JSON. Номер отчёта (`1`)
понадобится, чтобы открыть его снова. Все сохранённые отчёты:

```bash
python3 netaudit.py history
```

Готовый набор проверок для сайта (DNS проверяется только с `--domain`):

```bash
python3 netaudit.py run --quick --url https://example.com --domain example.com
```

## 4. Web-интерфейс: запуск и вход из браузера

### 4.1 NetAudit и браузер на одном компьютере

```bash
python3 netaudit.py web
```

Откройте в браузере `http://127.0.0.1:8000`. Остановить сервер — `Ctrl+C` в терминале. Пароль не
нужен: сервер слушает только этот компьютер.

Если порт 8000 занят, запустите на другом и откройте `http://127.0.0.1:8080`:

```bash
python3 netaudit.py web --port 8080
```

### 4.2 NetAudit на сервере, браузер на вашем компьютере

Выберите один из трёх способов.

**Способ А — SSH-туннель (проще всего, ничего не открывает в сеть).** На **своём** компьютере
(Linux, macOS или Windows 10+ в PowerShell) выполните, подставив адрес сервера:

```bash
ssh -L 8000:127.0.0.1:8000 netaudit@<IP-сервера>
```

Пока это окно открыто, на своём компьютере откройте `http://127.0.0.1:8000`. Это Web-интерфейс
сервера, переданный через SSH. Закрыли окно — доступ пропал. Если на вашем компьютере порт 8000
занят, используйте `-L 8080:127.0.0.1:8000` и откройте `http://127.0.0.1:8080`.

**Способ Б — nginx с паролем (постоянный доступ по адресу сервера).** На сервере, под
`netaudit`, из `~/netaudit`:

```bash
sudo apt install -y nginx apache2-utils
```

```bash
python3 netaudit.py setup-nginx --domain <IP-сервера> --user admin
```

```bash
sudo htpasswd -c /etc/nginx/.netaudit_htpasswd admin
```

`htpasswd` попросит придумать пароль: это пароль для входа в браузере.

```bash
sudo cp netaudit.nginx.conf /etc/nginx/sites-available/netaudit
```

```bash
sudo ln -s /etc/nginx/sites-available/netaudit /etc/nginx/sites-enabled/
```

```bash
sudo rm -f /etc/nginx/sites-enabled/default
```

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Откройте `http://<IP-сервера>` и войдите как `admin` с этим паролем. Сменить пароль:

```bash
sudo htpasswd /etc/nginx/.netaudit_htpasswd admin
```

Соединение идёт по HTTP без шифрования. Для доступа из интернета получите сертификат (certbot):
в `netaudit.nginx.conf` уже есть закомментированные строки для HTTPS.

**Способ В — напрямую в своей локальной сети (без nginx).** Запустите сервер на всех адресах:

```bash
python3 netaudit.py web --host 0.0.0.0 --port 8000
```

При первом таком запуске NetAudit сам создаёт логин `admin` и пароль и печатает его в лог
**один раз**, в рамке из `=`. Строка выглядит так: `password: <пароль>`. Если NetAudit работает
как служба и вы поменяли в ней `--host` на `0.0.0.0`, найдите пароль в журнале:

```bash
sudo journalctl -u netaudit | grep -A1 "user:"
```

Откройте `http://<IP-сервера>:8000` и войдите. Пароль можно сменить на вкладке «Настройки» →
«Доступ к веб-интерфейсу». Пароль идёт по сети без шифрования, поэтому этот способ подходит
только для своей локальной сети. Для остального используйте А или Б.

## 5. Что где в интерфейсе

Вверху — вкладки **«Аудит»**, **«Динамика»**, **«Настройки»**, **«Помощь»** и переключатель
языка RU/EN.

**«Аудит».**
- Слева **пресеты** (готовые наборы, например «🔒 Аудит сайта (снаружи)», «🖥️ Аудит сервера (SSH)») и
  список проверок. Отметьте проверку галочкой — появятся её параметры.
- **«+ Добавить хост»** добавляет ещё один сервер к той же проверке.
- Кнопка внизу показывает примерное время и режим: «Запустить · ~1мин · в фоне». Во время работы
  её можно нажать как «■ Остановить».
- Справа — отчёт. Над ним вкладки **«История»** (прошлые отчёты, ссылка «открыть») и **«AI-анализ:
  что делать»** (нужен ключ AI, раздел 10.1).
- «Сохранить как пресет» запоминает отмеченные проверки и параметры, но без паролей.

**«Динамика».** Как менялись находки и оценка по каждому объекту между запусками. Отдельно —
график потерь mtr по цели.

**«Настройки».**
- Anthropic API, HaveIBeenPwned API;
- доступ к веб-интерфейсу;
- режим sync/async;
- Telegram-алерты;
- история трафика (MikroTik);
- цели по умолчанию;
- SSH-хосты;
- списки репутации;
- инструменты системы;
- пресеты.

Кнопка «Сохранить настройки» сохраняет ключи Anthropic и HaveIBeenPwned, режим sync/async и
Telegram. У доступа к веб-интерфейсу, истории трафика, целей, SSH-хостов и пресетов свои кнопки.

**«Помощь».** Описание каждой проверки: что делает, что ей нужно и как то же запустить в
терминале.

## 6. Аудит сайта

Доступ к серверу сайта не нужен.

**В браузере:**
1. Вкладка «Аудит» → пресет «🔒 Аудит сайта (снаружи)». Он отмечает `ssl`,
   `web_security_external` и `security_headers`.
2. В каждой из них укажите адрес сайта (`url`, вместе с `https://`), например
   `https://example.com`.
3. Нужна проверка DNS (SPF, DKIM, DMARC, DNSSEC)? Отметьте ещё `dns_audit` и укажите домен
   (`domain`, без `https://`), например `example.com`.
4. Нажмите «Запустить».

**В консоли:**

```bash
python3 netaudit.py run --quick --url https://example.com --domain example.com
```

Каждая находка имеет серьёзность: `critical`, `high`, `medium`, `low`, `info` или `ok`. Пометка
`requires_manual_verification` значит, что проверка не смогла убедиться сама, и это нужно
посмотреть руками.

## 7. Подготовка SSH-доступа к серверу

Для аудита сервера NetAudit входит на него по SSH и только читает. Подготовка делается один раз
на каждый сервер.

**Шаг 1. Ключ на машине NetAudit.** Выполните под тем же пользователем, под которым работает
NetAudit: для службы это `netaudit`.

```bash
ssh-keygen -t ed25519 -f ~/.ssh/netaudit_audit -N '' -C netaudit-audit
```

Ключ создаётся без пароля (`-N ''`). Это нужно для службы и аудитов по расписанию: у них нет
ssh-agent, и ввести пароль ключа некому. Защищает его то, что файл может читать только этот
пользователь (`-rw-------`).

**Шаг 2. Пользователь на проверяемом сервере.** Проще всего входить как `root`. Безопаснее завести
отдельного пользователя `audit` с ограниченными правами sudo; какие команды ему разрешить, описано
в [README, «SSH и sudo»](../README.ru.md#ssh-и-sudo). Создать его — **на проверяемом сервере**:

```bash
sudo adduser audit
```

**Шаг 3. Положить ключ на сервер** — снова на машине NetAudit. Команда один раз спросит пароль
пользователя `audit`. Если вход по паролю на сервере выключен, допишите содержимое
`~/.ssh/netaudit_audit.pub` в `~audit/.ssh/authorized_keys` на сервере вручную.

```bash
ssh-copy-id -i ~/.ssh/netaudit_audit.pub audit@<IP-сервера>
```

**Шаг 4. Проверить вход по ключу** (не должно спрашивать пароль):

```bash
ssh -i ~/.ssh/netaudit_audit audit@<IP-сервера> true
```

**О ключе хоста.** При первом подключении NetAudit запоминает ключ сервера в
`~/.netaudit/known_hosts` и дальше сверяет с ним. Если ключ поменялся, подключение
отклоняется (см. [раздел 15](#15-типичные-ошибки)). Так NetAudit защищается от подмены сервера.

**sudo.** Часть проверок читает то, что доступно только root: `nginx -T`, `sshd -T`, `sysctl -a`,
правила файрвола. Если sudo на сервере спрашивает пароль, есть два варианта:
- ввести его при запуске: поле «Пароль sudo (если sudo его спрашивает)» в браузере или
  `--sudo_password -` в консоли, тогда NetAudit спросит пароль без отображения;
- разрешить нужные команды без пароля (NOPASSWD) — для аудитов по расписанию это единственный
  путь. Точные строки для sudoers — в [README, «SSH и sudo»](../README.ru.md#ssh-и-sudo).

Пароли нигде не сохраняются: ни в отчётах, ни в пресетах, ни в данных для AI.

## 8. Аудит сервера

**В браузере:**
1. Вкладка «Аудит» → пресет «🖥️ Аудит сервера (SSH)» (это `server_audit`: nginx, fail2ban,
   файрвол, MySQL, SSH). Добавьте галочками другие проверки, например `ssh_hardening`,
   `kernel_hardening`, `lynis_audit`.
2. В блоке каждой проверки укажите:
   - `host` — адрес сервера;
   - `user` — например `audit`;
   - `key_path` — путь к ключу на машине NetAudit, например `/home/netaudit/.ssh/netaudit_audit`;
   - «Пароль sudo», если sudo его спрашивает.
3. Нажмите «Запустить». По ходу видно, какая проверка выполняется.

**В консоли** (`--sudo_password -` значит «спросить без отображения»):

```bash
python3 netaudit.py run server_audit ssh_hardening kernel_hardening --host <IP-сервера> --user audit --key_path ~/.ssh/netaudit_audit --sudo_password -
```

Готовый серверный набор:

```bash
python3 netaudit.py run --quick --host <IP-сервера> --user audit --key_path ~/.ssh/netaudit_audit
```

Если проверка не смогла подключиться или ей не хватило прав, в отчёте будет ошибка с причиной,
например `could not connect: …` или `sudo: a password is required`. Такая проверка — не «всё
чисто», а «не проверено».

## 9. Несколько серверов сразу

**В браузере:**
1. «Настройки» → «SSH-хосты»: добавьте серверы (метка, хост, пользователь, порт, путь к ключу).
   Паролей там нет.
2. «Аудит»: отметьте нужные SSH-проверки. В блоке «Сохранённые хосты» отметьте серверы и
   нажмите «Подставить в выбранные проверки»: каждая проверка получит по блоку на сервер.
3. «Запустить». В отчёте есть сводка по хостам: ошибки и неполный сбор показаны отдельно от
   количества находок.

**В консоли.** Создайте файл `~/hosts.json` (пароли в него не пишутся):

```json
[
  {"host": "192.168.88.20", "user": "audit", "key_path": "/home/netaudit/.ssh/netaudit_audit"},
  {"host": "192.168.88.21", "user": "audit", "port": 2222, "key_path": "/home/netaudit/.ssh/netaudit_audit"}
]
```

```bash
python3 netaudit.py run ssh_hardening kernel_hardening --hosts-file ~/hosts.json
```

Одновременно проверяются 4 сервера, это меняется через `--max-parallel N` (от 1 до 16). Сводка
по хостам для сохранённого отчёта:

```bash
python3 netaudit.py summary <номер-отчёта>
```

## 10. Настройки: AI, Telegram, пароль Web

### 10.1 AI-анализ (Anthropic)

1. Получите API-ключ на `console.anthropic.com`.
2. «Настройки» → «Anthropic API» → вставьте ключ → «Проверить ключ» → «Сохранить настройки».
3. После аудита нажмите «AI-анализ: что делать». В консоли добавьте `--ai`:

```bash
python3 netaudit.py run ssl web_security_external --url https://example.com --ai
```

Отчёт уходит в Anthropic (без паролей). Ключ хранится в базе на машине NetAudit, и в браузер он
обратно не отдаётся.

### 10.2 Telegram

1. В Telegram откройте `@BotFather` → `/newbot` → придумайте имя. BotFather пришлёт **токен**
   вида `123456789:AA…`.
2. Напишите своему боту любое сообщение (иначе он не сможет вам писать).
3. Узнайте **chat ID**: откройте в браузере адрес ниже (подставьте токен) и найдите
   `"chat":{"id":…}`. Для группы добавьте бота в группу, напишите там сообщение и откройте адрес
   снова: у группы ID отрицательный.

```text
https://api.telegram.org/bot<ТОКЕН>/getUpdates
```

4. «Настройки» → «Telegram-алерты» → токен и chat ID → «Сохранить настройки».
5. Проверка: аудит заведомо недоступного порта всегда даёт ошибку, поэтому сообщение придёт:

```bash
python3 netaudit.py run ssh_hardening --host 127.0.0.1 --port 1 --notify --job test
```

Токен, как и ключ AI, в браузер обратно не отдаётся.

### 10.3 Пароль Web-интерфейса

Он нужен только для способа В из раздела 4.2. При способе Б пароль задаёт `htpasswd` в nginx.
«Настройки» → «Доступ к веб-интерфейсу»: логин и новый пароль (не короче 8 символов) →
«Сохранить доступ».

Если пароль забыт, сбросьте его под пользователем NetAudit:

```bash
python3 -c "import sqlite3, pathlib; c = sqlite3.connect(pathlib.Path.home() / '.netaudit' / 'netaudit.db'); c.execute(\"DELETE FROM settings WHERE key IN ('web_auth_user', 'web_auth_password_hash')\"); c.commit()"
```

После этого перезапустите NetAudit: новый пароль появится в логе, как в разделе 4.2.

## 11. Аудит по расписанию с уведомлениями

Например: каждую ночь проверять серверы и присылать в Telegram сообщение, если что-то сломалось
или появились новые проблемы.

Нужно заранее:
- Telegram настроен (раздел 10.2);
- SSH-ключ без пароля (раздел 7);
- sudo без пароля для нужных команд (раздел 7);
- файл хостов с абсолютными путями к ключам (раздел 9).

**Шаг 1.** Под пользователем службы (`netaudit`, не root), из `~/netaudit`:

```bash
python3 netaudit.py setup-timer --name daily --on-calendar daily --hosts-file /home/netaudit/hosts.json server_audit ssh_hardening kernel_hardening
```

Команда всё проверит и создаст в текущем каталоге два файла:
`netaudit-audit-daily.service` и `netaudit-audit-daily.timer`. Сама она ничего не устанавливает.
`--on-calendar` — расписание systemd, например `daily`, `Mon..Fri *-*-* 03:30:00`, `weekly`.

**Шаг 2.** Установите их командами, которые она напечатала:

```bash
sudo cp netaudit-audit-daily.service netaudit-audit-daily.timer /etc/systemd/system/
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now netaudit-audit-daily.timer
```

**Шаг 3.** Проверьте, когда будет следующий запуск, и запустите один раз сейчас:

```bash
systemctl list-timers netaudit-audit-daily.timer
```

```bash
sudo systemctl start netaudit-audit-daily.service
```

```bash
journalctl -u netaudit-audit-daily.service -n 50
```

**Когда приходит сообщение:**
- проверка упала, сервер недоступен или данные собраны не полностью;
- появились новые проблемы уровня `medium` и выше (порог меняется флагом `--notify-min-severity`);
- первый запуск нашёл проблемы.

**Важно:**
- **Нет сообщения — не значит «всё в порядке».** Так же выглядит и остановившийся timer, поэтому
  иногда проверяйте `systemctl list-timers`.
- Сообщение уходит на серверы Telegram. В нём имена хостов, id и заголовки находок, без паролей и
  подробностей.
- Разумная частота — раз в сутки: тренды смотрят последние 200 отчётов всей базы.

Подробные правила — в [README, «Плановые аудиты и уведомления в Telegram»](../README.ru.md#плановые-аудиты-и-уведомления-в-telegram).

## 12. История, сводка и динамика

```bash
python3 netaudit.py history
```

```bash
python3 netaudit.py summary <номер-отчёта>
```

```bash
python3 netaudit.py trend
```

```bash
python3 netaudit.py trend ssh_hardening <IP-сервера>
```

- `history` — список отчётов.
- `summary` — сводка по хостам одного отчёта.
- `trend` — какие объекты уже запускались несколько раз.
- `trend <проверка> <объект>` — что изменилось. «not evaluated» значит, что в этот раз проверить
  не удалось, а не что проблема исправлена.

В браузере то же самое: «История» на вкладке «Аудит» и вкладка «Динамика».

## 13. Обновление

На сервере, под `netaudit`:

```bash
cd ~/netaudit && git pull origin main && sudo systemctl restart netaudit
```

Затем в браузере обновите страницу с очисткой кэша: `Ctrl+Shift+R`. Если в обновлении изменился
`requirements.txt`, перед перезапуском выполните `pip install -r requirements.txt
--break-system-packages`. Отчёты и настройки лежат вне каталога с кодом, и `git pull` их не
трогает.

## 14. Где лежат данные и как сделать резервную копию

Всё лежит в `~/.netaudit/` пользователя, под которым работает NetAudit:
- `netaudit.db` — отчёты и настройки, включая ключ AI и токен Telegram;
- `known_hosts` — ключи хостов проверенных серверов.

Каталог доступен только владельцу (`700`), база — тоже (`600`).

Резервная копия (можно при работающей службе, копия тоже получит права `600`):

```bash
(umask 077; python3 -c "import sqlite3, os; s = sqlite3.connect(os.path.expanduser('~/.netaudit/netaudit.db')); d = sqlite3.connect(os.path.expanduser('~/netaudit-backup.db')); s.backup(d); d.close(); s.close()")
```

В копии те же секреты, что в базе: храните её так же закрыто. Восстановление:

```bash
sudo systemctl stop netaudit
```

```bash
cp ~/netaudit-backup.db ~/.netaudit/netaudit.db
```

```bash
rm -f ~/.netaudit/netaudit.db-wal ~/.netaudit/netaudit.db-shm
```

```bash
sudo systemctl start netaudit
```

## 15. Типичные ошибки

| Что видно | Причина | Что делать |
|---|---|---|
| Страница не открывается с другого компьютера | Служба слушает только `127.0.0.1` | SSH-туннель или nginx (раздел 4.2) |
| Браузер просит логин и пароль, а вы их не знаете | При nginx пароль задаёт `htpasswd`, при `--host 0.0.0.0` — сам NetAudit | `sudo htpasswd /etc/nginx/.netaudit_htpasswd admin` или сброс из раздела 10.3 |
| `Auth not configured. Restart the server to generate credentials.` | Логин Web удалён из базы, пока сервер работал | Перезапустите NetAudit, новый пароль появится в логе |
| `[Errno 98] … address already in use` | Порт уже занят (например, запущен второй экземпляр) | Остановите старый или запустите с `--port 8080` |
| После обновления старый вид интерфейса | Браузер взял страницу из кэша | `Ctrl+Shift+R` |
| `could not connect: timed out` / `Unable to connect to port …` | Неверный адрес или порт, сервер выключен, мешает файрвол | Проверьте `ssh -i ~/.ssh/netaudit_audit audit@<IP-сервера> true` с машины NetAudit |
| `… presented a different SSH host key than the one NetAudit has on file …` | Сервер переустановлен или подменён | Убедитесь, что сервер ваш и ключ сменился законно, затем `ssh-keygen -R <IP-сервера> -f ~/.netaudit/known_hosts` (для порта не 22: `ssh-keygen -R '[<IP-сервера>]:2222' -f ~/.netaudit/known_hosts`) |
| `the private key … is encrypted` | У ключа есть пароль, а ssh-agent его не держит | В консоли — `ssh-add`; для службы и расписания — ключ без пароля (раздел 7) |
| `sudo: a password is required` | sudo на сервере хочет пароль | Введите «Пароль sudo» / `--sudo_password -` или настройте NOPASSWD (раздел 7) |
| `… is open to other accounts and its mode could not be changed …` | Файлы `~/.netaudit` принадлежат другому пользователю | Запускайте NetAudit от владельца файлов или выполните `chmod`, указанный в сообщении |
| mtr зависает, когда NetAudit работает службой | У mtr нет права на ICMP | `sudo setcap cap_net_raw+ep $(which mtr)` |
| `--notify: Telegram is not configured …` | Не заданы токен или chat ID | Раздел 10.2 |
| `Telegram: HTTP 401 (the bot token was rejected)` / `HTTP 400 (check the chat ID)` / `HTTP 403 …` | Неверный токен, неверный chat ID, бот не может писать в этот чат | Проверьте токен у BotFather и chat ID через `getUpdates`, напишите боту первым |
| «Set ANTHROPIC_API_KEY on the server running netaudit.» | Нет ключа AI | Раздел 10.1 |
| `uvicorn not installed` | Не установлены зависимости Web | `pip install -r requirements.txt --break-system-packages` |
