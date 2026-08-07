// Локализация NetAudit: русский и английский.
// UI-строки — по ключам; строки проверок — по id проверки.
// ВАЖНО: value у options на бэкенд уходит оригинальное (русское) — переводим только отображение.

const I18N = {
  ru: {
    // шапка / навигация
    'app.sub': 'универсальный сетевой аудит',
    'tab.audit': 'Аудит',
    'tab.trends': 'Динамика',
    'tab.settings': 'Настройки',
    'tab.help': 'Помощь',
    'donate': '☕ Поддержать',
    // пресеты
    'presets.title': 'ПРЕСЕТЫ',
    // категории
    'cat.network': 'Сеть',
    'cat.site': 'Сайт',
    'cat.security': 'Безопасность',
    'cat.performance': 'Производительность',
    'cat.server': 'Сервер (SSH)',
    'cat.capture': 'Захват трафика',
    // кнопки/статусы аудита
    'run': 'Запустить аудит',
    'run.stop': '■ Остановить',
    'save.preset': 'Сохранить как пресет',
    'force.async': 'принудительно выполнять в фоне',
    'history': 'История',
    'ai.analyze': 'AI-анализ: что делать',
    'select.hint': 'Выбери проверки слева и запусти аудит.',
    'report.here': 'Здесь появится отчёт',
    'status.start': 'Запуск…',
    'status.stopping': 'Останавливаю…',
    'status.stopped': 'Остановлено',
    'status.done': 'Готово',
    'live.running': 'Выполняется…',
    'live.stream': 'живой поток',
    'live.stopped': 'Остановлено — накопленные данные',
    'live.saved': '(график сохранён)',
    'missing': 'нет',
    'presets.bar.title': 'Пресеты',
    'preset.applied': 'Применён пресет: ',
    'preset.select.first': 'Сначала выбери проверки.',
    'preset.name.prompt': 'Название пресета:',
    'preset.saved': 'Пресет «{name}» сохранён.',
    'preset.delete': 'удалить',
    'preset.none': 'Пресетов пока нет. Собери набор на вкладке «Аудит» и нажми «Сохранить как пресет».',
    // настройки
    'settings.api': 'Anthropic API ключ',
    'settings.thresholds': 'Пороги выполнения',
    'settings.sync': 'Порог синхронности, сек',
    'settings.ema': 'EMA alpha',
    'settings.telegram': 'Telegram-алерты',
    'settings.tg.hint': 'Для будущих фоновых мониторингов: токен бота и chat_id.',
    'settings.save': 'Сохранить настройки',
    'settings.targets': 'Цели по умолчанию',
    'settings.targets.hint': 'Часто используемые IP/URL — подставляются в параметры проверок.',
    'settings.empty': 'Пока пусто',
    'settings.label': 'Метка',
    'settings.value': 'Значение',
    'settings.type': 'Тип',
    'settings.rep': 'Списки репутации (для анализа трафика)',
    'settings.rep.hint': 'Белый список — адреса/домены, которым доверяешь (не флагятся). Чёрный — заведомо плохие (всегда опасно). Можно IP, подсеть (1.2.3.0/24) или часть домена.',
    'settings.rep.pattern': 'Паттерн',
    'settings.rep.list': 'Список',
    'settings.rep.note': 'Заметка',
    'settings.rep.black': 'чёрный',
    'settings.rep.white': 'белый',
    'settings.tools': 'Инструменты системы',
    'settings.tools.hint': 'Какие внешние утилиты установлены. Недостающие можно поставить кнопкой (нужны права sudo на сервере).',
    'settings.presets': 'Пресеты',
    'settings.presets.hint': 'Сохранённые наборы проверок. Клик по пресету на вкладке «Аудит» применяет его.',
    'tool.installed': 'установлен',
    'tool.missing': 'нет',
    'tool.install': 'установить',
    'delete': 'удалить',
    'open': 'открыть',
  },
  en: {
    'app.sub': 'universal network audit',
    'tab.audit': 'Audit',
    'tab.trends': 'Trends',
    'tab.settings': 'Settings',
    'tab.help': 'Help',
    'donate': '☕ Donate',
    'presets.title': 'PRESETS',
    'cat.network': 'Network',
    'cat.site': 'Site',
    'cat.security': 'Security',
    'cat.performance': 'Performance',
    'cat.server': 'Server (SSH)',
    'cat.capture': 'Traffic capture',
    'run': 'Run audit',
    'run.stop': '■ Stop',
    'save.preset': 'Save as preset',
    'force.async': 'force background execution',
    'history': 'History',
    'ai.analyze': 'AI analysis: what to do',
    'select.hint': 'Select checks on the left and run the audit.',
    'report.here': 'The report will appear here',
    'status.start': 'Starting…',
    'status.stopping': 'Stopping…',
    'status.stopped': 'Stopped',
    'status.done': 'Done',
    'live.running': 'Running…',
    'live.stream': 'live stream',
    'live.stopped': 'Stopped — collected data',
    'live.saved': '(chart preserved)',
    'missing': 'missing',
    'presets.bar.title': 'Presets',
    'preset.applied': 'Preset applied: ',
    'preset.select.first': 'Select checks first.',
    'preset.name.prompt': 'Preset name:',
    'preset.saved': 'Preset "{name}" saved.',
    'preset.delete': 'delete',
    'preset.none': 'No presets yet. Build a set on the "Audit" tab and click "Save as preset".',
    'settings.api': 'Anthropic API key',
    'settings.thresholds': 'Execution thresholds',
    'settings.sync': 'Sync threshold, sec',
    'settings.ema': 'EMA alpha',
    'settings.telegram': 'Telegram alerts',
    'settings.tg.hint': 'For future background monitoring: bot token and chat_id.',
    'settings.save': 'Save settings',
    'settings.targets': 'Default targets',
    'settings.targets.hint': 'Frequently used IPs/URLs — auto-filled into check parameters.',
    'settings.empty': 'Empty for now',
    'settings.label': 'Label',
    'settings.value': 'Value',
    'settings.type': 'Type',
    'settings.rep': 'Reputation lists (for traffic analysis)',
    'settings.rep.hint': 'Allowlist — addresses/domains you trust (never flagged). Blocklist — known-bad (always dangerous). Accepts IP, subnet (1.2.3.0/24) or part of a domain.',
    'settings.rep.pattern': 'Pattern',
    'settings.rep.list': 'List',
    'settings.rep.note': 'Note',
    'settings.rep.black': 'block',
    'settings.rep.white': 'allow',
    'settings.tools': 'System tools',
    'settings.tools.hint': 'Which external utilities are installed. Missing ones can be installed with a button (requires sudo on the server).',
    'settings.presets': 'Presets',
    'settings.presets.hint': 'Saved check sets. Click a preset on the "Audit" tab to apply it.',
    'tool.installed': 'installed',
    'tool.missing': 'missing',
    'tool.install': 'install',
    'delete': 'delete',
    'open': 'open',
  },
};

// Переводы проверок по id: label, desc, params (по имени), опции select (по оригинальному значению)
const I18N_CHECKS = {
  mtr: {
    label: { en: 'MTR (ICMP traceroute)' },
    desc: { en: 'Loss and latency per hop. Set the run time in seconds directly: 45 = 45 sec, 300 = 5 min, 3600 = 1 hour, 7200 = 2 hours.' },
    params: { target: { en: 'Target (IP/host)' }, duration_sec: { en: 'Duration, sec' } },
  },
  tcptraceroute: {
    label: { en: 'TCP traceroute' },
    desc: { en: 'TCP SYN instead of ICMP — refutes the ISP excuse "ICMP is just deprioritized". Default 8 hops: usually enough to catch the provider, and beyond that internet nodes often stay silent to TCP traceroute and only waste time.' },
    params: { target: { en: 'Target (IP/host)' }, port: { en: 'Port' }, max_hops: { en: 'Max hops' } },
  },
  ping: {
    label: { en: 'Ping' },
    desc: { en: 'Basic loss and RTT check.' },
    params: { target: { en: 'Target' }, count: { en: 'Packets' } },
  },
  dig: {
    label: { en: 'DNS (dig)' },
    desc: { en: 'Detailed DNS: server, TTL, query time.' },
    params: { hostname: { en: 'Domain' }, record_type: { en: 'Record type' } },
  },
  arping: {
    label: { en: 'ARPing (L2, local network)' },
    desc: { en: 'L2 check within the local subnet (not over the internet).' },
    params: { target: { en: 'IP in local subnet' }, count: { en: 'Packets' } },
  },
  ssl: {
    label: { en: 'SSL/TLS certificate' },
    desc: { en: 'Protocol, cipher, certificate chain, expiry. auto = openssl if available, else python.' },
    params: { url: { en: 'URL' }, method: { en: 'Tool' } },
  },
  http: {
    label: { en: 'HTTP timings' },
    desc: { en: 'Timings by phase: DNS / TCP connect / TLS / TTFB. auto = curl if available, else python.' },
    params: { url: { en: 'URL' }, method: { en: 'Tool' } },
  },
  security_headers: {
    label: { en: 'Security headers' },
    desc: { en: 'HSTS, X-Frame-Options, X-Content-Type-Options, CSP.' },
    params: { url: { en: 'URL' } },
  },
  ports: {
    label: { en: 'Open ports' },
    desc: { en: 'Listening TCP/UDP ports (ss).' },
    params: {},
  },
  firewall: {
    label: { en: 'Firewall' },
    desc: { en: 'ufw status / nftables rule count.' },
    params: {},
  },
  performance: {
    label: { en: 'CPU / RAM / disk' },
    desc: { en: 'System resource usage (psutil).' },
    params: {},
  },
  ssh_audit: {
    label: { en: 'SSH server audit' },
    desc: { en: 'Read-only audit of a remote server: ports, firewall, fail2ban, login logs.' },
    params: { host: { en: 'Host' }, user: { en: 'User' }, port: { en: 'Port' }, key_path: { en: 'Key path' }, password: { en: 'Password (if no key)' } },
  },
  iperf: {
    label: { en: 'iperf3 throughput' },
    desc: { en: 'Real upload/download speed (needs `iperf3 -s` on the other end).' },
    params: { server: { en: 'iperf3 server' }, port: { en: 'Port' }, duration: { en: 'Seconds' } },
  },
  tshark_capture: {
    label: { en: 'Traffic capture (tshark)' },
    desc: { en: 'Passive capture with the Wireshark engine + suspicion scoring of destinations. Needs root.' },
    params: { interface: { en: 'Interface' }, duration: { en: 'Duration, sec' }, bpf_filter: { en: 'BPF filter (e.g. host 192.168.88.55)' }, analyze_threats: { en: 'Threat analysis' } },
    options: { 'да': { en: 'yes' }, 'да+whois': { en: 'yes+whois' }, 'нет': { en: 'no' } },
  },
  mikrotik_sniffer: {
    label: { en: 'Device traffic via MikroTik' },
    desc: { en: 'Where a device\'s traffic goes via the router + suspicion scoring of destinations. Sees ALL of the device\'s traffic.' },
    params: { router: { en: 'Router IP' }, user: { en: 'User' }, password: { en: 'Password' }, target_ip: { en: 'Device IP (phone)' }, port: { en: 'SSH port' }, analyze_threats: { en: 'Threat analysis' } },
    options: { 'да': { en: 'yes' }, 'да+whois': { en: 'yes+whois' }, 'нет': { en: 'no' } },
  },
  server_audit: {
    label: { en: 'Server security audit (SSH)' },
    desc: { en: 'Full server security audit over SSH: nginx, fail2ban, firewall, MySQL, SSH hardening. Read-only.' },
    params: { host: { en: 'Host' }, user: { en: 'User' }, port: { en: 'SSH port' }, key_path: { en: 'Key path' }, password: { en: 'Password (if no key)' } },
  },
  cve_audit: {
    label: { en: 'CVE audit of installed software (SSH)' },
    desc: { en: 'Collects installed software versions (nginx, ssh, mysql/mariadb, php, kernel, wordpress) over SSH '
      + 'and cross-checks them against the OSV.dev vulnerability database. AI analysis cross-references found CVEs '
      + 'with the actual service config and tells you what really needs updating.' },
    params: { host: { en: 'Host' }, user: { en: 'User' }, port: { en: 'SSH port' }, key_path: { en: 'Key path' }, password: { en: 'Password (if no key)' } },
  },
  web_security_external: {
    label: { en: 'External web audit (no access)' },
    desc: { en: 'Site audit from the outside: security headers, outdated TLS, version leaks, exposure of .git/.env/backups.' },
    params: { url: { en: 'Site URL' } },
  },
  sql_injection: {
    label: { en: 'SQL injection check' },
    desc: { en: 'Passive input-point discovery always; active testing via sqlmap only with authorization confirmation.' },
    params: { url: { en: 'URL (with params, e.g. ?id=1)' }, authorization: { en: 'Test authorization' }, mode: { en: 'Mode' }, crawl: { en: 'Follow links (sqlmap crawl)' } },
    options: {
      'нет': { en: 'no' },
      'да — я владелец / есть письменное разрешение': { en: 'yes — I am the owner / have written permission' },
      'пассив (только точки ввода)': { en: 'passive (input points only)' },
      'пассив + sqlmap': { en: 'passive + sqlmap' },
      'да': { en: 'yes' },
    },
  },
  lynis_audit: {
    label: { en: 'Lynis security audit (SSH)' },
    desc: { en: 'Server security audit via Lynis (hardening index + findings) over SSH. Read-only.' },
    params: {
      host: { en: 'Host' }, user: { en: 'User' }, port: { en: 'SSH port' },
      key_path: { en: 'Key path' }, password: { en: 'Password (if no key)' },
      auto_install: { en: 'Install lynis if missing' },
    },
  },
  dns_audit: {
    label: { en: 'DNS domain audit' },
    desc: { en: 'SPF/DKIM/DMARC/DNSSEC + dangling CNAME detection (subdomain takeover). DNS queries only, no server access.' },
    params: {
      domain: { en: 'Domain' },
      subdomains_to_check: { en: 'Subdomains to check for CNAME (comma-separated)' },
    },
  },
};

let CURRENT_LANG = 'en';

const PRESET_NAME_TR = {
  '🌐 Неполадки в сети': { en: '🌐 Network issues' },
  '🔒 Аудит сайта (снаружи)': { en: '🔒 Site audit (external)' },
  '🖥️ Аудит сервера (SSH)': { en: '🖥️ Server audit (SSH)' },
  '🛡️ Аудит сервера + CVE (SSH)': { en: '🛡️ Server audit + CVE (SSH)' },
  '📡 Куда уходит трафик': { en: '📡 Where traffic goes' },
};

function trPresetName(name) {
  if (CURRENT_LANG === 'ru') return name;
  return (PRESET_NAME_TR[name] && PRESET_NAME_TR[name][CURRENT_LANG]) || name;
}

function detectLang() {
  const nav = (navigator.language || 'en').toLowerCase();
  return nav.startsWith('ru') ? 'ru' : 'en';
}

function t(key) {
  const d = I18N[CURRENT_LANG] || I18N.ru;
  return d[key] !== undefined ? d[key] : (I18N.ru[key] !== undefined ? I18N.ru[key] : key);
}

// перевод строк проверки: возвращает {label, description, params:{name->label}, optLabel(orig)}
function tCheck(check) {
  const tr = I18N_CHECKS[check.id];
  if (!tr || CURRENT_LANG === 'ru') {
    return {
      label: check.label,
      description: check.description,
      paramLabel: (p) => p.label,
      optLabel: (o) => o,
    };
  }
  return {
    label: (tr.label && tr.label[CURRENT_LANG]) || check.label,
    description: (tr.desc && tr.desc[CURRENT_LANG]) || check.description,
    paramLabel: (p) => (tr.params && tr.params[p.name] && tr.params[p.name][CURRENT_LANG]) || p.label,
    optLabel: (o) => (tr.options && tr.options[o] && tr.options[o][CURRENT_LANG]) || o,
  };
}
