# 🛰️ Attack Surface Recon Stack

> `attack-surface.sh` — устойчивый OSINT / Attack Surface Recon pipeline для аудита **своих доменов** или явно разрешённого scope.

Скрипт автоматизирует сбор поддоменов, проверку живых HTTP/HTTPS-сервисов и безопасный запуск Nuclei по найденным URL.

---

## ⚠️ Legal / Scope Notice

Этот инструмент предназначен **только** для:

- ✅ своих доменов;
- ✅ своей инфраструктуры;
- ✅ разрешённого security audit / pentest scope;
- ✅ инвентаризации внешней поверхности;
- ✅ поиска забытых поддоменов, панелей, API, dev/stage окружений.

Не запускай скрипт по чужой инфраструктуре без разрешения.

---

## 🧩 Что делает скрипт

```text
seeds.txt
   │
   ▼
root-candidates.txt
   │
   ├── subfinder  ─┐
   ├── amass       ├──► all-hostnames.txt
   └── crt.sh     ─┘
                         │
                         ▼
                       httpx
                         │
                         ▼
                    live-urls.txt
                         │
                         ▼
                       nuclei
                         │
                         ▼
                      report.md
```

---

## 🔧 Используемые инструменты

| Инструмент | Назначение |
|---|---|
| `subfinder` | Быстрый passive subdomain discovery |
| `amass` | Глубокий passive OSINT / DNS enum |
| `crt.sh` | Certificate Transparency lookup |
| `httpx` | Проверка живых HTTP/HTTPS сервисов |
| `nuclei` | Проверка live URL по шаблонам |
| `dig` | DNS summary root-доменов |
| `whois` | WHOIS summary root-доменов |
| `jq` | JSON parsing |
| `curl` | HTTP requests к crt.sh |

---

## 🚀 Главные особенности v4

```text
╭────────────────────────────────────────────────────────────╮
│ attack-surface.sh v4                                       │
├────────────────────────────────────────────────────────────┤
│ ✔ Один упавший инструмент не валит весь pipeline           │
│ ✔ Amass работает best-effort                               │
│ ✔ crt.sh устойчив к timeout / HTML / пустым ответам        │
│ ✔ httpx запускается как ProjectDiscovery httpx             │
│ ✔ httpx использует -rl, а не -rate                         │
│ ✔ Nuclei запускается только по live-urls.txt               │
│ ✔ Для Nuclei v3.x используется -j / JSONL                  │
│ ✔ Для Nuclei exclude-tags используется -etags              │
│ ✔ Все результаты складываются в runs/YYYY-mm-dd_HH-MM-SS   │
│ ✔ latest указывает на последний завершённый запуск         │
│ ✔ Есть delta между текущим и прошлым запуском              │
│ ✔ Автоматически генерируется report.md                     │
╰────────────────────────────────────────────────────────────╯
```

---

## 📦 Установка зависимостей

### Ubuntu / Debian / Kali

```bash
apt update
apt install -y \
  curl \
  jq \
  dnsutils \
  whois \
  git \
  unzip \
  golang-go \
  ca-certificates
```

---

## 🧰 Установка ProjectDiscovery tools

### Subfinder

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
ln -sf /root/go/bin/subfinder /usr/local/bin/subfinder
```

### httpx

> Важно: нужен именно **ProjectDiscovery httpx**, а не Python HTTPX CLI.

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
ln -sf /root/go/bin/httpx /usr/local/bin/httpx
```

Проверка:

```bash
type -a httpx
httpx -version
httpx -h | grep -E -- '-l, -list|-td, -tech-detect|-p, -ports|-j, -json'
```

Правильный вывод содержит:

```text
projectdiscovery.io
-l, -list
-td, -tech-detect
-p, -ports
-j, -json
```

### Nuclei

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
ln -sf /root/go/bin/nuclei /usr/local/bin/nuclei
```

Проверка:

```bash
type -a nuclei
nuclei -version
nuclei -h | grep -E -- '-l, -list|-s, -severity|-rl, -rate-limit|-j, -jsonl|-etags'
```

Обновление шаблонов:

```bash
nuclei -update-templates
```

---

## 🧰 Установка Amass

### Через apt

```bash
apt install -y amass
```

### Через Go

```bash
go install -v github.com/owasp-amass/amass/v5/cmd/amass@main
ln -sf /root/go/bin/amass /usr/local/bin/amass
```

Проверка:

```bash
amass -version
```

---

## ⚠️ Известный нюанс Amass / libpostal

На некоторых системах Amass может падать с ошибкой:

```text
ERR Could not find parser model file of known type
ERR Error loading address parser module
The Amass engine did not respond
```

В v4 это **не критично**:

```text
Amass падает → скрипт пишет warning → создаёт пустой amass-subdomains.txt → pipeline идёт дальше
```

Для обычного recon можно запускать без Amass:

```bash
./attack-surface.sh \
  -p honestvpn \
  -s /root/seeds.txt \
  --org-patterns 'domen-1|domen-2|domen-3|domen-4|honest' \
  --skip-amass
```

---

## 📁 Подготовка seeds.txt

Создай файл со своими root-доменами:

```bash
cat > /root/seeds.txt <<'EOF'
domen-1.ru
domen-2.com
domen-3.net
domen-4.org
EOF
```

Проверь:

```bash
cat /root/seeds.txt
```

---

## 🏁 Быстрый старт

```bash
chmod +x attack-surface.sh
bash -n attack-surface.sh

./attack-surface.sh \
  -p honestvpn \
  -s /root/seeds.txt \
  --org-patterns 'domen-1|domen-2|domen-3|domen-4|honest'
```

---

## 🧪 Режимы запуска

### 1. Полный запуск

```bash
./attack-surface.sh \
  -p honestvpn \
  -s /root/seeds.txt \
  --org-patterns 'domen-1|domen-2|domen-3|domen-4|honest' \
  --update-templates
```

Запускается:

```text
subfinder → amass → crt.sh → dns/whois → httpx → nuclei → delta → report.md
```

---

### 2. Быстрый стабильный запуск без Amass

```bash
./attack-surface.sh \
  -p honestvpn \
  -s /root/seeds.txt \
  --org-patterns 'domen-1|domen-2|domen-3|domen-4|honest' \
  --skip-amass
```

---

### 3. Быстрый запуск без Amass и crt.sh

```bash
./attack-surface.sh \
  -p honestvpn \
  -s /root/seeds.txt \
  --org-patterns 'domen-1|domen-2|domen-3|domen-4|honest' \
  --skip-amass \
  --skip-crtsh
```

---

### 4. Запуск без Nuclei

```bash
./attack-surface.sh \
  -p honestvpn \
  -s /root/seeds.txt \
  --org-patterns 'domen-1|domen-2|domen-3|domen-4|honest' \
  --skip-nuclei
```

---

### 5. Рекомендуемый быстрый режим Nuclei: high/critical

```bash
./attack-surface.sh \
  -p honestvpn \
  -s /root/seeds.txt \
  --org-patterns 'domen-1|domen-2|domen-3|domen-4|honest' \
  --nuclei-severity high,critical
```

---

### 6. Средний режим Nuclei

```bash
./attack-surface.sh \
  -p honestvpn \
  -s /root/seeds.txt \
  --org-patterns 'domen-1|domen-2|domen-3|domen-4|honest' \
  --nuclei-severity medium,high,critical
```

---

### 7. Полный Nuclei scan

```bash
./attack-surface.sh \
  -p honestvpn \
  -s /root/seeds.txt \
  --org-patterns 'domen-1|domen-2|domen-3|domen-4|honest' \
  --nuclei-severity low,medium,high,critical
```

⚠️ Может выполняться долго.

---

### 8. Запуск с явным указанием бинарников

```bash
HTTPX_BIN=/usr/local/bin/httpx \
NUCLEI_BIN=/usr/local/bin/nuclei \
./attack-surface.sh \
  -p honestvpn \
  -s /root/seeds.txt \
  --org-patterns 'domen-1|domen-2|domen-3|domen-4|honest'
```

---

### 9. Запуск с кастомными портами httpx

```bash
./attack-surface.sh \
  -p honestvpn \
  -s /root/seeds.txt \
  --ports 80,443,8080,8443,3000,4000,9090,9100 \
  --org-patterns 'domen-1|domen-2|domen-3|domen-4|honest'
```

---

### 10. Запуск с меньшей скоростью

```bash
./attack-surface.sh \
  -p honestvpn \
  -s /root/seeds.txt \
  --httpx-rate 20 \
  --nuclei-rate 10 \
  --org-patterns 'domen-1|domen-2|domen-3|domen-4|honest'
```

---

## 🧯 Ограничение времени через timeout

Если Nuclei работает слишком долго:

```bash
timeout 45m ./attack-surface.sh \
  -p honestvpn \
  -s /root/seeds.txt \
  --org-patterns 'domen-1|domen-2|domen-3|domen-4|honest' \
  --nuclei-severity high,critical
```

Глубокий ночной прогон:

```bash
timeout 2h ./attack-surface.sh \
  -p honestvpn \
  -s /root/seeds.txt \
  --org-patterns 'domen-1|domen-2|domen-3|domen-4|honest' \
  --update-templates
```

---

## 🗂️ Структура результата

После запуска создаётся каталог:

```text
~/osint-recon/<project>/runs/YYYY-mm-dd_HH-MM-SS/
```

Пример:

```text
/root/osint-recon/honestvpn/runs/2026-05-08_12-47-45/
```

Также создаётся symlink:

```text
/root/osint-recon/honestvpn/latest
```

Он указывает на последний завершённый запуск.

---

## 📁 Дерево каталогов

```text
/root/osint-recon/honestvpn/
├── latest -> runs/2026-05-08_12-47-45
└── runs/
    └── 2026-05-08_12-47-45/
        ├── 00-input/
        │   └── seeds.txt
        ├── 01-roots/
        │   └── root-candidates.txt
        ├── 02-sources/
        │   ├── subfinder/
        │   ├── amass/
        │   ├── crtsh/
        │   └── all-hostnames.txt
        ├── 03-dns/
        │   └── dns-summary.txt
        ├── 04-whois/
        ├── 05-live/
        │   ├── httpx-live.jsonl
        │   ├── httpx-live.tsv
        │   ├── httpx-live-pretty.txt
        │   └── live-urls.txt
        ├── 06-nuclei/
        │   ├── nuclei-results.jsonl
        │   ├── nuclei-results.tsv
        │   └── nuclei-results-pretty.txt
        ├── 07-reports/
        │   ├── report.md
        │   ├── root-classification.csv
        │   └── versions.txt
        ├── 08-delta/
        │   ├── added-hostnames.txt
        │   ├── removed-hostnames.txt
        │   ├── added-live-urls.txt
        │   └── removed-live-urls.txt
        ├── logs/
        │   ├── subfinder.log
        │   ├── amass.log
        │   ├── crtsh.log
        │   ├── httpx.log
        │   ├── nuclei.log
        │   └── nuclei-update-templates.log
        ├── all-hostnames.txt
        └── live-urls.txt
```

---

## 📌 Главные файлы

### `all-hostnames.txt`

```bash
cat /root/osint-recon/honestvpn/latest/all-hostnames.txt
```

### `live-urls.txt`

```bash
cat /root/osint-recon/honestvpn/latest/live-urls.txt
```

### `httpx-live-pretty.txt`

```bash
cat /root/osint-recon/honestvpn/latest/05-live/httpx-live-pretty.txt
```

### `nuclei-results-pretty.txt`

```bash
cat /root/osint-recon/honestvpn/latest/06-nuclei/nuclei-results-pretty.txt
```

### `report.md`

```bash
cat /root/osint-recon/honestvpn/latest/07-reports/report.md
```

---

## 📊 Что попадает в report.md

```text
- root candidates count
- subfinder count
- amass count
- crt.sh count
- all hostnames count
- live HTTP/HTTPS URLs count
- nuclei findings total
- critical/high/medium/low counters
- quick view httpx
- quick view nuclei
- added hostnames
- added live URLs
```

---

## 🔁 Delta между запусками

### Новые hostnames

```bash
cat /root/osint-recon/honestvpn/latest/08-delta/added-hostnames.txt
```

### Пропавшие hostnames

```bash
cat /root/osint-recon/honestvpn/latest/08-delta/removed-hostnames.txt
```

### Новые live URL

```bash
cat /root/osint-recon/honestvpn/latest/08-delta/added-live-urls.txt
```

### Пропавшие live URL

```bash
cat /root/osint-recon/honestvpn/latest/08-delta/removed-live-urls.txt
```

---

## 🧠 Как читать результаты

Пример строки `httpx`:

```text
200 https://panel.example.com nginx HSTS|WebAssembly Remnawave
```

Интерпретация:

```text
status_code     200
url             https://panel.example.com
server          nginx
tech            HSTS, WebAssembly
title           Remnawave
```

Что смотреть первым:

```text
- панели управления;
- Grafana;
- Prometheus;
- Swagger / OpenAPI;
- MinIO / S3;
- admin / dashboard / login;
- 401 / Basic Auth;
- 403, который должен быть 404;
- случайные 8080 / 8443;
- webserver banners;
- nginx version leaks;
- Ubuntu / framework leaks;
- fake dev/stage/test hostnames.
```

---

## 🧪 Проверка отдельными командами

### Subfinder

```bash
subfinder -dL /root/seeds.txt -all -recursive -silent
```

### Amass

```bash
amass enum -passive -df /root/seeds.txt -o /tmp/amass-test.txt
cat /tmp/amass-test.txt
```

### crt.sh

```bash
curl -fsSL 'https://crt.sh/?q=%25.domen-1.ru&output=json' \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | tr '\r' '\n' \
  | sort -u
```

### httpx

```bash
cat /root/osint-recon/honestvpn/latest/all-hostnames.txt \
  | httpx -silent -json -status-code -title -tech-detect -web-server -ports 80,443,8080,8443
```

### Nuclei

```bash
nuclei \
  -l /root/osint-recon/honestvpn/latest/live-urls.txt \
  -s high,critical \
  -etags fuzz,dos,bruteforce,intrusive \
  -j \
  -o /tmp/nuclei-test.jsonl
```

---

## 🧯 Troubleshooting

### `httpx` пишет `No such option: -l`

Причина: запускается Python HTTPX CLI, а не ProjectDiscovery httpx.

Проверка:

```bash
type -a httpx
httpx --help | head -40
```

Если видишь:

```text
Usage: httpx [OPTIONS] URL
```

это не тот `httpx`.

Фикс:

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
ln -sf /root/go/bin/httpx /usr/local/bin/httpx
hash -r
```

---

### `httpx` пишет `flag provided but not defined: -rate`

У ProjectDiscovery httpx правильный флаг:

```text
-rl
```

а не:

```text
-rate
```

В v4 используется:

```bash
-rl "$HTTPX_RATE"
```

---

### Nuclei пишет `flag provided but not defined: -json`

В Nuclei v3.x JSONL-флаг:

```bash
-j
```

а не:

```bash
-json
```

Правильный запуск:

```bash
nuclei -l live-urls.txt -s high,critical -j -o nuclei-results.jsonl
```

---

### Nuclei долго работает

Это нормально. Nuclei — самый тяжёлый этап pipeline.

Ускорить:

```bash
./attack-surface.sh \
  -p honestvpn \
  -s /root/seeds.txt \
  --org-patterns 'domen-1|domen-2|domen-3|domen-4|honest' \
  --nuclei-severity high,critical
```

Ограничить временем:

```bash
timeout 45m ./attack-surface.sh \
  -p honestvpn \
  -s /root/seeds.txt \
  --org-patterns 'domen-1|domen-2|domen-3|domen-4|honest'
```

Проверить, что Nuclei работает:

```bash
ps -eo pid,etime,stat,pcpu,pmem,cmd \
  | grep -E 'attack-surface|nuclei' \
  | grep -v grep
```

Смотреть лог:

```bash
tail -f /root/osint-recon/honestvpn/latest/logs/nuclei.log
```

---

### Amass падает с libpostal

Ошибка:

```text
ERR Could not find parser model file of known type
ERR Error loading address parser module
The Amass engine did not respond
```

Решение:

```bash
./attack-surface.sh \
  -p honestvpn \
  -s /root/seeds.txt \
  --skip-amass
```

---

### crt.sh иногда ничего не возвращает

Это нормально. `crt.sh` может:

```text
- таймаутиться;
- отдавать HTML вместо JSON;
- rate-limit'ить;
- возвращать пустой ответ.
```

Скрипт работает best-effort и продолжает pipeline.

---

### IP вида `198.18.x.x`

Если в результатах `httpx` видишь:

```text
198.18.x.x
```

это часто fake-ip DNS от Clash / Mihomo / локального прокси.

Проверка:

```bash
cat /etc/resolv.conf
resolvectl status 2>/dev/null || true

dig +short panel.domen-1.ru
dig @1.1.1.1 +short panel.domen-1.ru
dig @8.8.8.8 +short panel.domen-1.ru
```

Для чистого внешнего recon лучше запускать скрипт на сервере без fake-ip DNS.

---

## 🧹 Очистка старых запусков

Посмотреть размер:

```bash
du -sh /root/osint-recon/honestvpn
```

Удалить runs старше 30 дней:

```bash
find /root/osint-recon/honestvpn/runs \
  -mindepth 1 \
  -maxdepth 1 \
  -type d \
  -mtime +30 \
  -print \
  -exec rm -rf {} \;
```

---

## ⏰ Cron example

Ежедневный быстрый запуск в 04:30:

```bash
crontab -e
```

```cron
30 4 * * * /root/attack-surface.sh -p honestvpn -s /root/seeds.txt --org-patterns 'domen-1|domen-2|domen-3|domen-4|honest' --nuclei-severity high,critical >> /root/attack-surface-cron.log 2>&1
```

---

## 🧭 Systemd timer example

### Wrapper

```bash
cat > /root/run-attack-surface.sh <<'EOF'
#!/usr/bin/env bash
/root/attack-surface.sh \
  -p honestvpn \
  -s /root/seeds.txt \
  --org-patterns 'domen-1|domen-2|domen-3|domen-4|honest' \
  --nuclei-severity high,critical
EOF

chmod +x /root/run-attack-surface.sh
```

### Service

```bash
cat > /etc/systemd/system/attack-surface.service <<'EOF'
[Unit]
Description=Attack Surface Recon

[Service]
Type=oneshot
ExecStart=/root/run-attack-surface.sh
EOF
```

### Timer

```bash
cat > /etc/systemd/system/attack-surface.timer <<'EOF'
[Unit]
Description=Run Attack Surface Recon daily

[Timer]
OnCalendar=*-*-* 04:30:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
```

Enable:

```bash
systemctl daemon-reload
systemctl enable --now attack-surface.timer
systemctl list-timers | grep attack-surface
```

Logs:

```bash
journalctl -u attack-surface.service -n 100 --no-pager
```

---

## 🧪 Recommended workflow

```text
╭────────────────────────────────────────────╮
│ 1. Быстрый daily scan                      │
│    subfinder + crt.sh + httpx + nuclei HC  │
╰────────────────────────────────────────────╯
                 │
                 ▼
╭────────────────────────────────────────────╮
│ 2. Смотреть delta                          │
│    added-hostnames / added-live-urls       │
╰────────────────────────────────────────────╯
                 │
                 ▼
╭────────────────────────────────────────────╮
│ 3. Проверять новые панели / API / 8080     │
│    вручную и через Nuclei                  │
╰────────────────────────────────────────────╯
                 │
                 ▼
╭────────────────────────────────────────────╮
│ 4. Чистить exposed services                │
│    nginx allowlist / basic auth / firewall │
╰────────────────────────────────────────────╯
```

---

## 🔐 Практические рекомендации

```text
- панели управления лучше закрывать allowlist'ом;
- Prometheus/Grafana не держать публично без auth;
- 8080/8443 лучше не светить наружу без необходимости;
- nginx version лучше скрывать;
- 403 не всегда достаточно — иногда лучше 404 или allowlist;
- Basic Auth лучше комбинировать с IP allowlist;
- dev/test/stage hostnames лучше не публиковать в CT без необходимости;
- регулярно смотреть delta.
```

---

## ✅ Пример полного цикла

```bash
cat /root/seeds.txt

./attack-surface.sh \
  -p honestvpn \
  -s /root/seeds.txt \
  --org-patterns 'domen-1|domen-2|domen-3|domen-4|honest' \
  --nuclei-severity high,critical

cd /root/osint-recon/honestvpn/latest

cat 07-reports/report.md
cat 05-live/httpx-live-pretty.txt
cat 06-nuclei/nuclei-results-pretty.txt
cat 08-delta/added-hostnames.txt
cat 08-delta/added-live-urls.txt
```

---

## 🏷️ Exit behavior

Скрипт спроектирован как **best-effort pipeline**.

```text
subfinder упал   → warning → pipeline продолжается
amass упал       → warning → pipeline продолжается
crt.sh упал      → warning → pipeline продолжается
httpx пустой     → warning → nuclei пропускается
nuclei долгий    → можно ограничить timeout
nuclei упал      → warning → report всё равно создаётся
```

---

## 🧾 Minimal command set

```bash
cat > /root/seeds.txt <<'EOF'
domen-1.ru
domen-2.com
domen-3.net
domen-4.org
EOF

chmod +x attack-surface.sh
bash -n attack-surface.sh

./attack-surface.sh \
  -p honestvpn \
  -s /root/seeds.txt \
  --org-patterns 'domen-1|domen-2|domen-3|domen-4|honest' \
  --nuclei-severity high,critical

cd /root/osint-recon/honestvpn/latest
cat 07-reports/report.md
```

---

## 🛰️ ASCII Pipeline

```text
             ┌─────────────────────┐
             │      seeds.txt      │
             └──────────┬──────────┘
                        │
                        ▼
             ┌─────────────────────┐
             │ root-candidates.txt │
             └──────────┬──────────┘
                        │
        ┌───────────────┼────────────────┐
        │               │                │
        ▼               ▼                ▼
 ┌────────────┐   ┌────────────┐   ┌────────────┐
 │ subfinder  │   │   amass    │   │   crt.sh   │
 └─────┬──────┘   └─────┬──────┘   └─────┬──────┘
       │                │                │
       └────────────────┼────────────────┘
                        ▼
             ┌─────────────────────┐
             │  all-hostnames.txt  │
             └──────────┬──────────┘
                        │
                        ▼
             ┌─────────────────────┐
             │        httpx        │
             └──────────┬──────────┘
                        │
                        ▼
             ┌─────────────────────┐
             │    live-urls.txt    │
             └──────────┬──────────┘
                        │
                        ▼
             ┌─────────────────────┐
             │       nuclei        │
             └──────────┬──────────┘
                        │
                        ▼
             ┌─────────────────────┐
             │      report.md      │
             └─────────────────────┘
```

---

## 📌 Author notes

Этот стек лучше использовать как регулярный inventory / recon процесс:

```text
не один раз просканировал и забыл,
а периодически запускаешь,
смотришь delta,
и приводишь внешнюю поверхность в порядок.
```
