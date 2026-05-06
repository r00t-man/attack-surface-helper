# В разработке !!!


# attack-surface.sh

> Простая автоматизация OSINT / external attack surface discovery для своей доменной инфраструктуры на Kali Linux.

```text
   ___  _ _        _        _           _             
  / _ \| (_)_ __  | |_ __ _| |__   ___ | | ___   _    
 / /_)/| | | '_ \ | __/ _` | '_ \ / _ \| |/ / | | |   
/ ___/ | | | | | || || (_| | |_) | (_) |   <| |_| |   
\/     |_|_|_| |_| \__\__,_|_.__/ \___/|_|\_\\__,_|   

          OSINT attack surface helper
```

## Идея

Скрипт собирает доменную поверхность атаки вокруг твоих root‑доменов:

- берёт **seed‑список** твоих доменов;
- запускает:
  - `subfinder` (пассивный поиск поддоменов),
  - `amass enum -passive` (пассивное сканирование),
  - запросы к `crt.sh` (Certificate Transparency);
- всё склеивает в один список `all-hostnames.txt`;
- делает базовый **DNS/WHOIS‑чекап** и черновую классификацию root‑доменов по уверенности A/B/C.

Подходит для OSINT‑анализа своей инфраструктуры, внешнего периметра, подготовки к более глубокому сканированию. [habr](https://habr.com/ru/articles/802621/)

***

## ASCII‑схема пайплайна

```text
+-----------------------+
|      seeds.txt        |
|  (твои root-домены)   |
+----------+------------+
           |
           v
+-------------------------------+
|  attack-surface.sh           |
|  (оркестратор)               |
+----+------------+------------+
     |            |
     |            |
     v            v
+----------+   +----------------+
|subfinder |   | amass enum     |
| (passive)|   |   -passive     |
+-----+----+   +--------+-------+
      |                 |
      +--------+--------+
               |
               v
        +-------------+
        |  crt.sh     |
        | (CT-логи)   |
        +------+------+ 
               |
               v
      +-------------------+
      |  all-hostnames.txt|
      +---+-----------+---+
          |           |
          v           v
+---------------+  +-------------------+
| DNS checks    |  | WHOIS dumps       |
| dns-summary   |  | whois/*.txt       |
+-------+-------+  +---------+---------+
        |                    |
        +---------+----------+
                  |
                  v
      +-----------------------------+
      |  root-classification.csv    |
      |  (A/B/C по root-доменам)    |
      +-----------------------------+
```

***

## Установка

### 1. Зависимости

На Kali нужно:

```bash
sudo apt update
sudo apt install -y amass subfinder jq curl dnsutils whois
```

- `amass` и `subfinder` — ядро для поиска поддоменов и хостов. [kali](https://www.kali.org/tools/amass/)
- `jq` — парсинг JSON от `crt.sh`.
- `curl` — HTTP‑запросы к `crt.sh`.
- `dig` (в пакете `dnsutils`) — DNS‑чекап.
- `whois` — базовый WHOIS‑анализ.

### 2. Клонирование репозитория

# Пока не работает - код внизу в самом конце

```bash
git clone https://github.com/USERNAME/attack-surface-helper.git
cd attack-surface-helper
```

(подставь свой `USERNAME`/название репы). [docs.github](https://docs.github.com/ru/get-started/git-basics/set-up-git)

### 3. Сделать скрипт исполняемым

```bash
chmod +x attack-surface.sh
```

***

## Настройка seed‑доменов

Создай файл `seeds.txt` в корне репозитория:

```bash
cat > seeds.txt << 'EOF'
example.com
example.net
vpn-example.io
EOF
```

Рекомендуется:

- добавлять только **root‑домены** (`example.com`, а не `www.example.com`);
- включить все ключевые бренды / доменные зоны твоей экосистемы.

***

## Запуск

Скрипт всегда использует **абсолютный путь** до `seeds.txt`, чтобы не путаться с текущим каталогом.

```bash
./attack-surface.sh -p my-project -s "$(pwd)/seeds.txt"
```

- `-p my-project` — имя проекта; результаты уйдут в `~/osint-recon/my-project`.
- `-s /abs/path/to/seeds.txt` — путь до файла с доменами.

Пример для Kali (если репа в `/srv/sh`):

```bash
cd /srv/sh/attack-surface-helper
./attack-surface.sh -p vk-infra -s /srv/sh/attack-surface-helper/seeds.txt
```

***

## Что делает скрипт (по шагам с комментариями)

```bash
#!/usr/bin/env bash
set -euo pipefail
```

- `set -euo pipefail` — строгий режим bash, помогает ловить ошибки и пустые переменные. [securitylab](https://www.securitylab.ru/blog/personal/Neurosinaps/355407.php)

### Парсинг аргументов

```bash
usage() {
  echo "Usage: $0 -p project_name -s /absolute/path/to/seeds.txt"
}

PROJECT=""
SEEDS_FILE=""

while getopts "p:s:" opt; do
  case "$opt" in
    p) PROJECT="$OPTARG" ;;
    s) SEEDS_FILE="$OPTARG" ;;
    *) usage; exit 1 ;;
  esac
done
```

- `getopts` разбирает `-p` и `-s`.
- При ошибке выводит `usage` и выходит.

### Проверки и подготовка директории

```bash
if [[ -z "$PROJECT" || -z "$SEEDS_FILE" ]]; then
  usage
  exit 1
fi

if [[ ! -f "$SEEDS_FILE" ]]; then
  echo "[!] Seeds file not found: $SEEDS_FILE"
  exit 1
fi

SEEDS_FILE="$(readlink -f "$SEEDS_FILE")"

BASE_DIR="$HOME/osint-recon/$PROJECT"
mkdir -p "$BASE_DIR"
cd "$BASE_DIR"

echo "[+] Project directory: $BASE_DIR"
cp "$SEEDS_FILE" seeds.txt
```

- `readlink -f` превращает путь к seeds в абсолютный.
- Всё складывается в `~/osint-recon/<project>` — удобно, когда проектов много.

### 1. Формирование root‑кандидатов

```bash
echo "[+] Building root-candidates.txt from seeds..."
cat seeds.txt \
  | tr '[:upper:]' '[:lower:]' \
  | grep -Eo '([a-z0-9-]+\.)+[a-z]{2,}' \
  | sed 's/^\*\.//' \
  | sort -u > root-candidates.txt

echo "[+] Root candidates count:"
wc -l root-candidates.txt
```

- Нормализуем в нижний регистр.
- Вытаскиваем только валидные доменные строки.
- Убираем `*.` в начале (wildcard).
- Дедупликация через `sort -u`.

### 2. subfinder + amass enum -passive

```bash
echo "[+] Running subfinder on root candidates..."
subfinder -dL root-candidates.txt -all -recursive -silent -o subfinder-subdomains.txt || true

echo "[+] Running amass enum -passive on root candidates..."
amass enum -passive -df root-candidates.txt -o amass-subdomains.txt || true
```

- `subfinder -dL` берёт домены из файла и делает пассивный поиск поддоменов. [xakep](https://xakep.ru/2023/07/06/5-osint-utils/)
- `amass enum -passive` ищет хосты без активного брутфорса, что подходит для «тихого» OSINT. [dionach](https://dionach.com/how-to-use-owasp-amass-an-extensive-tutorial/)

### 3. Certificate Transparency (crt.sh)

```bash
echo "[+] Fetching from crt.sh..."
mkdir -p crtsh

while read -r d; do
  [[ -z "$d" ]] && continue
  echo "[+] crt.sh: $d"
  curl -fsSL "https://crt.sh/?q=%25.$d&output=json" \
    | jq -r '.[].name_value' 2>/dev/null \
    | sed 's/\*\.//g' \
    | tr '\r' '\n' \
    | grep -Eo '([a-z0-9-]+\.)+[a-z]{2,}' \
    | sort -u > "crtsh/$d.txt" || true
done < root-candidates.txt

cat crtsh/*.txt 2>/dev/null | sort -u > crtsh-subdomains.txt || true
```

- `crt.sh` даёт названия хостов, которые когда‑то светились в TLS‑сертификатах.
- Часто всплывают старые / внутренние имена, полезные для анализа поверхности. [xakep](https://xakep.ru/2023/07/06/5-osint-utils/)

### 4. Финальный список хостов

```bash
echo "[+] Building all-hostnames.txt..."
cat subfinder-subdomains.txt amass-subdomains.txt crtsh-subdomains.txt 2>/dev/null \
  | tr '[:upper:]' '[:lower:]' \
  | sed 's/^\*\.//' \
  | sort -u > all-hostnames.txt

echo "[+] All hostnames count:"
wc -l all-hostnames.txt
```

- Склейка результатов всех источников.
- Нормализация и дедупликация.

### 5. DNS‑чекап

```bash
echo "[+] Running DNS checks for root candidates..."
mkdir -p dns-checks
: > dns-checks/dns-summary.txt

while read -r d; do
  [[ -z "$d" ]] && continue
  {
    echo "===== $d ====="
    echo "[A]"
    dig +short A "$d"
    echo "[AAAA]"
    dig +short AAAA "$d"
    echo "[NS]"
    dig +short NS "$d"
    echo "[MX]"
    dig +short MX "$d"
    echo "[TXT]"
    dig +short TXT "$d"
    echo
  } >> dns-checks/dns-summary.txt
done < root-candidates.txt
```

- Быстрый обзор того, куда смотрят домены (IP, NS, MX, TXT/SPF).

### 6. WHOIS

```bash
echo "[+] Running WHOIS for root candidates (may be slow)..."
mkdir -p whois

while read -r d; do
  [[ -z "$d" ]] && continue
  echo "[+] whois $d"
  whois "$d" > "whois/$d.txt" 2>/dev/null || true
  sleep 1
done < root-candidates.txt
```

- WHOIS‑дампы сохраняются в отдельные файлы для последующего анализа. [habr](https://habr.com/ru/articles/802621/)

### 7. Черновая классификация A/B/C

```bash
echo "[+] Classifying root domains..."
CLASS_FILE="root-classification.csv"
echo "domain,confidence,reason" > "$CLASS_FILE"

ORG_PATTERNS="${ORG_PATTERNS:-example|mycorp|internal}"

while read -r d; do
  [[ -z "$d" ]] && continue

  dns_match=$(grep -i "$d" dns-checks/dns-summary.txt | grep -Ei "$ORG_PATTERNS" || true)
  whois_match=$(grep -RniE "$ORG_PATTERNS" "whois/$d.txt" 2>/dev/null || true)

  if [[ -n "$dns_match" && -n "$whois_match" ]]; then
    echo "$d,A,DNS+WHOIS match" >> "$CLASS_FILE"
  elif [[ -n "$dns_match" || -n "$whois_match" ]]; then
    echo "$d,B,Partial DNS/WHOIS match" >> "$CLASS_FILE"
  else
    echo "$d,C,Unverified candidate" >> "$CLASS_FILE"
  fi
done < root-candidates.txt
```

- Можно переопределить `ORG_PATTERNS` перед запуском:

```bash
export ORG_PATTERNS='vk|mail\.ru|myvpnbrand'
./attack-surface.sh -p vk-infra -s "$(pwd)/seeds.txt"
```

***

## Структура проекта

```text
~/osint-recon/<project>/
  seeds.txt                # исходные root-домены
  root-candidates.txt      # нормализованные root-кандидаты
  subfinder-subdomains.txt # поддомены от subfinder
  amass-subdomains.txt     # поддомены от amass enum -passive
  crtsh/                   # сырые CT-данные по доменам
  crtsh-subdomains.txt     # поддомены из CT
  all-hostnames.txt        # финальный список хостов
  dns-checks/
    dns-summary.txt        # DNS-резюме по root-доменам
  whois/
    <domain>.txt           # whois по каждому root-домену
  root-classification.csv  # A/B/C классификация root-доменов
```

# Рабочий код

```sh
cat > /srv/sh/attack-surface.sh << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

# ==============================
# Универсальный OSINT-скрипт для доменной экосистемы (без amass intel)
# Использование:
#   ./attack-surface.sh -p myproject -s /abs/path/to/seeds.txt
#
# Требует:
#   amass, subfinder, jq, curl, dig, whois
# ==============================

usage() {
  echo "Usage: $0 -p project_name -s /absolute/path/to/seeds.txt"
}

PROJECT=""
SEEDS_FILE=""

while getopts "p:s:" opt; do
  case "$opt" in
    p) PROJECT="$OPTARG" ;;
    s) SEEDS_FILE="$OPTARG" ;;
    *) usage; exit 1 ;;
  esac
done

if [[ -z "$PROJECT" || -z "$SEEDS_FILE" ]]; then
  usage
  exit 1
fi

if [[ ! -f "$SEEDS_FILE" ]]; then
  echo "[!] Seeds file not found: $SEEDS_FILE"
  exit 1
fi

# Желательно абсолютный путь
SEEDS_FILE="$(readlink -f "$SEEDS_FILE")"

BASE_DIR="$HOME/osint-recon/$PROJECT"
mkdir -p "$BASE_DIR"
cd "$BASE_DIR"

echo "[+] Project directory: $BASE_DIR"
cp "$SEEDS_FILE" seeds.txt

# ==============================
# 1. Формирование списка root-кандидатов
# (пока только из seeds, без intel)
# ==============================
echo "[+] Building root-candidates.txt from seeds..."
cat seeds.txt \
  | tr '[:upper:]' '[:lower:]' \
  | grep -Eo '([a-z0-9-]+\.)+[a-z]{2,}' \
  | sed 's/^\*\.//' \
  | sort -u > root-candidates.txt

echo "[+] Root candidates count:"
wc -l root-candidates.txt

# ==============================
# 2. Сбор поддоменов: subfinder + amass enum -passive
# ==============================
echo "[+] Running subfinder on root candidates..."
subfinder -dL root-candidates.txt -all -recursive -silent -o subfinder-subdomains.txt || true

echo "[+] Running amass enum -passive on root candidates..."
amass enum -passive -df root-candidates.txt -o amass-subdomains.txt || true

# ==============================
# 3. Certificate Transparency (crt.sh)
# ==============================
echo "[+] Fetching from crt.sh..."
mkdir -p crtsh

while read -r d; do
  [[ -z "$d" ]] && continue
  echo "[+] crt.sh: $d"
  curl -fsSL "https://crt.sh/?q=%25.$d&output=json" \
    | jq -r '.[].name_value' 2>/dev/null \
    | sed 's/\*\.//g' \
    | tr '\r' '\n' \
    | grep -Eo '([a-z0-9-]+\.)+[a-z]{2,}' \
    | sort -u > "crtsh/$d.txt" || true
done < root-candidates.txt

cat crtsh/*.txt 2>/dev/null | sort -u > crtsh-subdomains.txt || true

# ==============================
# 4. Финальный список hostnames
# ==============================
echo "[+] Building all-hostnames.txt..."
cat subfinder-subdomains.txt amass-subdomains.txt crtsh-subdomains.txt 2>/dev/null \
  | tr '[:upper:]' '[:lower:]' \
  | sed 's/^\*\.//' \
  | sort -u > all-hostnames.txt

echo "[+] All hostnames count:"
wc -l all-hostnames.txt

# ==============================
# 5. DNS-чеки для root-доменов
# ==============================
echo "[+] Running DNS checks for root candidates..."
mkdir -p dns-checks
: > dns-checks/dns-summary.txt

while read -r d; do
  [[ -z "$d" ]] && continue
  {
    echo "===== $d ====="
    echo "[A]"
    dig +short A "$d"
    echo "[AAAA]"
    dig +short AAAA "$d"
    echo "[NS]"
    dig +short NS "$d"
    echo "[MX]"
    dig +short MX "$d"
    echo "[TXT]"
    dig +short TXT "$d"
    echo
  } >> dns-checks/dns-summary.txt
done < root-candidates.txt

# ==============================
# 6. WHOIS по root-доменам (best-effort)
# ==============================
echo "[+] Running WHOIS for root candidates (may be slow)..."
mkdir -p whois

while read -r d; do
  [[ -z "$d" ]] && continue
  echo "[+] whois $d"
  whois "$d" > "whois/$d.txt" 2>/dev/null || true
  sleep 1
done < root-candidates.txt

# ==============================
# 7. Черновая классификация A/B/C по root-доменам
# ==============================
echo "[+] Classifying root domains..."
CLASS_FILE="root-classification.csv"
echo "domain,confidence,reason" > "$CLASS_FILE"

# Подправь под свои бренды / org-паттерны
ORG_PATTERNS="${ORG_PATTERNS:-example|mycorp|internal}"

while read -r d; do
  [[ -z "$d" ]] && continue

  dns_match=$(grep -i "$d" dns-checks/dns-summary.txt | grep -Ei "$ORG_PATTERNS" || true)
  whois_match=$(grep -RniE "$ORG_PATTERNS" "whois/$d.txt" 2>/dev/null || true)

  if [[ -n "$dns_match" && -n "$whois_match" ]]; then
    echo "$d,A,DNS+WHOIS match" >> "$CLASS_FILE"
  elif [[ -n "$dns_match" || -n "$whois_match" ]]; then
    echo "$d,B,Partial DNS/WHOIS match" >> "$CLASS_FILE"
  else
    echo "$d,C,Unverified candidate" >> "$CLASS_FILE"
  fi
done < root-candidates.txt

echo "[+] Classification written to $CLASS_FILE"
echo "[+] Done."
EOF
```
