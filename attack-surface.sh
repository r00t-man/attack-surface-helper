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
