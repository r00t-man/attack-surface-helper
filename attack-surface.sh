#!/usr/bin/env bash
set -uo pipefail

# ==============================================================================
# attack-surface.sh
# ------------------------------------------------------------------------------
# Устойчивый OSINT / Attack Surface Recon pipeline для СВОИХ доменов.
#
# Pipeline:
#   seeds.txt
#     -> root-candidates.txt
#     -> subfinder + amass + crt.sh
#     -> all-hostnames.txt
#     -> httpx / ProjectDiscovery
#     -> live-urls.txt
#     -> nuclei safe scan
#     -> report.md
#
# Версия v3:
#   - нет строгих preflight-проверок;
#   - если инструмент не найден/сломался, этап пропускается или продолжается best-effort;
#   - stdout внешних инструментов НЕ засоряет терминал, всё пишется в logs/;
#   - для httpx используется -rl, не -rate;
#   - для Nuclei v3.8.0 используется -j, не -json;
#   - для Nuclei exclude tags используется -etags;
#   - latest обновляется после завершения pipeline.
#
# Использование:
#   chmod +x attack-surface.sh
#
#   ./attack-surface.sh \
#     -p honestvpn \
#     -s /root/seeds.txt \
#     --org-patterns 'r00t|h0nest|wksdns|dnswks|honest' \
#     --update-templates
#
# Если хочешь видеть полный вывод инструментов в терминале:
#   VERBOSE=1 ./attack-surface.sh ...
#
# Важно:
#   Используй только для своих доменов или явно разрешённого scope.
# ==============================================================================


# ==============================================================================
# 0. Настройки по умолчанию
# ==============================================================================

PROJECT=""
SEEDS_FILE=""
OUT_BASE="$HOME/osint-recon"

HTTPX_PORTS="80,443,8080,8443,2082,2083,2086,2087,2095,2096"
HTTPX_RATE="50"
HTTPX_BIN="${HTTPX_BIN:-}"

RUN_NUCLEI="1"
UPDATE_TEMPLATES="0"
NUCLEI_SEVERITY="low,medium,high,critical"
NUCLEI_EXCLUDE_TAGS="fuzz,dos,bruteforce,intrusive"
NUCLEI_RATE_LIMIT="20"
NUCLEI_BULK_SIZE="10"
NUCLEI_RETRIES="1"
NUCLEI_TIMEOUT="8"
NUCLEI_BIN="${NUCLEI_BIN:-}"

RUN_SUBFINDER="1"
RUN_AMASS="1"
RUN_CRTSH="1"
RUN_DNS="1"
RUN_WHOIS="1"

ORG_PATTERNS="${ORG_PATTERNS:-}"
NO_COLOR="${NO_COLOR:-0}"
VERBOSE="${VERBOSE:-0}"

BASE_DIR=""
RUN_DIR=""
LOG_DIR=""
PREVIOUS_LATEST=""


# ==============================================================================
# 1. Цвета, визуал, логирование
# ==============================================================================

init_colors() {
  if [[ "$NO_COLOR" == "1" ]] || [[ ! -t 1 ]]; then
    C_RESET=""
    C_BOLD=""
    C_DIM=""
    C_RED=""
    C_GREEN=""
    C_YELLOW=""
    C_BLUE=""
    C_MAGENTA=""
    C_CYAN=""
  else
    C_RESET="$(tput sgr0 2>/dev/null || true)"
    C_BOLD="$(tput bold 2>/dev/null || true)"
    C_DIM="$(tput dim 2>/dev/null || true)"
    C_RED="$(tput setaf 1 2>/dev/null || true)"
    C_GREEN="$(tput setaf 2 2>/dev/null || true)"
    C_YELLOW="$(tput setaf 3 2>/dev/null || true)"
    C_BLUE="$(tput setaf 4 2>/dev/null || true)"
    C_MAGENTA="$(tput setaf 5 2>/dev/null || true)"
    C_CYAN="$(tput setaf 6 2>/dev/null || true)"
  fi
}

now() { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo -e "${C_DIM}[$(now)]${C_RESET} $*"; }
ok() { echo -e "${C_GREEN}✔${C_RESET} $*"; }
warn() { echo -e "${C_YELLOW}⚠${C_RESET} $*"; }
err() { echo -e "${C_RED}✖${C_RESET} $*" >&2; }

die() {
  err "$*"
  if [[ -n "${RUN_DIR:-}" ]]; then
    err "Run dir: $RUN_DIR"
    err "Logs: $RUN_DIR/logs"
  fi
  exit 1
}

hr() {
  echo -e "${C_BLUE}──────────────────────────────────────────────────────────────────────────────${C_RESET}"
}

banner() {
  clear 2>/dev/null || true
  echo -e "${C_CYAN}${C_BOLD}"
  cat <<'EOF'
      ___   __  __             __      _____             __
     /   | / /_/ /_____ ______/ /__   / ___/__  ________/ /_____  _____
    / /| |/ __/ __/ __ `/ ___/ //_/   \__ \/ / / / ___/ __/ __ `/ ___/
   / ___ / /_/ /_/ /_/ / /__/ ,<     ___/ / /_/ / /  / /_/ /_/ / /
  /_/  |_\__/\__/\__,_/\___/_/|_|   /____/\__,_/_/   \__/\__,_/_/

      Recon Stack: amass + subfinder + crt.sh + httpx + nuclei

  ╔══════════════════════════════════════════════════════════════════════════╗
  ║                                                                          ║
  ║   ██████╗  ██████╗  ██████╗ ████████╗      ███╗   ███╗ █████╗ ███╗   ██╗ ║
  ║   ██╔══██╗██╔═████╗██╔═████╗╚══██╔══╝      ████╗ ████║██╔══██╗████╗  ██║ ║
  ║   ██████╔╝██║██╔██║██║██╔██║   ██║         ██╔████╔██║███████║██╔██╗ ██║ ║
  ║   ██╔══██╗████╔╝██║████╔╝██║   ██║         ██║╚██╔╝██║██╔══██║██║╚██╗██║ ║
  ║   ██║  ██║╚██████╔╝╚██████╔╝   ██║         ██║ ╚═╝ ██║██║  ██║██║ ╚████║ ║
  ║   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝         ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ║
  ║                                                                          ║
  ║                       r00t-man  &  GiS-man                               ║
  ║                                                                          ║
  ║            ██████╗ ██╗███████╗       ███╗   ███╗ █████╗ ███╗   ██╗       ║
  ║           ██╔════╝ ██║██╔════╝       ████╗ ████║██╔══██╗████╗  ██║       ║
  ║           ██║  ███╗██║███████╗       ██╔████╔██║███████║██╔██╗ ██║       ║
  ║           ██║   ██║██║╚════██║       ██║╚██╔╝██║██╔══██║██║╚██╗██║       ║
  ║           ╚██████╔╝██║███████║       ██║ ╚═╝ ██║██║  ██║██║ ╚████║       ║
  ║            ╚═════╝ ╚═╝╚══════╝       ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝       ║
  ║                                                                          ║
  ║   GitHub: https://github.com/r00t-man                                    ║
  ║                                                                          ║
  ╚══════════════════════════════════════════════════════════════════════════╝
EOF
  echo -e "${C_RESET}"
}

section() {
  local num="$1"
  local title="$2"
  hr
  echo -e "${C_MAGENTA}${C_BOLD}[$num] $title${C_RESET}"
  hr
}

small_box() {
  local text="$1"
  echo -e "${C_CYAN}╭─ ${C_BOLD}${text}${C_RESET}"
}

small_done() {
  local text="$1"
  echo -e "${C_CYAN}╰─${C_RESET} ${C_GREEN}${text}${C_RESET}"
}

count_lines() {
  local file="$1"
  if [[ -s "$file" ]]; then
    wc -l < "$file" | tr -d ' '
  else
    echo "0"
  fi
}

safe_head() {
  local file="$1"
  local lines="${2:-80}"
  if [[ -s "$file" ]]; then
    head -n "$lines" "$file" || true
  fi
}

# Запуск внешней команды.
# По умолчанию stdout/stderr пишутся только в лог, чтобы не было огромной простыни.
# VERBOSE=1 включает tee в терминал.
run_logged() {
  local title="$1"
  local logfile="$2"
  shift 2

  small_box "$title"
  log "Лог: $logfile"

  local started
  started="$(date +%s)"
  local rc=0

  if [[ "$VERBOSE" == "1" ]]; then
    "$@" > >(tee "$logfile") 2> >(tee -a "$logfile" >&2)
    rc=$?
  else
    "$@" > "$logfile" 2>&1
    rc=$?
  fi

  local finished
  finished="$(date +%s)"
  local elapsed=$((finished - started))

  if [[ "$rc" -eq 0 ]]; then
    small_done "Готово за ${elapsed}s"
  else
    warn "Команда завершилась с кодом $rc, продолжаю best-effort. Подробности в логе."
  fi

  return 0
}


# ==============================================================================
# 2. Аргументы
# ==============================================================================

usage() {
  cat <<EOF
Usage:
  $0 -p project_name -s /absolute/path/to/seeds.txt [options]

Required:
  -p, --project NAME             Имя проекта
  -s, --seeds FILE               Файл с root-доменами / seed-доменами

Options:
  -o, --out DIR                  Базовая папка вывода. Default: $HOME/osint-recon

  --ports LIST                   Порты для httpx. Default: $HTTPX_PORTS
  --httpx-rate N                 Rate limit для httpx. Default: $HTTPX_RATE
  --httpx-bin FILE               Путь к httpx

  --nuclei-rate N                Rate limit для nuclei. Default: $NUCLEI_RATE_LIMIT
  --nuclei-severity LIST         Severity. Default: $NUCLEI_SEVERITY
  --nuclei-exclude-tags LIST     Exclude tags. Default: $NUCLEI_EXCLUDE_TAGS
  --nuclei-bin FILE              Путь к nuclei
  --update-templates             Обновить nuclei templates перед запуском
  --skip-nuclei                  Не запускать nuclei

  --skip-subfinder               Не запускать subfinder
  --skip-amass                   Не запускать amass
  --skip-crtsh                   Не использовать crt.sh
  --skip-dns                     Не делать DNS summary
  --skip-whois                   Не делать WHOIS

  --org-patterns REGEX           Regex для классификации доменов
  --no-color                     Отключить цветной вывод
  -h, --help                     Показать help
EOF
}

need_value() {
  local opt="$1"
  local val="${2:-}"
  [[ -n "$val" && ! "$val" =~ ^- ]] || die "Опция $opt требует значение"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -p|--project) need_value "$1" "${2:-}"; PROJECT="$2"; shift 2 ;;
      -s|--seeds) need_value "$1" "${2:-}"; SEEDS_FILE="$2"; shift 2 ;;
      -o|--out) need_value "$1" "${2:-}"; OUT_BASE="$2"; shift 2 ;;
      --ports) need_value "$1" "${2:-}"; HTTPX_PORTS="$2"; shift 2 ;;
      --httpx-rate) need_value "$1" "${2:-}"; HTTPX_RATE="$2"; shift 2 ;;
      --httpx-bin) need_value "$1" "${2:-}"; HTTPX_BIN="$2"; shift 2 ;;
      --nuclei-rate) need_value "$1" "${2:-}"; NUCLEI_RATE_LIMIT="$2"; shift 2 ;;
      --nuclei-severity) need_value "$1" "${2:-}"; NUCLEI_SEVERITY="$2"; shift 2 ;;
      --nuclei-exclude-tags) need_value "$1" "${2:-}"; NUCLEI_EXCLUDE_TAGS="$2"; shift 2 ;;
      --nuclei-bin) need_value "$1" "${2:-}"; NUCLEI_BIN="$2"; shift 2 ;;
      --update-templates) UPDATE_TEMPLATES="1"; shift ;;
      --skip-nuclei) RUN_NUCLEI="0"; shift ;;
      --skip-subfinder) RUN_SUBFINDER="0"; shift ;;
      --skip-amass) RUN_AMASS="0"; shift ;;
      --skip-crtsh) RUN_CRTSH="0"; shift ;;
      --skip-dns) RUN_DNS="0"; shift ;;
      --skip-whois) RUN_WHOIS="0"; shift ;;
      --org-patterns) need_value "$1" "${2:-}"; ORG_PATTERNS="$2"; shift 2 ;;
      --no-color) NO_COLOR="1"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) usage; die "Неизвестный аргумент: $1" ;;
    esac
  done

  [[ -n "$PROJECT" ]] || { usage; die "Не указан project: -p NAME"; }
  [[ -n "$SEEDS_FILE" ]] || { usage; die "Не указан seeds file: -s FILE"; }
  [[ -f "$SEEDS_FILE" ]] || die "Seeds file не найден: $SEEDS_FILE"

  SEEDS_FILE="$(readlink -f "$SEEDS_FILE")"
  OUT_BASE="$(readlink -m "$OUT_BASE")"
}


# ==============================================================================
# 3. Мягкая проверка зависимостей
# ==============================================================================

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

first_existing_bin() {
  local env_bin="$1"
  shift

  if [[ -n "$env_bin" && -x "$env_bin" ]]; then
    echo "$env_bin"
    return 0
  fi

  local candidate
  for candidate in "$@"; do
    [[ -n "$candidate" ]] || continue
    if [[ -x "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  done

  return 1
}

resolve_tools() {
  section "0/9" "Мягкая проверка зависимостей"

  local missing_common=0
  local common_tools=(bash cat sort grep sed awk tr wc date readlink mkdir ln jq curl dig whois)

  local cmd
  for cmd in "${common_tools[@]}"; do
    if ! have_cmd "$cmd"; then
      warn "Не найдено: $cmd"
      missing_common=1
    fi
  done

  if [[ "$missing_common" == "1" ]]; then
    die "Не хватает базовых системных утилит. Установи jq curl dnsutils whois coreutils."
  fi

  if [[ "$RUN_SUBFINDER" == "1" ]] && ! have_cmd subfinder; then
    warn "subfinder не найден, этап будет пропущен"
    RUN_SUBFINDER="0"
  fi

  if [[ "$RUN_AMASS" == "1" ]] && ! have_cmd amass; then
    warn "amass не найден, этап будет пропущен"
    RUN_AMASS="0"
  fi

  HTTPX_BIN="$(first_existing_bin "$HTTPX_BIN" \
    "/usr/local/bin/httpx" \
    "/root/go/bin/httpx" \
    "/usr/bin/httpx" \
    "/bin/httpx" \
    "$(command -v httpx 2>/dev/null || true)" \
  )" || true

  if [[ -n "${HTTPX_BIN:-}" ]]; then
    ok "httpx найден: $HTTPX_BIN"
  else
    warn "httpx не найден, этап httpx будет пропущен"
  fi

  if [[ "$RUN_NUCLEI" == "1" ]]; then
    NUCLEI_BIN="$(first_existing_bin "$NUCLEI_BIN" \
      "/usr/local/bin/nuclei" \
      "/root/go/bin/nuclei" \
      "/usr/bin/nuclei" \
      "/bin/nuclei" \
      "$(command -v nuclei 2>/dev/null || true)" \
    )" || true

    if [[ -n "${NUCLEI_BIN:-}" ]]; then
      ok "nuclei найден: $NUCLEI_BIN"
    else
      warn "nuclei не найден, этап nuclei будет пропущен"
      RUN_NUCLEI="0"
    fi
  fi

  ok "Preflight завершён без блокирующих проверок"
}


# ==============================================================================
# 4. Инициализация структуры проекта
# ==============================================================================

init_project() {
  local run_id
  run_id="$(date '+%Y-%m-%d_%H-%M-%S')"

  BASE_DIR="$OUT_BASE/$PROJECT"
  PREVIOUS_LATEST=""

  if [[ -L "$BASE_DIR/latest" || -d "$BASE_DIR/latest" ]]; then
    PREVIOUS_LATEST="$(readlink -f "$BASE_DIR/latest" 2>/dev/null || true)"
  fi

  RUN_DIR="$BASE_DIR/runs/$run_id"
  LOG_DIR="$RUN_DIR/logs"

  mkdir -p \
    "$RUN_DIR/00-input" \
    "$RUN_DIR/01-roots" \
    "$RUN_DIR/02-sources/subfinder" \
    "$RUN_DIR/02-sources/amass" \
    "$RUN_DIR/02-sources/crtsh" \
    "$RUN_DIR/03-dns" \
    "$RUN_DIR/04-whois" \
    "$RUN_DIR/05-live" \
    "$RUN_DIR/06-nuclei" \
    "$RUN_DIR/07-reports" \
    "$RUN_DIR/08-delta" \
    "$RUN_DIR/tmp" \
    "$LOG_DIR"

  cp "$SEEDS_FILE" "$RUN_DIR/00-input/seeds.txt"

  banner
  log "Project: $PROJECT"
  log "Run dir: $RUN_DIR"
  log "Seeds: $SEEDS_FILE"
  log "Previous latest: ${PREVIOUS_LATEST:-none}"
}


# ==============================================================================
# 5. Версии инструментов
# ==============================================================================

save_versions() {
  section "1/9" "Сохранение версий инструментов"

  local vf="$RUN_DIR/07-reports/versions.txt"
  {
    echo "Generated: $(now)"
    echo
    echo "[bash]"; bash --version | head -n 1 || true
    echo
    echo "[jq]"; jq --version || true
    echo
    echo "[curl]"; curl --version | head -n 1 || true
    echo
    echo "[dig]"; dig -v || true
    echo
    echo "[whois]"; whois --version 2>&1 | head -n 1 || true
    echo
    echo "[subfinder]"; if have_cmd subfinder; then subfinder -version 2>&1 || true; else echo "not installed"; fi
    echo
    echo "[amass]"; if have_cmd amass; then amass -version 2>&1 || true; else echo "not installed"; fi
    echo
    echo "[httpx]"; echo "HTTPX_BIN=${HTTPX_BIN:-not found}"; if [[ -n "${HTTPX_BIN:-}" ]]; then "$HTTPX_BIN" -version 2>&1 || true; fi
    echo
    echo "[nuclei]"; echo "NUCLEI_BIN=${NUCLEI_BIN:-not used}"; if [[ -n "${NUCLEI_BIN:-}" ]]; then "$NUCLEI_BIN" -version 2>&1 || true; fi
  } > "$vf"

  ok "Версии сохранены: $vf"
}


# ==============================================================================
# 6. Root domains
# ==============================================================================

build_roots() {
  section "2/9" "Формирование root-candidates.txt"

  local seeds="$RUN_DIR/00-input/seeds.txt"
  local roots="$RUN_DIR/01-roots/root-candidates.txt"

  cat "$seeds" \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/^\s*//; s/\s*$//' \
    | grep -Eo '([a-z0-9-]+\.)+[a-z]{2,}' \
    | sed 's/^\*\.//' \
    | sort -u \
    > "$roots"

  [[ -s "$roots" ]] || die "После нормализации root-candidates.txt пустой"

  ok "Root candidates: $(count_lines "$roots")"
  sed 's/^/  - /' "$roots" || true
}


# ==============================================================================
# 7. Subdomain collection
# ==============================================================================

run_subfinder() {
  local roots="$RUN_DIR/01-roots/root-candidates.txt"
  local out="$RUN_DIR/02-sources/subfinder/subfinder-subdomains.txt"
  local logf="$LOG_DIR/subfinder.log"

  if [[ "$RUN_SUBFINDER" != "1" ]]; then
    warn "Subfinder пропущен"
    : > "$out"
    return 0
  fi

  run_logged \
    "Subfinder: быстрый passive subdomain enumeration" \
    "$logf" \
    subfinder \
      -dL "$roots" \
      -all \
      -recursive \
      -silent \
      -o "$out"

  [[ -f "$out" ]] || : > "$out"
  sort -u -o "$out" "$out" 2>/dev/null || true
  ok "Subfinder results: $(count_lines "$out")"
}

run_amass() {
  local roots="$RUN_DIR/01-roots/root-candidates.txt"
  local out="$RUN_DIR/02-sources/amass/amass-subdomains.txt"
  local logf="$LOG_DIR/amass.log"

  if [[ "$RUN_AMASS" != "1" ]]; then
    warn "Amass пропущен"
    : > "$out"
    return 0
  fi

  run_logged \
    "Amass: глубокий passive enum" \
    "$logf" \
    amass enum \
      -passive \
      -df "$roots" \
      -o "$out"

  [[ -f "$out" ]] || : > "$out"
  sort -u -o "$out" "$out" 2>/dev/null || true
  ok "Amass results: $(count_lines "$out")"
}

run_crtsh() {
  local roots="$RUN_DIR/01-roots/root-candidates.txt"
  local out_dir="$RUN_DIR/02-sources/crtsh"
  local out="$out_dir/crtsh-subdomains.txt"
  local logf="$LOG_DIR/crtsh.log"

  if [[ "$RUN_CRTSH" != "1" ]]; then
    warn "crt.sh пропущен"
    : > "$out"
    return 0
  fi

  section "3/9" "Certificate Transparency: crt.sh"

  : > "$logf"
  : > "$out"

  local total
  total="$(count_lines "$roots")"

  local i=0

  while read -r d; do
    [[ -z "$d" ]] && continue

    i=$((i + 1))

    local domain_out="$out_dir/$d.txt"
    local raw_json="$out_dir/$d.raw.json"

    echo -e "${C_CYAN}[$i/$total]${C_RESET} crt.sh: ${C_BOLD}$d${C_RESET}" | tee -a "$logf"

    if curl -fsSL \
      --max-time 35 \
      --retry 2 \
      --retry-delay 2 \
      "https://crt.sh/?q=%25.$d&output=json" \
      -o "$raw_json" \
      2>>"$logf"; then

      if jq -e 'type == "array"' "$raw_json" >/dev/null 2>>"$logf"; then
        jq -r '.[].name_value // empty' "$raw_json" 2>>"$logf" \
          | sed 's/\*\.//g' \
          | tr '\r' '\n' \
          | tr '[:upper:]' '[:lower:]' \
          | grep -Eo '([a-z0-9-]+\.)+[a-z]{2,}' \
          | sort -u \
          > "$domain_out"

        if [[ "$?" -ne 0 ]]; then
          warn "crt.sh $d: совпадений нет или парсинг вернул пусто"
          : > "$domain_out"
        else
          ok "crt.sh $d: $(count_lines "$domain_out")"
        fi
      else
        warn "crt.sh $d: ответ не похож на JSON array"
        : > "$domain_out"
      fi
    else
      warn "crt.sh $d: curl не смог получить данные"
      : > "$domain_out"
    fi

    cat "$domain_out" >> "$out" 2>/dev/null || true
    sleep 1
  done < "$roots"

  sort -u -o "$out" "$out" 2>/dev/null || true
  ok "crt.sh results: $(count_lines "$out")"
}

build_all_hostnames() {
  section "4/9" "Сборка all-hostnames.txt"

  local subfinder_out="$RUN_DIR/02-sources/subfinder/subfinder-subdomains.txt"
  local amass_out="$RUN_DIR/02-sources/amass/amass-subdomains.txt"
  local crtsh_out="$RUN_DIR/02-sources/crtsh/crtsh-subdomains.txt"
  local all="$RUN_DIR/02-sources/all-hostnames.txt"

  [[ -f "$subfinder_out" ]] || : > "$subfinder_out"
  [[ -f "$amass_out" ]] || : > "$amass_out"
  [[ -f "$crtsh_out" ]] || : > "$crtsh_out"

  cat "$subfinder_out" "$amass_out" "$crtsh_out" 2>/dev/null \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/^\*\.//' \
    | grep -Eo '([a-z0-9-]+\.)+[a-z]{2,}' \
    | sort -u \
    > "$all"

  if [[ "$?" -ne 0 ]]; then
    warn "Не удалось собрать all-hostnames.txt или список пустой"
    : > "$all"
  fi

  ok "All hostnames: $(count_lines "$all")"
  cp "$all" "$RUN_DIR/all-hostnames.txt"
}


# ==============================================================================
# 8. DNS / WHOIS
# ==============================================================================

run_dns_checks() {
  local roots="$RUN_DIR/01-roots/root-candidates.txt"
  local out="$RUN_DIR/03-dns/dns-summary.txt"
  local logf="$LOG_DIR/dns.log"

  if [[ "$RUN_DNS" != "1" ]]; then
    warn "DNS checks пропущены"
    : > "$out"
    return 0
  fi

  section "5/9" "DNS summary для root-доменов"

  : > "$out"
  : > "$logf"

  while read -r d; do
    [[ -z "$d" ]] && continue

    echo -e "${C_CYAN}DNS:${C_RESET} $d" | tee -a "$logf"

    {
      echo "===== $d ====="
      echo "[A]"; dig +short A "$d" || true
      echo "[AAAA]"; dig +short AAAA "$d" || true
      echo "[NS]"; dig +short NS "$d" || true
      echo "[MX]"; dig +short MX "$d" || true
      echo "[TXT]"; dig +short TXT "$d" || true
      echo "[CAA]"; dig +short CAA "$d" || true
      echo
    } >> "$out"
  done < "$roots"

  ok "DNS summary: $out"
}

run_whois_checks() {
  local roots="$RUN_DIR/01-roots/root-candidates.txt"
  local out_dir="$RUN_DIR/04-whois"
  local logf="$LOG_DIR/whois.log"

  if [[ "$RUN_WHOIS" != "1" ]]; then
    warn "WHOIS пропущен"
    return 0
  fi

  section "6/9" "WHOIS для root-доменов"

  : > "$logf"

  while read -r d; do
    [[ -z "$d" ]] && continue
    echo -e "${C_CYAN}WHOIS:${C_RESET} $d" | tee -a "$logf"
    whois "$d" > "$out_dir/$d.txt" 2>>"$logf" || true
    sleep 1
  done < "$roots"

  ok "WHOIS сохранён: $out_dir"
}


# ==============================================================================
# 9. Classification
# ==============================================================================

classify_roots() {
  section "7/9" "Черновая классификация root-доменов"

  local roots="$RUN_DIR/01-roots/root-candidates.txt"
  local dns_summary="$RUN_DIR/03-dns/dns-summary.txt"
  local whois_dir="$RUN_DIR/04-whois"
  local class_file="$RUN_DIR/07-reports/root-classification.csv"

  echo "domain,confidence,reason" > "$class_file"

  if [[ -z "$ORG_PATTERNS" ]]; then
    warn "ORG_PATTERNS не задан. Классификация будет слабой."
  fi

  while read -r d; do
    [[ -z "$d" ]] && continue

    local dns_match=""
    local whois_match=""

    if [[ -n "$ORG_PATTERNS" && -s "$dns_summary" ]]; then
      dns_match="$(grep -i "$d" "$dns_summary" | grep -Ei "$ORG_PATTERNS" || true)"
    fi

    if [[ -n "$ORG_PATTERNS" && -f "$whois_dir/$d.txt" ]]; then
      whois_match="$(grep -RniE "$ORG_PATTERNS" "$whois_dir/$d.txt" 2>/dev/null || true)"
    fi

    if [[ -n "$dns_match" && -n "$whois_match" ]]; then
      echo "$d,A,DNS+WHOIS match" >> "$class_file"
    elif [[ -n "$dns_match" || -n "$whois_match" ]]; then
      echo "$d,B,Partial DNS/WHOIS match" >> "$class_file"
    else
      echo "$d,C,Unverified candidate" >> "$class_file"
    fi
  done < "$roots"

  if have_cmd column; then
    column -s, -t "$class_file" || cat "$class_file"
  else
    cat "$class_file"
  fi

  ok "Classification: $class_file"
}


# ==============================================================================
# 10. httpx
# ==============================================================================

run_httpx() {
  section "8/9" "httpx: поиск живых HTTP/HTTPS сервисов"

  local input="$RUN_DIR/02-sources/all-hostnames.txt"
  local out_json="$RUN_DIR/05-live/httpx-live.jsonl"
  local out_urls="$RUN_DIR/05-live/live-urls.txt"
  local out_tsv="$RUN_DIR/05-live/httpx-live.tsv"
  local out_pretty="$RUN_DIR/05-live/httpx-live-pretty.txt"
  local logf="$LOG_DIR/httpx.log"

  if [[ -z "${HTTPX_BIN:-}" || ! -x "$HTTPX_BIN" ]]; then
    warn "httpx не найден. Пропускаю httpx и nuclei."
    : > "$out_json"
    : > "$out_urls"
    : > "$out_tsv"
    : > "$out_pretty"
    cp "$out_urls" "$RUN_DIR/live-urls.txt"
    RUN_NUCLEI="0"
    return 0
  fi

  if [[ ! -s "$input" ]]; then
    warn "all-hostnames.txt пустой, httpx запускать не на чем"
    : > "$out_json"
    : > "$out_urls"
    : > "$out_tsv"
    : > "$out_pretty"
    cp "$out_urls" "$RUN_DIR/live-urls.txt"
    return 0
  fi

  run_logged \
    "httpx: probing hostnames on ports $HTTPX_PORTS" \
    "$logf" \
    "$HTTPX_BIN" \
      -l "$input" \
      -silent \
      -json \
      -status-code \
      -title \
      -tech-detect \
      -web-server \
      -ip \
      -cname \
      -cdn \
      -follow-redirects \
      -ports "$HTTPX_PORTS" \
      -rl "$HTTPX_RATE" \
      -o "$out_json"

  if [[ -s "$out_json" ]]; then
    jq -r '.url // empty' "$out_json" 2>/dev/null \
      | sort -u \
      > "$out_urls"

    jq -r '
      [
        (.url // "-"),
        ((.status_code // "-") | tostring),
        (.title // "-"),
        (.webserver // .server // "-"),
        ((.tech // .technologies // []) | if type == "array" then join("|") else tostring end),
        (.host // .input // "-"),
        (.cname // "-"),
        (.cdn_name // .cdn // "-")
      ] | @tsv
    ' "$out_json" 2>/dev/null > "$out_tsv" || : > "$out_tsv"

    {
      printf "%-8s %-48s %-14s %-32s %-42s\n" "STATUS" "URL" "SERVER" "TECH" "TITLE"
      printf "%-8s %-48s %-14s %-32s %-42s\n" "------" "---" "------" "----" "-----"

      jq -r '
        [
          ((.status_code // "-") | tostring),
          (.url // "-"),
          (.webserver // .server // "-"),
          ((.tech // .technologies // []) | if type == "array" then join("|") else tostring end),
          (.title // "-")
        ] | @tsv
      ' "$out_json" 2>/dev/null \
        | awk -F'\t' '{printf "%-8s %-48s %-14s %-32s %-42s\n",$1,substr($2,1,48),substr($3,1,14),substr($4,1,32),substr($5,1,42)}'
    } > "$out_pretty"
  else
    warn "httpx не вернул живых URL или завершился с ошибкой"
    : > "$out_urls"
    : > "$out_tsv"
    : > "$out_pretty"
  fi

  cp "$out_urls" "$RUN_DIR/live-urls.txt"

  ok "Live URLs: $(count_lines "$out_urls")"
  ok "httpx JSONL: $out_json"
  ok "httpx pretty: $out_pretty"
}


# ==============================================================================
# 11. nuclei
# ==============================================================================

run_nuclei() {
  local input="$RUN_DIR/05-live/live-urls.txt"
  local out_json="$RUN_DIR/06-nuclei/nuclei-results.jsonl"
  local out_tsv="$RUN_DIR/06-nuclei/nuclei-results.tsv"
  local out_pretty="$RUN_DIR/06-nuclei/nuclei-results-pretty.txt"
  local logf="$LOG_DIR/nuclei.log"

  if [[ "$RUN_NUCLEI" != "1" ]]; then
    warn "Nuclei пропущен"
    : > "$out_json"
    : > "$out_tsv"
    : > "$out_pretty"
    return 0
  fi

  section "9/9" "Nuclei: safe scan по live-urls.txt"

  if [[ -z "${NUCLEI_BIN:-}" || ! -x "$NUCLEI_BIN" ]]; then
    warn "nuclei не найден. Пропускаю этап nuclei."
    : > "$out_json"
    : > "$out_tsv"
    : > "$out_pretty"
    return 0
  fi

  if [[ ! -s "$input" ]]; then
    warn "live-urls.txt пустой. Nuclei запускать не на чем."
    : > "$out_json"
    : > "$out_tsv"
    : > "$out_pretty"
    return 0
  fi

  if [[ "$UPDATE_TEMPLATES" == "1" ]]; then
    run_logged \
      "Nuclei: обновление templates" \
      "$LOG_DIR/nuclei-update-templates.log" \
      "$NUCLEI_BIN" -update-templates
  fi

  # Жёстко под Nuclei v3.8.0:
  #   -j      = JSONL output
  #   -etags  = exclude tags
  #
  # Специально НЕ используем -json и авто-детект,
  # чтобы не получить старый баг: flag provided but not defined: -json.
  local cmd=(
    "$NUCLEI_BIN"
    -l "$input"
    -s "$NUCLEI_SEVERITY"
    -rl "$NUCLEI_RATE_LIMIT"
    -bs "$NUCLEI_BULK_SIZE"
    -retries "$NUCLEI_RETRIES"
    -timeout "$NUCLEI_TIMEOUT"
    -etags "$NUCLEI_EXCLUDE_TAGS"
    -j
    -o "$out_json"
  )

  run_logged \
    "Nuclei: severity=$NUCLEI_SEVERITY exclude-tags=$NUCLEI_EXCLUDE_TAGS" \
    "$logf" \
    "${cmd[@]}"

  if [[ -s "$out_json" ]]; then
    jq -r '
      [
        (.info.severity // .severity // "-"),
        (.["template-id"] // .templateID // .template_id // "-"),
        (.matched-at // .matched // .host // .url // "-"),
        (.info.name // .name // "-")
      ] | @tsv
    ' "$out_json" 2>/dev/null > "$out_tsv" || : > "$out_tsv"

    {
      printf "%-10s %-45s %-72s %-60s\n" "SEVERITY" "TEMPLATE" "TARGET" "NAME"
      printf "%-10s %-45s %-72s %-60s\n" "--------" "--------" "------" "----"

      awk -F'\t' '{
        printf "%-10s %-45s %-72s %-60s\n", $1, substr($2,1,45), substr($3,1,72), substr($4,1,60)
      }' "$out_tsv"
    } > "$out_pretty"
  else
    : > "$out_tsv"
    : > "$out_pretty"
  fi

  ok "Nuclei findings: $(count_lines "$out_json")"
  ok "Nuclei JSONL: $out_json"
  ok "Nuclei pretty: $out_pretty"
}


# ==============================================================================
# 12. Delta
# ==============================================================================

make_delta() {
  section "Δ" "Delta с предыдущим запуском"

  local delta_dir="$RUN_DIR/08-delta"
  mkdir -p "$delta_dir"

  local current_hosts="$RUN_DIR/all-hostnames.txt"
  local current_live="$RUN_DIR/live-urls.txt"

  if [[ -z "${PREVIOUS_LATEST:-}" || ! -d "$PREVIOUS_LATEST" ]]; then
    warn "Предыдущий latest не найден. Delta будет пустой."
    : > "$delta_dir/added-hostnames.txt"
    : > "$delta_dir/removed-hostnames.txt"
    : > "$delta_dir/added-live-urls.txt"
    : > "$delta_dir/removed-live-urls.txt"
    return 0
  fi

  local previous_hosts="$PREVIOUS_LATEST/all-hostnames.txt"
  local previous_live="$PREVIOUS_LATEST/live-urls.txt"

  if [[ -s "$previous_hosts" && -s "$current_hosts" ]]; then
    comm -13 <(sort -u "$previous_hosts") <(sort -u "$current_hosts") > "$delta_dir/added-hostnames.txt" || true
    comm -23 <(sort -u "$previous_hosts") <(sort -u "$current_hosts") > "$delta_dir/removed-hostnames.txt" || true
  else
    : > "$delta_dir/added-hostnames.txt"
    : > "$delta_dir/removed-hostnames.txt"
  fi

  if [[ -s "$previous_live" && -s "$current_live" ]]; then
    comm -13 <(sort -u "$previous_live") <(sort -u "$current_live") > "$delta_dir/added-live-urls.txt" || true
    comm -23 <(sort -u "$previous_live") <(sort -u "$current_live") > "$delta_dir/removed-live-urls.txt" || true
  else
    : > "$delta_dir/added-live-urls.txt"
    : > "$delta_dir/removed-live-urls.txt"
  fi

  ok "Added hostnames: $(count_lines "$delta_dir/added-hostnames.txt")"
  ok "Removed hostnames: $(count_lines "$delta_dir/removed-hostnames.txt")"
  ok "Added live URLs: $(count_lines "$delta_dir/added-live-urls.txt")"
  ok "Removed live URLs: $(count_lines "$delta_dir/removed-live-urls.txt")"
}


# ==============================================================================
# 13. Report
# ==============================================================================

make_report() {
  section "R" "Генерация report.md"

  local report="$RUN_DIR/07-reports/report.md"
  local roots="$RUN_DIR/01-roots/root-candidates.txt"
  local subfinder="$RUN_DIR/02-sources/subfinder/subfinder-subdomains.txt"
  local amass="$RUN_DIR/02-sources/amass/amass-subdomains.txt"
  local crtsh="$RUN_DIR/02-sources/crtsh/crtsh-subdomains.txt"
  local all="$RUN_DIR/all-hostnames.txt"
  local live="$RUN_DIR/live-urls.txt"
  local nuclei_json="$RUN_DIR/06-nuclei/nuclei-results.jsonl"

  local nuclei_total nuclei_critical nuclei_high nuclei_medium nuclei_low
  nuclei_total="$(count_lines "$nuclei_json")"

  if [[ -s "$nuclei_json" ]]; then
    nuclei_critical="$(jq -r 'select((.info.severity // .severity // "") == "critical") | .info.severity // .severity' "$nuclei_json" 2>/dev/null | wc -l | tr -d ' ')"
    nuclei_high="$(jq -r 'select((.info.severity // .severity // "") == "high") | .info.severity // .severity' "$nuclei_json" 2>/dev/null | wc -l | tr -d ' ')"
    nuclei_medium="$(jq -r 'select((.info.severity // .severity // "") == "medium") | .info.severity // .severity' "$nuclei_json" 2>/dev/null | wc -l | tr -d ' ')"
    nuclei_low="$(jq -r 'select((.info.severity // .severity // "") == "low") | .info.severity // .severity' "$nuclei_json" 2>/dev/null | wc -l | tr -d ' ')"
  else
    nuclei_critical="0"
    nuclei_high="0"
    nuclei_medium="0"
    nuclei_low="0"
  fi

  cat > "$report" <<EOF
# Attack Surface Report: $PROJECT

Generated: $(now)

Run directory:

\`\`\`text
$RUN_DIR
\`\`\`

## Scope

Seeds:

\`\`\`text
$(cat "$RUN_DIR/00-input/seeds.txt" 2>/dev/null || true)
\`\`\`

Root candidates:

\`\`\`text
$(cat "$roots" 2>/dev/null || true)
\`\`\`

## Summary

| Metric | Count |
|---|---:|
| Root candidates | $(count_lines "$roots") |
| Subfinder subdomains | $(count_lines "$subfinder") |
| Amass subdomains | $(count_lines "$amass") |
| crt.sh subdomains | $(count_lines "$crtsh") |
| All hostnames | $(count_lines "$all") |
| Live HTTP/HTTPS URLs | $(count_lines "$live") |
| Nuclei findings total | $nuclei_total |
| Nuclei critical | $nuclei_critical |
| Nuclei high | $nuclei_high |
| Nuclei medium | $nuclei_medium |
| Nuclei low | $nuclei_low |

## Important Files

| File | Description |
|---|---|
| \`all-hostnames.txt\` | Финальный список всех найденных hostnames |
| \`live-urls.txt\` | Живые HTTP/HTTPS URL после httpx |
| \`05-live/httpx-live.jsonl\` | Полный JSONL-вывод httpx |
| \`05-live/httpx-live-pretty.txt\` | Удобный просмотр live-сервисов |
| \`06-nuclei/nuclei-results.jsonl\` | JSONL-результаты nuclei |
| \`06-nuclei/nuclei-results-pretty.txt\` | Удобный просмотр nuclei findings |
| \`08-delta/added-hostnames.txt\` | Новые hostnames относительно прошлого запуска |
| \`08-delta/removed-hostnames.txt\` | Пропавшие hostnames относительно прошлого запуска |
| \`08-delta/added-live-urls.txt\` | Новые live URL |
| \`08-delta/removed-live-urls.txt\` | Пропавшие live URL |
| \`logs/\` | Логи каждого этапа |

## httpx Quick View

\`\`\`text
$(safe_head "$RUN_DIR/05-live/httpx-live-pretty.txt" 80)
\`\`\`

## Nuclei Quick View

\`\`\`text
$(safe_head "$RUN_DIR/06-nuclei/nuclei-results-pretty.txt" 80)
\`\`\`

## Delta

### Added hostnames

\`\`\`text
$(safe_head "$RUN_DIR/08-delta/added-hostnames.txt" 100)
\`\`\`

### Added live URLs

\`\`\`text
$(safe_head "$RUN_DIR/08-delta/added-live-urls.txt" 100)
\`\`\`

EOF

  ok "Report: $report"
}


# ==============================================================================
# 14. Final
# ==============================================================================

finalize() {
  ln -sfn "$RUN_DIR" "$BASE_DIR/latest"

  section "✓" "Готово"

  echo -e "${C_GREEN}${C_BOLD}Итог:${C_RESET}"
  echo
  printf "  %-25s %s\n" "Project:" "$PROJECT"
  printf "  %-25s %s\n" "Run dir:" "$RUN_DIR"
  printf "  %-25s %s\n" "Latest symlink:" "$BASE_DIR/latest"
  printf "  %-25s %s\n" "All hostnames:" "$(count_lines "$RUN_DIR/all-hostnames.txt")"
  printf "  %-25s %s\n" "Live URLs:" "$(count_lines "$RUN_DIR/live-urls.txt")"
  printf "  %-25s %s\n" "Nuclei findings:" "$(count_lines "$RUN_DIR/06-nuclei/nuclei-results.jsonl")"
  echo
  echo -e "${C_CYAN}Основные файлы:${C_RESET}"
  echo "  $RUN_DIR/all-hostnames.txt"
  echo "  $RUN_DIR/live-urls.txt"
  echo "  $RUN_DIR/05-live/httpx-live-pretty.txt"
  echo "  $RUN_DIR/06-nuclei/nuclei-results-pretty.txt"
  echo "  $RUN_DIR/07-reports/report.md"
  echo
}


# ==============================================================================
# 15. Main
# ==============================================================================

main() {
  init_colors
  parse_args "$@"
  init_project
  resolve_tools
  save_versions
  build_roots

  section "3/9" "Сбор поддоменов"
  run_subfinder
  run_amass
  run_crtsh
  build_all_hostnames

  run_dns_checks
  run_whois_checks
  classify_roots
  run_httpx
  run_nuclei
  make_delta
  make_report
  finalize
}

main "$@"
