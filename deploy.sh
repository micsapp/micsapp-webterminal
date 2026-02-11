#!/usr/bin/env bash
set -euo pipefail

# Deploy/redeploy this ttyd-auth project on the local machine.
# - Installs/updates nginx config from ./nginx/ttyd.conf
# - Reloads nginx
# - Restarts auth.py on 127.0.0.1:7682

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NGINX_SRC_CONF="${PROJECT_DIR}/nginx/ttyd.conf"
AUTH_PY="${PROJECT_DIR}/auth.py"
if [ "$(uname -s)" = "Darwin" ]; then
  AUTH_LOG="${HOME}/Library/Logs/ttyd-auth.log"
else
  AUTH_LOG="${PROJECT_DIR}/auth.log"
fi
AUTH_PID_FILE="${PROJECT_DIR}/.auth.pid"
AUTH_PORT="7682"
NGINX_PORT="7680"
AUTH_LAUNCHD_LABEL="com.ttyd-auth"
AUTH_PLIST="${HOME}/Library/LaunchAgents/${AUTH_LAUNCHD_LABEL}.plist"

say() { printf '%s\n' "$*"; }
err() { printf 'ERROR: %s\n' "$*" >&2; }

usage() {
  cat <<EOF
Usage:
  ./deploy.sh           Deploy/redeploy services
  ./deploy.sh --status  Show current health/status only
  ./deploy.sh --status --public-url https://example.com
  ./deploy.sh -h|--help Show this help
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    err "Missing required command: $1"
    exit 1
  }
}

is_macos() {
  [ "$(uname -s)" = "Darwin" ]
}

is_linux() {
  [ "$(uname -s)" = "Linux" ]
}

# Run a command with sudo when on Linux (for nginx/system operations).
# On macOS, Homebrew services run as the current user so sudo is not needed.
_priv() {
  if is_linux; then
    sudo "$@"
  else
    "$@"
  fi
}

ensure_linux_deps() {
  is_linux || return 0

  local need_apt=false

  if ! command -v nginx >/dev/null 2>&1; then
    say "nginx not found, will install..."
    need_apt=true
  fi
  if ! command -v sshpass >/dev/null 2>&1; then
    say "sshpass not found, will install..."
    need_apt=true
  fi
  if ! command -v tmux >/dev/null 2>&1; then
    say "tmux not found, will install..."
    need_apt=true
  fi

  if $need_apt && command -v apt-get >/dev/null 2>&1; then
    local pkgs=()
    command -v nginx   >/dev/null 2>&1 || pkgs+=(nginx)
    command -v sshpass >/dev/null 2>&1 || pkgs+=(sshpass)
    command -v tmux    >/dev/null 2>&1 || pkgs+=(tmux)
    sudo apt-get update -qq
    sudo apt-get install -y "${pkgs[@]}"
  fi

  if ! command -v ttyd >/dev/null 2>&1; then
    say "ttyd not found, installing native binary..."
    local arch
    arch="$(uname -m)"
    case "$arch" in
      x86_64)  arch="x86_64" ;;
      aarch64) arch="aarch64" ;;
      armv7l)  arch="armhf" ;;
      *)       err "Unsupported architecture: $arch"; exit 1 ;;
    esac
    sudo curl -fSL -o /usr/local/bin/ttyd \
      "https://github.com/tsl0922/ttyd/releases/latest/download/ttyd.${arch}"
    sudo chmod +x /usr/local/bin/ttyd
    say "ttyd installed: $(ttyd --version)"
  fi
}

detect_nginx_conf_dest() {
  if [ -d "/usr/local/etc/nginx/servers" ]; then
    printf '%s\n' "/usr/local/etc/nginx/servers/ttyd.conf"
    return 0
  fi
  if [ -d "/opt/homebrew/etc/nginx/servers" ]; then
    printf '%s\n' "/opt/homebrew/etc/nginx/servers/ttyd.conf"
    return 0
  fi
  if [ -d "/etc/nginx/sites-available" ]; then
    printf '%s\n' "/etc/nginx/sites-available/ttyd.conf"
    return 0
  fi
  # RHEL/CentOS/Fedora use conf.d instead of sites-available.
  if [ -d "/etc/nginx/conf.d" ]; then
    printf '%s\n' "/etc/nginx/conf.d/ttyd.conf"
    return 0
  fi
  err "Cannot find nginx config directory."
  err "Expected one of: /usr/local/etc/nginx/servers, /opt/homebrew/etc/nginx/servers, /etc/nginx/sites-available, /etc/nginx/conf.d"
  exit 1
}

install_nginx_conf() {
  local dest_conf="$1"
  local dest_dir
  dest_dir="$(dirname "$dest_conf")"

  say "Installing nginx config -> ${dest_conf}"

  if [ ! -f "${NGINX_SRC_CONF}" ]; then
    err "Source nginx config not found: ${NGINX_SRC_CONF}"
    exit 1
  fi

  if [ ! -d "$dest_dir" ]; then
    _priv mkdir -p "$dest_dir"
  fi

  # Clean up legacy backups that may get included by brew nginx configs that do
  # `include servers/*;`. Those backups can create duplicate/conflicting servers.
  local legacy
  for legacy in "${dest_dir}/$(basename "$dest_conf").bak."*; do
    [ -f "$legacy" ] || continue
    local hidden="${dest_dir}/.$(basename "$legacy")"
    _priv mv "$legacy" "$hidden" 2>/dev/null || _priv rm -f "$legacy" 2>/dev/null || true
  done

  if [ -f "$dest_conf" ] && cmp -s "${NGINX_SRC_CONF}" "$dest_conf"; then
    say "nginx config unchanged."
  else
    if [ -f "$dest_conf" ]; then
      # IMPORTANT: brew nginx often does `include servers/*;` so backups inside that dir
      # can get loaded as live config. Use a dotfile backup name to avoid inclusion.
      local backup_dir
      backup_dir="$(dirname "$dest_conf")"
      local backup="${backup_dir}/.$(basename "$dest_conf").bak.$(date +%Y%m%d_%H%M%S)"
      say "Backing up existing config -> ${backup}"
      _priv cp "$dest_conf" "$backup"
    fi
    _priv cp "${NGINX_SRC_CONF}" "$dest_conf"
    say "nginx config updated."
  fi

  # Debian/Ubuntu: ensure site is enabled.
  if [ -d "/etc/nginx/sites-enabled" ] && [ "$dest_conf" = "/etc/nginx/sites-available/ttyd.conf" ]; then
    _priv ln -sf "$dest_conf" "/etc/nginx/sites-enabled/ttyd.conf"
  fi
}

reload_nginx() {
  say "Testing nginx config..."
  _priv nginx -t
  say "Reloading nginx..."
  if is_linux && pidof systemd >/dev/null 2>&1; then
    sudo systemctl reload nginx
  elif is_linux && command -v service >/dev/null 2>&1; then
    sudo service nginx reload
  else
    nginx -s reload
  fi
}

stop_auth_service() {
  # macOS launchd-managed auth service.
  if is_macos && [ -f "$AUTH_PLIST" ] && command -v launchctl >/dev/null 2>&1; then
    launchctl unload "$AUTH_PLIST" 2>/dev/null || true
  fi

  # Linux systemd user service.
  if is_linux && pidof systemd >/dev/null 2>&1; then
    systemctl --user stop ttyd-auth.service 2>/dev/null || true
  fi

  # Best-effort stop by PID file first.
  if [ -f "$AUTH_PID_FILE" ]; then
    local pid
    pid="$(cat "$AUTH_PID_FILE" 2>/dev/null || true)"
    if [ -n "${pid}" ] && kill -0 "$pid" 2>/dev/null; then
      say "Stopping existing auth service PID ${pid}"
      kill "$pid" || true
      sleep 1
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$AUTH_PID_FILE"
  fi

  # Also stop any existing instance started elsewhere.
  if command -v lsof >/dev/null 2>&1; then
    lsof -ti:"${AUTH_PORT}" 2>/dev/null | xargs kill 2>/dev/null || true
  fi
  pkill -f "python3 ${AUTH_PY}" 2>/dev/null || true
}

wait_for_auth_ready() {
  local i
  for i in $(seq 1 20); do
    if command -v curl >/dev/null 2>&1; then
      local code
      code="$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${AUTH_PORT}/api/auth" || true)"
      if [ "$code" = "200" ] || [ "$code" = "401" ]; then
        return 0
      fi
    fi
    sleep 0.5
  done

  return 1
}

write_auth_plist() {
  local pybin
  local sshpass_bin
  local ttyd_bin
  local path_value
  pybin="$(command -v python3)"
  sshpass_bin="$(command -v sshpass)"
  ttyd_bin="$(command -v ttyd)"
  path_value="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"

  mkdir -p "$(dirname "$AUTH_PLIST")"
  mkdir -p "$(dirname "$AUTH_LOG")"

  cat > "$AUTH_PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${AUTH_LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${pybin}</string>
    <string>${AUTH_PY}</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${PROJECT_DIR}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PYTHONUNBUFFERED</key>
    <string>1</string>
    <key>PATH</key>
    <string>${path_value}</string>
    <key>AUTH_PORT</key>
    <string>${AUTH_PORT}</string>
    <key>SSHPASS_BIN</key>
    <string>${sshpass_bin}</string>
    <key>TTYD_BIN</key>
    <string>${ttyd_bin}</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${AUTH_LOG}</string>
  <key>StandardErrorPath</key>
  <string>${AUTH_LOG}</string>
</dict>
</plist>
PLISTEOF
}

write_auth_systemd_unit() {
  local svc_dir="${HOME}/.config/systemd/user"
  mkdir -p "$svc_dir"

  local pybin sshpass_bin ttyd_bin
  pybin="$(command -v python3)"
  sshpass_bin="$(command -v sshpass)"
  ttyd_bin="$(command -v ttyd)"

  cat > "${svc_dir}/ttyd-auth.service" <<SVCEOF
[Unit]
Description=ttyd web terminal auth service
After=network.target

[Service]
Type=simple
Environment=PYTHONUNBUFFERED=1
Environment=AUTH_PORT=${AUTH_PORT}
Environment=SSHPASS_BIN=${sshpass_bin}
Environment=TTYD_BIN=${ttyd_bin}
WorkingDirectory=${PROJECT_DIR}
ExecStart=${pybin} ${AUTH_PY}
Restart=on-failure
RestartSec=5
StandardOutput=append:${AUTH_LOG}
StandardError=append:${AUTH_LOG}

[Install]
WantedBy=default.target
SVCEOF
}

start_auth_service() {
  [ -f "${AUTH_PY}" ] || { err "Missing ${AUTH_PY}"; exit 1; }

  mkdir -p "$(dirname "$AUTH_LOG")"
  say "Starting auth service..."

  if is_macos && command -v launchctl >/dev/null 2>&1; then
    write_auth_plist
    launchctl unload "$AUTH_PLIST" 2>/dev/null || true
    launchctl load "$AUTH_PLIST"
    if wait_for_auth_ready; then
      say "Auth service running via launchd (${AUTH_LAUNCHD_LABEL})"
      rm -f "$AUTH_PID_FILE"
      return 0
    fi
    err "Auth service failed to become ready via launchd. Check log: ${AUTH_LOG}"
    exit 1
  fi

  if is_linux && pidof systemd >/dev/null 2>&1; then
    write_auth_systemd_unit
    systemctl --user daemon-reload
    systemctl --user restart ttyd-auth.service
    if wait_for_auth_ready; then
      say "Auth service running via systemd (ttyd-auth.service)"
      rm -f "$AUTH_PID_FILE"
      return 0
    fi
    err "Auth service failed to become ready via systemd. Check log: ${AUTH_LOG}"
    exit 1
  fi

  # Fallback mode (no launchd/systemd).
  nohup python3 "${AUTH_PY}" >>"${AUTH_LOG}" 2>&1 &
  local pid=$!
  printf '%s\n' "$pid" > "$AUTH_PID_FILE"

  if wait_for_auth_ready; then
    say "Auth service running (pid: ${pid})"
    return 0
  fi

  err "Auth service failed to become ready. Check log: ${AUTH_LOG}"
  rm -f "$AUTH_PID_FILE"
  exit 1
}

status_report() {
  local public_url="${1:-}"
  local rc=0
  local dest_conf
  local code

  say "Status report (local host health)"
  say "project    : ${PROJECT_DIR}"
  say "auth log   : ${AUTH_LOG}"

  if is_macos && command -v launchctl >/dev/null 2>&1; then
    if launchctl list | grep -q "${AUTH_LAUNCHD_LABEL}"; then
      say "launchd auth : OK (${AUTH_LAUNCHD_LABEL} loaded)"
    else
      say "launchd auth : WARN (${AUTH_LAUNCHD_LABEL} not loaded)"
    fi
  fi

  if is_linux && pidof systemd >/dev/null 2>&1; then
    if systemctl --user is-active --quiet ttyd-auth.service 2>/dev/null; then
      say "systemd auth : OK (ttyd-auth.service active)"
    else
      say "systemd auth : WARN (ttyd-auth.service not active)"
    fi
  fi

  if dest_conf="$(detect_nginx_conf_dest 2>/dev/null)"; then
    say "nginx conf : ${dest_conf}"
    if [ -f "$dest_conf" ]; then
      say "nginx conf : OK (present)"
    else
      say "nginx conf : FAIL (missing)"
      rc=1
    fi
  else
    say "nginx conf : FAIL (path not detected)"
    rc=1
  fi

  if _priv nginx -t >/dev/null 2>&1; then
    say "nginx test : OK"
  else
    say "nginx test : FAIL"
    rc=1
  fi

  if command -v lsof >/dev/null 2>&1; then
    if _priv lsof -nP -iTCP:7680 -sTCP:LISTEN >/dev/null 2>&1; then
      say "port ${NGINX_PORT} : OK (nginx listening)"
    else
      say "port ${NGINX_PORT} : FAIL (not listening)"
      rc=1
    fi

    if lsof -nP -iTCP:"${AUTH_PORT}" -sTCP:LISTEN >/dev/null 2>&1; then
      say "port ${AUTH_PORT} : OK (auth listening)"
    else
      say "port ${AUTH_PORT} : FAIL (not listening)"
      rc=1
    fi
  else
    say "ports      : SKIP (lsof not available)"
  fi

  if command -v curl >/dev/null 2>&1; then
    code="$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${NGINX_PORT}/login" || true)"
    if [ "$code" = "200" ]; then
      say "GET :${NGINX_PORT}/login : OK (200)"
    else
      say "GET :${NGINX_PORT}/login : FAIL (${code:-no response})"
      rc=1
    fi

    code="$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${AUTH_PORT}/api/auth" || true)"
    if [ "$code" = "200" ] || [ "$code" = "401" ]; then
      say "GET :${AUTH_PORT}/api/auth : OK (${code})"
    else
      say "GET :${AUTH_PORT}/api/auth : FAIL (${code:-no response})"
      rc=1
    fi
  else
    say "http checks: SKIP (curl not available)"
  fi

  if [ -n "$public_url" ] && command -v curl >/dev/null 2>&1; then
    code="$(curl -k -s -o /dev/null -w "%{http_code}" "${public_url%/}/login" || true)"
    if [ "$code" = "200" ] || [ "$code" = "302" ]; then
      say "GET public /login : OK (${code})"
    else
      say "GET public /login : WARN (${code:-no response})"
    fi
  fi

  return "$rc"
}

main() {
  local mode=""
  local public_url=""

  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help)
        usage
        return 0
        ;;
      --status)
        mode="status"
        shift
        ;;
      --public-url)
        if [ $# -lt 2 ]; then
          err "--public-url requires a value"
          return 1
        fi
        public_url="$2"
        shift 2
        ;;
      "")
        shift
        ;;
      *)
        err "Unknown argument: $1"
        usage
        return 1
        ;;
    esac
  done

  case "$mode" in
    status)
      status_report "$public_url"
      return $?
      ;;
    "")
      ;;
    *)
      err "Unexpected mode: $mode"
      return 1
      ;;
  esac

  ensure_linux_deps
  need_cmd python3
  need_cmd nginx
  need_cmd sshpass
  need_cmd ttyd

  local dest_conf
  dest_conf="$(detect_nginx_conf_dest)"

  install_nginx_conf "$dest_conf"
  reload_nginx
  stop_auth_service
  start_auth_service

  say ""
  say "Deploy complete."
  say "nginx conf : ${dest_conf}"
  say "auth log   : ${AUTH_LOG}"
}

main "$@"
