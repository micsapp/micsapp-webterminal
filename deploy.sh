#!/usr/bin/env bash
set -euo pipefail

# Deploy/redeploy this ttyd-auth project on the local machine.
# Manages all components: sshd, nginx, auth.py, cloudflared tunnel.
# Health-checks each component and only starts what's actually down.

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

CF_CONFIG="${HOME}/.cloudflared/config.yml"
CF_LOG="${PROJECT_DIR}/cloudflared.log"
CF_TMUX_SESSION="cloudflared"

say() { printf '%s\n' "$*"; }
err() { printf 'ERROR: %s\n' "$*" >&2; }

usage() {
  cat <<EOF
Usage:
  ./deploy.sh              Deploy/start services (only starts what's down)
  ./deploy.sh --restart    Force restart all components
  ./deploy.sh --status     Show current health/status only
  ./deploy.sh --status --public-url https://example.com
  ./deploy.sh -h|--help    Show this help
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

start_nginx() {
  say "Starting nginx..."
  if is_linux && pidof systemd >/dev/null 2>&1; then
    sudo systemctl start nginx
  elif is_linux && command -v service >/dev/null 2>&1; then
    sudo service nginx start
  else
    nginx
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

# ─── Cloudflared tunnel helpers ───────────────────────────────────────────────

detect_tunnel_name() {
  if [ -f "$CF_CONFIG" ]; then
    grep -E '^tunnel:' "$CF_CONFIG" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '"' || true
  fi
}

detect_tunnel_hostname() {
  if [ -f "$CF_CONFIG" ]; then
    grep -E '^\s*-\s*hostname:' "$CF_CONFIG" 2>/dev/null | head -1 | awk '{print $NF}' | tr -d '"' || true
  fi
}

check_sshd() {
  pgrep -x sshd >/dev/null 2>&1
}

# Ensure sshd allows password auth on localhost (required by auth.py)
# while keeping it disabled for external connections.
check_sshd_localhost_password_auth() {
  is_linux || return 0
  local needs_fix=false

  # Check if password auth is globally disabled.
  local global_off=false
  if grep -rqE '^\s*PasswordAuthentication\s+no' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null; then
    global_off=true
  fi

  if ! $global_off; then
    return 0
  fi

  # Password auth is off globally. Check if there's a Match block for localhost.
  if grep -A2 -E '^\s*Match\s+Address\s+127\.0\.0\.1' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
    | grep -qE '^\s*PasswordAuthentication\s+yes'; then
    return 0
  fi

  # Need to fix: add localhost Match block.
  say "  Fixing sshd: enabling password auth on localhost only (required by auth.py)..."
  local conf="/etc/ssh/sshd_config.d/60-cloudimg-settings.conf"
  if [ ! -f "$conf" ]; then
    conf="/etc/ssh/sshd_config.d/99-webterminal.conf"
  fi
  sudo tee "$conf" >/dev/null <<'SSHEOF'
PasswordAuthentication no

Match Address 127.0.0.1,::1
    PasswordAuthentication yes
SSHEOF

  sudo sshd -t 2>/dev/null || { err "sshd config test failed after edit"; return 1; }
  restart_sshd
}

restart_sshd() {
  if pidof systemd >/dev/null 2>&1; then
    local sshd_name="sshd"
    if ! systemctl list-unit-files "${sshd_name}.service" >/dev/null 2>&1; then
      sshd_name="ssh"
    fi
    sudo systemctl restart "$sshd_name"
  elif command -v service >/dev/null 2>&1; then
    sudo service ssh restart
  else
    sudo kill -HUP "$(cat /var/run/sshd.pid 2>/dev/null || pgrep -x sshd | head -1)" 2>/dev/null || sudo /usr/sbin/sshd
  fi
}

start_sshd() {
  say "Starting sshd..."
  if is_macos; then
    if sudo systemsetup -getremotelogin 2>/dev/null | grep -qi "on"; then
      say "  SSH (Remote Login) already enabled."
    else
      sudo systemsetup -setremotelogin on
    fi
  elif pidof systemd >/dev/null 2>&1; then
    local sshd_name="sshd"
    if ! systemctl list-unit-files "${sshd_name}.service" >/dev/null 2>&1; then
      sshd_name="ssh"
    fi
    sudo systemctl start "$sshd_name"
  elif command -v service >/dev/null 2>&1; then
    sudo service ssh start
  else
    sudo /usr/sbin/sshd
  fi
}

_port_listening() {
  local port="$1"
  # Try multiple methods; return 0 on first success.
  if command -v lsof >/dev/null 2>&1; then
    _priv lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1 && return 0
  fi
  if /usr/sbin/ss -tlnp 2>/dev/null | grep -q ":${port} "; then
    return 0
  fi
  # Last resort: try curl.
  if command -v curl >/dev/null 2>&1; then
    curl -s -o /dev/null --max-time 2 "http://127.0.0.1:${port}/" 2>/dev/null && return 0
  fi
  return 1
}

check_nginx() {
  # Check if nginx master process is running AND listening on our port.
  if ! pgrep -x nginx >/dev/null 2>&1; then
    return 1
  fi
  _port_listening "${NGINX_PORT}"
}

check_auth() {
  if command -v curl >/dev/null 2>&1; then
    local code
    code="$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${AUTH_PORT}/api/auth" 2>/dev/null || true)"
    [ "$code" = "200" ] || [ "$code" = "401" ]
  else
    _port_listening "${AUTH_PORT}"
  fi
}

check_cloudflared() {
  pgrep -x cloudflared >/dev/null 2>&1
}

stop_cloudflared() {
  say "Stopping cloudflared..."
  if tmux has-session -t "$CF_TMUX_SESSION" 2>/dev/null; then
    tmux kill-session -t "$CF_TMUX_SESSION" 2>/dev/null || true
  fi
  # Also kill any stray cloudflared processes (e.g. from nohup or systemd).
  if is_linux && pidof systemd >/dev/null 2>&1; then
    sudo systemctl stop cloudflared 2>/dev/null || true
  fi
  pkill -x cloudflared 2>/dev/null || true
  sleep 1
}

start_cloudflared() {
  local tunnel_name
  tunnel_name="$(detect_tunnel_name)"
  if [ -z "$tunnel_name" ]; then
    err "Cannot detect tunnel name from ${CF_CONFIG}. Run cf_tunnel_install.sh first."
    return 1
  fi

  if ! command -v cloudflared >/dev/null 2>&1; then
    err "cloudflared not found. Run cf_tunnel_install.sh first."
    return 1
  fi

  say "Starting cloudflared tunnel '${tunnel_name}' in tmux session '${CF_TMUX_SESSION}'..."

  # Kill existing tmux session if present (stale).
  if tmux has-session -t "$CF_TMUX_SESSION" 2>/dev/null; then
    tmux kill-session -t "$CF_TMUX_SESSION" 2>/dev/null || true
    sleep 1
  fi

  tmux new-session -d -s "$CF_TMUX_SESSION" \
    "cloudflared tunnel run ${tunnel_name} 2>&1 | tee -a ${CF_LOG}"

  # Wait for cloudflared to establish connections (up to 15s).
  say "Waiting for tunnel to connect..."
  local i
  for i in $(seq 1 30); do
    if pgrep -x cloudflared >/dev/null 2>&1; then
      # Check if tunnel has active connections.
      local conns
      conns="$(cloudflared tunnel info "$tunnel_name" 2>/dev/null | grep -c 'CONNECTIONS\|connector' || true)"
      if [ "${conns:-0}" -gt 0 ]; then
        say "  Tunnel '${tunnel_name}' connected."
        return 0
      fi
    fi
    sleep 0.5
  done

  # Even if connections aren't confirmed yet, check process is alive.
  if pgrep -x cloudflared >/dev/null 2>&1; then
    say "  cloudflared is running (connections may still be establishing)."
    say "  Log: ${CF_LOG}"
    say "  Attach: tmux attach -t ${CF_TMUX_SESSION}"
    return 0
  fi

  err "cloudflared failed to start. Check log: ${CF_LOG}"
  return 1
}

# ─── Smart component management ──────────────────────────────────────────────

# ensure_component NAME CHECK_FN START_FN
# Returns 0 if component is (now) running, 1 if start failed.
ensure_component() {
  local name="$1" check_fn="$2" start_fn="$3"

  if "$check_fn" 2>/dev/null; then
    say "[OK]  ${name}"
    return 0
  fi

  say "[DOWN] ${name} - starting..."
  if "$start_fn"; then
    # Verify it came up.
    sleep 1
    if "$check_fn" 2>/dev/null; then
      say "[OK]  ${name} - started"
      return 0
    fi
  fi

  err "${name} - failed to start"
  return 1
}

# ─── Status report ────────────────────────────────────────────────────────────

status_report() {
  local public_url="${1:-}"
  local rc=0
  local dest_conf
  local code

  say ""
  say "=== Status Report ==="
  say "project    : ${PROJECT_DIR}"
  say "auth log   : ${AUTH_LOG}"
  say "tunnel log : ${CF_LOG}"
  say ""

  # ── sshd ──
  if check_sshd; then
    say "sshd         : OK (running)"
  else
    say "sshd         : FAIL (not running)"
    rc=1
  fi

  # Check localhost password auth (needed by auth.py).
  if is_linux; then
    local pw_off=false
    if grep -rqE '^\s*PasswordAuthentication\s+no' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null; then
      pw_off=true
    fi
    if $pw_off; then
      if grep -A2 -rE '^\s*Match\s+Address\s+127\.0\.0\.1' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null \
        | grep -qE 'PasswordAuthentication\s+yes'; then
        say "sshd pw-auth : OK (localhost only)"
      else
        say "sshd pw-auth : FAIL (password auth disabled, login will fail)"
        rc=1
      fi
    else
      say "sshd pw-auth : OK"
    fi
  fi

  # ── nginx ──
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
    local conf_dir
    conf_dir="$(dirname "$dest_conf")"
    if [ -f "$dest_conf" ]; then
      say "nginx conf   : OK (${dest_conf})"
    else
      # cf_tunnel_install.sh creates hostname-based configs (e.g. dev-ssh.wetigu.com.conf).
      local alt_conf
      alt_conf="$(ls "${conf_dir}"/*.conf 2>/dev/null | head -1 || true)"
      if [ -n "$alt_conf" ]; then
        say "nginx conf   : OK (${alt_conf})"
      else
        say "nginx conf   : FAIL (no config in ${conf_dir})"
        rc=1
      fi
    fi
  else
    say "nginx conf   : FAIL (path not detected)"
    rc=1
  fi

  if _priv nginx -t >/dev/null 2>&1; then
    say "nginx test   : OK"
  else
    say "nginx test   : FAIL"
    rc=1
  fi

  if check_nginx; then
    say "nginx :${NGINX_PORT} : OK (listening)"
  else
    say "nginx :${NGINX_PORT} : FAIL (not listening)"
    rc=1
  fi

  # ── auth.py ──
  if check_auth; then
    say "auth  :${AUTH_PORT} : OK (responding)"
  else
    say "auth  :${AUTH_PORT} : FAIL (not responding)"
    rc=1
  fi

  # ── cloudflared ──
  local tunnel_name
  tunnel_name="$(detect_tunnel_name)"
  if [ -n "$tunnel_name" ]; then
    if check_cloudflared; then
      say "cloudflared  : OK (running, tunnel: ${tunnel_name})"
      if tmux has-session -t "$CF_TMUX_SESSION" 2>/dev/null; then
        say "tmux session : OK (${CF_TMUX_SESSION})"
      else
        say "tmux session : WARN (not in tmux - may be systemd/nohup)"
      fi
    else
      say "cloudflared  : FAIL (not running, tunnel: ${tunnel_name})"
      rc=1
    fi
  else
    say "cloudflared  : SKIP (no tunnel configured in ${CF_CONFIG})"
  fi

  # ── HTTP health checks ──
  say ""
  if command -v curl >/dev/null 2>&1; then
    code="$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${NGINX_PORT}/login" || true)"
    if [ "$code" = "200" ]; then
      say "GET :${NGINX_PORT}/login     : OK (200)"
    else
      say "GET :${NGINX_PORT}/login     : FAIL (${code:-no response})"
      rc=1
    fi

    code="$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${AUTH_PORT}/api/auth" || true)"
    if [ "$code" = "200" ] || [ "$code" = "401" ]; then
      say "GET :${AUTH_PORT}/api/auth   : OK (${code})"
    else
      say "GET :${AUTH_PORT}/api/auth   : FAIL (${code:-no response})"
      rc=1
    fi
  else
    say "http checks  : SKIP (curl not available)"
  fi

  # ── Public URL check ──
  # Auto-detect from tunnel config if not provided.
  if [ -z "$public_url" ]; then
    local hostname
    hostname="$(detect_tunnel_hostname)"
    if [ -n "$hostname" ]; then
      public_url="https://${hostname}"
    fi
  fi

  if [ -n "$public_url" ] && command -v curl >/dev/null 2>&1; then
    code="$(curl -k -s -o /dev/null -w "%{http_code}" --max-time 10 "${public_url%/}/login" || true)"
    if [ "$code" = "200" ] || [ "$code" = "302" ]; then
      say "GET ${public_url}/login : OK (${code})"
    else
      say "GET ${public_url}/login : FAIL (${code:-no response})"
      rc=1
    fi
  fi

  say ""
  if [ "$rc" -eq 0 ]; then
    say "All components healthy."
  else
    say "Some components have issues (see above)."
  fi

  return "$rc"
}

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
  local mode=""
  local public_url=""
  local force_restart=false

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
      --restart)
        force_restart=true
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
  local had_failure=false

  say ""
  say "=== Checking components ==="
  say ""

  # ── 1. sshd ──
  if $force_restart || ! check_sshd; then
    start_sshd || had_failure=true
  else
    say "[OK]  sshd"
  fi
  check_sshd_localhost_password_auth || had_failure=true

  # ── 2. nginx config + process ──
  install_nginx_conf "$dest_conf"
  if $force_restart; then
    reload_nginx || had_failure=true
  elif ! check_nginx; then
    say "[DOWN] nginx - starting..."
    start_nginx || had_failure=true
    # Also reload to pick up any config changes.
    reload_nginx 2>/dev/null || true
  else
    # nginx is running; reload only if config changed.
    if [ -f "$dest_conf" ] && ! cmp -s "${NGINX_SRC_CONF}" "$dest_conf" 2>/dev/null; then
      reload_nginx || had_failure=true
    else
      say "[OK]  nginx (:${NGINX_PORT})"
    fi
  fi

  # ── 3. auth.py ──
  if $force_restart; then
    stop_auth_service
    start_auth_service || had_failure=true
  elif ! check_auth; then
    say "[DOWN] auth service - starting..."
    stop_auth_service
    start_auth_service || had_failure=true
  else
    say "[OK]  auth (:${AUTH_PORT})"
  fi

  # ── 4. cloudflared tunnel ──
  local tunnel_name
  tunnel_name="$(detect_tunnel_name)"
  if [ -n "$tunnel_name" ]; then
    if $force_restart; then
      stop_cloudflared
      start_cloudflared || had_failure=true
    elif ! check_cloudflared; then
      say "[DOWN] cloudflared - starting..."
      start_cloudflared || had_failure=true
    else
      say "[OK]  cloudflared (tunnel: ${tunnel_name})"
    fi
  else
    say "[SKIP] cloudflared (no tunnel in ${CF_CONFIG})"
  fi

  # ── Final status ──
  say ""
  say "=== Deploy complete ==="
  status_report "$public_url"
}

main "$@"
