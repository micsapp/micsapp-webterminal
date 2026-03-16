#!/bin/bash
# add-local.sh — Interactive wizard to enable local LAN HTTPS access to the webterminal.
#
# Creates a separate nginx server block (port 7681, SSL) so the terminal is
# accessible from the local network without going through Cloudflare Tunnel.
# The config is NOT managed by deploy.sh and survives redeploys.
#
# Usage:
#   ./add-local.sh            # interactive wizard
#   ./add-local.sh --remove   # remove local access config

set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
NGINX_SRC="${PROJECT_DIR}/nginx/ttyd.conf"
DEFAULT_LOCAL_PORT=7681
DEFAULT_CERT_DIR="/etc/ssl/cloudflare"

# ─── Helpers ──────────────────────────────────────────────────────────────────

say()     { printf '  %s\n' "$*"; }
err()     { printf '  \033[31mERROR:\033[0m %s\n' "$*" >&2; }
info()    { printf '  \033[36m%s\033[0m\n' "$*"; }
success() { printf '  \033[32m%s\033[0m\n' "$*"; }
bold()    { printf '  \033[1m%s\033[0m\n' "$*"; }
dim()     { printf '  \033[2m%s\033[0m\n' "$*"; }

_priv() {
  if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}

prompt() {
  local msg="$1" default="${2:-}"
  if [ -n "$default" ]; then
    printf '  \033[33m?\033[0m %s \033[2m[%s]\033[0m: ' "$msg" "$default"
  else
    printf '  \033[33m?\033[0m %s: ' "$msg"
  fi
  read -r REPLY
  REPLY="${REPLY:-$default}"
}

confirm() {
  local msg="$1" default="${2:-y}"
  local hint="Y/n"
  [ "$default" = "n" ] && hint="y/N"
  printf '  \033[33m?\033[0m %s \033[2m[%s]\033[0m: ' "$msg" "$hint"
  read -r REPLY
  REPLY="${REPLY:-$default}"
  case "$REPLY" in [yY]*) return 0 ;; *) return 1 ;; esac
}

header() {
  echo ""
  bold "─── $1 ───"
  echo ""
}

check_ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
check_fail() { printf '  \033[31m✗\033[0m %s\n' "$*"; }
check_warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }

# ─── Detect nginx config directory ───────────────────────────────────────────

detect_nginx_dir() {
  if [ -d "/etc/nginx/sites-available" ]; then
    CONF_DIR="/etc/nginx/sites-available"
    ENABLED_DIR="/etc/nginx/sites-enabled"
  elif [ -d "/etc/nginx/conf.d" ]; then
    CONF_DIR="/etc/nginx/conf.d"
    ENABLED_DIR=""
  elif [ -d "/usr/local/etc/nginx/servers" ]; then
    CONF_DIR="/usr/local/etc/nginx/servers"
    ENABLED_DIR=""
  else
    return 1
  fi
}

# ─── Detect tunnel name ─────────────────────────────────────────────────────

detect_tunnel_name() {
  local cf_config="${HOME}/.cloudflared/config.yml"
  if [ -f "$cf_config" ]; then
    grep -E '^tunnel:' "$cf_config" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '"'
  fi
}

# ─── Remove mode ─────────────────────────────────────────────────────────────

if [ "${1:-}" = "--remove" ]; then
  header "Remove Local Access"

  detect_nginx_dir || { err "Cannot find nginx config directory"; exit 1; }

  # Find any *-local.conf files
  local_confs=()
  for f in "${CONF_DIR}/"*-local.conf; do
    [ -f "$f" ] && local_confs+=("$f")
  done

  if [ ${#local_confs[@]} -eq 0 ]; then
    check_warn "No local access configs found in ${CONF_DIR}"
    exit 0
  fi

  for conf in "${local_confs[@]}"; do
    conf_name="$(basename "$conf")"
    say "Found: ${conf}"
  done
  echo ""

  if confirm "Remove local access config?"; then
    for conf in "${local_confs[@]}"; do
      conf_name="$(basename "$conf")"
      _priv rm -f "$conf"
      [ -n "${ENABLED_DIR:-}" ] && _priv rm -f "${ENABLED_DIR}/${conf_name}"
      check_ok "Removed ${conf_name}"
    done
    _priv nginx -t 2>/dev/null && (_priv nginx -s reload 2>/dev/null || _priv service nginx reload)
    success "Local access removed."
  else
    say "Cancelled."
  fi
  exit 0
fi

# ─── Interactive wizard ─────────────────────────────────────────────────────

header "Local LAN Access Setup"
say "This wizard will configure HTTPS access to the webterminal"
say "from your local network, without going through Cloudflare Tunnel."
echo ""

# ── Step 1: System detection ──

header "Step 1: System Detection"

# OS
OS="$(uname -s)"
case "$OS" in
  Linux)
    if grep -qi microsoft /proc/version 2>/dev/null; then
      check_ok "Platform: WSL2 (Linux on Windows)"
      IS_WSL=true
    else
      check_ok "Platform: Linux"
      IS_WSL=false
    fi
    ;;
  Darwin)
    check_ok "Platform: macOS"
    IS_WSL=false
    ;;
  *)
    check_warn "Platform: $OS (untested)"
    IS_WSL=false
    ;;
esac

# nginx
if command -v nginx >/dev/null 2>&1; then
  check_ok "nginx: $(nginx -v 2>&1 | sed 's/.*\///')"
else
  check_fail "nginx: not found"
  err "nginx is required. Install it first."
  exit 1
fi

if detect_nginx_dir; then
  check_ok "nginx config: ${CONF_DIR}"
else
  check_fail "nginx config directory not found"
  exit 1
fi

# Tunnel
TUNNEL_NAME="$(detect_tunnel_name)"
if [ -n "$TUNNEL_NAME" ]; then
  check_ok "Tunnel name: ${TUNNEL_NAME}"
else
  check_warn "Tunnel: not detected (will ask for hostname)"
fi

# Template
if [ -f "$NGINX_SRC" ]; then
  check_ok "nginx template: ${NGINX_SRC}"
else
  check_fail "nginx template not found: ${NGINX_SRC}"
  exit 1
fi

# ── Step 2: Configuration ──

header "Step 2: Configuration"

# Hostname
if [ -n "$TUNNEL_NAME" ]; then
  DEFAULT_HOSTNAME="${TUNNEL_NAME}-local.micstec.com"
else
  DEFAULT_HOSTNAME=""
fi
prompt "Local hostname" "$DEFAULT_HOSTNAME"
LOCAL_HOSTNAME="$REPLY"
if [ -z "$LOCAL_HOSTNAME" ]; then
  err "Hostname is required"
  exit 1
fi

# Port
prompt "HTTPS port" "$DEFAULT_LOCAL_PORT"
LOCAL_PORT="$REPLY"

# ── Step 3: SSL Certificate ──

header "Step 3: SSL Certificate"

CERT_FILE=""
KEY_FILE=""

# Check default location
DEFAULT_CERT="${DEFAULT_CERT_DIR}/micstec.cer"
DEFAULT_KEY="${DEFAULT_CERT_DIR}/micstec.pem"

if [ -f "$DEFAULT_CERT" ] && [ -f "$DEFAULT_KEY" ]; then
  check_ok "Found cert: ${DEFAULT_CERT}"
  check_ok "Found key:  ${DEFAULT_KEY}"
  # Verify they match
  CERT_MOD="$(openssl x509 -in "$DEFAULT_CERT" -noout -modulus 2>/dev/null | md5sum | awk '{print $1}')"
  KEY_MOD="$(_priv openssl rsa -in "$DEFAULT_KEY" -noout -modulus 2>/dev/null | md5sum | awk '{print $1}')"
  if [ "$CERT_MOD" = "$KEY_MOD" ]; then
    check_ok "Cert and key match"
    # Show cert details
    CERT_DNS="$(openssl x509 -in "$DEFAULT_CERT" -noout -text 2>/dev/null | grep -oP 'DNS:\K[^,]+' | paste -sd', ')"
    CERT_EXP="$(openssl x509 -in "$DEFAULT_CERT" -noout -enddate 2>/dev/null | cut -d= -f2)"
    dim "  Covers: ${CERT_DNS}"
    dim "  Expires: ${CERT_EXP}"
  else
    check_fail "Cert and key DO NOT match"
  fi
  echo ""
  if confirm "Use these certificates?"; then
    CERT_FILE="$DEFAULT_CERT"
    KEY_FILE="$DEFAULT_KEY"
  fi
fi

if [ -z "$CERT_FILE" ]; then
  echo ""
  say "Choose how to provide SSL certificates:"
  echo ""
  say "  1) Enter file paths manually"
  say "  2) Copy from a remote server via SSH"
  say "  3) Paste certificate and key contents"
  echo ""
  prompt "Choose" "1"
  CERT_CHOICE="$REPLY"

  case "$CERT_CHOICE" in
    1)
      prompt "Path to certificate file (.cer/.crt/.pem)"
      CERT_FILE="$REPLY"
      prompt "Path to private key file (.pem/.key)"
      KEY_FILE="$REPLY"
      if [ ! -f "$CERT_FILE" ]; then
        err "Certificate file not found: $CERT_FILE"
        exit 1
      fi
      if [ ! -f "$KEY_FILE" ]; then
        err "Key file not found: $KEY_FILE"
        exit 1
      fi
      ;;
    2)
      prompt "SSH host (e.g. ssh.micstec.com)" "ssh.micstec.com"
      SSH_HOST="$REPLY"
      prompt "Remote cert path" "/cloudflare/ssl/micstec.cer"
      REMOTE_CERT="$REPLY"
      prompt "Remote key path" "/cloudflare/ssl/micstec.pem"
      REMOTE_KEY="$REPLY"

      _priv mkdir -p "$DEFAULT_CERT_DIR"
      CERT_FILE="${DEFAULT_CERT_DIR}/micstec.cer"
      KEY_FILE="${DEFAULT_CERT_DIR}/micstec.pem"

      info "Copying cert from ${SSH_HOST}..."
      ssh "$SSH_HOST" "sudo cat ${REMOTE_CERT}" | _priv tee "$CERT_FILE" > /dev/null
      check_ok "Certificate saved: ${CERT_FILE}"

      info "Copying key from ${SSH_HOST}..."
      ssh "$SSH_HOST" "sudo cat ${REMOTE_KEY}" | _priv tee "$KEY_FILE" > /dev/null
      _priv chmod 600 "$KEY_FILE"
      check_ok "Private key saved: ${KEY_FILE}"
      ;;
    3)
      _priv mkdir -p "$DEFAULT_CERT_DIR"
      CERT_FILE="${DEFAULT_CERT_DIR}/micstec.cer"
      KEY_FILE="${DEFAULT_CERT_DIR}/micstec.pem"

      echo ""
      say "Paste the certificate (PEM format), then press Enter and Ctrl-D:"
      CERT_CONTENT="$(cat)"
      echo "$CERT_CONTENT" | _priv tee "$CERT_FILE" > /dev/null
      check_ok "Certificate saved: ${CERT_FILE}"

      echo ""
      say "Paste the private key (PEM format), then press Enter and Ctrl-D:"
      KEY_CONTENT="$(cat)"
      echo "$KEY_CONTENT" | _priv tee "$KEY_FILE" > /dev/null
      _priv chmod 600 "$KEY_FILE"
      check_ok "Private key saved: ${KEY_FILE}"
      ;;
    *)
      err "Invalid choice"
      exit 1
      ;;
  esac

  # Verify cert/key match
  CERT_MOD="$(openssl x509 -in "$CERT_FILE" -noout -modulus 2>/dev/null | md5sum | awk '{print $1}')"
  KEY_MOD="$(_priv openssl rsa -in "$KEY_FILE" -noout -modulus 2>/dev/null | md5sum | awk '{print $1}')"
  if [ "$CERT_MOD" != "$KEY_MOD" ]; then
    check_fail "Certificate and key do not match!"
    err "The cert modulus and key modulus differ. Please check your files."
    exit 1
  fi
  check_ok "Certificate and key match"
fi

# ── Step 4: Confirm and install ──

header "Step 4: Confirm"

CONF_NAME="$(echo "$LOCAL_HOSTNAME" | sed 's/\.micstec\.com$//')-local.conf"
# If hostname doesn't end with .micstec.com, use the full hostname
echo "$LOCAL_HOSTNAME" | grep -q '\.micstec\.com$' || CONF_NAME="${LOCAL_HOSTNAME}-local.conf"
# Simplify: use tunnel-local.conf if we have a tunnel name
if [ -n "$TUNNEL_NAME" ]; then
  CONF_NAME="${TUNNEL_NAME}-local.conf"
fi
DEST_CONF="${CONF_DIR}/${CONF_NAME}"

say "Hostname     : ${LOCAL_HOSTNAME}"
say "HTTPS port   : ${LOCAL_PORT}"
say "Certificate  : ${CERT_FILE}"
say "Private key  : ${KEY_FILE}"
say "nginx config : ${DEST_CONF}"
echo ""

if ! confirm "Proceed with installation?"; then
  say "Cancelled."
  exit 0
fi

# ── Build and install nginx config ──

header "Installing"

TMP_CONF="$(mktemp)"
{
  echo "# Local LAN HTTPS access - NOT managed by deploy.sh"
  echo "# Generated by add-local.sh on $(date '+%Y-%m-%d %H:%M:%S')"
  echo "# Hostname: ${LOCAL_HOSTNAME}"
  sed \
    -e "s/listen 7680;/listen ${LOCAL_PORT} ssl;/" \
    -e "s/server_name .*/server_name ${LOCAL_HOSTNAME};/" \
    -e "/absolute_redirect off;/a\\
\\
    ssl_certificate     ${CERT_FILE};\\
    ssl_certificate_key ${KEY_FILE};" \
    "$NGINX_SRC"
} > "$TMP_CONF"

_priv cp "$TMP_CONF" "$DEST_CONF"
rm -f "$TMP_CONF"
check_ok "nginx config written: ${DEST_CONF}"

if [ -n "${ENABLED_DIR:-}" ]; then
  _priv ln -sf "$DEST_CONF" "${ENABLED_DIR}/${CONF_NAME}"
  check_ok "Symlinked to sites-enabled"
fi

_priv chmod 600 "$KEY_FILE"

info "Testing nginx config..."
if ! _priv nginx -t 2>&1; then
  check_fail "nginx config test failed"
  _priv rm -f "$DEST_CONF"
  [ -n "${ENABLED_DIR:-}" ] && _priv rm -f "${ENABLED_DIR}/${CONF_NAME}"
  err "Config removed. Please check your certificates and try again."
  exit 1
fi
check_ok "nginx config OK"

_priv nginx -s reload 2>/dev/null || _priv service nginx reload
check_ok "nginx reloaded"

# ── Verify ──

if curl -sk "https://localhost:${LOCAL_PORT}/login" -o /dev/null -w "%{http_code}" 2>/dev/null | grep -q "200"; then
  check_ok "HTTPS responding on port ${LOCAL_PORT}"
else
  check_warn "Could not verify HTTPS on port ${LOCAL_PORT} (may need auth service running)"
fi

# ── Done ──

header "Done"
success "Local access enabled!"
echo ""
say "URL: https://${LOCAL_HOSTNAME}:${LOCAL_PORT}"
echo ""
say "Next steps:"
if $IS_WSL; then
  say "  1. Forward port ${LOCAL_PORT} from Windows to WSL2:"
  dim "     ~/bin/wsl2-expose-nginx -Ports ${LOCAL_PORT}"
  say "  2. Point ${LOCAL_HOSTNAME} to your Windows LAN IP in DNS or hosts file"
else
  say "  1. Point ${LOCAL_HOSTNAME} to this machine's LAN IP in DNS or hosts file"
fi
echo ""
dim "To remove: $0 --remove"
