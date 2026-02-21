#!/usr/bin/env bash
set -euo pipefail

# cf_tunnel_install.sh
# Standalone installer/configurator for a Cloudflare Tunnel that exposes a local service.
# Supports --web-terminal mode for a full multi-tenant web terminal setup.
# Compatible with macOS + Linux (best-effort). Requires Cloudflare-managed DNS.
#
# NOTE: `cloudflared tunnel login` requires an interactive browser/URL step.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUTH_DIR="${SCRIPT_DIR}"

usage() {
  cat <<'EOF'
Usage:
  cf_tunnel_install.sh [options]

Options:
  --name NAME           Tunnel name (required)
  --hostname HOST       Public hostname to route (e.g. app.example.com) (required)
  --service URL         Local service URL (e.g. http://localhost:3000)
                        (required unless --web-terminal is used)

  --credentials FILE    Path to tunnel credentials JSON (optional; auto-detected)
  --config FILE         Path to cloudflared config.yml (default: ~/.cloudflared/config.yml)

  --replace-config      Replace config.yml with a new file containing ONLY this tunnel
  --no-dns              Skip `cloudflared tunnel route dns ...`
  --run-foreground      After setup, run `cloudflared tunnel run NAME` for testing

  --install-service     Install as a persistent service (tunnel + auth if --web-terminal)
                        - Linux: uses systemd
                        - macOS: uses launchd

  --web-terminal        Set up full web terminal stack:
                        ttyd + nginx auth proxy + Python auth service + sshpass
                        Overrides --service to http://localhost:<nginx-port>
  --nginx-port PORT     Nginx listen port (default: 7680, only with --web-terminal)
  --auth-port PORT      Auth service port (default: 7682, only with --web-terminal)

  --yes                 Non-interactive where possible (won't skip required browser auth)
  -h, --help            Show help

Examples:
  # Basic tunnel
  ./cf_tunnel_install.sh --name myapp --hostname app.example.com --service http://localhost:3000

  # Full web terminal
  ./cf_tunnel_install.sh --name myterminal --hostname term.example.com --web-terminal --install-service

Notes:
  1) You must have your domain managed by Cloudflare.
  2) First-time auth requires: cloudflared tunnel login
  3) This script will create/update ~/.cloudflared/config.yml and add a catch-all 404.
EOF
}

say() { printf '%s\n' "$*"; }
err() { printf 'ERROR: %s\n' "$*" >&2; }

# Ensure Homebrew paths are available (Apple Silicon: /opt/homebrew, Intel: /usr/local)
for _brew_prefix in /opt/homebrew /usr/local; do
  [ -d "$_brew_prefix/bin" ] && case ":$PATH:" in
    *":$_brew_prefix/bin:"*) ;;
    *) export PATH="$_brew_prefix/bin:$PATH" ;;
  esac
done
unset _brew_prefix

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "Missing required command: $1"; return 1; }
}

is_macos() { [ "$(uname -s)" = "Darwin" ]; }

# ─── Cloudflare Tunnel helpers ─────────────────────────────────────────────────

install_cloudflared() {
  if command -v cloudflared >/dev/null 2>&1; then
    return 0
  fi

  say "cloudflared not found. Attempting install..."

  if is_macos; then
    if command -v brew >/dev/null 2>&1; then
      brew install cloudflared
      return 0
    fi
    err "Homebrew not found. Install cloudflared manually: https://github.com/cloudflare/cloudflared/releases"
    return 1
  fi

  # Linux best-effort: try package manager if available, else instruct.
  if command -v apt-get >/dev/null 2>&1; then
    say "Detected apt-get. Installing cloudflared via Cloudflare repo..."
    set +e
    sudo mkdir -p /usr/share/keyrings >/dev/null 2>&1
    curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(. /etc/os-release && echo "$VERSION_CODENAME") main" | sudo tee /etc/apt/sources.list.d/cloudflared.list >/dev/null
    sudo apt-get update && sudo apt-get install -y cloudflared
    rc=$?
    set -e
    if [ $rc -eq 0 ]; then return 0; fi
    err "apt install failed. Install manually: https://github.com/cloudflare/cloudflared/releases"
    return 1
  fi

  if command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
    err "RPM-based install not implemented. Install cloudflared manually: https://github.com/cloudflare/cloudflared/releases"
    return 1
  fi

  err "Unknown Linux environment. Install cloudflared manually: https://github.com/cloudflare/cloudflared/releases"
  return 1
}

ensure_auth() {
  mkdir -p "$HOME/.cloudflared"
  if ls "$HOME/.cloudflared"/*cert.pem >/dev/null 2>&1; then
    say "Cloudflare auth already present (~/.cloudflared/*cert.pem)."
    return 0
  fi

  say "No Cloudflare login cert found. Running: cloudflared tunnel login"
  say "A browser window (or a URL) will appear. Complete authorization, then return here."
  cloudflared tunnel login

  if ! ls "$HOME/.cloudflared"/*cert.pem >/dev/null 2>&1; then
    err "Auth still not detected. Did login complete?"
    return 1
  fi
}

validate_hostname() {
  local h="$1"
  if [[ "$h" == *"_"* ]]; then
    err "Hostname contains underscore (_) which is invalid in DNS: $h"
    return 1
  fi
}

write_or_merge_config() {
  local name="$1" hostname="$2" service="$3" cfg="$4" creds="$5" replace="$6"

  mkdir -p "$(dirname "$cfg")"

  if [ "$replace" = true ] || [ ! -f "$cfg" ]; then
    [ -f "$cfg" ] && cp -a "$cfg" "${cfg}.bak.$(date +%Y%m%d_%H%M%S)"
    cat >"$cfg" <<EOF
tunnel: $name
credentials-file: $creds

ingress:
  - hostname: $hostname
    service: $service
  - service: http_status:404
EOF
    say "Wrote config: $cfg"
    return 0
  fi

  # Merge: insert a new ingress rule before the catch-all rule if present.
  cp -a "$cfg" "${cfg}.bak.$(date +%Y%m%d_%H%M%S)"

  if grep -qE '^\s*-\s*service:\s*http_status:404\s*$' "$cfg"; then
    awk -v h="$hostname" -v s="$service" '
      BEGIN{added=0}
      {line=$0}
      /^\s*-\s*service:\s*http_status:404\s*$/ && added==0 {
        print "  - hostname: " h
        print "    service: " s
        added=1
      }
      {print line}
      END{if(added==0){
        print "  - hostname: " h
        print "    service: " s
      }}
    ' "$cfg" >"${cfg}.tmp" && mv "${cfg}.tmp" "$cfg"
  else
    cat >>"$cfg" <<EOF

ingress:
  - hostname: $hostname
    service: $service
  - service: http_status:404
EOF
  fi

  if ! grep -qE '^tunnel:' "$cfg"; then
    printf 'tunnel: %s\n' "$name" | cat - "$cfg" >"${cfg}.tmp" && mv "${cfg}.tmp" "$cfg"
  fi
  if ! grep -qE '^credentials-file:' "$cfg"; then
    awk -v c="$creds" 'NR==1{print; print "credentials-file: " c; next} {print}' "$cfg" >"${cfg}.tmp" && mv "${cfg}.tmp" "$cfg"
  fi

  say "Updated config (merged): $cfg"
}

# ─── Web Terminal helpers ──────────────────────────────────────────────────────

install_web_terminal_deps() {
  say ""
  say "=== Installing web terminal dependencies ==="

  # --- ttyd ---
  if command -v ttyd >/dev/null 2>&1; then
    say "ttyd already installed: $(command -v ttyd)"
  else
    say "Installing ttyd..."
    if is_macos; then
      brew install ttyd
    else
      # Install native binary directly (works on WSL and headless Linux where snap/apt may lack ttyd)
      say "Downloading ttyd native binary..."
      local arch
      arch="$(uname -m)"
      case "$arch" in
        x86_64)  arch="x86_64" ;;
        aarch64) arch="aarch64" ;;
        armv7l)  arch="armhf" ;;
        *)       err "Unsupported architecture: $arch"; return 1 ;;
      esac
      sudo curl -fSL -o /usr/local/bin/ttyd \
        "https://github.com/tsl0922/ttyd/releases/latest/download/ttyd.${arch}"
      sudo chmod +x /usr/local/bin/ttyd
      say "ttyd installed: $(ttyd --version)"
    fi
  fi

  # --- sshpass ---
  if command -v sshpass >/dev/null 2>&1; then
    say "sshpass already installed: $(command -v sshpass)"
  else
    say "Installing sshpass..."
    if is_macos; then
      brew install sshpass 2>/dev/null || brew install hudochenkov/sshpass/sshpass
    else
      if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get install -y sshpass
      elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y sshpass
      elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y sshpass
      else
        err "Cannot auto-install sshpass. Install manually."
        return 1
      fi
    fi
  fi

  # --- apt-based packages: python3, nginx, tmux, openssh-server, curl, lsof ---
  if ! is_macos; then
    local need_apt=false
    local -A cmd_pkg=(
      [python3]=python3
      [nginx]=nginx
      [tmux]=tmux
      [sshd]=openssh-server
      [curl]=curl
      [lsof]=lsof
    )
    for cmd in "${!cmd_pkg[@]}"; do
      if ! command -v "$cmd" >/dev/null 2>&1; then
        say "${cmd} not found, will install ${cmd_pkg[$cmd]}..."
        need_apt=true
      fi
    done
    if $need_apt && command -v apt-get >/dev/null 2>&1; then
      local pkgs=()
      for cmd in "${!cmd_pkg[@]}"; do
        command -v "$cmd" >/dev/null 2>&1 || pkgs+=("${cmd_pkg[$cmd]}")
      done
      sudo apt-get update -qq
      sudo apt-get install -y "${pkgs[@]}"
    fi
    # Verify critical commands after install attempt
    for cmd in python3 nginx; do
      if ! command -v "$cmd" >/dev/null 2>&1; then
        err "${cmd} is required but could not be installed."
        return 1
      fi
    done
  else
    # macOS: check and suggest brew
    if ! command -v python3 >/dev/null 2>&1; then
      err "python3 is required but not found. Install: brew install python3"
      return 1
    fi
    say "python3 already installed: $(python3 --version 2>&1)"
    if ! command -v nginx >/dev/null 2>&1; then
      err "nginx is required but not found. Install: brew install nginx"
      return 1
    fi
    say "nginx already installed: $(nginx -v 2>&1)"
  fi
}

enable_ssh_server() {
  say ""
  say "=== Enabling SSH server ==="
  if is_macos; then
    # macOS: use systemsetup (idempotent)
    if sudo systemsetup -getremotelogin 2>/dev/null | grep -qi "on"; then
      say "SSH (Remote Login) is already enabled."
    else
      say "Enabling Remote Login (SSH)..."
      sudo systemsetup -setremotelogin on
    fi
  else
    # Install openssh-server if sshd is missing
    if ! command -v sshd >/dev/null 2>&1; then
      say "sshd not found, installing openssh-server..."
      if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -qq
        sudo apt-get install -y openssh-server
      elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y openssh-server
      elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y openssh-server
      else
        err "Cannot auto-install openssh-server. Install manually."
        return 1
      fi
    fi

    # Linux: start sshd via systemd or fallback to service/sshd binary
    local sshd_name="sshd"
    if ! systemctl list-unit-files "${sshd_name}.service" >/dev/null 2>&1; then
      sshd_name="ssh"  # Debian/Ubuntu uses 'ssh' not 'sshd'
    fi

    # Check if systemd is running as PID 1
    if pidof systemd >/dev/null 2>&1; then
      if systemctl is-active --quiet "$sshd_name" 2>/dev/null; then
        say "SSH server ($sshd_name) is already running."
      else
        say "Enabling and starting SSH server ($sshd_name)..."
        sudo systemctl enable --now "$sshd_name" 2>/dev/null \
          || sudo systemctl start "$sshd_name"
      fi
    elif command -v service >/dev/null 2>&1; then
      # WSL2 or non-systemd: use SysVinit service command
      if service ssh status >/dev/null 2>&1; then
        say "SSH server is already running."
      else
        say "Starting SSH server via service command..."
        sudo service ssh start
      fi
    else
      # Last resort: start sshd directly
      if pgrep -x sshd >/dev/null 2>&1; then
        say "SSH server is already running."
      else
        say "Starting sshd directly..."
        sudo /usr/sbin/sshd
      fi
    fi

    # Ensure password auth is allowed on localhost (auth.py needs it)
    # while keeping it disabled for external SSH connections.
    local _pw_off=false
    if grep -rqE '^\s*PasswordAuthentication\s+no' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null; then
      _pw_off=true
    fi
    if $_pw_off; then
      if ! grep -A2 -rE '^\s*Match\s+Address\s+127\.0\.0\.1' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null \
        | grep -qE 'PasswordAuthentication\s+yes'; then
        say "Enabling password auth on localhost only (required for web terminal login)..."
        local _conf="/etc/ssh/sshd_config.d/60-cloudimg-settings.conf"
        [ -f "$_conf" ] || _conf="/etc/ssh/sshd_config.d/99-webterminal.conf"
        sudo tee "$_conf" >/dev/null <<'SSHEOF'
PasswordAuthentication no

Match Address 127.0.0.1,::1
    PasswordAuthentication yes
SSHEOF
        if sudo sshd -t 2>/dev/null; then
          if pidof systemd >/dev/null 2>&1; then
            sudo systemctl restart "$sshd_name" 2>/dev/null || sudo service ssh restart
          elif command -v service >/dev/null 2>&1; then
            sudo service ssh restart
          fi
          say "sshd restarted with localhost password auth."
        else
          err "sshd config test failed after edit. Check /etc/ssh/sshd_config.d/"
        fi
      fi
    fi
  fi
}

get_nginx_conf_dir() {
  if is_macos; then
    local prefix
    prefix="$(brew --prefix 2>/dev/null || echo /usr/local)"
    echo "${prefix}/etc/nginx/servers"
  else
    echo "/etc/nginx/sites-available"
  fi
}

configure_nginx() {
  local hostname="$1" nginx_port="$2" auth_port="$3"

  say ""
  say "=== Configuring nginx ==="

  local conf_dir
  conf_dir="$(get_nginx_conf_dir)"
  local conf_file="${conf_dir}/${hostname}.conf"

  if is_macos; then
    mkdir -p "$conf_dir"
  else
    sudo mkdir -p "$conf_dir"
  fi

  # Write nginx config to a temp file first, then move into place.
  # Avoids $(cat <<HEREDOC) which breaks when heredoc content has parentheses.
  local tmp_conf
  tmp_conf="$(mktemp)"
  cat > "$tmp_conf" <<NGINXEOF
server {
    listen ${nginx_port};
    server_name ${hostname};

    # CRITICAL: use relative redirects so Cloudflare's HTTPS is preserved.
    # Without this, nginx redirects to http://<hostname>:<port>/... which breaks.
    absolute_redirect off;

    # Auth subrequest
    location = /api/auth {
        internal;
        proxy_pass http://127.0.0.1:${auth_port};
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Cookie \$http_cookie;
        # Used by auth.py to authorize /ut/<port>/ access (prevents cross-user port access).
        proxy_set_header X-TTYD-Port \$ttyd_port;
    }

    # Login page and login API (no auth required)
    location /login {
        proxy_pass http://127.0.0.1:${auth_port};
    }
    location /api/login {
        proxy_pass http://127.0.0.1:${auth_port};
    }

    # File browser API (requires auth)
    location /api/files/ {
        auth_request /api/auth;
        error_page 401 = @login_redirect;
        proxy_pass http://127.0.0.1:${auth_port};
        client_max_body_size 10m;
    }

    # Quick commands API (requires auth)
    location /api/quick-commands {
        auth_request /api/auth;
        error_page 401 = @login_redirect;
        proxy_pass http://127.0.0.1:${auth_port};
        client_max_body_size 2m;
    }

    # Wrapper app page (requires auth)
    location = / {
        auth_request /api/auth;
        error_page 401 = @login_redirect;
        proxy_pass http://127.0.0.1:${auth_port}/app;
    }

    # Per-user ttyd instances (dynamic port from URL path)
    location ~ ^/ut/(\d+)/(.*) {
        set \$ttyd_port \$1;
        auth_request /api/auth;
        error_page 401 = @login_redirect;

        proxy_pass http://127.0.0.1:\$1/\$2\$is_args\$args;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        # Allow sub_filter to operate (disable upstream compression).
        proxy_set_header Accept-Encoding "";

        # Inject a small helper into ttyd HTML so the iframe exposes the xterm instance.
        # This enables reliable buffer readback for mobile copy/select.
        sub_filter_once on;
        sub_filter '</body>' '<script>(function(){function L(o){return o&&typeof o.setOption==="function"&&(typeof o.write==="function"||typeof o.paste==="function"||typeof o.open==="function");}function F(w){try{var c=[w.term,w.terminal,w.xterm,w.ttyd&&w.ttyd.term,w.app&&w.app.term,w.app&&w.app.terminal];for(var i=0;i<c.length;i++){if(L(c[i]))return c[i];}var k=Object.getOwnPropertyNames(w);for(var j=0;j<k.length;j++){var n=k[j],v;try{v=w[n];}catch(e){continue;}if(L(v))return v;if(v&&typeof v==="object"){try{if(L(v.term))return v.term;if(L(v.terminal))return v.terminal;}catch(e2){}}}}catch(e3){}return null;}function E(){var t=F(window);if(t){window.term=t;window.terminal=t;window.xterm=t;return true;}return false;}if(!E()){var n=0,iv=setInterval(function(){n++;if(E()||n>50)clearInterval(iv);},200);}})();</script></body>';
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }

    location @login_redirect {
        return 302 /login;
    }
}
NGINXEOF

  if is_macos; then
    mv "$tmp_conf" "$conf_file"
  else
    sudo mv "$tmp_conf" "$conf_file"
    # Linux: symlink sites-available -> sites-enabled
    if [ -d "/etc/nginx/sites-enabled" ]; then
      sudo ln -sf "$conf_file" "/etc/nginx/sites-enabled/${hostname}.conf"
    fi
  fi

  say "Wrote nginx config: $conf_file"

  # Test and reload
  if is_macos; then
    nginx -t && nginx -s reload
  else
    if pidof systemd >/dev/null 2>&1; then
      sudo nginx -t && sudo systemctl reload nginx
    else
      sudo nginx -t && sudo service nginx reload
    fi
  fi
  say "nginx reloaded successfully."
}

deploy_auth_service() {
  local auth_port="$1"

  say ""
  say "=== Deploying auth service ==="

  local auth_dir="$AUTH_DIR"
  mkdir -p "$auth_dir"

  # Resolve ttyd full path at install time
  local ttyd_path
  ttyd_path="$(command -v ttyd 2>/dev/null || true)"
  if [ -z "$ttyd_path" ]; then
    if is_macos; then
      ttyd_path="/usr/local/bin/ttyd"
    else
      ttyd_path="/usr/bin/ttyd"
    fi
    say "Warning: ttyd not in PATH, using fallback: $ttyd_path"
  fi

  cat > "${auth_dir}/auth.py" <<'AUTHEOF'
#!/usr/bin/env python3
"""Tiny auth service for ttyd web terminal."""

import base64
import hashlib
import hmac
import http.server
import json
import mimetypes
import os
import secrets
import shlex
import shutil
import socket
import subprocess
import time
import urllib.parse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def load_dotenv(path):
    """Load KEY=VALUE pairs from .env into os.environ if not already set."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                if not key:
                    continue
                value = value.strip().strip('"').strip("'")
                os.environ.setdefault(key, value)
    except FileNotFoundError:
        pass


def env_bool(name, default=False):
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


load_dotenv(os.path.join(BASE_DIR, ".env"))

# --- Config ---
SECRET_KEY = os.environ.get("TTYD_SECRET", secrets.token_hex(32))
SESSION_MAX_AGE = int(os.environ.get("SESSION_MAX_AGE", "86400"))  # 24h default
PORT = int(os.environ.get("AUTH_PORT", "7682"))
ACCESS_LOG_ENABLED = env_bool("ACCESS_LOG_ENABLED", False)
COOKIE_NAME = os.environ.get("SESSION_COOKIE_NAME", "__Host-ttyd_session")
COOKIE_SECURE = env_bool("COOKIE_SECURE", True)

import platform as _platform
_IS_LINUX = _platform.system() == "Linux"

SSHPASS_BIN = (
    os.environ.get("SSHPASS_BIN")
    or shutil.which("sshpass")
    or ("/usr/bin/sshpass" if _IS_LINUX else "/usr/local/bin/sshpass")
)
SSH_BIN = os.environ.get("SSH_BIN") or shutil.which("ssh") or "/usr/bin/ssh"
TTYD_BIN = (
    os.environ.get("TTYD_BIN")
    or shutil.which("ttyd")
    or ("/usr/bin/ttyd" if _IS_LINUX else "/usr/local/bin/ttyd")
)

def _safe_ascii_filename(name):
    # Header values must be latin-1 encodable. Provide an ASCII fallback for
    # Content-Disposition and add a UTF-8 filename* parameter separately.
    if not isinstance(name, str):
        name = ""
    name = name.replace("\\", "_").replace('"', "_")
    # Strip control chars.
    name = "".join(ch for ch in name if 32 <= ord(ch) < 127)
    name = name.strip() or "download"
    return name


def content_disposition(disp, filename):
    # RFC 6266 + RFC 5987: ASCII filename fallback plus UTF-8 filename*.
    disp = "inline" if str(disp).lower() == "inline" else "attachment"
    fname_ascii = _safe_ascii_filename(filename)
    try:
        fname_utf8 = str(filename)
    except Exception:
        fname_utf8 = fname_ascii
    fname_star = urllib.parse.quote(fname_utf8.encode("utf-8"), safe=b"")
    return f"{disp}; filename=\"{fname_ascii}\"; filename*=UTF-8''{fname_star}"

DEFAULT_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}

# Apply only to HTML responses. Applying CSP/XFO to PDFs/media can break built-in viewers (e.g. PDF in iframe).
HTML_ONLY_SECURITY_HEADERS = {
    "X-Frame-Options": "SAMEORIGIN",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://static.cloudflareinsights.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "media-src 'self' data: blob:; "
        "connect-src 'self'; "
        "frame-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'self'"
    ),
}


def authenticate(username, password):
    """Authenticate a user by attempting SSH to localhost with sshpass."""
    try:
        result = subprocess.run(
            [SSHPASS_BIN, "-p", password, SSH_BIN,
             "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=5",
             "-o", "PreferredAuthentications=password",
             "-o", "PubkeyAuthentication=no",
             "-o", "PasswordAuthentication=yes",
             f"{username}@127.0.0.1", "echo", "ok"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, timeout=10
        )
        return result.returncode == 0 and "ok" in result.stdout
    except Exception as e:
        print(f"authenticate error: {e}", flush=True)
        return False

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Terminal Login</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #1a1a2e;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh;
  }
  .login-box {
    background: #16213e;
    border-radius: 12px;
    padding: 40px;
    width: 360px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
  }
  .login-box h1 {
    color: #e2e2e2;
    font-size: 22px;
    margin-bottom: 8px;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .login-box h1 span { font-size: 24px; }
  .login-box p {
    color: #7a7a9e;
    font-size: 14px;
    margin-bottom: 28px;
  }
  label {
    color: #9a9abf;
    font-size: 13px;
    font-weight: 500;
    display: block;
    margin-bottom: 6px;
  }
  input {
    width: 100%;
    padding: 12px 14px;
    background: #0f3460;
    border: 1px solid #1a4a7a;
    border-radius: 8px;
    color: #e2e2e2;
    font-size: 15px;
    margin-bottom: 18px;
    outline: none;
    transition: border-color 0.2s;
  }
  input:focus { border-color: #e94560; }
  button {
    width: 100%;
    padding: 13px;
    background: #e94560;
    color: #fff;
    border: none;
    border-radius: 8px;
    font-size: 15px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.2s;
  }
  button:hover { background: #c73652; }
  .error {
    background: rgba(233,69,96,0.15);
    color: #e94560;
    padding: 10px 14px;
    border-radius: 8px;
    font-size: 13px;
    margin-bottom: 18px;
    display: none;
  }
  @media (max-width: 400px) {
    .login-box { width: auto; margin: 16px; padding: 24px; }
  }
</style>
</head>
<body>
<div class="login-box">
  <h1><span>&#9611;</span> Terminal</h1>
  <p>Sign in to access the web terminal</p>
  <div class="error" id="error">Invalid username or password</div>
  <form id="form">
    <label for="username">Username</label>
    <input type="text" id="username" name="username" autocomplete="username" autofocus required>
    <label for="password">Password</label>
    <input type="password" id="password" name="password" autocomplete="current-password" required>
    <button type="submit">Sign In</button>
  </form>
</div>
<script>
document.getElementById('form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = document.getElementById('error');
  err.style.display = 'none';
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      username: document.getElementById('username').value,
      password: document.getElementById('password').value
    })
  });
  if (res.ok) {
    window.location.href = '/';
  } else {
    try {
      const data = await res.json();
      if (data && data.error) err.textContent = data.error;
    } catch (e2) {}
    err.style.display = 'block';
  }
});
</script>
</body>
</html>"""

TERM_HOOK_JS = r"""// ttyd term hook (injected by nginx into /ut/... HTML)
(function () {
  function looksLikeTerminal(obj) {
    return !!obj && typeof obj.setOption === 'function' &&
      (typeof obj.write === 'function' || typeof obj.paste === 'function' || typeof obj.open === 'function');
  }

  function findTerminalObject(win) {
    try {
      const direct = [
        win.term, win.terminal, win.xterm,
        win.app && win.app.term,
        win.app && win.app.terminal,
        win.ttyd && win.ttyd.term,
      ];
      for (const c of direct) {
        if (looksLikeTerminal(c)) return c;
      }

      const keys = Object.getOwnPropertyNames(win);
      for (const key of keys) {
        let v;
        try { v = win[key]; } catch (e) { continue; }
        if (looksLikeTerminal(v)) return v;
        if (v && typeof v === 'object') {
          try {
            if (looksLikeTerminal(v.term)) return v.term;
            if (looksLikeTerminal(v.terminal)) return v.terminal;
          } catch (e2) {}
        }
      }
    } catch (e3) {}
    return null;
  }

  function expose() {
    const t = findTerminalObject(window);
    if (!t) return false;
    window.term = t;
    window.terminal = t;
    window.xterm = t;
    return true;
  }

  if (!expose()) {
    let n = 0;
    const iv = setInterval(() => {
      n++;
      if (expose() || n > 60) clearInterval(iv);
    }, 200);
  }

  // Force xterm.js to bypass mouse reporting for click/drag events so that
  // native text selection works, while leaving wheel events untouched so
  // tmux mouse scroll keeps working.  xterm.js skips mouse reporting when
  // it sees shiftKey === true on the event, which is the standard Shift+click
  // bypass behaviour.
  ['mousedown', 'mousemove', 'mouseup', 'click', 'dblclick'].forEach(function (t) {
    document.addEventListener(t, function (e) {
      if (!e.shiftKey) {
        Object.defineProperty(e, 'shiftKey', { get: function () { return true; } });
      }
    }, true);
  });
})();
"""

APP_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Web Terminal</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  html { height: 100%; }
  body {
    background: #1a1a2e;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    position: fixed;
    inset: 0;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }

  /* Navbar */
  .navbar {
    height: 42px;
    flex-shrink: 0;
    background: #16213e;
    border-bottom: 1px solid #0f3460;
    display: flex;
    align-items: center;
    padding: 0 12px;
    gap: 8px;
    position: relative;
    z-index: 100;
  }
  .navbar .title {
    color: #e2e2e2;
    font-size: 14px;
    font-weight: 600;
    margin-right: 8px;
    display: flex;
    align-items: center;
    gap: 6px;
    flex-shrink: 0;
  }
  .navbar .title span { color: #e94560; }
  .nav-sep {
    width: 1px;
    height: 20px;
    background: #1a4a7a;
    margin: 0 4px;
    flex-shrink: 0;
  }
  .nav-btn {
    background: none;
    border: 1px solid transparent;
    color: #9a9abf;
    font-size: 12px;
    padding: 4px 10px;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.15s;
    display: flex;
    align-items: center;
    gap: 5px;
    white-space: nowrap;
    flex-shrink: 0;
  }
  .nav-btn:hover { background: #0f3460; color: #e2e2e2; }
  .quick-font-readout {
    cursor: default;
    min-width: 42px;
    justify-content: center;
    pointer-events: none;
  }
  .nav-btn.active { background: #0f3460; border-color: #1a4a7a; color: #e2e2e2; }
  .nav-right { margin-left: auto; display: flex; align-items: center; gap: 6px; flex-shrink: 0; }

  /* Tab bar */
  .tab-bar {
    height: 32px;
    flex-shrink: 0;
    background: #111a30;
    display: flex;
    align-items: stretch;
    padding: 0 4px;
    gap: 2px;
    overflow-x: auto;
    overflow-y: hidden;
  }
  .tab-bar::-webkit-scrollbar { height: 0; }
  .tab {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 0 12px;
    font-size: 12px;
    color: #7a7a9e;
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    cursor: pointer;
    transition: all 0.15s;
    white-space: nowrap;
    flex-shrink: 0;
  }
  .tab:hover { color: #b0b0d0; background: rgba(255,255,255,0.03); }
  .tab.active {
    color: #e2e2e2;
    border-bottom-color: #e94560;
    background: rgba(233,69,96,0.08);
  }
  .tab .tab-close {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 16px;
    height: 16px;
    border-radius: 3px;
    font-size: 14px;
    line-height: 1;
    color: #555;
    transition: all 0.15s;
  }
  .tab .tab-close:hover { background: rgba(233,69,96,0.3); color: #e94560; }
  .tab-add {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    flex-shrink: 0;
    font-size: 16px;
    color: #555;
    background: none;
    border: none;
    cursor: pointer;
    transition: color 0.15s;
  }
  .tab-add:hover { color: #e94560; }

  /* Settings Panel */
  .settings-panel {
    display: none;
    position: absolute;
    top: 42px;
    left: 0;
    right: 0;
    background: #16213e;
    border-bottom: 1px solid #0f3460;
    padding: 14px 16px;
    z-index: 99;
    box-shadow: 0 8px 24px rgba(0,0,0,0.4);
  }
  .settings-panel.open { display: flex; flex-wrap: wrap; gap: 16px; }
  .setting-group {
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 140px;
  }
  .setting-group label {
    color: #7a7a9e;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .setting-group select,
  .setting-group input[type="number"],
  .setting-group input[type="text"],
  .setting-group input[type="color"] {
    background: #0f3460;
    border: 1px solid #1a4a7a;
    color: #e2e2e2;
    font-size: 13px;
    padding: 5px 8px;
    border-radius: 6px;
    outline: none;
  }
  .setting-group input[type="color"] {
    width: 60px;
    height: 30px;
    padding: 2px;
    cursor: pointer;
  }
  .setting-group select { cursor: pointer; }
  .setting-group select:focus,
  .setting-group input:focus { border-color: #e94560; }
  .setting-row {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .toggle { position: relative; width: 36px; height: 20px; flex-shrink: 0; }
  .toggle input { opacity: 0; width: 0; height: 0; }
  .toggle .slider {
    position: absolute; inset: 0;
    background: #0f3460; border-radius: 10px; cursor: pointer; transition: 0.2s;
  }
  .toggle .slider:before {
    content: ""; position: absolute; height: 14px; width: 14px;
    left: 3px; bottom: 3px; background: #7a7a9e; border-radius: 50%; transition: 0.2s;
  }
  .toggle input:checked + .slider { background: #e94560; }
  .toggle input:checked + .slider:before { transform: translateX(16px); background: #fff; }
  .theme-chips { display: flex; gap: 4px; flex-wrap: wrap; }
  .theme-chip {
    padding: 3px 8px;
    font-size: 11px;
    border-radius: 4px;
    border: 1px solid #1a4a7a;
    background: #0f3460;
    color: #9a9abf;
    cursor: pointer;
    transition: 0.15s;
  }
  .theme-chip:hover, .theme-chip.active { border-color: #e94560; color: #e2e2e2; }
  .apply-btn {
    background: #e94560;
    color: #fff;
    border: none;
    padding: 6px 16px;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    align-self: flex-end;
    margin-left: auto;
  }
  .apply-btn:hover { background: #c73652; }

  /* Hamburger menu (mobile) */
  .hamburger {
    display: none;
    background: none;
    border: none;
    color: #9a9abf;
    font-size: 20px;
    cursor: pointer;
    padding: 4px 8px;
    margin-left: auto;
    line-height: 1;
  }
  .hamburger:hover { color: #e2e2e2; }
  .nav-dropdown {
    display: none;
    position: absolute;
    top: 42px;
    right: 0;
    background: #16213e;
    border: 1px solid #0f3460;
    border-radius: 0 0 8px 8px;
    padding: 8px;
    z-index: 101;
    box-shadow: 0 8px 24px rgba(0,0,0,0.4);
    flex-direction: column;
    gap: 4px;
    min-width: 160px;
  }
  .nav-dropdown.open { display: flex; }
  .nav-dropdown .nav-btn { width: 100%; justify-content: flex-start; padding: 8px 12px; font-size: 13px; }

  /* Special keys toolbar (mobile/touch) */
  .special-keys {
    display: none;
    height: 36px;
    flex-shrink: 0;
    background: #111a30;
    border-bottom: 1px solid #0f3460;
    overflow-x: auto;
    overflow-y: hidden;
    white-space: nowrap;
    padding: 2px 4px;
    gap: 3px;
    align-items: center;
    -webkit-overflow-scrolling: touch;
  }
  .special-keys::-webkit-scrollbar { height: 0; }
  .skey {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 36px;
    height: 28px;
    padding: 0 8px;
    background: #1a2744;
    border: 1px solid #1a4a7a;
    border-radius: 5px;
    color: #9a9abf;
    font-size: 12px;
    font-family: monospace;
    cursor: pointer;
    flex-shrink: 0;
    user-select: none;
    -webkit-user-select: none;
    touch-action: manipulation;
    transition: all 0.1s;
  }
  .skey:active { background: #0f3460; transform: scale(0.95); }
  .skey.active { background: #e94560; color: #fff; border-color: #e94560; }
  .skey-sep { width: 1px; height: 20px; background: #1a4a7a; flex-shrink: 0; }

  /* Main area (flex row: file panel + terminal) */
  .main-area {
    flex: 1;
    display: flex;
    flex-direction: row;
    min-height: 0;
  }

  /* File panel */
  .file-panel {
    display: none;
    width: 300px;
    flex-shrink: 0;
    background: #16213e;
    border-right: 1px solid #0f3460;
    flex-direction: column;
    overflow: hidden;
    z-index: 10;
  }
  .file-panel.open { display: flex; }
  .fp-header {
    display: flex;
    align-items: center;
    padding: 8px 10px;
    gap: 6px;
    border-bottom: 1px solid #0f3460;
    flex-shrink: 0;
  }
  .fp-header .fp-title {
    color: #e2e2e2;
    font-size: 13px;
    font-weight: 600;
    flex: 1;
  }
  .fp-btn {
    background: none;
    border: 1px solid #1a4a7a;
    color: #9a9abf;
    font-size: 12px;
    padding: 3px 8px;
    border-radius: 5px;
    cursor: pointer;
    transition: all 0.15s;
    white-space: nowrap;
  }
  .fp-btn:hover { background: #0f3460; color: #e2e2e2; }
  .fp-breadcrumbs {
    display: flex;
    align-items: center;
    padding: 6px 10px;
    gap: 2px;
    font-size: 12px;
    color: #7a7a9e;
    border-bottom: 1px solid #0f3460;
    flex-shrink: 0;
    overflow-x: auto;
    white-space: nowrap;
  }
  .fp-breadcrumbs::-webkit-scrollbar { height: 0; }
  .fp-crumb {
    color: #9a9abf;
    cursor: pointer;
    padding: 1px 3px;
    border-radius: 3px;
    transition: 0.15s;
    flex-shrink: 0;
  }
  .fp-crumb:hover { color: #e2e2e2; background: #0f3460; }
  .fp-list {
    flex: 1;
    overflow-y: auto;
    overflow-x: hidden;
  }
  .fp-list::-webkit-scrollbar { width: 6px; }
  .fp-list::-webkit-scrollbar-thumb { background: #1a4a7a; border-radius: 3px; }
  .fp-item {
    display: flex;
    align-items: center;
    padding: 5px 10px;
    gap: 8px;
    cursor: pointer;
    transition: background 0.1s;
    position: relative;
    font-size: 13px;
    color: #c0c0e0;
  }
  .fp-item:hover { background: rgba(255,255,255,0.04); }
  .fp-item-icon { flex-shrink: 0; font-size: 15px; width: 20px; text-align: center; }
  .fp-item-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .fp-item-size { color: #5a5a7a; font-size: 11px; flex-shrink: 0; }
  .fp-item-actions {
    display: none;
    gap: 2px;
    flex-shrink: 0;
  }
  .fp-item:hover .fp-item-actions { display: flex; }
  .fp-act {
    background: none;
    border: none;
    color: #7a7a9e;
    font-size: 14px;
    cursor: pointer;
    padding: 2px 4px;
    border-radius: 3px;
    line-height: 1;
    transition: 0.15s;
  }
  .fp-act:hover { color: #e2e2e2; background: #0f3460; }

  /* Sort bar */
  .fp-sort-bar {
    display: flex;
    align-items: center;
    padding: 4px 10px;
    gap: 2px;
    border-bottom: 1px solid #0f3460;
    flex-shrink: 0;
  }
  .fp-sort-btn {
    background: none;
    border: none;
    color: #5a5a7a;
    font-size: 11px;
    padding: 2px 6px;
    border-radius: 3px;
    cursor: pointer;
    transition: 0.15s;
    white-space: nowrap;
  }
  .fp-sort-btn:hover { color: #9a9abf; }
  .fp-sort-btn.active { color: #e2e2e2; background: #0f3460; }
  .fp-item-date { color: #5a5a7a; font-size: 11px; flex-shrink: 0; }

  /* File preview modal */
  .fp-modal-overlay {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.6);
    z-index: 200;
    align-items: center;
    justify-content: center;
  }
  .fp-modal-overlay.open { display: flex; }
  .fp-modal {
    background: #16213e;
    border: 1px solid #0f3460;
    border-radius: 10px;
    width: 90%;
    max-width: 700px;
    max-height: 80vh;
    display: flex;
    flex-direction: column;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
  }
  .fp-modal-header {
    display: flex;
    align-items: center;
    padding: 10px 14px;
    border-bottom: 1px solid #0f3460;
    gap: 8px;
  }
  .fp-modal-header .fp-modal-title {
    flex: 1;
    color: #e2e2e2;
    font-size: 14px;
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .fp-modal-body {
    flex: 1;
    overflow: auto;
    padding: 12px 14px;
  }
  .fp-modal-body pre {
    color: #c0c0e0;
    font-size: 13px;
    font-family: 'Menlo', 'Monaco', 'Consolas', monospace;
    white-space: pre-wrap;
    word-break: break-all;
    margin: 0;
  }
  .fp-modal-body .fp-modal-note {
    color: #9a9abf;
    font-size: 13px;
    margin-bottom: 10px;
    display: none;
  }
  .fp-modal-body textarea {
    display: none;
    width: 100%;
    min-height: 380px;
    background: #0f3460;
    border: 1px solid #1a4a7a;
    border-radius: 8px;
    color: #e2e2e2;
    font-size: 13px;
    font-family: 'Menlo', 'Monaco', 'Consolas', monospace;
    line-height: 1.45;
    padding: 10px 12px;
    outline: none;
    resize: vertical;
  }
  .fp-modal-body textarea:focus { border-color: #e94560; }
  .fp-modal-body .fp-modal-image,
  .fp-modal-body .fp-modal-video,
  .fp-modal-body .fp-modal-audio,
  .fp-modal-body .fp-modal-pdf {
    display: none;
    width: 100%;
    max-height: 60vh;
    border-radius: 8px;
    background: #0f3460;
    border: 1px solid #1a4a7a;
  }
  .fp-modal-body .fp-modal-image {
    object-fit: contain;
  }
  .fp-modal-body .fp-modal-pdf {
    height: 70vh;
  }
  .toast {
    position: fixed;
    left: 50%;
    bottom: calc(70px + env(safe-area-inset-bottom, 0px));
    transform: translateX(-50%) translateY(16px);
    background: rgba(15,52,96,0.96);
    border: 1px solid #1a4a7a;
    color: #e2e2e2;
    font-size: 12px;
    padding: 7px 12px;
    border-radius: 999px;
    opacity: 0;
    pointer-events: none;
    transition: opacity 0.18s ease, transform 0.18s ease;
    z-index: 260;
    max-width: calc(100vw - 24px);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .toast.show {
    opacity: 1;
    transform: translateX(-50%) translateY(0);
  }
  .toast.error {
    background: rgba(128,25,46,0.96);
    border-color: #b53250;
  }

  /* Copy/select modal (mobile-friendly selection) */
  .copy-modal-overlay {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.6);
    z-index: 240;
    align-items: center;
    justify-content: center;
  }
  .copy-modal-overlay.open { display: flex; }
  .copy-modal {
    background: #16213e;
    border: 1px solid #0f3460;
    border-radius: 10px;
    width: 92%;
    max-width: 760px;
    max-height: 90vh;
    display: flex;
    flex-direction: column;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
  }
  .copy-modal-header {
    display: flex;
    align-items: center;
    padding: 10px 14px;
    border-bottom: 1px solid #0f3460;
    gap: 8px;
  }
  .copy-modal-title {
    flex: 1;
    color: #e2e2e2;
    font-size: 14px;
    font-weight: 600;
  }
  .copy-modal-body {
    flex: 1;
    padding: 12px 14px;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .copy-modal-hint {
    color: #9a9abf;
    font-size: 12px;
    line-height: 1.35;
  }
  .copy-modal-body textarea {
    flex: 1;
    width: 100%;
    background: #0f3460;
    border: 1px solid #1a4a7a;
    border-radius: 8px;
    color: #e2e2e2;
    font-size: 12px;
    font-family: 'Menlo', 'Monaco', 'Consolas', monospace;
    line-height: 1.45;
    padding: 10px 12px;
    outline: none;
    resize: none;
    white-space: pre;
    user-select: text;
    -webkit-user-select: text;
  }
  .copy-modal-body textarea:focus { border-color: #e94560; }

  /* Dialog modal (replaces alert/confirm/prompt) */
  .dlg-overlay {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.6);
    z-index: 270;
    align-items: center;
    justify-content: center;
  }
  .dlg-overlay.open { display: flex; }
  .dlg {
    background: #16213e;
    border: 1px solid #0f3460;
    border-radius: 10px;
    width: 92%;
    max-width: 520px;
    max-height: 80vh;
    display: flex;
    flex-direction: column;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
  }
  .dlg-header {
    display: flex;
    align-items: center;
    padding: 10px 14px;
    border-bottom: 1px solid #0f3460;
    gap: 8px;
  }
  .dlg-title {
    flex: 1;
    color: #e2e2e2;
    font-size: 14px;
    font-weight: 700;
  }
  .dlg-body {
    padding: 12px 14px;
    overflow: auto;
    color: #c0c0e0;
    font-size: 13px;
    line-height: 1.35;
    white-space: pre-wrap;
    word-break: break-word;
  }
  .dlg-input {
    margin: 0 14px 12px 14px;
    padding: 10px 12px;
    background: #0f3460;
    border: 1px solid #1a4a7a;
    border-radius: 8px;
    color: #e2e2e2;
    font-size: 13px;
    outline: none;
  }
  .dlg-input:focus { border-color: #e94560; }
  .dlg-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    padding: 10px 14px 14px 14px;
    border-top: 1px solid #0f3460;
  }
  .dlg-btn {
    background: none;
    border: 1px solid #1a4a7a;
    color: #9a9abf;
    font-size: 12px;
    padding: 6px 10px;
    border-radius: 6px;
    cursor: pointer;
    transition: 0.15s;
    white-space: nowrap;
  }
  .dlg-btn:hover { background: #0f3460; color: #e2e2e2; }
  .dlg-btn.primary {
    background: #e94560;
    border-color: #e94560;
    color: #fff;
  }
  .dlg-btn.primary:hover { background: #c73652; border-color: #c73652; }
  .dlg-btn.danger {
    background: rgba(233,69,96,0.15);
    border-color: #e94560;
    color: #e94560;
  }
  .dlg-btn.danger:hover { background: rgba(233,69,96,0.25); }

  /* Drag-and-drop overlay */
  .fp-drop-overlay {
    display: none;
    position: absolute;
    inset: 0;
    background: rgba(233,69,96,0.15);
    border: 2px dashed #e94560;
    border-radius: 8px;
    z-index: 20;
    align-items: center;
    justify-content: center;
    color: #e94560;
    font-size: 16px;
    font-weight: 600;
    pointer-events: none;
  }
  .file-panel.dragover .fp-drop-overlay { display: flex; }

  /* Quick Commands panel */
  .qc-overlay {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.6);
    z-index: 200;
    align-items: center;
    justify-content: center;
  }
  .qc-overlay.open { display: flex; }
  .qc-modal {
    background: #16213e;
    border: 1px solid #0f3460;
    border-radius: 10px;
    width: 92%;
    max-width: 720px;
    max-height: 85vh;
    display: flex;
    flex-direction: column;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
  }
  .qc-header {
    display: flex;
    align-items: center;
    padding: 10px 14px;
    border-bottom: 1px solid #0f3460;
    gap: 8px;
    flex-shrink: 0;
  }
  .qc-header-title {
    color: #e2e2e2;
    font-size: 14px;
    font-weight: 600;
    flex: 1;
  }
  .qc-toolbar {
    display: flex;
    align-items: center;
    padding: 8px 14px;
    gap: 6px;
    border-bottom: 1px solid #0f3460;
    flex-shrink: 0;
    flex-wrap: wrap;
  }
  .qc-search {
    flex: 1;
    min-width: 140px;
    background: #0f3460;
    border: 1px solid #1a4a7a;
    color: #e2e2e2;
    font-size: 13px;
    padding: 6px 10px;
    border-radius: 6px;
    outline: none;
  }
  .qc-search:focus { border-color: #e94560; }
  .qc-search::placeholder { color: #5a5a7a; }
  .qc-tags-bar {
    display: flex;
    align-items: center;
    padding: 4px 14px 6px;
    gap: 4px;
    flex-wrap: wrap;
    border-bottom: 1px solid #0f3460;
    flex-shrink: 0;
  }
  .qc-tags-bar:empty { display: none; padding: 0; border: none; }
  .qc-tag-chip {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    font-size: 11px;
    border-radius: 10px;
    border: 1px solid #1a4a7a;
    background: #0f3460;
    color: #9a9abf;
    cursor: pointer;
    transition: 0.15s;
    white-space: nowrap;
  }
  .qc-tag-chip:hover, .qc-tag-chip.active {
    border-color: #e94560;
    color: #e2e2e2;
    background: rgba(233,69,96,0.15);
  }
  .qc-list {
    flex: 1;
    overflow-y: auto;
    overflow-x: hidden;
    min-height: 0;
  }
  .qc-list::-webkit-scrollbar { width: 6px; }
  .qc-list::-webkit-scrollbar-thumb { background: #1a4a7a; border-radius: 3px; }
  .qc-empty {
    padding: 30px 20px;
    text-align: center;
    color: #5a5a7a;
    font-size: 13px;
  }
  .qc-item {
    display: flex;
    align-items: flex-start;
    padding: 8px 14px;
    gap: 10px;
    cursor: pointer;
    transition: background 0.1s;
    border-bottom: 1px solid rgba(15,52,96,0.5);
  }
  .qc-item:hover { background: rgba(255,255,255,0.04); }
  .qc-item-body { flex: 1; min-width: 0; }
  .qc-item-name {
    color: #e2e2e2;
    font-size: 13px;
    font-weight: 600;
    margin-bottom: 2px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .qc-item-cmd {
    color: #9a9abf;
    font-size: 12px;
    font-family: 'Menlo','Monaco','Consolas',monospace;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .qc-item-tags {
    display: flex;
    gap: 3px;
    margin-top: 3px;
    flex-wrap: wrap;
  }
  .qc-item-tag {
    font-size: 10px;
    padding: 1px 5px;
    border-radius: 8px;
    background: rgba(15,52,96,0.8);
    color: #7a7a9e;
    border: 1px solid #1a4a7a;
  }
  .qc-item-actions {
    display: flex;
    gap: 2px;
    flex-shrink: 0;
    align-items: center;
    padding-top: 2px;
  }
  .qc-item-actions .fp-act { font-size: 13px; }
  .qc-form {
    padding: 12px 14px;
    border-bottom: 1px solid #0f3460;
    flex-shrink: 0;
  }
  .qc-form-row {
    display: flex;
    gap: 8px;
    margin-bottom: 8px;
    align-items: flex-start;
  }
  .qc-form-row:last-child { margin-bottom: 0; }
  .qc-form label {
    color: #7a7a9e;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    min-width: 70px;
    padding-top: 7px;
    flex-shrink: 0;
  }
  .qc-form input[type="text"],
  .qc-form textarea {
    flex: 1;
    background: #0f3460;
    border: 1px solid #1a4a7a;
    color: #e2e2e2;
    font-size: 13px;
    padding: 6px 10px;
    border-radius: 6px;
    outline: none;
  }
  .qc-form textarea {
    font-family: 'Menlo','Monaco','Consolas',monospace;
    resize: vertical;
    min-height: 56px;
    line-height: 1.4;
  }
  .qc-form input:focus,
  .qc-form textarea:focus { border-color: #e94560; }
  .qc-form-actions {
    display: flex;
    gap: 6px;
    justify-content: flex-end;
  }

  /* Terminal container */
  .term-container {
    flex: 1;
    min-height: 0;
    min-width: 0;
    position: relative;
  }
  .term-container iframe {
    position: absolute;
    top: 0; left: 0;
    width: 100%;
    height: 100%;
    border: none;
    display: none;
  }
  .term-container iframe.active { display: block; }

  /* Split pane layout */
  .split-container {
    display: flex;
    width: 100%;
    height: 100%;
    min-height: 0;
    min-width: 0;
  }
  .split-container.split-h { flex-direction: row; }
  .split-container.split-v { flex-direction: column; }
  .split-pane {
    position: relative;
    min-height: 0;
    min-width: 0;
    overflow: hidden;
  }
  .split-pane > iframe {
    position: absolute;
    top: 0; left: 0;
    width: 100%;
    height: 100%;
    border: none;
  }
  .split-pane.split-focused { outline: 2px solid #e94560; outline-offset: -2px; z-index: 1; }
  .split-divider {
    flex-shrink: 0;
    background: #0f3460;
    position: relative;
    z-index: 5;
    transition: background 0.15s;
  }
  .split-divider:hover, .split-divider.dragging { background: #e94560; }
  .split-container.split-h > .split-divider {
    width: 4px;
    cursor: col-resize;
  }
  .split-container.split-v > .split-divider {
    height: 4px;
    cursor: row-resize;
  }
  .split-divider::after {
    content: '';
    position: absolute;
    top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    border-radius: 2px;
    background: #7a7a9e;
  }
  .split-container.split-h > .split-divider::after { width: 2px; height: 32px; }
  .split-container.split-v > .split-divider::after { width: 32px; height: 2px; }
  /* Pane label (top-left, shows tab name) */
  .split-pane-label {
    position: absolute;
    top: 4px; left: 8px;
    font-size: 10px;
    color: #7a7a9e;
    background: rgba(22, 33, 62, 0.8);
    padding: 1px 6px;
    border-radius: 3px;
    z-index: 2;
    pointer-events: none;
    opacity: 0;
    transition: opacity 0.2s;
  }
  .split-pane:hover > .split-pane-label { opacity: 1; }

  /* Mobile responsive */
  @media (max-width: 600px) {
    .hamburger { display: block; }
    .nav-sep, .nav-hide-mobile { display: none !important; }
    .nav-right { display: none !important; }
    .navbar { padding: 0 8px; gap: 4px; }
    .special-keys { display: flex; }
    .file-panel {
      position: fixed;
      inset: 0;
      width: 100% !important;
      z-index: 150;
      border-right: none;
    }
    .fp-item-actions { display: flex; }

    /* Fullscreen copy modal on mobile for easier selection */
    .copy-modal {
      width: 100%;
      height: 100%;
      max-height: none;
      border-radius: 0;
    }
    .copy-modal-body textarea {
      font-size: 13px;
    }
  }
  /* Touch devices (tablets etc) */
  @media (pointer: coarse) {
    .special-keys { display: flex; }
    .fp-item-actions { display: flex; }
  }
</style>
</head>
<body>

<div class="navbar">
  <div class="title"><span>&#9611;</span> __USERNAME__</div>
  <div class="nav-sep"></div>
  <button class="nav-btn" onclick="addTab()">&#43; New Tab</button>
  <button class="nav-btn nav-hide-mobile" id="splitRightBtn" onclick="splitRight()" title="Split Right (Ctrl+Shift+\\)">&#9707; Split Right</button>
  <button class="nav-btn nav-hide-mobile" id="splitDownBtn" onclick="splitDown()" title="Split Down (Ctrl+Shift+-)">&#9707; Split Down</button>
  <button class="nav-btn nav-hide-mobile" id="unsplitBtn" onclick="unsplit()" title="Close Split Pane" style="display:none">&#9746; Unsplit</button>
  <button class="nav-btn" onclick="quickAdjustFontSize(-1)" title="Decrease Font Size">A-</button>
  <span class="nav-btn nav-hide-mobile quick-font-readout" id="quickFontSizeDisplay">15px</span>
  <button class="nav-btn" onclick="quickAdjustFontSize(1)" title="Increase Font Size">A+</button>
  <div class="nav-sep nav-hide-mobile"></div>
  <button class="nav-btn nav-hide-mobile" id="cmdsBtn" onclick="toggleQuickCommands()">&#9889; Commands</button>
  <button class="nav-btn nav-hide-mobile" id="filesBtn" onclick="toggleFilePanel()">&#128193; Files</button>
  <button class="nav-btn nav-hide-mobile" id="settingsBtn" onclick="toggleSettings()">&#9881; Settings</button>
  <button class="nav-btn nav-hide-mobile" id="themeBtn" onclick="toggleThemePanel()">&#9673; Themes</button>
  <button class="nav-btn nav-hide-mobile" onclick="fullscreen()">&#9974; Fullscreen</button>
  <button class="nav-btn nav-hide-mobile" onclick="reconnect()">&#8635; Reconnect</button>
  <button class="hamburger" onclick="toggleHamburger()" aria-label="Menu">&#9776;</button>
  <div class="nav-dropdown" id="navDropdown">
    <button class="nav-btn nav-split-mobile" onclick="splitRight();toggleHamburger()" style="display:none">&#9707; Split Right</button>
    <button class="nav-btn nav-split-mobile" onclick="splitDown();toggleHamburger()" style="display:none">&#9707; Split Down</button>
    <button class="nav-btn nav-unsplit-mobile" onclick="unsplit();toggleHamburger()" style="display:none">&#9746; Unsplit</button>
    <button class="nav-btn" onclick="toggleQuickCommands();toggleHamburger()">&#9889; Commands</button>
    <button class="nav-btn" onclick="toggleFilePanel();toggleHamburger()">&#128193; Files</button>
    <button class="nav-btn" onclick="toggleSettings();toggleHamburger()">&#9881; Settings</button>
    <button class="nav-btn" onclick="toggleThemePanel();toggleHamburger()">&#9673; Themes</button>
    <button class="nav-btn" onclick="fullscreen();toggleHamburger()">&#9974; Fullscreen</button>
    <button class="nav-btn" onclick="reconnect();toggleHamburger()">&#8635; Reconnect</button>
    <button class="nav-btn" onclick="logout()" style="color:#e94560;">&#9211; Logout</button>
  </div>
  <div class="nav-right">
    <button class="nav-btn" onclick="logout()" style="color:#e94560;">&#9211; Logout</button>
  </div>
</div>

<div class="tab-bar" id="tabBar"></div>

<div class="special-keys" id="specialKeys">
  <button class="skey" data-action="copy">&#128203;</button>
  <button class="skey" data-key="Escape">Esc</button>
  <button class="skey" data-key="Tab">Tab</button>
  <div class="skey-sep"></div>
  <button class="skey" data-mod="ctrl" id="modCtrl">Ctrl</button>
  <button class="skey" data-mod="alt" id="modAlt">Alt</button>
  <div class="skey-sep"></div>
  <button class="skey" data-key="ArrowUp">&uarr;</button>
  <button class="skey" data-key="ArrowDown">&darr;</button>
  <button class="skey" data-key="ArrowLeft">&larr;</button>
  <button class="skey" data-key="ArrowRight">&rarr;</button>
  <div class="skey-sep"></div>
  <button class="skey" data-combo="ctrl+c">^C</button>
  <button class="skey" data-combo="ctrl+d">^D</button>
  <button class="skey" data-combo="ctrl+z">^Z</button>
  <button class="skey" data-combo="ctrl+l">^L</button>
  <div class="skey-sep"></div>
  <button class="skey" data-char="|">|</button>
  <button class="skey" data-char="~">~</button>
  <button class="skey" data-char="`">`</button>
  <button class="skey" data-char="-">-</button>
  <button class="skey" data-char="_">_</button>
  <button class="skey" data-char="/">/</button>
  <button class="skey" data-char="&#92;">&#92;</button>
</div>

<div class="settings-panel" id="settingsPanel">
  <div class="setting-group">
    <label>Font Size</label>
    <input type="number" id="fontSize" value="15" min="8" max="36" step="1">
  </div>
  <div class="setting-group">
    <label>Font Family</label>
    <select id="fontFamily">
      <option value="">Default (Courier)</option>
      <option value="Menlo">Menlo</option>
      <option value="Monaco">Monaco</option>
      <option value="Consolas">Consolas</option>
      <option value="Source Code Pro">Source Code Pro</option>
      <option value="Fira Code">Fira Code</option>
      <option value="JetBrains Mono">JetBrains Mono</option>
      <option value="IBM Plex Mono">IBM Plex Mono</option>
    </select>
  </div>
  <div class="setting-group">
    <label>Cursor Style</label>
    <select id="cursorStyle">
      <option value="block">Block</option>
      <option value="underline">Underline</option>
      <option value="bar">Bar</option>
    </select>
  </div>
  <div class="setting-group">
    <label>Cursor Blink</label>
    <div class="setting-row">
      <label class="toggle">
        <input type="checkbox" id="cursorBlink" checked>
        <span class="slider"></span>
      </label>
    </div>
  </div>
  <div class="setting-group">
    <label>Scrollback Lines</label>
    <input type="number" id="scrollback" value="10000" min="100" max="100000" step="1000">
  </div>
  <div class="setting-group">
    <label>Disable Leave Alert</label>
    <div class="setting-row">
      <label class="toggle">
        <input type="checkbox" id="disableLeaveAlert">
        <span class="slider"></span>
      </label>
    </div>
  </div>
  <button class="apply-btn" onclick="applySettings()">Apply to All Tabs</button>
</div>

<div class="settings-panel" id="themePanel">
  <div class="setting-group">
    <label>Preset Themes</label>
    <div class="theme-chips">
      <span class="theme-chip active" onclick="selectTheme('default')">Default Dark</span>
      <span class="theme-chip" onclick="selectTheme('light')">Light</span>
      <span class="theme-chip" onclick="selectTheme('monokai')">Monokai</span>
      <span class="theme-chip" onclick="selectTheme('solarized')">Solarized Dark</span>
      <span class="theme-chip" onclick="selectTheme('dracula')">Dracula</span>
      <span class="theme-chip" onclick="selectTheme('nord')">Nord</span>
      <span class="theme-chip" onclick="selectTheme('gruvbox')">Gruvbox</span>
      <span class="theme-chip" onclick="selectTheme('tokyonight')">Tokyo Night</span>
    </div>
  </div>
  <div class="setting-group">
    <label>Background</label>
    <input type="color" id="colorBg" value="#000000">
  </div>
  <div class="setting-group">
    <label>Foreground</label>
    <input type="color" id="colorFg" value="#ffffff">
  </div>
  <div class="setting-group">
    <label>Cursor</label>
    <input type="color" id="colorCursor" value="#ffffff">
  </div>
  <div class="setting-group">
    <label>Selection</label>
    <input type="color" id="colorSelection" value="#4444aa">
  </div>
  <button class="apply-btn" onclick="applySettings()">Apply to All Tabs</button>
</div>

<div class="main-area">
  <div class="file-panel" id="filePanel">
    <div class="fp-header">
      <span class="fp-title">Files</span>
      <button class="fp-btn" onclick="document.getElementById('fpUploadInput').click()">&#8593; Upload</button>
      <button class="fp-btn" onclick="createFolder()">+ Folder</button>
      <button class="fp-btn" onclick="toggleFilePanel()">&#10005;</button>
    </div>
    <div class="fp-breadcrumbs" id="fpBreadcrumbs"></div>
    <div class="fp-sort-bar" id="fpSortBar"></div>
    <div class="fp-list" id="fpList"></div>
    <input type="file" id="fpUploadInput" multiple style="display:none" onchange="handleUpload(this.files);this.value='';">
    <div class="fp-drop-overlay">Drop files to upload</div>
  </div>
  <div class="term-container" id="termContainer"></div>
</div>

<div class="fp-modal-overlay" id="fpModal">
  <div class="fp-modal">
    <div class="fp-modal-header">
      <span class="fp-modal-title" id="fpModalTitle"></span>
      <button class="fp-btn" id="fpModalEdit" style="display:none">&#9998; Edit</button>
      <button class="fp-btn" id="fpModalSave" style="display:none">&#10003; Save</button>
      <button class="fp-btn" id="fpModalDownload">&#8595; Download</button>
      <button class="fp-btn" onclick="closeFileModal()">&#10005;</button>
    </div>
    <div class="fp-modal-body">
      <div class="fp-modal-note" id="fpModalNote"></div>
      <pre id="fpModalContent"></pre>
      <textarea id="fpModalEditor" spellcheck="false"></textarea>
      <img id="fpModalImage" class="fp-modal-image" alt="Image preview">
      <video id="fpModalVideo" class="fp-modal-video" controls preload="metadata"></video>
      <audio id="fpModalAudio" class="fp-modal-audio" controls preload="metadata"></audio>
      <iframe id="fpModalPdf" class="fp-modal-pdf" title="PDF preview"></iframe>
    </div>
  </div>
</div>
<div class="qc-overlay" id="qcOverlay">
  <div class="qc-modal">
    <div class="qc-header">
      <span class="qc-header-title">&#9889; Quick Commands</span>
      <button class="fp-btn" id="qcAddBtn" onclick="qcShowForm()">+ Add</button>
      <button class="fp-btn" id="qcImportBtn" onclick="document.getElementById('qcImportInput').click()">&#8593; Import</button>
      <button class="fp-btn" id="qcExportBtn" onclick="qcExport()">&#8595; Export</button>
      <button class="fp-btn" onclick="closeQuickCommands()">&#10005;</button>
    </div>
    <div class="qc-form" id="qcForm" style="display:none">
      <div class="qc-form-row">
        <label>Name</label>
        <input type="text" id="qcFormName" placeholder="Command name">
      </div>
      <div class="qc-form-row">
        <label>Command</label>
        <textarea id="qcFormCmd" placeholder="Command string (e.g. ls -la)" rows="2"></textarea>
      </div>
      <div class="qc-form-row">
        <label>Tags</label>
        <input type="text" id="qcFormTags" placeholder="Comma-separated tags (e.g. system,network)">
      </div>
      <div class="qc-form-actions">
        <button class="dlg-btn" onclick="qcHideForm()">Cancel</button>
        <button class="dlg-btn primary" id="qcFormSave" onclick="qcSaveForm()">Save</button>
      </div>
    </div>
    <div class="qc-toolbar">
      <input type="text" class="qc-search" id="qcSearch" placeholder="Search commands by name, command, or tag..." oninput="qcApplyFilter()">
    </div>
    <div class="qc-tags-bar" id="qcTagsBar"></div>
    <div class="qc-list" id="qcList"></div>
  </div>
</div>
<input type="file" id="qcImportInput" accept=".json,application/json" style="display:none" onchange="qcImport(this.files);this.value='';">

<div id="toast" class="toast"></div>

<div class="copy-modal-overlay" id="copyModal">
  <div class="copy-modal">
    <div class="copy-modal-header">
      <span class="copy-modal-title">&#128203; Copy and Select</span>
      <button class="fp-btn" id="copyModalCopy">Copy</button>
      <button class="fp-btn" id="copyModalClose">&#10005;</button>
    </div>
    <div class="copy-modal-body">
      <div class="copy-modal-hint">Long-press to select text on mobile. Tap Copy to copy selection (or all if nothing selected).</div>
      <textarea id="copyModalText" spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off"></textarea>
    </div>
  </div>
</div>

<div class="dlg-overlay" id="dlgOverlay" role="dialog" aria-modal="true">
  <div class="dlg">
    <div class="dlg-header">
      <span class="dlg-title" id="dlgTitle">Dialog</span>
      <button class="fp-btn" id="dlgClose">&#10005;</button>
    </div>
    <div class="dlg-body" id="dlgBody"></div>
    <input class="dlg-input" id="dlgInput" style="display:none" />
    <div class="dlg-actions">
      <button class="dlg-btn" id="dlgCancel">Cancel</button>
      <button class="dlg-btn primary" id="dlgOk">OK</button>
    </div>
  </div>
</div>

<script>
const THEMES = {
  'default':    { bg:'#000000', fg:'#ffffff', cursor:'#ffffff', selection:'#4444aa' },
  'light':      { bg:'#ffffff', fg:'#333333', cursor:'#333333', selection:'#b5d5ff' },
  'monokai':    { bg:'#272822', fg:'#f8f8f2', cursor:'#f8f8f0', selection:'#49483e' },
  'solarized':  { bg:'#002b36', fg:'#839496', cursor:'#93a1a1', selection:'#073642' },
  'dracula':    { bg:'#282a36', fg:'#f8f8f2', cursor:'#f8f8f2', selection:'#44475a' },
  'nord':       { bg:'#2e3440', fg:'#d8dee9', cursor:'#d8dee9', selection:'#434c5e' },
  'gruvbox':    { bg:'#282828', fg:'#ebdbb2', cursor:'#ebdbb2', selection:'#3c3836' },
  'tokyonight': { bg:'#1a1b26', fg:'#c0caf5', cursor:'#c0caf5', selection:'#283457' },
};

let currentTheme = 'default';
let tabs = [];
let activeTabId = null;
let tabCounter = 0;

// --- Split Screen System ---
// splitRoot: null (no split, single pane) or a tree node:
//   { type:'pane', tabId:'tab-1' }
//   { type:'split', direction:'h'|'v', ratio:0.5, children:[node, node] }
let splitRoot = null;
let focusedPaneTabId = null; // which pane has focus in split mode

const SPLIT_MIN_WIDTH = 768;   // tablet+ only
const SPLIT_NEST_MIN = 1024;   // nesting allowed on desktop only

function isSplitActive() { return splitRoot !== null && splitRoot.type === 'split'; }

function canSplit() { return window.innerWidth >= SPLIT_MIN_WIDTH; }
function canNest() { return window.innerWidth >= SPLIT_NEST_MIN; }

function getSplitPaneCount(node) {
  if (!node) return 0;
  if (node.type === 'pane') return 1;
  return getSplitPaneCount(node.children[0]) + getSplitPaneCount(node.children[1]);
}

function findPaneNode(node, tabId) {
  if (!node) return null;
  if (node.type === 'pane') return node.tabId === tabId ? node : null;
  return findPaneNode(node.children[0], tabId) || findPaneNode(node.children[1], tabId);
}

function findParent(node, target, parent) {
  if (!node) return null;
  if (node === target) return parent;
  if (node.type === 'split') {
    return findParent(node.children[0], target, node) || findParent(node.children[1], target, node);
  }
  return null;
}

function splitDirection(dir) {
  if (!canSplit()) return;
  if (!activeTabId || tabs.length < 2) { addTab(); if (tabs.length < 2) return; }

  // If not in split mode, enter split with active tab + next adjacent tab
  if (!isSplitActive()) {
    const activeIdx = tabs.findIndex(t => t.id === activeTabId);
    let secondId = null;
    // Pick next tab, or previous if active is last
    if (activeIdx < tabs.length - 1) secondId = tabs[activeIdx + 1].id;
    else if (activeIdx > 0) secondId = tabs[activeIdx - 1].id;
    if (!secondId) { addTab(); secondId = tabs[tabs.length - 1].id; }
    if (!secondId) return;
    splitRoot = {
      type: 'split', direction: dir, ratio: 0.5,
      children: [
        { type: 'pane', tabId: activeTabId },
        { type: 'pane', tabId: secondId },
      ]
    };
    focusedPaneTabId = activeTabId;
    renderSplitLayout();
    updateSplitButtons();
    saveSplitState();
    return;
  }

  // Already split: split the focused pane further
  const focusId = focusedPaneTabId || activeTabId;
  const paneCount = getSplitPaneCount(splitRoot);
  if (!canNest() && paneCount >= 2) return; // tablet: max 2 panes

  // Need a tab not already in a pane
  const panesInUse = new Set();
  (function collectPanes(n) {
    if (!n) return;
    if (n.type === 'pane') { panesInUse.add(n.tabId); return; }
    collectPanes(n.children[0]); collectPanes(n.children[1]);
  })(splitRoot);
  let freeTab = tabs.find(t => !panesInUse.has(t.id));
  if (!freeTab) { addTab(); freeTab = tabs[tabs.length - 1]; }

  // Find the pane node and replace it with a split
  (function replacePaneWithSplit(node, parent) {
    if (node.type === 'pane' && node.tabId === focusId) {
      const newSplit = {
        type: 'split', direction: dir, ratio: 0.5,
        children: [
          { type: 'pane', tabId: focusId },
          { type: 'pane', tabId: freeTab.id },
        ]
      };
      if (!parent) { splitRoot = newSplit; }
      else {
        const idx = parent.children.indexOf(node);
        parent.children[idx] = newSplit;
      }
      return true;
    }
    if (node.type === 'split') {
      return replacePaneWithSplit(node.children[0], node) || replacePaneWithSplit(node.children[1], node);
    }
    return false;
  })(splitRoot, null);

  focusedPaneTabId = focusId;
  renderSplitLayout();
  updateSplitButtons();
  saveSplitState();
}

function splitRight() { splitDirection('h'); }
function splitDown() { splitDirection('v'); }

function unsplit() {
  if (!isSplitActive()) return;
  // Collapse to single pane mode with focused/active tab
  splitRoot = null;
  focusedPaneTabId = null;
  renderSingleLayout();
  updateSplitButtons();
  saveSplitState();
}

function closeSplitPane(tabId) {
  if (!isSplitActive()) return;
  // Remove the pane with tabId, promote its sibling
  (function removePane(node, parent) {
    if (node.type !== 'split') return false;
    for (let i = 0; i < 2; i++) {
      const child = node.children[i];
      if (child.type === 'pane' && child.tabId === tabId) {
        const sibling = node.children[1 - i];
        if (!parent) { splitRoot = sibling; }
        else {
          const idx = parent.children.indexOf(node);
          parent.children[idx] = sibling;
        }
        return true;
      }
    }
    return removePane(node.children[0], node) || removePane(node.children[1], node);
  })(splitRoot, null);

  // If collapsed to single pane
  if (splitRoot && splitRoot.type === 'pane') {
    focusedPaneTabId = null;
    activeTabId = splitRoot.tabId;
    splitRoot = null;
    renderSingleLayout();
  } else {
    // Focus first available pane
    (function firstPane(n) {
      if (!n) return;
      if (n.type === 'pane') { focusedPaneTabId = n.tabId; activeTabId = n.tabId; return; }
      firstPane(n.children[0]);
    })(splitRoot);
    renderSplitLayout();
  }
  updateSplitButtons();
  saveSplitState();
}

function renderSingleLayout() {
  const container = document.getElementById('termContainer');
  // Remove overlay elements (dividers, labels)
  container.querySelectorAll('.split-divider-overlay, .split-pane-label').forEach(el => el.remove());
  // Clear ALL split-related inline styles and let CSS classes handle visibility
  // CSS: .term-container iframe { display:none } / iframe.active { display:block }
  tabs.forEach(t => {
    let f = document.getElementById('frame-' + t.id);
    if (!f) return;
    f.style.cssText = 'position:absolute;top:0;left:0;width:100%;height:100%;border:none;';
    f.classList.toggle('active', t.id === activeTabId);
  });
}

// Compute pane rectangles from split tree (all values in % of container)
function computeSplitRects(node, rect) {
  if (!node) return { panes: [], dividers: [] };
  if (node.type === 'pane') {
    return { panes: [{ tabId: node.tabId, rect: rect }], dividers: [] };
  }
  const isH = node.direction === 'h';
  const dividerPx = 4; // matches CSS
  // Split into two sub-rects
  const r1 = { ...rect }, r2 = { ...rect };
  if (isH) {
    r1.width = rect.width * node.ratio;
    r2.left = rect.left + r1.width;
    r2.width = rect.width - r1.width;
  } else {
    r1.height = rect.height * node.ratio;
    r2.top = rect.top + r1.height;
    r2.height = rect.height - r1.height;
  }
  const left = computeSplitRects(node.children[0], r1);
  const right = computeSplitRects(node.children[1], r2);
  const divider = {
    rect: isH
      ? { left: r2.left, top: rect.top, width: 0, height: rect.height }
      : { left: rect.left, top: r2.top, width: rect.width, height: 0 },
    direction: node.direction,
    splitNode: node
  };
  return {
    panes: left.panes.concat(right.panes),
    dividers: [divider].concat(left.dividers).concat(right.dividers)
  };
}

function renderSplitLayout() {
  const container = document.getElementById('termContainer');
  // Remove old overlay dividers and labels
  container.querySelectorAll('.split-divider-overlay, .split-pane-label').forEach(el => el.remove());
  // Compute layout as percentages
  const layout = computeSplitRects(splitRoot, { top: 0, left: 0, width: 100, height: 100 });
  const panesInUse = new Set(layout.panes.map(p => p.tabId));
  // Position iframes — never move them in DOM, just set position/size
  tabs.forEach(t => {
    const f = document.getElementById('frame-' + t.id);
    if (!f) return;
    const pane = layout.panes.find(p => p.tabId === t.id);
    if (pane) {
      f.style.position = 'absolute';
      f.style.display = 'block';
      f.style.left = pane.rect.left + '%';
      f.style.top = pane.rect.top + '%';
      f.style.width = pane.rect.width + '%';
      f.style.height = pane.rect.height + '%';
      f.style.outline = t.id === focusedPaneTabId ? '2px solid #e94560' : '1px solid #0f3460';
      f.style.outlineOffset = t.id === focusedPaneTabId ? '-2px' : '-1px';
      f.style.zIndex = t.id === focusedPaneTabId ? '1' : '0';
      f.classList.remove('active');
    } else {
      f.style.display = 'none';
      f.style.outline = '';
    }
  });
  // Create divider overlays (absolute positioned, on top of iframes)
  layout.dividers.forEach(d => {
    const div = document.createElement('div');
    div.className = 'split-divider-overlay';
    const isH = d.direction === 'h';
    div.style.position = 'absolute';
    div.style.zIndex = '5';
    if (isH) {
      div.style.left = 'calc(' + d.rect.left + '% - 2px)';
      div.style.top = d.rect.top + '%';
      div.style.width = '4px';
      div.style.height = d.rect.height + '%';
      div.style.cursor = 'col-resize';
    } else {
      div.style.left = d.rect.left + '%';
      div.style.top = 'calc(' + d.rect.top + '% - 2px)';
      div.style.width = d.rect.width + '%';
      div.style.height = '4px';
      div.style.cursor = 'row-resize';
    }
    div.style.background = '#0f3460';
    div.style.transition = 'background 0.15s';
    div.addEventListener('mouseenter', () => { div.style.background = '#e94560'; });
    div.addEventListener('mouseleave', () => { if (!div._dragging) div.style.background = '#0f3460'; });
    div.addEventListener('mousedown', (e) => startDividerDrag(e, d.splitNode, div, container));
    div.addEventListener('touchstart', (e) => {
      e.preventDefault();
      startDividerDragTouch(e, d.splitNode, div, container);
    }, { passive: false });
    container.appendChild(div);
  });
  // Add pane labels
  layout.panes.forEach(p => {
    const t = tabs.find(t => t.id === p.tabId);
    const label = document.createElement('div');
    label.className = 'split-pane-label';
    label.textContent = t ? t.name : p.tabId;
    label.style.position = 'absolute';
    label.style.left = 'calc(' + p.rect.left + '% + 8px)';
    label.style.top = 'calc(' + p.rect.top + '% + 4px)';
    label.style.zIndex = '3';
    container.appendChild(label);
  });
}

function focusSplitPane(tabId) {
  focusedPaneTabId = tabId;
  activeTabId = tabId;
  // Update iframe outlines
  tabs.forEach(t => {
    const f = document.getElementById('frame-' + t.id);
    if (!f || f.style.display === 'none') return;
    f.style.outline = t.id === tabId ? '2px solid #e94560' : '1px solid #0f3460';
    f.style.outlineOffset = t.id === tabId ? '-2px' : '-1px';
    f.style.zIndex = t.id === tabId ? '1' : '0';
  });
  // Update tab bar highlight
  document.querySelectorAll('#tabBar .tab').forEach(el => {
    el.classList.toggle('active', el.dataset.tabId === tabId);
  });
}

function startDividerDrag(e, splitNode, dividerEl, container) {
  e.preventDefault();
  const isH = splitNode.direction === 'h';
  const startPos = isH ? e.clientX : e.clientY;
  const containerRect = container.getBoundingClientRect();
  const totalSize = isH ? containerRect.width : containerRect.height;
  const startRatio = splitNode.ratio;
  dividerEl._dragging = true;
  dividerEl.style.background = '#e94560';
  // Overlay to capture mouse over iframes
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;cursor:' + (isH ? 'col-resize' : 'row-resize') + ';';
  document.body.appendChild(overlay);
  function onMove(ev) {
    const pos = isH ? ev.clientX : ev.clientY;
    const delta = (pos - startPos) / totalSize;
    splitNode.ratio = Math.max(0.15, Math.min(0.85, startRatio + delta));
    renderSplitLayout();
  }
  function onUp() {
    dividerEl._dragging = false;
    overlay.remove();
    document.removeEventListener('mousemove', onMove);
    document.removeEventListener('mouseup', onUp);
    saveSplitState();
  }
  document.addEventListener('mousemove', onMove);
  document.addEventListener('mouseup', onUp);
}

function startDividerDragTouch(e, splitNode, dividerEl, container) {
  const isH = splitNode.direction === 'h';
  const touch = e.touches[0];
  const startPos = isH ? touch.clientX : touch.clientY;
  const containerRect = container.getBoundingClientRect();
  const totalSize = isH ? containerRect.width : containerRect.height;
  const startRatio = splitNode.ratio;
  dividerEl._dragging = true;
  dividerEl.style.background = '#e94560';
  function onMove(ev) {
    ev.preventDefault();
    const t = ev.touches[0];
    const pos = isH ? t.clientX : t.clientY;
    const delta = (pos - startPos) / totalSize;
    splitNode.ratio = Math.max(0.15, Math.min(0.85, startRatio + delta));
    renderSplitLayout();
  }
  function onEnd() {
    dividerEl._dragging = false;
    document.removeEventListener('touchmove', onMove);
    document.removeEventListener('touchend', onEnd);
    saveSplitState();
  }
  document.addEventListener('touchmove', onMove, { passive: false });
  document.addEventListener('touchend', onEnd);
}

function updateSplitButtons() {
  const active = isSplitActive();
  const btn = document.getElementById('unsplitBtn');
  if (btn) btn.style.display = active ? '' : 'none';
  // Mobile hamburger split items
  document.querySelectorAll('.nav-split-mobile').forEach(el => {
    el.style.display = canSplit() ? '' : 'none';
  });
  document.querySelectorAll('.nav-unsplit-mobile').forEach(el => {
    el.style.display = active ? '' : 'none';
  });
}

function saveSplitState() {
  try {
    if (splitRoot) {
      localStorage.setItem('ttyd_split', JSON.stringify(splitRoot));
    } else {
      localStorage.removeItem('ttyd_split');
    }
  } catch(e) {}
}

function restoreSplitState() {
  try {
    const saved = localStorage.getItem('ttyd_split');
    if (!saved || !canSplit()) return false;
    const tree = JSON.parse(saved);
    // Validate all panes reference existing tabs
    const valid = (function validateTree(n) {
      if (!n) return false;
      if (n.type === 'pane') return tabs.some(t => t.id === n.tabId);
      if (n.type === 'split') return validateTree(n.children[0]) && validateTree(n.children[1]);
      return false;
    })(tree);
    if (!valid) { localStorage.removeItem('ttyd_split'); return false; }
    splitRoot = tree;
    // Set focus to first pane
    (function firstPane(n) {
      if (!n) return;
      if (n.type === 'pane') { focusedPaneTabId = n.tabId; activeTabId = n.tabId; return; }
      firstPane(n.children[0]);
    })(splitRoot);
    return true;
  } catch(e) { return false; }
}

// Collapse splits on window resize below threshold
window.addEventListener('resize', () => {
  if (isSplitActive() && !canSplit()) {
    unsplit();
  }
  updateSplitButtons();
});

// Detect clicks on iframes to focus the correct pane
// When an iframe gets focus, window blur fires; we check which iframe has focus
window.addEventListener('blur', () => {
  if (!isSplitActive()) return;
  setTimeout(() => {
    const active = document.activeElement;
    if (active && active.tagName === 'IFRAME' && active.id.startsWith('frame-')) {
      const tabId = active.id.replace('frame-', '');
      if (tabId !== focusedPaneTabId && findPaneNode(splitRoot, tabId)) {
        focusSplitPane(tabId);
      }
    }
  }, 0);
});

// Helper: get all iframes including those in split panes
function getAllIframes() {
  return document.querySelectorAll('#termContainer iframe');
}

// --- End Split Screen System ---

function buildTermUrl(overrides) {
  const s = getSettings();
  if (overrides && typeof overrides === 'object') {
    Object.assign(s, overrides);
  }
  const params = new URLSearchParams();
  if (s.fontSize && s.fontSize !== '15') params.set('fontSize', s.fontSize);
  if (s.fontFamily) params.set('fontFamily', s.fontFamily);
  if (s.cursorStyle && s.cursorStyle !== 'block') params.set('cursorStyle', s.cursorStyle);
  if (!s.cursorBlink) params.set('cursorBlink', 'false');
  if (s.scrollback && s.scrollback !== '10000') params.set('scrollback', s.scrollback);
  if (s.disableLeaveAlert) params.set('disableLeaveAlert', 'true');
  // Mobile/touch: use DOM renderer so terminal text exists in the DOM (enables selection/copy readback).
  if (isCoarsePointer && isCoarsePointer()) params.set('rendererType', 'dom');
  params.set('theme', JSON.stringify({
    background: s.colorBg,
    foreground: s.colorFg,
    cursor: s.colorCursor,
    selectionBackground: s.colorSelection,
  }));
  const qs = params.toString();
  return '/ut/__TTYD_PORT__/' + (qs ? '?' + qs : '');
}

function saveTabs() {
  try { localStorage.setItem('ttyd_tabs', JSON.stringify(tabs.map(t => ({ name: t.name })))); } catch(e) {}
}

function addTab() {
  tabCounter++;
  const id = 'tab-' + tabCounter;
  const iframe = document.createElement('iframe');
  iframe.id = 'frame-' + id;
  iframe.allow = 'clipboard-read; clipboard-write';
  iframe.src = buildTermUrl();
  document.getElementById('termContainer').appendChild(iframe);
  tabs.push({ id, name: 'Shell ' + tabCounter });
  if (!isSplitActive()) {
    switchTab(id);
  }
  renderTabs();
  saveTabs();
}

function closeTab(id, e) {
  if (e) e.stopPropagation();
  if (tabs.length <= 1) return;
  // If this tab is in a split pane, remove that pane first
  if (isSplitActive() && findPaneNode(splitRoot, id)) {
    closeSplitPane(id);
  }
  const idx = tabs.findIndex(t => t.id === id);
  const iframe = document.getElementById('frame-' + id);
  if (iframe) iframe.remove();
  tabs.splice(idx, 1);
  if (activeTabId === id) {
    const newIdx = Math.min(idx, tabs.length - 1);
    switchTab(tabs[newIdx].id);
  }
  renderTabs();
  saveTabs();
}

function switchTab(id) {
  activeTabId = id;
  if (isSplitActive()) {
    const focusId = focusedPaneTabId;
    const focusedPane = focusId ? findPaneNode(splitRoot, focusId) : null;
    if (focusedPane && focusedPane.tabId === id) {
      // Already showing in focused pane — no-op
    } else {
      const targetPane = findPaneNode(splitRoot, id);
      if (targetPane && focusedPane) {
        // Tab is in another pane — swap the two panes' content
        const oldTabId = focusedPane.tabId;
        focusedPane.tabId = id;
        targetPane.tabId = oldTabId;
        renderSplitLayout();
        focusSplitPane(id);
        saveSplitState();
      } else if (focusedPane) {
        // Tab not in any pane — put it in the focused pane
        focusedPane.tabId = id;
        renderSplitLayout();
        focusSplitPane(id);
        saveSplitState();
      }
    }
    // Update tab bar highlight
    document.querySelectorAll('#tabBar .tab').forEach(el => {
      el.classList.toggle('active', el.dataset.tabId === id);
    });
    return;
  }
  getAllIframes().forEach(f => f.classList.remove('active'));
  const frame = document.getElementById('frame-' + id);
  if (frame) frame.classList.add('active');
  // Update tab classes without rebuilding DOM
  document.querySelectorAll('#tabBar .tab').forEach(el => {
    el.classList.toggle('active', el.dataset.tabId === id);
  });
}

function renderTabs() {
  const bar = document.getElementById('tabBar');
  bar.innerHTML = '';
  tabs.forEach(t => {
    const tab = document.createElement('div');
    tab.className = 'tab' + (t.id === activeTabId ? ' active' : '');
    tab.dataset.tabId = t.id;
    tab.addEventListener('click', () => switchTab(t.id));
    tab.addEventListener('dblclick', (e) => {
      e.preventDefault();
      e.stopPropagation();
      const label = tab.querySelector('.tab-label');
      if (label) startRename(t.id, label);
    });

    const label = document.createElement('span');
    label.className = 'tab-label';
    label.textContent = t.name;
    tab.appendChild(label);

    if (tabs.length > 1) {
      const close = document.createElement('span');
      close.className = 'tab-close';
      close.innerHTML = '&times;';
      close.addEventListener('click', (e) => { e.stopPropagation(); closeTab(t.id); });
      tab.appendChild(close);
    }
    bar.appendChild(tab);
  });
}

function startRename(id, labelEl) {
  const t = tabs.find(t => t.id === id);
  if (!t) return;
  const input = document.createElement('input');
  input.type = 'text';
  input.value = t.name;
  input.style.cssText = 'background:#0f3460;border:1px solid #e94560;color:#e2e2e2;font-size:12px;padding:1px 4px;border-radius:3px;width:80px;outline:none;';
  let done = false;
  const finish = () => {
    if (done) return;
    done = true;
    const val = input.value.trim();
    if (val) t.name = val;
    renderTabs();
    saveTabs();
  };
  input.addEventListener('blur', finish);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); finish(); }
    if (e.key === 'Escape') { done = true; renderTabs(); }
  });
  input.addEventListener('click', (e) => e.stopPropagation());
  input.addEventListener('dblclick', (e) => e.stopPropagation());
  labelEl.replaceWith(input);
  input.focus();
  input.select();
}

function renameTab(id, name) {
  const t = tabs.find(t => t.id === id);
  if (t) { t.name = name; renderTabs(); }
}

function getSettings() {
  return {
    fontSize: document.getElementById('fontSize').value,
    fontFamily: document.getElementById('fontFamily').value,
    cursorStyle: document.getElementById('cursorStyle').value,
    cursorBlink: document.getElementById('cursorBlink').checked,
    scrollback: document.getElementById('scrollback').value,
    disableLeaveAlert: document.getElementById('disableLeaveAlert').checked,
    theme: currentTheme,
    colorBg: document.getElementById('colorBg').value,
    colorFg: document.getElementById('colorFg').value,
    colorCursor: document.getElementById('colorCursor').value,
    colorSelection: document.getElementById('colorSelection').value,
  };
}

function clampFontSize(v) {
  return Math.max(8, Math.min(36, v));
}

function updateQuickFontDisplay(v) {
  const el = document.getElementById('quickFontSizeDisplay');
  if (el) el.textContent = String(v) + 'px';
}

function saveSettingsOnly() {
  localStorage.setItem('ttyd_settings', JSON.stringify(getSettings()));
}

function bindPersist(id, ev, fn) {
  const el = document.getElementById(id);
  if (!el) return;
  el.addEventListener(ev, fn || (() => saveSettingsOnly()));
}

function wireSettingsPersistence() {
  // Persist basic settings as user changes them (no need to click Apply).
  bindPersist('fontFamily', 'change');
  bindPersist('cursorStyle', 'change');
  bindPersist('cursorBlink', 'change');
  bindPersist('scrollback', 'change');
  bindPersist('disableLeaveAlert', 'change');
  bindPersist('colorBg', 'input');
  bindPersist('colorFg', 'input');
  bindPersist('colorCursor', 'input');
  bindPersist('colorSelection', 'input');
}

let toastTimer = null;

function showToast(msg, isError) {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.classList.toggle('error', !!isError);
  t.classList.add('show');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 1400);
}

// --- Dialog modal helpers (replaces alert/confirm/prompt) ---
let dlgResolve = null;
let dlgKind = 'alert'; // alert|confirm|prompt

function dlgSetOpen(open) {
  const overlay = document.getElementById('dlgOverlay');
  if (!overlay) return;
  overlay.classList.toggle('open', !!open);
}

function dlgClose(result) {
  dlgSetOpen(false);
  const r = dlgResolve;
  dlgResolve = null;
  dlgKind = 'alert';
  if (typeof r === 'function') r(result);
}

function dlgOpen(opts) {
  opts = opts || {};
  const titleEl = document.getElementById('dlgTitle');
  const bodyEl = document.getElementById('dlgBody');
  const inputEl = document.getElementById('dlgInput');
  const okEl = document.getElementById('dlgOk');
  const cancelEl = document.getElementById('dlgCancel');
  const closeEl = document.getElementById('dlgClose');
  const overlay = document.getElementById('dlgOverlay');

  if (!titleEl || !bodyEl || !inputEl || !okEl || !cancelEl || !closeEl || !overlay) {
    // Hard fallback if modal isn't present.
    if ((opts.kind || 'alert') === 'confirm') return Promise.resolve(window.confirm(opts.message || ''));
    if ((opts.kind || 'alert') === 'prompt') return Promise.resolve(window.prompt(opts.message || '', opts.defaultValue || ''));
    window.alert(opts.message || '');
    return Promise.resolve(true);
  }

  dlgKind = opts.kind || 'alert';
  titleEl.textContent = opts.title || (dlgKind === 'confirm' ? 'Confirm' : dlgKind === 'prompt' ? 'Input' : 'Notice');
  bodyEl.textContent = opts.message || '';

  const showInput = dlgKind === 'prompt';
  inputEl.style.display = showInput ? 'block' : 'none';
  if (showInput) {
    inputEl.type = (opts.inputType || 'text');
    inputEl.value = (opts.defaultValue !== undefined && opts.defaultValue !== null) ? String(opts.defaultValue) : '';
  } else {
    inputEl.value = '';
  }

  okEl.textContent = opts.okText || (dlgKind === 'confirm' ? 'OK' : 'OK');
  cancelEl.textContent = opts.cancelText || (dlgKind === 'confirm' || dlgKind === 'prompt' ? 'Cancel' : 'Close');
  cancelEl.style.display = (dlgKind === 'confirm' || dlgKind === 'prompt') ? 'inline-flex' : 'none';

  okEl.classList.remove('danger');
  okEl.classList.add('primary');
  if (opts.danger) {
    okEl.classList.remove('primary');
    okEl.classList.add('danger');
  }

  // Remove previous handlers by cloning buttons (cheap and reliable)
  const okNew = okEl.cloneNode(true);
  okEl.parentNode.replaceChild(okNew, okEl);
  const cancelNew = cancelEl.cloneNode(true);
  cancelEl.parentNode.replaceChild(cancelNew, cancelEl);
  const closeNew = closeEl.cloneNode(true);
  closeEl.parentNode.replaceChild(closeNew, closeEl);

  return new Promise((resolve) => {
    dlgResolve = resolve;
    dlgSetOpen(true);

    okNew.addEventListener('click', () => {
      if (dlgKind === 'prompt') dlgClose(inputEl.value);
      else dlgClose(true);
    });
    cancelNew.addEventListener('click', () => {
      if (dlgKind === 'prompt') dlgClose(null);
      else dlgClose(false);
    });
    closeNew.addEventListener('click', () => {
      if (dlgKind === 'prompt') dlgClose(null);
      else dlgClose(false);
    });
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        if (dlgKind === 'prompt') dlgClose(null);
        else dlgClose(false);
      }
    }, { once: true });

    document.addEventListener('keydown', function onKey(e) {
      if (!document.getElementById('dlgOverlay').classList.contains('open')) {
        document.removeEventListener('keydown', onKey);
        return;
      }
      if (e.key === 'Escape') {
        e.preventDefault();
        document.removeEventListener('keydown', onKey);
        if (dlgKind === 'prompt') dlgClose(null);
        else dlgClose(false);
      } else if (e.key === 'Enter') {
        if (dlgKind === 'prompt' && document.activeElement === inputEl) {
          e.preventDefault();
          document.removeEventListener('keydown', onKey);
          dlgClose(inputEl.value);
        }
      }
    });

    setTimeout(() => {
      try {
        if (showInput) inputEl.focus();
        else okNew.focus();
      } catch (e) {}
    }, 0);
  });
}

function modalAlert(message, title) {
  return dlgOpen({ kind: 'alert', title: title || 'Notice', message: message || '' });
}

function modalConfirm(message, title, danger) {
  return dlgOpen({ kind: 'confirm', title: title || 'Confirm', message: message || '', danger: !!danger, okText: 'OK', cancelText: 'Cancel' });
}

function modalPrompt(message, title, defaultValue) {
  return dlgOpen({ kind: 'prompt', title: title || 'Input', message: message || '', defaultValue: defaultValue || '' });
}

function looksLikeTerminal(obj) {
  return !!obj && typeof obj.setOption === 'function' && (
    typeof obj.write === 'function' || typeof obj.paste === 'function'
  );
}

function findTerminalObject(win) {
  try {
    const direct = [
      win.term, win.terminal, win.xterm,
      win.app && win.app.term,
      win.app && win.app.terminal,
      win.ttyd && win.ttyd.term,
    ];
    for (const c of direct) {
      if (looksLikeTerminal(c)) return c;
    }

    // Best-effort scan top-level globals for ttyd's internal terminal object.
    const keys = Object.getOwnPropertyNames(win);
    for (const key of keys) {
      let v;
      try { v = win[key]; } catch (e) { continue; }
      if (looksLikeTerminal(v)) return v;
      if (v && typeof v === 'object') {
        try {
          if (looksLikeTerminal(v.term)) return v.term;
          if (looksLikeTerminal(v.terminal)) return v.terminal;
        } catch (e) {}
      }
    }
  } catch (e) {}
  return null;
}

function applyFontSizeToFrame(frame, size) {
  try {
    const w = frame.contentWindow;
    const term = w ? findTerminalObject(w) : null;
    if (term) {
      term.setOption('fontSize', size);
      if (typeof term.refresh === 'function' && typeof term.rows === 'number') {
        term.refresh(0, Math.max(0, term.rows - 1));
      }
      try { w.dispatchEvent(new Event('resize')); } catch (e) {}
      return true;
    }

    const doc = frame.contentDocument;
    if (!doc) return false;
    const xterm = doc.querySelector('.xterm');
    if (!xterm) return false;
    xterm.style.fontSize = String(size) + 'px';
    return true;
  } catch (e) {
    return false;
  }
}

function applyFontSizeToAllLiveSessions(size) {
  const frames = getAllIframes();
  let applied = 0;
  frames.forEach((f) => {
    if (applyFontSizeToFrame(f, size)) applied++;
  });
  return { applied, total: frames.length };
}

function getActiveTerminal() {
  const frame = document.getElementById('frame-' + activeTabId);
  if (!frame || !frame.contentWindow) return null;
  const term = findTerminalObject(frame.contentWindow);
  return term || null;
}

function getActiveFrame() {
  const frame = document.getElementById('frame-' + activeTabId);
  return frame || null;
}

function collectTerminalBuffer(term, maxLines) {
  try {
    const buf = term && term.buffer && term.buffer.active;
    if (!buf || typeof buf.length !== 'number' || typeof buf.getLine !== 'function') return '';
    const keep = Math.max(1, maxLines || 4000);
    const start = Math.max(0, buf.length - keep);
    const lines = [];
    for (let i = start; i < buf.length; i++) {
      const line = buf.getLine(i);
      lines.push(line && typeof line.translateToString === 'function'
        ? line.translateToString(true)
        : '');
    }
    // NOTE: This script is embedded in a Python string; backslashes are double-escaped.
    return lines.join('\\n').replace(/\\n+$/g, '');
  } catch (e) {
    return '';
  }
}

function collectTerminalTextFromDOM(frame, maxLines) {
  // Fallback when we can't access ttyd's internal terminal object: read rendered rows.
  try {
    if (!frame) return '';
    const doc = frame.contentDocument;
    if (!doc) return '';

    // Prefer container innerText: it preserves line breaks in many browsers.
    const rowsEl = doc.querySelector('.xterm-rows');
    if (rowsEl) {
      const t = (rowsEl.innerText || rowsEl.textContent || '').replace(/\\s+$/g, '');
      if (t) {
        // Keep only last N lines if requested.
        if (maxLines && typeof maxLines === 'number') {
          const parts = t.split('\\n');
          const keep = Math.max(1, maxLines);
          return parts.slice(Math.max(0, parts.length - keep)).join('\\n').replace(/\\n+$/g, '');
        }
        return t;
      }
    }

    let rows = doc.querySelectorAll('.xterm-rows > div');
    if ((!rows || !rows.length) && doc.querySelector('.xterm-rows')) {
      rows = doc.querySelectorAll('.xterm-rows div');
    }
    if (!rows || !rows.length) {
      const xterm = doc.querySelector('.xterm');
      if (xterm) {
        const t = (xterm.innerText || xterm.textContent || '').trim();
        return t ? t : '';
      }
      const bt = (doc.body && (doc.body.innerText || doc.body.textContent) || '').trim();
      return bt ? bt : '';
    }
    const keep = Math.max(1, maxLines || 4000);
    const start = Math.max(0, rows.length - keep);
    const lines = [];
    for (let i = start; i < rows.length; i++) {
      const t = rows[i].textContent || '';
      lines.push(t.replace(/\\s+$/g, ''));
    }
    return lines.join('\\n').replace(/\\n+$/g, '');
  } catch (e) {
    return '';
  }
}

function snapshotTerminalText(mode) {
  const frame = getActiveFrame();
  const term = getActiveTerminal();

  // 1) Selection via terminal API
  if (term) {
    try {
      if (typeof term.getSelection === 'function') {
        const s = term.getSelection() || '';
        if (s) return { text: s, source: 'term.selection' };
      }
    } catch (e) {}
  }

  // 2) Selection inside iframe
  if (frame && frame.contentWindow) {
    try {
      const sel = frame.contentWindow.getSelection && frame.contentWindow.getSelection();
      const s = sel ? String(sel.toString() || '') : '';
      if (s) return { text: s, source: 'iframe.selection' };
    } catch (e) {}
  }

  // 3) Full buffer via terminal API (best)
  if (term) {
    const t = collectTerminalBuffer(term, 4000);
    if (t) return { text: t, source: 'term.buffer' };
  }

  // 4) DOM rows text
  const dom = collectTerminalTextFromDOM(frame, 1200);
  if (dom) return { text: dom, source: 'dom.rows' };

  return { text: '', source: 'none' };
}

async function copyTextToClipboard(text) {
  if (!text) return false;
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (e) {}
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return !!ok;
  } catch (e) {
    return false;
  }
}

function isCoarsePointer() {
  try {
    return !!(window.matchMedia && window.matchMedia('(pointer: coarse)').matches);
  } catch (e) {
    return false;
  }
}

function isIOS() {
  try {
    const ua = navigator.userAgent || '';
    return /iPad|iPhone|iPod/.test(ua) || (ua.includes('Mac') && 'ontouchend' in document);
  } catch (e) {
    return false;
  }
}

function openInNewTab(url) {
  try {
    const a = document.createElement('a');
    a.href = url;
    a.target = '_blank';
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    a.remove();
    return true;
  } catch (e) {
    try { window.open(url, '_blank', 'noopener'); return true; } catch (e2) {}
    return false;
  }
}

function openCopyModal(text) {
  const overlay = document.getElementById('copyModal');
  const ta = document.getElementById('copyModalText');
  if (!overlay || !ta) return;
  ta.value = text || '';
  overlay.classList.add('open');
  setTimeout(() => {
    try { ta.focus(); } catch (e) {}
  }, 0);
}

function closeCopyModal() {
  const overlay = document.getElementById('copyModal');
  if (overlay) overlay.classList.remove('open');
}

async function copyFromActiveTerminal(mode) {
  // On mobile, text selection inside xterm-in-iframe is unreliable. Always open the
  // selectable modal, then populate it (with retries while the iframe is loading).
  if (isCoarsePointer()) {
    openCopyModal('Loading terminal text...');
    let tries = 0;
    const timer = setInterval(() => {
      tries++;
      const snap = snapshotTerminalText(mode);
      if (snap.text) {
        const ta = document.getElementById('copyModalText');
        if (ta) ta.value = snap.text;
        clearInterval(timer);
        return;
      }
      if (tries >= 12) { // ~2.4s
        const ta = document.getElementById('copyModalText');
        if (ta && (ta.value || '').startsWith('Loading')) {
          ta.value = 'Copy unavailable: terminal not ready or not accessible for readback.\\n\\nTip: wait a moment and tap Copy again.';
        }
        clearInterval(timer);
      }
    }, 200);
    return;
  }

  const snap = snapshotTerminalText(mode);
  if (!snap.text) {
    showToast('Copy unavailable (terminal not ready)', true);
    return;
  }

  const ok = await copyTextToClipboard(snap.text);
  if (!ok) openCopyModal(snap.text);
  else showToast('Copied to clipboard', false);
}

function suppressLeaveAlertInFrame(frame) {
  try {
    const w = frame.contentWindow;
    if (!w) return;
    // Clear common handlers first.
    w.onbeforeunload = null;
    if (w.document) w.document.onbeforeunload = null;
    // Capture-phase blocker to prevent existing listeners from firing.
    w.addEventListener('beforeunload', (e) => {
      try {
        e.stopImmediatePropagation();
        e.stopPropagation();
      } catch (err) {}
    }, true);
  } catch (e) {}
}

function reconnectAllTabsNoLeaveAlert() {
  // Fallback path: apply without browser "leave alert".
  const url = buildTermUrl({ disableLeaveAlert: true });
  getAllIframes().forEach((f) => {
    suppressLeaveAlertInFrame(f);
    f.src = url;
  });
}

function quickAdjustFontSize(delta) {
  const input = document.getElementById('fontSize');
  const cur = parseInt(input.value, 10) || 15;
  const next = clampFontSize(cur + delta);
  if (next === cur) return;
  input.value = String(next);
  updateQuickFontDisplay(next);
  saveSettingsOnly();
  reconnectAllTabsNoLeaveAlert();
}

function applySettings(initial) {
  const s = getSettings();
  localStorage.setItem('ttyd_settings', JSON.stringify(s));
  const url = buildTermUrl();
  getAllIframes().forEach(f => { f.src = url; });
  updateQuickFontDisplay(parseInt(s.fontSize, 10) || 15);
  if (!initial) {
    document.getElementById('settingsPanel').classList.remove('open');
    document.getElementById('themePanel').classList.remove('open');
    document.getElementById('settingsBtn').classList.remove('active');
    document.getElementById('themeBtn').classList.remove('active');
  }
}

function selectTheme(name) {
  currentTheme = name;
  const t = THEMES[name];
  document.getElementById('colorBg').value = t.bg;
  document.getElementById('colorFg').value = t.fg;
  document.getElementById('colorCursor').value = t.cursor;
  document.getElementById('colorSelection').value = t.selection;
  applyThemeUI(name);
  saveSettingsOnly();
}

function applyThemeUI(name) {
  document.querySelectorAll('.theme-chip').forEach(c => {
    c.classList.toggle('active', c.textContent.toLowerCase().includes(name) ||
      (name === 'default' && c.textContent === 'Default Dark') ||
      (name === 'tokyonight' && c.textContent === 'Tokyo Night') ||
      (name === 'solarized' && c.textContent === 'Solarized Dark'));
  });
}

function toggleSettings() {
  const p = document.getElementById('settingsPanel');
  const open = p.classList.toggle('open');
  document.getElementById('settingsBtn').classList.toggle('active', open);
  document.getElementById('themePanel').classList.remove('open');
  document.getElementById('themeBtn').classList.remove('active');
  document.getElementById('filePanel').classList.remove('open');
  document.getElementById('filesBtn').classList.remove('active');
}

function toggleThemePanel() {
  const p = document.getElementById('themePanel');
  const open = p.classList.toggle('open');
  document.getElementById('themeBtn').classList.toggle('active', open);
  document.getElementById('settingsPanel').classList.remove('open');
  document.getElementById('settingsBtn').classList.remove('active');
  document.getElementById('filePanel').classList.remove('open');
  document.getElementById('filesBtn').classList.remove('active');
}

function fullscreen() {
  const f = document.getElementById('frame-' + activeTabId);
  if (f) {
    if (f.requestFullscreen) f.requestFullscreen();
    else if (f.webkitRequestFullscreen) f.webkitRequestFullscreen();
  }
}

function reconnect() {
  const f = document.getElementById('frame-' + activeTabId);
  if (f) f.src = buildTermUrl();
}

function logout() {
  document.cookie = '__COOKIE_NAME__=; Path=/; Max-Age=0';
  localStorage.removeItem('ttyd_settings');
  window.location.href = '/login';
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
  // Ctrl+Shift+T = new tab
  if (e.ctrlKey && e.shiftKey && e.key === 'T') { e.preventDefault(); addTab(); }
  // Ctrl+Shift+W = close tab
  if (e.ctrlKey && e.shiftKey && e.key === 'W') { e.preventDefault(); closeTab(activeTabId); }
  // Ctrl+Shift+E = toggle file panel
  if (e.ctrlKey && e.shiftKey && e.key === 'E') { e.preventDefault(); toggleFilePanel(); }
  // Ctrl+Shift+\\ = split right
  if (e.ctrlKey && e.shiftKey && e.code === 'Backslash') { e.preventDefault(); splitRight(); }
  // Ctrl+Shift+- = split down
  if (e.ctrlKey && e.shiftKey && e.code === 'Minus') { e.preventDefault(); splitDown(); }
  // Ctrl+Shift+U = unsplit
  if (e.ctrlKey && e.shiftKey && e.key === 'U') { e.preventDefault(); unsplit(); }
  // Ctrl+Shift+] = next tab
  if (e.ctrlKey && e.shiftKey && e.key === ']') {
    e.preventDefault();
    const idx = tabs.findIndex(t => t.id === activeTabId);
    if (idx < tabs.length - 1) switchTab(tabs[idx + 1].id);
  }
  // Ctrl+Shift+[ = prev tab
  if (e.ctrlKey && e.shiftKey && e.key === '[') {
    e.preventDefault();
    const idx = tabs.findIndex(t => t.id === activeTabId);
    if (idx > 0) switchTab(tabs[idx - 1].id);
  }
  // Escape = close modals
  if (e.key === 'Escape') {
    closeFileModal();
    closeQuickCommands();
  }
});

// Hamburger menu toggle
function toggleHamburger() {
  document.getElementById('navDropdown').classList.toggle('open');
}
// Close hamburger when clicking outside
document.addEventListener('click', (e) => {
  const dd = document.getElementById('navDropdown');
  if (dd.classList.contains('open') && !e.target.closest('.hamburger') && !e.target.closest('.nav-dropdown')) {
    dd.classList.remove('open');
  }
});

// Special keys toolbar
let modCtrl = false, modAlt = false;

function sendKeyToTerminal(key, opts) {
  opts = opts || {};
  const frame = document.getElementById('frame-' + activeTabId);
  if (!frame || !frame.contentWindow) return;
  try {
    const textarea = frame.contentDocument.querySelector('.xterm-helper-textarea');
    if (!textarea) return;
    textarea.focus();
    const ev = new KeyboardEvent('keydown', {
      key: key,
      code: opts.code || '',
      keyCode: opts.keyCode || 0,
      ctrlKey: !!opts.ctrlKey || modCtrl,
      altKey: !!opts.altKey || modAlt,
      shiftKey: !!opts.shiftKey,
      bubbles: true,
      cancelable: true
    });
    textarea.dispatchEvent(ev);
  } catch(e) {}
  // Reset one-shot modifiers
  if (modCtrl) { modCtrl = false; document.getElementById('modCtrl').classList.remove('active'); }
  if (modAlt) { modAlt = false; document.getElementById('modAlt').classList.remove('active'); }
}

function getCharKeyOptions(ch) {
  // Avoid object literal keys with tricky escaping inside this embedded script.
  if (ch === '/') return { code: 'Slash', keyCode: 191 };
  if (ch === '\\\\') return { code: 'Backslash', keyCode: 220 };
  if (ch === '-') return { code: 'Minus', keyCode: 189 };
  if (ch === '_') return { code: 'Minus', keyCode: 189, shiftKey: true };
  if (ch && ch.length === 1 && ch.charCodeAt(0) === 96) return { code: 'Backquote', keyCode: 192 };          // `
  if (ch && ch.length === 1 && ch.charCodeAt(0) === 126) return { code: 'Backquote', keyCode: 192, shiftKey: true }; // ~
  if (ch === '|') return { code: 'Backslash', keyCode: 220, shiftKey: true };
  return { keyCode: (ch && ch.length ? ch.charCodeAt(0) : 0) };
}

document.getElementById('specialKeys').addEventListener('click', function(e) {
  var btn = e.target.closest('.skey');
  if (!btn) return;
  e.preventDefault();

  if (btn.dataset.action === 'copy') {
    copyFromActiveTerminal('smart');
    return;
  }

  // Modifier toggle
  if (btn.dataset.mod === 'ctrl') {
    modCtrl = !modCtrl;
    btn.classList.toggle('active', modCtrl);
    return;
  }
  if (btn.dataset.mod === 'alt') {
    modAlt = !modAlt;
    btn.classList.toggle('active', modAlt);
    return;
  }

  // Combo keys (e.g. ctrl+c)
  if (btn.dataset.combo) {
    var parts = btn.dataset.combo.split('+');
    var mod = parts[0], k = parts[1];
    sendKeyToTerminal(k, { ctrlKey: mod === 'ctrl', altKey: mod === 'alt',
      keyCode: k.charCodeAt(0) - 96 });
    return;
  }

  // Character keys
  if (btn.dataset.char !== undefined) {
    sendKeyToTerminal(btn.dataset.char, getCharKeyOptions(btn.dataset.char));
    return;
  }

  // Named keys
  if (btn.dataset.key) {
    var keyMap = {
      'Escape': 27, 'Tab': 9,
      'ArrowUp': 38, 'ArrowDown': 40, 'ArrowLeft': 37, 'ArrowRight': 39
    };
    sendKeyToTerminal(btn.dataset.key, { keyCode: keyMap[btn.dataset.key] || 0 });
  }
});

// Load settings and create first tab
function init() {
  try {
    const s = JSON.parse(localStorage.getItem('ttyd_settings') || '{}');
    if (s.fontSize) document.getElementById('fontSize').value = s.fontSize;
    if (s.fontFamily) document.getElementById('fontFamily').value = s.fontFamily;
    if (s.cursorStyle) document.getElementById('cursorStyle').value = s.cursorStyle;
    if (s.cursorBlink !== undefined) document.getElementById('cursorBlink').checked = s.cursorBlink;
    if (s.scrollback) document.getElementById('scrollback').value = s.scrollback;
    if (s.disableLeaveAlert) document.getElementById('disableLeaveAlert').checked = s.disableLeaveAlert;
    if (s.theme) { currentTheme = s.theme; applyThemeUI(s.theme); }
    if (s.colorBg) document.getElementById('colorBg').value = s.colorBg;
    if (s.colorFg) document.getElementById('colorFg').value = s.colorFg;
    if (s.colorCursor) document.getElementById('colorCursor').value = s.colorCursor;
    if (s.colorSelection) document.getElementById('colorSelection').value = s.colorSelection;
  } catch(e) {}
  updateQuickFontDisplay(parseInt(document.getElementById('fontSize').value || '15', 10) || 15);

  wireSettingsPersistence();

  document.getElementById('fontSize').addEventListener('input', () => {
    const input = document.getElementById('fontSize');
    const v = clampFontSize(parseInt(input.value, 10) || 15);
    input.value = String(v);
    updateQuickFontDisplay(v);
    saveSettingsOnly();
    const r = applyFontSizeToAllLiveSessions(v);
    if (r.applied < r.total) {
      reconnectAllTabsNoLeaveAlert();
    }
  });

  // Restore tabs from localStorage, or create one new tab
  let saved = [];
  try { saved = JSON.parse(localStorage.getItem('ttyd_tabs') || '[]'); } catch(e) {}
  if (saved.length > 0) {
    saved.forEach(t => {
      tabCounter++;
      tabs.push({ id: 'tab-' + tabCounter, name: t.name || ('Shell ' + tabCounter) });
    });
    renderTabs();
    switchTab(tabs[0].id);
    // Create iframes with staggered delays so each tmux grouped session
    // can register before the next one counts existing sessions
    const hasSplit = restoreSplitState();
    tabs.forEach((t, i) => {
      setTimeout(() => {
        const iframe = document.createElement('iframe');
        iframe.id = 'frame-' + t.id;
        iframe.allow = 'clipboard-read; clipboard-write';
        iframe.src = buildTermUrl();
        document.getElementById('termContainer').appendChild(iframe);
        if (!hasSplit && t.id === activeTabId) iframe.classList.add('active');
        // After all iframes created, render split layout if restored
        if (hasSplit && i === tabs.length - 1) {
          setTimeout(() => { renderSplitLayout(); updateSplitButtons(); }, 100);
        }
      }, i * 300);
    });
    if (!hasSplit) updateSplitButtons();
  } else {
    addTab();
    updateSplitButtons();
  }

  // Copy modal wiring
  const cmClose = document.getElementById('copyModalClose');
  const cmCopy = document.getElementById('copyModalCopy');
  const cmOverlay = document.getElementById('copyModal');
  if (cmClose) cmClose.addEventListener('click', closeCopyModal);
  if (cmOverlay) cmOverlay.addEventListener('click', (e) => {
    if (e.target === cmOverlay) closeCopyModal();
  });
  if (cmCopy) cmCopy.addEventListener('click', async () => {
    const ta = document.getElementById('copyModalText');
    if (!ta) return;
    const s = ta.selectionStart || 0;
    const e = ta.selectionEnd || 0;
    const sel = (e > s) ? ta.value.slice(s, e) : '';
    const payload = sel || ta.value;
    const ok = await copyTextToClipboard(payload);
    showToast(ok ? 'Copied to clipboard' : 'Copy failed', !ok);
  });
}

// --- File Browser ---
let fpCurrentPath = '~';
let fpCurrentPathToken = '';
let fpParentToken = '';
let fpModalPath = '';
let fpModalText = '';
let fpModalIsText = false;
let fpModalEditing = false;
let fpModalKind = 'binary';
let fpSortBy = 'name';
let fpSortAsc = true;
let fpCurrentEntries = [];

function isImageFile(name) {
  return /\\.(png|jpe?g|gif|webp|bmp|svg|ico|avif|heic)$/i.test(name || '');
}

function isVideoFile(name) {
  return /\\.(mp4|webm|ogg|mov|m4v)$/i.test(name || '');
}

function isAudioFile(name) {
  return /\\.(mp3|wav|m4a|aac|flac|ogg|oga|opus)$/i.test(name || '');
}

function isPdfFile(name) {
  return /\\.(pdf)$/i.test(name || '');
}

function getInlinePreviewUrl(pathToken) {
  return '/api/files/download?inline=1&path_token=' + encodeURIComponent(pathToken);
}

function closeFileModal() {
  fpModalPath = '';
  fpModalText = '';
  fpModalIsText = false;
  fpModalEditing = false;
  fpModalKind = 'binary';
  const img = document.getElementById('fpModalImage');
  const vid = document.getElementById('fpModalVideo');
  const aud = document.getElementById('fpModalAudio');
  const pdf = document.getElementById('fpModalPdf');
  img.style.display = 'none';
  img.src = '';
  vid.pause();
  vid.style.display = 'none';
  vid.removeAttribute('src');
  vid.load();
  aud.pause();
  aud.style.display = 'none';
  aud.removeAttribute('src');
  aud.load();
  pdf.style.display = 'none';
  pdf.removeAttribute('src');
  document.getElementById('fpModal').classList.remove('open');
  document.getElementById('fpModalContent').style.display = 'block';
  document.getElementById('fpModalEditor').style.display = 'none';
  document.getElementById('fpModalNote').style.display = 'none';
  document.getElementById('fpModalEdit').style.display = 'none';
  document.getElementById('fpModalSave').style.display = 'none';
}

function setModalEditing(editing) {
  fpModalEditing = !!editing;
  const pre = document.getElementById('fpModalContent');
  const editor = document.getElementById('fpModalEditor');
  const editBtn = document.getElementById('fpModalEdit');
  const saveBtn = document.getElementById('fpModalSave');
  const note = document.getElementById('fpModalNote');
  const img = document.getElementById('fpModalImage');
  const vid = document.getElementById('fpModalVideo');
  const aud = document.getElementById('fpModalAudio');
  const pdf = document.getElementById('fpModalPdf');

  pre.style.display = 'none';
  editor.style.display = 'none';
  img.style.display = 'none';
  vid.style.display = 'none';
  aud.style.display = 'none';
  pdf.style.display = 'none';
  editBtn.style.display = 'none';
  saveBtn.style.display = 'none';
  note.style.display = 'none';

  if (fpModalKind === 'text') {
    editBtn.style.display = 'inline-block';
    editBtn.innerHTML = fpModalEditing ? '&#10005; Cancel' : '&#9998; Edit';
    saveBtn.style.display = fpModalEditing ? 'inline-block' : 'none';
    pre.style.display = fpModalEditing ? 'none' : 'block';
    editor.style.display = fpModalEditing ? 'block' : 'none';
    return;
  }

  if (fpModalKind === 'image') {
    img.style.display = 'block';
    return;
  }

  if (fpModalKind === 'video') {
    vid.style.display = 'block';
    return;
  }

  if (fpModalKind === 'audio') {
    aud.style.display = 'block';
    return;
  }

  if (fpModalKind === 'pdf') {
    pdf.style.display = 'block';
    return;
  }

  note.style.display = 'block';
}

function startEditFile() {
  if (!fpModalIsText) return;
  document.getElementById('fpModalEditor').value = fpModalText;
  setModalEditing(true);
}

async function saveEditedFile() {
  if (!fpModalIsText || !fpModalPath) return;
  const editor = document.getElementById('fpModalEditor');
  const newContent = editor.value;
  try {
    const res = await fetch('/api/files/write', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ path_token: fpModalPath, content: newContent }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.error) throw new Error(data.error || ('HTTP ' + res.status));
    fpModalText = newContent;
    document.getElementById('fpModalContent').textContent = fpModalText;
    setModalEditing(false);
    fetchFiles(fpCurrentPathToken);
  } catch (e) {
    await modalAlert('Save failed: ' + e.message, 'Save Failed');
  }
}

function toggleFilePanel() {
  const panel = document.getElementById('filePanel');
  const open = panel.classList.toggle('open');
  document.getElementById('filesBtn').classList.toggle('active', open);
  document.getElementById('settingsPanel').classList.remove('open');
  document.getElementById('settingsBtn').classList.remove('active');
  document.getElementById('themePanel').classList.remove('open');
  document.getElementById('themeBtn').classList.remove('active');
  if (open) fetchFiles(fpCurrentPathToken);
}

async function fetchFiles(pathToken) {
  const list = document.getElementById('fpList');
  list.innerHTML = '<div style="padding:20px;color:#7a7a9e;text-align:center;">Loading...</div>';
  try {
    let url = '/api/files/list';
    if (pathToken) {
      url += '?path_token=' + encodeURIComponent(pathToken);
    }
    const res = await fetch(url);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    if (data.error) { list.innerHTML = '<div style="padding:12px;color:#e94560;">' + escHtml(data.error) + '</div>'; return; }
    fpCurrentPath = data.path;
    fpCurrentPathToken = data.path_token || '';
    fpParentToken = data.parent_token || '';
    renderBreadcrumbs(data.breadcrumbs || []);
    fpCurrentEntries = data.entries || [];
    renderSortBar();
    renderFileList(fpCurrentEntries);
  } catch (e) {
    list.innerHTML = '<div style="padding:12px;color:#e94560;">Error: ' + escHtml(e.message) + '</div>';
  }
}

function escHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function renderBreadcrumbs(breadcrumbs) {
  const bc = document.getElementById('fpBreadcrumbs');
  bc.innerHTML = '';
  (breadcrumbs || []).forEach((c, i) => {
    if (i > 0) {
      const sep = document.createElement('span');
      sep.textContent = ' / ';
      sep.style.color = '#3a3a5a';
      bc.appendChild(sep);
    }
    const crumb = document.createElement('span');
    crumb.className = 'fp-crumb';
    crumb.textContent = c.name || '/';
    crumb.onclick = () => fetchFiles(c.token || '');
    bc.appendChild(crumb);
  });
  // Scroll to end
  bc.scrollLeft = bc.scrollWidth;
}

function renderFileList(entries) {
  const list = document.getElementById('fpList');
  list.innerHTML = '';
  const sorted = sortEntries(entries);
  // Parent directory link
  if (fpParentToken) {
    const parent = document.createElement('div');
    parent.className = 'fp-item';
    parent.innerHTML = '<span class="fp-item-icon">&#128193;</span><span class="fp-item-name">..</span>';
    parent.onclick = () => fetchFiles(fpParentToken);
    list.appendChild(parent);
  }
  sorted.forEach(e => {
    const item = document.createElement('div');
    item.className = 'fp-item';
    const icon = document.createElement('span');
    icon.className = 'fp-item-icon';
    icon.innerHTML = e.type === 'dir' ? '&#128193;' : fileIcon(e.name);
    item.appendChild(icon);
    const name = document.createElement('span');
    name.className = 'fp-item-name';
    name.textContent = e.name;
    if (e.link) name.style.fontStyle = 'italic';
    item.appendChild(name);
    if (e.mtime) {
      const dt = document.createElement('span');
      dt.className = 'fp-item-date';
      dt.textContent = formatDate(e.mtime);
      item.appendChild(dt);
    }
    if (e.type !== 'dir') {
      const sz = document.createElement('span');
      sz.className = 'fp-item-size';
      sz.textContent = formatSize(e.size);
      item.appendChild(sz);
    }
    // Action buttons
    const actions = document.createElement('span');
    actions.className = 'fp-item-actions';
    if (e.type !== 'dir') {
      const dl = document.createElement('button');
      dl.className = 'fp-act';
      dl.innerHTML = '&#8595;';
      dl.title = 'Download';
      dl.onclick = (ev) => { ev.stopPropagation(); downloadFile(e.token, e.name); };
      actions.appendChild(dl);
    }
    const ren = document.createElement('button');
    ren.className = 'fp-act';
    ren.innerHTML = '&#9998;';
    ren.title = 'Rename';
    ren.onclick = (ev) => { ev.stopPropagation(); renameFile(e.token, e.name); };
    actions.appendChild(ren);
    const del = document.createElement('button');
    del.className = 'fp-act';
    del.innerHTML = '&#128465;';
    del.title = 'Delete';
    del.style.color = '#e94560';
    del.onclick = (ev) => { ev.stopPropagation(); deleteFile(e.token, e.name, e.type); };
    actions.appendChild(del);
    item.appendChild(actions);
    // Click handler
    item.onclick = () => {
      if (e.type === 'dir') fetchFiles(e.token);
      else previewFile(e.token, e.name);
    };
    list.appendChild(item);
  });
}

async function previewFile(pathToken, name) {
  const lowerName = (name || '').toLowerCase();
  fpModalPath = pathToken;
  document.getElementById('fpModalTitle').textContent = name;
  document.getElementById('fpModalDownload').onclick = () => downloadFile(pathToken, name);
  document.getElementById('fpModalSave').onclick = saveEditedFile;
  document.getElementById('fpModalEdit').onclick = () => {
    if (fpModalEditing) {
      document.getElementById('fpModalEditor').value = fpModalText;
      setModalEditing(false);
    } else {
      startEditFile();
    }
  };

  if (isImageFile(lowerName)) {
    fpModalKind = 'image';
    fpModalIsText = false;
    document.getElementById('fpModalNote').textContent = '';
    document.getElementById('fpModalImage').src = getInlinePreviewUrl(pathToken);
    setModalEditing(false);
    document.getElementById('fpModal').classList.add('open');
    return;
  }

  if (isVideoFile(lowerName)) {
    fpModalKind = 'video';
    fpModalIsText = false;
    document.getElementById('fpModalNote').textContent = '';
    const vid = document.getElementById('fpModalVideo');
    vid.src = getInlinePreviewUrl(pathToken);
    setModalEditing(false);
    document.getElementById('fpModal').classList.add('open');
    return;
  }

  if (isAudioFile(lowerName)) {
    fpModalKind = 'audio';
    fpModalIsText = false;
    document.getElementById('fpModalNote').textContent = '';
    const aud = document.getElementById('fpModalAudio');
    aud.src = getInlinePreviewUrl(pathToken);
    setModalEditing(false);
    document.getElementById('fpModal').classList.add('open');
    return;
  }

  if (isPdfFile(lowerName)) {
    const url = getInlinePreviewUrl(pathToken);
    // Mobile: don't embed PDFs (commonly blocked/blank). Open directly in a new tab.
    if (isCoarsePointer && isCoarsePointer()) {
      openInNewTab(url);
      showToast('Opened PDF in a new tab', false);
      return;
    }
    fpModalKind = 'pdf';
    fpModalIsText = false;
    const note = document.getElementById('fpModalNote');
    note.textContent = '';
    note.innerHTML = '';
    const pdf = document.getElementById('fpModalPdf');

    // iOS Safari often cannot display PDFs inside iframes and shows "content is blocked".
    // Keep the user in the modal and provide explicit open actions instead.
    if (isIOS()) {
      const msg = document.createElement('div');
      msg.textContent = 'PDF preview is blocked by iOS Safari when embedded. Open it instead:';
      msg.style.marginBottom = '8px';

      const row = document.createElement('div');
      row.style.display = 'flex';
      row.style.gap = '8px';
      row.style.flexWrap = 'wrap';

      const aNew = document.createElement('a');
      aNew.className = 'fp-btn';
      aNew.href = url;
      aNew.target = '_blank';
      aNew.rel = 'noopener';
      aNew.textContent = 'Open in new tab';

      const aHere = document.createElement('a');
      aHere.className = 'fp-btn';
      aHere.href = url;
      aHere.textContent = 'Open here';

      row.appendChild(aNew);
      row.appendChild(aHere);
      note.appendChild(msg);
      note.appendChild(row);

      // Don't try to set iframe src on iOS.
      pdf.removeAttribute('src');
      setModalEditing(false);
      document.getElementById('fpModal').classList.add('open');
      return;
    }

    // Non-iOS: render inline in modal.
    pdf.src = url;
    setModalEditing(false);
    document.getElementById('fpModal').classList.add('open');
    return;
  }

  try {
    const res = await fetch('/api/files/read?path_token=' + encodeURIComponent(pathToken));
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    if (data.error) { await modalAlert(data.error, 'Preview'); return; }
    fpModalIsText = !!data.is_text;
    fpModalKind = fpModalIsText ? 'text' : 'binary';
    fpModalText = data.content || '';
    document.getElementById('fpModalContent').textContent = fpModalText;
    document.getElementById('fpModalEditor').value = fpModalText;
    document.getElementById('fpModalNote').textContent = fpModalIsText
      ? ''
      : 'Binary file preview is disabled. Use Download.';
    setModalEditing(false);
    document.getElementById('fpModal').classList.add('open');
  } catch (e) {
    await modalAlert('Cannot preview: ' + e.message, 'Preview Failed');
  }
}

function downloadFile(pathToken, name) {
  const a = document.createElement('a');
  a.href = '/api/files/download?path_token=' + encodeURIComponent(pathToken);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

async function handleUpload(files) {
  if (!files || !files.length) return;
  for (const file of files) {
    try {
      const body = await file.arrayBuffer();
      const nameB64 = btoa(unescape(encodeURIComponent(file.name))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
      const res = await fetch('/api/files/upload?path_token=' + encodeURIComponent(fpCurrentPathToken), {
        method: 'POST',
        headers: {
          'X-Path-Token': fpCurrentPathToken,
          'X-File-Name-B64': nameB64,
        },
        body: body,
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        await modalAlert('Upload failed: ' + (d.error || res.status), 'Upload Failed');
      }
    } catch (e) {
      await modalAlert('Upload error: ' + e.message, 'Upload Failed');
    }
  }
  fetchFiles(fpCurrentPathToken);
}

async function createFolder() {
  const name = await modalPrompt('New folder name:', 'Create Folder', '');
  if (!name) return;
  try {
    const res = await fetch('/api/files/mkdir', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({path_token: fpCurrentPathToken, name: name}),
    });
    const data = await res.json();
    if (data.error) await modalAlert(data.error, 'Create Folder');
    else fetchFiles(fpCurrentPathToken);
  } catch (e) { await modalAlert('Error: ' + e.message, 'Create Folder'); }
}

async function deleteFile(pathToken, name, type) {
  const ok = await modalConfirm('Delete ' + (type === 'dir' ? 'folder' : 'file') + ' \"' + name + '\"?', 'Delete', true);
  if (!ok) return;
  try {
    const res = await fetch('/api/files/delete', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({path_token: pathToken}),
    });
    const data = await res.json();
    if (data.error) await modalAlert(data.error, 'Delete');
    else fetchFiles(fpCurrentPathToken);
  } catch (e) { await modalAlert('Error: ' + e.message, 'Delete'); }
}

async function renameFile(pathToken, name) {
  const newName = await modalPrompt('Rename \"' + name + '\" to:', 'Rename', name);
  if (!newName || newName === name) return;
  try {
    const res = await fetch('/api/files/rename', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({path_token: pathToken, new_name: newName}),
    });
    const data = await res.json();
    if (data.error) await modalAlert(data.error, 'Rename');
    else fetchFiles(fpCurrentPathToken);
  } catch (e) { await modalAlert('Error: ' + e.message, 'Rename'); }
}

function fileIcon(name) {
  const ext = name.split('.').pop().toLowerCase();
  const map = {
    js:'&#128220;', ts:'&#128220;', py:'&#128013;', rb:'&#128142;', go:'&#128220;',
    rs:'&#128220;', java:'&#128220;', c:'&#128220;', cpp:'&#128220;', h:'&#128220;',
    html:'&#127760;', css:'&#127912;', json:'&#128196;', xml:'&#128196;', yaml:'&#128196;', yml:'&#128196;',
    md:'&#128196;', txt:'&#128196;', log:'&#128196;', csv:'&#128196;',
    png:'&#127912;', jpg:'&#127912;', jpeg:'&#127912;', gif:'&#127912;', svg:'&#127912;', webp:'&#127912;',
    mp3:'&#127925;', wav:'&#127925;', mp4:'&#127910;', avi:'&#127910;', mkv:'&#127910;',
    zip:'&#128230;', tar:'&#128230;', gz:'&#128230;', bz2:'&#128230;', xz:'&#128230;', '7z':'&#128230;',
    pdf:'&#128213;', doc:'&#128213;', docx:'&#128213;', xls:'&#128213;', xlsx:'&#128213;',
    sh:'&#128187;', bash:'&#128187;', zsh:'&#128187;',
  };
  return map[ext] || '&#128196;';
}

function formatDate(ts) {
  if (!ts) return '';
  const d = new Date(ts * 1000);
  const now = new Date();
  const pad = n => String(n).padStart(2, '0');
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const today = now.toDateString() === d.toDateString();
  if (today) return pad(d.getHours()) + ':' + pad(d.getMinutes());
  if (d.getFullYear() === now.getFullYear()) return months[d.getMonth()] + ' ' + d.getDate();
  return months[d.getMonth()] + ' \\'' + String(d.getFullYear()).slice(2);
}

function sortEntries(entries) {
  const sorted = entries.slice();
  sorted.sort((a, b) => {
    if (a.type === 'dir' && b.type !== 'dir') return -1;
    if (a.type !== 'dir' && b.type === 'dir') return 1;
    let cmp = 0;
    if (fpSortBy === 'name') {
      cmp = a.name.toLowerCase().localeCompare(b.name.toLowerCase());
    } else if (fpSortBy === 'date') {
      cmp = (a.mtime || 0) - (b.mtime || 0);
    } else if (fpSortBy === 'size') {
      cmp = (a.size || 0) - (b.size || 0);
    }
    return fpSortAsc ? cmp : -cmp;
  });
  return sorted;
}

function setSortBy(field) {
  if (fpSortBy === field) {
    fpSortAsc = !fpSortAsc;
  } else {
    fpSortBy = field;
    fpSortAsc = field === 'name';
  }
  renderSortBar();
  renderFileList(fpCurrentEntries);
}

function renderSortBar() {
  const bar = document.getElementById('fpSortBar');
  bar.innerHTML = '';
  [{key:'name',label:'Name'},{key:'date',label:'Date'},{key:'size',label:'Size'}].forEach(f => {
    const btn = document.createElement('button');
    btn.className = 'fp-sort-btn' + (fpSortBy === f.key ? ' active' : '');
    btn.textContent = f.label + (fpSortBy === f.key ? (fpSortAsc ? ' \u25B2' : ' \u25BC') : '');
    btn.onclick = () => setSortBy(f.key);
    bar.appendChild(btn);
  });
}

function formatSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// --- Quick Commands ---
let qcCommands = [];
let qcFilterTag = '';
let qcEditId = '';

function toggleQuickCommands() {
  const overlay = document.getElementById('qcOverlay');
  const isOpen = overlay.classList.contains('open');
  if (isOpen) {
    closeQuickCommands();
  } else {
    openQuickCommands();
  }
}

function openQuickCommands() {
  document.getElementById('qcOverlay').classList.add('open');
  qcEditId = '';
  qcHideForm();
  qcLoadCommands();
}

function closeQuickCommands() {
  document.getElementById('qcOverlay').classList.remove('open');
  // Delay focus to ensure the overlay is fully hidden first
  setTimeout(focusActiveTerminal, 50);
}

function focusActiveTerminal() {
  try {
    var frame = document.getElementById('frame-' + activeTabId);
    if (!frame) return;
    frame.focus();
    // Also try to focus the xterm helper textarea inside the iframe
    try {
      var doc = frame.contentDocument;
      if (doc) {
        var ta = doc.querySelector('.xterm-helper-textarea');
        if (ta) { ta.focus(); return; }
      }
    } catch(ce) {}
    // Try via contentWindow
    try {
      if (frame.contentWindow) {
        frame.contentWindow.focus();
      }
    } catch(cw) {}
  } catch(e) {}
}

async function qcLoadCommands() {
  const list = document.getElementById('qcList');
  list.innerHTML = '<div class="qc-empty">Loading...</div>';
  try {
    const res = await fetch('/api/quick-commands');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    if (data.error) { list.innerHTML = '<div class="qc-empty" style="color:#e94560;">' + escHtml(data.error) + '</div>'; return; }
    qcCommands = data.commands || [];
    qcRenderTags();
    qcApplyFilter();
  } catch (e) {
    list.innerHTML = '<div class="qc-empty" style="color:#e94560;">Error: ' + escHtml(e.message) + '</div>';
  }
}

function qcGetAllTags() {
  const tags = new Set();
  qcCommands.forEach(c => {
    (c.tags || '').split(',').forEach(t => {
      t = t.trim();
      if (t) tags.add(t);
    });
  });
  return Array.from(tags).sort();
}

function qcRenderTags() {
  const bar = document.getElementById('qcTagsBar');
  const allTags = qcGetAllTags();
  bar.innerHTML = '';
  if (allTags.length === 0) return;
  const allChip = document.createElement('span');
  allChip.className = 'qc-tag-chip' + (qcFilterTag === '' ? ' active' : '');
  allChip.textContent = 'All';
  allChip.onclick = () => { qcFilterTag = ''; qcRenderTags(); qcApplyFilter(); };
  bar.appendChild(allChip);
  allTags.forEach(tag => {
    const chip = document.createElement('span');
    chip.className = 'qc-tag-chip' + (qcFilterTag === tag ? ' active' : '');
    chip.textContent = tag;
    chip.onclick = () => { qcFilterTag = (qcFilterTag === tag ? '' : tag); qcRenderTags(); qcApplyFilter(); };
    bar.appendChild(chip);
  });
}

function qcApplyFilter() {
  const query = (document.getElementById('qcSearch').value || '').toLowerCase().trim();
  const filtered = qcCommands.filter(c => {
    if (qcFilterTag) {
      const tags = (c.tags || '').split(',').map(t => t.trim().toLowerCase());
      if (!tags.includes(qcFilterTag.toLowerCase())) return false;
    }
    if (query) {
      const name = (c.name || '').toLowerCase();
      const cmd = (c.command || '').toLowerCase();
      const tags = (c.tags || '').toLowerCase();
      if (!name.includes(query) && !cmd.includes(query) && !tags.includes(query)) return false;
    }
    return true;
  });
  qcRenderList(filtered);
}

function qcRenderList(commands) {
  const list = document.getElementById('qcList');
  list.innerHTML = '';
  if (commands.length === 0) {
    list.innerHTML = '<div class="qc-empty">No commands found. Click "+ Add" to create one.</div>';
    return;
  }
  commands.forEach(c => {
    const item = document.createElement('div');
    item.className = 'qc-item';
    item.onclick = () => qcSendCommand(c.command);

    const body = document.createElement('div');
    body.className = 'qc-item-body';

    const name = document.createElement('div');
    name.className = 'qc-item-name';
    name.textContent = c.name;
    body.appendChild(name);

    const cmd = document.createElement('div');
    cmd.className = 'qc-item-cmd';
    cmd.textContent = c.command;
    body.appendChild(cmd);

    if (c.tags) {
      const tagsDiv = document.createElement('div');
      tagsDiv.className = 'qc-item-tags';
      c.tags.split(',').forEach(t => {
        t = t.trim();
        if (!t) return;
        const tag = document.createElement('span');
        tag.className = 'qc-item-tag';
        tag.textContent = t;
        tagsDiv.appendChild(tag);
      });
      body.appendChild(tagsDiv);
    }
    item.appendChild(body);

    const actions = document.createElement('div');
    actions.className = 'qc-item-actions';

    const editBtn = document.createElement('button');
    editBtn.className = 'fp-act';
    editBtn.innerHTML = '&#9998;';
    editBtn.title = 'Edit';
    editBtn.onclick = (ev) => { ev.stopPropagation(); qcEditCommand(c); };
    actions.appendChild(editBtn);

    const delBtn = document.createElement('button');
    delBtn.className = 'fp-act';
    delBtn.innerHTML = '&#128465;';
    delBtn.title = 'Delete';
    delBtn.style.color = '#e94560';
    delBtn.onclick = (ev) => { ev.stopPropagation(); qcDeleteCommand(c.id, c.name); };
    actions.appendChild(delBtn);

    item.appendChild(actions);
    list.appendChild(item);
  });
}

function qcSendCommand(cmd) {
  if (!cmd) return;
  const frame = getActiveFrame();
  if (!frame || !frame.contentWindow) {
    showToast('No active terminal', true);
    return;
  }
  try {
    const w = frame.contentWindow;
    const text = cmd + '\\r';

    // 1) Try term-hook exposed objects directly (works regardless of xterm version)
    const termObj = w.term || w.terminal || w.xterm;
    if (termObj) {
      // xterm.js v4: paste()
      if (typeof termObj.paste === 'function') {
        termObj.paste(text);
        closeQuickCommands();
        showToast('Command sent', false);
        return;
      }
      // xterm.js v5+: input() triggers onData which sends via WebSocket
      if (typeof termObj.input === 'function') {
        termObj.input(text);
        closeQuickCommands();
        showToast('Command sent', false);
        return;
      }
      // Try internal core data event (xterm.js v5 internals)
      try {
        var core = termObj._core || (termObj._addonManager && termObj._addonManager._terminal && termObj._addonManager._terminal._core);
        if (core && core.coreService && typeof core.coreService.triggerDataEvent === 'function') {
          core.coreService.triggerDataEvent(text);
          closeQuickCommands();
          showToast('Command sent', false);
          return;
        }
      } catch(ei) {}
    }

    // 2) Broader search: findTerminalObject (strict check)
    const term2 = findTerminalObject(w);
    if (term2 && typeof term2.paste === 'function') {
      term2.paste(text);
      closeQuickCommands();
      showToast('Command sent', false);
      return;
    }

    // 3) Try writing to WebSocket directly (ttyd protocol: type 0 = input)
    var ws = null;
    try {
      // Common ttyd WebSocket locations
      var candidates = [w.ws, w.socket, w.webSocket];
      // Also check nested objects
      var keys = Object.getOwnPropertyNames(w);
      for (var ki = 0; ki < keys.length && !ws; ki++) {
        try {
          var v = w[keys[ki]];
          if (v instanceof WebSocket && v.readyState === 1) { ws = v; break; }
          if (v && typeof v === 'object') {
            if (v.ws instanceof WebSocket && v.ws.readyState === 1) { ws = v.ws; break; }
            if (v.socket instanceof WebSocket && v.socket.readyState === 1) { ws = v.socket; break; }
          }
        } catch(ek) {}
      }
      for (var ci = 0; ci < candidates.length && !ws; ci++) {
        if (candidates[ci] instanceof WebSocket && candidates[ci].readyState === 1) { ws = candidates[ci]; break; }
      }
    } catch(ew) {}
    if (ws) {
      var enc = new TextEncoder();
      var d = enc.encode(text);
      var msg = new Uint8Array(d.length + 1);
      msg[0] = 0;
      msg.set(d, 1);
      ws.send(msg);
      closeQuickCommands();
      showToast('Command sent', false);
      return;
    }

    // 4) Last resort: type into the xterm helper textarea character by character
    try {
      var doc = frame.contentDocument;
      var ta = doc && doc.querySelector('.xterm-helper-textarea');
      if (ta) {
        ta.focus();
        for (var i = 0; i < text.length; i++) {
          var ch = text[i];
          var kc = ch.charCodeAt(0);
          var key = ch === '\\r' ? 'Enter' : ch;
          var code = ch === '\\r' ? 13 : kc;
          ta.dispatchEvent(new KeyboardEvent('keydown', { key: key, keyCode: code, which: code, bubbles: true, cancelable: true }));
          if (ch !== '\\r') {
            ta.dispatchEvent(new InputEvent('input', { data: ch, inputType: 'insertText', bubbles: true }));
          }
          ta.dispatchEvent(new KeyboardEvent('keyup', { key: key, keyCode: code, which: code, bubbles: true }));
        }
        closeQuickCommands();
        showToast('Command sent', false);
        return;
      }
    } catch(et) {}

    showToast('Terminal not accessible - try clicking the terminal first', true);
  } catch(e) {
    showToast('Failed to send: ' + e.message, true);
  }
}

function qcShowForm(editCmd) {
  const form = document.getElementById('qcForm');
  form.style.display = 'block';
  document.getElementById('qcFormName').value = editCmd ? editCmd.name : '';
  document.getElementById('qcFormCmd').value = editCmd ? editCmd.command : '';
  document.getElementById('qcFormTags').value = editCmd ? editCmd.tags : '';
  qcEditId = editCmd ? editCmd.id : '';
  document.getElementById('qcFormSave').textContent = editCmd ? 'Update' : 'Save';
  document.getElementById('qcAddBtn').style.display = 'none';
  setTimeout(() => document.getElementById('qcFormName').focus(), 0);
}

function qcHideForm() {
  document.getElementById('qcForm').style.display = 'none';
  document.getElementById('qcAddBtn').style.display = '';
  qcEditId = '';
}

async function qcSaveForm() {
  const name = document.getElementById('qcFormName').value.trim();
  const command = document.getElementById('qcFormCmd').value.trim();
  const tags = document.getElementById('qcFormTags').value.trim();
  if (!name || !command) {
    showToast('Name and command are required', true);
    return;
  }
  try {
    const body = qcEditId
      ? { action: 'update', id: qcEditId, name, command, tags }
      : { action: 'add', name, command, tags };
    const jsonBody = JSON.stringify(body);
    const res = await fetch('/api/quick-commands', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: jsonBody,
    });
    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch(pe) {
      showToast('Server error (status ' + res.status + '): ' + text.slice(0, 120), true);
      return;
    }
    if (data.error) { showToast(data.error, true); return; }
    const wasEdit = !!qcEditId;
    qcHideForm();
    await qcLoadCommands();
    showToast(wasEdit ? 'Command updated' : 'Command added', false);
  } catch (e) {
    showToast('Error: ' + e.message, true);
  }
}

function qcEditCommand(cmd) {
  qcShowForm(cmd);
}

async function qcDeleteCommand(id, name) {
  const ok = await modalConfirm('Delete command "' + name + '"?', 'Delete Command', true);
  if (!ok) return;
  try {
    const res = await fetch('/api/quick-commands', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'delete', id: id }),
    });
    const data = await res.json();
    if (data.error) { showToast(data.error, true); return; }
    await qcLoadCommands();
    showToast('Command deleted', false);
  } catch (e) {
    showToast('Error: ' + e.message, true);
  }
}

function qcExport() {
  const a = document.createElement('a');
  a.href = '/api/quick-commands/export';
  a.download = 'ttyd_quick_command.json';
  document.body.appendChild(a);
  a.click();
  a.remove();
  showToast('Exporting commands...', false);
}

async function qcImport(files) {
  if (!files || !files.length) return;
  const file = files[0];
  try {
    const text = await file.text();
    const parsed = JSON.parse(text);
    if (!Array.isArray(parsed)) {
      showToast('Invalid file: expected a JSON array', true);
      return;
    }
    const res = await fetch('/api/quick-commands/import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: text,
    });
    const data = await res.json();
    if (data.error) { showToast(data.error, true); return; }
    await qcLoadCommands();
    var parts = [];
    if (data.added) parts.push(data.added + ' added');
    if (data.updated) parts.push(data.updated + ' updated');
    showToast(parts.length ? 'Commands: ' + parts.join(', ') : 'No new commands to import', false);
  } catch (e) {
    showToast('Import error: ' + e.message, true);
  }
}

// Close quick commands on overlay click
document.getElementById('qcOverlay').addEventListener('click', function(e) {
  if (e.target === this) closeQuickCommands();
});

// Close quick commands on Escape (handled in existing keydown listener)

// Drag and drop for file panel
(function() {
  const panel = document.getElementById('filePanel');
  let dragCounter = 0;
  panel.addEventListener('dragenter', (e) => {
    e.preventDefault();
    dragCounter++;
    panel.classList.add('dragover');
  });
  panel.addEventListener('dragleave', (e) => {
    dragCounter--;
    if (dragCounter <= 0) { dragCounter = 0; panel.classList.remove('dragover'); }
  });
  panel.addEventListener('dragover', (e) => { e.preventDefault(); });
  panel.addEventListener('drop', (e) => {
    e.preventDefault();
    dragCounter = 0;
    panel.classList.remove('dragover');
    if (e.dataTransfer.files.length) handleUpload(e.dataTransfer.files);
  });
})();

init();
</script>
</body>
</html>"""


# --- Per-user ttyd instance management ---
user_instances = {}  # {username: {"port": int, "proc": Popen}}
next_port = int(os.environ.get("TTYD_START_PORT", "7700"))


def port_is_free(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", int(port)))
        return True
    except OSError:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def allocate_port():
    global next_port
    for _ in range(2000):
        p = next_port
        next_port += 1
        if port_is_free(p):
            return p
    raise RuntimeError("unable to allocate free port")

def wait_for_ttyd_ready(port, timeout=4.0):
    """Return True if something is listening/responding on 127.0.0.1:port."""
    deadline = time.time() + float(timeout)
    while time.time() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(0.5)
            s.connect(("127.0.0.1", int(port)))
            return True
        except OSError:
            time.sleep(0.1)
        finally:
            try:
                s.close()
            except Exception:
                pass
    return False

def spawn_user_ttyd(username, password):
    """Spawn a ttyd instance for the user via SSH. Returns the port."""
    global next_port
    # Reuse existing instance if still alive
    if username in user_instances:
        info = user_instances[username]
        if info["proc"].poll() is None:
            info["password"] = password  # refresh password
            return info["port"]
        # Dead, clean up
        del user_instances[username]

    port = allocate_port()

    # Bind ttyd to localhost only, so the per-user port isn't reachable directly from the LAN/Internet.
    # Use tmux so terminal sessions persist across page refreshes and re-logins.
    # Each tab gets a grouped session pointing at a distinct tmux window.
    # Grouped sessions have destroy-unattached so they auto-clean on disconnect,
    # while the base "main" session (and its windows) persist to keep processes alive.
    # On reconnect, tabs reattach to existing windows instead of creating new ones.
    tmux_cmd = (
        r'tmux has-session -t main 2>/dev/null || exec tmux new-session -s main \; set -g mouse on \; set -g history-limit 10000 \; set -s set-clipboard on;'
        r' tmux set -g mouse on 2>/dev/null; tmux set -g history-limit 10000 2>/dev/null; tmux set -s set-clipboard on 2>/dev/null; tmux set -g set-clipboard on 2>/dev/null;'
        r' IDX=$(tmux list-sessions -F "#{session_name}" | grep -cv "^main$" || true);'
        r' NWIN=$(tmux list-windows -t main -F x | wc -l | tr -d " ");'
        r' while [ $NWIN -le $IDX ]; do tmux new-window -t main; NWIN=$((NWIN + 1)); done;'
        r' TARGET=$(tmux list-windows -t main -F "#{window_index}" | sort -n | head -n $((IDX+1)) | tail -n 1);'
        r' exec tmux new-session -t main \; set-option destroy-unattached on \; select-window -t :${TARGET:-0}'
    )
    ttyd_cmd = f"{shlex.quote(TTYD_BIN)} -W -i 127.0.0.1 -p {port} bash -lc {shlex.quote(tmux_cmd)}"
    proc = subprocess.Popen(
        [SSHPASS_BIN, "-p", password, SSH_BIN,
         "-o", "StrictHostKeyChecking=no",
         "-o", "ConnectTimeout=5",
         "-o", "PreferredAuthentications=password",
         "-o", "PubkeyAuthentication=no",
         "-o", "PasswordAuthentication=yes",
         "-o", "ServerAliveInterval=30",
         f"{username}@127.0.0.1",
         ttyd_cmd],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    user_instances[username] = {"port": port, "proc": proc, "password": password}
    if not wait_for_ttyd_ready(port, timeout=4.0):
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            user_instances.pop(username, None)
        except Exception:
            pass
        raise RuntimeError("ttyd failed to start")
    return port


def get_user_port(username):
    """Get the ttyd port for a user, or None if not running."""
    if username in user_instances:
        info = user_instances[username]
        if info["proc"].poll() is None:
            return info["port"]
        del user_instances[username]
    return None


def make_token(username, port):
    ts = str(int(time.time()))
    msg = f"{username}:{int(port)}:{ts}"
    sig = hmac.new(SECRET_KEY.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return f"{username}:{int(port)}:{ts}:{sig}"


def verify_token(token):
    """Verify token and return (username, port) if valid, else (None, None)."""
    try:
        parts = token.split(":")
        if len(parts) == 4:
            username, port_s, ts, sig = parts
            msg = f"{username}:{int(port_s)}:{ts}"
        elif len(parts) == 3:
            # Legacy tokens (pre port-binding): treat as invalid for /ut authorization.
            username, ts, sig = parts
            port_s = ""
            msg = f"{username}:{ts}"
        else:
            return None, None

        expected = hmac.new(SECRET_KEY.encode(), msg.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None, None
        if time.time() - int(ts) > SESSION_MAX_AGE:
            return None, None
        port = int(port_s) if port_s else None
        return username, port
    except Exception:
        return None, None


def get_cookie_token(headers):
    cookie = headers.get("Cookie", "")
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith(f"{COOKIE_NAME}="):
            return part.split("=", 1)[1]
    return ""


def make_path_token(username, path):
    """Return opaque signed token for an absolute path."""
    raw_path = os.path.abspath(path)
    path_b64 = base64.urlsafe_b64encode(raw_path.encode()).decode().rstrip("=")
    sig = hmac.new(
        SECRET_KEY.encode(),
        f"{username}:{raw_path}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"{path_b64}.{sig}"


def parse_path_token(username, token):
    """Decode/verify a path token; return abs path or None."""
    try:
        path_b64, sig = token.rsplit(".", 1)
        pad = "=" * ((4 - len(path_b64) % 4) % 4)
        raw_path = base64.urlsafe_b64decode((path_b64 + pad).encode()).decode()
        raw_path = os.path.abspath(raw_path)
        expected = hmac.new(
            SECRET_KEY.encode(),
            f"{username}:{raw_path}".encode(),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        return raw_path
    except Exception:
        return None


def breadcrumb_tokens(username, abs_path):
    """Return breadcrumb list with opaque tokens for navigation."""
    parts = abs_path.strip("/").split("/") if abs_path != "/" else []
    crumbs = [{"name": "/", "token": make_path_token(username, "/")}]
    built = ""
    for p in parts:
        built += "/" + p
        crumbs.append({"name": p, "token": make_path_token(username, built)})
    return crumbs


def run_as_user(username, python_script, timeout=10):
    """Run a Python script as the given user via SSH. Returns (returncode, stdout_bytes, stderr_bytes)."""
    info = user_instances.get(username)
    if not info or "password" not in info:
        return (1, b"", b"no session")
    password = info["password"]
    try:
        result = subprocess.run(
            [SSHPASS_BIN, "-p", password, SSH_BIN,
             "-o", "StrictHostKeyChecking=no",
             "-o", "PubkeyAuthentication=no",
             "-o", "ConnectTimeout=5",
             f"{username}@127.0.0.1", "python3", "-"],
            input=python_script.encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout
        )
        return (result.returncode, result.stdout, result.stderr)
    except subprocess.TimeoutExpired:
        return (1, b"", b"timeout")
    except Exception as e:
        return (1, b"", str(e).encode())


class AuthHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        if ACCESS_LOG_ENABLED:
            super().log_message(fmt, *args)

    def send_header(self, keyword, value):
        # Track response content-type for conditional security headers.
        if keyword.lower() == "content-type":
            try:
                self._resp_content_type = str(value)
            except Exception:
                self._resp_content_type = ""
        super().send_header(keyword, value)

    def end_headers(self):
        for k, v in DEFAULT_SECURITY_HEADERS.items():
            self.send_header(k, v)
        ct = getattr(self, "_resp_content_type", "") or ""
        ct_main = ct.split(";", 1)[0].strip().lower()
        if ct_main == "text/html":
            for k, v in HTML_ONLY_SECURITY_HEADERS.items():
                self.send_header(k, v)
        super().end_headers()

    def _get_authenticated_user(self):
        token = get_cookie_token(self.headers)
        username, _port = verify_token(token)
        return username

    def _send_json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, code, msg):
        self._send_json(code, {"error": msg})

    def _path_from_params(self, username, params):
        token = params.get("path_token", [""])[0]
        if token:
            p = parse_path_token(username, token)
            return p
        raw = params.get("path", [""])[0]
        return os.path.expanduser(raw) if raw else None

    def _path_from_body(self, username, req):
        token = req.get("path_token", "")
        if token:
            return parse_path_token(username, token)
        raw = req.get("path", "")
        return os.path.expanduser(raw) if raw else None

    # --- File API handlers ---

    def _handle_files_list(self, params):
        username = self._get_authenticated_user()
        if not username:
            self._send_error(401, "not authenticated")
            return
        path = self._path_from_params(username, params) or "~"
        script = f'''
import os, json, stat
p = os.path.expanduser({path!r})
entries = []
try:
    for e in os.scandir(p):
        try:
            s = e.stat(follow_symlinks=False)
            entries.append({{
                "name": e.name,
                "type": "dir" if e.is_dir(follow_symlinks=False) else "file",
                "size": s.st_size,
                "mtime": int(s.st_mtime),
                "link": stat.S_ISLNK(s.st_mode),
            }})
        except OSError:
            entries.append({{"name": e.name, "type": "file", "size": 0, "mtime": 0, "link": False}})
    entries.sort(key=lambda x: (x["type"] != "dir", x["name"].lower()))
    print(json.dumps({{"path": os.path.abspath(p), "entries": entries}}))
except Exception as ex:
    print(json.dumps({{"error": str(ex)}}))
'''
        rc, out, err = run_as_user(username, script)
        if rc != 0:
            self._send_error(500, err.decode(errors="replace"))
            return
        try:
            data = json.loads(out)
        except Exception:
            self._send_error(500, out.decode(errors="replace"))
            return
        if "error" in data:
            self._send_error(400, data["error"])
        else:
            abs_path = os.path.abspath(data.get("path", "/"))
            parent_token = None
            if abs_path != "/":
                parent = os.path.dirname(abs_path.rstrip("/")) or "/"
                parent_token = make_path_token(username, parent)

            for e in data.get("entries", []):
                epath = os.path.join(abs_path, e.get("name", ""))
                e["token"] = make_path_token(username, epath)

            data["path_token"] = make_path_token(username, abs_path)
            data["parent_token"] = parent_token
            data["breadcrumbs"] = breadcrumb_tokens(username, abs_path)
            self._send_json(200, data)

    def _handle_files_read(self, params):
        username = self._get_authenticated_user()
        if not username:
            self._send_error(401, "not authenticated")
            return
        path = self._path_from_params(username, params)
        if not path:
            self._send_error(400, "missing path")
            return
        script = f'''
import os, json
p = os.path.expanduser({path!r})
try:
    size = os.path.getsize(p)
    if size > 102400:
        print(json.dumps({{"error": "file too large (>100KB)"}}))
    else:
        with open(p, "rb") as f:
            data = f.read()
        is_text = True
        content = ""
        if b"\\x00" in data:
            is_text = False
        else:
            try:
                content = data.decode("utf-8")
            except UnicodeDecodeError:
                is_text = False
        print(json.dumps({{
            "is_text": is_text,
            "content": content if is_text else "",
            "size": size
        }}))
except Exception as ex:
    print(json.dumps({{"error": str(ex)}}))
'''
        rc, out, err = run_as_user(username, script)
        if rc != 0:
            self._send_error(500, err.decode(errors="replace"))
            return
        try:
            data = json.loads(out)
        except Exception:
            self._send_error(500, out.decode(errors="replace"))
            return
        if "error" in data:
            self._send_error(400, data["error"])
        else:
            self._send_json(200, data)

    def _handle_files_write(self):
        username = self._get_authenticated_user()
        if not username:
            self._send_error(401, "not authenticated")
            return

        length = int(self.headers.get("Content-Length", 0))
        if length > 512 * 1024:
            self._send_error(413, "payload too large")
            return
        body = self.rfile.read(length)
        try:
            req = json.loads(body)
        except Exception:
            self._send_error(400, "invalid json")
            return

        path = self._path_from_body(username, req)
        content = req.get("content")
        if not path or not isinstance(content, str):
            self._send_error(400, "missing path or content")
            return

        content_size = len(content.encode("utf-8"))
        if content_size > 102400:
            self._send_error(400, "file too large (>100KB)")
            return

        script = f'''
import os, json
p = os.path.expanduser({path!r})
content = {content!r}
try:
    if os.path.isdir(p):
        raise Exception("path is a directory")
    if os.path.exists(p):
        with open(p, "rb") as f:
            sample = f.read(8192)
        if b"\\x00" in sample:
            raise Exception("binary file cannot be edited here")
        try:
            sample.decode("utf-8")
        except UnicodeDecodeError:
            raise Exception("non-UTF-8 file cannot be edited here")

    with open(p, "w", encoding="utf-8", newline="") as f:
        f.write(content)
    print(json.dumps({{"ok": True, "size": len(content.encode("utf-8"))}}))
except Exception as ex:
    print(json.dumps({{"error": str(ex)}}))
'''
        rc, out, err = run_as_user(username, script, timeout=20)
        if rc != 0:
            self._send_error(500, err.decode(errors="replace"))
            return
        try:
            data = json.loads(out)
        except Exception:
            self._send_error(500, out.decode(errors="replace"))
            return
        if "error" in data:
            self._send_error(400, data["error"])
        else:
            self._send_json(200, data)

    def _handle_files_download(self, params):
        username = self._get_authenticated_user()
        if not username:
            self._send_error(401, "not authenticated")
            return
        path = self._path_from_params(username, params)
        inline = params.get("inline", ["0"])[0].lower() in ("1", "true", "yes")
        if not path:
            self._send_error(400, "missing path")
            return
        script = f'''
import os, sys, base64
p = os.path.expanduser({path!r})
try:
    with open(p, "rb") as f:
        data = f.read()
    sys.stdout.buffer.write(b"OK\\n")
    sys.stdout.buffer.write(base64.b64encode(data))
    sys.stdout.buffer.write(b"\\n")
    sys.stdout.buffer.write(os.path.basename(p).encode())
except Exception as ex:
    sys.stdout.buffer.write(b"ERR\\n")
    sys.stdout.buffer.write(str(ex).encode())
'''
        rc, out, err = run_as_user(username, script, timeout=30)
        if rc != 0:
            self._send_error(500, err.decode(errors="replace"))
            return
        lines = out.split(b"\n", 2)
        if lines[0] == b"OK" and len(lines) >= 3:
            try:
                file_data = base64.b64decode(lines[1])
            except Exception:
                self._send_error(500, "decode error")
                return
            fname = lines[2].decode(errors="replace").strip()
            ext = os.path.splitext(fname.lower())[1]
            content_type = mimetypes.guess_type(fname)[0]
            if not content_type:
                fallback_types = {
                    ".pdf": "application/pdf",
                    ".mp3": "audio/mpeg",
                    ".wav": "audio/wav",
                    ".m4a": "audio/mp4",
                    ".aac": "audio/aac",
                    ".flac": "audio/flac",
                    ".ogg": "audio/ogg",
                    ".oga": "audio/ogg",
                    ".opus": "audio/ogg",
                    ".mp4": "video/mp4",
                    ".m4v": "video/mp4",
                    ".webm": "video/webm",
                    ".mov": "video/quicktime",
                    ".jpg": "image/jpeg",
                    ".jpeg": "image/jpeg",
                    ".png": "image/png",
                    ".gif": "image/gif",
                    ".webp": "image/webp",
                }
                content_type = fallback_types.get(ext, "application/octet-stream")
            self.send_response(200)
            self.send_header("Content-Type", content_type if inline else "application/octet-stream")
            disp = "inline" if inline else "attachment"
            self.send_header("Content-Disposition", content_disposition(disp, fname))
            self.send_header("Content-Length", str(len(file_data)))
            self.end_headers()
            self.wfile.write(file_data)
        else:
            msg = lines[1].decode(errors="replace") if len(lines) > 1 else "download failed"
            self._send_error(500, msg)

    def _handle_files_upload(self, params):
        username = self._get_authenticated_user()
        if not username:
            self._send_error(401, "not authenticated")
            return

        dir_path = self._path_from_params(username, params)
        if not dir_path:
            dir_token = self.headers.get("X-Path-Token", "")
            if dir_token:
                dir_path = parse_path_token(username, dir_token)

        name_b64 = self.headers.get("X-File-Name-B64", "")
        file_name = ""
        if name_b64:
            try:
                pad = "=" * ((4 - len(name_b64) % 4) % 4)
                file_name = base64.urlsafe_b64decode((name_b64 + pad).encode()).decode()
            except Exception:
                file_name = ""
        if not file_name:
            file_name = params.get("name", [""])[0]

        file_name = os.path.basename(file_name)
        if file_name in ("", ".", ".."):
            self._send_error(400, "invalid file name")
            return
        if not dir_path or not file_name:
            self._send_error(400, "missing path or name")
            return
        length = int(self.headers.get("Content-Length", 0))
        if length > 10 * 1024 * 1024:
            self._send_error(413, "file too large (>10MB)")
            return
        body = self.rfile.read(length)
        b64data = base64.b64encode(body).decode()
        script = f'''
import os, base64, json
d = os.path.expanduser({dir_path!r})
fp = os.path.join(d, {file_name!r})
try:
    data = base64.b64decode({b64data!r})
    with open(fp, "wb") as f:
        f.write(data)
    print(json.dumps({{"ok": True, "path": fp, "size": len(data)}}))
except Exception as ex:
    print(json.dumps({{"error": str(ex)}}))
'''
        rc, out, err = run_as_user(username, script, timeout=30)
        if rc != 0:
            self._send_error(500, err.decode(errors="replace"))
            return
        try:
            data = json.loads(out)
        except Exception:
            self._send_error(500, out.decode(errors="replace"))
            return
        if "error" in data:
            self._send_error(400, data["error"])
        else:
            self._send_json(200, data)

    def _handle_files_mkdir(self):
        username = self._get_authenticated_user()
        if not username:
            self._send_error(401, "not authenticated")
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            req = json.loads(body)
        except Exception:
            self._send_error(400, "invalid json")
            return
        parent = self._path_from_body(username, req)
        name = os.path.basename(req.get("name", ""))
        if name in (".", ".."):
            self._send_error(400, "invalid folder name")
            return
        path = req.get("path", "")
        if parent and name:
            path = os.path.join(parent, name)
        if not path:
            self._send_error(400, "missing path")
            return
        script = f'''
import os, json
p = os.path.expanduser({path!r})
try:
    os.makedirs(p, exist_ok=False)
    print(json.dumps({{"ok": True, "path": p}}))
except Exception as ex:
    print(json.dumps({{"error": str(ex)}}))
'''
        rc, out, err = run_as_user(username, script)
        if rc != 0:
            self._send_error(500, err.decode(errors="replace"))
            return
        try:
            data = json.loads(out)
        except Exception:
            self._send_error(500, out.decode(errors="replace"))
            return
        if "error" in data:
            self._send_error(400, data["error"])
        else:
            self._send_json(200, data)

    def _handle_files_delete(self):
        username = self._get_authenticated_user()
        if not username:
            self._send_error(401, "not authenticated")
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            req = json.loads(body)
        except Exception:
            self._send_error(400, "invalid json")
            return
        path = self._path_from_body(username, req)
        if not path:
            self._send_error(400, "missing path")
            return
        script = f'''
import os, shutil, json
p = os.path.expanduser({path!r})
try:
    if os.path.isdir(p):
        shutil.rmtree(p)
    else:
        os.remove(p)
    print(json.dumps({{"ok": True}}))
except Exception as ex:
    print(json.dumps({{"error": str(ex)}}))
'''
        rc, out, err = run_as_user(username, script)
        if rc != 0:
            self._send_error(500, err.decode(errors="replace"))
            return
        try:
            data = json.loads(out)
        except Exception:
            self._send_error(500, out.decode(errors="replace"))
            return
        if "error" in data:
            self._send_error(400, data["error"])
        else:
            self._send_json(200, data)

    # --- Quick Commands API handlers ---

    def _handle_quick_commands_list(self):
        username = self._get_authenticated_user()
        if not username:
            self._send_error(401, "not authenticated")
            return
        script = '''
import os, json
p = os.path.expanduser("~/ttyd_quick_command.json")
try:
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            data = []
    else:
        data = []
    print(json.dumps({"ok": True, "commands": data}))
except Exception as ex:
    print(json.dumps({"error": str(ex)}))
'''
        rc, out, err = run_as_user(username, script)
        if rc != 0:
            self._send_error(500, err.decode(errors="replace"))
            return
        try:
            data = json.loads(out)
        except Exception:
            self._send_error(500, out.decode(errors="replace"))
            return
        if "error" in data:
            self._send_error(400, data["error"])
        else:
            self._send_json(200, data)

    def _handle_quick_commands_action(self):
        username = self._get_authenticated_user()
        if not username:
            self._send_error(401, "not authenticated")
            return
        length = int(self.headers.get("Content-Length", 0))
        if length > 512 * 1024:
            self._send_error(413, "payload too large")
            return
        body = self.rfile.read(length) if length > 0 else b""
        try:
            req = json.loads(body)
        except Exception as e:
            print(f"quick-commands: invalid json body ({length} bytes): {body[:200]!r}", flush=True)
            self._send_error(400, f"invalid json (received {length} bytes): {str(e)}")
            return
        action = req.get("action", "")
        if action not in ("add", "update", "delete"):
            self._send_error(400, "invalid action (must be add, update, or delete)")
            return
        # Pass request data as base64-encoded JSON to avoid quoting issues
        req_b64 = base64.b64encode(json.dumps(req).encode()).decode()
        script = f'''
import os, json, time, hashlib, base64
p = os.path.expanduser("~/ttyd_quick_command.json")
req = json.loads(base64.b64decode({req_b64!r}).decode())
action = req.get("action", "")
try:
    cmds = []
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as f:
            cmds = json.load(f)
        if not isinstance(cmds, list):
            cmds = []

    if action == "add":
        name = req.get("name", "").strip()
        command = req.get("command", "").strip()
        tags = req.get("tags", "").strip()
        if not name or not command:
            raise Exception("name and command are required")
        new_id = hashlib.sha256((name + command + str(time.time())).encode()).hexdigest()[:12]
        cmds.append({{
            "id": new_id,
            "name": name,
            "command": command,
            "tags": tags,
            "created": int(time.time()),
            "updated": int(time.time()),
        }})
        with open(p, "w", encoding="utf-8") as f:
            json.dump(cmds, f, indent=2)
        print(json.dumps({{"ok": True, "id": new_id}}))

    elif action == "update":
        cmd_id = req.get("id", "")
        if not cmd_id:
            raise Exception("id is required")
        found = False
        for c in cmds:
            if c.get("id") == cmd_id:
                if "name" in req:
                    c["name"] = req["name"].strip()
                if "command" in req:
                    c["command"] = req["command"].strip()
                if "tags" in req:
                    c["tags"] = req["tags"].strip()
                c["updated"] = int(time.time())
                found = True
                break
        if not found:
            raise Exception("command not found")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(cmds, f, indent=2)
        print(json.dumps({{"ok": True}}))

    elif action == "delete":
        cmd_id = req.get("id", "")
        if not cmd_id:
            raise Exception("id is required")
        new_cmds = [c for c in cmds if c.get("id") != cmd_id]
        if len(new_cmds) == len(cmds):
            raise Exception("command not found")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(new_cmds, f, indent=2)
        print(json.dumps({{"ok": True}}))

except Exception as ex:
    print(json.dumps({{"error": str(ex)}}))
'''
        rc, out, err = run_as_user(username, script)
        if rc != 0:
            errmsg = err.decode(errors="replace").strip()
            print(f"quick-commands action: script failed rc={rc} err={errmsg[:300]}", flush=True)
            self._send_error(500, f"script error: {errmsg[:200]}")
            return
        try:
            data = json.loads(out)
        except Exception:
            raw = out.decode(errors="replace").strip()
            print(f"quick-commands action: bad output: {raw[:300]}", flush=True)
            self._send_error(500, f"script output not json: {raw[:200]}")
            return
        if "error" in data:
            self._send_error(400, data["error"])
        else:
            self._send_json(200, data)

    def _handle_quick_commands_export(self):
        username = self._get_authenticated_user()
        if not username:
            self._send_error(401, "not authenticated")
            return
        script = '''
import os, json, sys
p = os.path.expanduser("~/ttyd_quick_command.json")
try:
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            data = []
    else:
        data = []
    print(json.dumps(data))
except Exception as ex:
    print(json.dumps({"error": str(ex)}))
'''
        rc, out, err = run_as_user(username, script)
        if rc != 0:
            self._send_error(500, err.decode(errors="replace"))
            return
        try:
            data = json.loads(out)
        except Exception:
            self._send_error(500, out.decode(errors="replace"))
            return
        if isinstance(data, dict) and "error" in data:
            self._send_error(400, data["error"])
            return
        body = json.dumps(data, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Disposition",
                         content_disposition("attachment", "ttyd_quick_command.json"))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_quick_commands_import(self):
        username = self._get_authenticated_user()
        if not username:
            self._send_error(401, "not authenticated")
            return
        length = int(self.headers.get("Content-Length", 0))
        if length > 2 * 1024 * 1024:
            self._send_error(413, "file too large (>2MB)")
            return
        body = self.rfile.read(length)
        try:
            imported = json.loads(body)
        except Exception:
            self._send_error(400, "invalid json")
            return
        if not isinstance(imported, list):
            self._send_error(400, "expected a JSON array of commands")
            return
        # Validate structure
        for item in imported:
            if not isinstance(item, dict):
                self._send_error(400, "each command must be a JSON object")
                return
            if not item.get("name") or not item.get("command"):
                self._send_error(400, "each command must have name and command fields")
                return
        # Pass imported data as base64-encoded JSON to avoid quoting issues
        imported_b64 = base64.b64encode(json.dumps(imported).encode()).decode()
        script = f'''
import os, json, time, hashlib, base64
p = os.path.expanduser("~/ttyd_quick_command.json")
imported = json.loads(base64.b64decode({imported_b64!r}).decode())
try:
    cmds = []
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as f:
            cmds = json.load(f)
        if not isinstance(cmds, list):
            cmds = []
    existing_by_name = {{}}
    for i, c in enumerate(cmds):
        existing_by_name[c.get("name", "").strip().lower()] = i
    existing_ids = set(c.get("id", "") for c in cmds)
    added = 0
    updated = 0
    for item in imported:
        iname = str(item.get("name", "")).strip()
        key = iname.lower()
        if key in existing_by_name:
            idx = existing_by_name[key]
            cmds[idx]["command"] = str(item.get("command", ""))
            cmds[idx]["tags"] = str(item.get("tags", ""))
            cmds[idx]["updated"] = int(time.time())
            updated += 1
        else:
            cmd_id = item.get("id", "")
            if not cmd_id or cmd_id in existing_ids:
                cmd_id = hashlib.sha256((iname + str(item.get("command","")) + str(time.time()) + str(added)).encode()).hexdigest()[:12]
            existing_ids.add(cmd_id)
            cmds.append({{
                "id": cmd_id,
                "name": iname,
                "command": str(item.get("command", "")),
                "tags": str(item.get("tags", "")),
                "created": item.get("created", int(time.time())),
                "updated": int(time.time()),
            }})
            existing_by_name[key] = len(cmds) - 1
            added += 1
    with open(p, "w", encoding="utf-8") as f:
        json.dump(cmds, f, indent=2)
    print(json.dumps({{"ok": True, "added": added, "updated": updated, "total": len(cmds)}}))
except Exception as ex:
    print(json.dumps({{"error": str(ex)}}))
'''
        rc, out, err = run_as_user(username, script)
        if rc != 0:
            self._send_error(500, err.decode(errors="replace"))
            return
        try:
            data = json.loads(out)
        except Exception:
            self._send_error(500, out.decode(errors="replace"))
            return
        if "error" in data:
            self._send_error(400, data["error"])
        else:
            self._send_json(200, data)

    def _handle_files_rename(self):
        username = self._get_authenticated_user()
        if not username:
            self._send_error(401, "not authenticated")
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            req = json.loads(body)
        except Exception:
            self._send_error(400, "invalid json")
            return
        old = self._path_from_body(username, req) or req.get("old", "")
        new_name = os.path.basename(req.get("new_name", ""))
        if new_name in (".", ".."):
            self._send_error(400, "invalid new name")
            return
        if old and new_name:
            new = os.path.join(os.path.dirname(old), new_name)
        else:
            new = req.get("new", "")
        if not old or not new:
            self._send_error(400, "missing old or new")
            return
        script = f'''
import os, json
old = os.path.expanduser({old!r})
new = os.path.expanduser({new!r})
try:
    os.rename(old, new)
    print(json.dumps({{"ok": True}}))
except Exception as ex:
    print(json.dumps({{"error": str(ex)}}))
'''
        rc, out, err = run_as_user(username, script)
        if rc != 0:
            self._send_error(500, err.decode(errors="replace"))
            return
        try:
            data = json.loads(out)
        except Exception:
            self._send_error(500, out.decode(errors="replace"))
            return
        if "error" in data:
            self._send_error(400, data["error"])
        else:
            self._send_json(200, data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        if path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(LOGIN_HTML.encode())
        elif path == "/app":
            # Extract username and port from session
            token = get_cookie_token(self.headers)
            username, port = verify_token(token)
            if not username or not port:
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            # Inject the user's ttyd port into the app HTML
            html = (
                APP_HTML
                .replace("__TTYD_PORT__", str(port))
                .replace("__USERNAME__", username)
                .replace("__COOKIE_NAME__", COOKIE_NAME)
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode())
        elif path == "/api/term-hook.js":
            token = get_cookie_token(self.headers)
            username, _port = verify_token(token)
            if not username:
                self.send_response(401)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(TERM_HOOK_JS.encode("utf-8"))
        elif path == "/api/auth":
            token = get_cookie_token(self.headers)
            username, token_port = verify_token(token)
            if not username:
                self.send_response(401)
                self.end_headers()
                return

            # Optional authorization for /ut/<port>/ access.
            # nginx passes the requested port in X-TTYD-Port (inherited var from /ut location).
            req_port = (self.headers.get("X-TTYD-Port") or "").strip()
            if req_port:
                try:
                    req_port_i = int(req_port)
                except ValueError:
                    self.send_response(401)
                    self.end_headers()
                    return
                # Enforce that the cookie is bound to the requested ttyd port.
                if token_port != req_port_i:
                    self.send_response(401)
                    self.end_headers()
                    return

            self.send_response(200)
            self.end_headers()
        elif path == "/api/files/list":
            self._handle_files_list(params)
        elif path == "/api/files/read":
            self._handle_files_read(params)
        elif path == "/api/files/download":
            self._handle_files_download(params)
        elif path == "/api/quick-commands":
            self._handle_quick_commands_list()
        elif path == "/api/quick-commands/export":
            self._handle_quick_commands_export()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        if path == "/api/login":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                data = json.loads(body)
            except Exception:
                self.send_response(400)
                self.end_headers()
                return
            username = data.get("username", "")
            password = data.get("password", "")
            if authenticate(username, password):
                try:
                    port = spawn_user_ttyd(username, password)
                except Exception:
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"ok":false,"error":"terminal startup failed"}')
                    return
                token = make_token(username, port)
                self.send_response(200)
                cookie_parts = [
                    f"{COOKIE_NAME}={token}",
                    "Path=/",
                    "HttpOnly",
                    "SameSite=Strict",
                    f"Max-Age={SESSION_MAX_AGE}",
                ]
                if COOKIE_SECURE:
                    cookie_parts.append("Secure")
                self.send_header("Set-Cookie", "; ".join(cookie_parts))
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": True, "port": port}).encode())
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok":false,"error":"invalid username or password"}')
        elif path == "/api/files/upload":
            self._handle_files_upload(params)
        elif path == "/api/files/write":
            self._handle_files_write()
        elif path == "/api/files/mkdir":
            self._handle_files_mkdir()
        elif path == "/api/files/delete":
            self._handle_files_delete()
        elif path == "/api/files/rename":
            self._handle_files_rename()
        elif path == "/api/quick-commands":
            self._handle_quick_commands_action()
        elif path == "/api/quick-commands/import":
            self._handle_quick_commands_import()
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    server = http.server.HTTPServer(("127.0.0.1", PORT), AuthHandler)
    print(f"Auth service running on http://127.0.0.1:{PORT}")
    server.serve_forever()
AUTHEOF

  # Replace the ttyd path placeholder with the resolved path
  if is_macos; then
    sed -i '' "s|TTYD_PATH_PLACEHOLDER|${ttyd_path}|g" "${auth_dir}/auth.py"
  else
    sed -i "s|TTYD_PATH_PLACEHOLDER|${ttyd_path}|g" "${auth_dir}/auth.py"
  fi

  chmod +x "${auth_dir}/auth.py"
  say "Deployed auth service: ${auth_dir}/auth.py"
  say "  ttyd path baked in: ${ttyd_path}"
}

start_auth_service() {
  local auth_port="$1"

  say ""
  say "=== Starting auth service ==="

  # Kill any existing process on the auth port
  local pids
  pids="$(lsof -ti:"${auth_port}" 2>/dev/null || true)"
  if [ -n "$pids" ]; then
    say "Killing existing process on port ${auth_port}..."
    echo "$pids" | xargs kill -9 2>/dev/null || true
    sleep 1
  fi

  local log_file
  if is_macos; then
    mkdir -p "$HOME/Library/Logs"
    log_file="$HOME/Library/Logs/ttyd-auth.log"
  else
    log_file="$AUTH_DIR/auth.log"
  fi

  AUTH_PORT="$auth_port" python3 "$AUTH_DIR/auth.py" > "$log_file" 2>&1 &
  local pid=$!
  sleep 2

  if kill -0 "$pid" 2>/dev/null; then
    say "Auth service started (PID: $pid) on port ${auth_port}"
    say "  Log: $log_file"
  else
    err "Auth service failed to start. Check log: $log_file"
    return 1
  fi
}

install_auth_plist() {
  local auth_port="$1"

  say "Installing auth service as macOS LaunchAgent..."
  local plist="$HOME/Library/LaunchAgents/com.ttyd-auth.plist"
  local log_dir="$HOME/Library/Logs"
  mkdir -p "$log_dir"

  cat > "$plist" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ttyd-auth</string>
    <key>ProgramArguments</key>
    <array>
        <string>$(command -v python3)</string>
        <string>$AUTH_DIR/auth.py</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>AUTH_PORT</key>
        <string>${auth_port}</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${log_dir}/ttyd-auth.log</string>
    <key>StandardErrorPath</key>
    <string>${log_dir}/ttyd-auth.log</string>
</dict>
</plist>
PLISTEOF

  launchctl unload "$plist" 2>/dev/null || true
  launchctl load "$plist"
  say "Auth service LaunchAgent installed: $plist"
}

install_auth_systemd() {
  local auth_port="$1"

  if pidof systemd >/dev/null 2>&1; then
    say "Installing auth service as systemd user service..."
    local svc_dir="$HOME/.config/systemd/user"
    mkdir -p "$svc_dir"

    cat > "${svc_dir}/ttyd-auth.service" <<SVCEOF
[Unit]
Description=ttyd web terminal auth service
After=network.target

[Service]
Type=simple
Environment=AUTH_PORT=${auth_port}
ExecStart=$(command -v python3) $AUTH_DIR/auth.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
SVCEOF

    systemctl --user daemon-reload
    systemctl --user enable --now ttyd-auth.service
    say "Auth service systemd unit installed: ${svc_dir}/ttyd-auth.service"
  else
    # WSL2 or non-systemd: start auth directly in background
    say "Starting auth service in background (no systemd)..."
    local auth_py="$AUTH_DIR/auth.py"
    local auth_log="$AUTH_DIR/auth.log"
    AUTH_PORT="$auth_port" nohup python3 "$auth_py" >> "$auth_log" 2>&1 &
    say "Auth service started (pid: $!), log: $auth_log"
  fi
}

# ─── Main ──────────────────────────────────────────────────────────────────────

main() {
  local name="" hostname="" service=""
  local cfg="$HOME/.cloudflared/config.yml"
  local creds=""
  local replace_config=false no_dns=false run_fg=false install_service=false yes=false
  local web_terminal=false nginx_port="7680" auth_port="7682"

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --name) name="$2"; shift 2;;
      --hostname) hostname="$2"; shift 2;;
      --service) service="$2"; shift 2;;
      --credentials) creds="$2"; shift 2;;
      --config) cfg="$2"; shift 2;;
      --replace-config) replace_config=true; shift;;
      --no-dns) no_dns=true; shift;;
      --run-foreground) run_fg=true; shift;;
      --install-service) install_service=true; shift;;
      --web-terminal) web_terminal=true; shift;;
      --nginx-port) nginx_port="$2"; shift 2;;
      --auth-port) auth_port="$2"; shift 2;;
      --yes) yes=true; shift;;
      -h|--help) usage; exit 0;;
      *) err "Unknown option: $1"; usage; exit 2;;
    esac
  done

  # When --web-terminal, service defaults to nginx port and is not required from CLI
  if [ "$web_terminal" = true ]; then
    service="http://localhost:${nginx_port}"
  fi

  if [ -z "$name" ] || [ -z "$hostname" ]; then
    err "Missing required args. --name and --hostname are required."
    usage
    exit 2
  fi
  if [ -z "$service" ]; then
    err "Missing --service. Provide a local service URL or use --web-terminal."
    usage
    exit 2
  fi

  validate_hostname "$hostname"

  need_cmd curl
  install_cloudflared
  cloudflared --version

  ensure_auth

  say "Checking existing tunnels..."
  cloudflared tunnel list || true

  if cloudflared tunnel list 2>/dev/null | awk '{print $2}' | grep -qx "$name"; then
    say "Tunnel already exists: $name (will reuse)"
  else
    say "Creating tunnel: $name"
    cloudflared tunnel create "$name"
  fi

  if [ -z "$creds" ]; then
    tid="$(cloudflared tunnel list 2>/dev/null | awk -v n="$name" '$2==n {print $1}' | head -n1 || true)"
    if [ -n "$tid" ] && [ -f "$HOME/.cloudflared/${tid}.json" ]; then
      creds="$HOME/.cloudflared/${tid}.json"
    fi
  fi

  if [ -z "$creds" ] || [ ! -f "$creds" ]; then
    err "Could not auto-detect credentials JSON."
    err "Look for ~/.cloudflared/<TUNNEL_ID>.json and re-run with --credentials <file>"
    exit 1
  fi

  write_or_merge_config "$name" "$hostname" "$service" "$cfg" "$creds" "$replace_config"

  if [ "$no_dns" = false ]; then
    say "Creating DNS route (CNAME) in Cloudflare: $hostname -> tunnel $name"
    cloudflared tunnel route dns "$name" "$hostname"
  else
    say "Skipping DNS route (--no-dns)."
  fi

  # ── Web Terminal Setup ──
  if [ "$web_terminal" = true ]; then
    install_web_terminal_deps
    enable_ssh_server
    deploy_auth_service "$auth_port"
    configure_nginx "$hostname" "$nginx_port" "$auth_port"
    start_auth_service "$auth_port"
  fi

  if [ "$run_fg" = true ]; then
    say "Running tunnel in foreground for testing. Visit: https://$hostname"
    say "Press Ctrl+C to stop when verified."
    cloudflared tunnel run "$name"
  fi

  if [ "$install_service" = true ]; then
    say ""
    say "=== Installing persistent services ==="

    # --- cloudflared service ---
    say "Installing cloudflared as a service..."
    if is_macos; then
      cloudflared service install

      # macOS: fix broken plist missing "tunnel run" arguments
      local plist="$HOME/Library/LaunchAgents/com.cloudflare.cloudflared.plist"
      if [ -f "$plist" ]; then
        if ! /usr/libexec/PlistBuddy -c "Print :ProgramArguments" "$plist" 2>/dev/null | grep -q "tunnel"; then
          say "Fixing plist: adding 'tunnel run' to ProgramArguments..."
          /usr/libexec/PlistBuddy -c "Add :ProgramArguments:1 string tunnel" "$plist"
          /usr/libexec/PlistBuddy -c "Add :ProgramArguments:2 string run" "$plist"
          launchctl unload "$plist" 2>/dev/null || true
          launchctl load "$plist"
          say "Plist fixed and service reloaded: $plist"
        else
          say "Plist already has 'tunnel run' arguments. No fix needed."
        fi
      else
        say "Warning: expected plist not found at $plist"
      fi
    else
      if pidof systemd >/dev/null 2>&1; then
        sudo cloudflared service install
        say "Linux: cloudflared service installed (systemd)."
      else
        say "No systemd detected (WSL2?). Starting cloudflared in background..."
        sudo nohup cloudflared tunnel run >> /var/log/cloudflared.log 2>&1 &
        say "Linux: cloudflared started (pid: $!), log: /var/log/cloudflared.log"
      fi
    fi

    # --- auth service (only with --web-terminal) ---
    if [ "$web_terminal" = true ]; then
      if is_macos; then
        install_auth_plist "$auth_port"
      else
        install_auth_systemd "$auth_port"
      fi
    fi
  fi

  # ── Summary ──
  cat <<EOF

=======================================
Cloudflare Tunnel Setup Complete
  Tunnel name:   $name
  Local service: $service
  Public URL:    https://$hostname
  Config file:   $cfg
  Credentials:   $creds
EOF

  if [ "$web_terminal" = true ]; then
    local conf_dir
    conf_dir="$(get_nginx_conf_dir)"
    cat <<EOF

Web Terminal Setup
  Auth service:  http://127.0.0.1:${auth_port} (${AUTH_DIR}/auth.py)
  nginx config:  ${conf_dir}/${hostname}.conf
  nginx port:    ${nginx_port}
  ttyd ports:    7700+ (per-user, dynamic)
  Login URL:     https://${hostname}
=======================================
EOF
  else
    say "======================================="
  fi

  # ── Ensure tunnel is running ──
  # If neither --run-foreground nor --install-service was used, the tunnel
  # won't be running. Start it in a tmux session so the user doesn't hit
  # error 1033 (tunnel not connected).
  if [ "$run_fg" = false ] && [ "$install_service" = false ]; then
    if ! pgrep -x cloudflared >/dev/null 2>&1; then
      say ""
      say "Starting tunnel in tmux session 'cloudflared'..."
      need_cmd tmux
      local cf_log="${AUTH_DIR}/cloudflared.log"
      if tmux has-session -t cloudflared 2>/dev/null; then
        tmux kill-session -t cloudflared 2>/dev/null || true
        sleep 1
      fi
      tmux new-session -d -s cloudflared \
        "cloudflared tunnel run ${name} 2>&1 | tee -a ${cf_log}"

      # Wait for tunnel to connect (up to 15s).
      say "Waiting for tunnel to connect..."
      local _i _connected=false
      for _i in $(seq 1 30); do
        if pgrep -x cloudflared >/dev/null 2>&1; then
          local _conns
          _conns="$(cloudflared tunnel info "$name" 2>/dev/null | grep -c 'CONNECTIONS\|connector' || true)"
          if [ "${_conns:-0}" -gt 0 ]; then
            _connected=true
            break
          fi
        fi
        sleep 0.5
      done

      if $_connected; then
        say "Tunnel '${name}' is connected and serving https://${hostname}"
      elif pgrep -x cloudflared >/dev/null 2>&1; then
        say "cloudflared is running (connections still establishing)."
        say "  Log: ${cf_log}"
        say "  Attach: tmux attach -t cloudflared"
      else
        err "cloudflared failed to start. Check log: ${cf_log}"
      fi
    else
      say ""
      say "cloudflared is already running."
    fi
  fi
}

main "$@"
