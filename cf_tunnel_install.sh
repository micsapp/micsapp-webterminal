#!/usr/bin/env bash
set -euo pipefail

# cf_tunnel_install.sh
# Standalone installer/configurator for a Cloudflare Tunnel that exposes a local service.
# Supports --web-terminal mode for a full multi-tenant web terminal setup.
# Compatible with macOS + Linux (best-effort). Requires Cloudflare-managed DNS.
#
# NOTE: `cloudflared tunnel login` requires an interactive browser/URL step.

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
      if command -v snap >/dev/null 2>&1; then
        sudo snap install ttyd --classic
      elif command -v apt-get >/dev/null 2>&1; then
        sudo apt-get install -y ttyd 2>/dev/null || {
          say "ttyd not in apt repos. Downloading binary..."
          local arch
          arch="$(uname -m)"
          [ "$arch" = "x86_64" ] && arch="x86_64" || arch="aarch64"
          curl -fsSL "https://github.com/nicm/ttyd/releases/latest/download/ttyd.${arch}" -o /tmp/ttyd
          chmod +x /tmp/ttyd
          sudo mv /tmp/ttyd /usr/local/bin/ttyd
        }
      else
        err "Cannot auto-install ttyd. Install manually: https://github.com/nicm/ttyd"
        return 1
      fi
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

  # --- python3 ---
  if command -v python3 >/dev/null 2>&1; then
    say "python3 already installed: $(python3 --version 2>&1)"
  else
    err "python3 is required but not found. Please install Python 3."
    return 1
  fi

  # --- nginx ---
  if command -v nginx >/dev/null 2>&1; then
    say "nginx already installed: $(nginx -v 2>&1)"
  else
    err "nginx is required but not found. Please install nginx first."
    err "  macOS: brew install nginx"
    err "  Linux: sudo apt-get install nginx"
    return 1
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
    # Linux: enable sshd via systemd
    local sshd_name="sshd"
    if ! systemctl list-unit-files "${sshd_name}.service" >/dev/null 2>&1; then
      sshd_name="ssh"  # Debian/Ubuntu uses 'ssh' not 'sshd'
    fi
    if systemctl is-active --quiet "$sshd_name" 2>/dev/null; then
      say "SSH server ($sshd_name) is already running."
    else
      say "Enabling and starting SSH server ($sshd_name)..."
      sudo systemctl enable --now "$sshd_name"
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

    # Wrapper app page (requires auth)
    location = / {
        auth_request /api/auth;
        error_page 401 = @login_redirect;
        proxy_pass http://127.0.0.1:${auth_port}/app;
    }

    # Per-user ttyd instances (dynamic port from URL path)
    location ~ ^/ut/(\d+)/(.*) {
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
    sudo nginx -t && sudo systemctl reload nginx
  fi
  say "nginx reloaded successfully."
}

deploy_auth_service() {
  local auth_port="$1"

  say ""
  say "=== Deploying auth service ==="

  local auth_dir="$HOME/ttyd-auth"
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

SSHPASS_BIN = (
    os.environ.get("SSHPASS_BIN")
    or shutil.which("sshpass")
    or "/usr/local/bin/sshpass"
)
SSH_BIN = os.environ.get("SSH_BIN") or shutil.which("ssh") or "/usr/bin/ssh"
TTYD_BIN = (
    os.environ.get("TTYD_BIN")
    or shutil.which("ttyd")
    or "/usr/local/bin/ttyd"
)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "SAMEORIGIN",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
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
             f"{username}@127.0.0.1", "echo", "ok"],
            capture_output=True, text=True, timeout=10
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
  .fp-modal-body .fp-modal-audio {
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
  <button class="nav-btn" onclick="quickAdjustFontSize(-1)" title="Decrease Font Size">A-</button>
  <span class="nav-btn nav-hide-mobile quick-font-readout" id="quickFontSizeDisplay">15px</span>
  <button class="nav-btn" onclick="quickAdjustFontSize(1)" title="Increase Font Size">A+</button>
  <button class="nav-btn" onclick="copyFromActiveTerminal('smart')" title="Copy terminal text">&#128203; Copy</button>
  <div class="nav-sep nav-hide-mobile"></div>
  <button class="nav-btn nav-hide-mobile" id="filesBtn" onclick="toggleFilePanel()">&#128193; Files</button>
  <button class="nav-btn nav-hide-mobile" id="settingsBtn" onclick="toggleSettings()">&#9881; Settings</button>
  <button class="nav-btn nav-hide-mobile" id="themeBtn" onclick="toggleThemePanel()">&#9673; Themes</button>
  <button class="nav-btn nav-hide-mobile" onclick="fullscreen()">&#9974; Fullscreen</button>
  <button class="nav-btn nav-hide-mobile" onclick="reconnect()">&#8635; Reconnect</button>
  <button class="hamburger" onclick="toggleHamburger()" aria-label="Menu">&#9776;</button>
  <div class="nav-dropdown" id="navDropdown">
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
    </div>
</div>
</div>
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

function addTab() {
  tabCounter++;
  const id = 'tab-' + tabCounter;
  const iframe = document.createElement('iframe');
  iframe.id = 'frame-' + id;
  iframe.src = buildTermUrl();
  document.getElementById('termContainer').appendChild(iframe);
  tabs.push({ id, name: 'Shell ' + tabCounter });
  switchTab(id);
  renderTabs();
}

function closeTab(id, e) {
  if (e) e.stopPropagation();
  if (tabs.length <= 1) return;
  const idx = tabs.findIndex(t => t.id === id);
  const iframe = document.getElementById('frame-' + id);
  if (iframe) iframe.remove();
  tabs.splice(idx, 1);
  if (activeTabId === id) {
    const newIdx = Math.min(idx, tabs.length - 1);
    switchTab(tabs[newIdx].id);
  }
  renderTabs();
}

function switchTab(id) {
  activeTabId = id;
  document.querySelectorAll('#termContainer iframe').forEach(f => f.classList.remove('active'));
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
  const frames = document.querySelectorAll('#termContainer iframe');
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
  document.querySelectorAll('#termContainer iframe').forEach((f) => {
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
  document.querySelectorAll('#termContainer iframe').forEach(f => { f.src = url; });
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
  // Escape = close preview modal
  if (e.key === 'Escape') {
    closeFileModal();
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

  addTab();

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

function isImageFile(name) {
  return /\\.(png|jpe?g|gif|webp|bmp|svg|ico|avif|heic)$/i.test(name || '');
}

function isVideoFile(name) {
  return /\\.(mp4|webm|ogg|mov|m4v)$/i.test(name || '');
}

function isAudioFile(name) {
  return /\\.(mp3|wav|m4a|aac|flac|ogg|oga|opus)$/i.test(name || '');
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

  pre.style.display = 'none';
  editor.style.display = 'none';
  img.style.display = 'none';
  vid.style.display = 'none';
  aud.style.display = 'none';
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
    alert('Save failed: ' + e.message);
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
    renderFileList(data.entries);
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
  // Parent directory link
  if (fpParentToken) {
    const parent = document.createElement('div');
    parent.className = 'fp-item';
    parent.innerHTML = '<span class="fp-item-icon">&#128193;</span><span class="fp-item-name">..</span>';
    parent.onclick = () => fetchFiles(fpParentToken);
    list.appendChild(parent);
  }
  entries.forEach(e => {
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

  try {
    const res = await fetch('/api/files/read?path_token=' + encodeURIComponent(pathToken));
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    if (data.error) { alert(data.error); return; }
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
    alert('Cannot preview: ' + e.message);
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
        alert('Upload failed: ' + (d.error || res.status));
      }
    } catch (e) {
      alert('Upload error: ' + e.message);
    }
  }
  fetchFiles(fpCurrentPathToken);
}

async function createFolder() {
  const name = prompt('New folder name:');
  if (!name) return;
  try {
    const res = await fetch('/api/files/mkdir', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({path_token: fpCurrentPathToken, name: name}),
    });
    const data = await res.json();
    if (data.error) alert(data.error);
    else fetchFiles(fpCurrentPathToken);
  } catch (e) { alert('Error: ' + e.message); }
}

async function deleteFile(pathToken, name, type) {
  if (!confirm('Delete ' + (type === 'dir' ? 'folder' : 'file') + ' "' + name + '"?')) return;
  try {
    const res = await fetch('/api/files/delete', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({path_token: pathToken}),
    });
    const data = await res.json();
    if (data.error) alert(data.error);
    else fetchFiles(fpCurrentPathToken);
  } catch (e) { alert('Error: ' + e.message); }
}

async function renameFile(pathToken, name) {
  const newName = prompt('Rename "' + name + '" to:', name);
  if (!newName || newName === name) return;
  try {
    const res = await fetch('/api/files/rename', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({path_token: pathToken, new_name: newName}),
    });
    const data = await res.json();
    if (data.error) alert(data.error);
    else fetchFiles(fpCurrentPathToken);
  } catch (e) { alert('Error: ' + e.message); }
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

function formatSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

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
next_port = 7700

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

    port = next_port
    next_port += 1

    ttyd_cmd = f"{shlex.quote(TTYD_BIN)} -W -p {port} bash -l"
    proc = subprocess.Popen(
        [SSHPASS_BIN, "-p", password, SSH_BIN,
         "-o", "StrictHostKeyChecking=no",
         "-o", "PubkeyAuthentication=no",
         "-o", "ServerAliveInterval=30",
         f"{username}@127.0.0.1",
         ttyd_cmd],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    user_instances[username] = {"port": port, "proc": proc, "password": password}
    return port


def get_user_port(username):
    """Get the ttyd port for a user, or None if not running."""
    if username in user_instances:
        info = user_instances[username]
        if info["proc"].poll() is None:
            return info["port"]
        del user_instances[username]
    return None


def make_token(username):
    ts = str(int(time.time()))
    msg = f"{username}:{ts}"
    sig = hmac.new(SECRET_KEY.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return f"{username}:{ts}:{sig}"


def verify_token(token):
    """Verify token and return username if valid, else None."""
    try:
        username, ts, sig = token.split(":")
        expected = hmac.new(SECRET_KEY.encode(), f"{username}:{ts}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        if time.time() - int(ts) > SESSION_MAX_AGE:
            return None
        return username
    except Exception:
        return None


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
            input=python_script.encode(), capture_output=True, timeout=timeout
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

    def end_headers(self):
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        super().end_headers()

    def _get_authenticated_user(self):
        token = get_cookie_token(self.headers)
        return verify_token(token)

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
            self.send_header("Content-Disposition", f'{disp}; filename="{fname}"')
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
            username = verify_token(token)
            port = get_user_port(username) if username else None
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
            if not verify_token(token):
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
            if verify_token(token):
                self.send_response(200)
                self.end_headers()
            else:
                self.send_response(401)
                self.end_headers()
        elif path == "/api/files/list":
            self._handle_files_list(params)
        elif path == "/api/files/read":
            self._handle_files_read(params)
        elif path == "/api/files/download":
            self._handle_files_download(params)
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
                port = spawn_user_ttyd(username, password)
                token = make_token(username)
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
                self.wfile.write(b'{"ok":false}')
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
    log_file="$HOME/ttyd-auth/auth.log"
  fi

  AUTH_PORT="$auth_port" python3 "$HOME/ttyd-auth/auth.py" > "$log_file" 2>&1 &
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
        <string>$HOME/ttyd-auth/auth.py</string>
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
ExecStart=$(command -v python3) $HOME/ttyd-auth/auth.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
SVCEOF

  systemctl --user daemon-reload
  systemctl --user enable --now ttyd-auth.service
  say "Auth service systemd unit installed: ${svc_dir}/ttyd-auth.service"
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
      sudo cloudflared service install
      say "Linux: cloudflared service installed (systemd)."
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
  Auth service:  http://127.0.0.1:${auth_port} (~/ttyd-auth/auth.py)
  nginx config:  ${conf_dir}/${hostname}.conf
  nginx port:    ${nginx_port}
  ttyd ports:    7700+ (per-user, dynamic)
  Login URL:     https://${hostname}
=======================================
EOF
  else
    say "======================================="
  fi
}

main "$@"
