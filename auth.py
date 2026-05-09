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
import struct
import subprocess
import threading
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
  // it sees shiftKey === true on the event.
  //
  // Since tmux "mouse on" activates DECSET mouse tracking, we always fake
  // shiftKey for click/drag events to ensure text selection works in tmux.
  // Hold Alt (Option on Mac) to temporarily bypass and send mouse events
  // to TUI apps (htop, vim, etc.) that need mouse interaction.

  ['mousedown', 'mousemove', 'mouseup', 'click', 'dblclick'].forEach(function (t) {
    document.addEventListener(t, function (e) {
      // Alt+click: let mouse through to terminal app (for TUI interaction)
      // Otherwise: fake shiftKey so xterm.js does native text selection
      if (!e.shiftKey && !e.altKey) {
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
    position: relative;
    min-width: 200px;
    max-width: 80vw;
  }
  .file-panel.open { display: flex; }
  .file-panel.fp-fullscreen {
    position: fixed;
    inset: 0;
    top: 0;
    width: 100% !important;
    max-width: 100vw !important;
    z-index: 150;
    border-right: none;
  }
  .fp-resize-handle {
    position: absolute;
    top: 0;
    right: -3px;
    width: 6px;
    height: 100%;
    cursor: col-resize;
    z-index: 20;
    background: transparent;
  }
  .fp-resize-handle:hover,
  .fp-resize-handle.active {
    background: #1a4a7a;
  }
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
  .fp-recent-wrap { position: relative; display: inline-block; }
  .fp-recent-drop {
    display: none;
    position: absolute;
    top: 100%;
    right: 0;
    margin-top: 4px;
    min-width: 220px;
    max-width: 350px;
    background: #16213e;
    border: 1px solid #1a4a7a;
    border-radius: 6px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.5);
    z-index: 200;
    max-height: 300px;
    overflow-y: auto;
  }
  .fp-recent-drop.open { display: block; }
  .fp-recent-item {
    display: block;
    width: 100%;
    padding: 7px 10px;
    background: none;
    border: none;
    color: #c0c0e0;
    font-size: 12px;
    text-align: left;
    cursor: pointer;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .fp-recent-item:hover { background: #0f3460; color: #fff; }
  .fp-recent-empty {
    padding: 10px;
    color: #666;
    font-size: 12px;
    text-align: center;
  }
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
  .fp-breadcrumbs { cursor: text; }
  .fp-path-input {
    display: none;
    width: 100%;
    box-sizing: border-box;
    padding: 5px 10px;
    font-size: 12px;
    font-family: inherit;
    color: #e2e2e2;
    background: #0a1929;
    border: none;
    border-bottom: 1px solid #1a6aff;
    outline: none;
    flex-shrink: 0;
  }
  .fp-path-input::placeholder { color: #3a3a5a; }
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
    z-index: 200;
    pointer-events: none;
    inset: 0;
  }
  .fp-modal-overlay.open { display: flex; align-items: center; justify-content: center; }
  .fp-modal {
    pointer-events: auto;
    background: #16213e;
    border: 1px solid #0f3460;
    border-radius: 10px;
    width: 700px;
    max-width: 95vw;
    max-height: 95vh;
    min-width: 320px;
    min-height: 200px;
    display: flex;
    flex-direction: column;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
    resize: both;
    overflow: hidden;
    position: relative;
  }
  .fp-modal-overlay.fp-fullscreen .fp-modal {
    width: 100vw !important;
    height: 100vh !important;
    max-width: 100vw;
    max-height: 100vh;
    border-radius: 0;
    resize: none;
  }
  .fp-modal-overlay.fp-dragging .fp-modal,
  .fp-modal-overlay.fp-dragged .fp-modal {
    position: fixed;
  }
  .fp-modal-header {
    display: flex;
    align-items: center;
    padding: 10px 14px;
    border-bottom: 1px solid #0f3460;
    gap: 8px;
    cursor: grab;
    user-select: none;
  }
  .fp-modal-header:active { cursor: grabbing; }
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
  .fp-modal-md-render {
    display: none;
    color: #c9d1d9;
    font-size: 14px;
    line-height: 1.7;
    word-wrap: break-word;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  }
  .fp-modal-md-render h1, .fp-modal-md-render h2, .fp-modal-md-render h3,
  .fp-modal-md-render h4, .fp-modal-md-render h5, .fp-modal-md-render h6 {
    color: #e6edf3; margin: 24px 0 16px 0; font-weight: 600; line-height: 1.25;
  }
  .fp-modal-md-render h1 { font-size: 2em; border-bottom: 1px solid #30363d; padding-bottom: 0.3em; }
  .fp-modal-md-render h2 { font-size: 1.5em; border-bottom: 1px solid #30363d; padding-bottom: 0.3em; }
  .fp-modal-md-render h3 { font-size: 1.25em; }
  .fp-modal-md-render h4 { font-size: 1em; }
  .fp-modal-md-render p { margin: 0 0 16px 0; }
  .fp-modal-md-render ul, .fp-modal-md-render ol { padding-left: 2em; margin: 0 0 16px 0; }
  .fp-modal-md-render li { margin: 4px 0; }
  .fp-modal-md-render li > p { margin: 0; }
  .fp-modal-md-render code {
    background: rgba(110,118,129,0.4); padding: 0.2em 0.4em; border-radius: 6px;
    font-family: 'SFMono-Regular','Menlo','Monaco','Consolas','Liberation Mono',monospace;
    font-size: 85%;
  }
  .fp-modal-md-render pre {
    background: #161b22; border: 1px solid #30363d; border-radius: 6px;
    padding: 16px; overflow-x: auto; margin: 0 0 16px 0; line-height: 1.45;
  }
  .fp-modal-md-render pre code {
    background: none; padding: 0; font-size: 85%; border-radius: 0;
  }
  .fp-modal-md-render blockquote {
    border-left: 4px solid #3b82f6; padding: 0 16px; margin: 0 0 16px 0;
    color: #8b949e;
  }
  .fp-modal-md-render blockquote p { margin: 0; }
  .fp-modal-md-render a { color: #58a6ff; text-decoration: none; }
  .fp-modal-md-render a:hover { text-decoration: underline; }
  .fp-modal-md-render table { border-collapse: collapse; margin: 0 0 16px 0; width: auto; display: block; overflow-x: auto; }
  .fp-modal-md-render th, .fp-modal-md-render td {
    border: 1px solid #30363d; padding: 6px 13px;
  }
  .fp-modal-md-render th { background: #161b22; font-weight: 600; }
  .fp-modal-md-render tr:nth-child(even) td { background: rgba(110,118,129,0.1); }
  .fp-modal-md-render hr { border: none; border-top: 2px solid #30363d; margin: 24px 0; }
  .fp-modal-md-render img { max-width: 100%; border-radius: 6px; }
  .fp-modal-md-render svg { max-width: 100%; height: auto; margin: 8px 0; display: block; }
  .fp-modal-md-render pre.mermaid { background: none; border: none; padding: 0; text-align: center; }
  .fp-modal-md-render pre.mermaid svg { display: inline-block; }
  .fp-modal-md-render strong { color: #e6edf3; font-weight: 600; }
  .fp-modal-md-render em { font-style: italic; }
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
  .fp-modal-body .fp-modal-html {
    display: none;
    width: 100%;
    height: 70vh;
    border-radius: 8px;
    background: #fff;
    border: 1px solid #1a4a7a;
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
      max-width: 100vw !important;
      z-index: 150;
      border-right: none;
    }
    .file-panel .fp-header {
      flex-wrap: wrap;
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
  <button class="nav-btn nav-hide-mobile" onclick="addDesktopTab()">&#128421; Desktop</button>
  <button class="nav-btn nav-hide-mobile" onclick="reconnect()">&#8635; Reconnect</button>
  <button class="nav-btn nav-hide-mobile" onclick="showHelp()">&#10068; Help</button>
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
    <button class="nav-btn" onclick="addDesktopTab();toggleHamburger()">&#128421; Desktop</button>
    <button class="nav-btn" onclick="reconnect();toggleHamburger()">&#8635; Reconnect</button>
    <button class="nav-btn" onclick="showHelp();toggleHamburger()">&#10068; Help</button>
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
  <div style="flex-basis:100%;border-top:1px solid #0f3460;padding-top:14px;margin-top:4px;">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
      <span style="color:#7a7a9e;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;">API Tokens</span>
      <button class="fp-btn" onclick="apiTokenCreate()" style="font-size:12px;padding:3px 8px;">+ New Token</button>
    </div>
    <div id="apiTokenList" style="display:flex;flex-direction:column;gap:6px;max-height:200px;overflow-y:auto;"></div>
  </div>
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
      <button class="fp-btn" onclick="pasteImageFromClipboard()">&#128203; Paste Img</button>
      <button class="fp-btn" onclick="createFolder()">+ Folder</button>
      <button class="fp-btn" onclick="fetchFiles(fpCurrentPathToken)" title="Refresh">&#8635;</button>
      <button class="fp-btn" id="fpFullscreenBtn" onclick="toggleFilePanelFullscreen()" title="Fullscreen">&#x26F6;</button>
      <button class="fp-btn" onclick="toggleFilePanel()">&#10005;</button>
    </div>
    <div style="display:flex;align-items:center;gap:0;">
      <div class="fp-breadcrumbs" id="fpBreadcrumbs" ondblclick="startPathEdit()" style="flex:1;min-width:0;"></div>
      <div class="fp-recent-wrap" style="flex-shrink:0;padding-right:6px;">
        <button class="fp-btn" id="fpRecentBtn" onclick="toggleRecentFolders()" title="Recent folders" style="font-size:11px;padding:2px 6px;">&#128338;</button>
        <div class="fp-recent-drop" id="fpRecentDrop"></div>
      </div>
    </div>
    <input type="text" class="fp-path-input" id="fpPathInput" style="display:none"
      onkeydown="if(event.key==='Enter'){commitPathEdit();}else if(event.key==='Escape'){cancelPathEdit();}"
      onblur="cancelPathEdit()"
      spellcheck="false" autocomplete="off" placeholder="Type path and press Enter">
    <div class="fp-sort-bar" id="fpSortBar"></div>
    <div class="fp-list" id="fpList"></div>
    <input type="file" id="fpUploadInput" multiple style="display:none" onchange="handleUpload(this.files);this.value='';">
    <div class="fp-drop-overlay">Drop files to upload</div>
    <div class="fp-resize-handle" id="fpResizeHandle"></div>
  </div>
  <div class="term-container" id="termContainer"></div>
</div>

<!-- file preview modals are created dynamically by JS -->
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

<div class="fp-modal-overlay" id="helpModal">
  <div class="fp-modal" style="max-width:860px;height:90vh;max-height:90vh">
    <div class="fp-modal-header">
      <span class="fp-modal-title">&#10068; Help &mdash; User Manual</span>
      <button class="fp-btn" onclick="closeHelp()">&#10005;</button>
    </div>
    <div class="fp-modal-body" style="overflow-y:auto">
      <div id="helpContent" class="fp-modal-md-render" style="display:block"></div>
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
let nextWindowSlot = 0;

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
      // Trigger lazy-load if this pane's iframe was never visited.
      if (f.dataset.lazySrc && (!f.src || f.src === 'about:blank' || f.src.endsWith('/blank'))) {
        f.src = f.dataset.lazySrc;
        delete f.dataset.lazySrc;
      }
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

function buildTermUrl(tab, overrides) {
  const s = getSettings();
  if (overrides && typeof overrides === 'object') {
    Object.assign(s, overrides);
  }
  const params = new URLSearchParams();
  const slot = tab && Number.isInteger(tab.windowSlot) ? tab.windowSlot : 0;
  // Include active slots list only when explicitly provided (page restore / reconnect).
  // Single-tab additions skip cleanup to avoid races.
  const arg = s._activeSlots ? slot + ':' + s._activeSlots : String(slot);
  params.append('arg', arg);
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
  try { localStorage.setItem('ttyd_tabs', JSON.stringify(tabs.map(t => ({ name: t.name, windowSlot: t.windowSlot, type: t.type || 'shell', wsPort: t.wsPort })))); } catch(e) {}
}

function nextTabWindowSlot() {
  const slot = nextWindowSlot;
  nextWindowSlot += 1;
  return slot;
}

function addTab() {
  tabCounter++;
  const id = 'tab-' + tabCounter;
  const tab = { id, name: 'Shell ' + tabCounter, windowSlot: nextTabWindowSlot() };
  tabs.push(tab);
  const iframe = document.createElement('iframe');
  iframe.id = 'frame-' + id;
  iframe.allow = 'clipboard-read; clipboard-write';
  iframe.src = buildTermUrl(tab);
  document.getElementById('termContainer').appendChild(iframe);
  if (!isSplitActive()) {
    switchTab(id);
  }
  renderTabs();
  saveTabs();
}

function addDesktopTab() {
  // If a desktop tab already exists, just switch to it
  const existing = tabs.find(t => t.type === 'desktop');
  if (existing) {
    switchTab(existing.id);
    return;
  }
  tabCounter++;
  const id = 'tab-' + tabCounter;
  const tab = { id, name: 'Desktop', type: 'desktop' };
  tabs.push(tab);
  const iframe = document.createElement('iframe');
  iframe.id = 'frame-' + id;
  iframe.allow = 'clipboard-read; clipboard-write';
  iframe.src = '/noVNC/vnc.html?autoconnect=true&resize=scale&reconnect=true&reconnect_delay=1000&path=noVNC/websockify';
  document.getElementById('termContainer').appendChild(iframe);
  switchTab(id);
  renderTabs();
  saveTabs();
  showToast('Desktop ready');
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
  if (frame) {
    // Lazy-load: if iframe hasn't loaded its real URL yet, load it now
    if (frame.dataset.lazySrc && (!frame.src || frame.src === 'about:blank' || frame.src.endsWith('/blank'))) {
      frame.src = frame.dataset.lazySrc;
      delete frame.dataset.lazySrc;
    }
    frame.classList.add('active');
  }
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
  if (opts.html) bodyEl.innerHTML = opts.message || '';
  else bodyEl.textContent = opts.message || '';

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
  const activeSlots = tabs.map(t => t.windowSlot).join(',');
  getAllIframes().forEach((f) => {
    const tabId = f.id.replace('frame-', '');
    const tab = tabs.find(t => t.id === tabId);
    suppressLeaveAlertInFrame(f);
    f.src = buildTermUrl(tab, { disableLeaveAlert: true, _activeSlots: activeSlots });
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
  getAllIframes().forEach(f => {
    const tabId = f.id.replace('frame-', '');
    const tab = tabs.find(t => t.id === tabId);
    f.src = buildTermUrl(tab);
  });
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
  if (open) apiTokenLoad();
}

// --- API Token management ---
function _escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function apiTokenLoad() {
  const list = document.getElementById('apiTokenList');
  if (!list) return;
  list.innerHTML = '<span style="color:#7a7a9e;font-size:12px;">Loading…</span>';
  try {
    const r = await fetch('/api/tokens');
    if (!r.ok) { list.innerHTML = '<span style="color:#7a7a9e;font-size:12px;">Failed to load tokens.</span>'; return; }
    const data = await r.json();
    const tokens = data.tokens || [];
    if (tokens.length === 0) {
      list.innerHTML = '<span style="color:#7a7a9e;font-size:12px;">No tokens yet. Create one to enable scripted API access.</span>';
      return;
    }
    list.innerHTML = tokens.map(t => {
      const created = new Date(t.created_at * 1000).toLocaleDateString();
      const used = t.last_used ? new Date(t.last_used * 1000).toLocaleDateString() : 'never';
      return `<div style="display:flex;align-items:center;gap:8px;background:#0f3460;border-radius:6px;padding:6px 10px;">
        <span style="flex:1;font-size:13px;color:#e2e2e2;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${_escHtml(t.name)}</span>
        <span style="font-size:11px;color:#7a7a9e;flex-shrink:0;">created ${_escHtml(created)}</span>
        <span style="font-size:11px;color:#7a7a9e;flex-shrink:0;">used ${_escHtml(used)}</span>
        <button class="fp-btn" style="font-size:11px;padding:2px 7px;color:#e94560;flex-shrink:0;" onclick="apiTokenRevoke(${JSON.stringify(t.name)})">Revoke</button>
      </div>`;
    }).join('');
  } catch(e) {
    list.innerHTML = '<span style="color:#7a7a9e;font-size:12px;">Error loading tokens.</span>';
  }
}

async function apiTokenCreate() {
  const name = await modalPrompt('Token name (e.g. "ci-bot", "laptop"):', 'New API Token');
  if (!name || !name.trim()) return;
  try {
    const r = await fetch('/api/tokens', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({name: name.trim()})
    });
    const data = await r.json();
    if (!r.ok) { await modalAlert(data.error || 'Failed to create token', 'Error'); return; }
    const token = data.token;
    const origin = window.location.origin;
    const curlEx = `curl -H "Authorization: Bearer ${token}" ${origin}/api/files/list`;
    await dlgOpen({
      kind: 'alert',
      title: 'New API Token: ' + name.trim(),
      html: true,
      message:
        '<b style="color:#e94560;">Copy this token now — it won\\\'t be shown again.</b><br><br>' +
        '<label style="color:#7a7a9e;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;">Token</label><br>' +
        `<textarea style="width:100%;height:56px;background:#0a1628;border:1px solid #0f3460;color:#e2e2e2;font-family:monospace;font-size:11px;padding:6px;border-radius:6px;resize:vertical;margin-top:4px;" onclick="this.select()" readonly>${_escHtml(token)}</textarea><br><br>` +
        '<label style="color:#7a7a9e;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;">Example curl</label><br>' +
        `<textarea style="width:100%;height:44px;background:#0a1628;border:1px solid #0f3460;color:#e2e2e2;font-family:monospace;font-size:11px;padding:6px;border-radius:6px;resize:vertical;margin-top:4px;" onclick="this.select()" readonly>${_escHtml(curlEx)}</textarea>`
    });
    apiTokenLoad();
  } catch(e) {
    await modalAlert('Error creating token: ' + e.message, 'Error');
  }
}

async function apiTokenRevoke(name) {
  const ok = await modalConfirm(`Revoke token "${name}"? This cannot be undone.`, 'Revoke Token', true);
  if (!ok) return;
  try {
    const r = await fetch('/api/tokens/revoke', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({name})
    });
    if (!r.ok) {
      const data = await r.json();
      await modalAlert(data.error || 'Failed to revoke token', 'Error');
      return;
    }
    apiTokenLoad();
  } catch(e) {
    await modalAlert('Error: ' + e.message, 'Error');
  }
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
  if (f) {
    const tab = tabs.find(t => t.id === activeTabId);
    f.src = buildTermUrl(tab);
  }
}

function logout() {
  document.cookie = '__COOKIE_NAME__=; Path=/; Max-Age=0';
  localStorage.removeItem('ttyd_settings');
  window.location.href = '/login';
}

// Help manual
let helpLoaded = false;
function showHelp() {
  const modal = document.getElementById('helpModal');
  modal.classList.add('open');
  if (!helpLoaded) {
    fetch('/api/help').then(r => r.text()).then(md => {
      var hc = document.getElementById('helpContent');
      hc.innerHTML = renderMarkdown(md);
      // Rewrite relative image paths to absolute /api/help/images/
      hc.querySelectorAll('img').forEach(img => {
        const src = img.getAttribute('src');
        if (src && !src.startsWith('http') && !src.startsWith('/')) {
          img.src = '/api/help/' + src;
        }
      });
      renderMermaidIn(hc);
      helpLoaded = true;
    }).catch(() => {
      document.getElementById('helpContent').innerHTML = '<p style="color:#e94560">Failed to load manual.</p>';
    });
  }
}
function closeHelp() {
  document.getElementById('helpModal').classList.remove('open');
}
document.getElementById('helpModal').addEventListener('click', (e) => {
  if (e.target.id === 'helpModal') closeHelp();
});

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

// Clipboard image paste handler
document.addEventListener('paste', async (e) => {
  if (!e.clipboardData || !e.clipboardData.items) return;
  const active = document.activeElement;
  if (active && (active.tagName === 'INPUT' || active.tagName === 'TEXTAREA' || active.isContentEditable)) return;
  const imageBlobs = [];
  for (const item of e.clipboardData.items) {
    if (item.kind === 'file' && item.type.startsWith('image/')) {
      const blob = item.getAsFile();
      if (blob) imageBlobs.push({ blob, type: item.type });
    }
  }
  if (!imageBlobs.length) return;
  e.preventDefault();
  await _promptAndUploadClipboardImages(imageBlobs);
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
    saved.forEach((t, idx) => {
      tabCounter++;
      const slot = Number.isInteger(t.windowSlot) && t.windowSlot >= 0 ? t.windowSlot : idx;
      nextWindowSlot = Math.max(nextWindowSlot, slot + 1);
      const tabObj = { id: 'tab-' + tabCounter, name: t.name || ('Shell ' + tabCounter), windowSlot: slot };
      if (t.type === 'desktop') { tabObj.type = 'desktop'; }
      tabs.push(tabObj);
    });
    renderTabs();
    switchTab(tabs[0].id);
    // Clear stale split state — tab IDs are regenerated on reload so
    // the saved split tree references are no longer reliable.
    localStorage.removeItem('ttyd_split');
    // Load all iframes eagerly with a small stagger so each tab's tmux
    // window is created at startup. Lazy-loading inactive tabs left their
    // tmux slots unspawned, so the status bar showed fewer windows than
    // browser tabs and split panes rendered empty when the second pane
    // had never been visited.
    const activeSlots = tabs.filter(t => t.type !== 'desktop').map(t => t.windowSlot).join(',');
    tabs.forEach((t, i) => {
      const isActive = (t.id === activeTabId);
      setTimeout(() => {
        const iframe = document.createElement('iframe');
        iframe.id = 'frame-' + t.id;
        iframe.allow = 'clipboard-read; clipboard-write';
        let url;
        if (t.type === 'desktop') {
          url = '/noVNC/vnc.html?autoconnect=true&resize=scale&reconnect=true&reconnect_delay=1000&path=noVNC/websockify';
        } else {
          url = buildTermUrl(t, { _activeSlots: activeSlots });
        }
        iframe.src = url;
        if (isActive) iframe.classList.add('active');
        document.getElementById('termContainer').appendChild(iframe);
      }, isActive ? 0 : i * 300);
    });
    updateSplitButtons();
  } else {
    addTab();
    updateSplitButtons();
  }

  // Restore file panel open state
  if (localStorage.getItem('ttyd_fp_open') === '1') {
    const panel = document.getElementById('filePanel');
    panel.classList.add('open');
    document.getElementById('filesBtn').classList.add('active');
    if (localStorage.getItem('ttyd_fp_fullscreen') === '1') {
      panel.classList.add('fp-fullscreen');
      document.getElementById('fpFullscreenBtn').innerHTML = '&#x2716;';
      document.getElementById('fpFullscreenBtn').title = 'Exit fullscreen';
    }
    const savedToken = localStorage.getItem('ttyd_fp_last_token') || '';
    fetchFiles(savedToken);
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
// Multi-window file modal system
let _fmNextId = 0;
let _fmTopZ = 200;
const _fmModals = new Map();
function _fmEl(st, sel) { return st.el.querySelector(sel); }
let fpSortBy = localStorage.getItem('ttyd_fp_sort_by') || 'name';
let fpSortAsc = localStorage.getItem('ttyd_fp_sort_asc') !== '0';
let fpCurrentEntries = [];
const FP_RECENT_MAX = 10;

function fpGetRecentFolders() {
  try { return JSON.parse(localStorage.getItem('ttyd_fp_recent') || '[]'); } catch(e) { return []; }
}
function fpAddRecentFolder(path, token) {
  if (!path || !token) return;
  let recent = fpGetRecentFolders();
  recent = recent.filter(r => r.path !== path);
  recent.unshift({ path: path, token: token });
  if (recent.length > FP_RECENT_MAX) recent = recent.slice(0, FP_RECENT_MAX);
  localStorage.setItem('ttyd_fp_recent', JSON.stringify(recent));
}
function toggleRecentFolders() {
  const drop = document.getElementById('fpRecentDrop');
  const isOpen = drop.classList.toggle('open');
  if (isOpen) {
    const recent = fpGetRecentFolders();
    if (recent.length === 0) {
      drop.innerHTML = '<div class="fp-recent-empty">No recent folders</div>';
    } else {
      drop.innerHTML = '';
      recent.forEach(r => {
        const btn = document.createElement('button');
        btn.className = 'fp-recent-item';
        btn.textContent = r.path;
        btn.title = r.path;
        btn.onclick = () => { drop.classList.remove('open'); fetchFiles(null, r.path); };
        drop.appendChild(btn);
      });
    }
    // Close on outside click
    setTimeout(() => {
      const closer = (e) => {
        if (!drop.contains(e.target) && e.target.id !== 'fpRecentBtn') {
          drop.classList.remove('open');
          document.removeEventListener('click', closer);
        }
      };
      document.addEventListener('click', closer);
    }, 0);
  }
}

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

function isMdFile(name) {
  return /\\.(md|markdown|mkd|mdx)$/i.test(name || '');
}

function isHtmlFile(name) {
  return /\\.(html?|xhtml)$/i.test(name || '');
}

function renderMarkdown(src, imgBaseUrl) {
  var placeholders = [];
  function ph(content) {
    placeholders.push(content);
    return '\\x00PH' + (placeholders.length - 1) + '\\x00';
  }
  var h = src.replace(/\\r\\n/g, '\\n').replace(/\\r/g, '\\n');
  // 1. Extract raw HTML/SVG blocks (opening tag at line start, closing tag at line start)
  h = h.replace(/^(<(?:svg|div|details|figure|picture|section)(?:\\s[^>]*)?>(?:[\\s\\S]*?)\\n<\\/(?:svg|div|details|figure|picture|section)>)/gm, function(m) {
    return ph(m);
  });
  // 2a. Mermaid code blocks (render as diagrams, before general fenced blocks)
  h = h.replace(/^`{3,}[ \\t]*mermaid[ \\t]*\\n([\\s\\S]*?)\\n[ \\t]*`{3,}[ \\t]*$/gm, function(m, code) {
    return ph('<pre class="mermaid">' + code.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</pre>');
  });
  // 2. Fenced code blocks (before escaping)
  h = h.replace(/^`{3,}(\\w*)[ \\t]*\\n([\\s\\S]*?)\\n[ \\t]*`{3,}[ \\t]*$/gm, function(m, lang, code) {
    var escaped = code.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    return ph('<pre><code class="language-' + (lang||'') + '">' + escaped + '</code></pre>');
  });
  // 3. Inline code (before escaping so backtick content is protected)
  h = h.replace(/`([^`\\n]+)`/g, function(m, code) {
    var escaped = code.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    return ph('<code>' + escaped + '</code>');
  });
  // 4. Escape remaining HTML
  h = h.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  // 5. Tables (must be before lists/hr to avoid conflicts with | and ---)
  h = h.replace(/^(\\|.+\\|)\\n(\\|[\\s:|-]+\\|)\\n((\\|.+\\|(?:\\n|$))*)/gm, function(m, hdr, sep, body) {
    var cols = hdr.split('|').slice(1, -1);
    var aligns = sep.split('|').slice(1, -1).map(function(c) {
      c = c.trim();
      if (c.startsWith(':') && c.endsWith(':')) return 'center';
      if (c.endsWith(':')) return 'right';
      return 'left';
    });
    var t = '<table><thead><tr>';
    cols.forEach(function(c, i) {
      t += '<th align="' + (aligns[i]||'left') + '">' + c.trim() + '</th>';
    });
    t += '</tr></thead><tbody>';
    var rows = body.trim().split('\\n');
    rows.forEach(function(row) {
      if (!row.trim()) return;
      var cells = row.split('|').slice(1, -1);
      t += '<tr>';
      cells.forEach(function(c, i) {
        t += '<td align="' + (aligns[i]||'left') + '">' + c.trim() + '</td>';
      });
      t += '</tr>';
    });
    t += '</tbody></table>';
    return ph(t);
  });
  // 6. Blockquotes (consecutive lines)
  h = h.replace(/(^&gt; .+$\\n?)+/gm, function(block) {
    var lines = block.replace(/^&gt; /gm, '').trim();
    return ph('<blockquote><p>' + lines.replace(/\\n/g, '<br>') + '</p></blockquote>');
  });
  // 7. Headings
  h = h.replace(/^###### (.+)$/gm, function(m,t){ return ph('<h6>'+t+'</h6>'); });
  h = h.replace(/^##### (.+)$/gm, function(m,t){ return ph('<h5>'+t+'</h5>'); });
  h = h.replace(/^#### (.+)$/gm, function(m,t){ return ph('<h4>'+t+'</h4>'); });
  h = h.replace(/^### (.+)$/gm, function(m,t){ return ph('<h3>'+t+'</h3>'); });
  h = h.replace(/^## (.+)$/gm, function(m,t){ return ph('<h2>'+t+'</h2>'); });
  h = h.replace(/^# (.+)$/gm, function(m,t){ return ph('<h1>'+t+'</h1>'); });
  // 8. Horizontal rules (only standalone lines of 3+ dashes/stars/underscores)
  h = h.replace(/^[ \\t]*[-]{3,}[ \\t]*$/gm, function(m){ return ph('<hr>'); });
  h = h.replace(/^[ \\t]*[*]{3,}[ \\t]*$/gm, function(m){ return ph('<hr>'); });
  h = h.replace(/^[ \\t]*[_]{3,}[ \\t]*$/gm, function(m){ return ph('<hr>'); });
  // 9. Images (resolve relative paths via file API when imgBaseUrl provided)
  h = h.replace(/!\\[([^\\]]*)\\]\\(([^)]+)\\)/g, function(m, alt, src) {
    if (imgBaseUrl && !/^(?:https?:\\/\\/|data:|\\/)/.test(src)) {
      src = imgBaseUrl + encodeURIComponent(src);
    }
    return '<img src="' + src + '" alt="' + alt + '">';
  });
  // 10. Links
  h = h.replace(/\\[([^\\]]+)\\]\\(([^)]+)\\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
  // 11. Bold + italic (order matters)
  h = h.replace(/\\*\\*\\*(.+?)\\*\\*\\*/g, '<strong><em>$1</em></strong>');
  h = h.replace(/\\*\\*(.+?)\\*\\*/g, '<strong>$1</strong>');
  h = h.replace(/(?<![\\w*])\\*([^*\\n]+)\\*(?![\\w*])/g, '<em>$1</em>');
  h = h.replace(/&amp;mdash;/g, '\\u2014');
  h = h.replace(/&amp;rarr;/g, '\\u2192');
  h = h.replace(/&amp;bull;/g, '\\u2022');
  // 12. Checkboxes
  h = h.replace(/\\[x\\]/gi, '&#9745;').replace(/\\[ \\]/g, '&#9744;');
  // 13. Unordered lists (consecutive lines starting with - or * or +, not HR)
  h = h.replace(/(^[ \\t]*[-*+] .+(?:\\n|$))+/gm, function(block) {
    var items = block.trim().split('\\n').map(function(l) {
      return '<li>' + l.replace(/^[ \\t]*[-*+] /, '') + '</li>';
    }).join('\\n');
    return ph('<ul>' + items + '</ul>');
  });
  // 14. Ordered lists
  h = h.replace(/(^[ \\t]*\\d+\\. .+(?:\\n|$))+/gm, function(block) {
    var items = block.trim().split('\\n').map(function(l) {
      return '<li>' + l.replace(/^[ \\t]*\\d+\\. /, '') + '</li>';
    }).join('\\n');
    return ph('<ol>' + items + '</ol>');
  });
  // 15. Paragraphs: group consecutive non-empty, non-block lines
  var lines = h.split('\\n');
  var out = [], para = [];
  function flushPara() {
    if (para.length) {
      out.push('<p>' + para.join('<br>') + '</p>');
      para = [];
    }
  }
  for (var i = 0; i < lines.length; i++) {
    var ln = lines[i];
    if (ln.indexOf('\\x00PH') !== -1 || ln.match(/^\\s*$/)) {
      flushPara();
      out.push(ln);
    } else {
      para.push(ln);
    }
  }
  flushPara();
  h = out.join('\\n');
  // 16. Restore all placeholders (repeat to handle nested placeholders)
  for (var pass = 0; pass < 3; pass++) {
    var changed = false;
    for (var j = 0; j < placeholders.length; j++) {
      var marker = '\\x00PH' + j + '\\x00';
      if (h.indexOf(marker) !== -1) {
        h = h.split(marker).join(placeholders[j]);
        changed = true;
      }
    }
    if (!changed) break;
  }
  // Clean up empty paragraphs
  h = h.replace(/<p>\\s*<\\/p>/g, '');
  return h;
}

function _mdImgBase() {
  return fpCurrentPathToken
    ? '/api/files/download?inline=1&dir_token=' + encodeURIComponent(fpCurrentPathToken) + '&rel='
    : '';
}

var _mermaidMod = null, _mermaidLoading = false;
function renderMermaidIn(container) {
  var els = container.querySelectorAll('pre.mermaid:not([data-processed])');
  if (!els.length) return;
  function doRender() {
    var targets = container.querySelectorAll('pre.mermaid:not([data-processed])');
    if (!targets.length) return;
    _mermaidMod.run({nodes: targets, suppressErrors: true});
  }
  if (_mermaidMod) { doRender(); return; }
  if (_mermaidLoading) { var iv = setInterval(function() { if (_mermaidMod) { clearInterval(iv); doRender(); } }, 200); return; }
  _mermaidLoading = true;
  import('https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs').then(function(mod) {
    _mermaidMod = mod.default;
    _mermaidMod.initialize({startOnLoad: false, theme: 'dark', securityLevel: 'loose'});
    doRender();
  }).catch(function(e) { console.error('Mermaid load failed:', e); _mermaidLoading = false; });
}

function getInlinePreviewUrl(pathToken) {
  return '/api/files/download?inline=1&path_token=' + encodeURIComponent(pathToken);
}

// --- Multi-window file modal: create / close / helpers ---
function _fmCreate(name) {
  const id = ++_fmNextId;
  const z = ++_fmTopZ;
  const cascade = ((id - 1) % 8) * 25;
  const overlay = document.createElement('div');
  overlay.className = 'fp-modal-overlay open';
  overlay.style.zIndex = z;
  overlay.innerHTML =
    '<div class="fp-modal" style="transform:translate(' + cascade + 'px,' + cascade + 'px)">' +
      '<div class="fp-modal-header">' +
        '<span class="fp-modal-title"></span>' +
        '<button class="fp-btn fp-btn-html-toggle" style="display:none">&#9654; Render</button>' +
        '<button class="fp-btn fp-btn-md-toggle" style="display:none">&#60;/&#62; Source</button>' +
        '<button class="fp-btn fp-btn-edit" style="display:none">&#9998; Edit</button>' +
        '<button class="fp-btn fp-btn-save" style="display:none">&#10003; Save</button>' +
        '<button class="fp-btn fp-btn-download">&#8595; Download</button>' +
        '<button class="fp-btn fp-btn-fullscreen" title="Toggle fullscreen">&#x26F6;</button>' +
        '<button class="fp-btn fp-btn-close">&#10005;</button>' +
      '</div>' +
      '<div class="fp-modal-body">' +
        '<div class="fp-modal-note"></div>' +
        '<pre></pre>' +
        '<div class="fp-modal-md-render"></div>' +
        '<textarea spellcheck="false"></textarea>' +
        '<img class="fp-modal-image" alt="Image preview">' +
        '<video class="fp-modal-video" controls preload="metadata"></video>' +
        '<audio class="fp-modal-audio" controls preload="metadata"></audio>' +
        '<iframe class="fp-modal-pdf" title="PDF preview"></iframe>' +
        '<iframe class="fp-modal-html" title="HTML preview"></iframe>' +
      '</div>' +
    '</div>';

  const st = {
    id: id, el: overlay, path: '', text: '', isText: false, editing: false,
    kind: 'binary', encoding: 'utf-8', mdRendered: false, htmlRendered: false
  };
  _fmModals.set(id, st);
  document.body.appendChild(overlay);

  // Bring to front on click (attach to .fp-modal since overlay is pointer-events:none)
  _fmEl(st, '.fp-modal').addEventListener('pointerdown', function() { overlay.style.zIndex = ++_fmTopZ; });

  // Wire buttons
  _fmEl(st, '.fp-btn-close').onclick = function() { _fmClose(id); };
  _fmEl(st, '.fp-btn-fullscreen').onclick = function() { _fmToggleFullscreen(st); };
  _fmEl(st, '.fp-btn-md-toggle').onclick = function() { _fmToggleMd(st); };
  _fmEl(st, '.fp-btn-html-toggle').onclick = function() { _fmToggleHtml(st); };
  _fmEl(st, '.fp-modal-title').textContent = name || '';

  // Per-modal drag
  _fmInitDrag(st);
  return st;
}

function _fmClose(id) {
  const st = _fmModals.get(id);
  if (!st) return;
  const vid = _fmEl(st, '.fp-modal-video');
  const aud = _fmEl(st, '.fp-modal-audio');
  const htmlIf = _fmEl(st, '.fp-modal-html');
  _fmEl(st, '.fp-modal-image').src = '';
  vid.pause(); vid.removeAttribute('src'); vid.load();
  aud.pause(); aud.removeAttribute('src'); aud.load();
  _fmEl(st, '.fp-modal-pdf').removeAttribute('src');
  htmlIf.src = 'about:blank';
  if (st._dragAbort) st._dragAbort.abort();
  if (st._dragRo) st._dragRo.disconnect();
  st.el.remove();
  _fmModals.delete(id);
}

function _fmCloseTop() {
  let topId = null, topZ = -1;
  for (const [id, st] of _fmModals) {
    const z = parseInt(st.el.style.zIndex) || 0;
    if (z > topZ) { topZ = z; topId = id; }
  }
  if (topId !== null) _fmClose(topId);
}

// Legacy wrappers (Escape key calls closeFileModal)
function closeFileModal() { _fmCloseTop(); }

function _fmToggleFullscreen(st) {
  const overlay = st.el;
  const modal = _fmEl(st, '.fp-modal');
  const btn = _fmEl(st, '.fp-btn-fullscreen');
  overlay.classList.toggle('fp-fullscreen');
  overlay.classList.remove('fp-dragged');
  modal.style.left = ''; modal.style.top = ''; modal.style.transform = '';
  btn.innerHTML = overlay.classList.contains('fp-fullscreen') ? '&#x2750;' : '&#x26F6;';
}

function _fmToggleMd(st) {
  st.mdRendered = !st.mdRendered;
  var btn = _fmEl(st, '.fp-btn-md-toggle');
  btn.innerHTML = st.mdRendered ? '&#60;/&#62; Source' : '&#128196; Rendered';
  var pre = _fmEl(st, '.fp-modal-body pre');
  var md = _fmEl(st, '.fp-modal-md-render');
  if (st.mdRendered) {
    md.innerHTML = renderMarkdown(st.text, _mdImgBase());
    renderMermaidIn(md);
    md.style.display = 'block';
    pre.style.display = 'none';
  } else {
    md.style.display = 'none';
    pre.style.display = 'block';
  }
}

function _fmToggleHtml(st) {
  st.htmlRendered = !st.htmlRendered;
  var btn = _fmEl(st, '.fp-btn-html-toggle');
  btn.innerHTML = st.htmlRendered ? '&#60;/&#62; Source' : '&#9654; Render';
  var pre = _fmEl(st, '.fp-modal-body pre');
  var htmlIframe = _fmEl(st, '.fp-modal-html');
  if (st.htmlRendered) {
    htmlIframe.src = getInlinePreviewUrl(st.path);
    htmlIframe.style.display = 'block';
    pre.style.display = 'none';
  } else {
    htmlIframe.style.display = 'none';
    htmlIframe.src = 'about:blank';
    pre.style.display = 'block';
  }
}

function _fmInitDrag(st) {
  let dragging = false, startX = 0, startY = 0, origX = 0, origY = 0;
  const ac = new AbortController();
  st._dragAbort = ac;
  const overlay = st.el;
  const header = _fmEl(st, '.fp-modal-header');
  const modal = _fmEl(st, '.fp-modal');

  function endDrag() {
    if (!dragging) return;
    dragging = false;
    header.style.cursor = 'grab';
    overlay.classList.remove('fp-dragging');
    if (modal.style.left || modal.style.top) overlay.classList.add('fp-dragged');
  }
  header.addEventListener('pointerdown', function(e) {
    if (e.target.tagName === 'BUTTON') return;
    if (overlay.classList.contains('fp-fullscreen')) return;
    e.preventDefault();
    dragging = true;
    header.style.cursor = 'grabbing';
    overlay.classList.add('fp-dragging');
    modal.style.transform = '';
    var rect = modal.getBoundingClientRect();
    startX = e.clientX; startY = e.clientY;
    origX = rect.left; origY = rect.top;
  });
  document.addEventListener('pointermove', function(e) {
    if (!dragging) return;
    var dx = e.clientX - startX, dy = e.clientY - startY;
    modal.style.left = (origX + dx) + 'px';
    modal.style.top = (origY + dy) + 'px';
  }, { signal: ac.signal });
  document.addEventListener('pointerup', endDrag, { signal: ac.signal });
  document.addEventListener('pointercancel', endDrag, { signal: ac.signal });
  window.addEventListener('blur', endDrag, { signal: ac.signal });
  if (typeof ResizeObserver !== 'undefined') {
    var ro = new ResizeObserver(function() { if (!dragging) header.style.cursor = 'grab'; });
    ro.observe(modal);
    st._dragRo = ro;
  }
}

function _fmSetEditing(st, editing) {
  st.editing = !!editing;
  var pre = _fmEl(st, '.fp-modal-body pre');
  var editor = _fmEl(st, '.fp-modal-body textarea');
  var editBtn = _fmEl(st, '.fp-btn-edit');
  var saveBtn = _fmEl(st, '.fp-btn-save');
  var note = _fmEl(st, '.fp-modal-note');
  var img = _fmEl(st, '.fp-modal-image');
  var vid = _fmEl(st, '.fp-modal-video');
  var aud = _fmEl(st, '.fp-modal-audio');
  var pdf = _fmEl(st, '.fp-modal-pdf');
  var mdRender = _fmEl(st, '.fp-modal-md-render');
  var mdToggle = _fmEl(st, '.fp-btn-md-toggle');
  var htmlIframe = _fmEl(st, '.fp-modal-html');
  var htmlToggle = _fmEl(st, '.fp-btn-html-toggle');

  pre.style.display = 'none';
  editor.style.display = 'none';
  img.style.display = 'none';
  vid.style.display = 'none';
  aud.style.display = 'none';
  pdf.style.display = 'none';
  htmlIframe.style.display = 'none';
  mdRender.style.display = 'none';
  editBtn.style.display = 'none';
  saveBtn.style.display = 'none';
  note.style.display = 'none';
  mdToggle.style.display = 'none';
  htmlToggle.style.display = 'none';

  if (st.kind === 'text') {
    var fname = _fmEl(st, '.fp-modal-title').textContent;
    var isMd = isMdFile(fname);
    var isHtml = isHtmlFile(fname);
    editBtn.style.display = 'inline-block';
    editBtn.innerHTML = st.editing ? '&#10005; Cancel' : '&#9998; Edit';
    saveBtn.style.display = st.editing ? 'inline-block' : 'none';
    if (st.editing) {
      editor.style.display = 'block';
    } else if (isHtml) {
      htmlToggle.style.display = 'inline-block';
      htmlToggle.innerHTML = st.htmlRendered ? '&#60;/&#62; Source' : '&#9654; Render';
      if (st.htmlRendered) {
        htmlIframe.src = getInlinePreviewUrl(st.path);
        htmlIframe.style.display = 'block';
      } else {
        pre.style.display = 'block';
      }
    } else if (isMd) {
      mdToggle.style.display = 'inline-block';
      mdToggle.innerHTML = st.mdRendered ? '&#60;/&#62; Source' : '&#128196; Rendered';
      if (st.mdRendered) {
        mdRender.innerHTML = renderMarkdown(st.text, _mdImgBase());
        renderMermaidIn(mdRender);
        mdRender.style.display = 'block';
      } else {
        pre.style.display = 'block';
      }
    } else {
      pre.style.display = 'block';
    }
    if (st.encoding !== 'utf-8') note.style.display = 'block';
    return;
  }
  if (st.kind === 'image') { img.style.display = 'block'; return; }
  if (st.kind === 'video') { vid.style.display = 'block'; return; }
  if (st.kind === 'audio') { aud.style.display = 'block'; return; }
  if (st.kind === 'pdf') { pdf.style.display = 'block'; return; }
  note.style.display = 'block';
}

function _fmStartEdit(st) {
  if (!st.isText) return;
  _fmEl(st, '.fp-modal-body textarea').value = st.text;
  _fmSetEditing(st, true);
}

async function _fmSave(st) {
  if (!st.isText || !st.path) return;
  var editor = _fmEl(st, '.fp-modal-body textarea');
  var newContent = editor.value;
  try {
    var res = await fetch('/api/files/write', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ path_token: st.path, content: newContent, encoding: st.encoding }),
    });
    var data = await res.json().catch(function() { return {}; });
    if (!res.ok || data.error) throw new Error(data.error || ('HTTP ' + res.status));
    st.text = newContent;
    _fmEl(st, '.fp-modal-body pre').textContent = st.text;
    _fmSetEditing(st, false);
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
  localStorage.setItem('ttyd_fp_open', open ? '1' : '0');
  if (open) {
    const savedToken = localStorage.getItem('ttyd_fp_last_token') || '';
    fetchFiles(fpCurrentPathToken || savedToken);
  }
}

function toggleFilePanelFullscreen() {
  const panel = document.getElementById('filePanel');
  const isFs = panel.classList.toggle('fp-fullscreen');
  document.getElementById('fpFullscreenBtn').innerHTML = isFs ? '&#x2716;' : '&#x26F6;';
  document.getElementById('fpFullscreenBtn').title = isFs ? 'Exit fullscreen' : 'Fullscreen';
  localStorage.setItem('ttyd_fp_fullscreen', isFs ? '1' : '0');
}

// File panel resize
(function() {
  const handle = document.getElementById('fpResizeHandle');
  const panel = document.getElementById('filePanel');
  if (!handle || !panel) return;
  let startX, startW;
  handle.addEventListener('mousedown', function(e) {
    if (panel.classList.contains('fp-fullscreen')) return;
    e.preventDefault();
    startX = e.clientX;
    startW = panel.offsetWidth;
    handle.classList.add('active');
    // Block iframes from stealing mouse events and prevent text selection
    document.body.style.userSelect = 'none';
    document.querySelectorAll('iframe').forEach(f => f.style.pointerEvents = 'none');
    const onMove = (e) => {
      const w = Math.max(200, Math.min(startW + (e.clientX - startX), window.innerWidth * 0.8));
      panel.style.width = w + 'px';
    };
    const onUp = () => {
      handle.classList.remove('active');
      document.body.style.userSelect = '';
      document.querySelectorAll('iframe').forEach(f => f.style.pointerEvents = '');
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      localStorage.setItem('ttyd_fp_width', panel.style.width);
    };
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  });
  // Restore saved width
  const savedW = localStorage.getItem('ttyd_fp_width');
  if (savedW) panel.style.width = savedW;
})();

async function fetchFiles(pathToken, rawPath) {
  const list = document.getElementById('fpList');
  list.innerHTML = '<div style="padding:20px;color:#7a7a9e;text-align:center;">Loading...</div>';
  try {
    let url = '/api/files/list';
    if (pathToken) {
      url += '?path_token=' + encodeURIComponent(pathToken);
    } else if (rawPath) {
      url += '?path=' + encodeURIComponent(rawPath);
    }
    const res = await fetch(url, {cache: 'no-store'});
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    if (data.error) { list.innerHTML = '<div style="padding:12px;color:#e94560;">' + escHtml(data.error) + '</div>'; return; }
    fpCurrentPath = data.path;
    fpCurrentPathToken = data.path_token || '';
    fpParentToken = data.parent_token || '';
    localStorage.setItem('ttyd_fp_last_token', fpCurrentPathToken);
    localStorage.setItem('ttyd_fp_last_path', fpCurrentPath);
    fpAddRecentFolder(fpCurrentPath, fpCurrentPathToken);
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

function startPathEdit() {
  const bc = document.getElementById('fpBreadcrumbs');
  const inp = document.getElementById('fpPathInput');
  bc.style.display = 'none';
  inp.style.display = 'block';
  inp.value = fpCurrentPath || '~';
  inp.focus();
  inp.select();
}

function cancelPathEdit() {
  const bc = document.getElementById('fpBreadcrumbs');
  const inp = document.getElementById('fpPathInput');
  inp.style.display = 'none';
  bc.style.display = 'flex';
}

async function commitPathEdit() {
  const inp = document.getElementById('fpPathInput');
  const raw = (inp.value || '').trim();
  cancelPathEdit();
  if (!raw || raw === fpCurrentPath) return;
  try {
    const res = await fetch('/api/files/list?path=' + encodeURIComponent(raw));
    if (!res.ok) { showToast('Path not found: ' + raw, true); return; }
    const data = await res.json();
    if (data.error) { showToast(data.error, true); return; }
    fpCurrentPath = data.path;
    fpCurrentPathToken = data.path_token || '';
    fpParentToken = data.parent_token || '';
    localStorage.setItem('ttyd_fp_last_token', fpCurrentPathToken);
    localStorage.setItem('ttyd_fp_last_path', fpCurrentPath);
    fpAddRecentFolder(fpCurrentPath, fpCurrentPathToken);
    renderBreadcrumbs(data.breadcrumbs || []);
    fpCurrentEntries = data.entries || [];
    renderSortBar();
    renderFileList(fpCurrentEntries);
  } catch (e) {
    showToast('Error: ' + e.message, true);
  }
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
  var lowerName = (name || '').toLowerCase();
  var st = _fmCreate(name);
  st.path = pathToken;

  _fmEl(st, '.fp-btn-download').onclick = function() { downloadFile(pathToken, name); };
  _fmEl(st, '.fp-btn-save').onclick = function() { _fmSave(st); };
  _fmEl(st, '.fp-btn-edit').onclick = function() {
    if (st.editing) {
      _fmEl(st, '.fp-modal-body textarea').value = st.text;
      _fmSetEditing(st, false);
    } else {
      _fmStartEdit(st);
    }
  };

  if (isImageFile(lowerName)) {
    st.kind = 'image'; st.isText = false;
    _fmEl(st, '.fp-modal-note').textContent = '';
    _fmEl(st, '.fp-modal-image').src = getInlinePreviewUrl(pathToken);
    _fmSetEditing(st, false);
    return;
  }

  if (isVideoFile(lowerName)) {
    st.kind = 'video'; st.isText = false;
    _fmEl(st, '.fp-modal-note').textContent = '';
    _fmEl(st, '.fp-modal-video').src = getInlinePreviewUrl(pathToken);
    _fmSetEditing(st, false);
    return;
  }

  if (isAudioFile(lowerName)) {
    st.kind = 'audio'; st.isText = false;
    _fmEl(st, '.fp-modal-note').textContent = '';
    _fmEl(st, '.fp-modal-audio').src = getInlinePreviewUrl(pathToken);
    _fmSetEditing(st, false);
    return;
  }

  if (isPdfFile(lowerName)) {
    var url = getInlinePreviewUrl(pathToken);
    if (isCoarsePointer && isCoarsePointer()) {
      _fmClose(st.id);
      openInNewTab(url);
      showToast('Opened PDF in a new tab', false);
      return;
    }
    st.kind = 'pdf'; st.isText = false;
    var note = _fmEl(st, '.fp-modal-note');
    note.textContent = ''; note.innerHTML = '';
    var pdf = _fmEl(st, '.fp-modal-pdf');
    if (isIOS()) {
      var msg = document.createElement('div');
      msg.textContent = 'PDF preview is blocked by iOS Safari when embedded. Open it instead:';
      msg.style.marginBottom = '8px';
      var row = document.createElement('div');
      row.style.display = 'flex'; row.style.gap = '8px'; row.style.flexWrap = 'wrap';
      var aNew = document.createElement('a');
      aNew.className = 'fp-btn'; aNew.href = url; aNew.target = '_blank'; aNew.rel = 'noopener';
      aNew.textContent = 'Open in new tab';
      var aHere = document.createElement('a');
      aHere.className = 'fp-btn'; aHere.href = url; aHere.textContent = 'Open here';
      row.appendChild(aNew); row.appendChild(aHere);
      note.appendChild(msg); note.appendChild(row);
      pdf.removeAttribute('src');
      _fmSetEditing(st, false);
      return;
    }
    pdf.src = url;
    _fmSetEditing(st, false);
    return;
  }

  try {
    var res = await fetch('/api/files/read?path_token=' + encodeURIComponent(pathToken));
    if (!res.ok) throw new Error('HTTP ' + res.status);
    var data = await res.json();
    if (data.error) { _fmClose(st.id); await modalAlert(data.error, 'Preview'); return; }
    st.isText = !!data.is_text;
    st.kind = st.isText ? 'text' : 'binary';
    st.text = data.content || '';
    st.encoding = data.encoding || 'utf-8';
    st.mdRendered = st.isText && isMdFile(name);
    _fmEl(st, '.fp-modal-body pre').textContent = st.text;
    _fmEl(st, '.fp-modal-body textarea').value = st.text;
    _fmEl(st, '.fp-modal-note').textContent = st.isText
      ? (st.encoding !== 'utf-8' ? 'Encoding: ' + st.encoding : '')
      : 'Binary file preview is disabled. Use Download.';
    _fmSetEditing(st, false);
  } catch (e) {
    _fmClose(st.id);
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

function _clipboardDefaultName(mimeType) {
  const now = new Date();
  const ts = now.getFullYear().toString() +
    String(now.getMonth() + 1).padStart(2, '0') +
    String(now.getDate()).padStart(2, '0') + '_' +
    String(now.getHours()).padStart(2, '0') +
    String(now.getMinutes()).padStart(2, '0') +
    String(now.getSeconds()).padStart(2, '0');
  const ext = mimeType === 'image/png' ? '.png' :
              mimeType === 'image/jpeg' ? '.jpg' :
              mimeType === 'image/gif' ? '.gif' :
              mimeType === 'image/webp' ? '.webp' : '.png';
  return 'clipboard_' + ts + ext;
}

async function _promptAndUploadClipboardImages(blobs) {
  // blobs: array of { blob: Blob, type: string }
  if (!blobs.length) return;

  // Ensure file panel is open so user sees the current folder
  const panel = document.getElementById('filePanel');
  if (!panel.classList.contains('open')) {
    panel.classList.add('open');
    document.getElementById('filesBtn').classList.add('active');
  }
  if (!fpCurrentPathToken) await fetchFiles('');
  if (!fpCurrentPathToken) { showToast('Cannot determine upload path', true); return; }

  // Prompt for folder — default to current file-panel path
  const folder = await modalPrompt(
    'Save to folder (relative to home, or absolute):',
    'Paste Image — Choose Folder',
    fpCurrentPath || '~'
  );
  if (folder === null || folder === undefined) return; // cancelled

  // Resolve folder to a path token via the API
  let targetToken = fpCurrentPathToken;
  const trimmed = folder.trim();
  if (trimmed && trimmed !== fpCurrentPath) {
    try {
      const res = await fetch('/api/files/list?path=' + encodeURIComponent(trimmed));
      if (!res.ok) { showToast('Folder not found: ' + trimmed, true); return; }
      const data = await res.json();
      if (data.error) { showToast(data.error, true); return; }
      targetToken = data.path_token || '';
    } catch (e) {
      showToast('Error resolving folder: ' + e.message, true);
      return;
    }
  }
  if (!targetToken) { showToast('Cannot determine upload path', true); return; }

  for (let i = 0; i < blobs.length; i++) {
    const item = blobs[i];
    const defaultName = _clipboardDefaultName(item.type);
    const chosenName = await modalPrompt(
      'File name' + (blobs.length > 1 ? ' (' + (i + 1) + '/' + blobs.length + ')' : '') + ':',
      'Paste Image — File Name',
      defaultName
    );
    if (chosenName === null || chosenName === undefined) return; // cancelled
    const finalName = chosenName.trim() || defaultName;
    const file = new File([item.blob], finalName, { type: item.type });

    try {
      const body = await file.arrayBuffer();
      const nameB64 = btoa(unescape(encodeURIComponent(file.name))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const res = await fetch('/api/files/upload?path_token=' + encodeURIComponent(targetToken), {
        method: 'POST',
        headers: { 'X-Path-Token': targetToken, 'X-File-Name-B64': nameB64 },
        body: body,
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        await modalAlert('Upload failed: ' + (d.error || res.status), 'Upload Failed');
      } else {
        showToast('Saved ' + finalName);
      }
    } catch (e) {
      await modalAlert('Upload error: ' + e.message, 'Upload Failed');
    }
  }
  fetchFiles(fpCurrentPathToken);
}

async function pasteImageFromClipboard() {
  try {
    const items = await navigator.clipboard.read();
    const imageBlobs = [];
    for (const item of items) {
      const imageType = item.types.find(t => t.startsWith('image/'));
      if (imageType) {
        const blob = await item.getType(imageType);
        imageBlobs.push({ blob, type: imageType });
      }
    }
    if (!imageBlobs.length) {
      showToast('No image in clipboard', true);
      return;
    }
    await _promptAndUploadClipboardImages(imageBlobs);
  } catch (e) {
    if (e.name === 'NotAllowedError') {
      showToast('Clipboard access denied', true);
    } else {
      showToast('Paste failed: ' + e.message, true);
    }
  }
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
  localStorage.setItem('ttyd_fp_sort_by', fpSortBy);
  localStorage.setItem('ttyd_fp_sort_asc', fpSortAsc ? '1' : '0');
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
# STATE_LOCK guards user_instances, user_vnc_instances, and next_port — the
# server runs as ThreadingHTTPServer so any handler may touch these from any
# thread. Held across the spawn calls because port allocation + dict insert
# need to be atomic relative to other logins. RLock so allocate_port() can
# be called while spawn_user_ttyd already holds it.
STATE_LOCK = threading.RLock()
user_instances = {}  # {username: {"port": int, "proc": Popen}}
user_vnc_instances = {}  # {username: {"vnc_port": int, "ws_port": int, "vnc_proc": Popen, "ws_proc": Popen}}
WEBSOCKIFY_BIN = os.environ.get("WEBSOCKIFY_BIN") or shutil.which("websockify") or "/home/mli/miniconda3/bin/websockify"
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
    with STATE_LOCK:
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
    with STATE_LOCK:
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
        # Each tab gets a grouped session pointing at a deterministic tmux window slot.
        # Grouped sessions have destroy-unattached so they auto-clean on disconnect,
        # while the base "main" session (and its windows) persist to keep processes alive.
        # On reconnect, tabs reattach to existing windows instead of creating new ones.
        tmux_cmd = (
            r'tmux has-session -t main 2>/dev/null || exec tmux new-session -s main \; set -g mouse on \; set -g history-limit 10000 \; set -s set-clipboard on \; setw -g aggressive-resize on;'
            r' tmux set -g mouse on 2>/dev/null; tmux set -g history-limit 10000 2>/dev/null; tmux set -s set-clipboard on 2>/dev/null; tmux set -g set-clipboard on 2>/dev/null; tmux setw -g aggressive-resize on 2>/dev/null;'
            # Parse arg format "SLOT:ACTIVE_SLOTS" (e.g. "0:0,2,3") or plain "SLOT"
            r' RAW="$1"; case "$RAW" in *:*) SLOT="${RAW%%:*}"; ACTIVE="${RAW#*:}" ;; *) SLOT="$RAW"; ACTIVE="" ;; esac;'
            r' case "$SLOT" in (""|*[!0-9]*) SLOT=0 ;; esac;'
            # Create window at exact SLOT index (no gap-filling)
            r' tmux list-windows -t main -F "#{window_index}" | grep -q "^${SLOT}$" || tmux new-window -t main:${SLOT};'
            # Clean up orphaned windows not in the active slots list
            r' if [ -n "$ACTIVE" ]; then for _w in $(tmux list-windows -t main -F "#{window_index}"); do'
            r' _k=0; _I="$IFS"; IFS=","; for _a in $ACTIVE; do [ "$_w" = "$_a" ] && _k=1; done; IFS="$_I";'
            r' [ "$_k" = "0" ] && tmux kill-window -t "main:${_w}" 2>/dev/null; done; true; fi;'
            r' exec tmux new-session -t main \; set-option destroy-unattached on \; select-window -t :${SLOT}'
        )
        ttyd_cmd = f"{shlex.quote(TTYD_BIN)} -W -a -i 127.0.0.1 -p {port} bash -lc {shlex.quote(tmux_cmd)} ttyd-tab"
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
    with STATE_LOCK:
        info = user_instances.get(username)
        if info is None:
            return None
        if info["proc"].poll() is None:
            return info["port"]
        user_instances.pop(username, None)
        return None


def spawn_user_vnc(username, password):
    """Spawn a per-user VNC desktop (Xtigervnc + xfce4 + websockify). Returns ws_port."""
    with STATE_LOCK:
        # Reuse existing instance if still alive
        if username in user_vnc_instances:
            info = user_vnc_instances[username]
            if info["ws_proc"].poll() is None:
                return info["ws_port"]
            _cleanup_vnc(username)

        vnc_port = allocate_port()
        ws_port = allocate_port()

        # Pick a display number from the VNC port to avoid collisions
        display_num = vnc_port - 5900
        if display_num < 1:
            display_num = vnc_port % 1000 + 100

        # Spawn Xtigervnc + xfce4-session via SSH as the user
        # Kill any stale Xtigervnc on this display before starting
        vnc_cmd = (
            f"rm -f /tmp/.X{display_num}-lock /tmp/.X11-unix/X{display_num} 2>/dev/null;"
            f" unset DISPLAY;"
            f" Xtigervnc :{display_num} -rfbport {vnc_port} -localhost=1"
            f" -SecurityTypes None -geometry 1920x1080 -depth 24 &"
            f" sleep 1; DISPLAY=:{display_num} xfce4-session"
        )
        # Clear DISPLAY from env to prevent SSH X11 forwarding interference
        clean_env = {k: v for k, v in os.environ.items() if k != "DISPLAY"}
        vnc_proc = subprocess.Popen(
            [SSHPASS_BIN, "-p", password, SSH_BIN,
             "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=5",
             "-o", "ForwardX11=no",
             "-o", "PreferredAuthentications=password",
             "-o", "PubkeyAuthentication=no",
             "-o", "PasswordAuthentication=yes",
             "-o", "ServerAliveInterval=30",
             f"{username}@127.0.0.1",
             "bash", "-lc", vnc_cmd],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=clean_env,
        )

        # Wait for VNC server to be ready
        if not wait_for_ttyd_ready(vnc_port, timeout=6.0):
            # Capture output for debugging
            try:
                out, err = vnc_proc.communicate(timeout=2)
            except Exception:
                out, err = b"", b""
            print(f"[VNC] FAILED for {username} display=:{display_num} port={vnc_port}")
            print(f"[VNC] stdout: {out[:500]}")
            print(f"[VNC] stderr: {err[:500]}")
            try:
                vnc_proc.terminate()
            except Exception:
                pass
            raise RuntimeError("VNC server failed to start")

        # Spawn websockify to bridge WebSocket → VNC
        ws_proc = subprocess.Popen(
            [WEBSOCKIFY_BIN, "--heartbeat=30",
             f"127.0.0.1:{ws_port}", f"localhost:{vnc_port}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        if not wait_for_ttyd_ready(ws_port, timeout=4.0):
            try:
                ws_proc.terminate()
                vnc_proc.terminate()
            except Exception:
                pass
            raise RuntimeError("websockify failed to start")

        user_vnc_instances[username] = {
            "vnc_port": vnc_port,
            "ws_port": ws_port,
            "vnc_proc": vnc_proc,
            "ws_proc": ws_proc,
            "display": display_num,
            "password": password,
        }
        print(f"[VNC] desktop started for {username}: display=:{display_num} vnc_port={vnc_port} ws_port={ws_port}")
        return ws_port


def _cleanup_vnc(username):
    """Clean up VNC instance for a user."""
    info = user_vnc_instances.pop(username, None)
    if not info:
        return
    for key in ("ws_proc", "vnc_proc"):
        proc = info.get(key)
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass


def get_user_vnc_port(username):
    """Get the websockify port for a user's VNC session, or None."""
    if username in user_vnc_instances:
        info = user_vnc_instances[username]
        if info["ws_proc"].poll() is None:
            return info["ws_port"]
        _cleanup_vnc(username)
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


# --- API Token helpers ---

API_TOKENS_DIR = os.path.join(BASE_DIR, ".api_tokens")


def _ensure_tokens_dir():
    os.makedirs(API_TOKENS_DIR, mode=0o700, exist_ok=True)


def _tokens_file(username):
    safe = "".join(c for c in username if c.isalnum() or c in "-_.")
    return os.path.join(API_TOKENS_DIR, f"{safe}.json")


def _load_api_tokens(username):
    try:
        with open(_tokens_file(username), "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        return []


def _save_api_tokens(username, tokens):
    _ensure_tokens_dir()
    path = _tokens_file(username)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)
    os.replace(tmp, path)


def _make_api_token(username):
    """Generate a new raw token string (username:rand:hmac). Not stored server-side."""
    rand = secrets.token_hex(32)
    msg = f"{username}:{rand}"
    sig = hmac.new(SECRET_KEY.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return f"{username}:{rand}:{sig}"


def _verify_api_token(token_str):
    """Verify HMAC signature and confirm token exists. Returns username or None."""
    try:
        parts = token_str.split(":", 2)
        if len(parts) != 3:
            return None
        username, rand, sig = parts
        msg = f"{username}:{rand}"
        expected = hmac.new(SECRET_KEY.encode(), msg.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        token_hash = hashlib.sha256(token_str.encode()).hexdigest()
        tokens = _load_api_tokens(username)
        for t in tokens:
            if t.get("hash") == token_hash:
                t["last_used"] = int(time.time())
                _save_api_tokens(username, tokens)
                return username
        return None
    except Exception:
        return None


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


# --- Minimal WebSocket helpers (RFC 6455, server-side only) -----------------
# We implement the small subset needed for /api/shell so the project keeps
# its "stdlib only, no pip deps" rule. Frame size cap prevents a malicious
# client from making us allocate gigabytes for a single frame.
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WS_MAX_FRAME = 16 * 1024 * 1024  # 16 MiB

def _ws_recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError:
            return None
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)

def _ws_recv_frame(sock):
    """Read one WebSocket frame. Returns (fin, opcode, payload) or None on close/error."""
    hdr = _ws_recv_exact(sock, 2)
    if not hdr:
        return None
    fin = (hdr[0] >> 7) & 1
    opcode = hdr[0] & 0x0F
    masked = (hdr[1] >> 7) & 1
    plen = hdr[1] & 0x7F
    if plen == 126:
        ext = _ws_recv_exact(sock, 2)
        if ext is None:
            return None
        plen = struct.unpack(">H", ext)[0]
    elif plen == 127:
        ext = _ws_recv_exact(sock, 8)
        if ext is None:
            return None
        plen = struct.unpack(">Q", ext)[0]
    if plen > WS_MAX_FRAME:
        return None
    mask = _ws_recv_exact(sock, 4) if masked else None
    if masked and mask is None:
        return None
    payload = _ws_recv_exact(sock, plen) if plen else b""
    if payload is None:
        return None
    if mask:
        payload = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
    return (fin, opcode, payload)

def _ws_send_frame(sock, opcode, payload, lock=None):
    """Send one unfragmented, unmasked WebSocket frame. Server frames must not be masked."""
    n = len(payload)
    hdr = bytearray([0x80 | (opcode & 0x0F)])
    if n < 126:
        hdr.append(n)
    elif n < 65536:
        hdr.append(126)
        hdr += struct.pack(">H", n)
    else:
        hdr.append(127)
        hdr += struct.pack(">Q", n)
    data = bytes(hdr) + payload
    if lock:
        with lock:
            sock.sendall(data)
    else:
        sock.sendall(data)


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
        # Skip CSP/XFO for inline file previews so user HTML can load external resources.
        if ct_main == "text/html" and not getattr(self, "_skip_csp", False):
            for k, v in HTML_ONLY_SECURITY_HEADERS.items():
                self.send_header(k, v)
        super().end_headers()

    def _get_authenticated_user(self):
        token = get_cookie_token(self.headers)
        username, _port = verify_token(token)
        if username:
            return username
        # Fallback: bearer token for API / scripting access
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return _verify_api_token(auth[7:].strip())
        return None

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

    # --- Desktop VNC API handler ---

    def _handle_desktop_request(self, params):
        token = get_cookie_token(self.headers)
        username, _port = verify_token(token)
        if not username:
            self._send_error(401, "not authenticated")
            return
        # Check if user already has a running VNC session
        ws_port = get_user_vnc_port(username)
        if ws_port:
            self._send_json(200, {"ok": True, "ws_port": ws_port})
            return
        # Need password to spawn via SSH — retrieve from ttyd instance
        info = user_instances.get(username)
        if not info or not info.get("password"):
            self._send_error(400, "no active session – please open a terminal first")
            return
        try:
            ws_port = spawn_user_vnc(username, info["password"])
            self._send_json(200, {"ok": True, "ws_port": ws_port})
        except Exception as e:
            import traceback; traceback.print_exc()
            self._send_error(500, f"failed to start desktop: {e}")

    # --- Help manual handler ---

    def _handle_help_request(self, path):
        token = get_cookie_token(self.headers)
        username, _port = verify_token(token)
        if not username:
            self._send_error(401, "not authenticated")
            return
        doc_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "doc")
        if path == "/api/help":
            # Serve manual.md text
            md_path = os.path.join(doc_dir, "manual.md")
            try:
                with open(md_path, "r") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(content.encode("utf-8"))
            except FileNotFoundError:
                self._send_error(404, "manual not found")
        elif path.startswith("/api/help/images/"):
            # Serve image files from doc/images/
            fname = path.split("/api/help/images/", 1)[1]
            # Security: no path traversal
            if ".." in fname or "/" in fname:
                self._send_error(403, "forbidden")
                return
            img_path = os.path.join(doc_dir, "images", fname)
            if not os.path.isfile(img_path):
                self._send_error(404, "image not found")
                return
            ext = fname.rsplit(".", 1)[-1].lower()
            ct = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                  "gif": "image/gif", "svg": "image/svg+xml", "webp": "image/webp"}.get(ext, "application/octet-stream")
            with open(img_path, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.send_header("Cache-Control", "public, max-age=3600")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self._send_error(404, "not found")

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
    if size > 8388608:
        print(json.dumps({{"error": "file too large (>8MB)"}}))
    else:
        with open(p, "rb") as f:
            data = f.read()
        is_text = True
        content = ""
        encoding = "utf-8"
        if b"\\x00" in data:
            is_text = False
        else:
            try:
                content = data.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    content = data.decode("latin-1")
                    encoding = "latin-1"
                except Exception:
                    is_text = False
        print(json.dumps({{
            "is_text": is_text,
            "content": content if is_text else "",
            "size": size,
            "encoding": encoding if is_text else ""
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
        if length > 16 * 1024 * 1024:
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
        encoding = req.get("encoding", "utf-8")
        if encoding not in ("utf-8", "latin-1"):
            encoding = "utf-8"
        if not path or not isinstance(content, str):
            self._send_error(400, "missing path or content")
            return

        content_size = len(content.encode(encoding, errors="replace"))
        if content_size > 8388608:
            self._send_error(400, "file too large (>8MB)")
            return

        script = f'''
import os, json
p = os.path.expanduser({path!r})
content = {content!r}
encoding = {encoding!r}
try:
    if os.path.isdir(p):
        raise Exception("path is a directory")
    if os.path.exists(p):
        with open(p, "rb") as f:
            sample = f.read(8192)
        if b"\\x00" in sample:
            raise Exception("binary file cannot be edited here")

    with open(p, "w", encoding=encoding, newline="") as f:
        f.write(content)
    print(json.dumps({{"ok": True, "size": os.path.getsize(p)}}))
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
        # Support dir_token + rel for relative path resolution (markdown images)
        dir_token = params.get("dir_token", [""])[0]
        rel = params.get("rel", [""])[0]
        if dir_token and rel:
            dir_path = parse_path_token(username, dir_token)
            if not dir_path:
                self._send_error(400, "invalid directory token")
                return
            full = os.path.normpath(os.path.join(dir_path, rel))
            home = os.path.expanduser(f"~{username}")
            if not (full == home or full.startswith(home + os.sep)):
                self._send_error(403, "access denied")
                return
            path = full
        else:
            path = self._path_from_params(username, params)
        inline = params.get("inline", ["0"])[0].lower() in ("1", "true", "yes")
        if inline:
            self._skip_csp = True
        if not path:
            self._send_error(400, "missing path")
            return

        # Get file metadata (size, name) and stream content via a single
        # subprocess.  The script writes a header line "OK <size> <basename>\n"
        # then streams raw file bytes — no base64, no full-file buffering.
        script = f'''
import os, sys
p = os.path.expanduser({path!r})
try:
    st = os.stat(p)
    if not os.path.isfile(p):
        raise IsADirectoryError("not a regular file")
    name = os.path.basename(p)
    sys.stdout.buffer.write(f"OK {{st.st_size}} {{name}}\\n".encode())
    sys.stdout.buffer.flush()
    with open(p, "rb") as f:
        while True:
            chunk = f.read(262144)
            if not chunk:
                break
            sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()
except Exception as ex:
    sys.stdout.buffer.write(f"ERR {{ex}}\\n".encode())
    sys.stdout.buffer.flush()
'''
        info = user_instances.get(username)
        if not info or "password" not in info:
            self._send_error(500, "no session")
            return
        password = info["password"]
        try:
            proc = subprocess.Popen(
                [SSHPASS_BIN, "-p", password, SSH_BIN,
                 "-o", "StrictHostKeyChecking=no",
                 "-o", "PubkeyAuthentication=no",
                 "-o", "ConnectTimeout=5",
                 f"{username}@127.0.0.1", "python3", "-"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            proc.stdin.write(script.encode())
            proc.stdin.close()

            # Read the header line (e.g. "OK 12345 myfile.zip\n")
            header_line = proc.stdout.readline(4096)
            if not header_line:
                proc.terminate()
                self._send_error(500, "no response from file reader")
                return
            header = header_line.decode(errors="replace").strip()
            if header.startswith("ERR "):
                proc.terminate()
                self._send_error(500, header[4:])
                return
            if not header.startswith("OK "):
                proc.terminate()
                self._send_error(500, "unexpected response")
                return

            # Parse "OK <size> <filename>"
            parts = header.split(" ", 2)
            if len(parts) < 3:
                proc.terminate()
                self._send_error(500, "bad metadata")
                return
            file_size = int(parts[1])
            fname = parts[2]

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
            self.send_header("Content-Length", str(file_size))
            self.end_headers()

            # Stream file content in chunks
            bytes_sent = 0
            while bytes_sent < file_size:
                chunk = proc.stdout.read(min(262144, file_size - bytes_sent))
                if not chunk:
                    break
                self.wfile.write(chunk)
                bytes_sent += len(chunk)

            proc.stdout.close()
            proc.wait(timeout=5)
        except BrokenPipeError:
            # Client disconnected mid-download
            try:
                proc.terminate()
            except Exception:
                pass
        except Exception as e:
            try:
                proc.terminate()
            except Exception:
                pass
            self._send_error(500, str(e))

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
        if length > 40 * 1024 * 1024:
            self._send_error(413, "file too large (>40MB)")
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
        if length > 8 * 1024 * 1024:
            self._send_error(413, "file too large (>8MB)")
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

    # --- API Tokens handlers ---

    def _handle_tokens_list(self):
        username = self._get_authenticated_user()
        if not username:
            self._send_error(401, "not authenticated")
            return
        tokens = _load_api_tokens(username)
        safe = [{"name": t["name"], "created_at": t.get("created_at", 0),
                 "last_used": t.get("last_used")} for t in tokens]
        self._send_json(200, {"tokens": safe})

    def _handle_tokens_create(self):
        # Token creation requires a browser session (not a bearer token itself)
        cookie_token = get_cookie_token(self.headers)
        username, _ = verify_token(cookie_token)
        if not username:
            self._send_error(403, "token creation requires a browser session")
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            req = json.loads(body)
        except Exception:
            self._send_error(400, "invalid json")
            return
        name = req.get("name", "").strip()
        if not name:
            self._send_error(400, "name is required")
            return
        if len(name) > 80:
            self._send_error(400, "name too long (max 80 chars)")
            return
        tokens = _load_api_tokens(username)
        if any(t["name"] == name for t in tokens):
            self._send_error(409, "a token with that name already exists")
            return
        raw_token = _make_api_token(username)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        tokens.append({
            "name": name,
            "hash": token_hash,
            "created_at": int(time.time()),
            "last_used": None,
        })
        _save_api_tokens(username, tokens)
        self._send_json(200, {"token": raw_token})

    def _handle_tokens_revoke(self):
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
        name = req.get("name", "").strip()
        if not name:
            self._send_error(400, "name is required")
            return
        tokens = _load_api_tokens(username)
        new_tokens = [t for t in tokens if t["name"] != name]
        if len(new_tokens) == len(tokens):
            self._send_error(404, "token not found")
            return
        _save_api_tokens(username, new_tokens)
        self._send_json(200, {"ok": True})

    # --- Exec handler ---

    def _handle_exec(self):
        username = self._get_authenticated_user()
        if not username:
            self._send_error(401, "not authenticated")
            return
        length = int(self.headers.get("Content-Length", 0))
        if length > 64 * 1024:
            self._send_error(413, "request body too large")
            return
        body = self.rfile.read(length) if length else b""
        try:
            req = json.loads(body)
        except Exception:
            self._send_error(400, "invalid json")
            return
        command = req.get("command", "").strip()
        if not command:
            self._send_error(400, "command is required")
            return
        timeout = max(1, min(int(req.get("timeout", 30)), 300))
        cwd = req.get("cwd") or os.path.expanduser(f"~{username}")
        if cwd.startswith("~"):
            cwd = os.path.expanduser(f"~{username}") + cwd[1:]
        stdin_str = req.get("stdin")
        try:
            result = subprocess.run(
                ["sudo", "-u", username, "bash", "-c", command],
                input=stdin_str.encode() if isinstance(stdin_str, str) else (stdin_str or b""),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                cwd=cwd if os.path.isdir(cwd) else None,
            )
            self._send_json(200, {
                "stdout": result.stdout[:512 * 1024].decode(errors="replace"),
                "stderr": result.stderr[:512 * 1024].decode(errors="replace"),
                "exit_code": result.returncode,
            })
        except subprocess.TimeoutExpired:
            self._send_error(408, f"command timed out after {timeout}s")
        except Exception as e:
            self._send_error(500, str(e))

    # --- Interactive shell over WebSocket -------------------------------------

    def _handle_shell_ws(self, params):
        """Upgrade to WebSocket and pump bytes between the client and a fresh
        login shell running as the authenticated user. Protocol:
          server -> client: binary frames of raw PTY output
          client -> server: binary frames of raw input,
                            or text frames carrying control JSON like
                            {"type":"resize","cols":80,"rows":24}
        """
        username = self._get_authenticated_user()
        if not username:
            self.send_response(401); self.end_headers(); return
        if self.headers.get("Upgrade", "").lower() != "websocket":
            self.send_response(400); self.end_headers(); return
        key = self.headers.get("Sec-WebSocket-Key", "")
        if not key:
            self.send_response(400); self.end_headers(); return

        # Lazy import — pty/fcntl/termios are unix-only and not used elsewhere.
        import pty, fcntl, termios, signal

        accept = base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode()).digest()
        ).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        try:
            self.wfile.flush()
        except Exception:
            return
        # Tell the keep-alive logic this connection is finished after we return.
        self.close_connection = True

        sock = self.connection
        sock_lock = threading.Lock()

        # Optional initial geometry from query string (?cols=80&rows=24).
        try:
            cols = int(params.get("cols", ["80"])[0])
            rows = int(params.get("rows", ["24"])[0])
        except (TypeError, ValueError):
            cols, rows = 80, 24
        cols = max(20, min(cols, 500))
        rows = max(5, min(rows, 200))

        # Spawn a PTY running a fresh login shell as the user. Using sudo here
        # matches the bearer-token model: there's no SSH password to forward.
        try:
            pid, master_fd = pty.fork()
        except OSError as e:
            try:
                _ws_send_frame(sock, 0x2, f"pty.fork failed: {e}\n".encode(), sock_lock)
                _ws_send_frame(sock, 0x8, b"\x03\xee", sock_lock)
            except Exception:
                pass
            return

        if pid == 0:
            # Child: become the user via sudo. -i runs the login shell.
            try:
                env = {
                    "TERM": "xterm-256color",
                    "LANG": os.environ.get("LANG", "en_US.UTF-8"),
                    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                }
                os.execvpe("sudo", ["sudo", "-iu", username], env)
            except Exception as e:
                os.write(2, f"exec failed: {e}\n".encode())
            os._exit(127)

        # Parent: set initial window size and pump bytes both ways.
        try:
            fcntl.ioctl(master_fd, termios.TIOCSWINSZ,
                        struct.pack("HHHH", rows, cols, 0, 0))
        except Exception:
            pass

        stop = threading.Event()

        import select as _select

        def pty_to_ws():
            try:
                while not stop.is_set():
                    # select() with a small timeout so we can also notice the
                    # child exited even if read() hasn't returned yet (some
                    # platforms latch EOF on the master fd a moment after the
                    # final process closes the slave).
                    try:
                        ready, _, _ = _select.select([master_fd], [], [], 0.5)
                    except (OSError, ValueError):
                        break
                    if not ready:
                        try:
                            done, _ = os.waitpid(pid, os.WNOHANG)
                            if done:
                                break
                        except OSError:
                            break
                        continue
                    try:
                        data = os.read(master_fd, 65536)
                    except OSError:
                        break
                    if not data:
                        break
                    try:
                        _ws_send_frame(sock, 0x2, data, sock_lock)
                    except OSError:
                        break
            finally:
                stop.set()
                # Send a close frame so the client sees a clean shutdown,
                # then half-close the socket so the recv loop wakes up.
                try:
                    _ws_send_frame(sock, 0x8, b"\x03\xe8", sock_lock)
                except Exception:
                    pass
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass

        t = threading.Thread(target=pty_to_ws, daemon=True, name=f"ws-shell-out:{username}")
        t.start()

        try:
            while not stop.is_set():
                frame = _ws_recv_frame(sock)
                if frame is None:
                    break
                fin, opcode, payload = frame
                if opcode == 0x8:  # close
                    try:
                        _ws_send_frame(sock, 0x8, payload[:2] if payload else b"", sock_lock)
                    except Exception:
                        pass
                    break
                if opcode == 0x9:  # ping → pong
                    try:
                        _ws_send_frame(sock, 0xA, payload, sock_lock)
                    except Exception:
                        break
                    continue
                if opcode == 0xA:  # pong
                    continue
                if opcode == 0x1:  # text — control JSON
                    try:
                        msg = json.loads(payload.decode("utf-8", errors="replace"))
                    except Exception:
                        continue
                    if isinstance(msg, dict) and msg.get("type") == "resize":
                        try:
                            c = max(20, min(int(msg.get("cols", 80)), 500))
                            r = max(5, min(int(msg.get("rows", 24)), 200))
                            fcntl.ioctl(master_fd, termios.TIOCSWINSZ,
                                        struct.pack("HHHH", r, c, 0, 0))
                        except Exception:
                            pass
                    continue
                if opcode == 0x2:  # binary — keystrokes
                    try:
                        os.write(master_fd, payload)
                    except OSError:
                        break
                    continue
                # Unknown opcode → ignore
        finally:
            stop.set()
            try:
                os.kill(pid, signal.SIGHUP)
            except Exception:
                pass
            try:
                os.close(master_fd)
            except Exception:
                pass
            try:
                # Reap the child without blocking forever.
                for _ in range(20):
                    pid_done, _status = os.waitpid(pid, os.WNOHANG)
                    if pid_done:
                        break
                    time.sleep(0.05)
                else:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
            except Exception:
                pass
            t.join(timeout=1.0)

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
                # Try bearer token (API scripting — no port binding, no /ut/ access)
                auth = self.headers.get("Authorization", "")
                if auth.lower().startswith("bearer "):
                    api_user = _verify_api_token(auth[7:].strip())
                    if api_user:
                        # Bearer tokens cannot authorize /ut/ terminal access
                        if (self.headers.get("X-TTYD-Port") or "").strip():
                            self.send_response(401)
                            self.end_headers()
                            return
                        self.send_response(200)
                        self.end_headers()
                        return
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
        elif path == "/api/desktop":
            self._handle_desktop_request(params)
        elif path == "/api/help" or path.startswith("/api/help/"):
            self._handle_help_request(path)
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
        elif path == "/api/tokens":
            self._handle_tokens_list()
        elif path == "/api/shell":
            self._handle_shell_ws(params)
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
        elif path == "/api/tokens":
            self._handle_tokens_create()
        elif path == "/api/tokens/revoke":
            self._handle_tokens_revoke()
        elif path == "/api/exec":
            self._handle_exec()
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    # ThreadingHTTPServer so a long-running /api/shell session (which holds
    # the connection open for the entire interactive shell) doesn't block
    # other requests. Daemon threads exit when the main process does.
    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), AuthHandler)
    server.daemon_threads = True
    print(f"Auth service running on http://127.0.0.1:{PORT}")
    server.serve_forever()
