# CLAUDE.md — micsapp-webterminal

## Project Overview

Browser-based multi-tenant terminal: sshd -> ttyd (per-user, ports 7700+) -> nginx (7680) -> auth.py (7682) -> cloudflared tunnel. Each system user gets an isolated shell under their own UID.

## Key Files

- `auth.py` — Monolith (~5000 lines): Python HTTP auth service + embedded HTML/CSS/JS SPA + per-user ttyd management. Zero external Python dependencies (stdlib only + `sshpass` CLI).
- `cf_tunnel_install.sh` — One-time setup (~4400 lines). **Embeds a copy of auth.py inline** — changes to auth.py must be mirrored here.
- `deploy.sh` — Service lifecycle: health checks, smart start (only starts what's down), nginx config drift detection.
- `nginx/ttyd.conf` — Reverse proxy template for ttyd routing + WebSocket upgrade + term-hook.js injection via `sub_filter`.

## Critical Rules

1. **Dual-file sync**: `auth.py` and `cf_tunnel_install.sh` contain the same Python+HTML+JS code. Any change to auth.py MUST be replicated in cf_tunnel_install.sh (the embedded copy starting around line 506).
2. **No external Python deps**: auth.py uses only stdlib. Do not add pip dependencies.
3. **Absolute paths for port checks**: Use `/usr/sbin/ss` or `lsof`, never `/home/mli/bin/ss` (broken).
4. **WSL2 environment**: No systemd. Use `service` commands and nohup/tmux for process management.

## Architecture Details

- `TERM_HOOK_JS` (auth.py ~line 262): Injected into ttyd iframe via nginx `sub_filter`. Exposes xterm Terminal object as `window.term` and overrides mouse events to enable text selection while keeping tmux scroll.
- `APP_HTML` (auth.py ~line 316): The full SPA — tabs, split panes, settings, file browser, quick commands, copy modal. All inline, no build step.
- Per-user ttyd spawning (auth.py ~line 4067): `sshpass` + SSH + ttyd + tmux with grouped sessions. Each tab gets a tmux window via grouped session.
- tmux is configured with `mouse on` (scroll), `history-limit 10000`, `set-clipboard on` (OSC 52).

## Code Patterns

- `_priv()` wrapper: runs commands with sudo on Linux, without on macOS.
- `_port_listening()`: tries lsof, /usr/sbin/ss, then curl fallback.
- Health checks: process check (pgrep) + port check + HTTP response code.
- Settings are persisted to `localStorage` keys prefixed with `ttyd_`.
- Terminal iframes use `allow="clipboard-read; clipboard-write"` for clipboard API access.

## Testing / Deploying

```bash
./deploy.sh          # Deploy/restart services (idempotent, only restarts what's needed)
./create-user.sh     # Create a new system user for terminal access
```

After changing auth.py, deploy.sh detects the change and restarts the auth service. Users must log out and back in to pick up frontend (HTML/JS) changes since the SPA is served on login.

## HTTP API

### POST /api/exec — Shell command execution

Runs a shell command as the authenticated user and returns stdout/stderr/exit code. Requires a session cookie or bearer token.

**Request:**
```json
{
  "command": "ls -la /tmp",
  "timeout": 30,
  "cwd": "/home/mli",
  "stdin": "optional stdin data"
}
```
- `command` (required): shell command to run via `bash -c`.
- `timeout` (optional, default 30): max seconds (1–300).
- `cwd` (optional): working directory, defaults to user's home.
- `stdin` (optional): string piped to stdin.
- Request body max 64 KB.

**Response (200):**
```json
{
  "stdout": "...",
  "stderr": "...",
  "exit_code": 0
}
```

**Example with bearer token:**
```bash
curl -X POST https://host/api/exec \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"command": "whoami"}'
```

**Errors:** 400 (bad request), 401 (not authenticated), 408 (timeout), 413 (body too large), 500 (execution error).

## Environment Variables

See `.env.example`. Key ones: `AUTH_PORT` (default 7682), `SESSION_MAX_AGE`, `COOKIE_SECURE`, binary path overrides (`TTYD_BIN`, `SSHPASS_BIN`, `SSH_BIN`).
