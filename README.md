# Web Terminal via Cloudflare Tunnel

A browser-based multi-tenant terminal exposed securely over the internet using Cloudflare Tunnel, per-user ttyd instances, nginx, and a custom auth service. Each system user logs in once via the web login page and gets a shell running under their own UID — no double authentication.

## Architecture

```
Browser (client)
    │
    │  HTTPS (port 443)
    ▼
Cloudflare Edge Network
    │
    │  Cloudflare Tunnel (QUIC)
    ▼
cloudflared (service)
    │
    │  HTTP (port 7680)
    ▼
nginx (reverse proxy + auth gate)
    │
    ├──► /login, /api/*  ──►  Python Auth Service (port 7682)
    │                            • Serves login page
    │                            • Validates credentials via sshpass+SSH
    │                            • Issues/verifies HMAC-signed session cookies
    │                            • Spawns per-user ttyd instances
    │
    ├──► /  ──►  Python Auth Service /app
    │              • Wrapper page with navbar + tabs + settings
    │              • Embeds per-user ttyd iframe at /ut/<port>/
    │
    └──► /ut/<port>/*  ──►  Per-user ttyd (port 7700+)
                               • One instance per logged-in user
                               • Spawned via SSH as the authenticated user
                               • Runs bash -l (login shell) directly
                               • WebSocket connection for I/O
```

## Components

### 1. Cloudflare Tunnel (`cloudflared`)

**What it does:** Creates an encrypted outbound-only tunnel from this machine to Cloudflare's edge network. No inbound ports need to be opened on the firewall/router.

**How it works:**
- `cloudflared` initiates 4 persistent QUIC connections to Cloudflare edge servers
- When a request hits `micsmac-ssh.micstec.com`, Cloudflare routes it through the tunnel to this machine
- Traffic is end-to-end encrypted between Cloudflare and the local service

**Config:** `~/.cloudflared/config.yml`
```yaml
tunnel: micsmacssh
credentials-file: /Users/mli/.cloudflared/<TUNNEL_ID>.json

ingress:
  - hostname: micsmac-ssh.micstec.com
    service: http://localhost:7680
  - service: http_status:404
```

**DNS:** A CNAME record `micsmac-ssh.micstec.com` points to `<TUNNEL_ID>.cfargotunnel.com`.

**Service:** Runs as a macOS LaunchAgent at `~/Library/LaunchAgents/com.cloudflare.cloudflared.plist`.

**Tunnel ID:** `d95faf61-a32a-4ef5-ac20-b75f415802b5`

### 2. nginx (Reverse Proxy + Auth Gate)

**What it does:** Acts as the central routing layer. Enforces authentication before allowing access to the terminal. Handles WebSocket upgrades for ttyd.

**How it works:**
- Listens on port 7680 (only localhost)
- Uses `auth_request` module to check every protected request against the auth service
- If the auth check returns 401, redirects to `/login`
- If authenticated, proxies to either the wrapper app or per-user ttyd instances
- Uses regex location `^/ut/(\d+)/(.*)` to extract the dynamic port from the URL and proxy to the correct ttyd instance
- `absolute_redirect off` ensures redirects use relative paths (critical behind Cloudflare)

**Config:** `/usr/local/etc/nginx/servers/ttyd.conf`

**Route table:**

| Path | Auth Required | Proxied To | Purpose |
|------|:---:|---|---|
| `/login` | No | Auth service (7682) | Login page |
| `/api/login` | No | Auth service (7682) | Login API (POST) |
| `/api/auth` | — | Auth service (7682) | Internal auth check |
| `/` | Yes | Auth service (7682) `/app` | Wrapper page with navbar |
| `/ut/<port>/*` | Yes | Per-user ttyd (port from URL) | Terminal + WebSocket |

### 3. Python Auth Service

**What it does:** Handles authentication, spawns per-user ttyd instances, and serves the web UI pages. Zero external dependencies — uses only Python stdlib + `sshpass` (CLI tool).

**How it works:**
- `POST /api/login` — Validates username/password via `sshpass -p <pass> ssh <user>@127.0.0.1 echo ok`. On success, spawns a per-user ttyd instance and returns an HMAC-SHA256 signed session cookie.
- `GET /api/auth` — Validates the session cookie (checks signature + expiry). Returns 200 or 401. Called internally by nginx `auth_request`.
- `GET /login` — Serves the HTML login page
- `GET /app` — Serves the wrapper page with the user's ttyd port injected (replaces `__TTYD_PORT__` and `__USERNAME__` placeholders)

**Per-user ttyd spawning:**
- On login, spawns: `sshpass -p <pass> ssh <user>@127.0.0.1 "/usr/local/bin/ttyd -W -p <port> bash -l"`
- Ports are allocated starting from 7700, incrementing per user
- Existing instances are reused if the process is still alive
- Each user's ttyd runs as their own system user (via SSH), providing proper UID isolation

**Session cookie format:** `username:timestamp:hmac_signature`
- Signed with a random secret key (regenerated on restart)
- Expires after 24 hours
- `HttpOnly` + `SameSite=Strict` flags for security

**Location:** `/Users/mli/ttyd-auth/auth.py`
**Port:** 7682 (localhost only)

### 4. Per-user ttyd Instances

**What it does:** Provides browser-based terminals using xterm.js. Each logged-in user gets their own ttyd instance running as their system user.

**How it works:**
- The auth service spawns a ttyd process via SSH for each authenticated user
- Each instance listens on a unique port (7700, 7701, 7702, ...)
- Runs `bash -l` (login shell) directly — no SSH login prompt in the terminal
- The wrapper app iframe points to `/ut/<port>/` which nginx routes to the correct instance
- Runs with `-W` (writable) flag to allow keyboard input

**Spawn command:**
```
sshpass -p <password> ssh -o StrictHostKeyChecking=no -o PubkeyAuthentication=no \
  -o ServerAliveInterval=30 <user>@127.0.0.1 \
  "/usr/local/bin/ttyd -W -p <port> bash -l"
```

**Important:** Must use full path `/usr/local/bin/ttyd` because SSH login shells may not have `/usr/local/bin` in PATH.

### 5. Wrapper App (Navbar + Tabs + Settings)

**What it does:** Provides a settings UI and tabbed interface around the terminal. Each tab is a separate ttyd iframe connection.

**Features:**
- **Tabs:** Multiple terminal sessions, each in its own iframe. Click `+ New Tab` or press `Ctrl+Shift+T`. Double-click a tab name to rename it.
- **Keyboard shortcuts:** `Ctrl+Shift+T` (new tab), `Ctrl+Shift+W` (close tab), `Ctrl+Shift+]` (next tab), `Ctrl+Shift+[` (prev tab)
- **Settings panel:** Font size, font family (Menlo, Monaco, Consolas, etc.), cursor style (block/underline/bar), cursor blink, scrollback buffer size, disable leave alert
- **Themes panel:** 8 preset themes (Default Dark, Light, Monokai, Solarized Dark, Dracula, Nord, Gruvbox, Tokyo Night) + custom color pickers for background, foreground, cursor, and selection colors
- **Fullscreen:** Puts the terminal iframe into browser fullscreen mode
- **Reconnect:** Reloads the terminal iframe (new session)
- **Logout:** Clears the session cookie and redirects to login

**Settings persistence:** All settings are saved to `localStorage` and restored on page load.

## Request Flow

### Initial visit (unauthenticated)

```
1. Browser → https://micsmac-ssh.micstec.com/
2. Cloudflare edge → cloudflared tunnel → nginx :7680
3. nginx: location = / → auth_request /api/auth
4. nginx → auth service :7682 /api/auth → 401 (no cookie)
5. nginx: error_page 401 → 302 redirect to /login
6. Browser → /login → auth service serves login HTML
```

### Login

```
1. Browser POST /api/login { username, password }
2. nginx → auth service :7682 → validates via sshpass+SSH
3. Auth service spawns: sshpass -p <pass> ssh <user>@127.0.0.1 "/usr/local/bin/ttyd -W -p 7700 bash -l"
4. Auth service → 200 + Set-Cookie: ttyd_session=<signed_token> + { "ok": true, "port": 7700 }
5. Browser redirects to /
```

### Authenticated visit

```
1. Browser → /
2. nginx: auth_request → auth service checks cookie → 200 ✓
3. nginx: proxy_pass → auth service /app → wrapper HTML (with port 7700 injected)
4. Browser renders navbar + tabs + iframe src="/ut/7700/"
5. iframe → /ut/7700/ → nginx regex match → proxy to 127.0.0.1:7700
6. nginx: auth_request → 200 ✓ → ttyd HTML
7. iframe → /ut/7700/ws (WebSocket upgrade) → nginx → ttyd
8. User sees terminal running bash -l as their own system user
```

## File Locations

| File | Purpose |
|------|---------|
| `~/.cloudflared/config.yml` | Tunnel configuration |
| `~/.cloudflared/<ID>.json` | Tunnel credentials |
| `~/Library/LaunchAgents/com.cloudflare.cloudflared.plist` | cloudflared service plist |
| `/usr/local/etc/nginx/servers/ttyd.conf` | nginx virtual host config |
| `~/ttyd-auth/auth.py` | Auth service + web UI + per-user ttyd management |
| `~/Library/Logs/com.cloudflare.cloudflared.err.log` | cloudflared error log |
| `~/Library/Logs/com.cloudflare.cloudflared.out.log` | cloudflared output log |
| `~/Library/Logs/ttyd-auth.log` | Auth service log |

## Port Summary

| Port | Service | Binding | Exposed Externally |
|------|---------|---------|:---:|
| 443 | Cloudflare edge (HTTPS) | — | Yes (via Cloudflare) |
| 7680 | nginx | localhost | No |
| 7682 | Auth service | localhost | No |
| 7700+ | Per-user ttyd instances | localhost | No |

No ports are opened on the firewall. All external access goes through the Cloudflare Tunnel.

## Managing the Services

### Check tunnel status
```bash
cloudflared tunnel info micsmacssh
```

### Restart cloudflared
```bash
launchctl unload ~/Library/LaunchAgents/com.cloudflare.cloudflared.plist
launchctl load ~/Library/LaunchAgents/com.cloudflare.cloudflared.plist
```

### Restart nginx
```bash
nginx -t && nginx -s reload
```

### Restart auth service
```bash
lsof -ti:7682 | xargs kill -9  # kill existing
python3 ~/ttyd-auth/auth.py > ~/Library/Logs/ttyd-auth.log 2>&1 &
```

### Kill all per-user ttyd instances
```bash
pkill -f "ttyd -W -p 77"
```

### View logs
```bash
tail -f ~/Library/Logs/com.cloudflare.cloudflared.err.log  # tunnel
tail -f ~/Library/Logs/ttyd-auth.log                        # auth
```

## Security Notes

- **No open ports:** The tunnel is outbound-only. No firewall ports need to be opened.
- **All services bind to localhost:** nginx, ttyd instances, and the auth service only listen on 127.0.0.1.
- **Per-user isolation:** Each user's terminal runs under their own system UID via SSH. Users cannot access each other's shells.
- **HTTPS enforced:** Cloudflare terminates TLS. Browser ↔ Cloudflare is HTTPS. Cloudflare ↔ tunnel is encrypted via QUIC.
- **Session cookies:** HMAC-SHA256 signed, HttpOnly, SameSite=Strict. 24-hour expiry.
- **Auth on every request:** nginx `auth_request` checks the session cookie on every protected route, including WebSocket upgrades.
- **No client-side software required:** Only a web browser is needed to access the terminal.

## Known Limitations

- **Session key regenerates on auth service restart:** All active sessions are invalidated. Users must log in again. Per-user ttyd instances are also killed.
- **Single concurrent shell per tab:** Each tab spawns a separate WebSocket connection to the same ttyd instance. Closing a tab disconnects that shell.
- **No persistent sessions:** Shell state is lost on reconnect. Consider using `tmux` or `screen` inside the terminal for session persistence.
- **Per-user ttyd cleanup:** ttyd instances stay alive as long as the SSH connection is maintained. They are cleaned up when the auth service restarts or the SSH keep-alive expires.
- **Port allocation:** Ports are allocated sequentially starting from 7700. If the auth service restarts, port numbering resets (old instances on those ports must be dead first).
