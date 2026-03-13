# Product Requirements Document (PRD)

## micsapp-webterminal — Browser-Based Multi-Tenant Terminal

| Field | Value |
|-------|-------|
| **Product Name** | micsapp-webterminal |
| **Version** | 1.0 |
| **Repository** | github.com/micsapp/micsapp-webterminal |
| **Status** | Production |

---

## 1. Overview

micsapp-webterminal is a browser-based, multi-tenant terminal system that provides isolated shell access to system users over the internet. It combines a custom authentication service, per-user terminal instances, a file browser, and a rich SPA frontend — all exposed securely through a Cloudflare Tunnel with zero open inbound ports.

### 1.1 Problem Statement

System administrators and remote users need secure shell access to shared Linux/macOS servers without installing SSH clients, managing VPNs, or opening firewall ports. Existing solutions (raw SSH, web-based jump hosts) either require client-side software, lack multi-user isolation, or expose open ports to the internet.

### 1.2 Solution

A zero-install, browser-only terminal that:
- Authenticates users against the host's system accounts (PAM/SSH)
- Provides each user an isolated shell running under their own UID
- Exposes nothing to the public internet — all traffic flows through an encrypted Cloudflare Tunnel
- Offers a modern tabbed UI with split panes, theming, a file browser, quick commands, and remote desktop (VNC)

### 1.3 Target Users

| Persona | Description |
|---------|-------------|
| **System Administrator** | Deploys and manages the service on one or more servers |
| **Remote Developer / User** | Accesses their shell from any device with a browser |
| **Mobile User** | Performs quick terminal tasks from a phone or tablet |

---

## 2. Goals & Success Metrics

| Goal | Metric |
|------|--------|
| Zero-install access | Users need only a modern web browser |
| Per-user isolation | Each session runs under the user's own UID; no cross-user access |
| No open ports | All external traffic flows through Cloudflare Tunnel (outbound-only) |
| Low latency | Terminal keystroke round-trip < 100ms on standard connections |
| Session resilience | Shell processes survive browser close/refresh via tmux |
| Mobile usability | Fully functional on phones/tablets with adaptive UI |
| Easy deployment | Single-script install (`cf_tunnel_install.sh`) provisions the entire stack |

---

## 3. Architecture

### 3.1 System Components

```
Browser (HTTPS)
  → Cloudflare Edge (443)
    → cloudflared tunnel (QUIC → HTTP :7680)
      → nginx (127.0.0.1:7680)
        ├── /login, /api/login         → auth.py (7682)   [Login + Auth API]
        ├── /api/auth                  → auth.py (7682)   [Session validation]
        ├── /app                       → auth.py (7682)   [Main SPA]
        ├── /api/files/*, /api/quick-* → auth.py (7682)   [File browser + commands]
        ├── /api/term-hook.js          → auth.py (7682)   [Injected terminal script]
        └── /ut/<port>/*               → ttyd (7700+)     [Per-user terminal]
```

### 3.2 Component Responsibilities

| Component | Port | Role |
|-----------|------|------|
| **cloudflared** | — | Outbound-only encrypted tunnel to Cloudflare edge |
| **nginx** | 7680 | Reverse proxy, auth gating (`auth_request`), WebSocket upgrade, script injection (`sub_filter`) |
| **auth.py** | 7682 | Authentication, session management, SPA serving, file API, ttyd lifecycle management |
| **ttyd** | 7700+ | Per-user WebSocket terminal (one instance per authenticated user) |
| **tmux** | — | Session persistence; each tab is a tmux grouped session |
| **sshd** | 22 | Localhost-only; used for credential validation and UID isolation |

### 3.3 Technology Stack

| Layer | Technology |
|-------|------------|
| Frontend | Single-page HTML/CSS/JS embedded in `auth.py` (zero build step) |
| Backend | Python 3 stdlib only (`http.server`, `hmac`, `subprocess`) |
| Terminal | ttyd + xterm.js (WebSocket) |
| Session Mgmt | tmux (grouped sessions per user) |
| Proxy | nginx with `auth_request` and `sub_filter` modules |
| Tunnel | Cloudflare Tunnel (cloudflared) |
| Auth | System PAM via `sshpass` + SSH to localhost |

---

## 4. Functional Requirements

### 4.1 Authentication & Sessions

| ID | Requirement | Priority |
|----|-------------|----------|
| AUTH-01 | Users authenticate with system (Linux/macOS) username and password | P0 |
| AUTH-02 | Credentials are validated via `sshpass + ssh` to localhost (PAM) | P0 |
| AUTH-03 | On success, issue an HMAC-SHA256 signed session cookie | P0 |
| AUTH-04 | Cookie attributes: `HttpOnly`, `SameSite=Strict`, `Secure`, `__Host-` prefix | P0 |
| AUTH-05 | Session expiry: configurable, default 24 hours | P0 |
| AUTH-06 | nginx `auth_request` validates cookie on every protected route including WebSocket upgrades | P0 |
| AUTH-07 | Unauthenticated requests redirect to `/login` | P0 |
| AUTH-08 | Logout clears the session cookie and redirects to login | P0 |
| AUTH-09 | Token includes the user's allocated ttyd port; nginx cross-checks via `X-TTYD-Port` header | P1 |

### 4.2 Terminal Management

| ID | Requirement | Priority |
|----|-------------|----------|
| TERM-01 | On first login, spawn a per-user ttyd instance via SSH as the authenticated user | P0 |
| TERM-02 | ttyd runs with `-W` (writable) flag, binding to `127.0.0.1` only | P0 |
| TERM-03 | Port allocation: sequential from 7700+; reuse existing instance if alive | P0 |
| TERM-04 | Each tab opens a separate WebSocket connection to the user's ttyd | P0 |
| TERM-05 | Each connection gets its own tmux grouped session (auto-cleanup on disconnect) | P0 |
| TERM-06 | Shell processes survive browser close/refresh (tmux persistence) | P1 |
| TERM-07 | Wait for ttyd to be ready (socket connect test, 4s timeout) before returning port to client | P1 |
| TERM-08 | Inject `term-hook.js` into ttyd HTML via nginx `sub_filter` for cross-frame communication | P1 |

### 4.3 Tabbed Interface

| ID | Requirement | Priority |
|----|-------------|----------|
| TAB-01 | Multiple concurrent terminal tabs, each in a separate iframe | P0 |
| TAB-02 | Create new tab: button click or `Ctrl+Shift+T` | P0 |
| TAB-03 | Close tab: button click or `Ctrl+Shift+W` | P0 |
| TAB-04 | Switch tabs: click or `Ctrl+Shift+[` / `Ctrl+Shift+]` | P0 |
| TAB-05 | Rename tab: double-click the tab label for inline editing | P1 |
| TAB-06 | Tab state persisted to `localStorage`; restored on page reload with 300ms staggered iframe creation | P1 |
| TAB-07 | Scrollable tab bar for many open tabs | P2 |

### 4.4 Split Panes

| ID | Requirement | Priority |
|----|-------------|----------|
| SPLIT-01 | Split the terminal view horizontally (side-by-side) or vertically (stacked) | P1 |
| SPLIT-02 | Data structure: binary tree of pane/split nodes with configurable ratio | P1 |
| SPLIT-03 | Drag dividers to resize panes | P1 |
| SPLIT-04 | Focus a pane by clicking it (visual indicator: highlighted border) | P1 |
| SPLIT-05 | Unsplit: collapse all splits back to single pane | P1 |
| SPLIT-06 | Keyboard shortcuts: `Ctrl+Shift+\` (split right), `Ctrl+Shift+-` (split down), `Ctrl+Shift+U` (unsplit) | P1 |
| SPLIT-07 | Responsive breakpoints: no split on phone (<768px), max 2 panes on tablet (768–1023px), full nesting on desktop (1024px+) | P1 |
| SPLIT-08 | Split state persisted to `localStorage`; auto-collapsed if window resizes below 768px | P2 |

### 4.5 Settings & Themes

| ID | Requirement | Priority |
|----|-------------|----------|
| SET-01 | Configurable: font size (8–36px), font family, cursor style (block/underline/bar), cursor blink, scrollback lines (100–100k), disable leave alert | P1 |
| SET-02 | Quick font size adjustment via A-/A+ toolbar buttons | P1 |
| SET-03 | "Apply to All Tabs" reloads all iframes with updated settings as query params | P1 |
| SET-04 | All settings saved to `localStorage` and restored on next visit | P1 |
| THEME-01 | 8 preset themes: Default Dark, Light, Monokai, Solarized Dark, Dracula, Nord, Gruvbox, Tokyo Night | P1 |
| THEME-02 | Custom color pickers for background, foreground, cursor, and selection colors | P2 |
| THEME-03 | Theme applied to all tabs via "Apply to All Tabs" | P1 |

### 4.6 File Browser

| ID | Requirement | Priority |
|----|-------------|----------|
| FILE-01 | Toggle sidebar file browser panel (300px wide, left side) | P1 |
| FILE-02 | Navigate directories: click to enter, `..` to go up, breadcrumb path segments | P1 |
| FILE-03 | Direct path input: double-click breadcrumb bar to type a path | P2 |
| FILE-04 | Upload files: button click or drag-and-drop | P1 |
| FILE-05 | Paste image from clipboard | P2 |
| FILE-06 | Create new folders | P1 |
| FILE-07 | Download, rename, delete files (with confirmation) | P1 |
| FILE-08 | File preview modal: text (with syntax highlighting, inline editing), markdown (rendered HTML with source toggle), images, video/audio (embedded player), PDF (embedded viewer) | P1 |
| FILE-09 | Column sorting: name, date, size | P2 |
| FILE-10 | All file operations run as the authenticated user via `run_as_user()` (SSH) for UID isolation | P0 |
| FILE-11 | Path tokens: Base64 + HMAC-signed to prevent directory traversal | P0 |

### 4.7 Quick Commands

| ID | Requirement | Priority |
|----|-------------|----------|
| CMD-01 | Library of saved terminal commands runnable with one click | P2 |
| CMD-02 | Search/filter by name, text, or tag | P2 |
| CMD-03 | Tag-based categorization with clickable tag chips | P2 |
| CMD-04 | Add, edit, delete commands | P2 |
| CMD-05 | Commands stored server-side and shared across sessions | P2 |

### 4.8 Remote Desktop (VNC)

| ID | Requirement | Priority |
|----|-------------|----------|
| VNC-01 | Open a graphical desktop session via noVNC in a dedicated tab | P2 |
| VNC-02 | Connects to the server's VNC display through a WebSocket proxy | P2 |
| VNC-03 | noVNC controls: sidebar toggle, fullscreen, settings | P2 |

### 4.9 Mobile Support

| ID | Requirement | Priority |
|----|-------------|----------|
| MOB-01 | Hamburger menu replaces toolbar buttons at ≤600px width | P1 |
| MOB-02 | Special keys touch toolbar: Ctrl, Shift, Alt, Tab, Enter, Delete, arrow keys | P1 |
| MOB-03 | Touch-friendly copy modal for reliable clipboard access | P1 |
| MOB-04 | File panel action buttons visible on touch devices | P2 |
| MOB-05 | Split panes disabled below 768px width | P1 |

---

## 5. Non-Functional Requirements

### 5.1 Security

| ID | Requirement | Priority |
|----|-------------|----------|
| SEC-01 | All services bind to `127.0.0.1` only — no direct external exposure | P0 |
| SEC-02 | All external access through Cloudflare Tunnel (outbound-only, zero open ports) | P0 |
| SEC-03 | Browser ↔ Cloudflare: HTTPS (TLS). Cloudflare ↔ tunnel: encrypted QUIC | P0 |
| SEC-04 | Session cookies: HMAC-SHA256, `HttpOnly`, `SameSite=Strict`, `Secure`, `__Host-` prefix | P0 |
| SEC-05 | Auth check on every protected request including WebSocket upgrades (nginx `auth_request`) | P0 |
| SEC-06 | Per-user UID isolation: terminals and file operations run as the authenticated system user | P0 |
| SEC-07 | File path tokens signed with HMAC to prevent directory traversal attacks | P0 |
| SEC-08 | Token includes ttyd port for port-binding cross-validation | P1 |

### 5.2 Performance

| ID | Requirement |
|----|-------------|
| PERF-01 | Terminal latency: target < 100ms keystroke round-trip |
| PERF-02 | Iframe creation staggered at 300ms to avoid tmux session registration race conditions |
| PERF-03 | Zero external dependencies in auth.py (Python stdlib only) — fast cold start |
| PERF-04 | Reuse existing ttyd instance for returning users (no re-spawn overhead) |

### 5.3 Reliability

| ID | Requirement |
|----|-------------|
| REL-01 | tmux sessions persist shell processes across browser disconnects |
| REL-02 | Reconnect button reloads terminal iframe without losing tmux session |
| REL-03 | `deploy.sh` health-checks each component and only starts what's down |
| REL-04 | `wait_for_ttyd_ready()` ensures ttyd is accepting connections before returning port |

### 5.4 Compatibility

| ID | Requirement |
|----|-------------|
| COMPAT-01 | Host OS: Linux (WSL2) and macOS |
| COMPAT-02 | Browser: any modern browser with WebSocket support (Chrome, Firefox, Safari, Edge) |
| COMPAT-03 | Mobile: iOS Safari, Android Chrome — responsive layout with touch adaptations |

### 5.5 Deployment

| ID | Requirement |
|----|-------------|
| DEPLOY-01 | One-command install via `cf_tunnel_install.sh` (provisions entire stack including auth.py inline) |
| DEPLOY-02 | `deploy.sh` manages service lifecycle: start, restart, status check |
| DEPLOY-03 | Supports macOS (LaunchAgent) and Linux/WSL2 (tmux/nohup, `service` commands) |
| DEPLOY-04 | Configuration via `.env` file or environment variables |
| DEPLOY-05 | When `auth.py` is modified, the embedded copy in `cf_tunnel_install.sh` must be synced |

---

## 6. User Flows

### 6.1 First-Time Login

```
1. User navigates to https://<hostname>/
2. nginx auth_request → 401 (no cookie) → redirect to /login
3. User enters system username + password
4. POST /api/login → auth.py validates via sshpass+SSH
5. auth.py spawns per-user ttyd on port 7700+ (if not already running)
6. Response: 200 + Set-Cookie + { port: 7700 }
7. Browser redirects to / → nginx auth_request → 200 ✓
8. auth.py serves SPA with user's port injected
9. SPA creates first tab → iframe loads /ut/7700/ → WebSocket → terminal
```

### 6.2 Returning Visit (Valid Session)

```
1. User navigates to https://<hostname>/
2. nginx auth_request → 200 ✓ (valid cookie)
3. auth.py serves SPA
4. SPA restores tabs from localStorage (staggered 300ms iframe creation)
5. Each iframe reconnects to tmux session via WebSocket
```

### 6.3 Working with Multiple Tabs & Split Panes

```
1. User presses Ctrl+Shift+T → new tab created
2. User presses Ctrl+Shift+\ → view splits horizontally
3. User clicks left pane → focuses it → switches tab in tab bar
4. User drags divider to resize
5. Split state auto-saved to localStorage
```

### 6.4 File Management

```
1. User clicks Files → sidebar opens
2. User navigates to target directory
3. User drags file onto sidebar → uploads as authenticated user
4. User clicks a file → preview modal opens (text/image/pdf)
5. User edits text file inline → saves
```

---

## 7. Configuration

| Parameter | Default | Env Variable | Description |
|-----------|---------|--------------|-------------|
| Secret Key | Random per restart | `TTYD_SECRET` | HMAC signing key |
| Session Max Age | 86400 (24h) | `SESSION_MAX_AGE` | Token expiry in seconds |
| Auth Port | 7682 | `AUTH_PORT` | Auth service listen port |
| ttyd Start Port | 7700 | `TTYD_START_PORT` | First port for user ttyd instances |
| Cookie Name | `__Host-ttyd_session` | `SESSION_COOKIE_NAME` | HTTP session cookie name |
| Cookie Secure | true | `COOKIE_SECURE` | Require HTTPS for cookies |
| Access Log | false | `ACCESS_LOG_ENABLED` | Enable HTTP access logging |
| sshpass Binary | auto-detect | `SSHPASS_BIN` | Path to sshpass |
| SSH Binary | auto-detect | `SSH_BIN` | Path to ssh |
| ttyd Binary | auto-detect | `TTYD_BIN` | Path to ttyd |

---

## 8. Known Limitations & Constraints

| # | Limitation |
|---|-----------|
| 1 | **Secret key regenerates on restart** — all sessions invalidated; users must re-login |
| 2 | **Port allocation resets on restart** — old ttyd instances on those ports must be dead first |
| 3 | **Single ttyd instance per user** — all tabs share the same ttyd port; separate WebSocket connections |
| 4 | **No built-in HTTPS** — relies on Cloudflare for TLS termination |
| 5 | **No multi-server support** — designed for single-host deployment |
| 6 | **Auth.py embedded in install script** — changes require syncing two files |
| 7 | **No 2FA / SSO** — authentication is system PAM credentials only |

---

## 9. Future Considerations

| Area | Description |
|------|-------------|
| **Persistent secret key** | Store `TTYD_SECRET` in `.env` to survive restarts without invalidating sessions |
| **SSO / OAuth integration** | Support SAML, OIDC, or Cloudflare Access for enterprise auth |
| **Multi-host support** | Route users to different backend servers |
| **Audit logging** | Log all terminal commands and file operations for compliance |
| **Session recording** | Record and replay terminal sessions |
| **Collaborative mode** | Shared terminal viewing for pair programming / support |
| **Plugin system** | Allow custom quick-command providers and file preview handlers |
| **Container isolation** | Run user shells in containers instead of directly on the host |

---

## 10. Glossary

| Term | Definition |
|------|------------|
| **ttyd** | Open-source terminal-over-WebSocket server using xterm.js |
| **tmux** | Terminal multiplexer providing session persistence and window management |
| **cloudflared** | Cloudflare's tunnel client; creates outbound-only encrypted connections |
| **auth_request** | nginx module that delegates auth decisions to an external HTTP service |
| **sub_filter** | nginx module that rewrites response body content (used to inject scripts) |
| **SPA** | Single Page Application — the main UI served as one HTML document |
| **PAM** | Pluggable Authentication Modules — Linux/macOS system auth framework |
| **HMAC-SHA256** | Hash-based Message Authentication Code used for token signing |
| **noVNC** | Browser-based VNC client using WebSockets |
