# micsapp-webterminal — Agent-Readable Codebase Reference

## File Map

```
/home/mli/micsapp-webterminal/
├── auth.py                   # Core service (~4600 lines): auth, web UI, file browser, terminal mgmt
├── nginx/ttyd.conf           # Reverse proxy & WebSocket routing
├── deploy.sh                 # Service lifecycle management (~700 lines)
├── cf_tunnel_install.sh      # One-time setup (~4400 lines); embeds auth.py inline (lines 506-5100)
├── create-user.sh            # System user creation helper
├── login.sh                  # Quick login script
├── .env.example              # Environment config template
└── CODEBASE.md               # This file
```

## Architecture

```
Browser (HTTPS)
  → Cloudflare Edge (443)
    → cloudflared tunnel (QUIC → HTTP :7680)
      → nginx (127.0.0.1:7680)
        ├── /login, /api/login         → auth.py (7682)   [Login page + API]
        ├── /api/auth                  → auth.py (7682)   [Session validation, internal]
        ├── /app                       → auth.py (7682)   [Main SPA wrapper]
        ├── /api/files/*, /api/quick-* → auth.py (7682)   [File browser + commands]
        ├── /api/term-hook.js          → auth.py (7682)   [Script injected into ttyd HTML]
        └── /ut/<port>/*               → ttyd (7700+)     [Per-user terminal via WebSocket]
```

## Environment

- WSL2 (no systemd) — uses `service` commands and nohup/tmux
- `/home/mli/bin/ss` is broken — use `/usr/sbin/ss` or `lsof` for port checks
- Tunnel config: `~/.cloudflared/config.yml`, cloudflared runs in tmux session `cloudflared`

---

## auth.py Structure (Line Map)

### Python backend (lines 1-139, 3469-end)

| Lines       | Section                        |
|-------------|--------------------------------|
| 1-48        | Imports, load_dotenv, env_bool |
| 49-70       | Config constants (SECRET_KEY, SESSION_MAX_AGE, PORT, etc.) |
| 72-120      | Utility helpers (_safe_ascii_filename, content_disposition) |
| 121-138     | `authenticate(username, password)` — SSH-based auth |
| 3469-3580   | Per-user ttyd management (port_is_free, allocate_port, wait_for_ttyd_ready, spawn_user_ttyd) |
| 3581-3665   | Token management (make_token, verify_token, make_path_token, parse_path_token, breadcrumb_tokens) |
| 3665-3687   | `run_as_user()` — runs Python scripts as target user via SSH |
| 3688-end    | `AuthHandler(BaseHTTPRequestHandler)` — all HTTP handlers |

### Embedded HTML Templates

| Lines       | Template         | Description                            |
|-------------|------------------|----------------------------------------|
| 140-261     | `LOGIN_HTML`     | Login page (dark theme, form, fetch)   |
| 262-315     | `TERM_HOOK_JS`   | Injected into ttyd iframe via nginx sub_filter |
| 316-3468    | `APP_HTML`       | Main SPA (~3150 lines of HTML+CSS+JS)  |

### APP_HTML Internal Structure

```
316-322     : HTML head, meta tags
322-1285    : <style> block (all CSS)
  322-613   :   Navbar, tab bar, settings panel, theme panel CSS
  614-633   :   Main area layout (flex row: file panel + terminal)
  634-1000  :   File panel CSS
  1000-1230 :   Quick commands, copy modal, dialog modal CSS
  1237-1251 :   .term-container and iframe CSS
  1253-1284 :   Media queries (mobile responsive)
1287-1316   : Navbar HTML (buttons, hamburger, nav-right)
1318        : Tab bar (#tabBar)
1320-1344   : Special keys toolbar (mobile touch)
1345-1396   : Settings panel HTML
1398-1429   : Theme panel HTML
1431-1446   : Main area: file panel + #termContainer
1448-1533   : Modals (file preview, copy, dialog)
1535-1551   : <script> start: THEMES object, global state vars
1552-1574   : buildTermUrl() — builds iframe src with settings as query params
1576-1578   : saveTabs() — persist to localStorage
1580-1591   : addTab() — create tab + iframe + switchTab
1593-1606   : closeTab(id, e) — remove iframe + tab
1608-1617   : switchTab(id) — show/hide iframes via .active class
1619-1648   : renderTabs() — rebuild tab bar DOM
1650-1676   : startRename(id, labelEl) — inline edit tab name
1683-1717   : getSettings() — read all settings from DOM/localStorage
1718-2082   : wireSettingsPersistence(), settings/theme wiring
2083-2085   : isCoarsePointer() — touch device detection
2186-2204   : reconnectAllTabsNoLeaveAlert(), quickAdjustFontSize()
2206-2218   : applySettings(initial) — reload all iframes with new settings
2220-2277   : selectTheme(), applyThemeUI(), fullscreen(), reconnect(), logout()
2279-2304   : Keyboard shortcuts (Ctrl+Shift+T/W/[/])
2306-2480   : Hamburger menu, special keys handler, init/boot code
2440-2460   : Tab restoration from localStorage (staggered iframe creation)
2482-3468   : File browser, quick commands, copy modal, dialog system
```

---

## Key JavaScript Globals & Functions

### State

```javascript
let tabs = [];           // Array of {id: "tab-N", name: "Shell N"}
let activeTabId = null;  // Currently visible tab ID
let tabCounter = 0;      // Auto-increment for tab naming
let currentTheme = 'default';
```

### Tab Lifecycle

| Function | Line | Purpose |
|----------|------|---------|
| `addTab()` | 1580 | Create iframe + tab object, switchTab, renderTabs, saveTabs |
| `closeTab(id, e)` | 1593 | Remove iframe + tab, switch to adjacent |
| `switchTab(id)` | 1608 | Hide all iframes, show target (toggle `.active` class) |
| `renderTabs()` | 1619 | Rebuild tab bar buttons from `tabs[]` array |
| `saveTabs()` | 1576 | Persist to `localStorage.ttyd_tabs` |
| `startRename(id, labelEl)` | 1650 | Inline edit mode on double-click |
| `buildTermUrl(overrides)` | 1552 | Build `/ut/__TTYD_PORT__/?settings...` URL |

### Terminal Container Layout

```css
.term-container {         /* Line 1237 */
  flex: 1;
  min-height: 0;
  min-width: 0;
  position: relative;
}
.term-container iframe {  /* Line 1243 */
  position: absolute;     /* All stacked on top of each other */
  top: 0; left: 0;
  width: 100%; height: 100%;
  border: none;
  display: none;          /* Hidden by default */
}
.term-container iframe.active { display: block; }  /* Line 1251 */
```

**Current model**: All iframes are `position: absolute` and stacked. Only the active one has `display: block`. This must change for split screen (need multiple visible iframes in a flex layout).

### Settings & Apply

| Function | Line | Purpose |
|----------|------|---------|
| `getSettings()` | 1683 | Read all settings from DOM inputs + localStorage |
| `applySettings(initial)` | 2206 | Reload ALL iframes with new URL (settings as query params) |
| `reconnectAllTabsNoLeaveAlert()` | 2186 | Reload all iframes without triggering leave alerts |

### Keyboard Shortcuts (Line 2280)

| Shortcut | Action |
|----------|--------|
| Ctrl+Shift+T | New Tab |
| Ctrl+Shift+W | Close Tab |
| Ctrl+Shift+] | Next Tab |
| Ctrl+Shift+[ | Previous Tab |
| Escape | Close modals |

### Boot Sequence (Line 2440)

1. Restore tabs from `localStorage.ttyd_tabs`
2. If saved tabs exist: create tab objects, render tab bar, switch to first tab
3. Create iframes with **300ms stagger** (important: tmux needs time to register sessions)
4. If no saved tabs: call `addTab()` (creates "Shell 1")

---

## DOM Layout

```
body (fixed, flex column)
├── .navbar (42px, flex row)
│   ├── .title ("◻ USERNAME")
│   ├── nav buttons (New Tab, A-, A+, Commands, Files, Settings, Themes, Fullscreen, Reconnect)
│   ├── .hamburger (mobile only)
│   ├── .nav-dropdown (mobile menu)
│   └── .nav-right (Logout)
├── .tab-bar#tabBar (32px, flex row, scrollable)
│   └── .tab (per tab: label + close button)
├── .special-keys#specialKeys (mobile touch toolbar, hidden on desktop)
├── .settings-panel#settingsPanel (toggleable, absolute positioned)
├── .settings-panel#themePanel (toggleable, absolute positioned)
├── .main-area (flex: 1, flex row)
│   ├── .file-panel#filePanel (300px wide, left sidebar, toggleable)
│   └── .term-container#termContainer (flex: 1, position: relative)
│       ├── iframe#frame-tab-1 (absolute, display:none or block)
│       ├── iframe#frame-tab-2 (absolute, display:none)
│       └── ... more iframes
├── .fp-modal-overlay#fpModal (file preview modal)
├── .copy-modal-overlay#copyModal (copy text modal)
└── .dlg-overlay#dlgOverlay (alert/confirm/prompt dialog)
```

---

## nginx/ttyd.conf Key Routes

```nginx
server {
    listen 7680;
    server_name micsmac-ssh.micstec.com;

    # Auth subrequest (internal only)
    location = /api/auth {
        internal;
        proxy_pass http://127.0.0.1:7682;
        proxy_set_header X-TTYD-Port $ttyd_port;  # For port binding validation
    }

    # Login (no auth required)
    location = /login { proxy_pass http://127.0.0.1:7682; }
    location = /api/login { proxy_pass http://127.0.0.1:7682; }

    # Main app (auth required, redirects to /login on 401)
    location = / {
        auth_request /api/auth;
        error_page 401 = @login_redirect;
        proxy_pass http://127.0.0.1:7682/app;
    }

    # Per-user ttyd terminal (dynamic port routing + WebSocket upgrade)
    location ~ ^/ut/(\d+)/(.*) {
        set $ttyd_port $1;
        auth_request /api/auth;
        proxy_pass http://127.0.0.1:$1/$2$is_args$args;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        # Injects term-hook.js into ttyd HTML:
        sub_filter '</head>' '<script src="/api/term-hook.js"></script></head>';
    }
}
```

---

## cf_tunnel_install.sh Sync Pattern

The install script embeds auth.py inline as a heredoc:

```bash
# Line 506:
cat > "${auth_dir}/auth.py" <<'AUTHEOF'
#!/usr/bin/env python3
... (entire auth.py content) ...
AUTHEOF
# Line 5100: end of heredoc

# Line 5102-5106: post-processing (sed replaces TTYD_PATH_PLACEHOLDER)
```

**When modifying auth.py, the embedded copy in cf_tunnel_install.sh (lines 507-5099) must be updated to match.**

Procedure:
1. Edit auth.py directly
2. Find the heredoc bounds in cf_tunnel_install.sh (between `<<'AUTHEOF'` at line 506 and `AUTHEOF` at line 5100)
3. Replace lines 507-5099 with the updated auth.py content
4. Note: the embedded copy uses `TTYD_PATH_PLACEHOLDER` where auth.py uses the actual ttyd path — this is replaced by sed at deploy time

---

## Per-User ttyd Spawning (auth.py line 3516)

1. Check for existing instance in `user_instances[username]`
2. `allocate_port()` → next free port from 7700+
3. Build tmux command: creates/reuses `main` session, assigns window per tab
4. Launch: `sshpass -p <pw> ssh user@127.0.0.1 "ttyd -W -i 127.0.0.1 -p <port> bash -lc '<tmux_cmd>'"`
5. `wait_for_ttyd_ready(port, timeout=4.0)` — socket connect test
6. Track in `user_instances[username] = {port, proc, password}`

Each tab creates a **separate WebSocket connection** to the same ttyd port. Each connection gets its own tmux grouped session (auto-cleanup on disconnect).

---

## Security Model

- **Auth**: SSH to localhost validates system credentials
- **Tokens**: HMAC-SHA256 signed `username:port:timestamp:signature`, 24h expiry
- **Cookies**: `__Host-ttyd_session`, HttpOnly, SameSite=Strict, Secure
- **Port binding**: Token includes ttyd port; nginx passes `X-TTYD-Port` header for cross-check
- **File paths**: Base64+HMAC signed path tokens prevent directory traversal
- **Binding**: All services bind to 127.0.0.1 only; external access only through Cloudflare tunnel

---

## Mobile Support

- Hamburger menu replaces desktop nav buttons at `@media (max-width: 600px)`
- Special keys toolbar visible on `@media (pointer: coarse)` (touch devices)
- `isCoarsePointer()` (line 2083) returns true for touch → uses DOM renderer for copy support
- File panel items show action buttons on touch devices

---

## Split Screen System

Added in the `APP_HTML` frontend (purely client-side, no backend changes).

### Data Structure
Binary tree: each node is either `{type:'pane', tabId}` or `{type:'split', direction:'h'|'v', ratio:0.5, children:[node,node]}`.

### Responsive Breakpoints
- **Phone (<768px)**: No split, tabs only
- **Tablet (768-1023px)**: Max 2 panes, no nesting
- **Desktop (1024px+)**: Full nesting support

### Keyboard Shortcuts
| Shortcut | Action |
|----------|--------|
| Ctrl+Shift+\\ | Split Right |
| Ctrl+Shift+- | Split Down |
| Ctrl+Shift+U | Unsplit |

### Key Functions (auth.py)
| Function | Purpose |
|----------|---------|
| `splitDirection(dir)` | Core split logic, creates/nests split nodes |
| `splitRight()` / `splitDown()` | Convenience wrappers |
| `unsplit()` | Collapse all splits back to single pane |
| `closeSplitPane(tabId)` | Remove one pane, promote sibling |
| `renderSplitLayout()` | Build DOM from split tree |
| `renderSingleLayout()` | Restore flat iframe layout |
| `buildSplitDOM(node)` | Recursive DOM builder |
| `focusSplitPane(tabId)` | Set active pane (pink border) |
| `startDividerDrag()` | Mouse drag to resize panes |
| `saveSplitState()` / `restoreSplitState()` | localStorage persistence |
| `getAllIframes()` | Returns all iframes (works in both modes) |

### Persistence
- Split tree saved to `localStorage.ttyd_split` as JSON
- Restored on page load (after tab iframes are created)
- Auto-collapsed if window resizes below 768px

---

## Key Constants

| Constant | Default | Env Var | Purpose |
|----------|---------|---------|---------|
| SECRET_KEY | random per restart | TTYD_SECRET | HMAC signing |
| SESSION_MAX_AGE | 86400 (24h) | SESSION_MAX_AGE | Token expiry |
| PORT | 7682 | AUTH_PORT | Auth service listen port |
| TTYD_START_PORT | 7700 | TTYD_START_PORT | First user ttyd port |
| COOKIE_NAME | __Host-ttyd_session | SESSION_COOKIE_NAME | HTTP cookie name |
