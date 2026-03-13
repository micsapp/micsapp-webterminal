# Web Terminal — Architecture Wiki

> **Author:** Solution Architecture Team  
> **Last Updated:** March 2026  
> **Audience:** Engineers, DevOps, Security Reviewers

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [High-Level System Architecture](#2-high-level-system-architecture)
3. [Network Topology & Traffic Flow](#3-network-topology--traffic-flow)
4. [Request Lifecycle](#4-request-lifecycle)
5. [Authentication & Session Management](#5-authentication--session-management)
6. [Per-User Terminal Isolation](#6-per-user-terminal-isolation)
7. [Reverse Proxy & Routing Layer](#7-reverse-proxy--routing-layer)
8. [Frontend SPA Architecture](#8-frontend-spa-architecture)
9. [File Browser Subsystem](#9-file-browser-subsystem)
10. [Security Architecture](#10-security-architecture)
11. [Deployment & Operations](#11-deployment--operations)
12. [Data Persistence Model](#12-data-persistence-model)
13. [Cross-Cutting Concerns](#13-cross-cutting-concerns)

---

## 1. Executive Summary

micsapp-webterminal is a **browser-based, multi-tenant terminal system** that provides isolated shell access to Linux/macOS system users over the internet. It requires **zero client-side software** — only a modern web browser.

**Key Design Decisions:**

| Decision | Rationale |
|----------|-----------|
| Cloudflare Tunnel (outbound-only) | Zero open ports, no VPN, no firewall rules |
| System PAM auth via SSH | Leverage existing user accounts — no separate user database |
| Python stdlib only (no pip deps) | Minimal attack surface, instant cold start, no dependency management |
| Embedded SPA in Python (no build step) | Single-file deployment, no Node.js/npm required on server |
| Per-user ttyd + tmux | OS-level UID isolation, session persistence across disconnects |

---

## 2. High-Level System Architecture

```mermaid
graph TB
    subgraph Internet
        Browser["🌐 Browser<br/>(Any device)"]
        CF["☁️ Cloudflare Edge<br/>(TLS termination)"]
    end

    subgraph Host["🖥️ Host Machine (127.0.0.1 only)"]
        CFD["cloudflared<br/>(Tunnel client)"]

        subgraph Proxy["Reverse Proxy Layer"]
            NGINX["nginx :7680<br/>auth_request + WebSocket<br/>+ sub_filter injection"]
        end

        subgraph App["Application Layer"]
            AUTH["auth.py :7682<br/>Authentication<br/>SPA Serving<br/>File API<br/>ttyd Lifecycle"]
        end

        subgraph Terminal["Terminal Layer"]
            TTYD1["ttyd :7701<br/>(alice)"]
            TTYD2["ttyd :7702<br/>(bob)"]
            TTYDN["ttyd :770N<br/>(user N)"]
        end

        subgraph Session["Session Layer"]
            TMUX1["tmux session<br/>alice: main"]
            TMUX2["tmux session<br/>bob: main"]
            TMUXN["tmux session<br/>user N: main"]
        end

        SSHD["sshd :22<br/>(localhost only)"]
        VNC["noVNC :6080<br/>(optional)"]
    end

    Browser -->|"HTTPS :443"| CF
    CF -->|"QUIC tunnel"| CFD
    CFD -->|"HTTP :7680"| NGINX
    NGINX -->|"auth subreq<br/>/api/* /app"| AUTH
    NGINX -->|"/ut/7701/*<br/>WebSocket"| TTYD1
    NGINX -->|"/ut/7702/*<br/>WebSocket"| TTYD2
    NGINX -->|"/ut/770N/*<br/>WebSocket"| TTYDN
    NGINX -->|"/noVNC/"| VNC
    AUTH -->|"sshpass+ssh<br/>credential check"| SSHD
    AUTH -->|"spawn ttyd<br/>as user UID"| SSHD
    TTYD1 --> TMUX1
    TTYD2 --> TMUX2
    TTYDN --> TMUXN
    AUTH -.->|"run_as_user()<br/>file ops"| SSHD

    classDef internet fill:#3b82f6,stroke:#1e40af,color:#fff
    classDef proxy fill:#22c55e,stroke:#15803d,color:#fff
    classDef app fill:#e94560,stroke:#b91c3c,color:#fff
    classDef terminal fill:#8b5cf6,stroke:#6d28d9,color:#fff
    classDef session fill:#64748b,stroke:#475569,color:#fff
    classDef infra fill:#06b6d4,stroke:#0e7490,color:#fff

    class Browser,CF internet
    class NGINX proxy
    class AUTH app
    class TTYD1,TTYD2,TTYDN terminal
    class TMUX1,TMUX2,TMUXN session
    class SSHD,VNC,CFD infra
```

### Component Inventory

| Component | Technology | Binding | Purpose |
|-----------|------------|---------|---------|
| **cloudflared** | Go binary | Outbound QUIC | Encrypted tunnel to Cloudflare edge |
| **nginx** | C (modules) | 127.0.0.1:7680 | Reverse proxy, auth gating, WebSocket upgrade, JS injection |
| **auth.py** | Python 3 stdlib | 127.0.0.1:7682 | Auth, SPA serving, file API, ttyd lifecycle |
| **ttyd** | C + xterm.js | 127.0.0.1:7700+ | Per-user WebSocket terminal emulator |
| **tmux** | C | — | Session multiplexer, process persistence |
| **sshd** | OpenSSH | 127.0.0.1:22 | PAM auth, UID isolation for spawning |
| **noVNC** | JS + Python | 127.0.0.1:6080 | Optional browser-based VNC |

---

## 3. Network Topology & Traffic Flow

```mermaid
graph LR
    subgraph External
        B["Browser"]
        CFE["Cloudflare<br/>Edge"]
    end

    subgraph Tunnel
        CFD["cloudflared"]
    end

    subgraph Localhost["127.0.0.1"]
        N["nginx<br/>:7680"]
        A["auth.py<br/>:7682"]
        T1["ttyd :7701"]
        T2["ttyd :7702"]
        S["sshd :22"]
    end

    B -->|"HTTPS 443<br/>TLS 1.3"| CFE
    CFE -->|"QUIC<br/>encrypted"| CFD
    CFD -->|"HTTP<br/>:7680"| N
    N <-->|"HTTP<br/>:7682"| A
    N <-->|"HTTP+WS<br/>:770x"| T1
    N <-->|"HTTP+WS<br/>:770x"| T2
    A -->|"SSH<br/>:22"| S

    style B fill:#3b82f6,color:#fff
    style CFE fill:#f59e0b,color:#1e293b
    style CFD fill:#f59e0b,color:#1e293b
    style N fill:#22c55e,color:#fff
    style A fill:#e94560,color:#fff
    style T1 fill:#8b5cf6,color:#fff
    style T2 fill:#8b5cf6,color:#fff
    style S fill:#06b6d4,color:#fff
```

**Key Network Properties:**

- **Zero open inbound ports** — `cloudflared` initiates 4 outbound QUIC connections
- **All services bind `127.0.0.1`** — unreachable from LAN or internet directly
- **No VPN or SSH tunnel required** by end users — browser-only access
- **TLS terminated at Cloudflare edge** — HTTPS between browser and Cloudflare; QUIC between Cloudflare and host

---

## 4. Request Lifecycle

### 4.1 Login Flow

```mermaid
sequenceDiagram
    participant B as Browser
    participant CF as Cloudflare
    participant N as nginx :7680
    participant A as auth.py :7682
    participant S as sshd :22
    participant T as ttyd :770x

    B->>CF: GET /
    CF->>N: HTTP :7680
    N->>A: auth_request /api/auth
    A-->>N: 401 (no cookie)
    N-->>B: 302 → /login

    B->>N: GET /login
    N->>A: proxy (no auth)
    A-->>B: Login HTML page

    B->>N: POST /api/login {user, pass}
    N->>A: proxy
    A->>S: sshpass + ssh user@127.0.0.1 echo ok
    S-->>A: exit 0 (credentials valid)

    Note over A: Spawn ttyd as user
    A->>S: ssh user@127.0.0.1 "ttyd -W -p PORT bash -lc 'tmux ...'"
    Note over A: Wait for ttyd ready (socket test, 4s timeout)
    A-->>B: 200 + Set-Cookie + {port: 7701}
    B->>N: 302 → /
```

### 4.2 Authenticated SPA + Terminal

```mermaid
sequenceDiagram
    participant B as Browser
    participant N as nginx :7680
    participant A as auth.py :7682
    participant T as ttyd :7701

    B->>N: GET / (with cookie)
    N->>A: auth_request /api/auth
    A-->>N: 200 OK (token valid)
    N->>A: proxy GET /app
    A-->>B: APP_HTML (SPA with port injected)

    Note over B: SPA creates iframe

    B->>N: iframe GET /ut/7701/
    N->>A: auth_request (verify port=7701 in token)
    A-->>N: 200 OK
    N->>T: proxy + sub_filter (inject term-hook.js)
    T-->>B: ttyd HTML + xterm.js

    B->>N: WebSocket /ut/7701/ws
    N->>T: WebSocket upgrade
    Note over B,T: Bidirectional terminal I/O via tmux
```

### 4.3 File Operations

```mermaid
sequenceDiagram
    participant B as Browser (SPA)
    participant N as nginx :7680
    participant A as auth.py :7682
    participant S as sshd :22

    B->>N: GET /api/files/list?token=...
    N->>A: auth_request /api/auth
    A-->>N: 200 OK
    N->>A: proxy
    Note over A: Verify path token HMAC
    A->>S: run_as_user() via sshpass+ssh
    Note over S: Execute as user's UID
    S-->>A: JSON result
    A-->>B: {entries, breadcrumbs, parent_token}
```

---

## 5. Authentication & Session Management

### 5.1 Token Architecture

```mermaid
graph LR
    subgraph Token Structure
        U["username"]
        P["port"]
        TS["timestamp"]
        SIG["HMAC-SHA256<br/>signature"]
    end

    subgraph Signing
        SK["SECRET_KEY"]
        HMAC["HMAC-SHA256"]
    end

    U --> HMAC
    P --> HMAC
    TS --> HMAC
    SK --> HMAC
    HMAC --> SIG

    style SK fill:#e94560,color:#fff
    style HMAC fill:#f59e0b,color:#1e293b
    style SIG fill:#22c55e,color:#fff
```

**Token format:** `username:port:timestamp:HMAC-SHA256(key, "username:port:timestamp")`

### 5.2 Cookie Properties

| Attribute | Value | Purpose |
|-----------|-------|---------|
| `Name` | `__Host-ttyd_session` | `__Host-` prefix enforces Secure + no Domain + Path=/ |
| `HttpOnly` | Yes | Inaccessible to JavaScript (XSS mitigation) |
| `Secure` | Yes | HTTPS only |
| `SameSite` | Strict | No cross-site transmission (CSRF mitigation) |
| `Max-Age` | 86400 | 24h expiry (configurable) |

### 5.3 Auth Verification Pipeline

```mermaid
flowchart TD
    REQ["Incoming Request"] --> EXTRACT["Extract cookie<br/>from header"]
    EXTRACT --> PARSE["Parse token<br/>user:port:ts:sig"]
    PARSE --> VERIFY["Verify HMAC<br/>SHA256(key, user:port:ts)"]

    VERIFY -->|"Valid"| EXPIRY["Check expiry<br/>now - ts < MAX_AGE"]
    VERIFY -->|"Invalid"| REJECT["401 Unauthorized"]

    EXPIRY -->|"Fresh"| PORT["Verify port binding<br/>X-TTYD-Port == port"]
    EXPIRY -->|"Expired"| REJECT

    PORT -->|"Match"| ALLOW["200 OK<br/>Set X-Auth-User header"]
    PORT -->|"Mismatch"| REJECT

    REJECT --> REDIRECT["nginx → 302 /login"]

    style ALLOW fill:#22c55e,color:#fff
    style REJECT fill:#ef4444,color:#fff
    style VERIFY fill:#f59e0b,color:#1e293b
```

**Port binding check:** When a request hits `/ut/7701/...`, nginx sets `X-TTYD-Port: 7701` in the auth subrequest. auth.py verifies that the token's port matches. This prevents User A from accessing User B's ttyd port.

---

## 6. Per-User Terminal Isolation

### 6.1 Isolation Model

```mermaid
graph TB
    subgraph Browser
        TAB1["Tab 1<br/>(iframe)"]
        TAB2["Tab 2<br/>(iframe)"]
        TAB3["Tab 3<br/>(iframe)"]
    end

    subgraph "alice (UID 1001) — port 7701"
        TTYD_A["ttyd :7701<br/>-W -i 127.0.0.1"]
        TMUX_A["tmux 'main' session"]
        W1["window 0<br/>(bash)"]
        W2["window 1<br/>(bash)"]
        W3["window 2<br/>(bash)"]
    end

    subgraph "bob (UID 1002) — port 7702"
        TTYD_B["ttyd :7702<br/>-W -i 127.0.0.1"]
        TMUX_B["tmux 'main' session"]
        W4["window 0<br/>(bash)"]
    end

    TAB1 -->|"WebSocket"| TTYD_A
    TAB2 -->|"WebSocket"| TTYD_A
    TAB3 -->|"WebSocket"| TTYD_A
    TTYD_A --> TMUX_A
    TMUX_A --> W1
    TMUX_A --> W2
    TMUX_A --> W3

    TTYD_B --> TMUX_B
    TMUX_B --> W4

    style TTYD_A fill:#8b5cf6,color:#fff
    style TTYD_B fill:#8b5cf6,color:#fff
    style TMUX_A fill:#64748b,color:#fff
    style TMUX_B fill:#64748b,color:#fff
```

### 6.2 ttyd Spawning Sequence

```mermaid
sequenceDiagram
    participant A as auth.py
    participant M as Memory<br/>(user_instances)
    participant S as sshd
    participant T as ttyd
    participant TM as tmux

    A->>M: Check user_instances[alice]
    alt Existing & alive
        M-->>A: Return existing port
    else Not found or dead
        A->>A: allocate_port()<br/>socket bind test 7700+
        A->>S: sshpass + ssh alice@127.0.0.1
        S->>T: ttyd -W -i 127.0.0.1 -p 7701<br/>bash -lc "tmux new-session -s main ..."
        T->>TM: Create/attach tmux session

        loop wait_for_ttyd_ready (4s timeout)
            A->>T: TCP connect test :7701
        end
        T-->>A: Port accepting connections

        A->>M: Store {port:7701, proc, password}
        M-->>A: Return port 7701
    end
```

### 6.3 Port Allocation

```mermaid
graph LR
    subgraph "Port Pool (7700 — 9699)"
        P7700["7700<br/>🟢 free"]
        P7701["7701<br/>🔴 alice"]
        P7702["7702<br/>🔴 bob"]
        P7703["7703<br/>🟢 free"]
        DOTS["..."]
        P9699["9699<br/>🟢 free"]
    end

    ALG["allocate_port()"] -->|"socket bind test"| P7700

    style P7701 fill:#e94560,color:#fff
    style P7702 fill:#f59e0b,color:#1e293b
    style P7700 fill:#22c55e,color:#fff
    style P7703 fill:#22c55e,color:#fff
    style P9699 fill:#22c55e,color:#fff
```

- **2000 port slots** (7700–9699)
- Allocated sequentially with **socket bind test** to verify availability
- Tracked in-memory: `user_instances[username] = {port, proc, password}`
- Reused if the process is still alive on return visits

---

## 7. Reverse Proxy & Routing Layer

### 7.1 nginx Route Map

```mermaid
graph TD
    REQ["Incoming Request<br/>:7680"] --> ROUTE{Route?}

    ROUTE -->|"/login<br/>/api/login"| NO_AUTH["No auth required"]
    NO_AUTH --> AUTH_PY_1["auth.py :7682"]

    ROUTE -->|"/ (root)"| AUTH_1["auth_request<br/>/api/auth"]
    AUTH_1 -->|"200 OK"| SPA["proxy /app → auth.py<br/>(SPA HTML)"]
    AUTH_1 -->|"401"| LOGIN["302 → /login"]

    ROUTE -->|"/ut/PORT/*"| AUTH_2["auth_request<br/>(port binding check)"]
    AUTH_2 -->|"200 OK"| TTYD_PROXY["proxy → ttyd :PORT<br/>+ WebSocket upgrade<br/>+ sub_filter inject"]
    AUTH_2 -->|"401"| LOGIN

    ROUTE -->|"/api/files/*"| AUTH_3["auth_request"]
    AUTH_3 -->|"200 OK"| FILE_API["proxy → auth.py<br/>(10MB upload limit)"]
    AUTH_3 -->|"401"| LOGIN

    ROUTE -->|"/api/quick-commands"| AUTH_4["auth_request"]
    AUTH_4 -->|"200 OK"| CMD_API["proxy → auth.py<br/>(2MB limit)"]
    AUTH_4 -->|"401"| LOGIN

    ROUTE -->|"/noVNC/"| AUTH_5["auth_request"]
    AUTH_5 -->|"200 OK"| VNC_PROXY["proxy → noVNC :6080<br/>+ WebSocket"]
    AUTH_5 -->|"401"| LOGIN

    style NO_AUTH fill:#22c55e,color:#fff
    style AUTH_1 fill:#e94560,color:#fff
    style AUTH_2 fill:#e94560,color:#fff
    style AUTH_3 fill:#e94560,color:#fff
    style AUTH_4 fill:#e94560,color:#fff
    style AUTH_5 fill:#e94560,color:#fff
    style LOGIN fill:#ef4444,color:#fff
```

### 7.2 Key nginx Features Used

| Feature | How It's Used |
|---------|--------------|
| `auth_request` | Every protected route delegates auth to `auth.py /api/auth` |
| `proxy_pass` with regex capture | `/ut/(\d+)/(.*)` → dynamic port routing to per-user ttyd |
| `proxy_set_header Upgrade/Connection` | WebSocket upgrade for ttyd and noVNC |
| `sub_filter` | Injects `<script src="/api/term-hook.js">` into ttyd HTML response |
| `proxy_set_header X-TTYD-Port` | Passes the requested port to auth.py for cross-validation |
| `proxy_set_header Accept-Encoding ""` | Disables upstream compression so sub_filter can operate |
| `proxy_read_timeout 86400s` | 24h timeout for long-lived WebSocket connections |
| `absolute_redirect off` | Relative redirects (critical behind Cloudflare tunnel) |
| `error_page 401 = @login_redirect` | 401 → 302 /login (user-friendly redirect) |

---

## 8. Frontend SPA Architecture

### 8.1 DOM Hierarchy

```mermaid
graph TD
    BODY["body<br/>(fixed, flex column)"]
    NAV[".navbar<br/>(42px)"]
    TABS[".tab-bar #tabBar<br/>(32px, scrollable)"]
    KEYS[".special-keys<br/>(mobile only)"]
    MAIN[".main-area<br/>(flex: 1, flex row)"]
    FILES[".file-panel<br/>(300px sidebar)"]
    TERM[".term-container<br/>(flex: 1)"]
    IF1["iframe #frame-tab-1<br/>(position: absolute)"]
    IF2["iframe #frame-tab-2<br/>(hidden)"]
    MODALS["Modals<br/>(preview, copy, dialog)"]
    SETTINGS["Panels<br/>(settings, themes)"]

    BODY --> NAV
    BODY --> TABS
    BODY --> KEYS
    BODY --> SETTINGS
    BODY --> MAIN
    BODY --> MODALS
    MAIN --> FILES
    MAIN --> TERM
    TERM --> IF1
    TERM --> IF2

    style NAV fill:#1a1a2e,color:#e2e8f0
    style TABS fill:#0d1b2a,color:#e2e8f0
    style TERM fill:#0a0a1a,color:#22c55e
    style FILES fill:#0d1b2a,color:#e2e8f0
```

### 8.2 Tab & Split Pane Model

```mermaid
graph TD
    subgraph "Single Pane Mode (default)"
        TC1[".term-container"]
        TC1 --> IFA["iframe tab-1<br/>(active, display:block)"]
        TC1 --> IFB["iframe tab-2<br/>(hidden, display:none)"]
        TC1 --> IFC["iframe tab-3<br/>(hidden, display:none)"]
    end

    subgraph "Split Mode (binary tree)"
        ROOT["split node<br/>direction: h, ratio: 0.5"]
        LEFT["pane node<br/>tabId: tab-1"]
        RIGHT["split node<br/>direction: v, ratio: 0.5"]
        RTOP["pane node<br/>tabId: tab-2"]
        RBOT["pane node<br/>tabId: tab-3"]

        ROOT --> LEFT
        ROOT --> RIGHT
        RIGHT --> RTOP
        RIGHT --> RBOT
    end

    style IFA fill:#22c55e,color:#fff
    style LEFT fill:#22c55e,color:#fff
    style RTOP fill:#8b5cf6,color:#fff
    style RBOT fill:#f59e0b,color:#1e293b
```

**Split Pane Data Structure:** Binary tree where each node is either:
- `{type: 'pane', tabId: 'tab-N'}` — a terminal pane
- `{type: 'split', direction: 'h'|'v', ratio: 0.5, children: [node, node]}` — a split container

**Responsive Rules:**

| Breakpoint | Behavior |
|------------|----------|
| < 768px (phone) | No split — tabs only |
| 768–1023px (tablet) | Max 2 panes, no nesting |
| ≥ 1024px (desktop) | Full nesting support |

### 8.3 Client-Side State

```mermaid
graph LR
    subgraph "JavaScript Globals"
        TABS_ARR["tabs[]<br/>{id, name}"]
        ACTIVE["activeTabId"]
        COUNTER["tabCounter"]
        THEME["currentTheme"]
        SPLIT["splitRoot<br/>(binary tree)"]
    end

    subgraph "localStorage"
        LS_TABS["ttyd_tabs<br/>(JSON array)"]
        LS_SPLIT["ttyd_split<br/>(JSON tree)"]
        LS_SETTINGS["ttyd_fontSize<br/>ttyd_fontFamily<br/>ttyd_cursorStyle<br/>..."]
        LS_THEME["ttyd_theme"]
    end

    TABS_ARR <-->|"saveTabs()"| LS_TABS
    SPLIT <-->|"saveSplitState()"| LS_SPLIT
    THEME <--> LS_THEME

    style LS_TABS fill:#3b82f6,color:#fff
    style LS_SPLIT fill:#8b5cf6,color:#fff
    style LS_SETTINGS fill:#22c55e,color:#fff
```

### 8.4 Keyboard Shortcuts

| Shortcut | Action | Category |
|----------|--------|----------|
| `Ctrl+Shift+T` | New Tab | Tabs |
| `Ctrl+Shift+W` | Close Tab | Tabs |
| `Ctrl+Shift+]` | Next Tab | Tabs |
| `Ctrl+Shift+[` | Previous Tab | Tabs |
| `Ctrl+Shift+\` | Split Right | Split |
| `Ctrl+Shift+-` | Split Down | Split |
| `Ctrl+Shift+U` | Unsplit | Split |
| `Ctrl+Shift+E` | Toggle File Browser | Files |
| `Escape` | Close Modals | UI |

---

## 9. File Browser Subsystem

### 9.1 Path Token Security

```mermaid
flowchart LR
    PATH["/home/alice/docs"] --> B64["base64url<br/>encode"]
    B64 --> TOKEN_P["path_b64"]

    USER["alice"] --> HMAC
    PATH --> HMAC["HMAC-SHA256<br/>(SECRET_KEY)"]
    HMAC --> SIG["signature"]

    TOKEN_P --> JOIN["path_b64.signature"]
    SIG --> JOIN

    JOIN --> VERIFY{"Server verifies:<br/>1. Decode path<br/>2. Recompute HMAC<br/>3. Compare signatures<br/>4. Check username scope"}

    VERIFY -->|"Valid"| ALLOW["Execute file op<br/>as user's UID"]
    VERIFY -->|"Invalid"| DENY["403 Forbidden"]

    style HMAC fill:#f59e0b,color:#1e293b
    style ALLOW fill:#22c55e,color:#fff
    style DENY fill:#ef4444,color:#fff
```

**Why path tokens?** Prevents directory traversal attacks. The client never sends raw paths — only opaque, signed tokens. Tokens are username-scoped: alice's tokens don't work for bob.

### 9.2 File API Endpoints

```mermaid
graph TD
    API["/api/files/*"] --> LIST["/list<br/>GET — directory listing"]
    API --> READ["/read<br/>GET — file content (2MB)"]
    API --> WRITE["/write<br/>POST — save file (2MB)"]
    API --> DL["/download<br/>GET — binary download"]
    API --> UL["/upload<br/>POST — upload (10MB)"]
    API --> MKDIR["/mkdir<br/>POST — create folder"]
    API --> DEL["/delete<br/>POST — delete (confirmed)"]
    API --> REN["/rename<br/>POST — rename"]

    LIST --> RUN["run_as_user()"]
    READ --> RUN
    WRITE --> RUN
    DL --> RUN
    UL --> RUN
    MKDIR --> RUN
    DEL --> RUN
    REN --> RUN

    RUN --> SSH["sshpass + ssh user@127.0.0.1<br/>python3 - < script"]

    style API fill:#06b6d4,color:#fff
    style RUN fill:#e94560,color:#fff
    style SSH fill:#64748b,color:#fff
```

### 9.3 File Preview Support

| File Type | Preview Method |
|-----------|---------------|
| Text files | Syntax-highlighted editor (inline editable) |
| Markdown (.md) | Rendered HTML with source toggle |
| Images | Embedded in modal |
| Video / Audio | HTML5 media player |
| PDF | Embedded viewer |

---

## 10. Security Architecture

### 10.1 Defense-in-Depth Layers

```mermaid
graph TD
    subgraph L1["Layer 1: Network Perimeter"]
        NET["Cloudflare Tunnel<br/>(outbound-only, HTTPS+QUIC)<br/>All services bind 127.0.0.1"]
    end

    subgraph L2["Layer 2: Authentication"]
        AUTH["HMAC-SHA256 signed tokens<br/>__Host- cookie prefix<br/>HttpOnly + Secure + SameSite=Strict<br/>24h expiry"]
    end

    subgraph L3["Layer 3: Authorization"]
        AUTHZ["nginx auth_request on every route<br/>Port binding in token (cross-validated)<br/>HMAC-signed path tokens (file ops)"]
    end

    subgraph L4["Layer 4: Process Isolation"]
        ISO["Per-user UID (via SSH)<br/>OS file permissions enforced<br/>Separate ttyd per user<br/>Isolated tmux sessions"]
    end

    subgraph L5["Layer 5: HTTP Hardening"]
        HDR["Content-Security-Policy<br/>X-Frame-Options: SAMEORIGIN<br/>X-Content-Type-Options: nosniff<br/>Referrer-Policy: no-referrer<br/>Permissions-Policy"]
    end

    L1 --> L2 --> L3 --> L4 --> L5

    style L1 fill:#3b82f6,color:#fff
    style L2 fill:#e94560,color:#fff
    style L3 fill:#f59e0b,color:#1e293b
    style L4 fill:#22c55e,color:#fff
    style L5 fill:#8b5cf6,color:#fff
```

### 10.2 Threat Mitigation Matrix

| Threat | Attack Vector | Mitigation |
|--------|--------------|------------|
| **Network exposure** | Port scanning, direct access | All services bind 127.0.0.1; tunnel is outbound-only |
| **Credential theft** | Brute force | PAM rate limiting via sshd; HTTPS only |
| **Session hijacking** | Cookie theft via XSS | HttpOnly + Secure + SameSite=Strict + __Host- prefix |
| **Cross-user access** | Guessing another user's ttyd port | Token includes port; nginx cross-validates via X-TTYD-Port |
| **Directory traversal** | Manipulated file paths | HMAC-signed path tokens (per-user scoped) |
| **Privilege escalation** | File ops with wrong UID | All operations run via `run_as_user()` SSH (OS-level enforcement) |
| **XSS** | Injected scripts | Content-Security-Policy headers |
| **CSRF** | Cross-site form submission | SameSite=Strict cookies |
| **Supply chain** | Compromised dependencies | Zero external Python dependencies (stdlib only) |
| **Framing attacks** | Embedding in malicious site | X-Frame-Options: SAMEORIGIN |

---

## 11. Deployment & Operations

### 11.1 Deployment Pipeline

```mermaid
flowchart TD
    START["deploy.sh"] --> CHECK_SSHD{"sshd running?<br/>pw-auth enabled?"}

    CHECK_SSHD -->|"No"| FIX_SSHD["Configure sshd<br/>Match LocalAddress 127.0.0.1<br/>PasswordAuthentication yes"]
    CHECK_SSHD -->|"Yes"| CHECK_NGINX
    FIX_SSHD --> START_SSHD["Start/restart sshd"]
    START_SSHD --> CHECK_NGINX

    CHECK_NGINX{"nginx config<br/>changed?"}
    CHECK_NGINX -->|"Yes"| INSTALL_CONF["Copy ttyd.conf<br/>nginx -t (syntax check)<br/>Reload nginx"]
    CHECK_NGINX -->|"No, running"| CHECK_AUTH
    INSTALL_CONF --> CHECK_AUTH

    CHECK_AUTH{"auth.py<br/>stale or dead?"}
    CHECK_AUTH -->|"File newer than proc"| RESTART_AUTH["Kill old → start auth.py<br/>(nohup / launchd / systemd)"]
    CHECK_AUTH -->|"Running & current"| CHECK_CF
    RESTART_AUTH --> CHECK_CF

    CHECK_CF{"cloudflared<br/>tunnel running?"}
    CHECK_CF -->|"No"| START_CF["Start in tmux session<br/>'cloudflared'"]
    CHECK_CF -->|"Yes"| HEALTH
    START_CF --> HEALTH

    HEALTH["Health Checks"]
    HEALTH --> H1["✅ sshd :22"]
    HEALTH --> H2["✅ nginx :7680"]
    HEALTH --> H3["✅ auth.py :7682<br/>(HTTP 401 from /api/auth)"]
    HEALTH --> H4["✅ cloudflared tunnel"]
    HEALTH --> H5["✅ E2E: curl https://hostname/login"]

    style START fill:#3b82f6,color:#fff
    style HEALTH fill:#22c55e,color:#fff
    style FIX_SSHD fill:#f59e0b,color:#1e293b
    style RESTART_AUTH fill:#e94560,color:#fff
```

### 11.2 Platform Support

| Platform | auth.py Management | nginx | cloudflared |
|----------|-------------------|-------|-------------|
| **macOS** | launchd plist (LaunchAgent) | Homebrew service | tmux session |
| **Linux + systemd** | systemd user service | systemctl reload | tmux session |
| **Linux (no systemd / WSL2)** | nohup + PID file | service nginx reload | tmux session |

### 11.3 Operations Commands

```mermaid
graph LR
    subgraph "deploy.sh modes"
        D1["./deploy.sh<br/>Start what's down"]
        D2["./deploy.sh --restart<br/>Force restart all"]
        D3["./deploy.sh --status<br/>Health check only"]
    end

    style D1 fill:#22c55e,color:#fff
    style D2 fill:#f59e0b,color:#1e293b
    style D3 fill:#3b82f6,color:#fff
```

### 11.4 File Sync Requirement

```mermaid
graph LR
    AUTH["auth.py<br/>(source of truth)"] -->|"Must sync"| CF["cf_tunnel_install.sh<br/>(embedded heredoc<br/>lines 507–5099)"]

    NOTE["⚠️ Manual process:<br/>1. Edit auth.py<br/>2. Replace heredoc content<br/>3. Note: TTYD_PATH_PLACEHOLDER<br/>   is sed-replaced at deploy"]

    style AUTH fill:#e94560,color:#fff
    style CF fill:#f59e0b,color:#1e293b
    style NOTE fill:#1e293b,color:#94a3b8,stroke:#334155
```

---

## 12. Data Persistence Model

```mermaid
graph TD
    subgraph "Server-Side (Ephemeral)"
        MEM["Process Memory<br/>• user_instances {port, proc, pw}<br/>• SECRET_KEY (if not in .env)"]
        FILE_CMD["~/ttyd_quick_command.json<br/>• Quick commands library"]
        TUNNEL["~/.cloudflared/<br/>• Tunnel credentials<br/>• config.yml"]
    end

    subgraph "Client-Side (Browser)"
        LS["localStorage<br/>• ttyd_tabs (tab state)<br/>• ttyd_split (split tree)<br/>• ttyd_fontSize, ttyd_fontFamily...<br/>• ttyd_theme"]
        COOKIE["Cookie<br/>• __Host-ttyd_session"]
    end

    subgraph "Lifetime"
        MEM -.->|"Lost on restart"| RESTART["⚠️ All sessions invalidated"]
        FILE_CMD -.->|"Permanent"| PERM["✅ Survives restart"]
        TUNNEL -.->|"Permanent"| PERM
        LS -.->|"Per-browser permanent"| PERM
        COOKIE -.->|"24h expiry"| EXPIRE["🕐 Auto-expires"]
    end

    style RESTART fill:#ef4444,color:#fff
    style PERM fill:#22c55e,color:#fff
    style EXPIRE fill:#f59e0b,color:#1e293b
```

---

## 13. Cross-Cutting Concerns

### 13.1 Mobile Responsiveness

```mermaid
graph TD
    WIDTH{"Screen Width"}
    WIDTH -->|"≤ 600px"| PHONE["Phone Mode<br/>• Hamburger menu<br/>• Special keys toolbar<br/>• No split panes"]
    WIDTH -->|"601–767px"| SMALL["Small Tablet<br/>• Full nav<br/>• No split panes"]
    WIDTH -->|"768–1023px"| TABLET["Tablet<br/>• Max 2 split panes<br/>• No nesting"]
    WIDTH -->|"≥ 1024px"| DESKTOP["Desktop<br/>• Full split nesting<br/>• All features"]

    TOUCH{"Touch Device?<br/>(pointer: coarse)"}
    TOUCH -->|"Yes"| MOBILE_UX["• Special keys bar visible<br/>• Touch copy modal<br/>• DOM renderer for selection<br/>• File action buttons always visible"]
    TOUCH -->|"No"| DESKTOP_UX["• Keyboard shortcuts<br/>• Native selection<br/>• Hover-reveal actions"]

    style PHONE fill:#e94560,color:#fff
    style TABLET fill:#f59e0b,color:#1e293b
    style DESKTOP fill:#22c55e,color:#fff
```

### 13.2 Session Persistence via tmux

```mermaid
graph LR
    subgraph "Browser Tab 1"
        WS1["WebSocket"]
    end
    subgraph "Browser Tab 2"
        WS2["WebSocket"]
    end

    subgraph "ttyd (single port per user)"
        TTYD["ttyd :7701"]
    end

    subgraph "tmux (persistence layer)"
        MAIN["session: main"]
        G1["grouped session 1<br/>(auto-created)"]
        G2["grouped session 2<br/>(auto-created)"]
        W0["window 0"]
        W1["window 1"]
    end

    WS1 --> TTYD
    WS2 --> TTYD
    TTYD --> G1
    TTYD --> G2
    G1 --> MAIN
    G2 --> MAIN
    MAIN --> W0
    MAIN --> W1

    CLOSE["Browser closed"] -.->|"tmux sessions<br/>keep running"| MAIN
    REOPEN["Browser reopened"] -.->|"Reattach to<br/>existing windows"| MAIN

    style TTYD fill:#8b5cf6,color:#fff
    style MAIN fill:#64748b,color:#fff
    style CLOSE fill:#ef4444,color:#fff
    style REOPEN fill:#22c55e,color:#fff
```

### 13.3 Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `TTYD_SECRET` | Random per restart | HMAC signing key (set in `.env` for persistence) |
| `SESSION_MAX_AGE` | 86400 (24h) | Token validity in seconds |
| `AUTH_PORT` | 7682 | Auth service listen port |
| `TTYD_START_PORT` | 7700 | First port for user ttyd instances |
| `SESSION_COOKIE_NAME` | `__Host-ttyd_session` | HTTP cookie name |
| `COOKIE_SECURE` | true | Require HTTPS for cookies |
| `ACCESS_LOG_ENABLED` | false | Enable HTTP request logging |
| `TTYD_BIN` | auto-detect | Override ttyd binary path |
| `SSHPASS_BIN` | auto-detect | Override sshpass binary path |
| `SSH_BIN` | auto-detect | Override ssh binary path |

---

> **Document Conventions:** All Mermaid diagrams are renderable in GitHub, GitLab, Notion, and VS Code with the Markdown Preview Mermaid extension.
