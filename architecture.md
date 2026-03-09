# Architecture: micsapp-webterminal

Browser-based multi-tenant terminal system providing isolated shell access per system user through a secure reverse-proxy chain.

---

## System Overview

<svg viewBox="0 0 900 520" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, Arial, sans-serif">
  <defs>
    <marker id="ah" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto"><polygon points="0 0, 10 3.5, 0 7" fill="#64748b"/></marker>
    <marker id="ah-r" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto"><polygon points="0 0, 10 3.5, 0 7" fill="#e94560"/></marker>
    <linearGradient id="g1" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#1e293b"/><stop offset="100%" stop-color="#0f172a"/></linearGradient>
  </defs>
  <rect width="900" height="520" rx="12" fill="url(#g1)"/>

  <!-- Browser -->
  <rect x="350" y="20" width="200" height="50" rx="8" fill="#3b82f6" opacity="0.9"/>
  <text x="450" y="50" text-anchor="middle" fill="#fff" font-size="15" font-weight="600">Browser (SPA)</text>

  <!-- Cloudflared -->
  <rect x="350" y="110" width="200" height="50" rx="8" fill="#f59e0b" opacity="0.9"/>
  <text x="450" y="130" text-anchor="middle" fill="#1e293b" font-size="13" font-weight="600">Cloudflare Tunnel</text>
  <text x="450" y="147" text-anchor="middle" fill="#1e293b" font-size="11">(cloudflared)</text>

  <!-- nginx -->
  <rect x="350" y="200" width="200" height="50" rx="8" fill="#22c55e" opacity="0.9"/>
  <text x="450" y="220" text-anchor="middle" fill="#fff" font-size="13" font-weight="600">nginx :7680</text>
  <text x="450" y="237" text-anchor="middle" fill="#d1fae5" font-size="11">reverse proxy + auth subreq</text>

  <!-- auth.py -->
  <rect x="120" y="290" width="240" height="60" rx="8" fill="#e94560" opacity="0.9"/>
  <text x="240" y="315" text-anchor="middle" fill="#fff" font-size="13" font-weight="600">auth.py :7682</text>
  <text x="240" y="332" text-anchor="middle" fill="#fecdd3" font-size="11">HTTP auth + SPA + file API + ttyd mgr</text>

  <!-- ttyd instances -->
  <rect x="520" y="290" width="240" height="60" rx="8" fill="#8b5cf6" opacity="0.9"/>
  <text x="640" y="315" text-anchor="middle" fill="#fff" font-size="13" font-weight="600">ttyd :7700+</text>
  <text x="640" y="332" text-anchor="middle" fill="#e0d4fc" font-size="11">per-user WebSocket terminal</text>

  <!-- SSH -->
  <rect x="520" y="390" width="240" height="50" rx="8" fill="#06b6d4" opacity="0.9"/>
  <text x="640" y="410" text-anchor="middle" fill="#fff" font-size="13" font-weight="600">sshd :22</text>
  <text x="640" y="427" text-anchor="middle" fill="#cffafe" font-size="11">localhost password auth</text>

  <!-- tmux + shell -->
  <rect x="520" y="470" width="240" height="35" rx="8" fill="#64748b" opacity="0.9"/>
  <text x="640" y="493" text-anchor="middle" fill="#fff" font-size="13" font-weight="600">tmux session / user shell</text>

  <!-- sshpass -->
  <rect x="120" y="390" width="240" height="50" rx="8" fill="#06b6d4" opacity="0.5"/>
  <text x="240" y="410" text-anchor="middle" fill="#cffafe" font-size="13" font-weight="600">sshpass + ssh</text>
  <text x="240" y="427" text-anchor="middle" fill="#94a3b8" font-size="11">run_as_user() for file ops</text>

  <!-- Arrows -->
  <line x1="450" y1="70" x2="450" y2="110" stroke="#64748b" stroke-width="2" marker-end="url(#ah)"/>
  <text x="460" y="95" fill="#94a3b8" font-size="10">HTTPS</text>

  <line x1="450" y1="160" x2="450" y2="200" stroke="#64748b" stroke-width="2" marker-end="url(#ah)"/>
  <text x="460" y="185" fill="#94a3b8" font-size="10">:7680</text>

  <!-- nginx to auth.py -->
  <path d="M400 250 L300 290" stroke="#e94560" stroke-width="2" marker-end="url(#ah-r)" fill="none"/>
  <text x="310" y="268" fill="#f87171" font-size="10">auth subreq</text>
  <text x="310" y="280" fill="#f87171" font-size="10">+ /api/*</text>

  <!-- nginx to ttyd -->
  <path d="M500 250 L580 290" stroke="#64748b" stroke-width="2" marker-end="url(#ah)" fill="none"/>
  <text x="530" y="268" fill="#94a3b8" font-size="10">/ut/PORT/</text>
  <text x="530" y="280" fill="#94a3b8" font-size="10">WebSocket</text>

  <!-- ttyd to ssh -->
  <line x1="640" y1="350" x2="640" y2="390" stroke="#64748b" stroke-width="2" marker-end="url(#ah)"/>
  <text x="650" y="375" fill="#94a3b8" font-size="10">sshpass</text>

  <!-- ssh to tmux -->
  <line x1="640" y1="440" x2="640" y2="470" stroke="#64748b" stroke-width="2" marker-end="url(#ah)"/>

  <!-- auth.py to sshpass -->
  <line x1="240" y1="350" x2="240" y2="390" stroke="#64748b" stroke-width="2" marker-end="url(#ah)"/>

  <!-- sshpass to sshd -->
  <path d="M360 415 L520 415" stroke="#64748b" stroke-width="1.5" stroke-dasharray="6,3" marker-end="url(#ah)" fill="none"/>
  <text x="420" y="408" fill="#94a3b8" font-size="10">file ops via SSH</text>
</svg>

---

## Request Flow

<svg viewBox="0 0 900 700" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, Arial, sans-serif">
  <defs>
    <marker id="a2" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#64748b"/></marker>
    <marker id="a2g" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#22c55e"/></marker>
    <marker id="a2r" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#e94560"/></marker>
  </defs>
  <rect width="900" height="700" rx="12" fill="#0f172a"/>

  <!-- Swim lanes -->
  <text x="90" y="30" text-anchor="middle" fill="#3b82f6" font-size="13" font-weight="600">Browser</text>
  <line x1="90" y1="38" x2="90" y2="690" stroke="#1e3a5f" stroke-width="1" stroke-dasharray="4,4"/>

  <text x="300" y="30" text-anchor="middle" fill="#22c55e" font-size="13" font-weight="600">nginx :7680</text>
  <line x1="300" y1="38" x2="300" y2="690" stroke="#1e3a5f" stroke-width="1" stroke-dasharray="4,4"/>

  <text x="530" y="30" text-anchor="middle" fill="#e94560" font-size="13" font-weight="600">auth.py :7682</text>
  <line x1="530" y1="38" x2="530" y2="690" stroke="#1e3a5f" stroke-width="1" stroke-dasharray="4,4"/>

  <text x="760" y="30" text-anchor="middle" fill="#8b5cf6" font-size="13" font-weight="600">ttyd :7700+</text>
  <line x1="760" y1="38" x2="760" y2="690" stroke="#1e3a5f" stroke-width="1" stroke-dasharray="4,4"/>

  <!-- Phase 1: Login -->
  <rect x="20" y="52" width="860" height="165" rx="6" fill="#1e293b" stroke="#334155" stroke-width="1"/>
  <text x="40" y="72" fill="#f59e0b" font-size="12" font-weight="600">1. LOGIN</text>

  <line x1="90" y1="90" x2="290" y2="90" stroke="#64748b" stroke-width="1.5" marker-end="url(#a2)"/>
  <text x="190" y="85" text-anchor="middle" fill="#94a3b8" font-size="10">GET /login</text>

  <line x1="300" y1="95" x2="520" y2="95" stroke="#64748b" stroke-width="1.5" marker-end="url(#a2)"/>
  <text x="410" y="90" text-anchor="middle" fill="#94a3b8" font-size="10">proxy (no auth needed)</text>

  <line x1="520" y1="100" x2="310" y2="100" stroke="#22c55e" stroke-width="1.5" marker-end="url(#a2g)"/>
  <text x="410" y="115" text-anchor="middle" fill="#86efac" font-size="10">login HTML form</text>

  <line x1="90" y1="135" x2="290" y2="135" stroke="#64748b" stroke-width="1.5" marker-end="url(#a2)"/>
  <text x="190" y="130" text-anchor="middle" fill="#94a3b8" font-size="10">POST /api/login {user, pass}</text>

  <line x1="300" y1="140" x2="520" y2="140" stroke="#64748b" stroke-width="1.5" marker-end="url(#a2)"/>

  <rect x="535" y="128" width="165" height="28" rx="4" fill="#e94560" opacity="0.3"/>
  <text x="617" y="145" text-anchor="middle" fill="#fecdd3" font-size="10">sshpass auth + spawn ttyd</text>

  <line x1="520" y1="170" x2="310" y2="170" stroke="#22c55e" stroke-width="1.5" marker-end="url(#a2g)"/>
  <text x="410" y="168" text-anchor="middle" fill="#86efac" font-size="10">Set-Cookie + port</text>

  <line x1="290" y1="195" x2="100" y2="195" stroke="#22c55e" stroke-width="1.5" marker-end="url(#a2g)"/>
  <text x="190" y="193" text-anchor="middle" fill="#86efac" font-size="10">redirect to /</text>

  <!-- Phase 2: Load SPA -->
  <rect x="20" y="225" width="860" height="130" rx="6" fill="#1e293b" stroke="#334155" stroke-width="1"/>
  <text x="40" y="245" fill="#f59e0b" font-size="12" font-weight="600">2. LOAD SPA</text>

  <line x1="90" y1="265" x2="290" y2="265" stroke="#64748b" stroke-width="1.5" marker-end="url(#a2)"/>
  <text x="190" y="260" text-anchor="middle" fill="#94a3b8" font-size="10">GET / (with cookie)</text>

  <line x1="300" y1="270" x2="520" y2="270" stroke="#e94560" stroke-width="1.5" marker-end="url(#a2r)"/>
  <text x="410" y="268" text-anchor="middle" fill="#f87171" font-size="10">auth subrequest /api/auth</text>

  <line x1="520" y1="280" x2="310" y2="280" stroke="#22c55e" stroke-width="1.5" marker-end="url(#a2g)"/>
  <text x="410" y="295" text-anchor="middle" fill="#86efac" font-size="10">200 OK (token valid)</text>

  <line x1="300" y1="310" x2="520" y2="310" stroke="#64748b" stroke-width="1.5" marker-end="url(#a2)"/>
  <text x="410" y="308" text-anchor="middle" fill="#94a3b8" font-size="10">proxy GET /app</text>

  <line x1="520" y1="335" x2="100" y2="335" stroke="#22c55e" stroke-width="1.5" marker-end="url(#a2g)"/>
  <text x="310" y="333" text-anchor="middle" fill="#86efac" font-size="10">APP_HTML (full SPA with port injected)</text>

  <!-- Phase 3: Terminal -->
  <rect x="20" y="365" width="860" height="150" rx="6" fill="#1e293b" stroke="#334155" stroke-width="1"/>
  <text x="40" y="385" fill="#f59e0b" font-size="12" font-weight="600">3. TERMINAL SESSION</text>

  <line x1="90" y1="405" x2="290" y2="405" stroke="#64748b" stroke-width="1.5" marker-end="url(#a2)"/>
  <text x="190" y="400" text-anchor="middle" fill="#94a3b8" font-size="10">iframe /ut/7701/</text>

  <line x1="300" y1="410" x2="520" y2="410" stroke="#e94560" stroke-width="1.5" marker-end="url(#a2r)"/>
  <text x="410" y="408" text-anchor="middle" fill="#f87171" font-size="10">auth subreq (verify port=7701)</text>

  <line x1="520" y1="420" x2="310" y2="420" stroke="#22c55e" stroke-width="1.5" marker-end="url(#a2g)"/>
  <text x="410" y="435" text-anchor="middle" fill="#86efac" font-size="10">200 OK</text>

  <line x1="300" y1="450" x2="750" y2="450" stroke="#8b5cf6" stroke-width="1.5" marker-end="url(#a2)"/>
  <text x="525" y="448" text-anchor="middle" fill="#c4b5fd" font-size="10">proxy + sub_filter (inject term-hook.js)</text>

  <line x1="750" y1="470" x2="100" y2="470" stroke="#8b5cf6" stroke-width="1.5" marker-end="url(#a2)"/>
  <text x="400" y="468" text-anchor="middle" fill="#c4b5fd" font-size="10">ttyd HTML + xterm.js + TERM_HOOK_JS</text>

  <line x1="90" y1="490" x2="750" y2="490" stroke="#8b5cf6" stroke-width="1.5" stroke-dasharray="4,2" marker-end="url(#a2)"/>
  <text x="400" y="505" text-anchor="middle" fill="#c4b5fd" font-size="10">WebSocket (bidirectional terminal I/O via tmux)</text>

  <!-- Phase 4: File ops -->
  <rect x="20" y="525" width="860" height="165" rx="6" fill="#1e293b" stroke="#334155" stroke-width="1"/>
  <text x="40" y="545" fill="#f59e0b" font-size="12" font-weight="600">4. FILE OPERATIONS</text>

  <line x1="90" y1="565" x2="290" y2="565" stroke="#64748b" stroke-width="1.5" marker-end="url(#a2)"/>
  <text x="190" y="560" text-anchor="middle" fill="#94a3b8" font-size="10">GET /api/files/list?path_token=...</text>

  <line x1="300" y1="570" x2="520" y2="570" stroke="#e94560" stroke-width="1.5" marker-end="url(#a2r)"/>
  <text x="410" y="568" text-anchor="middle" fill="#f87171" font-size="10">auth subreq</text>

  <line x1="520" y1="580" x2="310" y2="580" stroke="#22c55e" stroke-width="1.5" marker-end="url(#a2g)"/>

  <line x1="300" y1="600" x2="520" y2="600" stroke="#64748b" stroke-width="1.5" marker-end="url(#a2)"/>
  <text x="410" y="598" text-anchor="middle" fill="#94a3b8" font-size="10">proxy to auth.py</text>

  <rect x="535" y="605" width="165" height="28" rx="4" fill="#06b6d4" opacity="0.3"/>
  <text x="617" y="622" text-anchor="middle" fill="#67e8f9" font-size="10">run_as_user() via SSH</text>

  <line x1="520" y1="650" x2="100" y2="650" stroke="#22c55e" stroke-width="1.5" marker-end="url(#a2g)"/>
  <text x="310" y="668" text-anchor="middle" fill="#86efac" font-size="10">JSON {entries, breadcrumbs, parent_token}</text>
</svg>

---

## Authentication & Session Model

### Token Format

```
username:port:timestamp:HMAC-SHA256(SECRET_KEY, "username:port:timestamp")
```

Example: `alice:7701:1709999999:a1b2c3d4e5f6...`

### Cookie

| Attribute | Value |
|-----------|-------|
| Name | `__Host-ttyd_session` |
| HttpOnly | Yes |
| Secure | Yes (HTTPS only) |
| SameSite | Strict |
| Max-Age | 86400 (24h, configurable) |

### Auth Verification Flow

<svg viewBox="0 0 740 340" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, Arial, sans-serif">
  <defs>
    <marker id="a2" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#64748b"/></marker>
    <marker id="a2g" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#22c55e"/></marker>
    <marker id="a2r" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#e94560"/></marker>
  </defs>
  <rect width="740" height="340" rx="12" fill="#0f172a"/>

  <!-- Start -->
  <ellipse cx="70" cy="50" rx="50" ry="22" fill="#3b82f6" opacity="0.8"/>
  <text x="70" y="55" text-anchor="middle" fill="#fff" font-size="12">Request</text>

  <!-- Extract cookie -->
  <rect x="160" y="30" width="140" height="40" rx="6" fill="#1e293b" stroke="#334155"/>
  <text x="230" y="55" text-anchor="middle" fill="#e2e8f0" font-size="11">Extract cookie</text>

  <!-- Parse token -->
  <rect x="340" y="30" width="140" height="40" rx="6" fill="#1e293b" stroke="#334155"/>
  <text x="410" y="48" text-anchor="middle" fill="#e2e8f0" font-size="11">Parse token</text>
  <text x="410" y="62" text-anchor="middle" fill="#94a3b8" font-size="10">user:port:ts:sig</text>

  <!-- Verify HMAC -->
  <path d="M520 50 L570 50" stroke="#64748b" stroke-width="1.5" marker-end="url(#a2)"/>
  <rect x="570" y="22" width="140" height="55" rx="6" fill="#e94560" opacity="0.3" stroke="#e94560" stroke-width="1"/>
  <text x="640" y="44" text-anchor="middle" fill="#fecdd3" font-size="11">Verify HMAC</text>
  <text x="640" y="58" text-anchor="middle" fill="#94a3b8" font-size="10">SHA256(key,</text>
  <text x="640" y="70" text-anchor="middle" fill="#94a3b8" font-size="10">user:port:ts)</text>

  <!-- Check expiry -->
  <rect x="570" y="110" width="140" height="40" rx="6" fill="#1e293b" stroke="#334155"/>
  <text x="640" y="128" text-anchor="middle" fill="#e2e8f0" font-size="11">Check expiry</text>
  <text x="640" y="142" text-anchor="middle" fill="#94a3b8" font-size="10">now - ts &lt; MAX_AGE</text>

  <!-- Check port binding -->
  <rect x="570" y="180" width="140" height="40" rx="6" fill="#1e293b" stroke="#334155"/>
  <text x="640" y="198" text-anchor="middle" fill="#e2e8f0" font-size="11">Verify port binding</text>
  <text x="640" y="212" text-anchor="middle" fill="#94a3b8" font-size="10">X-TTYD-Port == port</text>

  <!-- 200 OK -->
  <ellipse cx="640" cy="265" rx="50" ry="22" fill="#22c55e" opacity="0.8"/>
  <text x="640" y="270" text-anchor="middle" fill="#fff" font-size="12">200 OK</text>

  <!-- 401 -->
  <ellipse cx="380" cy="265" rx="50" ry="22" fill="#ef4444" opacity="0.8"/>
  <text x="380" y="270" text-anchor="middle" fill="#fff" font-size="12">401</text>

  <!-- Arrows -->
  <line x1="120" y1="50" x2="158" y2="50" stroke="#64748b" stroke-width="1.5" marker-end="url(#a2)"/>
  <line x1="300" y1="50" x2="338" y2="50" stroke="#64748b" stroke-width="1.5" marker-end="url(#a2)"/>
  <line x1="640" y1="77" x2="640" y2="108" stroke="#22c55e" stroke-width="1.5" marker-end="url(#a2g)"/>
  <text x="655" y="96" fill="#86efac" font-size="10">valid</text>
  <line x1="640" y1="150" x2="640" y2="178" stroke="#22c55e" stroke-width="1.5" marker-end="url(#a2g)"/>
  <text x="655" y="168" fill="#86efac" font-size="10">fresh</text>
  <line x1="640" y1="220" x2="640" y2="243" stroke="#22c55e" stroke-width="1.5" marker-end="url(#a2g)"/>
  <text x="655" y="236" fill="#86efac" font-size="10">match</text>

  <!-- Fail paths -->
  <path d="M570 50 L380 50 L380 243" stroke="#ef4444" stroke-width="1.2" stroke-dasharray="4,3" marker-end="url(#a2r)" fill="none"/>
  <text x="470" y="42" fill="#f87171" font-size="10">invalid sig</text>
  <path d="M570 130 L480 130 L480 180 L380 180 L380 243" stroke="#ef4444" stroke-width="1.2" stroke-dasharray="4,3" fill="none"/>
  <text x="510" y="122" fill="#f87171" font-size="10">expired</text>
  <path d="M570 200 L480 200 L480 220 L380 220 L380 243" stroke="#ef4444" stroke-width="1.2" stroke-dasharray="4,3" fill="none"/>
  <text x="510" y="192" fill="#f87171" font-size="10">wrong port</text>
</svg>

---

## Per-User Terminal Isolation

<svg viewBox="0 0 800 420" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, Arial, sans-serif">
  <rect width="800" height="420" rx="12" fill="#0f172a"/>

  <!-- Title -->
  <text x="400" y="30" text-anchor="middle" fill="#e2e8f0" font-size="14" font-weight="600">Per-User Process Isolation</text>

  <!-- User A -->
  <rect x="30" y="55" width="350" height="165" rx="8" fill="#1e293b" stroke="#3b82f6" stroke-width="1.5"/>
  <text x="205" y="75" text-anchor="middle" fill="#3b82f6" font-size="13" font-weight="600">User: alice (UID 1001)</text>

  <rect x="50" y="90" width="130" height="35" rx="5" fill="#8b5cf6" opacity="0.7"/>
  <text x="115" y="112" text-anchor="middle" fill="#fff" font-size="11">ttyd :7701</text>

  <rect x="50" y="135" width="130" height="35" rx="5" fill="#06b6d4" opacity="0.5"/>
  <text x="115" y="157" text-anchor="middle" fill="#cffafe" font-size="11">ssh alice@127.0.0.1</text>

  <rect x="50" y="180" width="310" height="30" rx="5" fill="#64748b" opacity="0.4"/>
  <text x="205" y="200" text-anchor="middle" fill="#e2e8f0" font-size="11">tmux: main (win 0, win 1, win 2...)</text>

  <rect x="200" y="90" width="160" height="80" rx="5" fill="#0f172a" stroke="#334155"/>
  <text x="280" y="108" text-anchor="middle" fill="#94a3b8" font-size="10">Browser tabs</text>
  <rect x="210" y="115" width="60" height="18" rx="3" fill="#e94560" opacity="0.5"/>
  <text x="240" y="129" text-anchor="middle" fill="#fff" font-size="9">Tab 1</text>
  <rect x="280" y="115" width="60" height="18" rx="3" fill="#e94560" opacity="0.3"/>
  <text x="310" y="129" text-anchor="middle" fill="#fff" font-size="9">Tab 2</text>
  <rect x="210" y="140" width="60" height="18" rx="3" fill="#e94560" opacity="0.3"/>
  <text x="240" y="154" text-anchor="middle" fill="#fff" font-size="9">Tab 3</text>
  <text x="280" y="160" fill="#64748b" font-size="20">...</text>

  <!-- User B -->
  <rect x="420" y="55" width="350" height="165" rx="8" fill="#1e293b" stroke="#f59e0b" stroke-width="1.5"/>
  <text x="595" y="75" text-anchor="middle" fill="#f59e0b" font-size="13" font-weight="600">User: bob (UID 1002)</text>

  <rect x="440" y="90" width="130" height="35" rx="5" fill="#8b5cf6" opacity="0.7"/>
  <text x="505" y="112" text-anchor="middle" fill="#fff" font-size="11">ttyd :7702</text>

  <rect x="440" y="135" width="130" height="35" rx="5" fill="#06b6d4" opacity="0.5"/>
  <text x="505" y="157" text-anchor="middle" fill="#cffafe" font-size="11">ssh bob@127.0.0.1</text>

  <rect x="440" y="180" width="310" height="30" rx="5" fill="#64748b" opacity="0.4"/>
  <text x="595" y="200" text-anchor="middle" fill="#e2e8f0" font-size="11">tmux: main (win 0, win 1...)</text>

  <rect x="590" y="90" width="160" height="80" rx="5" fill="#0f172a" stroke="#334155"/>
  <text x="670" y="108" text-anchor="middle" fill="#94a3b8" font-size="10">Browser tabs</text>
  <rect x="600" y="115" width="60" height="18" rx="3" fill="#e94560" opacity="0.5"/>
  <text x="630" y="129" text-anchor="middle" fill="#fff" font-size="9">Tab 1</text>
  <rect x="670" y="115" width="60" height="18" rx="3" fill="#e94560" opacity="0.3"/>
  <text x="700" y="129" text-anchor="middle" fill="#fff" font-size="9">Tab 2</text>

  <!-- Port allocation -->
  <rect x="30" y="245" width="740" height="160" rx="8" fill="#1e293b" stroke="#334155"/>
  <text x="400" y="270" text-anchor="middle" fill="#e2e8f0" font-size="13" font-weight="600">Port Allocation Pool</text>

  <rect x="60" y="285" width="80" height="30" rx="4" fill="#3b82f6" opacity="0.6"/>
  <text x="100" y="305" text-anchor="middle" fill="#fff" font-size="11">7700</text>
  <text x="100" y="330" text-anchor="middle" fill="#64748b" font-size="9">(free)</text>

  <rect x="160" y="285" width="80" height="30" rx="4" fill="#e94560" opacity="0.6"/>
  <text x="200" y="305" text-anchor="middle" fill="#fff" font-size="11">7701</text>
  <text x="200" y="330" text-anchor="middle" fill="#fecdd3" font-size="9">alice</text>

  <rect x="260" y="285" width="80" height="30" rx="4" fill="#f59e0b" opacity="0.6"/>
  <text x="300" y="305" text-anchor="middle" fill="#fff" font-size="11">7702</text>
  <text x="300" y="330" text-anchor="middle" fill="#fde68a" font-size="9">bob</text>

  <rect x="360" y="285" width="80" height="30" rx="4" fill="#3b82f6" opacity="0.6"/>
  <text x="400" y="305" text-anchor="middle" fill="#fff" font-size="11">7703</text>
  <text x="400" y="330" text-anchor="middle" fill="#64748b" font-size="9">(free)</text>

  <text x="460" y="305" fill="#64748b" font-size="18">...</text>

  <rect x="500" y="285" width="80" height="30" rx="4" fill="#3b82f6" opacity="0.6"/>
  <text x="540" y="305" text-anchor="middle" fill="#fff" font-size="11">9699</text>
  <text x="540" y="330" text-anchor="middle" fill="#64748b" font-size="9">(free)</text>

  <text x="400" y="380" text-anchor="middle" fill="#94a3b8" font-size="11">Ports 7700-9699 (2000 slots) &mdash; allocated sequentially, socket-bind tested</text>
  <text x="400" y="396" text-anchor="middle" fill="#94a3b8" font-size="11">Stored in memory: user_instances[username] = {port, proc, password}</text>
</svg>

### Spawning Sequence

1. **Login** triggers `spawn_user_ttyd(username, password)`
2. Check `user_instances` for existing session — reuse if process alive
3. Allocate free port via socket bind test (7700+)
4. Build tmux command: create/attach `main` session, map tabs to windows
5. Run: `sshpass -p PASS ssh user@127.0.0.1 ttyd -W -a -i 127.0.0.1 -p PORT bash -lc "tmux_cmd"`
6. Poll port until ttyd responds (timeout 4s)
7. Store `{port, proc, password}` in `user_instances`

---

## Frontend SPA Layout

<svg viewBox="0 0 800 500" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, Arial, sans-serif">
  <rect width="800" height="500" rx="12" fill="#0f172a"/>

  <!-- Browser window chrome -->
  <rect x="40" y="20" width="720" height="460" rx="10" fill="#16213e" stroke="#334155" stroke-width="2"/>

  <!-- Navbar -->
  <rect x="42" y="22" width="716" height="42" rx="8" fill="#1a1a2e"/>
  <circle cx="60" cy="43" r="6" fill="#e94560"/>
  <circle cx="78" cy="43" r="6" fill="#f59e0b"/>
  <circle cx="96" cy="43" r="6" fill="#22c55e"/>
  <text x="120" y="47" fill="#e2e8f0" font-size="13" font-weight="600">Terminal</text>
  <rect x="620" y="32" width="50" height="22" rx="4" fill="#334155"/>
  <text x="645" y="47" text-anchor="middle" fill="#94a3b8" font-size="10">Files</text>
  <rect x="680" y="32" width="60" height="22" rx="4" fill="#334155"/>
  <text x="710" y="47" text-anchor="middle" fill="#94a3b8" font-size="10">Logout</text>

  <!-- Tab bar -->
  <rect x="42" y="64" width="716" height="32" rx="0" fill="#0d1b2a"/>
  <rect x="50" y="68" width="90" height="24" rx="4" fill="#16213e" stroke="#e94560" stroke-width="0 0 2 0"/>
  <text x="95" y="84" text-anchor="middle" fill="#e94560" font-size="11" font-weight="600">Tab 1</text>
  <rect x="148" y="68" width="90" height="24" rx="4" fill="#0f172a"/>
  <text x="193" y="84" text-anchor="middle" fill="#64748b" font-size="11">Tab 2</text>
  <rect x="246" y="68" width="90" height="24" rx="4" fill="#0f172a"/>
  <text x="291" y="84" text-anchor="middle" fill="#64748b" font-size="11">Tab 3</text>
  <rect x="700" y="68" width="24" height="24" rx="4" fill="#0f172a"/>
  <text x="712" y="85" text-anchor="middle" fill="#64748b" font-size="14">+</text>

  <!-- Split: File panel + Terminal -->
  <!-- File panel -->
  <rect x="42" y="96" width="220" height="382" fill="#0d1b2a" stroke="#1e3a5f" stroke-width="1"/>

  <!-- Breadcrumbs -->
  <rect x="50" y="102" width="204" height="24" rx="3" fill="#16213e"/>
  <text x="60" y="118" fill="#3b82f6" font-size="10">~ / projects / myapp</text>

  <!-- File entries -->
  <rect x="50" y="132" width="204" height="24" rx="3" fill="transparent"/>
  <text x="72" y="148" fill="#f59e0b" font-size="11">src/</text>
  <rect x="50" y="158" width="204" height="24" rx="3" fill="transparent"/>
  <text x="72" y="174" fill="#f59e0b" font-size="11">docs/</text>
  <rect x="50" y="184" width="204" height="24" rx="3" fill="transparent"/>
  <text x="72" y="200" fill="#e2e8f0" font-size="11">README.md</text>
  <text x="200" y="200" text-anchor="end" fill="#64748b" font-size="9">2.3 KB</text>
  <rect x="50" y="210" width="204" height="24" rx="3" fill="transparent"/>
  <text x="72" y="226" fill="#e2e8f0" font-size="11">package.json</text>
  <text x="200" y="226" text-anchor="end" fill="#64748b" font-size="9">1.1 KB</text>
  <rect x="50" y="236" width="204" height="24" rx="3" fill="transparent"/>
  <text x="72" y="252" fill="#e2e8f0" font-size="11">.env</text>
  <text x="200" y="252" text-anchor="end" fill="#64748b" font-size="9">256 B</text>

  <!-- Upload zone -->
  <rect x="50" y="430" width="204" height="40" rx="6" fill="#16213e" stroke="#334155" stroke-dasharray="4,3"/>
  <text x="152" y="454" text-anchor="middle" fill="#64748b" font-size="10">Drop files to upload</text>

  <!-- Terminal area -->
  <rect x="262" y="96" width="496" height="382" fill="#0a0a1a"/>
  <text x="280" y="120" fill="#22c55e" font-size="12" font-family="monospace">alice@server:~$ </text>
  <text x="416" y="120" fill="#e2e8f0" font-size="12" font-family="monospace">ls -la</text>
  <text x="280" y="140" fill="#94a3b8" font-size="12" font-family="monospace">total 24</text>
  <text x="280" y="156" fill="#94a3b8" font-size="12" font-family="monospace">drwxr-xr-x  5 alice alice 4096 Mar  8</text>
  <text x="280" y="172" fill="#3b82f6" font-size="12" font-family="monospace">drwxr-xr-x  3 alice alice 4096 Mar  7</text>
  <text x="280" y="188" fill="#94a3b8" font-size="12" font-family="monospace">-rw-r--r--  1 alice alice 2341 Mar  8</text>
  <text x="280" y="220" fill="#22c55e" font-size="12" font-family="monospace">alice@server:~$ </text>
  <rect x="416" y="210" width="8" height="15" fill="#e94560" opacity="0.8"/>

  <!-- Label: iframe -->
  <text x="510" y="465" text-anchor="middle" fill="#334155" font-size="10">iframe &rarr; /ut/7701/ &rarr; ttyd &rarr; xterm.js &rarr; tmux</text>
</svg>

---

## File Browser Architecture

### Path Token System

Path tokens prevent directory traversal attacks by encoding filesystem paths as opaque, signed tokens.

```
path_b64 = base64url(abs_path)
sig      = HMAC-SHA256(SECRET_KEY, "username:abs_path")
token    = path_b64 + "." + sig
```

Every file operation requires a valid token. Tokens are username-scoped — a token generated for `alice` cannot be used by `bob`.

### File API Endpoints

| Endpoint | Method | Description | Limit |
|----------|--------|-------------|-------|
| `/api/files/list` | GET | List directory contents | — |
| `/api/files/read` | GET | Read file content (text detection) | 2 MB |
| `/api/files/write` | POST | Write/save file content | 2 MB |
| `/api/files/download` | GET | Download file (binary-safe) | — |
| `/api/files/upload` | POST | Upload file | 10 MB |
| `/api/files/mkdir` | POST | Create directory | — |
| `/api/files/delete` | POST | Delete file or directory | — |
| `/api/files/rename` | POST | Rename file or directory | — |

### File Operations Execution Model

All file operations run as the authenticated user via `run_as_user()`:

```
auth.py  --[sshpass + ssh]--> user@127.0.0.1  --[python3 -]--> script on stdin
```

This ensures OS-level permission enforcement: users can only access files their UID permits.

---

## nginx Routing

<svg viewBox="0 0 800 380" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, Arial, sans-serif">
  <rect width="800" height="380" rx="12" fill="#0f172a"/>

  <text x="400" y="30" text-anchor="middle" fill="#e2e8f0" font-size="14" font-weight="600">nginx Routing Rules (:7680)</text>

  <!-- Routes -->
  <g transform="translate(40, 50)">
    <!-- /login -->
    <rect x="0" y="0" width="200" height="40" rx="6" fill="#22c55e" opacity="0.2" stroke="#22c55e" stroke-width="1"/>
    <text x="10" y="25" fill="#86efac" font-size="12" font-weight="600">/login, /api/login</text>
    <text x="230" y="25" fill="#94a3b8" font-size="11">&rarr; proxy auth.py :7682</text>
    <text x="530" y="25" fill="#64748b" font-size="10">(no auth required)</text>

    <!-- /api/auth -->
    <rect x="0" y="55" width="200" height="40" rx="6" fill="#e94560" opacity="0.2" stroke="#e94560" stroke-width="1"/>
    <text x="10" y="80" fill="#fecdd3" font-size="12" font-weight="600">/api/auth</text>
    <text x="230" y="80" fill="#94a3b8" font-size="11">&rarr; proxy auth.py :7682</text>
    <text x="530" y="80" fill="#64748b" font-size="10">(internal subrequest only)</text>

    <!-- / and /app -->
    <rect x="0" y="110" width="200" height="40" rx="6" fill="#3b82f6" opacity="0.2" stroke="#3b82f6" stroke-width="1"/>
    <text x="10" y="135" fill="#93c5fd" font-size="12" font-weight="600">/, /app</text>
    <text x="230" y="135" fill="#94a3b8" font-size="11">&rarr; auth_request &rarr; proxy auth.py</text>
    <text x="530" y="135" fill="#64748b" font-size="10">(serves SPA HTML)</text>

    <!-- /ut/PORT/ -->
    <rect x="0" y="165" width="200" height="40" rx="6" fill="#8b5cf6" opacity="0.2" stroke="#8b5cf6" stroke-width="1"/>
    <text x="10" y="190" fill="#c4b5fd" font-size="12" font-weight="600">/ut/&lt;port&gt;/</text>
    <text x="230" y="185" fill="#94a3b8" font-size="11">&rarr; auth_request (port binding check)</text>
    <text x="230" y="200" fill="#94a3b8" font-size="11">&rarr; proxy ttyd :PORT + WebSocket upgrade</text>

    <!-- sub_filter -->
    <rect x="250" y="210" width="350" height="28" rx="4" fill="#f59e0b" opacity="0.15" stroke="#f59e0b" stroke-width="1"/>
    <text x="260" y="229" fill="#fde68a" font-size="10">sub_filter &lt;/head&gt; &rarr; inject term-hook.js &lt;/head&gt;</text>

    <!-- /api/files/* -->
    <rect x="0" y="250" width="200" height="40" rx="6" fill="#06b6d4" opacity="0.2" stroke="#06b6d4" stroke-width="1"/>
    <text x="10" y="275" fill="#67e8f9" font-size="12" font-weight="600">/api/files/*</text>
    <text x="230" y="275" fill="#94a3b8" font-size="11">&rarr; auth_request &rarr; proxy auth.py</text>
    <text x="530" y="275" fill="#64748b" font-size="10">(client_max_body_size 10m)</text>

    <!-- /api/quick-commands -->
    <rect x="0" y="305" width="200" height="40" rx="6" fill="#06b6d4" opacity="0.2" stroke="#06b6d4" stroke-width="1"/>
    <text x="10" y="330" fill="#67e8f9" font-size="12" font-weight="600">/api/quick-commands</text>
    <text x="230" y="330" fill="#94a3b8" font-size="11">&rarr; auth_request &rarr; proxy auth.py</text>
  </g>
</svg>

---

## Security Model

<svg viewBox="0 0 800 350" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, Arial, sans-serif">
  <rect width="800" height="350" rx="12" fill="#0f172a"/>
  <text x="400" y="30" text-anchor="middle" fill="#e2e8f0" font-size="14" font-weight="600">Security Layers</text>

  <!-- Layer 1: Network -->
  <rect x="40" y="50" width="720" height="50" rx="8" fill="#3b82f6" opacity="0.15" stroke="#3b82f6" stroke-width="1"/>
  <text x="60" y="72" fill="#3b82f6" font-size="12" font-weight="600">Network</text>
  <text x="60" y="88" fill="#93c5fd" font-size="10">Cloudflare tunnel (HTTPS) &bull; ttyd binds 127.0.0.1 only &bull; SSH localhost only</text>

  <!-- Layer 2: Auth -->
  <rect x="60" y="110" width="680" height="50" rx="8" fill="#e94560" opacity="0.15" stroke="#e94560" stroke-width="1"/>
  <text x="80" y="132" fill="#e94560" font-size="12" font-weight="600">Authentication</text>
  <text x="80" y="148" fill="#fecdd3" font-size="10">HMAC-SHA256 tokens &bull; __Host- cookie prefix &bull; HttpOnly + Secure + SameSite=Strict &bull; 24h expiry</text>

  <!-- Layer 3: Authorization -->
  <rect x="80" y="170" width="640" height="50" rx="8" fill="#f59e0b" opacity="0.15" stroke="#f59e0b" stroke-width="1"/>
  <text x="100" y="192" fill="#f59e0b" font-size="12" font-weight="600">Authorization</text>
  <text x="100" y="208" fill="#fde68a" font-size="10">Port binding in token &bull; nginx auth subrequest &bull; HMAC-signed path tokens (file ops)</text>

  <!-- Layer 4: Isolation -->
  <rect x="100" y="230" width="600" height="50" rx="8" fill="#22c55e" opacity="0.15" stroke="#22c55e" stroke-width="1"/>
  <text x="120" y="252" fill="#22c55e" font-size="12" font-weight="600">Process Isolation</text>
  <text x="120" y="268" fill="#86efac" font-size="10">Per-user UID &bull; OS file permissions &bull; Separate ttyd process per user &bull; Isolated tmux sessions</text>

  <!-- Layer 5: Headers -->
  <rect x="120" y="290" width="560" height="50" rx="8" fill="#8b5cf6" opacity="0.15" stroke="#8b5cf6" stroke-width="1"/>
  <text x="140" y="312" fill="#8b5cf6" font-size="12" font-weight="600">HTTP Hardening</text>
  <text x="140" y="328" fill="#c4b5fd" font-size="10">CSP &bull; X-Frame-Options: SAMEORIGIN &bull; no-referrer &bull; nosniff &bull; Permissions-Policy</text>
</svg>

### Key Security Properties

| Threat | Mitigation |
|--------|-----------|
| Directory traversal | HMAC-signed path tokens (per-user scoped) |
| Session hijacking | HttpOnly + Secure + SameSite=Strict cookies, HMAC-signed tokens |
| Cross-user port access | Token includes port number, verified by nginx auth subrequest |
| Privilege escalation | File ops run as user's UID via SSH; no root needed |
| XSS | Content-Security-Policy, X-Content-Type-Options: nosniff |
| Framing attacks | X-Frame-Options: SAMEORIGIN |
| Supply chain | Zero external Python dependencies (stdlib only) |
| LAN exposure | ttyd binds 127.0.0.1 only; only reachable via nginx |

---

## Deployment & Process Management

### deploy.sh Lifecycle

<svg viewBox="0 0 800 300" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, Arial, sans-serif">
  <defs>
    <marker id="a2" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#64748b"/></marker>
  </defs>
  <rect width="800" height="300" rx="12" fill="#0f172a"/>

  <!-- Steps -->
  <rect x="40" y="30" width="130" height="55" rx="8" fill="#22c55e" opacity="0.3" stroke="#22c55e"/>
  <text x="105" y="52" text-anchor="middle" fill="#86efac" font-size="11" font-weight="600">1. Check sshd</text>
  <text x="105" y="68" text-anchor="middle" fill="#64748b" font-size="9">pw-auth on 127.0.0.1</text>

  <rect x="200" y="30" width="130" height="55" rx="8" fill="#3b82f6" opacity="0.3" stroke="#3b82f6"/>
  <text x="265" y="52" text-anchor="middle" fill="#93c5fd" font-size="11" font-weight="600">2. nginx</text>
  <text x="265" y="68" text-anchor="middle" fill="#64748b" font-size="9">install conf + reload</text>

  <rect x="360" y="30" width="130" height="55" rx="8" fill="#e94560" opacity="0.3" stroke="#e94560"/>
  <text x="425" y="52" text-anchor="middle" fill="#fecdd3" font-size="11" font-weight="600">3. auth.py</text>
  <text x="425" y="68" text-anchor="middle" fill="#64748b" font-size="9">start/restart if stale</text>

  <rect x="520" y="30" width="130" height="55" rx="8" fill="#f59e0b" opacity="0.3" stroke="#f59e0b"/>
  <text x="585" y="52" text-anchor="middle" fill="#fde68a" font-size="11" font-weight="600">4. cloudflared</text>
  <text x="585" y="68" text-anchor="middle" fill="#64748b" font-size="9">tmux session</text>

  <rect x="680" y="30" width="90" height="55" rx="8" fill="#8b5cf6" opacity="0.3" stroke="#8b5cf6"/>
  <text x="725" y="52" text-anchor="middle" fill="#c4b5fd" font-size="11" font-weight="600">5. Report</text>
  <text x="725" y="68" text-anchor="middle" fill="#64748b" font-size="9">health checks</text>

  <!-- Arrows -->
  <line x1="170" y1="57" x2="198" y2="57" stroke="#64748b" stroke-width="1.5" marker-end="url(#a2)"/>
  <line x1="330" y1="57" x2="358" y2="57" stroke="#64748b" stroke-width="1.5" marker-end="url(#a2)"/>
  <line x1="490" y1="57" x2="518" y2="57" stroke="#64748b" stroke-width="1.5" marker-end="url(#a2)"/>
  <line x1="650" y1="57" x2="678" y2="57" stroke="#64748b" stroke-width="1.5" marker-end="url(#a2)"/>

  <!-- Health checks detail -->
  <rect x="40" y="110" width="720" height="175" rx="8" fill="#1e293b" stroke="#334155"/>
  <text x="400" y="135" text-anchor="middle" fill="#e2e8f0" font-size="13" font-weight="600">Health Check Matrix</text>

  <text x="60" y="160" fill="#22c55e" font-size="11">sshd</text>
  <text x="200" y="160" fill="#94a3b8" font-size="10">pgrep sshd + password auth config check</text>

  <text x="60" y="182" fill="#3b82f6" font-size="11">nginx</text>
  <text x="200" y="182" fill="#94a3b8" font-size="10">config diff detection + syntax test + port :7680 listening</text>

  <text x="60" y="204" fill="#e94560" font-size="11">auth.py</text>
  <text x="200" y="204" fill="#94a3b8" font-size="10">file mtime vs process start time + port :7682 + HTTP 401 from /api/auth</text>

  <text x="60" y="226" fill="#f59e0b" font-size="11">cloudflared</text>
  <text x="200" y="226" fill="#94a3b8" font-size="10">tmux session exists + pgrep cloudflared</text>

  <text x="60" y="254" fill="#8b5cf6" font-size="11">end-to-end</text>
  <text x="200" y="254" fill="#94a3b8" font-size="10">curl :7680/login (200) + curl :7682/api/auth (401) + curl https://hostname/login (200)</text>
</svg>

### Smart Restart

deploy.sh is **idempotent** — it only starts or restarts components that need it:

- **sshd**: ensures password auth enabled for 127.0.0.1 via Match block
- **nginx**: detects config drift (diff against installed), reloads only if changed
- **auth.py**: compares file mtime against process start time, restarts if stale
- **cloudflared**: starts in tmux if not already running

### Service Backends (by platform)

| Platform | auth.py | nginx | cloudflared |
|----------|---------|-------|-------------|
| Linux + systemd | `systemctl --user` service | `sudo systemctl reload` | tmux session |
| Linux (no systemd) | nohup + PID file | `sudo service nginx reload` | tmux session |
| macOS | launchd plist | Homebrew service | tmux session |

---

## Key Files

| File | Lines | Purpose |
|------|-------|---------|
| `auth.py` | ~5400 | Monolith: HTTP auth, SPA frontend, ttyd management, file browser, quick commands |
| `cf_tunnel_install.sh` | ~6300 | One-time setup script + embedded copy of auth.py |
| `deploy.sh` | ~850 | Idempotent deploy: health checks, smart restart, drift detection |
| `nginx/ttyd.conf` | ~80 | Reverse proxy template: auth subrequest, WebSocket, JS injection |
| `create-user.sh` | ~35 | System user creation (macOS/Linux) |
| `.env.example` | ~17 | Configuration template |

### Dual-File Sync Requirement

`auth.py` and `cf_tunnel_install.sh` contain the **same Python + HTML + JS code**. Any change to auth.py must be manually replicated in cf_tunnel_install.sh (embedded starting around line 506).

---

## Data Persistence

| Data | Storage | Lifetime |
|------|---------|----------|
| Session tokens | Process memory | Until restart (logout all) |
| User passwords | Process memory | During active session |
| UI settings | Browser localStorage (`ttyd_*`) | Permanent (per browser) |
| Quick commands | `~/ttyd_quick_command.json` | Permanent (per user) |
| Tunnel credentials | `~/.cloudflared/` | Permanent |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_PORT` | 7682 | Auth service listen port |
| `SESSION_MAX_AGE` | 86400 | Token validity (seconds) |
| `COOKIE_SECURE` | true | Require HTTPS for cookies |
| `TTYD_START_PORT` | 7700 | Port pool start |
| `TTYD_SECRET` | (random) | Fixed HMAC secret key |
| `TTYD_BIN` | (auto) | Override ttyd binary path |
| `SSHPASS_BIN` | (auto) | Override sshpass binary path |
| `SSH_BIN` | (auto) | Override ssh binary path |
| `ACCESS_LOG_ENABLED` | false | Enable HTTP request logging |
