# Multi-Server Terminal Tabs — SSH-Backed Plan

## Status

Implemented in web-terminal 1.2.0+. The protected Droppy repository is the
catalog source; `ssh_mode` selects direct or Cloudflare-tunneled SSH. The
browser stores only the approved server ID and tmux slot, and the backend
revalidates that ID before creating or restoring a remote window.


Remote setup is opt-in per deployment. `./deploy.sh --remote-setup` prompts for
the repository URL and passcode, validates the list, saves the protected
per-user config, installs the local tunnel client if needed, deploys the Nginx
API routes, and restarts the auth service. If
`~/.config/micsapp-webterminal/server-repo.conf` is absent, the API returns an
empty catalog and the UI shows no remote servers, regardless of cached data or
environment variables.

## Decision

Add remote systems to the existing **+ New Tab** workflow by opening an SSH connection inside a new ttyd/tmux window.

This provides practical multi-server terminal access without introducing cross-server WebSocket relays, browser token storage, cross-origin iframes, or a federated authentication system.

## User experience

The **+ New Tab** control becomes a split button or menu:

- Local Shell
- Production
- Staging
- NAS
- Configured remote servers

Selecting a remote system creates a normal terminal tab, for example:

```text
Local · Shell 1    Production · Shell 2    NAS · Shell 3
```

The existing tab functionality continues to work:

- Rename and close tabs
- Restore tabs after a browser refresh
- Arrange local and remote terminals in split panes
- Apply terminal themes, fonts, fullscreen, and reconnect behavior
- Use the existing keyboard shortcuts

For backward compatibility, `Ctrl+Shift+T` should continue to open a local shell. The dropdown beside **+ New Tab** provides the server picker.

## Architecture

```text
Browser
   │ HTTPS/WebSocket
   ▼
Current web-terminal server
   │
   ├── Local tab ─────────────► local shell
   ├── Production tab ── SSH ─► production server
   ├── Staging tab ───── SSH ─► staging server
   └── NAS tab ───────── SSH ─► NAS
```

The browser communicates only with the current web-terminal installation. The current ttyd and tmux processes create and preserve the tabs, while standard SSH handles connections to other systems.

The other servers do not need special federation endpoints. Their existing web-terminal services may continue running independently.

## Embedded web-terminal option

Each registered server also exposes its existing web-terminal as an internal
iframe tab. Framing remains limited to the trusted HTTPS origins configured by
`WEBTERMINAL_FRAME_ORIGINS`; the default allowlist covers `micstec.com` and
`wetigu.com` subdomains. Remote login sessions remain independent, use Secure
`SameSite=None` cookies, and are never converted into local tmux sessions.

Registration checks the destination's live CSP and rejects
`X-Frame-Options`. If an older deployment is detected,
`deploy.sh --refresh-web` refreshes only nginx and the auth web app
before the catalog update is uploaded. This makes the framing requirement part
of every future register/update operation.

The SSH-backed option remains separate and continues to provide the locally
managed tmux session, reconnect, session-list, and shell settings behavior.

## Server configuration

Each destination is registered in the shared `micsapp-webterminal-server-list`
JSON document. Tunnel mode expects a Cloudflare SSH hostname; direct mode
expects a publicly reachable SSH hostname:

```json
{
  "id": "minipc2.micstec.com",
  "name": "minipc2",
  "web_hostname": "minipc2.micstec.com",
  "ssh_mode": "tunnel",
  "ssh_hostname": "ssh-minipc2.micstec.com",
  "enabled": true
}
```

Register or update a destination with `ssh-tunnel-tui.sh` server mode. The
destination still needs a working `sshd` and either a Cloudflare SSH ingress or
direct network reachability. Each web-terminal user also needs a matching
remote account and SSH key, SSH config, or interactive password.

The legacy alias examples below describe the equivalent per-user SSH settings;
the catalog itself stores `ssh_hostname` and `ssh_mode`, not shell commands.


Remote targets should be defined as SSH host aliases. Each web-terminal user can configure aliases in `~/.ssh/config`:

```sshconfig
Host production
    HostName 10.0.0.21
    User mli
    IdentityFile ~/.ssh/id_ed25519
    ServerAliveInterval 30
    ServerAliveCountMax 3

Host staging
    HostName staging.example.com
    User mli
    IdentityFile ~/.ssh/id_ed25519
    ServerAliveInterval 30
    ServerAliveCountMax 3

Host nas
    HostName nas.example.com
    User mli
    IdentityFile ~/.ssh/id_ed25519
    ServerAliveInterval 30
    ServerAliveCountMax 3
```

The web-terminal server catalog can then reference only those aliases:

```json
[
  {
    "id": "local",
    "name": "Local Shell",
    "type": "local"
  },
  {
    "id": "production",
    "name": "Production",
    "type": "ssh",
    "ssh_host": "production"
  },
  {
    "id": "staging",
    "name": "Staging",
    "type": "ssh",
    "ssh_host": "staging"
  },
  {
    "id": "nas",
    "name": "NAS",
    "type": "ssh",
    "ssh_host": "nas"
  }
]
```

The catalog must contain SSH aliases, not arbitrary shell commands.

## Authentication

SSH keys are the recommended authentication method.

```bash
ssh-keygen -t ed25519
ssh-copy-id production
ssh-copy-id staging
ssh-copy-id nas
```

If SSH keys are not configured, the user can type the remote password directly into the terminal. The web application should never collect, save, or transmit that remote password itself.

The remote host key should be verified before routine use:

```bash
ssh production
```

The user should confirm the displayed fingerprint against a trusted source. `StrictHostKeyChecking=no` must not be added automatically.

## Tab data model

Extend the current tab object with a target type and server ID:

```javascript
{
  id: "tab-2",
  name: "Production · Shell 2",
  type: "ssh",
  serverId: "production",
  windowSlot: 1
}
```

A local tab remains similar:

```javascript
{
  id: "tab-1",
  name: "Local · Shell 1",
  type: "local",
  serverId: "local",
  windowSlot: 0
}
```

Only the safe server ID and display information are stored in browser `localStorage`. SSH credentials and private keys remain in the user's server-side home directory.

## Terminal startup behavior

For a local tab, tmux creates the current login shell as it does today.

For an SSH tab, tmux creates the requested window and starts:

```bash
ssh production
```

The SSH alias must be passed as a distinct process argument or strictly validated before command construction. It must never be concatenated from unrestricted browser input.

Suggested validation:

```text
^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$
```

The backend must also verify that the alias exists in the configured server catalog. Validation alone is not authorization.

## Manage Servers behavior

The first version can use an administrator-managed JSON configuration file. This is safer and smaller than building a complete management API immediately.

A later version may add a UI with:

- Friendly name
- SSH alias
- Optional color or icon
- Enabled/disabled status
- Test Connection button

The test operation should execute a fixed command such as:

```bash
ssh -o BatchMode=yes production true
```

It must not accept an arbitrary command from the browser.

## Implementation plan

### Phase 1 — Configuration and backend

1. Add a remote-system catalog with a local entry and named SSH targets.
2. Load and validate the catalog when the authentication service starts.
3. Add a read-only endpoint that returns safe target metadata without credentials or paths.
4. Extend terminal startup arguments to include an approved server ID.
5. Start either a local shell or `ssh <approved-alias>` in the selected tmux window.
6. Preserve the existing per-user ttyd port and tmux window-slot model.

### Phase 2 — Tab interface

1. Convert **+ New Tab** into a local-action button with a server dropdown.
2. Add the server ID and tab type to the tab data model.
3. Display the system name in each tab label and tooltip.
4. Restore remote tabs from `localStorage` using the saved server ID.
5. Keep local tabs as the default for existing saved tab data.

### Phase 3 — Reliability and feedback

1. Show a clear SSH connection failure inside the terminal.
2. Preserve remote terminals through normal browser refreshes using tmux.
3. Ensure reconnect reloads the correct remote target.
4. Add an optional status indicator based on the SSH process or a safe connection test.
5. Keep terminal sessions independent across tabs and window slots.

### Phase 4 — Testing and documentation

Add tests covering:

- Opening a local tab
- Opening each configured remote target
- Rejecting unknown or malformed target IDs
- Restoring local and remote tabs after refresh
- Closing a remote tab and its tmux window
- Renaming a remote tab
- Mixing local and remote tabs in split panes
- Keyboard shortcuts continuing to work
- No credentials or private-key content appearing in HTML, URLs, API responses, or `localStorage`

Update the user manual, deployment documentation, example configuration, and embedded installer copy of `auth.py`.

## Main code areas

The expected changes are concentrated in:

- `auth.py` — server catalog, tab picker UI, tab model, and ttyd/tmux startup behavior
- `.env.example` or a new example systems configuration — catalog location and defaults
- `cf_tunnel_install.sh` — synchronized embedded copy of `auth.py`
- `test/cypress/e2e/03-tabs.cy.js` — local and remote tab behavior
- `doc/manual.md` — administrator setup and user instructions

This is a moderate change that reuses the current architecture. It should require a few hundred lines of focused code rather than a new federation subsystem.

## Security requirements

- Permit only server IDs present in the configured catalog.
- Validate SSH aliases and pass them safely to the process.
- Never accept an arbitrary SSH command or hostname from tab state.
- Never place passwords, tokens, or private keys in the browser.
- Preserve SSH host-key verification.
- Run the SSH connection as the authenticated web-terminal user.
- Do not allow one web-terminal user to access another user's SSH agent or key files.
- Log the selected server ID and connection result, but never sensitive authentication material.

## Acceptance criteria

The feature is ready when:

1. A user can open both local and configured remote systems from **+ New Tab**.
2. A remote tab opens the intended SSH host as the authenticated web-terminal user.
3. Existing tabs, split panes, themes, fullscreen, rename, close, and restoration continue working.
4. Browser storage contains no SSH secrets.
5. Unknown or manipulated server IDs are rejected by the backend.
6. A browser refresh reconnects to the same tmux-backed remote session.
7. Existing installations with no remote-system catalog continue to behave as local-only terminals.

## Future extension

If terminal-only SSH tabs later become insufficient, federation can be considered for:

- File browsing on the active remote server
- Remote quick commands and API execution
- Remote desktop/noVNC
- Centralized identity and single sign-on
- Fleet health and session administration

Those capabilities should be added separately rather than increasing the risk and size of the initial multi-server terminal feature.
