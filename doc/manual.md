# Web Terminal User Manual

A browser-based multi-tenant terminal with file management, split panes, themes, and remote desktop access.

---

## Login

Enter your username and password to sign in. Each user gets an isolated shell session running under their own system account.

![Login Page](images/login.png)

---

## Main Interface

After login you land on the terminal with a toolbar at the top and a tab bar below it.

![Main Terminal](images/main-terminal.png)

### Toolbar

The toolbar provides quick access to all features:

![Toolbar](images/toolbar.png)

| Button | Description |
|--------|-------------|
| **+ New Tab** | Open a new terminal tab |
| **Split Right / Split Down** | Split the view into side-by-side or stacked panes |
| **A- / A+** | Decrease / increase font size (current size shown between them) |
| **Commands** | Open the quick commands library |
| **Files** | Toggle the file browser sidebar |
| **Settings** | Terminal settings (font, cursor, scrollback) |
| **Themes** | Color theme picker |
| **Fullscreen** | Enter browser fullscreen mode |
| **Desktop** | Open a remote desktop (VNC) tab |
| **Reconnect** | Reconnect the current terminal session |
| **Logout** | Sign out and return to the login page |

On mobile devices, overflow buttons collapse into a hamburger menu.

---

## Tabs

Each tab is an independent terminal session backed by a tmux window. Your tabs persist across page reloads.

![Multiple Tabs](images/multi-tabs.png)

- **New Tab** -- click **+ New Tab** or press `Ctrl+Shift+T`
- **Switch Tab** -- click a tab name
- **Rename Tab** -- double-click the tab name and type a new name
- **Close Tab** -- click the **x** button or press `Ctrl+Shift+W`

Tabs are backed by tmux grouped sessions. Closing a tab detaches the tmux client but the underlying tmux window and its processes keep running. Reopening or reconnecting reattaches to the same window.

---

## Split Panes

Split the terminal view to see two sessions side by side.

![Split Panes](images/split-panes.png)

| Action | Button | Shortcut |
|--------|--------|----------|
| Split horizontally | **Split Right** | `Ctrl+Shift+\` |
| Split vertically | **Split Down** | `Ctrl+Shift+-` |
| Close split | **Unsplit** | `Ctrl+Shift+U` |

Each pane shows a different tab. Click a pane to focus it, then use the tab bar to change which session is displayed. You can drag the divider to resize panes.

---

## Settings

Click **Settings** in the toolbar to configure the terminal.

![Settings Panel](images/settings.png)

| Setting | Options | Default |
|---------|---------|---------|
| **Font Size** | 8 -- 36 px | 15 px |
| **Font Family** | Courier, Menlo, Monaco, Consolas, Ubuntu Mono, and more | Courier |
| **Cursor Style** | Block, Underline, Bar | Block |
| **Cursor Blink** | On / Off | On |
| **Scrollback Lines** | 100 -- 100,000 | 10,000 |
| **Disable Leave Alert** | On / Off | Off |

Click **Apply to All Tabs** to push changes to every open terminal. Settings are saved in your browser and restored on next visit.

The **A-** and **A+** buttons in the toolbar provide quick font size adjustment without opening the settings panel.

---

## Themes

Click **Themes** to choose a color scheme.

![Theme Panel](images/themes.png)

### Preset Themes

Default Dark, Light, Monokai, Solarized Dark, Dracula, Nord, Gruvbox, Tokyo Night

### Custom Colors

Use the color pickers to override individual colors:
- **Background** -- terminal background
- **Foreground** -- default text color
- **Cursor** -- cursor color
- **Selection** -- text selection highlight

Click **Apply to All Tabs** to apply your theme everywhere.

---

## Quick Commands

Click **Commands** to open a library of saved terminal commands you can run with one click.

![Commands Panel](images/commands.png)

- **Search** -- type to filter commands by name, text, or tag
- **Tags** -- click a tag chip to filter by category
- **Run** -- click any command to send it to the active terminal
- **Add** -- create a new command with a name, command text, and tags
- **Edit / Delete** -- manage existing commands

Commands are stored server-side and shared across sessions.

---

## File Browser

Click **Files** to open the file browser sidebar on the left.

![File Browser](images/file-browser.png)

### Navigation

- Click a folder to enter it
- Click **..** to go up one level
- Click the breadcrumb path segments at the top to jump to a parent directory
- Double-click the breadcrumb bar to type a path directly

### File Operations

| Action | How |
|--------|-----|
| **Upload** | Click **+ Upload** or drag-and-drop files onto the sidebar |
| **Paste Image** | Click **Paste Img** to paste an image from clipboard |
| **New Folder** | Click **+ Folder** |
| **Download** | Click a file to preview, then use the download button |
| **Rename** | Right-click or use the context action on a file |
| **Delete** | Right-click or use the context action (with confirmation) |

### File Preview

Clicking a file opens a preview modal:
- **Text files** -- displayed with syntax highlighting; editable inline
- **Markdown** (`.md`) -- rendered as formatted HTML with a toggle to view source
- **Images** -- displayed in the modal
- **Video / Audio** -- embedded player
- **PDF** -- embedded viewer

### Sorting

Click the column headers (**Name**, **Date**, **Size**) to sort the file listing.

---

## Remote Desktop (VNC)

Click **Desktop** in the toolbar to open a graphical desktop session via noVNC.

![Desktop VNC](images/desktop-vnc.png)

The desktop runs in a dedicated tab. It connects to the server's VNC display through a websocket proxy. Use the noVNC controls on the left edge to toggle the sidebar, enter fullscreen, or adjust settings.

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Shift+T` | New Tab |
| `Ctrl+Shift+W` | Close Tab |
| `Ctrl+Shift+]` | Next Tab |
| `Ctrl+Shift+[` | Previous Tab |
| `Ctrl+Shift+E` | Toggle File Browser |
| `Ctrl+Shift+\` | Split Right |
| `Ctrl+Shift+-` | Split Down |
| `Ctrl+Shift+U` | Unsplit |

---

## Mobile Support

On smaller screens the interface adapts automatically:

- Toolbar buttons collapse into a **hamburger menu** (three-line icon)
- A **special keys bar** appears at the bottom with touch-friendly buttons for Ctrl, Shift, Alt, Tab, Enter, Delete, and arrow keys
- Long-press to select terminal text; a copy modal provides reliable clipboard access
- Split panes are disabled below 768px width

---

## API Tokens

The Settings panel includes an **API Tokens** section at the bottom for creating bearer tokens that allow programmatic (non-browser) access to the HTTP API.

### Creating a Token

1. Open **Settings** in the toolbar
2. Scroll to the **API Tokens** section
3. Click **+ New Token** and enter a descriptive name (e.g. "ci-bot", "laptop")
4. Copy the token immediately -- it is shown only once

### Using a Token

Pass the token in an `Authorization` header:

```
Authorization: Bearer <your-token>
```

Tokens authenticate the same API endpoints as a browser session (file operations, quick commands, etc.) but cannot access terminal WebSocket connections (`/ut/...`).

### Revoking a Token

Click **Revoke** next to any token in the Settings panel to permanently delete it.

---

## Command-Line Client (`mics_cli`)

A Node.js CLI distributed alongside the server in the `cli/` directory. It wraps the HTTP API so you can interact with the webterminal from any machine that has Node 18+ — or as a single packaged binary built with `./build_cli.sh`.

The CLI keeps zero runtime dependencies and works entirely over the same HTTPS path the SPA uses, so it goes straight through cloudflared without needing SSH or any extra firewall rules.

### Setup

```sh
cd cli
npm link                                            # installs the `mics_cli` binary
mics_cli login --url https://your-host              # mints a bearer token
```

The token is saved to `~/.mics-webterminal/auth.json` (mode 0600). You can also point at an existing token via a `.env` file:

```
MICS_TOKEN=agt_xxxxxxxxxxxxxxxx
MICS_URL=https://your-host
```

### Commands

```text
mics_cli exec <command>                  Run a shell command (one-shot)
mics_cli shell                           Open an interactive shell (WebSocket)
mics_cli ls [path]                       List files in a directory
mics_cli cat <path>                      Print a text file
mics_cli download <path> [-o file]       Download a file
mics_cli upload <local> <remote-dir>     Upload a local file
mics_cli mkdir <path>                    Create a directory
mics_cli rm <path>                       Delete a file or directory
mics_cli tokens list                     List your bearer tokens
mics_cli tokens revoke <name>            Revoke a token
mics_cli quick-commands list/export/import
mics_cli login / logout / whoami / help [cmd]
```

### Examples

```sh
mics_cli exec "uname -a"                            # one-shot command
mics_cli exec "wc -l" --stdin-file ./access.log     # pipe stdin to remote
mics_cli shell                                      # full interactive shell
mics_cli ls ~                                       # browse files
mics_cli upload ./build.tar.gz ~/uploads
mics_cli download ~/notes.md -o ./notes.md
```

`exec` exits with the remote command's exit code, so it composes naturally with shell pipelines. See [`cli/README.md`](https://github.com/micsapp/micsapp-webterminal/blob/main/cli/README.md) for full per-command flags and options.

### Building a standalone binary

```sh
./build_cli.sh           # current OS/arch  → cli/dist/mics_cli (~57MB)
./build_cli.sh linux     # Linux x64 + arm64
./build_cli.sh mac       # macOS x64 + arm64
./build_cli.sh win       # Windows x64
```

The resulting binary bundles Node and runs on machines that don't have Node installed.

---

## Shell Command Execution (`/api/exec`)

The `/api/exec` endpoint lets you run shell commands remotely and receive structured output. Requires a session cookie or bearer token. The CLI's `mics_cli exec` is a thin wrapper over this endpoint.

### Request

```bash
curl -X POST https://host/api/exec \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"command": "ls -la /tmp"}'
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `command` | Yes | -- | Shell command to run (via `bash -c`) |
| `timeout` | No | 30 | Max seconds to wait (1--300) |
| `cwd` | No | User's home | Working directory |
| `stdin` | No | -- | String piped to stdin |

Request body is limited to 64 KB.

### Response

```json
{
  "stdout": "...",
  "stderr": "...",
  "exit_code": 0
}
```

Stdout and stderr are each capped at 512 KB. Commands that exceed the timeout return HTTP 408.

---

## Interactive Shell (`/api/shell`)

`/api/shell` upgrades the connection to a **WebSocket** and pumps bytes between the client and a fresh `sudo -u <user> -i` login shell on a PTY. Bearer-token auth, same as `/api/exec`. This is the endpoint behind `mics_cli shell`.

Because the session rides on the existing HTTPS tunnel, it works through cloudflared with no extra SSH route — you don't need port 22 open anywhere.

### Query parameters

| Param | Default | Description |
|-------|---------|-------------|
| `cols` | 80 | Initial terminal width |
| `rows` | 24 | Initial terminal height |

### WebSocket protocol

| Direction | Frame type | Meaning |
|-----------|------------|---------|
| Server → Client | Binary | Raw PTY output bytes |
| Client → Server | Binary | Raw input bytes (keystrokes) |
| Client → Server | Text | JSON control messages |

The only control message defined today is window resize:

```json
{"type": "resize", "cols": 120, "rows": 40}
```

### Quickest way to use it

```sh
mics_cli shell
```

The CLI handles raw stdin mode, forwards `SIGWINCH`, echoes binary output to stdout, and tears down cleanly when the remote shell exits. Type `exit` (or `Ctrl+D`) to end the session.

---

## Tips

- **Session persistence** -- your shell processes run inside tmux. Even if you close the browser, processes keep running. Reopen the same tabs to reconnect.
- **Clipboard** -- iframes have clipboard API access. Copy/paste should work natively. On mobile, use the copy modal for reliable results.
- **Reconnect** -- if a terminal goes blank or disconnects, click **Reconnect** to reattach without losing your tmux session.
- **Fullscreen** -- press the **Fullscreen** button for a distraction-free terminal experience.
