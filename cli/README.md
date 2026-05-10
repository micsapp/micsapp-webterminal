# mics_cli

Command-line client for [micsapp-webterminal](../). Lets you run remote shell
commands, browse and move files, manage your bearer tokens, and sync quick
commands from any machine that has Node.js 18+.

## Install

The CLI has **no runtime dependencies** — it only needs Node 18+.

### From this repo (development)

```sh
cd cli
npm link              # exposes `mics_cli` on your PATH
```

### On a client machine (no server checkout needed)

Copy or publish the `cli/` directory by itself, then:

```sh
cd path/to/cli
npm install --omit=dev      # no-op (no deps), creates the standard layout
npm link                    # or: npm install -g .
```

You can also run it directly without installing:

```sh
node path/to/cli/bin/mics_cli.js exec "uname -a"
```

## Configure

The fastest way to authenticate is `mics_cli login`:

```sh
mics_cli login --url https://term.example.com
# Username: alice
# Password: ********
# logged in as alice
# saved to  ~/.mics-webterminal/auth.json
# token:    agt_a1b2…  (name: mics_cli@laptop 2026-05-09)
```

The token is saved to `~/.mics-webterminal/auth.json` (mode 0600). After the
first run the URL is remembered too — subsequent `mics_cli login` calls don't
need `--url`.

### Alternative: hand-managed token via .env

If you'd rather paste a token yourself, create one from the **API Tokens**
dialog inside the webterminal SPA, then put it in a `.env` file (see
`.env.example`):

```
MICS_TOKEN=agt_xxxxxxxxxxxxxxxx
MICS_URL=https://term.example.com
```

The CLI walks up from your cwd to find a `.env`. You can also override per
invocation:

```sh
mics_cli --env-file ./prod.env exec whoami
mics_cli --token agt_… --url https://term.example.com ls
```

## Commands

```text
mics_cli exec <command>                  Run a shell command
mics_cli shell                           Open an interactive shell (WebSocket)
mics_cli use <profile>                   Switch the active server profile
mics_cli profiles [list|rm|rename]       Manage saved profiles
mics_cli ls [path]                       List files in a directory
mics_cli cat <path>                      Print a text file
mics_cli download <path> [-o file]       Download a file
mics_cli upload <local> <remote-dir>     Upload a local file
mics_cli mkdir <path>                    Create a directory
mics_cli rm <path>                       Delete a file or directory
mics_cli tokens list                     List your bearer tokens
mics_cli tokens revoke <name>            Revoke a token
mics_cli quick-commands list             List saved quick commands
mics_cli quick-commands export [-o f]    Export quick commands as JSON
mics_cli quick-commands import <file>    Import quick commands from JSON
mics_cli login                           Log in (mints a bearer token)
mics_cli logout                          Forget the saved token
mics_cli whoami                          Show current config
mics_cli help <command>                  Detailed help
```

### Profiles (multi-server)

Each `mics_cli login` saves a **profile** to `~/.mics-webterminal/profiles/<name>.json`.
The active profile is recorded in `~/.mics-webterminal/current` and used by every
command that doesn't pass `--token`/`--url` explicitly. Switch between servers
without re-entering credentials:

```sh
mics_cli login --url https://dev-ssh.wetigu.com   # creates profile "dev-ssh", makes it active
mics_cli login --url https://prod.example.com      # creates profile "prod", switches to it
mics_cli use dev-ssh                               # switch back
mics_cli profiles                                  # list all profiles, marks active
mics_cli --profile prod exec "uname -a"            # one-shot use without switching
```

Profile name defaults to the URL's first hostname label (`dev-ssh.wetigu.com` → `dev-ssh`).
Override with `--profile <name>`. Re-using an auto-derived name needs `--force`;
explicit `--profile NAME` always overwrites.

Migrating from an older single-file `auth.json`? The CLI auto-migrates on first
run — your existing login keeps working under a profile name derived from the
saved URL.

### Where the token comes from

`mics_cli` resolves the token in this order (first match wins):

1. `--token <t>` flag
2. `MICS_TOKEN` env var
3. `.env` file (cwd or any parent)
4. `--profile NAME` flag (loads `profiles/NAME.json`)
5. `MICS_PROFILE` env var
6. The active profile (`~/.mics-webterminal/current`)

`mics_cli whoami` prints which source the active token came from and lists every
saved profile.

Add `--json` to most commands for machine-readable output.

## Examples

```sh
# Confirm setup
mics_cli whoami

# Interactive shell over the same HTTPS the web UI uses
mics_cli shell

# One-shot remote command
mics_cli exec "uname -a"
mics_cli exec "cat /etc/os-release" --cwd /etc

# Pipe local data through a remote command
mics_cli exec "wc -l" --stdin-file ./access.log

# File browsing / transfer
mics_cli ls ~
mics_cli cat ~/.bashrc | head -20
mics_cli download ~/build.tar.gz -o ./build.tar.gz
mics_cli upload ./report.pdf ~/uploads
mics_cli mkdir ~/projects/new-thing

# Token housekeeping
mics_cli tokens list
mics_cli tokens revoke "old laptop"

# Quick-commands sync
mics_cli quick-commands export -o qc.json
mics_cli quick-commands import qc.json --mode replace
```

`exec` exits with the remote command's exit code, so it composes naturally
with shell pipelines:

```sh
mics_cli exec "test -f ~/needed.txt" && echo "present"
```

## Build standalone binaries

You can package `mics_cli` into a single executable that runs on machines
without Node.js installed. The build uses [`@yao-pkg/pkg`](https://www.npmjs.com/package/@yao-pkg/pkg)
(a maintained fork of `vercel/pkg`) and is declared as a `devDependency` so it
isn't pulled in for normal CLI use.

First time setup:

```sh
cd cli
npm install            # installs @yao-pkg/pkg into node_modules
```

Then pick a target:

```sh
npm run build           # current OS/arch (fastest, ~40MB binary in dist/)
npm run build:linux     # Linux x64 + arm64
npm run build:mac       # macOS x64 + arm64
npm run build:win       # Windows x64
npm run build:all       # all five targets
npm run clean           # delete dist/
```

Output goes to `cli/dist/`. Single-target builds produce `dist/mics_cli`
(or `mics_cli.exe`); multi-target builds produce per-platform names like
`mics_cli-linux-x64`, `mics_cli-macos-arm64`, `mics_cli-win-x64.exe`.

The first build downloads the prebuilt Node runtime for each target into
`~/.pkg-cache/`; subsequent builds are cached and fast.

Distribute the binary alongside a sample `.env`. The binary still reads
`MICS_TOKEN` and `MICS_URL` from `.env` exactly the same way.

```sh
./mics_cli whoami
./mics_cli exec "hostname"
```

## Exit codes

- `0` — success
- Non-zero — for `exec`, this is the **remote** command's exit code; for any
  other command, `1` indicates a CLI/network/API error (an `error: …` line is
  written to stderr).

## What's not in v1

- No streaming output for long-running commands. `exec` waits for the remote
  command to finish (subject to `--timeout`) and returns the full output.
  Use `mics_cli shell` for interactive sessions.
- No file rename/move (`mv`). Use `exec "mv …"` for now.
- No symlink creation. Use `exec "ln -s …"`.

## How `mics_cli shell` works

`shell` opens a WebSocket to `/api/shell` on your webterminal host, attaches
your bearer token as `Authorization: Bearer …`, and on the server spawns
`sudo -u <you> -i` against a fresh PTY. Bytes flow both directions; window
resize is sent as a JSON control frame. Because everything rides over the
same HTTPS port the web UI uses, it works through a Cloudflare Tunnel
without exposing SSH separately.
