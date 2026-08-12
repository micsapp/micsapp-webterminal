# Shared Quick-Commands Repository

## Goal

Add a shared, passcode-protected Droppy repository for quick commands, using
the same configuration and safe update pattern as the existing shared server
list. A sync must merge the local and remote collections in both directions so
that running it repeatedly is idempotent and never creates duplicate commands.

This document records the implemented design and its rollout requirements. The
remote file is created separately with a conditional, non-overwriting PUT.

## Existing behavior

- The server catalog is stored at:
  `https://tnas_d.micsapp.com/s/web-terminal-servers/serverlist.json`.
- Its Droppy share URL and passcode are read from
  `~/.config/micsapp-webterminal/server-repo.conf`, with environment variables
  taking precedence.
- Server catalog updates use a GET, capture the response `ETag`, and PUT with
  `If-Match`. An HTTP 412 causes one fresh download and merge retry.
- Each authenticated user's quick commands are currently stored as a bare JSON
  array in `~/ttyd_quick_command.json`.
- Quick-command imports currently merge by case-insensitive command name.

## Repository location and configuration

The command repository will be a sibling of `serverlist.json`:

```text
https://tnas_d.micsapp.com/s/web-terminal-servers/commands.json
```

By default, derive this URL by replacing the last path component of the
configured server repository URL with `commands.json`. This keeps one Droppy
folder and one passcode for both repositories.

Support an optional explicit override:

```text
WEBTERMINAL_COMMANDS_REPO_URL
```

The existing `WEBTERMINAL_SERVER_REPO_PASSCODE` and saved passcode remain the
credentials. Do not add another plaintext credential file.

URL parsing must preserve the scheme, host, path prefix, and any query string
required by Droppy. It must reject non-HTTP(S) URLs and embedded CR/LF
characters.

## `commands.json` schema

The remote file uses an envelope rather than the local bare array so its type,
schema revision, repository revision, and update time can be validated.

Initial file:

```json
{
  "kind": "micsapp-webterminal-commands",
  "schema_version": 1,
  "revision": 0,
  "updated_at": "2026-08-12T00:00:00Z",
  "commands": []
}
```

Command entry:

```json
{
  "id": "19c4887bb66a",
  "name": "Docker status",
  "command": "docker ps --format 'table {{.Names}}\\t{{.Status}}'",
  "tags": "docker,status",
  "created": 1786492800,
  "updated": 1786492800
}
```

Rules:

- `kind` must equal `micsapp-webterminal-commands`.
- `schema_version` and `revision` must be non-negative integers.
- `commands` must be an array of objects.
- Every command requires a non-empty `id`, `name`, and `command`.
- `tags` is stored as the existing comma-separated string for compatibility
  with the browser UI. Imports may accept an array and normalize it to a
  comma-separated string.
- `created` and `updated` are Unix timestamps. Missing legacy timestamps are
  normalized without changing the local file until a successful sync.
- Unknown top-level and command fields are preserved to allow future schema
  extensions.
- Apply the existing quick-command request limits and cap the remote document
  at 8 MiB and a reasonable command count (proposed: 10,000).

The local file remains a bare array. This avoids breaking the current web UI,
export endpoint, CLI, and existing user files.

## Merge identity and duplicate prevention

Each sync computes one canonical union of the local and remote collections.
Commands are matched in this order:

1. Exact non-empty `id` match.
2. Otherwise, normalized name match, where the key is
   `name.strip().casefold()` with internal whitespace collapsed.

The name fallback is required for commands independently created on two
servers, because their random IDs will differ. Two commands with different
names are allowed even when their shell text is identical; aliases can be
intentional.

When a name match has different IDs, keep the remote ID as the stable shared
identity and replace the local ID during the successful sync. A command ID must
be unique in the final collection. Invalid or colliding legacy IDs receive a
new 12-character lowercase hexadecimal ID.

For a matched command:

- The entry with the greater `updated` timestamp wins the editable fields
  `name`, `command`, and `tags`.
- Preserve the earliest valid `created` timestamp.
- If timestamps are equal but fields differ, choose deterministically by a
  canonical JSON comparison. This guarantees that two clients produce the
  same result and prevents endless flip-flopping.
- Preserve unknown fields from both sides; the winning entry takes precedence
  on a collision.

After merging, sort commands deterministically by normalized name and then ID.
Running the merge again with unchanged inputs must report `unchanged`, leave
the repository revision untouched, and produce byte-for-byte equivalent JSON.

### Deletion behavior

The first version is an additive/update merge. A command deleted locally but
still present remotely will return on the next sync. This is intentional: a
plain union cannot distinguish deletion from a client that has not synced yet.

Reliable cross-server deletion should be a later schema revision using
tombstones such as `{ "id": "...", "deleted": 1786492800 }`, plus a defined
retention window. The initial implementation must state this behavior in the
UI instead of silently losing remote commands.

## Sync transaction

Implement a reusable `commands-repo.py` helper, following the structure of
`server-repo.py`, with these operations:

```text
commands-repo.py init OUTPUT
commands-repo.py show INPUT
commands-repo.py merge REMOTE LOCAL REMOTE_OUTPUT LOCAL_OUTPUT
```

`merge` validates both inputs, writes the remote envelope and local bare array,
and prints machine-readable merge metadata: added locally, added remotely,
updated, deduplicated, total, changed, and the proposed repository revision.

The network sync flow is:

1. Acquire a process-local sync lock scoped to the authenticated username.
2. Read the user's local file through `run_as_user`; treat a missing file as an
   empty array, but reject malformed existing JSON rather than overwriting it.
3. GET `commands.json` with `X-Droppy-Share-Passcode` and capture its `ETag`.
4. Validate and merge the downloaded document with the local array in temporary
   files.
5. If the remote result changed, PUT it with `If-Match: <etag>` and
   `Content-Type: application/json`.
6. On HTTP 412, discard the tentative result, GET the latest file, and retry
   the merge once. If it changes again, report a conflict and make no local
   write.
7. After the remote PUT succeeds, or immediately if the remote was unchanged,
   atomically replace the user's local file using a same-directory temporary
   file, mode 0600, `fsync`, and `os.replace` while running as that user.
8. Invalidate any in-memory quick-command cache and return the merge counts.

Never expose the Droppy passcode to browser JavaScript, API responses, command
output, logs, or the authenticated user's subprocess. The parent auth service
performs Droppy requests.

If the local write fails after a successful remote PUT, report the partial
failure clearly. The next sync is safe because merging is idempotent.

## Repository initialization

Creating `commands.json` is an explicit administrative action, separate from a
normal user sync:

1. Generate the validated empty schema shown above.
2. PUT it to the derived URL using `If-None-Match: *` so an existing repository
   cannot be overwritten accidentally.
3. Accept HTTP 200, 201, or 204 as success.
4. Treat HTTP 412 as "already exists" and fetch/validate the existing file.

Add matching server-mode TUI actions:

- Display shared command repository.
- Initialize shared command repository.
- Sync this user's quick commands.

The initialization action should display the exact target URL and require a
confirmation before its first PUT.

## Web API and UI

Add an authenticated endpoint:

```text
POST /api/quick-commands/sync
```

An empty JSON body is sufficient for merge mode. A successful response:

```json
{
  "ok": true,
  "mode": "merge",
  "added_local": 2,
  "added_remote": 1,
  "updated": 1,
  "deduplicated": 1,
  "total": 14,
  "revision": 7,
  "remote_changed": true,
  "local_changed": true
}
```

Add a **Sync** button to the Quick Commands overlay. Disable it while running,
show the merge summary in a toast, and reload the list after success. A failed
sync must not clear or replace the displayed local list.

Keep add, edit, delete, import, and export behavior backward compatible. They
continue to update only the local file until the user presses **Sync**.

## CLI

Extend the existing command group with:

```text
mics_cli quick-commands sync
mics_cli quick-commands sync --json
```

This calls `POST /api/quick-commands/sync`; the CLI never receives Droppy
credentials. Merge is the only mode in the first version. Existing import
`--mode` behavior is unrelated and remains unchanged.

## Files to change

- `commands-repo.py`: new schema validation, normalization, deterministic
  merge, display, and initialization helper.
- `auth.py`: URL derivation, authenticated sync handler, locking, Droppy
  conditional GET/PUT, and the Quick Commands Sync button.
- `cf_tunnel_install.sh`: synchronize the embedded `auth.py` copy and nginx API
  routing, following the repository's dual-file requirement.
- `ssh-tunnel-tui.sh`: display, initialize, and manual sync actions.
- `cli/src/api.js` and `cli/src/index.js`: CLI sync request and output.
- `.env.example`, `README.md`, `doc/manual.md`, and `cli/README.md`: document
  the repository URL, override, merge semantics, and deletion limitation.
- Unit, shell, API, and Cypress tests described below.

## Tests

### Helper unit tests

- Validate a correct empty and populated repository.
- Reject wrong `kind`, invalid versions, malformed commands, and duplicate IDs.
- Merge disjoint local and remote lists into their union.
- Deduplicate different IDs with the same normalized name.
- Resolve newer local and newer remote updates.
- Resolve equal-timestamp conflicts deterministically.
- Preserve the earliest `created`, tags, and unknown fields.
- Prove a second merge is unchanged and byte-stable.
- Verify malformed local JSON is never overwritten.

### Droppy/network tests

- Derive `commands.json` from both a folder URL and a full
  `serverlist.json` URL.
- Send the share passcode only through the curl header file/stdin mechanism.
- Initialize with `If-None-Match: *`.
- Sync PUT uses the downloaded `ETag` in `If-Match`.
- A 412 triggers one refetch and remerge.
- A second 412 returns a conflict without changing the local file.
- HTTP/auth/timeout/invalid-JSON failures preserve the local file.

### API, UI, and CLI tests

- Unauthenticated sync is rejected.
- Authenticated sync returns the documented counters.
- Concurrent sync calls for one user are serialized.
- The Sync button shows progress, success, and failure states and refreshes the
  local command list only after success.
- `mics_cli quick-commands sync` and `--json` handle success and API errors.
- Existing quick-command CRUD/import/export tests continue to pass.

## Rollout order

1. Add and test `commands-repo.py` without network changes.
2. Add Droppy URL derivation and explicit TUI initialization.
3. Create the remote `commands.json` with `If-None-Match: *`.
4. Add the backend sync endpoint and tests.
5. Add the web UI and CLI entry points.
6. Synchronize `auth.py` into `cf_tunnel_install.sh` and run the full test suite.
7. Deploy one server, perform two consecutive syncs, and confirm the second is
   unchanged before deploying to the remaining servers.

## Acceptance criteria

- `commands.json` exists beside `serverlist.json` and validates against schema
  version 1.
- A command created on server A appears locally on server B after sync.
- Independently created commands with the same normalized name result in one
  shared command, not two.
- Repeating sync without edits does not increment `revision` or change either
  file.
- Concurrent remote changes are not overwritten without remerging.
- Existing local command files, browser CRUD, exports/imports, and CLI commands
  remain compatible.
- Credentials and command contents are not leaked to logs or unauthenticated
  responses.
