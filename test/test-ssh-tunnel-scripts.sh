#!/usr/bin/env bash
set -euo pipefail

TEST_ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_TMP_DIR"' EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

assert_contains() {
  local file="$1" expected="$2"
  grep -Fq "$expected" "$file" || fail "$file does not contain: $expected"
}

# Unit-test the name rule without running installer side effects.
source "$TEST_ROOT_DIR/cf_tunnel_install.sh"
actual_hostname="$(derive_ssh_hostname minipc2 minipc2.micstec.com)"
[ "$actual_hostname" = "ssh-minipc2.micstec.com" ] \
  || fail "unexpected derived hostname: $actual_hostname"

if derive_ssh_hostname 'not valid' terminal.example.com >/dev/null 2>&1; then
  fail "invalid tunnel name was accepted for SSH DNS"
fi

# Exercise add/update/idempotency using an isolated config.
TEST_CONFIG="$TEST_TMP_DIR/config.yml"
cat > "$TEST_CONFIG" <<EOF
tunnel: demo
credentials-file: $TEST_TMP_DIR/demo.json

ingress:
  - hostname: demo.example.com
    service: http://localhost:7680
  - service: http_status:404
EOF

(
  CLOUDFLARED_CONFIG="$TEST_CONFIG"
  WEBTERMINAL_SERVER_REPO_CONFIG="$TEST_TMP_DIR/no-server-repo.conf"
  source "$TEST_ROOT_DIR/ssh-tunnel-tui.sh"
  [ "$(configured_tunnel_name)" = "demo" ] \
    || fail "TUI did not read tunnel name from the shared config"
  [ "$(configured_web_hostname)" = "demo.example.com" ] \
    || fail "TUI did not read the web hostname from the shared config"
  [ "$(derive_ssh_hostname demo demo.example.com)" = "ssh-demo.example.com" ] \
    || fail "TUI derived the wrong SSH hostname"
  load_server_repo_settings
  [ "$SERVER_REPO_URL" = "$DEFAULT_SERVER_REPO_URL" ] \
    || fail "TUI did not load the TNAS repository default"
  [ "$DEFAULT_SERVER_REPO_URL" = "https://tnas_d.micsapp.com/s/web-terminal-servers/serverlist.json" ] \
    || fail "TUI does not default to the TNAS server repository"

  GOOD_EMBED_HEADERS="HTTP/2 200
Content-Security-Policy: default-src 'self'; frame-src 'self' https://*.micstec.com https://*.wetigu.com; frame-ancestors 'self' https://*.micstec.com https://*.wetigu.com
"
  webterminal_headers_allow_embedding "$GOOD_EMBED_HEADERS" \
    || fail "valid Web Terminal embedding headers were rejected"
  if webterminal_headers_allow_embedding "$GOOD_EMBED_HEADERS"$'X-Frame-Options: SAMEORIGIN\n'; then
    fail "X-Frame-Options was accepted for an embedded Web Terminal"
  fi
  if webterminal_headers_allow_embedding "Content-Security-Policy: frame-src 'self'; frame-ancestors 'self'"; then
    fail "a CSP without the trusted fleet origins was accepted"
  fi
)

"$TEST_ROOT_DIR/add-tunnel-route.sh" --config "$TEST_CONFIG" \
  --hostname ssh-demo.example.com --no-dns
assert_contains "$TEST_CONFIG" '  - hostname: ssh-demo.example.com'
assert_contains "$TEST_CONFIG" '    service: ssh://localhost:22'

(
  CLOUDFLARED_CONFIG="$TEST_CONFIG"
  source "$TEST_ROOT_DIR/ssh-tunnel-tui.sh"
  [ "$(configured_ssh_hostname)" = "ssh-demo.example.com" ] \
    || fail "TUI did not read the SSH hostname from the shared config"
  [ "$(normalize_server_repo_url https://files.example.com/s/servers)" = \
      "https://files.example.com/s/servers/serverlist.json" ] \
    || fail "TUI did not normalize a Droppy folder share URL"
)

"$TEST_ROOT_DIR/add-tunnel-route.sh" --config "$TEST_CONFIG" \
  --hostname ssh-demo.example.com --no-dns
[ "$(grep -c 'hostname: ssh-demo.example.com' "$TEST_CONFIG")" -eq 1 ] \
  || fail "idempotent route update created a duplicate"

"$TEST_ROOT_DIR/add-tunnel-route.sh" --config "$TEST_CONFIG" \
  --hostname ssh-demo.example.com --service ssh://localhost:2222 --no-dns
assert_contains "$TEST_CONFIG" '    service: ssh://localhost:2222'
[ "$(grep -c 'hostname: ssh-demo.example.com' "$TEST_CONFIG")" -eq 1 ] \
  || fail "service update created a duplicate"

route_line="$(grep -n 'hostname: ssh-demo.example.com' "$TEST_CONFIG" | cut -d: -f1)"
catchall_line="$(grep -n 'service: http_status:404' "$TEST_CONFIG" | cut -d: -f1)"
[ "$route_line" -lt "$catchall_line" ] || fail "SSH route was not inserted before catch-all"

# Exercise protected-repository data validation and idempotent registration.
TEST_REPO="$TEST_TMP_DIR/serverlist.json"
TEST_REPO_UPDATED="$TEST_TMP_DIR/serverlist-updated.json"
TEST_REPO_SECOND="$TEST_TMP_DIR/serverlist-second.json"
TEST_REPO_META="$TEST_TMP_DIR/serverlist-meta"
cat > "$TEST_REPO" <<'EOF'
{
  "kind": "micsapp-webterminal-server-list",
  "schema_version": 2,
  "revision": 4,
  "servers": [
    {
      "id": "demo",
      "name": "Demo Server",
      "hostname": "demo.example.com",
      "web_hostname": "demo.example.com",
      "enabled": true
    }
  ]
}
EOF

python3 "$TEST_ROOT_DIR/server-repo.py" merge "$TEST_REPO" "$TEST_REPO_UPDATED" \
  --web-hostname demo.example.com --ssh-hostname ssh-demo.example.com \
  --ssh-mode tunnel --name demo > "$TEST_REPO_META"
[ "$(sed -n '1p' "$TEST_REPO_META")" = "updated" ] \
  || fail "repository helper did not report an updated entry"
[ "$(sed -n '2p' "$TEST_REPO_META")" = "5" ] \
  || fail "repository helper did not increment the revision"
assert_contains "$TEST_REPO_UPDATED" '"id": "demo"'
assert_contains "$TEST_REPO_UPDATED" '"ssh_hostname": "ssh-demo.example.com"'
assert_contains "$TEST_REPO_UPDATED" '"ssh_mode": "tunnel"'

python3 "$TEST_ROOT_DIR/server-repo.py" merge "$TEST_REPO_UPDATED" "$TEST_REPO_SECOND" \
  --web-hostname demo.example.com --ssh-hostname ssh-demo.example.com \
  --ssh-mode tunnel --name demo > "$TEST_REPO_META"
[ "$(sed -n '1p' "$TEST_REPO_META")" = "unchanged" ] \
  || fail "repository helper was not idempotent"
[ "$(sed -n '2p' "$TEST_REPO_META")" = "5" ] \
  || fail "idempotent registration changed the revision"

TEST_REPO_NONE="$TEST_TMP_DIR/serverlist-none.json"
python3 "$TEST_ROOT_DIR/server-repo.py" merge "$TEST_REPO_SECOND" "$TEST_REPO_NONE" \
  --web-hostname demo.example.com --ssh-mode none --name demo > "$TEST_REPO_META"
assert_contains "$TEST_REPO_NONE" '"ssh_mode": "none"'
if grep -Fq '"ssh_hostname"' "$TEST_REPO_NONE"; then
  fail "web-only registration retained a stale SSH hostname"
fi

if python3 "$TEST_ROOT_DIR/server-repo.py" merge "$TEST_REPO_SECOND" \
  "$TEST_TMP_DIR/serverlist-invalid.json" --web-hostname demo.example.com \
  --ssh-mode direct >/dev/null 2>&1; then
  fail "direct SSH registration accepted an empty server name/DNS"
fi
python3 "$TEST_ROOT_DIR/server-repo.py" show "$TEST_REPO_SECOND" \
  --current demo.example.com > "$TEST_TMP_DIR/serverlist-display"
assert_contains "$TEST_TMP_DIR/serverlist-display" '* demo.example.com'

# Exercise the TUI's authenticated GET, ETag-safe PUT, and hostname discovery.
TEST_REPO_UPLOAD="$TEST_TMP_DIR/serverlist-upload.json"
(
  CLOUDFLARED_CONFIG="$TEST_CONFIG"
  WEBTERMINAL_SERVER_REPO_URL="https://files.example.com/s/servers/serverlist.json"
  WEBTERMINAL_SERVER_REPO_PASSCODE="test-passcode"
  source "$TEST_ROOT_DIR/ssh-tunnel-tui.sh"

  header() { :; }
  pause() { :; }
  ensure_webterminal_embedding() { :; }
  curl() {
    local method="GET" output_file="" headers_file="" data_file="" auth_file=""
    local if_match="" previous="" argument
    for argument in "$@"; do
      case "$previous" in
        -D) headers_file="$argument" ;;
        -o) output_file="$argument" ;;
        -X) method="$argument" ;;
        -H)
          case "$argument" in
            @*) auth_file="${argument#@}" ;;
            If-Match:*) if_match="$argument" ;;
          esac
          ;;
        --data-binary) data_file="${argument#@}" ;;
      esac
      previous="$argument"
    done

    [ -f "$auth_file" ] || fail "repository request did not use an auth header file"
    assert_contains "$auth_file" 'X-Droppy-Share-Passcode: test-passcode'
    [ "$(stat -c '%a' "$auth_file")" = "600" ] \
      || fail "repository auth header file was not mode 600"

    if [ "$method" = "GET" ]; then
      cp "$TEST_REPO" "$output_file"
      printf 'HTTP/2 200\r\nETag: "test-etag"\r\n\r\n' > "$headers_file"
    else
      [ "$if_match" = 'If-Match: "test-etag"' ] \
        || fail "repository upload did not use the downloaded ETag"
      cp "$data_file" "$TEST_REPO_UPLOAD"
      : > "$output_file"
    fi
    printf '200'
  }

  server_register_repository <<< $'2\ndirect-ssh.demo.example.com\n'
)
assert_contains "$TEST_REPO_UPLOAD" '"web_hostname": "demo.example.com"'
assert_contains "$TEST_REPO_UPLOAD" '"ssh_hostname": "direct-ssh.demo.example.com"'
assert_contains "$TEST_REPO_UPLOAD" '"ssh_mode": "direct"'
assert_contains "$TEST_REPO_UPLOAD" '"revision": 5'

# Verify DNS invocation ignores the caller's default config and overwrites only
# the explicitly requested SSH hostname.
mkdir -p "$TEST_TMP_DIR/bin"
cat > "$TEST_TMP_DIR/bin/cloudflared" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$TASK_CLOUDFLARED_LOG"
EOF
chmod +x "$TEST_TMP_DIR/bin/cloudflared"
TASK_CLOUDFLARED_LOG="$TEST_TMP_DIR/cloudflared.log" \
PATH="$TEST_TMP_DIR/bin:$PATH" \
  "$TEST_ROOT_DIR/add-tunnel-route.sh" --config "$TEST_CONFIG" \
    --hostname ssh-demo.example.com --service ssh://localhost:2222
assert_contains "$TEST_TMP_DIR/cloudflared.log" \
  'tunnel --config /dev/null route dns --overwrite-dns demo ssh-demo.example.com'

# Integration-test --ssh-tunnel with side-effecting commands stubbed in-shell.
TEST_INSTALL_CONFIG="$TEST_TMP_DIR/install-config.yml"
TEST_CREDS="$TEST_TMP_DIR/demo.json"
TEST_SSH_MARKER="$TEST_TMP_DIR/ssh-enabled"
printf '{}\n' > "$TEST_CREDS"

install_cloudflared() { :; }
ensure_auth() { :; }
enable_ssh_server() { printf 'called\n' > "$TEST_SSH_MARKER"; }
pgrep() { return 0; }
cloudflared() {
  if [ "${1:-}" = "--version" ]; then
    printf 'cloudflared test\n'
  elif [ "${1:-}" = "tunnel" ] && [ "${2:-}" = "list" ]; then
    printf 'ID NAME CREATED CONNECTIONS\n'
    printf '00000000-0000-0000-0000-000000000001 demo now test\n'
  fi
}

main --name demo --hostname demo.example.com --service http://localhost:7680 \
  --ssh-tunnel --no-dns --config "$TEST_INSTALL_CONFIG" \
  --credentials "$TEST_CREDS" --yes

assert_contains "$TEST_INSTALL_CONFIG" '  - hostname: demo.example.com'
assert_contains "$TEST_INSTALL_CONFIG" '  - hostname: ssh-demo.example.com'
assert_contains "$TEST_INSTALL_CONFIG" '    service: ssh://localhost:22'
[ -f "$TEST_SSH_MARKER" ] || fail "--ssh-tunnel did not enable the SSH server"

printf 'PASS: SSH tunnel installer and route helper\n'
