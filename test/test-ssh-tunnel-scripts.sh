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
  source "$TEST_ROOT_DIR/ssh-tunnel-tui.sh"
  [ "$(configured_tunnel_name)" = "demo" ] \
    || fail "TUI did not read tunnel name from the shared config"
  [ "$(configured_web_hostname)" = "demo.example.com" ] \
    || fail "TUI did not read the web hostname from the shared config"
  [ "$(derive_ssh_hostname demo demo.example.com)" = "ssh-demo.example.com" ] \
    || fail "TUI derived the wrong SSH hostname"
)

"$TEST_ROOT_DIR/add-tunnel-route.sh" --config "$TEST_CONFIG" \
  --hostname ssh-demo.example.com --no-dns
assert_contains "$TEST_CONFIG" '  - hostname: ssh-demo.example.com'
assert_contains "$TEST_CONFIG" '    service: ssh://localhost:22'

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
