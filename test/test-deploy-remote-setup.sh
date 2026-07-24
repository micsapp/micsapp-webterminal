#!/usr/bin/env bash
set -euo pipefail

TEST_ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_TMP_DIR"' EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

unset WEBTERMINAL_SERVER_REPO_URL WEBTERMINAL_SERVER_REPO_PASSCODE
source "$TEST_ROOT_DIR/deploy.sh"

SERVER_REPO_CONFIG="$TEST_TMP_DIR/config/server-repo.conf"
SERVER_REPO_HELPER="$TEST_ROOT_DIR/server-repo.py"
REMOTE_SSH_CONFIG="$TEST_TMP_DIR/ssh/config"
mkdir -p "$(dirname "$REMOTE_SSH_CONFIG")"
printf '%s\n' \
  'Host ssh-existing.example.com' \
  '    HostName ssh-existing.example.com' \
  '    User original-user' \
  '    ProxyCommand /original/cloudflared access ssh --hostname %h' \
  '' \
  'Host web-terminal.example.com' \
  '    User web-user' > "$REMOTE_SSH_CONFIG"

fetch_remote_repository() {
  local repo_url="$1" passcode="$2" output_file="$3"
  [ "$repo_url" = "$DEFAULT_SERVER_REPO_URL" ] \
    || fail "unexpected repository URL: $repo_url"
  [ "$passcode" = "test-passcode" ] \
    || fail "unexpected repository passcode"
  printf '%s\n' \
    '{"kind":"micsapp-webterminal-server-list","schema_version":2,"revision":9,' \
    '"servers":[{"id":"remote.example.com","name":"remote","web_hostname":' \
    '"remote.example.com","ssh_mode":"direct","ssh_hostname":"remote.example.com",' \
    '"enabled":true},{"id":"existing.example.com","ssh_mode":"tunnel",' \
    '"ssh_hostname":"ssh-existing.example.com","enabled":true},' \
    '{"id":"new.example.com","web_hostname":"web-terminal.example.com",' \
    '"ssh_mode":"tunnel","ssh_hostname":"ssh-new.example.com","enabled":true}]}' \
    > "$output_file"
}

ensure_remote_client_tools() {
  :
}

setup_output="$(configure_remote_repository <<'EOF'

test-passcode
EOF
)"

[ "$(sed -n '1p' "$SERVER_REPO_CONFIG")" = "$DEFAULT_SERVER_REPO_URL" ] \
  || fail "default repository URL was not saved"
[ "$(sed -n '2p' "$SERVER_REPO_CONFIG")" = "test-passcode" ] \
  || fail "repository passcode was not saved"
[ "$(stat -c '%a' "$SERVER_REPO_CONFIG")" = "600" ] \
  || fail "repository config is not mode 600"
[ "$(stat -c '%a' "$(dirname "$SERVER_REPO_CONFIG")")" = "700" ] \
  || fail "repository config directory is not mode 700"
printf '%s' "$setup_output" | grep -Fq 'Saved repository configuration:' \
  || fail "setup did not report the saved configuration"
printf '%s' "$setup_output" | grep -Fq 'remote.example.com' \
  || fail "setup did not display the validated repository"
grep -Fq 'Host ssh-new.example.com' "$REMOTE_SSH_CONFIG" \
  || fail "new tunnel SSH hostname was not appended"
[ "$(grep -Fc 'Host ssh-existing.example.com' "$REMOTE_SSH_CONFIG")" = "1" ] \
  || fail "existing tunnel SSH hostname was duplicated"
if grep -Fq 'Host remote.example.com' "$REMOTE_SSH_CONFIG"; then
  fail "direct SSH hostname must not be added by proxy sync"
fi
[ "$(grep -Fc 'Host web-terminal.example.com' "$REMOTE_SSH_CONFIG")" = "1" ] \
  || fail "web hostname was added as a tunnel alias"
[ "$(sed -n '3p' "$REMOTE_SSH_CONFIG")" = '    User original-user' ] \
  || fail "existing SSH config content was changed"
if printf '%s' "$setup_output" | grep -Fq 'test-passcode'; then
  fail "setup printed the protected passcode"
fi

# Blank answers must retain both saved values.
second_output="$(configure_remote_repository <<'EOF'


EOF
)"
printf '%s' "$second_output" | grep -Fq 'remote.example.com' \
  || fail "saved URL/passcode were not reused"
[ "$(grep -Fc 'Host ssh-new.example.com' "$REMOTE_SSH_CONFIG")" = "1" ] \
  || fail "repeated sync duplicated the new tunnel SSH hostname"

printf 'PASS: deploy --remote-setup configuration\n'
