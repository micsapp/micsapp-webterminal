#!/usr/bin/env bash
set -euo pipefail

# Add or update an SSH ingress route on an existing named Cloudflare tunnel.
# The web-terminal installer and ssh-tunnel-tui.sh share this config by default.

CONFIG_FILE="${CLOUDFLARED_CONFIG:-$HOME/.cloudflared/config.yml}"
HOSTNAME=""
SERVICE="ssh://localhost:22"
NO_DNS=false
LIST_ONLY=false

usage() {
  cat <<'EOF'
Usage:
  add-tunnel-route.sh --hostname HOST [options]
  add-tunnel-route.sh --list [options]

Options:
  --hostname HOST       Public SSH tunnel hostname
  --service URL         SSH origin (default: ssh://localhost:22)
  --config FILE         cloudflared config (default: ~/.cloudflared/config.yml)
  --no-dns              Update ingress only; do not create/update Cloudflare DNS
  --list                List configured ingress routes
  -h, --help            Show this help

The DNS record is updated to point at the tunnel named by the config file.
EOF
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --hostname) HOSTNAME="${2:-}"; shift 2 ;;
    --service) SERVICE="${2:-}"; shift 2 ;;
    --config) CONFIG_FILE="${2:-}"; shift 2 ;;
    --no-dns) NO_DNS=true; shift ;;
    --list) LIST_ONLY=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Unknown option: $1" ;;
  esac
done

[ -f "$CONFIG_FILE" ] || fail "Tunnel config not found: $CONFIG_FILE"

if [ "$LIST_ONLY" = true ]; then
  printf 'Config: %s\n' "$CONFIG_FILE"
  awk '
    $1 == "-" && $2 == "hostname:" { hostname=$3; next }
    hostname != "" && $1 == "service:" {
      printf "  %s -> %s\n", hostname, $2
      hostname=""
    }
  ' "$CONFIG_FILE"
  exit 0
fi

[ -n "$HOSTNAME" ] || fail "--hostname is required"
if [[ ! "$HOSTNAME" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || [[ "$HOSTNAME" != *.* ]]; then
  fail "Invalid DNS hostname: $HOSTNAME"
fi
if [[ ! "$SERVICE" =~ ^ssh://(localhost|127\.0\.0\.1|\[::1\]):[0-9]+$ ]]; then
  fail "SSH service must use localhost, for example ssh://localhost:22"
fi

TUNNEL_NAME="$(awk '$1 == "tunnel:" {print $2; exit}' "$CONFIG_FILE" | tr -d "\"'")"
[ -n "$TUNNEL_NAME" ] || fail "No tunnel: value found in $CONFIG_FILE"

EXISTING_SERVICE="$(awk -v h="$HOSTNAME" '
  $1 == "-" && $2 == "hostname:" && $3 == h { found=1; next }
  found && $1 == "service:" { print $2; exit }
' "$CONFIG_FILE")"

if [ "$EXISTING_SERVICE" = "$SERVICE" ]; then
  printf 'Ingress already configured: %s -> %s\n' "$HOSTNAME" "$SERVICE"
else
  BACKUP_FILE="${CONFIG_FILE}.bak.$(date +%Y%m%d_%H%M%S).$$"
  cp -a "$CONFIG_FILE" "$BACKUP_FILE"
  TMP_FILE="$(mktemp "${CONFIG_FILE}.tmp.XXXXXX")"
  trap 'rm -f "${TMP_FILE:-}"' EXIT

  if [ -n "$EXISTING_SERVICE" ]; then
    awk -v h="$HOSTNAME" -v s="$SERVICE" '
      $1 == "-" && $2 == "hostname:" && $3 == h {
        target=1
        print
        next
      }
      target && $1 == "service:" {
        print "    service: " s
        target=0
        next
      }
      { print }
    ' "$CONFIG_FILE" > "$TMP_FILE"
    printf 'Updated ingress: %s -> %s\n' "$HOSTNAME" "$SERVICE"
  elif grep -qE '^[[:space:]]*-[[:space:]]*service:[[:space:]]*http_status:404[[:space:]]*$' "$CONFIG_FILE"; then
    awk -v h="$HOSTNAME" -v s="$SERVICE" '
      BEGIN { added=0 }
      /^[[:space:]]*-[[:space:]]*service:[[:space:]]*http_status:404[[:space:]]*$/ && !added {
        print "  - hostname: " h
        print "    service: " s
        added=1
      }
      { print }
    ' "$CONFIG_FILE" > "$TMP_FILE"
    printf 'Added ingress: %s -> %s\n' "$HOSTNAME" "$SERVICE"
  elif grep -qE '^[[:space:]]*ingress:[[:space:]]*$' "$CONFIG_FILE"; then
    cp "$CONFIG_FILE" "$TMP_FILE"
    cat >> "$TMP_FILE" <<EOF
  - hostname: $HOSTNAME
    service: $SERVICE
EOF
    printf 'Added ingress: %s -> %s\n' "$HOSTNAME" "$SERVICE"
  else
    cp "$CONFIG_FILE" "$TMP_FILE"
    cat >> "$TMP_FILE" <<EOF

ingress:
  - hostname: $HOSTNAME
    service: $SERVICE
  - service: http_status:404
EOF
    printf 'Added ingress: %s -> %s\n' "$HOSTNAME" "$SERVICE"
  fi

  chmod 600 "$TMP_FILE"
  mv "$TMP_FILE" "$CONFIG_FILE"
  trap - EXIT
  printf 'Backup: %s\n' "$BACKUP_FILE"
fi

if [ "$NO_DNS" = true ]; then
  printf 'Skipped DNS route (--no-dns).\n'
  exit 0
fi

command -v cloudflared >/dev/null 2>&1 || fail "cloudflared is required for DNS setup"

# Ignore the caller's default config while resolving the requested tunnel.
# Otherwise a credentials-file from another config can silently override the
# tunnel argument. The tunnel's origin certificate still supplies DNS auth.
cloudflared tunnel --config /dev/null route dns --overwrite-dns "$TUNNEL_NAME" "$HOSTNAME"
printf 'DNS route configured: %s -> tunnel %s\n' "$HOSTNAME" "$TUNNEL_NAME"
