#!/usr/bin/env bash
set -euo pipefail

# list-servers.sh — List every remote Web Terminal and SSH DNS name from the
# shared catalog, optionally with a live reachability probe.
#
# The catalog URL/passcode come from the same config `./deploy.sh --remote-setup`
# writes, so this needs no arguments on a configured deployment.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_REPO_CONFIG="${WEBTERMINAL_SERVER_REPO_CONFIG:-$HOME/.config/micsapp-webterminal/server-repo.conf}"
DEFAULT_SERVER_REPO_URL="https://tnas_d.micsapp.com/s/web-terminal-servers/serverlist.json"
SERVER_REPO_URL="${WEBTERMINAL_SERVER_REPO_URL:-}"
SERVER_REPO_PASSCODE="${WEBTERMINAL_SERVER_REPO_PASSCODE:-}"
PROBE_TIMEOUT="${WEBTERMINAL_PROBE_TIMEOUT:-4}"

# ── colours ────────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'
W='\033[1;37m'; DIM='\033[2m'; BOLD='\033[1m'; NC='\033[0m'
if [ ! -t 1 ] || [ -n "${NO_COLOR:-}" ]; then
    R=''; G=''; Y=''; C=''; W=''; DIM=''; BOLD=''; NC=''
fi

STATUS=0
FORMAT="table"
FILTER="all"

usage() {
    cat <<EOF
Usage: ./list-servers.sh [options]

  -s, --status       probe each endpoint and show up/down (slower)
      --ssh          only SSH DNS names
      --web          only Web Terminal hostnames
      --json         raw catalog JSON (implies no probing)
      --plain        bare hostnames, one per line (pipe-friendly)
  -h, --help         this help

Environment:
  WEBTERMINAL_SERVER_REPO_CONFIG    default $HOME/.config/micsapp-webterminal/server-repo.conf
  WEBTERMINAL_SERVER_REPO_URL       override catalog URL
  WEBTERMINAL_SERVER_REPO_PASSCODE  override passcode
  WEBTERMINAL_PROBE_TIMEOUT         per-probe seconds (default 4)
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -s|--status) STATUS=1 ;;
        --ssh)       FILTER="ssh" ;;
        --web)       FILTER="web" ;;
        --json)      FORMAT="json" ;;
        --plain)     FORMAT="plain" ;;
        -h|--help)   usage; exit 0 ;;
        *) printf "${R}unknown option: %s${NC}\n" "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

# ── load catalog settings ──────────────────────────────────────────────────────
# Config file format (written by --remote-setup, mode 600): line 1 URL, line 2 passcode.
if [ -z "$SERVER_REPO_URL" ] || [ -z "$SERVER_REPO_PASSCODE" ]; then
    if [ -r "$SERVER_REPO_CONFIG" ]; then
        [ -z "$SERVER_REPO_URL" ]      && SERVER_REPO_URL="$(sed -n 1p "$SERVER_REPO_CONFIG" || true)"
        [ -z "$SERVER_REPO_PASSCODE" ] && SERVER_REPO_PASSCODE="$(sed -n 2p "$SERVER_REPO_CONFIG" || true)"
    fi
fi
SERVER_REPO_URL="${SERVER_REPO_URL:-$DEFAULT_SERVER_REPO_URL}"

if [ -z "$SERVER_REPO_PASSCODE" ]; then
    printf "${R}✗${NC} No catalog passcode configured.\n" >&2
    printf "  Run ${W}./deploy.sh --remote-setup${NC} or set WEBTERMINAL_SERVER_REPO_PASSCODE.\n" >&2
    exit 1
fi

# ── fetch ──────────────────────────────────────────────────────────────────────
# The passcode goes in via stdin (-H @-) so it never appears in `ps` output —
# same approach as fetch_server_repository() in auth.py.
fetch_catalog() {
    printf 'X-Droppy-Share-Passcode: %s\n' "$SERVER_REPO_PASSCODE" \
    | curl --silent --show-error --fail \
           --connect-timeout 5 --max-time 10 \
           -H @- "$SERVER_REPO_URL"
}

if ! CATALOG="$(fetch_catalog 2>&1)"; then
    printf "${R}✗${NC} Cannot fetch catalog: %s\n" "$CATALOG" >&2
    printf "  URL: ${DIM}%s${NC}\n" "$SERVER_REPO_URL" >&2
    exit 1
fi

if [ "$FORMAT" = "json" ]; then
    printf '%s\n' "$CATALOG"
    exit 0
fi

# ── parse: id \t name \t web_hostname \t ssh_hostname \t ssh_mode \t enabled ───
ROWS="$(printf '%s' "$CATALOG" | python3 -c '
import sys, json
try:
    doc = json.load(sys.stdin)
except json.JSONDecodeError as exc:
    sys.exit("catalog is not valid JSON: %s" % exc)
for s in doc.get("servers", []):
    print("\t".join([
        s.get("id") or "-",
        s.get("name") or "-",
        s.get("web_hostname") or s.get("hostname") or "",
        s.get("ssh_hostname") or "",
        s.get("ssh_mode") or "none",
        "yes" if s.get("enabled", True) else "no",
    ]))
')"

if [ -z "$ROWS" ]; then
    printf "${Y}⚠${NC} Catalog contains no servers.\n"
    exit 0
fi

# ── plain output ───────────────────────────────────────────────────────────────
if [ "$FORMAT" = "plain" ]; then
    while IFS=$'\t' read -r id name web ssh mode enabled; do
        [ "$FILTER" != "ssh" ] && [ -n "$web" ] && printf '%s\n' "$web"
        [ "$FILTER" != "web" ] && [ -n "$ssh" ] && [ "$mode" != "none" ] && printf '%s\n' "$ssh"
    done <<< "$ROWS"
    exit 0
fi

# ── probes ─────────────────────────────────────────────────────────────────────
# Web: an HTTP response of any status means the endpoint is serving. A login
# redirect or 401 is still "up" — we are testing reachability, not authorization.
probe_web() {
    local host="$1" code
    code="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
                 --location --max-time "$PROBE_TIMEOUT" "https://${host}/" 2>/dev/null || echo 000)"
    [ "$code" != "000" ] && printf 'up %s' "$code" || printf 'down -'
}

# SSH: Cloudflare-tunnelled hosts have no reachable TCP 22 — they are brokered by
# `cloudflared access ssh`. Probing 443 tells us the tunnel edge answers, which is
# the closest honest signal without opening a real SSH session.
probe_ssh() {
    local host="$1" mode="$2" port=22
    [ "$mode" = "tunnel" ] && port=443
    if timeout "$PROBE_TIMEOUT" bash -c "</dev/tcp/${host}/${port}" 2>/dev/null; then
        printf 'up %s' "$port"
    else
        printf 'down %s' "$port"
    fi
}

status_cell() {
    local state="$1" detail="$2"
    if [ "$state" = "up" ]; then
        printf "${G}●${NC} ${DIM}%s${NC}" "$detail"
    else
        printf "${R}●${NC} ${DIM}%s${NC}" "$detail"
    fi
}

# ── table output ───────────────────────────────────────────────────────────────
printf "\n${BOLD}${W}  Web Terminal / SSH catalog${NC}  ${DIM}(%s)${NC}\n" "$SERVER_REPO_URL"
printf "${DIM}  %s${NC}\n\n" "$(printf '─%.0s' $(seq 1 72))"

total=0; up=0
while IFS=$'\t' read -r id name web ssh mode enabled; do
    total=$((total + 1))
    label="$name"
    [ "$enabled" = "no" ] && label="$name ${DIM}(disabled)${NC}"
    printf "  ${BOLD}${C}%s${NC}\n" "$label"

    if [ "$FILTER" != "ssh" ]; then
        if [ -n "$web" ]; then
            line="$(printf "    %-6s ${W}%s${NC}" "web" "$web")"
            if [ "$STATUS" = "1" ]; then
                read -r state detail <<< "$(probe_web "$web")"
                [ "$state" = "up" ] && up=$((up + 1))
                line="$line  $(status_cell "$state" "$detail")"
            fi
            printf '%b\n' "$line"
        else
            printf "    %-6s ${DIM}(none)${NC}\n" "web"
        fi
    fi

    if [ "$FILTER" != "web" ]; then
        if [ -n "$ssh" ] && [ "$mode" != "none" ]; then
            line="$(printf "    %-6s ${W}%s${NC} ${DIM}[%s]${NC}" "ssh" "$ssh" "$mode")"
            if [ "$STATUS" = "1" ]; then
                read -r state detail <<< "$(probe_ssh "$ssh" "$mode")"
                [ "$state" = "up" ] && up=$((up + 1))
                line="$line  $(status_cell "$state" ":$detail")"
            fi
            printf '%b\n' "$line"
        else
            printf "    %-6s ${DIM}(none)${NC}\n" "ssh"
        fi
    fi
    printf '\n'
done <<< "$ROWS"

printf "${DIM}  %s${NC}\n" "$(printf '─%.0s' $(seq 1 72))"
if [ "$STATUS" = "1" ]; then
    printf "  ${DIM}%d servers · %d endpoints reachable${NC}\n\n" "$total" "$up"
else
    printf "  ${DIM}%d servers · run with --status to probe reachability${NC}\n\n" "$total"
fi
