#!/usr/bin/env bash
set -euo pipefail

# ssh-tunnel-tui.sh — Interactive TUI for SSH-over-Cloudflare-Tunnel setup
# Two modes: Server (set up tunnel service) / Client (connect & diagnose)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/.cloudflared/config.yml"
PID_FILE="$SCRIPT_DIR/.cloudflared/tunnel.pid"
LOG_FILE="$SCRIPT_DIR/.cloudflared/tunnel.log"

# ── colours ────────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'
M='\033[0;35m'; W='\033[1;37m'; DIM='\033[2m'; BOLD='\033[1m'; NC='\033[0m'

clear_screen() { printf '\033[2J\033[H'; }
hr() { printf "${DIM}"; printf '─%.0s' $(seq 1 "${COLUMNS:-70}"); printf "${NC}\n"; }
header() {
    clear_screen
    printf "${B}${BOLD}╔══════════════════════════════════════════╗${NC}\n"
    printf "${B}${BOLD}║  🔑 SSH Tunnel ─ %-23s║${NC}\n" "$1"
    printf "${B}${BOLD}╚══════════════════════════════════════════╝${NC}\n"
    hr
}
info()  { printf "  ${G}✓${NC} %s\n" "$*"; }
warn()  { printf "  ${Y}⚠${NC} %s\n" "$*"; }
error() { printf "  ${R}✗${NC} %s\n" "$*"; }
step()  { printf "  ${C}→${NC} %s" "$*"; }
menu_item() { printf "  ${C}${BOLD}%s${NC}) %s\n" "$1" "$2"; }
pause() { printf "\n${DIM}  Press Enter to continue…${NC}"; read -r; }

# ── detect environment ─────────────────────────────────────────────────────────
is_wsl() { grep -qiE "microsoft|wsl" /proc/version 2>/dev/null; }
is_mac() { [[ "$(uname -s)" == "Darwin" ]]; }
is_linux() { [[ "$(uname -s)" == "Linux" ]] && ! is_wsl; }

detect_os() {
    if is_mac; then echo "macOS"
    elif is_wsl; then echo "WSL"
    elif is_linux; then echo "Linux"
    else echo "Unknown"; fi
}

# ── check if SSH is listening on port 22 ───────────────────────────────────────
ssh_is_running() {
    # Method 1: netstat (most reliable, widely available)
    if command -v netstat &>/dev/null; then
        netstat -tln 2>/dev/null | grep -qE ':22\s' && return 0
    fi
    # Method 2: /usr/bin/ss (avoid user-local overrides)
    if [ -x /usr/bin/ss ]; then
        /usr/bin/ss -tln 2>/dev/null | grep -qE ':22\s' && return 0
    fi
    # Method 3: systemctl / service
    if command -v systemctl &>/dev/null; then
        systemctl is-active --quiet ssh 2>/dev/null && return 0
        systemctl is-active --quiet sshd 2>/dev/null && return 0
    fi
    # Method 4: pgrep for sshd process
    if pgrep -x sshd &>/dev/null; then
        return 0
    fi
    return 1
}

# ══════════════════════════════════════════════════════════════════════════════
#  SERVER MODE
# ══════════════════════════════════════════════════════════════════════════════

# ── check SSH service ──────────────────────────────────────────────────────────
server_check_ssh() {
    header "Server: SSH Service"
    echo ""

    step "Checking SSH server... "
    if ssh_is_running; then
        printf "${G}running${NC}\n"
        info "SSH is listening on port 22"
    else
        printf "${R}not running${NC}\n"
        warn "SSH server is not listening on port 22"
        echo ""
        printf "  ${W}Start SSH now? [Y/n]:${NC} "
        read -rn1 yn; echo
        if [[ "${yn:-y}" != "n" && "${yn:-y}" != "N" ]]; then
            if command -v systemctl &>/dev/null && systemctl --version &>/dev/null 2>&1; then
                sudo systemctl start ssh 2>/dev/null || sudo systemctl start sshd 2>/dev/null || {
                    error "Failed to start SSH with systemctl"
                    warn "Trying 'service' fallback..."
                    sudo service ssh start 2>/dev/null || sudo service sshd start 2>/dev/null || {
                        error "Could not start SSH. Install with: sudo apt install openssh-server"
                    }
                }
            else
                sudo service ssh start 2>/dev/null || sudo service sshd start 2>/dev/null || {
                    error "Could not start SSH. Install with: sudo apt install openssh-server"
                }
            fi

            # Re-check
            sleep 1
            if ssh_is_running; then
                info "SSH started successfully"
            else
                error "SSH still not running after start attempt"
            fi
        fi
    fi
    pause
}

# ── check cloudflared ─────────────────────────────────────────────────────────
server_check_cloudflared() {
    header "Server: Cloudflared"
    echo ""

    step "Checking cloudflared... "
    if command -v cloudflared &>/dev/null; then
        printf "${G}installed${NC}\n"
        info "$(cloudflared --version 2>&1 | head -1)"
    else
        printf "${R}not found${NC}\n"
        echo ""
        printf "  ${W}Install cloudflared now? [Y/n]:${NC} "
        read -rn1 yn; echo
        if [[ "${yn:-y}" != "n" && "${yn:-y}" != "N" ]]; then
            echo ""
            step "Installing cloudflared...\n"
            if command -v apt-get &>/dev/null; then
                sudo mkdir -p /usr/share/keyrings
                curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
                    | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
                echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] \
https://pkg.cloudflare.com/cloudflared $(. /etc/os-release && echo "$VERSION_CODENAME") main" \
                    | sudo tee /etc/apt/sources.list.d/cloudflared.list >/dev/null
                sudo apt-get update -qq && sudo apt-get install -y cloudflared
            elif command -v brew &>/dev/null; then
                brew install cloudflared
            else
                local arch; arch=$(uname -m)
                case "$arch" in
                    x86_64)  arch="amd64" ;;
                    aarch64) arch="arm64" ;;
                    armv7l)  arch="arm"   ;;
                    *) error "Unsupported arch: $arch"; pause; return ;;
                esac
                sudo curl -fsSL "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}" \
                    -o /usr/local/bin/cloudflared
                sudo chmod +x /usr/local/bin/cloudflared
            fi

            if command -v cloudflared &>/dev/null; then
                info "cloudflared installed: $(cloudflared --version 2>&1 | head -1)"
            else
                error "Installation failed"
            fi
        fi
    fi

    # Check auth
    echo ""
    step "Checking Cloudflare auth... "
    if ls "$HOME/.cloudflared/"*cert.pem &>/dev/null 2>&1; then
        printf "${G}authenticated${NC}\n"
    else
        printf "${Y}not logged in${NC}\n"
        echo ""
        printf "  ${W}Run 'cloudflared tunnel login' now? [Y/n]:${NC} "
        read -rn1 yn; echo
        if [[ "${yn:-y}" != "n" && "${yn:-y}" != "N" ]]; then
            echo ""
            info "A browser URL will appear. Authorize and return here."
            cloudflared tunnel login
            if ls "$HOME/.cloudflared/"*cert.pem &>/dev/null 2>&1; then
                info "Authentication successful"
            else
                error "Auth cert not found after login"
            fi
        fi
    fi
    pause
}

# ── check tunnel status ───────────────────────────────────────────────────────
server_tunnel_status() {
    header "Server: Tunnel Status"
    echo ""

    # Config file
    step "Config file... "
    if [ -f "$CONFIG_FILE" ]; then
        printf "${G}found${NC}\n"
        local tunnel_name
        tunnel_name=$(grep '^tunnel:' "$CONFIG_FILE" 2>/dev/null | awk '{print $2}' || echo "unknown")
        info "Tunnel name: ${tunnel_name}"
    else
        printf "${Y}not found${NC}\n"
        warn "No tunnel configured. Run create_tunnel.sh first."
        pause
        return
    fi

    # Tunnel process
    echo ""
    step "Tunnel process... "
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null; then
        printf "${G}running (PID $(cat "$PID_FILE"))${NC}\n"
    else
        printf "${R}not running${NC}\n"
    fi

    # SSH route
    echo ""
    step "SSH routes in config:\n"
    if grep -q 'ssh://' "$CONFIG_FILE" 2>/dev/null; then
        grep -B1 'ssh://' "$CONFIG_FILE" | while read -r line; do
            if echo "$line" | grep -q 'hostname:'; then
                local host; host=$(echo "$line" | awk '{print $NF}')
                local svc; read -r svc_line
                svc=$(echo "$svc_line" | awk '{print $NF}')
                printf "    ${G}%s${NC} → ${C}%s${NC}\n" "$host" "$svc"
            fi
        done 2>/dev/null || true
        # Fallback: just show matching lines
        grep -E 'hostname:.*|service:.*ssh' "$CONFIG_FILE" 2>/dev/null | \
            sed 's/^/    /' || true
    else
        warn "  No SSH routes found in tunnel config"
    fi

    pause
}

# ── add SSH route ──────────────────────────────────────────────────────────────
server_add_ssh_route() {
    header "Server: Add SSH Route"
    echo ""

    if [ ! -f "$CONFIG_FILE" ]; then
        error "No tunnel configured. Run create_tunnel.sh first."
        pause
        return
    fi

    printf "  ${W}SSH hostname${NC} (e.g. cssh.micstec.com): "
    read -r ssh_hostname
    [ -z "$ssh_hostname" ] && return

    printf "  ${W}SSH port${NC} [22]: "
    read -r ssh_port
    ssh_port="${ssh_port:-22}"

    echo ""
    step "Adding route: ${ssh_hostname} → ssh://localhost:${ssh_port}\n"
    echo ""

    if [ -x "$SCRIPT_DIR/add-tunnel-route.sh" ]; then
        "$SCRIPT_DIR/add-tunnel-route.sh" --hostname "$ssh_hostname" --service "ssh://localhost:${ssh_port}"
        info "SSH route added successfully"
    else
        error "add-tunnel-route.sh not found or not executable"
    fi

    pause
}

# ── start/stop tunnel ─────────────────────────────────────────────────────────
server_start_tunnel() {
    header "Server: Start Tunnel"
    echo ""

    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null; then
        info "Tunnel already running (PID $(cat "$PID_FILE"))"
        pause
        return
    fi

    if [ -x "$SCRIPT_DIR/tunnel-start.sh" ]; then
        "$SCRIPT_DIR/tunnel-start.sh"
        sleep 1
        if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null; then
            info "Tunnel started (PID $(cat "$PID_FILE"))"
        else
            error "Tunnel may not have started. Check logs: $LOG_FILE"
        fi
    else
        error "tunnel-start.sh not found"
    fi
    pause
}

server_stop_tunnel() {
    header "Server: Stop Tunnel"
    echo ""

    if [ -x "$SCRIPT_DIR/tunnel-stop.sh" ]; then
        "$SCRIPT_DIR/tunnel-stop.sh"
        info "Done"
    else
        error "tunnel-stop.sh not found"
    fi
    pause
}

# ── view tunnel logs ───────────────────────────────────────────────────────────
server_view_logs() {
    header "Server: Tunnel Logs"
    echo ""

    if [ -f "$LOG_FILE" ]; then
        info "Last 30 lines of $LOG_FILE:"
        hr
        tail -30 "$LOG_FILE" | sed 's/^/  /'
    else
        warn "No log file found at $LOG_FILE"
    fi
    pause
}

# ── list routes ────────────────────────────────────────────────────────────────
server_list_routes() {
    header "Server: Current Routes"
    echo ""

    if [ -x "$SCRIPT_DIR/add-tunnel-route.sh" ]; then
        "$SCRIPT_DIR/add-tunnel-route.sh" --list
    elif [ -f "$CONFIG_FILE" ]; then
        grep -E 'hostname:|service:' "$CONFIG_FILE" | sed 's/^/  /'
    else
        warn "No tunnel configured"
    fi
    pause
}

# ── full server setup wizard ──────────────────────────────────────────────────
server_full_setup() {
    header "Server: Full SSH Setup"
    echo ""
    echo -e "  ${BOLD}This wizard will:${NC}"
    echo "    1. Ensure SSH is running"
    echo "    2. Ensure cloudflared is installed & authenticated"
    echo "    3. Ensure the tunnel is created & running"
    echo "    4. Add an SSH route to the tunnel"
    echo ""
    printf "  ${W}Continue? [Y/n]:${NC} "
    read -rn1 yn; echo
    [[ "${yn:-y}" == "n" || "${yn:-y}" == "N" ]] && return

    # Step 1: SSH
    echo ""
    echo -e "  ${BOLD}Step 1/4: SSH Service${NC}"
    hr
    step "Checking SSH... "
    if ssh_is_running; then
        printf "${G}running${NC}\n"
    else
        printf "${Y}starting...${NC}\n"
        sudo service ssh start 2>/dev/null || sudo service sshd start 2>/dev/null || \
            sudo systemctl start ssh 2>/dev/null || sudo systemctl start sshd 2>/dev/null || true
        sleep 1
        if ssh_is_running; then
            info "SSH started"
        else
            error "Could not start SSH. Install: sudo apt install openssh-server"
            pause; return
        fi
    fi

    # Step 2: cloudflared
    echo ""
    echo -e "  ${BOLD}Step 2/4: Cloudflared${NC}"
    hr
    step "Checking cloudflared... "
    if command -v cloudflared &>/dev/null; then
        printf "${G}installed${NC}\n"
    else
        printf "${Y}installing...${NC}\n"
        if command -v apt-get &>/dev/null; then
            sudo mkdir -p /usr/share/keyrings
            curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
                | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
            echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] \
https://pkg.cloudflare.com/cloudflared $(. /etc/os-release && echo "$VERSION_CODENAME") main" \
                | sudo tee /etc/apt/sources.list.d/cloudflared.list >/dev/null
            sudo apt-get update -qq && sudo apt-get install -y cloudflared
        elif command -v brew &>/dev/null; then
            brew install cloudflared
        fi
        if ! command -v cloudflared &>/dev/null; then
            error "Failed to install cloudflared"
            pause; return
        fi
        info "cloudflared installed"
    fi

    step "Checking auth... "
    if ls "$HOME/.cloudflared/"*cert.pem &>/dev/null 2>&1; then
        printf "${G}authenticated${NC}\n"
    else
        printf "${Y}need login${NC}\n"
        info "A browser URL will appear. Authorize and return here."
        cloudflared tunnel login
    fi

    # Step 3: Tunnel
    echo ""
    echo -e "  ${BOLD}Step 3/4: Tunnel${NC}"
    hr
    if [ -f "$CONFIG_FILE" ]; then
        local tunnel_name
        tunnel_name=$(grep '^tunnel:' "$CONFIG_FILE" | awk '{print $2}')
        info "Tunnel config found: ${tunnel_name}"

        step "Checking tunnel process... "
        if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null; then
            printf "${G}running${NC}\n"
        else
            printf "${Y}starting...${NC}\n"
            [ -x "$SCRIPT_DIR/tunnel-start.sh" ] && "$SCRIPT_DIR/tunnel-start.sh"
            sleep 1
            if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null; then
                info "Tunnel started"
            else
                warn "Could not start tunnel. Check logs."
            fi
        fi
    else
        warn "No tunnel configured. Run create_tunnel.sh first."
        pause; return
    fi

    # Step 4: SSH route
    echo ""
    echo -e "  ${BOLD}Step 4/4: SSH Route${NC}"
    hr
    printf "  ${W}SSH hostname${NC} (e.g. cssh.micstec.com): "
    read -r ssh_hostname
    if [ -n "$ssh_hostname" ]; then
        printf "  ${W}SSH port${NC} [22]: "
        read -r ssh_port
        ssh_port="${ssh_port:-22}"

        if grep -q "hostname: ${ssh_hostname}" "$CONFIG_FILE" 2>/dev/null; then
            info "Route for ${ssh_hostname} already exists"
        else
            [ -x "$SCRIPT_DIR/add-tunnel-route.sh" ] && \
                "$SCRIPT_DIR/add-tunnel-route.sh" --hostname "$ssh_hostname" --service "ssh://localhost:${ssh_port}"
            info "SSH route added"
        fi
    fi

    echo ""
    hr
    echo ""
    info "Server setup complete!"
    echo ""
    echo -e "  ${BOLD}Clients can now connect with:${NC}"
    echo -e "  ${DIM}ssh -o ProxyCommand=\"cloudflared access ssh --hostname ${ssh_hostname:-<hostname>}\" <user>@${ssh_hostname:-<hostname>}${NC}"
    pause
}

# ── server menu ────────────────────────────────────────────────────────────────
server_menu() {
    while true; do
        header "Server Menu"
        echo ""
        menu_item 1 "Full SSH setup wizard (recommended)"
        hr
        menu_item 2 "Check/start SSH service"
        menu_item 3 "Check/install cloudflared"
        menu_item 4 "Tunnel status"
        menu_item 5 "Add SSH route"
        menu_item 6 "List all routes"
        menu_item 7 "Start tunnel"
        menu_item 8 "Stop tunnel"
        menu_item 9 "View tunnel logs"
        hr
        menu_item b "Back to main menu"
        menu_item q "Quit"
        printf "\n  ${W}Choose: ${NC}"
        read -rn1 choice; echo
        case "${choice}" in
            1) server_full_setup ;;
            2) server_check_ssh ;;
            3) server_check_cloudflared ;;
            4) server_tunnel_status ;;
            5) server_add_ssh_route ;;
            6) server_list_routes ;;
            7) server_start_tunnel ;;
            8) server_stop_tunnel ;;
            9) server_view_logs ;;
            b|B) return ;;
            q|Q) echo ""; info "Bye!"; exit 0 ;;
        esac
    done
}

# ══════════════════════════════════════════════════════════════════════════════
#  CLIENT MODE
# ══════════════════════════════════════════════════════════════════════════════

# ── smart detection & full client setup ────────────────────────────────────────
client_smart_setup() {
    header "Client: Smart Setup"
    echo ""

    local os_name; os_name=$(detect_os)
    info "Detected OS: ${os_name}"
    echo ""

    printf "  ${W}SSH hostname to connect to${NC} (e.g. cssh.micstec.com): "
    read -r target_host
    [ -z "$target_host" ] && return

    printf "  ${W}SSH username${NC} [$(whoami)]: "
    read -r ssh_user
    ssh_user="${ssh_user:-$(whoami)}"

    local all_ok=true

    # ── Step 1: Check cloudflared ──
    echo ""
    echo -e "  ${BOLD}Step 1/4: Cloudflared${NC}"
    hr
    step "Checking cloudflared... "
    if command -v cloudflared &>/dev/null; then
        printf "${G}installed${NC}\n"
        info "$(cloudflared --version 2>&1 | head -1)"
    else
        printf "${R}not found${NC}\n"
        all_ok=false
        echo ""
        printf "  ${W}Install cloudflared now? [Y/n]:${NC} "
        read -rn1 yn; echo
        if [[ "${yn:-y}" != "n" && "${yn:-y}" != "N" ]]; then
            echo ""
            if is_mac && command -v brew &>/dev/null; then
                step "Installing via Homebrew...\n"
                brew install cloudflared
            elif command -v apt-get &>/dev/null; then
                step "Installing via apt...\n"
                sudo mkdir -p /usr/share/keyrings
                curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
                    | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
                local codename
                codename=$(lsb_release -cs 2>/dev/null || . /etc/os-release && echo "$VERSION_CODENAME")
                echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] \
https://pkg.cloudflare.com/cloudflared ${codename} main" \
                    | sudo tee /etc/apt/sources.list.d/cloudflared.list >/dev/null
                sudo apt-get update -qq && sudo apt-get install -y cloudflared
            else
                step "Downloading binary...\n"
                local arch; arch=$(uname -m)
                case "$arch" in
                    x86_64)  arch="amd64" ;;
                    aarch64) arch="arm64" ;;
                    armv7l)  arch="arm"   ;;
                    *) error "Unsupported arch: $arch"; ;;
                esac
                if [ -n "$arch" ]; then
                    sudo curl -fsSL "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}" \
                        -o /usr/local/bin/cloudflared
                    sudo chmod +x /usr/local/bin/cloudflared
                fi
            fi

            if command -v cloudflared &>/dev/null; then
                info "cloudflared installed successfully"
                all_ok=true
            else
                error "Installation failed"
            fi
        fi
    fi

    # ── Step 2: Check DNS resolution ──
    echo ""
    echo -e "  ${BOLD}Step 2/4: DNS Resolution${NC}"
    hr
    step "Resolving ${target_host}... "
    local dns_ok=false
    if command -v dig &>/dev/null; then
        if dig +short "$target_host" 2>/dev/null | grep -q '.'; then
            printf "${G}OK${NC}\n"
            local resolved; resolved=$(dig +short "$target_host" 2>/dev/null | head -1)
            info "Resolves to: ${resolved}"
            dns_ok=true
        else
            printf "${R}FAILED${NC}\n"
            warn "DNS not resolving. It may take a few minutes after server setup."
            all_ok=false
        fi
    elif command -v nslookup &>/dev/null; then
        if nslookup "$target_host" 2>/dev/null | grep -q 'Address'; then
            printf "${G}OK${NC}\n"
            dns_ok=true
        else
            printf "${R}FAILED${NC}\n"
            warn "DNS not resolving"
            all_ok=false
        fi
    elif command -v host &>/dev/null; then
        if host "$target_host" &>/dev/null; then
            printf "${G}OK${NC}\n"
            dns_ok=true
        else
            printf "${R}FAILED${NC}\n"
            all_ok=false
        fi
    else
        printf "${Y}SKIP (no dig/nslookup/host)${NC}\n"
        warn "Install dnsutils for DNS checks"
    fi

    # ── Step 3: SSH config ──
    echo ""
    echo -e "  ${BOLD}Step 3/4: SSH Config${NC}"
    hr
    local ssh_config="$HOME/.ssh/config"
    local config_exists=false

    step "Checking ~/.ssh/config for ${target_host}... "
    if [ -f "$ssh_config" ] && grep -q "Host ${target_host}" "$ssh_config" 2>/dev/null; then
        printf "${G}found${NC}\n"
        config_exists=true
        # Show current entry
        echo ""
        printf "  ${DIM}Current entry:${NC}\n"
        awk "/Host ${target_host//./\\.}/,/^Host / { if (/^Host / && !/Host ${target_host//./\\.}/) exit; print }" "$ssh_config" | sed 's/^/    /'
    else
        printf "${Y}not found${NC}\n"
        echo ""
        printf "  ${W}Add SSH config entry for ${target_host}? [Y/n]:${NC} "
        read -rn1 yn; echo
        if [[ "${yn:-y}" != "n" && "${yn:-y}" != "N" ]]; then
            mkdir -p "$HOME/.ssh"
            chmod 700 "$HOME/.ssh"

            local cf_path
            cf_path=$(command -v cloudflared 2>/dev/null || echo "cloudflared")

            local entry
            entry=$(cat <<EOF

Host ${target_host}
    HostName ${target_host}
    User ${ssh_user}
    ProxyCommand ${cf_path} access ssh --hostname %h
EOF
)
            if [ -f "$ssh_config" ]; then
                echo "$entry" >> "$ssh_config"
            else
                echo "$entry" > "$ssh_config"
                chmod 600 "$ssh_config"
            fi
            info "SSH config entry added"
            config_exists=true
            echo ""
            printf "  ${DIM}Added:${NC}\n"
            echo "$entry" | sed 's/^/    /'
        fi
    fi

    # ── Step 4: Connection test ──
    echo ""
    echo -e "  ${BOLD}Step 4/4: Connection Test${NC}"
    hr

    if ! command -v cloudflared &>/dev/null; then
        error "cloudflared not installed — cannot test connection"
        pause; return
    fi

    step "Testing SSH connection to ${ssh_user}@${target_host}...\n"
    echo ""
    printf "  ${DIM}(timeout: 15s — this may take a moment via Cloudflare)${NC}\n"
    echo ""

    local test_result
    if $config_exists; then
        test_result=$(ssh -o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
            "${target_host}" "echo SSH_CONNECTION_OK" 2>&1) || true
    else
        test_result=$(ssh -o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
            -o "ProxyCommand=cloudflared access ssh --hostname ${target_host}" \
            "${ssh_user}@${target_host}" "echo SSH_CONNECTION_OK" 2>&1) || true
    fi

    if echo "$test_result" | grep -q "SSH_CONNECTION_OK"; then
        info "SSH connection successful!"
        all_ok=true
    else
        # Check specific failure types for smart diagnostics
        if echo "$test_result" | grep -qi "permission denied"; then
            warn "Connection reached server but authentication failed"
            echo ""
            echo -e "  ${BOLD}Suggestions:${NC}"
            echo "    • Check that user '${ssh_user}' exists on the server"
            echo "    • Set up SSH key auth: ssh-copy-id ${target_host}"
            echo "    • Or verify your password"
        elif echo "$test_result" | grep -qi "connection refused"; then
            error "Connection refused — SSH may not be running on the server"
            echo ""
            echo -e "  ${BOLD}Suggestions:${NC}"
            echo "    • On server: sudo service ssh start"
            echo "    • Verify the SSH route in tunnel config"
        elif echo "$test_result" | grep -qi "timed out\|timeout"; then
            error "Connection timed out"
            echo ""
            echo -e "  ${BOLD}Suggestions:${NC}"
            echo "    • Verify the tunnel is running on the server"
            echo "    • Check DNS resolves: dig ${target_host}"
            echo "    • Wait a few minutes if DNS was just created"
        elif echo "$test_result" | grep -qi "Could not resolve\|Name .* not known"; then
            error "DNS resolution failed for ${target_host}"
            echo ""
            echo -e "  ${BOLD}Suggestions:${NC}"
            echo "    • Verify DNS record exists in Cloudflare"
            echo "    • Wait a few minutes for DNS propagation"
        else
            error "Connection failed"
            echo ""
            echo -e "  ${DIM}Output: ${test_result}${NC}" | head -5
        fi
        all_ok=false
    fi

    # ── Summary ──
    echo ""
    hr
    echo ""
    if [ "$all_ok" = true ]; then
        printf "  ${G}${BOLD}✓ All checks passed!${NC}\n"
        echo ""
        echo -e "  ${BOLD}Connect with:${NC}"
        if $config_exists; then
            echo -e "    ${C}ssh ${target_host}${NC}"
        else
            echo -e "    ${C}ssh -o ProxyCommand=\"cloudflared access ssh --hostname ${target_host}\" ${ssh_user}@${target_host}${NC}"
        fi
    else
        printf "  ${Y}${BOLD}⚠ Some checks failed — review above for details${NC}\n"
    fi
    pause
}

# ── test connection only ───────────────────────────────────────────────────────
client_test_connection() {
    header "Client: Test Connection"
    echo ""

    if ! command -v cloudflared &>/dev/null; then
        error "cloudflared is not installed. Use Smart Setup first."
        pause; return
    fi

    printf "  ${W}SSH hostname${NC} (e.g. cssh.micstec.com): "
    read -r target_host
    [ -z "$target_host" ] && return

    printf "  ${W}SSH username${NC} [$(whoami)]: "
    read -r ssh_user
    ssh_user="${ssh_user:-$(whoami)}"

    echo ""

    # Quick diagnostics
    step "DNS resolution... "
    if command -v dig &>/dev/null && dig +short "$target_host" 2>/dev/null | grep -q '.'; then
        printf "${G}OK${NC}\n"
    elif command -v host &>/dev/null && host "$target_host" &>/dev/null; then
        printf "${G}OK${NC}\n"
    else
        printf "${Y}WARN${NC}\n"
    fi

    step "Cloudflared proxy test... "
    local proxy_test
    proxy_test=$(timeout 10 cloudflared access ssh --hostname "$target_host" --url 2>&1) || true
    printf "${G}OK${NC}\n"

    step "SSH connection... "
    local ssh_config="$HOME/.ssh/config"
    local test_result

    if [ -f "$ssh_config" ] && grep -q "Host ${target_host}" "$ssh_config" 2>/dev/null; then
        test_result=$(ssh -o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
            "${target_host}" "echo SSH_CONNECTION_OK" 2>&1) || true
    else
        test_result=$(ssh -o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
            -o "ProxyCommand=cloudflared access ssh --hostname ${target_host}" \
            "${ssh_user}@${target_host}" "echo SSH_CONNECTION_OK" 2>&1) || true
    fi

    if echo "$test_result" | grep -q "SSH_CONNECTION_OK"; then
        printf "${G}SUCCESS${NC}\n"
        echo ""
        info "SSH connection working!"
    else
        printf "${R}FAILED${NC}\n"
        echo ""
        if echo "$test_result" | grep -qi "permission denied"; then
            warn "Auth failed — server reachable but credentials rejected"
        elif echo "$test_result" | grep -qi "refused"; then
            error "Connection refused — SSH not running on server?"
        elif echo "$test_result" | grep -qi "timed out\|timeout"; then
            error "Timeout — tunnel may not be running on server"
        else
            error "Failed: $(echo "$test_result" | head -3)"
        fi
    fi
    pause
}

# ── view/edit SSH config ───────────────────────────────────────────────────────
client_view_ssh_config() {
    header "Client: SSH Config"
    echo ""

    local ssh_config="$HOME/.ssh/config"
    if [ -f "$ssh_config" ]; then
        info "File: ${ssh_config}"
        hr
        # Show only ProxyCommand cloudflared entries
        local has_cf=false
        while IFS= read -r line || [ -n "$line" ]; do
            echo "  $line"
        done < "$ssh_config"

        echo ""
        hr
        echo ""
        echo -e "  ${DIM}Cloudflare tunnel entries:${NC}"
        grep -B1 'cloudflared' "$ssh_config" 2>/dev/null | sed 's/^/    /' || \
            warn "  No cloudflared entries found"
    else
        warn "No SSH config file found at ${ssh_config}"
    fi
    pause
}

# ── add SSH config entry ──────────────────────────────────────────────────────
client_add_ssh_config() {
    header "Client: Add SSH Config"
    echo ""

    if ! command -v cloudflared &>/dev/null; then
        error "cloudflared not installed. Install it first."
        pause; return
    fi

    printf "  ${W}SSH hostname${NC} (e.g. cssh.micstec.com): "
    read -r target_host
    [ -z "$target_host" ] && return

    printf "  ${W}SSH username${NC} [$(whoami)]: "
    read -r ssh_user
    ssh_user="${ssh_user:-$(whoami)}"

    local ssh_config="$HOME/.ssh/config"
    if [ -f "$ssh_config" ] && grep -q "Host ${target_host}" "$ssh_config" 2>/dev/null; then
        warn "Entry for ${target_host} already exists in SSH config"
        printf "  ${W}Overwrite? [y/N]:${NC} "
        read -rn1 yn; echo
        if [[ "$yn" == "y" || "$yn" == "Y" ]]; then
            # Remove existing entry
            local tmpfile; tmpfile=$(mktemp)
            awk -v host="Host ${target_host}" '
                $0 == host { skip=1; next }
                /^Host / && skip { skip=0 }
                !skip { print }
            ' "$ssh_config" > "$tmpfile"
            mv "$tmpfile" "$ssh_config"
        else
            pause; return
        fi
    fi

    mkdir -p "$HOME/.ssh"
    chmod 700 "$HOME/.ssh"

    local cf_path; cf_path=$(command -v cloudflared)
    cat >> "$ssh_config" <<EOF

Host ${target_host}
    HostName ${target_host}
    User ${ssh_user}
    ProxyCommand ${cf_path} access ssh --hostname %h
EOF
    chmod 600 "$ssh_config"
    info "Added SSH config entry for ${target_host}"
    echo ""
    echo -e "  ${DIM}You can now connect with:${NC}"
    echo -e "    ${C}ssh ${target_host}${NC}"
    pause
}

# ── install cloudflared (standalone) ──────────────────────────────────────────
client_install_cloudflared() {
    header "Client: Install Cloudflared"
    echo ""

    local os_name; os_name=$(detect_os)
    info "Detected OS: ${os_name}"
    echo ""

    if command -v cloudflared &>/dev/null; then
        info "cloudflared is already installed: $(cloudflared --version 2>&1 | head -1)"
        printf "\n  ${W}Reinstall/upgrade? [y/N]:${NC} "
        read -rn1 yn; echo
        [[ "$yn" != "y" && "$yn" != "Y" ]] && { pause; return; }
    fi

    echo ""
    if is_mac; then
        if command -v brew &>/dev/null; then
            step "Installing via Homebrew...\n"
            brew install cloudflared || brew upgrade cloudflared
        else
            error "Homebrew not found. Install with: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
            echo "  Then run: brew install cloudflared"
        fi
    elif command -v apt-get &>/dev/null; then
        step "Installing via apt...\n"
        sudo mkdir -p /usr/share/keyrings
        curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
            | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
        local codename
        codename=$(lsb_release -cs 2>/dev/null || (. /etc/os-release && echo "$VERSION_CODENAME"))
        echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] \
https://pkg.cloudflare.com/cloudflared ${codename} main" \
            | sudo tee /etc/apt/sources.list.d/cloudflared.list >/dev/null
        sudo apt-get update -qq && sudo apt-get install -y cloudflared
    else
        step "Downloading binary...\n"
        local arch; arch=$(uname -m)
        case "$arch" in
            x86_64)  arch="amd64" ;;
            aarch64) arch="arm64" ;;
            armv7l)  arch="arm"   ;;
            *) error "Unsupported arch: $arch"; pause; return ;;
        esac
        sudo curl -fsSL "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}" \
            -o /usr/local/bin/cloudflared
        sudo chmod +x /usr/local/bin/cloudflared
    fi

    echo ""
    if command -v cloudflared &>/dev/null; then
        info "cloudflared installed: $(cloudflared --version 2>&1 | head -1)"
    else
        error "Installation failed"
    fi
    pause
}

# ── client menu ────────────────────────────────────────────────────────────────
client_menu() {
    while true; do
        header "Client Menu"
        local os_name; os_name=$(detect_os)
        printf "  ${DIM}OS: ${os_name}${NC}"
        if command -v cloudflared &>/dev/null; then
            printf "  ${DIM}│ cloudflared: $(cloudflared --version 2>&1 | head -1 | grep -oP '\d+\.\d+\.\d+' | head -1)${NC}"
        else
            printf "  ${DIM}│ cloudflared: ${R}not installed${NC}"
        fi
        echo ""
        echo ""
        menu_item 1 "Smart setup & test (recommended)"
        hr
        menu_item 2 "Install/upgrade cloudflared"
        menu_item 3 "Add SSH config entry"
        menu_item 4 "View SSH config"
        menu_item 5 "Test connection"
        hr
        menu_item b "Back to main menu"
        menu_item q "Quit"
        printf "\n  ${W}Choose: ${NC}"
        read -rn1 choice; echo
        case "${choice}" in
            1) client_smart_setup ;;
            2) client_install_cloudflared ;;
            3) client_add_ssh_config ;;
            4) client_view_ssh_config ;;
            5) client_test_connection ;;
            b|B) return ;;
            q|Q) echo ""; info "Bye!"; exit 0 ;;
        esac
    done
}

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ══════════════════════════════════════════════════════════════════════════════

main_menu() {
    while true; do
        header "Main Menu"
        echo ""
        echo -e "  ${BOLD}Select your role:${NC}"
        echo ""
        menu_item 1 "Server — Set up SSH tunnel service"
        echo -e "         ${DIM}(Run on the machine you want to SSH into)${NC}"
        echo ""
        menu_item 2 "Client — Connect to SSH tunnel"
        echo -e "         ${DIM}(Run on the machine you're connecting from)${NC}"
        echo ""
        hr
        menu_item q "Quit"
        printf "\n  ${W}Choose: ${NC}"
        read -rn1 choice; echo
        case "${choice}" in
            1) server_menu ;;
            2) client_menu ;;
            q|Q) echo ""; info "Bye!"; exit 0 ;;
        esac
    done
}

# ── CLI passthrough ────────────────────────────────────────────────────────────
case "${1:-}" in
    -h|--help|help)
        cat <<'EOF'
Usage: ssh-tunnel-tui.sh [server|client]

Interactive TUI for setting up SSH over Cloudflare Tunnel.

Modes:
  server    Set up the SSH tunnel service (run on the server/WSL machine)
  client    Connect to an SSH tunnel (run on the remote client machine)

If no argument is given, shows the interactive menu to choose a mode.

Server mode will:
  • Ensure SSH is running
  • Install/verify cloudflared
  • Add SSH route to the Cloudflare tunnel
  • Start/manage the tunnel

Client mode will:
  • Detect your OS (macOS, Linux, WSL)
  • Install cloudflared if needed
  • Configure ~/.ssh/config
  • Test the SSH connection with smart diagnostics
EOF
        exit 0 ;;
    server)
        server_menu ;;
    client)
        client_menu ;;
    *)
        main_menu ;;
esac
