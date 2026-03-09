#!/usr/bin/env bash
# =============================================================================
# setup.sh – One-Click Install: Hardened WireGuard Gateway + Canary Monitor
# =============================================================================
# Tested on: Ubuntu 24.04 LTS (Noble Numbat)
# Usage    : curl -fsSL https://raw.githubusercontent.com/shanmkuu/Cloud-VPN-Gateway-with-Canary-Breach-Alerts/main/setup.sh | sudo bash
#            OR: sudo bash setup.sh [WG_PORT] [SSH_PORT]
# =============================================================================
set -euo pipefail

WG_PORT="${1:-51820}"
SSH_PORT="${2:-2222}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/wg-gateway-setup.log"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

log()     { echo -e "${GREEN}[✓]${NC} $*" | tee -a "$LOG_FILE"; }
info()    { echo -e "${BLUE}[→]${NC} $*" | tee -a "$LOG_FILE"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*" | tee -a "$LOG_FILE"; }
die()     { echo -e "${RED}[✗]${NC} $*" | tee -a "$LOG_FILE"; exit 1; }
section() { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${NC}"; \
            echo -e "${BOLD}  $*${NC}"; \
            echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}\n"; }

banner() {
cat << "BANNER"
  ____  _                   _   _   _     _ _
 / ___|| |_ __ ___  _ __ __| | | | | |   | | |
 \___ \| __/ _` \ \/ / '_ \ _` | | | | |   | | |
  ___) | || (_| |>  <| | | \__,_| |_| |___| |_|
 |____/ \__\__,_/_/\_\_| |_|\__,_| |_|_____|_(_)

  WireGuard Hardened Gateway + Canary Monitor
  Setup Script — shanmkuu | github.com/shanmkuu
BANNER
echo ""
}

# ─── Preflight Checks ─────────────────────────────────────────────────────────
preflight() {
    section "Preflight Checks"
    [[ $(id -u) -ne 0 ]] && die "Must run as root (sudo bash setup.sh)"

    local distro
    distro=$(lsb_release -is 2>/dev/null || cat /etc/os-release | grep ^ID= | cut -d= -f2 | tr -d '"')
    if [[ "$distro" != "Ubuntu" ]]; then
        warn "This script is optimized for Ubuntu. Detected: $distro. Proceeding anyway..."
    fi

    local ver
    ver=$(lsb_release -rs 2>/dev/null || "0")
    if [[ $(echo "$ver >= 24.04" | bc -l 2>/dev/null || echo 1) -eq 1 ]]; then
        log "Ubuntu ${ver} detected"
    fi

    # Check internet connectivity
    if ! ping -c1 -W3 1.1.1.1 &>/dev/null; then
        die "No internet connectivity — cannot download packages."
    fi
    log "Internet connectivity: OK"
}

# ─── System Update ────────────────────────────────────────────────────────────
update_system() {
    section "System Update"
    info "Updating package lists and upgrading system..."
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold"
    log "System updated"
}

# ─── Install WireGuard ────────────────────────────────────────────────────────
install_wireguard() {
    section "WireGuard Installation"
    info "Installing WireGuard kernel module and tools..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        wireguard \
        wireguard-tools \
        linux-headers-"$(uname -r)" \
        qrencode \
        resolvconf
    log "WireGuard installed: $(wg --version)"

    # Generate server keys
    info "Generating WireGuard server key pair..."
    mkdir -p /etc/wireguard
    chmod 700 /etc/wireguard

    if [[ ! -f /etc/wireguard/server.key ]]; then
        wg genkey | tee /etc/wireguard/server.key \
                  | wg pubkey > /etc/wireguard/server.pub
        chmod 600 /etc/wireguard/server.key
        SERVER_PRIV=$(cat /etc/wireguard/server.key)
        SERVER_PUB=$(cat /etc/wireguard/server.pub)
        log "Server private key: /etc/wireguard/server.key"
        log "Server public key : $(cat /etc/wireguard/server.pub)"
    else
        warn "Server keys already exist — skipping generation"
        SERVER_PRIV=$(cat /etc/wireguard/server.key)
        SERVER_PUB=$(cat /etc/wireguard/server.pub)
    fi

    # Detect public-facing network interface
    ETH_IFACE=$(ip route show default | awk '/default/ {print $5}' | head -1)
    info "Detected default interface: ${ETH_IFACE}"

    # Deploy WireGuard configuration
    info "Deploying wg0.conf..."
    cp "${REPO_DIR}/configs/wg0.conf" /etc/wireguard/wg0.conf
    # Substitute key placeholders
    sed -i "s|<SERVER_PRIVATE_KEY>|${SERVER_PRIV}|g" /etc/wireguard/wg0.conf
    sed -i "s|%i|${ETH_IFACE}|g" /etc/wireguard/wg0.conf
    chmod 600 /etc/wireguard/wg0.conf

    systemctl enable --now wg-quick@wg0
    log "WireGuard interface wg0 started"
    wg show
}

# ─── Install & Configure CrowdSec ─────────────────────────────────────────────
install_crowdsec() {
    section "CrowdSec IPS Installation"

    if ! command -v cscli &>/dev/null; then
        info "Adding CrowdSec repository..."
        curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq crowdsec
        log "CrowdSec installed"
    else
        log "CrowdSec already installed: $(cscli version 2>&1 | head -1)"
    fi

    # Install nftables bouncer (blocks IPs at kernel level)
    if ! command -v crowdsec-firewall-bouncer &>/dev/null; then
        info "Installing CrowdSec nftables bouncer..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            crowdsec-firewall-bouncer-nftables 2>/dev/null || \
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            crowdsec-firewall-bouncer-iptables
        log "CrowdSec bouncer installed"
    fi

    # Deploy custom WireGuard handshake exhaustion scenario
    info "Deploying custom CrowdSec WireGuard scenario..."
    mkdir -p /etc/crowdsec/scenarios
    cp "${REPO_DIR}/configs/crowdsec/wg-handshake-exhaustion.yaml" \
       /etc/crowdsec/scenarios/wg-handshake-exhaustion.yaml

    # Install the WireGuard log parser (community hub or custom)
    cscli parsers install crowdsecurity/syslog-logs 2>/dev/null || true
    cscli scenarios install crowdsecurity/ssh-bf 2>/dev/null || true

    systemctl restart crowdsec
    log "CrowdSec scenario deployed and service restarted"
    cscli scenarios list 2>/dev/null | grep -E "wg-|ssh" || true
}

# ─── Apply Hardening ──────────────────────────────────────────────────────────
apply_hardening() {
    section "System Hardening"
    info "Running harden.sh..."
    bash "${REPO_DIR}/scripts/harden.sh" "${WG_PORT}" "${SSH_PORT}"
    log "Hardening complete"
}

# ─── Install Python Canary Monitor ───────────────────────────────────────────
install_canary() {
    section "Python Canary Monitor Setup"

    # Install Python 3.12+ if needed
    if ! python3 --version 2>/dev/null | grep -q "3\.1[2-9]"; then
        info "Installing Python 3.12..."
        DEBIAN_FRONTEND=noninteractive add-apt-repository -y ppa:deadsnakes/ppa
        DEBIAN_FRONTEND=noninteractive apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            python3.12 python3.12-venv python3.12-dev
    fi
    log "Python version: $(python3 --version)"

    # Create virtual environment
    info "Creating Python virtual environment..."
    python3 -m venv /opt/wg-canary/venv
    /opt/wg-canary/venv/bin/pip install --upgrade pip -q
    /opt/wg-canary/venv/bin/pip install -r "${REPO_DIR}/requirements.txt" -q
    log "Python dependencies installed"

    # Copy source
    cp -r "${REPO_DIR}/src" /opt/wg-canary/
    log "Canary monitor source deployed to /opt/wg-canary/src/"

    # Deploy .env if not present
    if [[ ! -f /opt/wg-canary/.env ]]; then
        cp "${REPO_DIR}/configs/.env.example" /opt/wg-canary/.env
        chmod 600 /opt/wg-canary/.env
        warn "IMPORTANT: Edit /opt/wg-canary/.env and set your WEBHOOK_URL before starting"
    fi

    # Create systemd service
    info "Creating canary-monitor systemd service..."
    cat > /etc/systemd/system/wg-canary.service << SERVICE
[Unit]
Description=WireGuard Canary Breach Monitor
Documentation=https://github.com/shanmkuu/Cloud-VPN-Gateway-with-Canary-Breach-Alerts
After=network.target wg-quick@wg0.service
Wants=wg-quick@wg0.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/wg-canary
EnvironmentFile=/opt/wg-canary/.env
ExecStart=/opt/wg-canary/venv/bin/python src/canary_monitor.py
Restart=always
RestartSec=10s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=wg-canary

# Security hardening for the service itself
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/log /opt/wg-canary

[Install]
WantedBy=multi-user.target
SERVICE

    systemctl daemon-reload
    systemctl enable wg-canary.service
    warn "wg-canary service enabled but NOT started — set WEBHOOK_URL in .env first"
    warn "Start with: systemctl start wg-canary"
    log "Canary monitor systemd service created"
}

# ─── Final Status ─────────────────────────────────────────────────────────────
print_summary() {
    section "Setup Complete!"
    echo -e "${BOLD}${GREEN}"
    cat << "DONE"
  ╔═══════════════════════════════════════════════════════╗
  ║        WIREGUARD HARDENED GATEWAY — READY            ║
  ╚═══════════════════════════════════════════════════════╝
DONE
    echo -e "${NC}"
    echo ""
    echo -e "${BOLD}Services:${NC}"
    echo -e "  WireGuard   : $(systemctl is-active wg-quick@wg0 2>/dev/null)"
    echo -e "  CrowdSec    : $(systemctl is-active crowdsec 2>/dev/null)"
    echo -e "  WG Canary   : $(systemctl is-active wg-canary 2>/dev/null) (start after configuring .env)"
    echo ""
    echo -e "${BOLD}Next Steps:${NC}"
    echo -e "  1. Edit ${YELLOW}/opt/wg-canary/.env${NC} — set WEBHOOK_URL"
    echo -e "  2. ${YELLOW}systemctl start wg-canary${NC}"
    echo -e "  3. Add WireGuard peers: ${YELLOW}wg set wg0 peer <PUBKEY> allowed-ips 10.10.0.x/32${NC}"
    echo -e "  4. Monitor alerts: ${YELLOW}journalctl -fu wg-canary${NC}"
    echo -e "  5. Check CrowdSec: ${YELLOW}cscli decisions list${NC}"
    echo ""
    echo -e "${BOLD}Server Public Key (share with peers):${NC}"
    cat /etc/wireguard/server.pub 2>/dev/null || echo "  (key file not found)"
    echo ""
    echo -e "Setup log: ${YELLOW}${LOG_FILE}${NC}"
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
    banner
    exec 2>> "$LOG_FILE"

    preflight
    update_system
    install_wireguard
    install_crowdsec
    apply_hardening
    install_canary
    print_summary
}

main "$@"
