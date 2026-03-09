#!/usr/bin/env bash
# =============================================================================
# harden.sh – Kernel & Firewall Hardening for WireGuard Gateway
# =============================================================================
# Author  : Lead Security Engineer
# Purpose : Apply CIS/NIST-aligned kernel sysctl hardening, configure UFW with
#           default-deny policy, and open only the required service ports.
# Usage   : sudo bash harden.sh [WG_PORT] [SSH_PORT]
#           Defaults: WG_PORT=51820, SSH_PORT=2222
# =============================================================================
set -euo pipefail

WG_PORT="${1:-51820}"
SSH_PORT="${2:-2222}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }

[[ $(id -u) -ne 0 ]] && die "Run as root."

# ─── 1. Kernel Hardening via sysctl ──────────────────────────────────────────
log "Applying sysctl hardening rules..."

SYSCTL_CONF="/etc/sysctl.d/99-wireguard-hardening.conf"
cat > "$SYSCTL_CONF" << 'SYSCTL'
# ── Anti-Spoofing & Routing ──────────────────────────────────────────────────
# Strict Reverse Path Filtering (CIS 3.3.1 / NIST SP 800-123)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable IP source routing (prevents SRR attack)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# ── ICMP / Redirect Hardening ─────────────────────────────────────────────────
# Ignore ICMP redirects (prevents MitM via routing manipulation)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Log martian packets (aids intrusion detection)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ── TCP SYN Cookie Protection (CIS 3.3.8) ────────────────────────────────────
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# ── IP Forwarding (required for WireGuard routing) ───────────────────────────
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# ── General Network Security ──────────────────────────────────────────────────
# Disable IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Protect against TIME-WAIT assassination
net.ipv4.tcp_rfc1337 = 1

# Disable the magic SysRq key
kernel.sysrq = 0

# Restrict core dumps
fs.suid_dumpable = 0
kernel.core_uses_pid = 1

# Restrict dmesg access to root
kernel.dmesg_restrict = 1

# Restrict ptrace
kernel.yama.ptrace_scope = 1

# ── Memory Protection ─────────────────────────────────────────────────────────
kernel.randomize_va_space = 2
vm.mmap_min_addr = 65536
SYSCTL

sysctl --system > /dev/null 2>&1
log "sysctl rules applied from $SYSCTL_CONF"

# ─── 2. UFW Firewall Configuration ───────────────────────────────────────────
log "Configuring UFW firewall..."

command -v ufw &>/dev/null || { apt-get install -y -q ufw; }

# Ensure UFW is enabled with strict defaults
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw default deny forward

# Allow WireGuard UDP tunnel
ufw allow "${WG_PORT}/udp" comment "WireGuard VPN"
log "  → Opened UDP/${WG_PORT} for WireGuard"

# Allow non-standard SSH (prevents default port brute-force)
ufw allow "${SSH_PORT}/tcp" comment "SSH (non-standard)"
log "  → Opened TCP/${SSH_PORT} for SSH"

# Allow established / related connections (stateful tracking)
# UFW's default rules handle this via iptables ESTABLISHED,RELATED

# Rate-limit SSH to mitigate brute-force (triggers after 6 conn/30s)
ufw limit "${SSH_PORT}/tcp" comment "SSH rate-limit"

# Enable UFW
ufw --force enable
log "UFW enabled with default-deny policy"
ufw status verbose

# ─── 3. Fail2Ban (optional hardening layer, non-blocking) ────────────────────
if command -v fail2ban-client &>/dev/null; then
    log "Fail2Ban detected – skipping (CrowdSec is primary IPS)"
fi

# ─── 4. SSH Daemon Hardening ──────────────────────────────────────────────────
log "Hardening SSH daemon configuration..."

SSHD_CONF="/etc/ssh/sshd_config.d/99-hardening.conf"
cat > "$SSHD_CONF" << SSHD
# ── Hardened SSH Configuration (CIS 5.2) ─────────────────────────────────────
Port ${SSH_PORT}
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
IgnoreRhosts yes
HostbasedAuthentication no
Banner /etc/issue.net
LogLevel VERBOSE
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
SSHD

systemctl reload sshd 2>/dev/null || warn "Could not reload sshd – verify manually"
log "SSH hardened on port ${SSH_PORT}"

# ─── 5. Filesystem Hardening ──────────────────────────────────────────────────
log "Applying filesystem hardening..."

# Secure /tmp with noexec/nosuid
if ! grep -q "^tmpfs /tmp" /etc/fstab; then
    echo "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    log "  → /tmp secured with noexec,nosuid,nodev"
fi

# Restrict /proc
if ! grep -q "^proc /proc" /etc/fstab; then
    echo "proc /proc proc rw,nosuid,nodev,noexec,relatime,hidepid=2 0 0" >> /etc/fstab
    log "  → /proc restricted with hidepid=2"
fi

# ─── 6. Audit Framework ───────────────────────────────────────────────────────
if command -v auditctl &>/dev/null; then
    log "Configuring auditd rules for WireGuard key access..."
    cat >> /etc/audit/rules.d/99-wireguard.rules << 'AUDIT' 2>/dev/null || true
# Monitor WireGuard private key access
-w /etc/wireguard/ -p rwxa -k wireguard_keys
# Monitor sysctl changes
-a always,exit -F arch=b64 -S sysctl -k sysctl_change
AUDIT
fi

echo ""
log "═══════════════════════════════════════════════════════════"
log "  Hardening complete! Summary:"
log "    • Kernel: sysctl anti-spoofing + SYN cookies + ASLR"
log "    • Firewall: UFW default-deny, WG:${WG_PORT}/udp SSH:${SSH_PORT}/tcp"
log "    • SSH: hardened ciphers, key-auth only, no root login"
log "    • Filesystem: /tmp noexec, /proc hidepid=2"
log "═══════════════════════════════════════════════════════════"
warn "ACTION REQUIRED: Reboot to fully apply all kernel settings."
