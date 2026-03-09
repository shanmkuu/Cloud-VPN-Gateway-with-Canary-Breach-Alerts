# Security Policy & Compliance References
# WireGuard Hardened Gateway Project
# =============================================================================
# This document maps the security controls implemented in this project to
# recognized industry benchmarks and standards.
# =============================================================================

# RESOURCES.md — NIST & CIS Benchmark Mapping

## Standards This Project Addresses

---

### 🔵 NIST Special Publications

| Control | Reference | Implementation |
|---------|-----------|----------------|
| VPN Security | [NIST SP 800-77 Rev.1](https://csrc.nist.gov/publications/detail/sp/800-77/rev-1/final) | WireGuard protocol selection, key management, peer authentication |
| Network Security | [NIST SP 800-41 Rev.1](https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final) | UFW default-deny policy, stateful packet inspection |
| Server Hardening | [NIST SP 800-123](https://csrc.nist.gov/publications/detail/sp/800-123/final) | sysctl anti-spoofing, SSH hardening, /proc/tmp restrictions |
| Log Management | [NIST SP 800-92](https://csrc.nist.gov/publications/detail/sp/800-92/final) | canary_monitor.py log tailing, event correlation, alerting |
| Incident Response | [NIST SP 800-61 Rev.2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) | CrowdSec automated ban + Discord/Slack alert on threshold breach |
| Cryptography | [NIST SP 800-175B Rev.1](https://csrc.nist.gov/publications/detail/sp/800-175b/rev-1/final) | WireGuard ChaCha20-Poly1305, Curve25519 key exchange, BLAKE2s MACs |
| Zero Trust | [NIST SP 800-207](https://csrc.nist.gov/publications/detail/sp/800-207/final) | Peer allowlist, no default peer acceptance, pre-shared key layer |

---

### 🟠 CIS Benchmarks

#### CIS Ubuntu Linux 24.04 LTS Benchmark (Level 2)

| CIS Control | Section | Implementation |
|------------|---------|----------------|
| Ensure IP forwarding is disabled (or controlled) | 3.1.1 | `net.ipv4.ip_forward=1` only when WG routing is required |
| Ensure packet redirect sending is disabled | 3.1.2 | `net.ipv4.conf.all.send_redirects=0` in sysctl |
| Ensure source routed packets are not accepted | 3.3.1 | `net.ipv4.conf.all.accept_source_route=0` |
| Ensure ICMP redirects are not accepted | 3.3.2 | `net.ipv4.conf.all.accept_redirects=0` |
| Ensure broadcast ICMP requests are ignored | 3.3.5 | `net.ipv4.icmp_ignore_bogus_error_responses=1` |
| Ensure TCP SYN Cookies are enabled | 3.3.8 | `net.ipv4.tcp_syncookies=1` |
| Ensure ufw is installed & active | 4.1.1 | UFW installed, enabled, default-deny in `harden.sh` |
| Ensure ufw default deny policy | 4.1.2 | `ufw default deny incoming/forward` |
| Ensure SSH Protocol is set to 2 | 5.2.2 | `Protocol 2` in `sshd_config.d/99-hardening.conf` |
| Ensure SSH root login is disabled | 5.2.10 | `PermitRootLogin no` |
| Ensure SSH MaxAuthTries ≤ 4 | 5.2.7 | `MaxAuthTries 3` |
| Ensure SSH PermitEmptyPasswords is off | 5.2.11 | `PermitEmptyPasswords no` |
| Ensure SSH Idle Timeout Interval | 5.2.16 | `ClientAliveInterval 300`, `ClientAliveCountMax 2` |
| Restrict core dumps | 1.5.1 | `fs.suid_dumpable=0` |
| Enable Address Space Layout Randomization | 1.5.2 | `kernel.randomize_va_space=2` |
| Ensure /tmp is configured separately | 1.1.2 | `tmpfs /tmp noexec,nosuid,nodev` |

---

### 🟢 CIS Controls v8 (Critical Security Controls)

| CIS Control | Control Name | Implementation |
|------------|--------------|----------------|
| Control 4 | Secure Configuration of Enterprise Assets | `harden.sh`, `sysctl.d/`, `sshd_config.d/` |
| Control 6 | Access Control Management | WireGuard peer allowlist, public-key-only auth |
| Control 8 | Audit Log Management | `canary_monitor.py` log tailing, auditd rules |
| Control 9 | Email and Web Browser Protections | N/A (infrastructure layer) |
| Control 10 | Malware Defenses | CrowdSec IPS with automated bans |
| Control 12 | Network Infrastructure Management | UFW segmentation, WireGuard encrypted overlay |
| Control 13 | Network Monitoring and Defense | `canary_monitor.py` threshold alerting |
| Control 16 | Application Software Security | Bandit SAST, pip-audit in CI/CD pipeline |

---

### 🔴 OWASP Guidance

| Reference | Application |
|-----------|-------------|
| [OWASP Network Security Checklist](https://cheatsheetseries.owasp.org/cheatsheets/Network_Segmentation_Cheat_Sheet.html) | UFW network segmentation, WireGuard overlay |
| [OWASP Logging Guide](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | canary_monitor structured logging with timestamps |
| [OWASP Docker Security](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) | Trivy container scanning in CI |
| [OWASP Python Security](https://cheatsheetseries.owasp.org/cheatsheets/Python_Security_Cheat_Sheet.html) | Bandit SAST, no hardcoded credentials, .env isolation |

---

### 📋 RFC References

| RFC | Title | Relevance |
|-----|-------|-----------|
| RFC 8446 | TLS 1.3 | Cipher selection philosophy (ChaCha20, AEAD) |
| RFC 4787 | NAT UDP Mapping | PersistentKeepalive = 25s for NAT traversal |
| RFC 3704 | Ingress Filtering | `rp_filter=1` anti-spoofing |
| RFC 4301 | IPsec Architecture | Comparison baseline for WireGuard design |

---

## Threat Model Summary

```
┌─────────────────────────────────────────────────────┐
│              THREAT MATRIX                          │
├────────────────────┬───────────────┬────────────────┤
│ Threat             │ Likelihood    │ Mitigation     │
├────────────────────┼───────────────┼────────────────┤
│ Brute-force scan   │ HIGH          │ CrowdSec + UFW │
│ MAC1 exhaustion    │ MEDIUM        │ CrowdSec WG    │
│                    │               │ scenario       │
│ SSH brute-force    │ HIGH          │ Non-std port + │
│                    │               │ key-only auth  │
│ Packet spoofing    │ MEDIUM        │ rp_filter=1    │
│ ICMP redirect MitM │ LOW           │ ICMP disabled  │
│ SYN flood          │ MEDIUM        │ tcp_syncookies │
│ Credential leak    │ MEDIUM        │ Bandit/Trivy   │
│                    │               │ SAST in CI     │
└────────────────────┴───────────────┴────────────────┘
```

---

*Last reviewed: 2026-03-09 | Maintainer: shanmkuu*
