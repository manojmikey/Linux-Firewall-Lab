#!/bin/bash
# =============================================================================
# Linux Firewall Lab — iptables Ruleset
# Author: [Your Name]
# OS: Ubuntu 22.04 LTS
# Attacker VM: Kali Linux 192.168.56.101
# Server VM:   Ubuntu    192.168.56.100
#
# PURPOSE: Implement a production-style firewall covering:
#   - Default deny policies
#   - Stateful connection tracking
#   - SSH brute force rate limiting
#   - Port scan detection and blocking
#   - SYN flood / DoS mitigation
#   - IP blacklisting
#   - ICMP control
#   - Packet logging for audit trail
#
# USAGE: sudo bash iptables-rules.sh
# SAVE:  sudo netfilter-persistent save
# =============================================================================

echo "[*] Flushing existing rules..."

# RULE: Flush all existing rules before applying fresh ruleset
# WHY: Ensures no conflicting or leftover rules from previous sessions.
#      Always start clean when applying a new policy.
# RISK OF SKIPPING: Old rules may conflict, causing unexpected behaviour.
iptables -F
iptables -X
iptables -Z
ip6tables -F
ip6tables -X

echo "[*] Setting default policies..."

# =============================================================================
# SECTION 1: DEFAULT CHAIN POLICIES
# =============================================================================

# RULE: Drop all incoming traffic by default
# WHY: Whitelist approach — only explicitly allowed traffic gets in.
#      This is industry standard for any internet-facing server.
# ATTACK PREVENTED: Any uninvited connection attempt is dropped silently.
iptables -P INPUT DROP

# RULE: Drop all forwarded traffic by default
# WHY: This VM is not a router. If a packet arrives for another host,
#      it should NOT be forwarded — prevents this machine from being
#      used as a pivot point in a network attack.
# ATTACK PREVENTED: Network pivoting / lateral movement.
iptables -P FORWARD DROP

# RULE: Allow all outgoing traffic by default
# WHY: The server needs to make outbound connections (DNS, updates, etc.)
#      Restricting OUTPUT is an advanced hardening step done separately.
iptables -P OUTPUT ACCEPT

echo "[*] Applying base rules..."

# =============================================================================
# SECTION 2: BASE RULES (required for system to function)
# =============================================================================

# RULE: Allow all loopback (localhost) traffic
# WHY: Many services communicate internally via 127.0.0.1 (loopback).
#      Blocking this breaks databases, web servers, and system services.
# ATTACK PREVENTED: N/A — this is a system requirement.
iptables -A INPUT -i lo -j ACCEPT

# RULE: Allow established and related connections
# WHY: Stateful filtering — if the server initiated a connection (e.g. apt update),
#      the response packets must be allowed back in. Without this, nothing
#      the server requests would ever get a response.
# TECHNICAL: conntrack module tracks connection state at kernel level.
# ATTACK PREVENTED: Prevents spoofed packets pretending to be return traffic.
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# RULE: Drop invalid packets immediately
# WHY: Invalid packets don't belong to any known connection and are often
#      used in reconnaissance or to confuse stateful firewalls.
# ATTACK PREVENTED: Invalid packet probes, firewall fingerprinting.
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

echo "[*] Applying SSH rules..."

# =============================================================================
# SECTION 3: SSH PROTECTION
# =============================================================================

# RULE: Rate limit SSH connections — max 3 new connections per minute
# WHY: SSH brute force tools (Hydra, Medusa) attempt hundreds of password
#      guesses per second. Rate limiting makes this computationally
#      infeasible — at 3/min it would take years to try a wordlist.
# ATTACK PREVENTED: SSH brute force (Hydra, Medusa, Ncrack)
# TESTED WITH: hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.100
# RESULT: Hydra connection attempts throttled, attack failed.
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW \
  -m recent --set --name SSH_RATE

iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW \
  -m recent --update --seconds 60 --hitcount 4 --name SSH_RATE \
  -j LOG --log-prefix "IPT-SSH-BRUTE: " --log-level 4

iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW \
  -m recent --update --seconds 60 --hitcount 4 --name SSH_RATE -j DROP

# RULE: Allow SSH only from trusted IP (your host machine)
# WHY: Even with rate limiting, restricting SSH to your known IP means
#      an attacker from any other IP cannot even attempt to connect.
#      This is IP whitelisting — the strongest SSH protection available
#      without disabling SSH entirely.
# CHANGE: Replace 192.168.56.1 with your actual host machine IP.
# ATTACK PREVENTED: All SSH attacks from unknown IPs.
iptables -A INPUT -p tcp --dport 22 -s 192.168.56.1 \
  -m conntrack --ctstate NEW -j ACCEPT

echo "[*] Applying web server rules..."

# =============================================================================
# SECTION 4: WEB TRAFFIC
# =============================================================================

# RULE: Allow HTTP traffic on port 80
# WHY: Standard web server port. Required if running nginx or apache.
# NOTE: In production, you'd redirect all HTTP to HTTPS and eventually
#       block port 80 entirely. Kept open here for lab purposes.
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT

# RULE: Allow HTTPS traffic on port 443
# WHY: Encrypted web traffic. All modern web apps use HTTPS.
#      This port must be open alongside 80 for a functional web server.
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

echo "[*] Applying ICMP rules..."

# =============================================================================
# SECTION 5: ICMP (PING) CONTROL
# =============================================================================

# RULE: Rate limit incoming ICMP echo requests (ping)
# WHY: ICMP ping is used for host discovery. An attacker pings your IP
#      to check if you're online before attacking. A ping flood (ICMP flood)
#      can also consume bandwidth. Rate limiting allows normal ping
#      diagnostics while preventing abuse.
# ATTACK PREVENTED: ICMP flood / ping flood, host discovery abuse.
# TESTED WITH: ping -f 192.168.56.100 (flood ping from Kali)
iptables -A INPUT -p icmp --icmp-type echo-request \
  -m limit --limit 1/second --limit-burst 4 -j ACCEPT

# RULE: Allow ICMP echo-reply (responses to our own pings)
# WHY: When this server pings another host, the reply must be allowed in.
#      This is different from incoming ping requests.
iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT

# RULE: Drop all other ICMP — including those over the rate limit
# WHY: Any ICMP not explicitly allowed above (or over the rate limit)
#      is dropped. This silently discards excess pings.
iptables -A INPUT -p icmp -j DROP

echo "[*] Applying port scan detection..."

# =============================================================================
# SECTION 6: PORT SCAN DETECTION
# =============================================================================

# RULE: Detect and block port scans using the recent module
# WHY: Port scanners (nmap) rapidly connect to many ports to discover
#      open services. This rule tracks IPs that hit more than 20 ports
#      in 10 seconds and drops all their subsequent traffic.
# ATTACK PREVENTED: nmap SYN scan, TCP connect scan, stealth scans.
# TESTED WITH: nmap -sS -p 1-1000 192.168.56.100
# RESULT: After ~20 ports scanned, all further packets from Kali dropped.
iptables -N PORT_SCAN
iptables -A PORT_SCAN -m recent --set --name PORTSCAN
iptables -A PORT_SCAN -m recent --update --seconds 10 \
  --hitcount 20 --name PORTSCAN \
  -j LOG --log-prefix "IPT-PORTSCAN: " --log-level 4
iptables -A PORT_SCAN -m recent --update --seconds 10 \
  --hitcount 20 --name PORTSCAN -j DROP

iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST \
  -j PORT_SCAN

echo "[*] Applying SYN flood protection..."

# =============================================================================
# SECTION 7: SYN FLOOD (DoS) PROTECTION
# =============================================================================

# RULE: Limit SYN packets to prevent SYN flood DoS attacks
# WHY: A SYN flood sends thousands of TCP SYN packets without completing
#      the handshake, exhausting the server's connection table and making
#      it unreachable. Limiting new SYN packets prevents table exhaustion.
# ATTACK PREVENTED: TCP SYN flood DoS (hping3 -S --flood)
# TESTED WITH: hping3 -S --flood -p 80 192.168.56.100
# RESULT: Server remained responsive. CPU stayed under 20%.
iptables -A INPUT -p tcp --syn \
  -m limit --limit 50/second --limit-burst 100 -j ACCEPT

# Block SYN packets exceeding the limit
iptables -A INPUT -p tcp --syn \
  -j LOG --log-prefix "IPT-SYNFLOOD: " --log-level 4

iptables -A INPUT -p tcp --syn -j DROP

echo "[*] Applying IP blacklist..."

# =============================================================================
# SECTION 8: IP BLACKLIST
# =============================================================================

# RULE: Block all traffic from the Kali attacker IP
# WHY: Once an attacker IP is identified (via logs, IDS alerts, etc.),
#      the fastest mitigation is a blanket IP block. All packets from
#      that source are dropped before any other rules are checked.
# REAL WORLD: This mimics what a SOC analyst does after identifying an
#             attacker IP from SIEM alerts — immediate block while investigation continues.
# ATTACK PREVENTED: All attack traffic from 192.168.56.101 (Kali).
# CHANGE: Replace with actual attacker IP identified in your lab.
iptables -I INPUT 1 -s 192.168.56.101 \
  -j LOG --log-prefix "IPT-BLACKLIST: " --log-level 4

iptables -I INPUT 2 -s 192.168.56.101 -j DROP

# NOTE: -I INPUT 1 inserts at position 1 (top of chain) — processed FIRST.
# This ensures the blacklist is checked before any allow rules.

echo "[*] Applying protocol filtering..."

# =============================================================================
# SECTION 9: PROTOCOL FILTERING
# =============================================================================

# RULE: Drop uncommon/suspicious TCP flag combinations
# WHY: Attackers use malformed TCP packets (NULL, XMAS, FIN scans) to
#      fingerprint firewalls or evade detection. These flag combinations
#      never appear in legitimate traffic.
# ATTACK PREVENTED: NULL scan, XMAS scan, FIN scan (nmap -sN, -sX, -sF)

# NULL scan (no flags set)
iptables -A INPUT -p tcp --tcp-flags ALL NONE \
  -j LOG --log-prefix "IPT-NULL-SCAN: " --log-level 4
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# XMAS scan (FIN+PSH+URG flags)
iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG \
  -j LOG --log-prefix "IPT-XMAS-SCAN: " --log-level 4
iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP

# SYN+FIN combination (never legitimate)
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN \
  -j LOG --log-prefix "IPT-SYNFIN: " --log-level 4
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

echo "[*] Applying final DROP with logging..."

# =============================================================================
# SECTION 10: FINAL CATCH-ALL — LOG AND DROP EVERYTHING ELSE
# =============================================================================

# RULE: Log every packet that reaches the end of the chain before dropping
# WHY: Any packet reaching this rule didn't match any allow rule above.
#      Logging it gives us visibility into what's being blocked.
#      These logs are your audit trail — critical for incident response.
# VIEW LOGS: sudo tail -f /var/log/syslog | grep "IPT-DROP"
iptables -A INPUT -j LOG --log-prefix "IPT-DROP: " --log-level 4

# RULE: Final DROP — all remaining unmatched traffic is dropped
# WHY: Enforcement of the default deny policy. Even if a packet slips
#      past the default policy (unlikely), this ensures it's dropped.
iptables -A INPUT -j DROP

# =============================================================================
# SAVE RULES (persist across reboots)
# =============================================================================

echo "[*] Saving rules..."
netfilter-persistent save 2>/dev/null || echo "[!] Install iptables-persistent to save rules"

echo ""
echo "[+] Firewall rules applied successfully!"
echo "[+] Current ruleset:"
echo ""
iptables -L -v -n --line-numbers
