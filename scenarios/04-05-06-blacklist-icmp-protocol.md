# Scenario 04 — IP Blacklisting

## Overview

| | |
|---|---|
| **Attack** | All traffic from attacker IP |
| **Tool used (attacker)** | nmap, nc, ping |
| **Attacker machine** | Kali Linux — 192.168.56.101 |
| **Rule type** | iptables source IP drop (inserted at top of chain) |
| **Result** | ✅ All traffic from attacker IP silently dropped |

---

## What is IP blacklisting?

After identifying an attacker IP (via logs, alerts, or manual review), the fastest mitigation is a complete block — drop every packet from that source before any other rule is checked. This mirrors real SOC workflow: analyst sees malicious IP in SIEM → adds it to blocklist → investigation continues.

---

## Apply the blacklist (Ubuntu VM1)

```bash
# -I INPUT 1 = INSERT at position 1 (top of chain — processed first)
# This means the blacklist check happens BEFORE any allow rules

# Log the traffic first (evidence collection)
sudo iptables -I INPUT 1 -s 192.168.56.101 \
  -j LOG --log-prefix "IPT-BLACKLIST: " --log-level 4

# Then drop everything from that IP
sudo iptables -I INPUT 2 -s 192.168.56.101 -j DROP
```

---

## Test from Kali (VM2)

```bash
# All of these should fail after the blacklist rule
ping 192.168.56.100           # should timeout
nmap -p 22 192.168.56.100     # should show filtered
nc -zv 192.168.56.100 80      # should timeout
ssh ubuntu@192.168.56.100     # should timeout
```

**Expected result:** All tools timeout or fail. The server appears completely offline from the attacker's perspective.

---

## View in logs (Ubuntu VM1)

```bash
sudo grep "IPT-BLACKLIST" /var/log/syslog
```

```
May 10 15:02:44 ubuntu kernel: IPT-BLACKLIST: IN=enp0s8 
  SRC=192.168.56.101 DST=192.168.56.100 PROTO=TCP DPT=22
May 10 15:02:44 ubuntu kernel: IPT-BLACKLIST: IN=enp0s8 
  SRC=192.168.56.101 DST=192.168.56.100 PROTO=ICMP
```

## Remove the blacklist (when done testing)

```bash
# List rules with line numbers
sudo iptables -L INPUT -n --line-numbers

# Delete by line number (blacklist rules are lines 1 and 2)
sudo iptables -D INPUT 1
sudo iptables -D INPUT 1
```

---
---

# Scenario 05 — ICMP (Ping) Control

## Overview

| | |
|---|---|
| **Attack** | ICMP flood (ping flood) |
| **Tool used (attacker)** | ping -f (flood ping) |
| **Attacker machine** | Kali Linux — 192.168.56.101 |
| **Rule type** | iptables ICMP rate limit |
| **Result** | ✅ Flood blocked, legitimate ping still works |

---

## Why control ICMP?

ICMP ping is used by attackers to: (1) discover if a host is online, (2) map networks, (3) launch ICMP floods. Blocking ping entirely breaks legitimate network diagnostics. Rate limiting is the right balance.

---

## Apply ICMP rules (Ubuntu VM1)

```bash
# Allow 1 ping per second with burst of 4
# This handles normal diagnostics (ping -c 4) without issue
sudo iptables -A INPUT -p icmp --icmp-type echo-request \
  -m limit --limit 1/second --limit-burst 4 -j ACCEPT

# Log pings that exceed the rate limit
sudo iptables -A INPUT -p icmp \
  -j LOG --log-prefix "IPT-ICMP-DROP: " --log-level 4

# Drop all excess ICMP
sudo iptables -A INPUT -p icmp -j DROP
```

---

## Test from Kali (VM2)

```bash
# Normal ping — should work (under limit)
ping -c 4 192.168.56.100
# Expected: 4 replies received

# Flood ping — should fail (over limit)
sudo ping -f 192.168.56.100
# Expected: most packets lost, high % packet loss shown
```

---

## View in logs (Ubuntu VM1)

```bash
sudo grep "IPT-ICMP-DROP" /var/log/syslog | head -5
```

---
---

# Scenario 06 — Malformed Packet / Protocol Filtering

## Overview

| | |
|---|---|
| **Attack** | NULL scan, XMAS scan, SYN+FIN packets |
| **Tool used (attacker)** | nmap -sN, nmap -sX, hping3 |
| **Attacker machine** | Kali Linux — 192.168.56.101 |
| **Rule type** | iptables TCP flag inspection |
| **Result** | ✅ All malformed packets detected and dropped |

---

## What are malformed packets?

Certain TCP flag combinations never appear in legitimate traffic. Attackers use them to:
- Bypass stateless firewalls (which only check ports, not flags)
- Fingerprint firewalls (different firewalls respond differently to invalid flags)
- Evade IDS systems trained on normal traffic patterns

---

## Apply protocol filtering rules (Ubuntu VM1)

```bash
# NULL scan — no flags set (nmap -sN)
# Real TCP packets always have at least one flag
sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE \
  -j LOG --log-prefix "IPT-NULL-SCAN: " --log-level 4
sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# XMAS scan — FIN, PSH, URG all set (nmap -sX)
# Named "XMAS" because all bits are lit up like a Christmas tree
sudo iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG \
  -j LOG --log-prefix "IPT-XMAS-SCAN: " --log-level 4
sudo iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP

# SYN+FIN — impossible combination in real traffic
# SYN initiates connection, FIN closes it — can't happen simultaneously
sudo iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN \
  -j LOG --log-prefix "IPT-SYNFIN: " --log-level 4
sudo iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

# FIN scan — only FIN flag (nmap -sF)
# No legitimate session starts with a FIN packet
sudo iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN \
  -j LOG --log-prefix "IPT-FIN-SCAN: " --log-level 4
sudo iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP
```

---

## Test from Kali (VM2)

```bash
# NULL scan
nmap -sN 192.168.56.100 -p 1-100 -v
# Expected: all ports shown as open|filtered (dropped silently)

# XMAS scan  
nmap -sX 192.168.56.100 -p 1-100 -v
# Expected: all ports open|filtered

# FIN scan
nmap -sF 192.168.56.100 -p 1-100 -v
# Expected: all ports open|filtered
```

---

## View in logs (Ubuntu VM1)

```bash
sudo grep -E "IPT-NULL|IPT-XMAS|IPT-SYNFIN|IPT-FIN" /var/log/syslog
```

**Sample output:**
```
May 10 15:20:11 ubuntu kernel: IPT-XMAS-SCAN: IN=enp0s8 
  SRC=192.168.56.101 DST=192.168.56.100 PROTO=TCP 
  DPT=22 WINDOW=1024 URG PSH FIN
```

---

## Key learning

Unlike a stateful firewall (which tracks connections), these rules perform **deep packet inspection** — looking inside the TCP header at individual flag bits. This is what next-generation firewalls (NGFWs) do at scale. You're implementing the same logic manually here.

---

## Screenshot checklist (all 3 scenarios)
- [ ] nmap output showing NULL, XMAS, FIN scans all returning open|filtered
- [ ] syslog entries for each scan type
- [ ] `iptables -L -v -n` showing packet/byte counts on each rule
