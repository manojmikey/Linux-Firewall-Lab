# Scenario 01 — Port Scan Detection & Blocking

## Overview

| | |
|---|---|
| **Attack** | TCP SYN Port Scan |
| **Tool used (attacker)** | nmap |
| **Attacker machine** | Kali Linux — 192.168.56.101 |
| **Target machine** | Ubuntu — 192.168.56.100 |
| **Rule type** | iptables recent module |
| **Result** | ✅ Scan detected and blocked after 20 ports |

---

## What is a port scan?

A port scan probes a target machine across multiple ports to discover which services are running. It's the first step in almost every attack — attackers need to know what's open before they can exploit it. nmap is the most widely used port scanner in both ethical hacking and real attacks.

---

## Step 1 — Scan BEFORE firewall rule (Kali VM2)

```bash
# Run from Kali — full SYN scan on first 1000 ports
nmap -sS -p 1-1000 192.168.56.100 -v
```

**Expected output (before rule):**
```
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
997 ports filtered
```
The scan completes and reveals open ports. Attacker now knows exactly what services to target.

---

## Step 2 — Apply the detection rule (Ubuntu VM1)

```bash
# Create a custom chain for port scan logic
sudo iptables -N PORT_SCAN

# Track IPs hitting multiple ports
sudo iptables -A PORT_SCAN -m recent --set --name PORTSCAN

# If same IP hits 20+ ports in 10 seconds — log it
sudo iptables -A PORT_SCAN -m recent --update --seconds 10 \
  --hitcount 20 --name PORTSCAN \
  -j LOG --log-prefix "IPT-PORTSCAN: " --log-level 4

# Then drop all their traffic
sudo iptables -A PORT_SCAN -m recent --update --seconds 10 \
  --hitcount 20 --name PORTSCAN -j DROP

# Send RST packets to the PORT_SCAN chain for analysis
sudo iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST \
  -j PORT_SCAN
```

---

## Step 3 — Scan AFTER firewall rule (Kali VM2)

```bash
# Same scan, same target
nmap -sS -p 1-1000 192.168.56.100 -v
```

**Expected output (after rule):**
```
Note: Host seems down. If it is really up, but blocking our probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned
```
The scan fails to complete. After hitting ~20 ports, the attacker IP is flagged and all further packets are dropped — the server appears offline.

---

## Step 4 — View the detection in logs (Ubuntu VM1)

```bash
sudo grep "IPT-PORTSCAN" /var/log/syslog | tail -20
```

**Sample log output:**
```
May 10 14:23:01 ubuntu kernel: IPT-PORTSCAN: IN=enp0s8 OUT= 
  MAC=... SRC=192.168.56.101 DST=192.168.56.100 
  PROTO=TCP SPT=54231 DPT=445 WINDOW=1024 SYN
```

---

## Analysis

**Why does this work?**
The `recent` module maintains a list of source IPs and timestamps of recent packets. When an IP exceeds the threshold (20 unique port hits in 10 seconds), it crosses from "normal user" behaviour into "scanner" behaviour — and gets blocked.

**Limitation:** A slow scan (`nmap --scan-delay 1s`) stays under the threshold. Real-world IDS systems use more sophisticated detection. This rule handles aggressive/automated scans effectively.

**What an attacker sees:** The target appears to go offline. They have no idea if it's a firewall or the host is actually down — which is exactly what you want.

---

## Screenshot checklist
- [ ] nmap output BEFORE rule (showing open ports)
- [ ] nmap output AFTER rule (showing host down / filtered)
- [ ] `sudo iptables -L PORT_SCAN -v -n` showing rule hit count
- [ ] `/var/log/syslog` showing IPT-PORTSCAN entries
