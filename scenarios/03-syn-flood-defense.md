# Scenario 03 — SYN Flood (DoS) Attack & Defense

## Overview

| | |
|---|---|
| **Attack** | TCP SYN Flood (Denial of Service) |
| **Tool used (attacker)** | hping3 |
| **Attacker machine** | Kali Linux — 192.168.56.101 |
| **Target machine** | Ubuntu — 192.168.56.100 |
| **Rule type** | iptables SYN rate limiting + SYN cookies |
| **Result** | ✅ Server stayed responsive under flood |

---

## What is a SYN flood?

TCP connections begin with a 3-way handshake: SYN → SYN-ACK → ACK. A SYN flood sends thousands of SYN packets without ever completing the handshake, filling the server's connection table (backlog) with half-open connections. When the table fills up, the server can't accept new legitimate connections — it becomes unreachable. This is a classic Denial of Service (DoS) attack.

---

## Step 1 — Verify server is reachable BEFORE flood (Kali VM2)

```bash
# Confirm SSH works normally
ssh ubuntu@192.168.56.100

# Confirm web server responds
curl -I http://192.168.56.100
# Expected: HTTP/1.1 200 OK
```

---

## Step 2 — Enable SYN cookies on Ubuntu (VM1) — OS-level protection

```bash
# SYN cookies prevent connection table exhaustion
# When enabled, the server doesn't allocate resources until handshake completes
sudo sysctl -w net.ipv4.tcp_syncookies=1

# Also increase backlog queue size
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=2048

# Make permanent
echo "net.ipv4.tcp_syncookies = 1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 2048" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

---

## Step 3 — Apply iptables SYN rate limiting (Ubuntu VM1)

```bash
# Allow SYN packets up to 50 per second with burst of 100
# Legitimate web traffic rarely exceeds this. A flood sends thousands/sec.
sudo iptables -A INPUT -p tcp --syn \
  -m limit --limit 50/second --limit-burst 100 -j ACCEPT

# Log SYN packets exceeding the limit
sudo iptables -A INPUT -p tcp --syn \
  -j LOG --log-prefix "IPT-SYNFLOOD: " --log-level 4

# Drop excess SYN packets
sudo iptables -A INPUT -p tcp --syn -j DROP
```

---

## Step 4 — Launch SYN flood from Kali (VM2)

```bash
# WARNING: Only run this against your OWN lab VM — never on public networks

# SYN flood on port 80 with random source IPs
sudo hping3 -S --flood -V -p 80 192.168.56.100

# On a second terminal — watch if server is still reachable
ping 192.168.56.100
curl -I http://192.168.56.100
```

**Without protection:** Server becomes unreachable within seconds. Ping times out.

**With protection (after rules above):**
```
# ping still responds
64 bytes from 192.168.56.100: icmp_seq=1 ttl=64 time=1.2 ms
64 bytes from 192.168.56.100: icmp_seq=2 ttl=64 time=1.4 ms

# curl still works
HTTP/1.1 200 OK
```

---

## Step 5 — Monitor on Ubuntu (VM1)

```bash
# Watch SYN flood log entries appearing
sudo tail -f /var/log/syslog | grep "IPT-SYNFLOOD"

# Watch connection table
watch -n1 'ss -ant | grep SYN_RECV | wc -l'

# Monitor CPU/memory during flood
htop
```

---

## Analysis

**Two-layer defense used here:**

1. **SYN cookies (kernel level):** The server doesn't allocate memory for a connection until the 3-way handshake completes. Spoofed SYN packets (which never complete the handshake) consume no resources.

2. **iptables rate limiting (network level):** SYN packets above 50/sec are dropped at the firewall before they even reach the TCP stack. This reduces load on the kernel.

**Together:** The flood packets are dropped at the firewall, and any that slip through don't exhaust the connection table because SYN cookies are enabled.

**Real world:** Cloud providers (AWS, Cloudflare) handle SYN floods at the network edge before traffic reaches your server. This lab demonstrates the same principle at the host level.

---

## Screenshot checklist
- [ ] `curl` response DURING flood — showing server is still up
- [ ] `ss -ant | grep SYN_RECV` showing SYN_RECV count staying low
- [ ] syslog showing IPT-SYNFLOOD entries
- [ ] `iptables -L -v -n` showing packet counts on the limit rule
- [ ] `htop` showing CPU not spiking to 100%
