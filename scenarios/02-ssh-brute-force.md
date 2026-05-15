# Scenario 02 — SSH Brute Force Attack & Rate Limiting

## Overview

| | |
|---|---|
| **Attack** | SSH credential brute force |
| **Tool used (attacker)** | Hydra |
| **Attacker machine** | Kali Linux — 192.168.56.101 |
| **Target machine** | Ubuntu — 192.168.56.100 |
| **Rule type** | iptables rate limiting (recent module) |
| **Result** | ✅ Brute force throttled to 3 attempts/min — attack infeasible |

---

## What is SSH brute force?

Automated tools like Hydra try thousands of username/password combinations against SSH in rapid succession. A typical attack tries 100–500 passwords per second. Without rate limiting, a weak password can be cracked in minutes. SSH is the most commonly attacked port on any internet-facing server.

---

## Step 1 — Attack BEFORE rate limiting (Kali VM2)

```bash
# First install a small wordlist if not present
ls /usr/share/wordlists/
gunzip /usr/share/wordlists/rockyou.txt.gz

# Launch Hydra SSH brute force
hydra -l ubuntu -P /usr/share/wordlists/rockyou.txt \
  192.168.56.100 ssh -t 4 -V
```

**Expected output (before rule):**
```
[DATA] attacking ssh://192.168.56.100:22/
[ATTEMPT] target 192.168.56.100 - login "ubuntu" - pass "123456"
[ATTEMPT] target 192.168.56.100 - login "ubuntu" - pass "password"
[ATTEMPT] target 192.168.56.100 - login "ubuntu" - pass "12345678"
...
(hundreds of attempts per minute succeed in connecting)
```

---

## Step 2 — Apply rate limiting rule (Ubuntu VM1)

```bash
# Track new SSH connections per source IP
sudo iptables -A INPUT -p tcp --dport 22 \
  -m conntrack --ctstate NEW \
  -m recent --set --name SSH_RATE

# If more than 3 new connections in 60 seconds — log it
sudo iptables -A INPUT -p tcp --dport 22 \
  -m conntrack --ctstate NEW \
  -m recent --update --seconds 60 --hitcount 4 \
  --name SSH_RATE \
  -j LOG --log-prefix "IPT-SSH-BRUTE: " --log-level 4

# Then drop the excess connection attempts
sudo iptables -A INPUT -p tcp --dport 22 \
  -m conntrack --ctstate NEW \
  -m recent --update --seconds 60 --hitcount 4 \
  --name SSH_RATE -j DROP

# Allow the first 3 connections per minute (legitimate users)
sudo iptables -A INPUT -p tcp --dport 22 \
  -m conntrack --ctstate NEW -j ACCEPT
```

---

## Step 3 — Attack AFTER rate limiting (Kali VM2)

```bash
# Same Hydra command
hydra -l ubuntu -P /usr/share/wordlists/rockyou.txt \
  192.168.56.100 ssh -t 4 -V
```

**Expected output (after rule):**
```
[ATTEMPT] target 192.168.56.100 - login "ubuntu" - pass "123456"   [SUCCESS? NO]
[ATTEMPT] target 192.168.56.100 - login "ubuntu" - pass "password"  [SUCCESS? NO]
[ATTEMPT] target 192.168.56.100 - login "ubuntu" - pass "12345678"  [SUCCESS? NO]
[ERROR] could not connect to ssh://192.168.56.100:22 - Connection refused
[ERROR] could not connect to ssh://192.168.56.100:22 - Connection refused
(all subsequent attempts timed out / refused)
```

---

## Step 4 — View detection in logs (Ubuntu VM1)

```bash
sudo grep "IPT-SSH-BRUTE" /var/log/syslog
```

**Sample log:**
```
May 10 14:45:12 ubuntu kernel: IPT-SSH-BRUTE: IN=enp0s8 
  SRC=192.168.56.101 DST=192.168.56.100 PROTO=TCP DPT=22
```

---

## Analysis

**Why 3 per minute?**
A legitimate user who mistyped their password would rarely need more than 3 SSH connection attempts in a minute. An automated tool needs thousands. The threshold is set to protect against automation while not impacting real users.

**Math:** At 3 attempts/minute, a 10,000 word wordlist would take 3,333 minutes (~55 hours). A real dictionary like rockyou.txt has 14 million entries — that's 4.4 million minutes (8 years) at this rate. The attack is effectively defeated.

**Additional hardening to mention in your report:**
- Disable SSH password auth entirely — use SSH keys only
- Change SSH port from 22 to a high port (security through obscurity, limited value)
- Use `fail2ban` alongside iptables for automatic IP banning

---

## Screenshot checklist
- [ ] Hydra running BEFORE rule — showing rapid attempts
- [ ] Hydra output AFTER rule — showing connection errors/timeouts
- [ ] `iptables -L -v -n` showing packet count increasing on the rate-limit rule
- [ ] syslog showing IPT-SSH-BRUTE entries with attacker IP
