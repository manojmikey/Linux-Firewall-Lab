# Linux-Firewall-Lab
Linux firewall security lab with UFW &amp; iptables defending against real-world attacks from Kali Linux.

#  Linux Firewall Security Lab

> **A hands-on network security lab simulating real-world attack scenarios and defending against them using UFW and iptables on Ubuntu — tested with a live Kali Linux attacker machine.**

---

##  Project Overview

This project demonstrates practical firewall configuration and network traffic filtering using two virtual machines:

| Machine | OS | Role |
|---|---|---|
| VM1 | Ubuntu 22.04 LTS | Target / Server (firewall applied here) |
| VM2 | Kali Linux | Attacker (used to test and simulate attacks) |

Both VMs are connected on a **Host-Only network** to simulate a real isolated network environment.

---

##  Objectives

- Configure a layered firewall using **UFW** (beginner layer) and **iptables** (advanced layer)
- Filter TCP/IP traffic by port, protocol, IP address, and connection state
- Simulate **6 real-world attack scenarios** from the Kali attacker machine
- Verify each firewall rule actually **blocks the intended attack** with evidence
- Log all dropped packets for monitoring and audit trail

---

##  Tools & Technologies

| Tool | Purpose |
|---|---|
| UFW | User-friendly firewall frontend |
| iptables | Low-level Linux packet filtering |
| nmap | Port scanning (attacker) |
| Hydra | SSH brute force simulation (attacker) |
| hping3 | SYN flood simulation (attacker) |
| Wireshark | Packet capture and analysis |
| netcat (nc) | Port connectivity testing |
| iptables-persistent | Save rules across reboots |

---

##  Repository Structure

```
linux-firewall-lab/
│
├── README.md                        ← You are here
│
├── rules/
│   ├── ufw-rules.md                 ← UFW rules with explanations
│   └── iptables-rules.sh            ← Full iptables script (documented)
│
├── scenarios/
│   ├── 01-port-scan-block.md        ← Scenario 1: Block nmap port scan
│   ├── 02-ssh-brute-force.md        ← Scenario 2: Block Hydra brute force
│   ├── 03-syn-flood-defense.md      ← Scenario 3: Defend against SYN flood
│   ├── 04-ip-blacklist.md           ← Scenario 4: Blacklist attacker IP
│   ├── 05-icmp-control.md           ← Scenario 5: Control ping/ICMP
│   └── 06-protocol-filtering.md     ← Scenario 6: TCP/UDP protocol filtering
│
├── logs/
│   └── sample-dropped-packets.log   ← Real iptables LOG output
│
├── screenshots/
│   └── (evidence screenshots go here)
│
└── report.md                        ← Final findings and summary report
```

---

##  Lab Setup

### Network Topology

```
┌─────────────────────┐         Host-Only Network          ┌─────────────────────┐
│   Ubuntu VM1        │◄──────── 192.168.56.0/24 ─────────►│   Kali Linux VM2    │
│   (Server/Target)   │         192.168.56.101              │   (Attacker)        │
│   192.168.56.100    │                                     │   192.168.56.101    │
│   [iptables active] │                                     │   [nmap/hydra/hping]│
└─────────────────────┘                                     └─────────────────────┘
```

### Step 1 — Install VirtualBox & create VMs
```bash
# Download VirtualBox: https://www.virtualbox.org/
# Ubuntu ISO:  https://ubuntu.com/download/server
# Kali ISO:    https://www.kali.org/get-kali/

# Set both VMs to: Settings → Network → Adapter 1 → Host-Only Adapter
```

### Step 2 — Find VM IP addresses
```bash
# On each VM run:
ip addr show
# Note the 192.168.56.x address for each
```

### Step 3 — Install required tools on Ubuntu (VM1)
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install ufw iptables iptables-persistent net-tools -y
```

### Step 4 — Install attack tools on Kali (VM2)
```bash
# Kali has most tools pre-installed. Verify:
nmap --version
hydra --version
hping3 --version
```

---

##  Quick Start — Run the Full Firewall

```bash
# Clone this repo on your Ubuntu VM
git clone https://github.com/YOUR_USERNAME/linux-firewall-lab.git
cd linux-firewall-lab

# Make the iptables script executable and run it
chmod +x rules/iptables-rules.sh
sudo bash rules/iptables-rules.sh

# Verify rules are loaded
sudo iptables -L -v -n --line-numbers
```

---

##  Attack Scenarios Tested

| # | Attack | Tool Used | Rule Applied | Result |
|---|--------|-----------|--------------|--------|
| 1 | Port Scan | nmap | recent module drop | ✅ Scan blocked |
| 2 | SSH Brute Force | Hydra | rate limit 3/min | ✅ Attack failed |
| 3 | SYN Flood (DoS) | hping3 | SYN cookie + limit | ✅ Server survived |
| 4 | IP Blacklist | nc / nmap | source IP drop | ✅ All traffic blocked |
| 5 | ICMP Flood (ping) | ping -f | ICMP rate limit | ✅ Flood stopped |
| 6 | Protocol Abuse | hping3 raw | protocol whitelist | ✅ Invalid packets dropped |

> Full writeups with commands, evidence and analysis for each scenario in the `/scenarios` folder.

---

##  What I Learned

- How Linux processes packets through **INPUT, OUTPUT, FORWARD chains**
- Difference between **stateful** (`conntrack`) and **stateless** packet filtering
- How **rate limiting** prevents brute force and DoS without blocking legitimate users
- Why **logging dropped packets** is critical for incident detection
- How UFW is simply a **wrapper that writes iptables rules** under the hood
- Real attacker methodology using Kali — and how each attack looks in packet logs

---

##  License

MIT License — free to use for learning and portfolio purposes.

---

*Built as part of a hands-on network security portfolio. Environment: Ubuntu 22.04 + Kali Linux on VirtualBox.*
