# UFW Firewall Rules

> UFW (Uncomplicated Firewall) is a frontend for iptables. Every rule here translates to an iptables rule under the hood. We start here because it builds intuition before moving to raw iptables.

---

## Why UFW first?

UFW uses plain English syntax. Running `sudo ufw status verbose` after each rule shows exactly what's being applied. Once comfortable here, the same logic in iptables becomes much clearer.

---

## Setup — Default Policies

```bash
# Step 1: Set default — deny all incoming, allow all outgoing
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

**Why deny incoming by default?**
This is the "whitelist" approach — nothing gets in unless you explicitly allow it. This is how production servers are configured. The opposite (allow by default) is dangerous because you have to remember to block everything bad — impossible in practice.

**Why allow outgoing by default?**
The server needs to reach the internet for updates, DNS lookups, etc. Restricting outgoing is done in advanced hardening — not needed at this stage.

---

## Allow Rules

```bash
# Allow SSH — remote management
sudo ufw allow 22/tcp
```
**Why:** SSH is how you manage a Linux server remotely. Without this rule, you'd be locked out of your own VM after enabling the firewall.
**Attack context:** SSH is also the most commonly attacked port on the internet — brute forced constantly by bots. We allow it here but rate-limit it in iptables.

---

```bash
# Allow HTTP — web server traffic
sudo ufw allow 80/tcp
```
**Why:** If this VM runs a web server (nginx/apache), port 80 must be open for users to access it over HTTP.

---

```bash
# Allow HTTPS — encrypted web traffic
sudo ufw allow 443/tcp
```
**Why:** HTTPS (TLS encrypted HTTP) is the standard for all modern web traffic. Port 443 is required alongside 80.

---

```bash
# Allow traffic only from a specific trusted IP (e.g. your host machine)
sudo ufw allow from 192.168.56.1 to any port 22
```
**Why:** This restricts SSH to only your host machine IP. Even if an attacker finds port 22 open, they can't connect unless they're coming from your specific IP. This is called IP whitelisting — a critical hardening step.

---

## Enable and Verify

```bash
sudo ufw enable
sudo ufw status verbose
```

**Expected output:**
```
Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    192.168.56.1
80/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
```

---

## Test from Kali (VM2)

```bash
# Test blocked port — should timeout or show filtered
nc -zv 192.168.56.100 8080
nmap -p 8080 192.168.56.100

# Test allowed port — should connect
nc -zv 192.168.56.100 80

# Test SSH from non-whitelisted IP — should be blocked
ssh user@192.168.56.100
```

**Evidence:** Screenshot the nmap output showing port 8080 as "filtered" and port 80 as "open". This confirms the rules are working.

---

## Key Insight

UFW rules are stored in `/etc/ufw/` and translate to iptables rules you can see with:
```bash
sudo iptables -L -v -n
```
This is the bridge between UFW and iptables — the same rules, different syntax.
