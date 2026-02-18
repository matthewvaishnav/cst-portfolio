# Firewall Rules Reference
> Network Security — Matthew Vaishnav | CST, Conestoga College

---

## Table of Contents
1. [UFW (Ubuntu)](#ufw-ubuntu)
2. [iptables](#iptables)
3. [Windows Firewall (PowerShell)](#windows-firewall-powershell)
4. [pfSense Rules Logic](#pfsense-rules-logic)
5. [Common Rule Sets](#common-rule-sets)
6. [Rule Design Principles](#rule-design-principles)

---

## UFW (Ubuntu)

### Basic Setup
```bash
# Set default policies
ufw default deny incoming
ufw default allow outgoing

# Enable UFW
ufw enable

# Check status
ufw status verbose
```

### Common Rules
```bash
# Allow SSH (rate-limited)
ufw limit ssh

# Allow HTTP/HTTPS
ufw allow 80/tcp
ufw allow 443/tcp

# Allow specific IP to SSH
ufw allow from 203.0.113.5 to any port 22

# Allow subnet to access port
ufw allow from 192.168.1.0/24 to any port 3306

# Deny specific IP
ufw deny from 198.51.100.0/24

# Delete a rule
ufw delete allow 80/tcp

# Allow port range
ufw allow 8000:8080/tcp
```

### Application Profiles
```bash
ufw app list                  # List available profiles
ufw allow 'Nginx Full'        # Allow HTTP + HTTPS
ufw allow 'OpenSSH'           # Allow SSH
ufw app info 'Nginx Full'     # Show profile details
```

---

## iptables

### View Current Rules
```bash
iptables -L -v -n             # List all rules with counters
iptables -L INPUT -v -n       # List INPUT chain only
iptables -S                   # Show rules in save format
iptables -t nat -L -v -n      # List NAT table
```

### Basic Hardened Ruleset
```bash
#!/bin/bash
# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t mangle -F

# Default policies — drop everything
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established/related connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (rate limited — max 3 attempts per minute)
iptables -A INPUT -p tcp --dport 22 -m state --state NEW \
  -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 22 -m state --state NEW \
  -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

# Allow HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT

# Allow ICMP (ping) — limit rate
iptables -A INPUT -p icmp --icmp-type echo-request \
  -m limit --limit 1/s --limit-burst 5 -j ACCEPT

# Drop invalid packets
iptables -A INPUT -m state --state INVALID -j DROP

# Log dropped packets (before final DROP)
iptables -A INPUT -m limit --limit 5/min -j LOG \
  --log-prefix "iptables-DROP: " --log-level 7

# Save rules
iptables-save > /etc/iptables/rules.v4
```

### Port Forwarding (NAT)
```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Forward port 80 on eth0 to internal host
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 \
  -j DNAT --to-destination 192.168.1.10:80

# Masquerade outbound traffic
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

### Block Common Attack Patterns
```bash
# Block NULL packets
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# Block XMAS packets
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# Block SYN-FIN (malformed)
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

# Block FIN scan
iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP

# Block port scanners
iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A INPUT -m recent --name portscan --remove
iptables -A INPUT -p tcp -m tcp --dport 139 \
  -m recent --name portscan --set -j LOG --log-prefix "Portscan: "
iptables -A INPUT -p tcp -m tcp --dport 139 \
  -m recent --name portscan --set -j DROP
```

---

## Windows Firewall (PowerShell)

### View Rules
```powershell
# Show all rules
Get-NetFirewallRule | Select-Object DisplayName, Enabled, Direction, Action

# Show enabled inbound rules
Get-NetFirewallRule -Direction Inbound -Enabled True |
  Select-Object DisplayName, Action | Sort-Object DisplayName

# Find rule by port
Get-NetFirewallRule | Where-Object { $_ | Get-NetFirewallPortFilter |
  Where-Object LocalPort -eq 3389 }
```

### Create Rules
```powershell
# Allow inbound SSH
New-NetFirewallRule -DisplayName "Allow SSH" `
  -Direction Inbound -Protocol TCP `
  -LocalPort 22 -Action Allow

# Allow inbound HTTPS from specific subnet
New-NetFirewallRule -DisplayName "Allow HTTPS from LAN" `
  -Direction Inbound -Protocol TCP `
  -LocalPort 443 -RemoteAddress 192.168.1.0/24 `
  -Action Allow

# Block inbound Telnet
New-NetFirewallRule -DisplayName "Block Telnet" `
  -Direction Inbound -Protocol TCP `
  -LocalPort 23 -Action Block

# Rate limit RDP (allow only from specific IP)
New-NetFirewallRule -DisplayName "RDP — Admin Only" `
  -Direction Inbound -Protocol TCP `
  -LocalPort 3389 -RemoteAddress 10.0.0.5 `
  -Action Allow

# Block outbound to known bad IP
New-NetFirewallRule -DisplayName "Block Malicious IP" `
  -Direction Outbound `
  -RemoteAddress 198.51.100.100 `
  -Action Block
```

### Manage Profiles
```powershell
# View profile status
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction

# Enable all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Set default deny inbound on Public profile
Set-NetFirewallProfile -Profile Public `
  -DefaultInboundAction Block `
  -DefaultOutboundAction Allow
```

---

## pfSense Rules Logic

### Rule Processing Order
```
Interface rules are processed TOP to BOTTOM — first match wins.

1. Floating rules (all interfaces)
2. Interface group rules
3. Interface-specific rules
```

### Recommended LAN → WAN Rules
```
# Allow established/related (stateful — automatic in pfSense)
# Block RFC1918 from WAN (anti-spoofing)
# Allow LAN to WAN HTTP/HTTPS
# Allow LAN to WAN DNS (port 53)
# Allow LAN to WAN NTP (port 123)
# Block everything else
```

### VLAN Segmentation Example
```
VLAN 10 — Management  (10.0.10.0/24)
VLAN 20 — Servers     (10.0.20.0/24)
VLAN 30 — Users       (10.0.30.0/24)
VLAN 40 — IoT         (10.0.40.0/24)
VLAN 99 — DMZ         (10.0.99.0/24)

Rules:
  Management → All VLANs   : ALLOW (admin access)
  Servers    → Internet     : ALLOW (updates)
  Users      → Servers      : ALLOW ports 80,443,445 only
  Users      → Internet     : ALLOW
  IoT        → Internet     : ALLOW (updates only)
  IoT        → Any VLAN     : DENY (isolation)
  DMZ        → Internal     : DENY (DMZ must not reach LAN)
  Any        → Management   : DENY (protect mgmt VLAN)
```

---

## Common Rule Sets

### Web Server
```bash
ufw default deny incoming
ufw default allow outgoing
ufw limit ssh
ufw allow 80/tcp
ufw allow 443/tcp
# If behind load balancer — restrict 80/443 to LB IP only:
# ufw allow from 10.0.0.5 to any port 80
# ufw allow from 10.0.0.5 to any port 443
ufw enable
```

### Database Server (no direct internet)
```bash
ufw default deny incoming
ufw default deny outgoing
ufw allow from 10.0.20.0/24 to any port 3306  # MySQL from app subnet
ufw allow from 10.0.10.0/24 to any port 22    # SSH from mgmt only
ufw allow out 53                               # DNS resolution
ufw allow out 443                              # Package updates
ufw enable
```

### Bastion / Jump Host
```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow from 203.0.113.5/32 to any port 22  # SSH from admin IP only
ufw limit ssh
ufw enable
# No other inbound ports — bastion should do nothing else
```

---

## Rule Design Principles

### ✅ Best Practices
- **Default deny** — block everything, allow only what's needed
- **Least privilege** — restrict source IPs where possible, not just ports
- **Stateful inspection** — always allow ESTABLISHED,RELATED return traffic
- **Rate limiting** — apply to SSH, RDP, and any auth endpoint
- **Log before drop** — log denied traffic for SOC visibility
- **VLAN segmentation** — never flat network in production
- **Regular audits** — review rules quarterly, remove stale entries
- **Document everything** — every rule needs a comment/ticket reference

### ❌ Common Mistakes
- Allowing `0.0.0.0/0` on SSH/RDP to internet
- No rate limiting on authentication ports
- Forgetting to block RFC1918 on WAN interface (anti-spoofing)
- Rules that shadow each other (unreachable rules below broad ALLOW)
- No logging — flying blind when incidents happen
- Allowing all ICMP instead of just echo-request with rate limit
- Not testing rules after changes (use `ufw status` / `iptables -L`)

### 🔍 Testing Your Rules
```bash
# Test from external — should fail
nmap -p 22 YOUR_SERVER_IP --open

# Test UFW is active
ufw status verbose

# Check what iptables is doing
iptables -L -v -n | grep -v "0     0"  # Show only rules with hits

# Watch live drops
tail -f /var/log/syslog | grep "iptables-DROP"
```
