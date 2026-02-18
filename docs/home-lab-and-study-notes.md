# Home Lab Setup & Study Notes
> CST Co-op Preparation — Matthew Vaishnav

---

## 🖥️ Home Lab Architecture
```
                    ┌─────────────────────────────────┐
                    │         Host Machine            │
                    │       VirtualBox / VMware       │
                    └─────────────┬───────────────────┘
                                  │ Internal Network (NAT)
            ┌────────────┬────────┼───────────┬──────────────┐
            │            │        │           │              │
       ┌────▼───┐  ┌────▼───┐  ┌─▼──────┐  ┌▼──────┐  ┌──▼──────┐
       │ Kali   │  │Ubuntu  │  │Win     │  │pfSense │ │Security │
       │ Linux  │  │Server  │  │Server  │  │FW/RTR  │ │ Onion   │
       │(Attack)│  │22.04   │  │2019    │  │        │ │(SIEM)   │
       └────────┘  └────────┘  └────────┘  └────────┘ └─────────┘
       172.16.0.5 172.16.0.10 172.16.0.15 172.16.0.1  172.16.0.20
```

### VM Specs & Purpose

| VM | OS | RAM | Purpose |
|----|----|----|---------|
| **Kali Linux** | Kali 2024 | 4GB | Pentesting, tools, CTFs |
| **Ubuntu Server** | Ubuntu 22.04 | 2GB | Target, LAMP stack, monitoring |
| **Windows Server** | WS 2019 | 4GB | Active Directory, DNS, DHCP |
| **pfSense** | FreeBSD | 1GB | Firewall, network segmentation |
| **Security Onion** | SO 2.3 | 8GB | IDS/IPS, log management, SIEM |

---

## 📚 Study Schedule (Co-op Prep)

### Week Structure
```
Mon-Wed:  Technical skill building (scripting, labs)
Thu-Fri:  TryHackMe / HackTheBox rooms
Weekend:  CTF events, certification study
```

### Current Focus Areas

#### 🔵 Blue Team / SOC Skills
- [ ] Windows Event Log analysis (Event IDs: 4624, 4625, 4720, 4732, 4698)
- [ ] Splunk fundamentals (SPL queries, dashboards, alerts)
- [ ] Network traffic analysis with Wireshark
- [ ] Incident response workflow (NIST 800-61)
- [ ] MITRE ATT&CK framework navigation
- [ ] Threat intelligence (IOC types, TIP platforms)

#### ⚙️ DevOps Skills
- [ ] Docker & Docker Compose (intermediate)
- [ ] GitHub Actions CI/CD pipelines
- [ ] Terraform basics (AWS/Azure)
- [ ] Ansible playbook writing
- [ ] Linux administration (files, processes, networking, systemd)
- [ ] Kubernetes basics (Pods, Deployments, Services)

#### 🐍 Scripting & Automation
- [ ] Python: file I/O, regex, APIs, argparse, logging
- [ ] Bash: scripting, cron, process management, piping
- [ ] PowerShell: AD queries, file ops, remote execution
- [ ] Git: branching strategies, rebasing, PRs

#### 🌐 Networking
- [ ] TCP/IP model — all 7 layers, can explain each
- [ ] Subnetting — can subnet /24, /22, /16 in head
- [ ] DNS resolution process — full walk-through
- [ ] Common protocols: HTTP/S, SSH, SMB, FTP, DNS, DHCP
- [ ] VPN types: IPSec, SSL/TLS, WireGuard

---

## 🔑 Key Event IDs to Know

### Authentication (Security Log)
| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Logoff |
| 4648 | Explicit credential logon (runas) |
| 4740 | Account locked out |
| 4767 | Account unlocked |

### Account Management
| Event ID | Description |
|----------|-------------|
| 4720 | User account created |
| 4722 | User account enabled |
| 4725 | User account disabled |
| 4726 | User account deleted |
| 4728 | Member added to global security group |
| 4732 | Member added to local security group |
| 4756 | Member added to universal security group |

### Privilege Use
| Event ID | Description |
|----------|-------------|
| 4672 | Special privileges assigned at logon |
| 4673 | Privileged service called |
| 4674 | Privileged object operation |

### Persistence / Execution
| Event ID | Description |
|----------|-------------|
| 4698 | Scheduled task created |
| 7045 | New service installed (System Log) |
| 4104 | PowerShell script block logged |

---

## 🛡️ MITRE ATT&CK Quick Reference

### Initial Access
- **T1566** Phishing (spear, attachment, link)
- **T1190** Exploit Public-Facing Application

### Execution
- **T1059.001** PowerShell
- **T1059.003** Windows Command Shell
- **T1053.005** Scheduled Task

### Persistence
- **T1547.001** Registry Run Keys / Startup Folder
- **T1136.001** Create Local Account
- **T1543.003** Create or Modify System Process: Windows Service

### Privilege Escalation
- **T1055** Process Injection
- **T1134** Access Token Manipulation
- **T1078** Valid Accounts

### Credential Access
- **T1003.001** LSASS Memory (Mimikatz)
- **T1110** Brute Force
- **T1552** Unsecured Credentials

### Lateral Movement
- **T1021.001** Remote Services: RDP
- **T1021.002** SMB/Windows Admin Shares
- **T1550.002** Pass the Hash

### Collection & Exfiltration
- **T1005** Data from Local System
- **T1048** Exfiltration Over Alternative Protocol

---

## 🌐 Useful Tools & Commands

### Nmap Cheat Sheet
```bash
nmap -sn 192.168.1.0/24                    # Ping sweep
nmap -sV -sC 192.168.1.10                  # Version + default scripts
nmap -p- --min-rate 5000 192.168.1.10      # All ports, fast
nmap -A -T4 192.168.1.10                   # Aggressive scan
nmap -sU --top-ports 100 192.168.1.10      # Top 100 UDP ports
nmap -p 445 --script smb-vuln-ms17-010     # EternalBlue check
```

### Netstat / ss
```bash
ss -tulnp                   # All listening ports with process
netstat -anp | grep LISTEN  # Older systems
ss -s                       # Summary statistics
```

### Log Locations
```bash
/var/log/auth.log           # SSH, sudo (Ubuntu)
/var/log/syslog             # System messages
/var/log/apache2/access.log # Apache access
/var/log/nginx/access.log   # Nginx access
/var/log/fail2ban.log       # Fail2ban bans
journalctl -u sshd -f       # Follow SSH journal
```

### Windows Event Log (PowerShell)
```powershell
Get-EventLog -LogName Security -Newest 50
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 100
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddHours(-1)}
```

---

## 📋 Interview Prep — Common Questions

**Q: Walk me through how you'd respond to a phishing alert.**
A: 1) Retrieve and analyze email headers for spoofing indicators, 2) Sandbox any attachments/URLs, 3) Check if user clicked, 4) If credentials phished → force password reset, revoke sessions, enable MFA, 5) Pull back email from all inboxes, 6) Block IOCs at gateway, 7) Document in ticket.

**Q: What's the difference between IDS and IPS?**
A: IDS (Intrusion Detection System) monitors and alerts — passive. IPS (Intrusion Prevention System) monitors and actively blocks — inline. IDS has no impact on traffic; IPS can cause false-positive blocks. In practice, tools like Snort and Suricata can operate in either mode.

**Q: Explain the OSI model.**
A: 7 layers from physical to application: Physical → Data Link → Network → Transport → Session → Presentation → Application. Example: HTTP request traverses all 7 on the way down (encapsulation), and all 7 on the way up at the destination (decapsulation). "Please Do Not Throw Sausage Pizza Away."

**Q: What is a VLAN and why is it useful?**
A: Virtual LAN — logical segmentation of a physical network. Useful for: isolating sensitive segments (finance, OT/ICS), reducing broadcast domains, applying different firewall policies per segment, containing lateral movement in a breach.

**Q: What would you do if you found a high-severity vulnerability on a production server?**
A: 1) Verify it's a true positive, 2) Assess exploitability and active exploitation risk, 3) Notify the asset owner and management, 4) Apply compensating controls (WAF rule, network ACL) if immediate patch isn't possible, 5) Track in vulnerability management system with SLA, 6) Apply patch in maintenance window, 7) Verify remediation.
