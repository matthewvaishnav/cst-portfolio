# 🛡️ CST Co-op Portfolio — Security, DevOps & Systems Analysis

> **Conestoga College — Computer Systems Technician**  
> Actively seeking Co-op placement | Targeting: SOC Analyst · DevOps · Junior IT Analyst · Systems Admin  
> 📍Kitchener/Waterloo Region, ON · 📧 fivepenguinz@proton.me · 🔗 [LinkedIn](https://www.linkedin.com/in/matthew-vaishnav-279670229/)

---

## 📌 About This Repository

This repo is a living, hands-on portfolio demonstrating practical skills across the **Blue Team security**, **DevOps**, **scripting/automation**, **networking**, and **data analysis** domains — all relevant to entry-level co-op roles in the Greater Waterloo tech ecosystem.

Everything here is written, tested, and documented by me as part of my learning journey at Conestoga.

---

## 🗂️ Repository Map

| Folder | Domain | What's Inside |
|--------|--------|---------------|
| [`soc/`](./soc) | 🔵 Blue Team / SOC | Log parsers, threat hunting scripts, IR playbooks, Splunk queries |
| [`devops/`](./devops) | ⚙️ DevOps / CI-CD | Docker, Ansible, Terraform, GitHub Actions pipelines |
| [`scripting/`](./scripting) | 🐍 Automation | Python, Bash, PowerShell utilities |
| [`networking/`](./networking) | 🌐 Networking | Packet analysis, firewall rule templates, subnet calculators |
| [`monitoring/`](./monitoring) | 📊 Observability | Grafana dashboards, alerting configs, Prometheus setup |
| [`data-analysis/`](./data-analysis) | 📈 Analysis | Log correlation, anomaly detection notebooks |
| [`ctf-writeups/`](./ctf-writeups) | 🚩 CTF / Labs | TryHackMe & HackTheBox writeups |
| [`docs/`](./docs) | 📄 Documentation | Architecture diagrams, runbooks, study notes |

---

## 🧰 Skills Demonstrated

### Security / SOC
- Log analysis (Windows Event Logs, Syslog, Apache/Nginx)
- SIEM query writing (Splunk SPL, simulated)
- Threat hunting using MITRE ATT&CK framework
- Incident response playbook creation
- IOC extraction and triage
- Vulnerability scanning with Nmap & Nessus concepts

### DevOps & Infrastructure
- Docker containerization & Docker Compose
- CI/CD pipeline authoring (GitHub Actions)
- Infrastructure as Code (Terraform HCL)
- Configuration management (Ansible playbooks)
- Kubernetes basics (manifests, deployments)
- Linux system administration

### Scripting & Automation
- Python: log parsing, API calls, file automation, alerting
- Bash: system monitoring, cron automation, hardening scripts
- PowerShell: AD queries, system auditing, Windows automation

### Networking & Systems
- TCP/IP, subnetting, VLAN concepts
- Firewall rule design (iptables, pfSense concepts)
- Wireshark/tcpdump packet analysis
- DNS, DHCP, HTTP/S traffic understanding

### Tools & Platforms
`Python` `Bash` `PowerShell` `Docker` `Git` `Linux (Ubuntu/Kali)` `Wireshark` `Nmap` `Splunk` `Grafana` `Prometheus` `Ansible` `Terraform` `GitHub Actions` `VS Code` `VirtualBox/VMware`

---

## 🚀 Featured Projects

### 1. 🔍 [Automated Log Anomaly Detector](./soc/log-analysis/anomaly_detector.py)
Python script that ingests Apache/Nginx access logs, identifies brute-force patterns, suspicious user agents, and geo-anomalies — outputs structured JSON alerts.

### 2. 🛡️ [Linux Server Hardening Automation](./scripting/bash/server_hardening.sh)
Bash script that applies CIS Benchmark Level 1 hardening steps: disables unused services, configures UFW, sets SSH best practices, enables auditd.

### 3. ⚙️ [Full CI/CD Pipeline with Security Scanning](./devops/ci-cd/)
GitHub Actions workflow with stages: lint → unit test → SAST (Bandit) → Docker build → deploy to staging → smoke test.

### 4. 📊 [SOC Dashboard Stack](./monitoring/)
Docker Compose stack spinning up Prometheus + Grafana + Loki for a home-lab SOC monitoring environment with pre-built dashboards.

### 5. 🌐 [Network Recon & Asset Inventory Script](./scripting/python/network_recon.py)
Python + Nmap integration that auto-discovers hosts on a subnet, fingerprints OS/services, and outputs a formatted asset inventory report.

---

## 🏅 Certifications & Training (In Progress)

- [ ] CompTIA Security+ *(studying)*
- [ ] Google Cybersecurity Certificate *(Coursera)*
- [x] TryHackMe — Pre-Security Path *(completed)*
- [x] Cisco Networking Essentials
- [ ] AWS Cloud Practitioner

---

## 🏠 Home Lab Setup

Running a virtualized home lab using Proxmox VE:
- **Kali Linux** — attack/pentest VM
- **Ubuntu Server 22.04** — target & monitoring server  
- **Windows Server 2019** — Active Directory practice
- **pfSense** — firewall/router VM
- **Security Onion** — SIEM/IDS monitoring

---

## 📬 Contact

I'm actively looking for co-op opportunities starting **August 2025** in the Waterloo Region.  
Feel free to reach out — I'm eager, reliable, and learn fast.

> *"Security is not a product, but a process." — Bruce Schneier*
