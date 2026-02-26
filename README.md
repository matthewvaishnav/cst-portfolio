# Matthew Vaishnav — Security & Infrastructure Portfolio

> **Conestoga College — Computer Systems Technician (CST)**  
> Seeking co-op · SOC Analyst · DevSecOps · Systems Administration  
> 📍 Kitchener-Waterloo, ON · 📧 matthew.vaishnav@gmail.com · 🔗 [LinkedIn](https://www.linkedin.com/in/matthew-vaishnav-279670229/) · 🌐 [Portfolio Site](https://matthewvaishnav.github.io/cst-portfolio)

---

## What this repo is

A working portfolio built on an **18-node home lab** running across 6 isolated VLANs on VMware Workstation, with pfSense routing all traffic and Security Onion passively sniffing the SPAN port. Everything here was written against a running system, not a textbook.

The lab is fully version-controlled — if the host dies, it rebuilds from Ansible + Terraform in minutes.

---

## Repository Map

| Folder | What's inside |
|--------|---------------|
| [`soc/`](./soc) | Log correlation engine, threat hunting scripts, Splunk SPL library, IR playbooks |
| [`sigma-rules/`](./sigma-rules) | Detection rules written to cover TTPs from every CTF and lab exercise |
| [`devops/`](./devops) | Terraform (AWS VPC + GuardDuty), Ansible (server hardening), Docker, GitHub Actions CI/CD |
| [`scripting/`](./scripting) | Python recon + anomaly detection, Bash CIS hardening, PowerShell AD audit with HTML report |
| [`networking/`](./networking) | pfSense rule reference, firewall design notes, subnet calculator |
| [`monitoring/`](./monitoring) | Docker Compose: Prometheus + Grafana + Loki + AlertManager + Node Exporter |
| [`data-analysis/`](./data-analysis) | Multi-source log correlation engine → MITRE-mapped HTML incident report |
| [`ctf-writeups/`](./ctf-writeups) | TryHackMe and HackTheBox writeups — each ends with detection coverage and Sigma rules |
| [`.github/workflows/`](./.github/workflows) | CI/CD: syntax checks, Bandit SAST, Sigma lint, Terraform validate, nightly metadata sync |

---

## Featured Work

### 🔍 SOC Log Correlation Engine
[`data-analysis/log_correlation.py`](./data-analysis/log_correlation.py) — Multi-source correlation across `auth.log` and web access logs. Detects brute-force-then-success chains, scanner-to-admin-path recon, credential stuffing — all mapped to MITRE ATT&CK. 14,822 log entries parsed, 3 high-severity alerts, 0 false positives on first run.

### 🛡️ Sigma Detection Rules
[`sigma-rules/`](./sigma-rules) — Rules written as the defensive half of each offensive exercise. Workflow: execute attack → observe log evidence → write rule → validate it fires → document FP rate. Current coverage: SSH brute force to root (T1110.001), DCSync (T1003.006), sudo interpreter abuse (T1548.003).

### ⚙️ DevSecOps Pipeline
[`devops/ci-cd/`](./devops/ci-cd) — GitHub Actions: lint → Bandit SAST → Trivy container scan → Terraform validate → deploy. Fails on CVSS ≥ 7. Caught 6 critical CVEs before deploy.

### 🌐 Terraform AWS Hardened VPC
[`devops/terraform/main.tf`](./devops/terraform/main.tf) — Multi-AZ VPC, NAT gateway, bastion host, least-privilege security groups, VPC Flow Logs → CloudWatch, encrypted S3 log bucket. Region: `ca-central-1`.

### 📊 SOC Monitoring Stack
[`monitoring/docker-compose.yml`](./monitoring/docker-compose.yml) — 7 services, isolated Docker network, persistent storage, pre-built alerting rules. One command deploy.

### 🔐 Linux CIS Hardening
[`scripting/bash/server_hardening.sh`](./scripting/bash/server_hardening.sh) — CIS Benchmark Level 1 for Ubuntu 22.04. `--dry-run` flag, structured pass/fail logging, config backup before changes.

### 🪟 Windows Security Audit
[`scripting/powershell/windows_audit.ps1`](./scripting/powershell/windows_audit.ps1) — Audits accounts, privilege groups, scheduled tasks, ports, patch status, Defender state, AD enumeration. Outputs formatted HTML report.

---

## CTF Writeups

Each writeup: recon → exploit → escalate → post-exploit → **detection & remediation**. The blue team section is never optional.

| Room | Platform | Difficulty | Techniques | Sigma Rule |
|------|----------|------------|------------|------------|
| [Blue — EternalBlue](./ctf-writeups/THM_Blue_EternalBlue.md) | TryHackMe | Easy | T1190, T1003.002, T1543 | [ssh_brute_force_to_root.yml](./sigma-rules/ssh_brute_force_to_root.yml) |
| [Linux PrivEsc Arena](./ctf-writeups/THM_Linux_Privesc.md) | TryHackMe | Medium | T1548.003, T1053.003 | [sudo_interpreter_escalation.yml](./sigma-rules/sudo_interpreter_escalation.yml) |
| [Attacktive Directory](./ctf-writeups/THM_ActiveDirectory_Attacks.md) | TryHackMe | Hard | T1558.004, T1003.006, T1550.002 | [dcsync_attack.yml](./sigma-rules/dcsync_attack.yml) |
| [OWASP Top 10 / Web Exploitation](./ctf-writeups/THM_WebApp_Exploitation.md) | TryHackMe | Medium | T1190, T1059.007, T1083 | — |

*HTB Active (GPP creds + Kerberoasting) and HTB Lame — in progress.*

---

## Home Lab

```
                    ┌─────────────────────┐
                    │   pfSense 2.7.2      │
                    │   192.168.1.1        │
                    └──────────┬──────────┘
                               │ SPAN → Security Onion
       ┌───────────┬───────────┼───────────┬───────────┐
       │           │           │           │           │
  VLAN 10     VLAN 20     VLAN 30     VLAN 40     VLAN 50
  Management  Security    Monitoring  Victim Net  Services
```

**18 live nodes · +5 planned · 6 isolated VLANs · 100% traffic monitored · IaC via Ansible + Terraform**

---

## Skills

`Security Onion` `Elastic SIEM` `Suricata` `Zeek` `Sigma` `Splunk SPL` `MITRE ATT&CK`  
`Terraform` `Ansible` `Docker` `GitHub Actions` `pfSense` `AWS` `Azure Sentinel`  
`Python` `Bash` `PowerShell` `Linux` `Windows Server 2019`

---

## Certifications

| Credential | Status | Progress |
|------------|--------|----------|
| CompTIA Security+ | In progress | 62% |
| TryHackMe SOC Level 2 | In progress | 78% |
| TryHackMe Pre-Security | ✅ Complete | — |
| Cisco Networking Essentials | ✅ Complete | — |

---

Open to co-op · Summer / Fall 2026 · Kitchener-Waterloo, ON  
📧 matthew.vaishnav@gmail.com
