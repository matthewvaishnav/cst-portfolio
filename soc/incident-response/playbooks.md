# Incident Response Playbooks
> SOC Runbooks — CST Portfolio | Based on NIST SP 800-61r2 | Matthew Vaishnav

---

## Playbook Index

| # | Scenario | Severity | Avg TTR |
|---|----------|----------|---------|
| 1 | [Ransomware Infection](#1-ransomware-infection) | CRITICAL | 4–8 hrs |
| 2 | [Phishing with Credential Theft](#2-phishing--credential-theft) | HIGH | 1–2 hrs |
| 3 | [Brute Force / Account Lockout](#3-brute-force--account-lockout) | MEDIUM | 30 min |
| 4 | [Suspicious PowerShell Execution](#4-suspicious-powershell-execution) | HIGH | 1–3 hrs |
| 5 | [Unauthorized Admin Account Creation](#5-unauthorized-admin-account-creation) | HIGH | 45 min |
| 6 | [Data Exfiltration Alert](#6-data-exfiltration-alert) | CRITICAL | 2–4 hrs |

---

## 1. Ransomware Infection

**Trigger**: AV/EDR detects ransomware binary, mass file rename events, or `.encrypted` extension spread.

### Phase 1 — Identification (0–15 min)
- [ ] Identify affected host(s) via EDR/AV console alert
- [ ] Check file system events: look for mass rename/delete (Sysmon Event 11)
- [ ] Confirm ransomware family (VirusTotal hash lookup)
- [ ] Identify patient zero via network logs / email gateway

### Phase 2 — Containment (15–30 min)
- [ ] **IMMEDIATELY isolate** affected host(s) at switch level (VLAN quarantine or port disable)
- [ ] Disable affected AD accounts if user-initiated
- [ ] Block C2 IPs/domains at perimeter firewall
- [ ] Snapshot VMs if in virtual environment (preserve memory for forensics)
- [ ] Notify: IT Manager, CISO, affected business unit

### Phase 3 — Eradication (30 min–2 hrs)
- [ ] Identify and terminate malicious processes
- [ ] Remove persistence mechanisms (registry run keys, scheduled tasks)
- [ ] Scan all network shares for encryption activity
- [ ] Check lateral movement logs — was it spreading via SMB/RDP?

### Phase 4 — Recovery
- [ ] Restore from last known-good backup (verify backup integrity first)
- [ ] Re-image compromised host if full clean not certain
- [ ] Reset credentials for all affected accounts
- [ ] Monitor restored systems for 48 hours

### Phase 5 — Lessons Learned
- [ ] Document timeline (Detection → Containment → Recovery)
- [ ] Update firewall/AV signatures
- [ ] Patch vulnerability used for initial access
- [ ] Update playbook if gaps found

**Key Evidence to Collect**: Memory dump, $MFT, Prefetch files, Event logs (Security, System, Application), registry hives (NTUSER.DAT, SOFTWARE), network captures

---

## 2. Phishing / Credential Theft

**Trigger**: User reports suspicious email, email gateway alert, or impossible travel login detected.

### Phase 1 — Identification (0–10 min)
- [ ] Retrieve original email headers (full RFC 822)
- [ ] Extract and analyze attachments/URLs safely (sandbox: Any.run, Cuckoo)
- [ ] Check if user clicked link or opened attachment
- [ ] Search mail gateway for all recipients of same campaign
- [ ] Check MFA logs — was MFA prompted and approved?

### Phase 2 — Containment (10–20 min)
- [ ] If credentials compromised: **force password reset immediately**
- [ ] Revoke active sessions (Azure AD: Revoke Sign-in Sessions)
- [ ] Block sender domain/IP at email gateway
- [ ] Pull back email from all inboxes (M365: Content Search → Purge)
- [ ] Enable MFA if not already on affected account

### Phase 3 — Eradication
- [ ] Check email rules for malicious forwarding rules
- [ ] Audit OAuth app consents (look for suspicious app permissions)
- [ ] Review account activity: logins, file access, email sent
- [ ] Check for persistence: new inbox rules, delegates, forwarding

### Phase 4 — Recovery
- [ ] Confirm account clean before restoring access
- [ ] Brief user on what happened and what to watch for
- [ ] Send organization-wide phishing awareness reminder if campaign is broad

**MITRE**: T1566 (Phishing), T1078 (Valid Accounts), T1534 (Internal Spearphishing)

---

## 3. Brute Force / Account Lockout

**Trigger**: >10 failed logins in 5 min (Event 4625), account lockout (Event 4740).

### Steps
- [ ] Identify source IP — internal or external?
- [ ] If **external**: block IP at perimeter, check if VPN/RDP is exposed, notify user
- [ ] If **internal**: identify compromised host, isolate, scan for malware
- [ ] Check if any logon succeeded after failures (Event 4624 after 4625 burst)
- [ ] Reset password if account may be compromised
- [ ] If targeting service accounts: treat as HIGH severity, check for Pass-the-Hash

**Quick Splunk Query**:
```
index=security EventCode=4625 | bucket _time span=5m
| stats count by src_ip _time | where count > 10
```

---

## 4. Suspicious PowerShell Execution

**Trigger**: Event 4104 with encoded commands, `bypass`, `DownloadString`, or `Invoke-Expression`.

### Steps
- [ ] Capture full script block (Event 4104 — enable if not already on)
- [ ] Decode Base64 content: `[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("..."))`
- [ ] Determine parent process — what spawned PowerShell?
- [ ] Check for network connections spawned by the PS process (Sysmon Event 3)
- [ ] Check for files dropped (Sysmon Event 11)
- [ ] If malicious: isolate host, kill process, collect memory

**Red flags**: `-EncodedCommand`, `-Exec Bypass`, `IEX`, `Invoke-Mimikatz`, `Invoke-ReflectivePEInjection`

---

## 5. Unauthorized Admin Account Creation

**Trigger**: Event 4720 (account created) or 4732 (user added to Administrators group) by non-IT account.

### Steps
- [ ] Identify who created the account (Subject fields in event log)
- [ ] Determine if creator account is legitimate and expected to create accounts
- [ ] Immediately disable the new account
- [ ] Remove from any privileged groups
- [ ] Audit all activity by the creator account over the past 24–72 hours
- [ ] Check for backdoor persistence (new scheduled tasks, services)
- [ ] If creator account is compromised: full incident escalation

---

## 6. Data Exfiltration Alert

**Trigger**: >100MB outbound to external IP, DLP alert, or unusual cloud storage upload.

### Steps
- [ ] Identify source host, destination IP, and data volume
- [ ] WHOIS/Geo lookup on destination — known CDN, or suspicious country?
- [ ] Review what data was transferred (DLP classification if available)
- [ ] Was this a sanctioned tool (OneDrive, Google Drive) or shadow IT?
- [ ] Check user's recent activity — was account compromised or is this insider threat?
- [ ] If insider threat suspected: do NOT alert the user — escalate to HR/legal
- [ ] Preserve logs immediately — do not allow rotation or deletion
- [ ] Block destination at firewall temporarily while investigating

**Notification Requirements (Canada)**: If personal data involved, assess PIPEDA breach reporting obligation (significant risk of harm threshold).

---

## Communication Templates

### Initial Incident Notification
```
Subject: [INCIDENT-XXXX] [Severity] - [Brief Description]

Incident ID    : INC-YYYY-NNNN
Severity       : CRITICAL / HIGH / MEDIUM
Status         : INVESTIGATING
Detected       : YYYY-MM-DD HH:MM UTC
Affected Asset : [hostname/IP/service]
Summary        : [2-3 sentences max]
Next Update    : In 1 hour or upon status change

Actions Taken  : [Bullet list]
Actions Pending: [Bullet list]

Incident Commander: [Name]
```

### All-Clear Notification
```
Subject: [RESOLVED] [INCIDENT-XXXX] - [Description]

Resolution Time  : YYYY-MM-DD HH:MM UTC
Root Cause       : [Brief]
Impact           : [What was/wasn't affected]
Remediation Steps: [What was done]
Preventive Action: [What will stop recurrence]

Full post-mortem to follow within 5 business days.
```
