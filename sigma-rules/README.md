# Sigma Detection Rules

> Author: Matthew Vaishnav — CST, Conestoga College  
> Validated against: Security Onion 2.4, Elastic SIEM, lab environment

---

Rules in this directory were written as the **defensive half** of each CTF and lab exercise. The workflow for every offensive technique I practice:

1. Execute the attack in the lab
2. Observe what log evidence it leaves (Event IDs, auth.log entries, Zeek conn.log, Suricata alerts)
3. Write a Sigma rule that would have caught it
4. Validate the rule fires correctly against the captured log evidence
5. Document false-positive rate and tuning guidance

This is the discipline I want to bring to a SOC co-op role — not just "I ran Metasploit," but "here's the detection rule that makes that technique visible."

---

## Rules

| File | Technique | ATT&CK | Level | Validated |
|------|-----------|--------|-------|-----------|
| [`ssh_brute_force_to_root.yml`](./ssh_brute_force_to_root.yml) | SSH brute force → root escalation | T1110.001, T1078.003 | High | ✅ Security Onion 2.4 |
| [`dcsync_attack.yml`](./dcsync_attack.yml) | DCSync via secretsdump.py | T1003.006 | Critical | ✅ Windows AD Lab |
| [`sudo_interpreter_escalation.yml`](./sudo_interpreter_escalation.yml) | Sudo abuse via Python/Perl | T1548.003 | High | ✅ Linux PrivEsc Lab |

---

## Deployment

These rules are written in [Sigma format](https://github.com/SigmaHQ/sigma) and can be converted to any SIEM backend:

```bash
# Convert to Elastic Query DSL
sigma convert -t elasticsearch ssh_brute_force_to_root.yml

# Convert to Splunk SPL
sigma convert -t splunk dcsync_attack.yml

# Convert to QRadar AQL
sigma convert -t qradar sudo_interpreter_escalation.yml
```

For Splunk equivalents, see [`soc/splunk-queries/sql_playbook.spl`](../soc/splunk-queries/sql_playbook.spl).

---

## Coverage Map

```
ATT&CK Tactic          Technique           Rule
──────────────────────────────────────────────────────────
Credential Access      T1110.001           ssh_brute_force_to_root.yml
Credential Access      T1003.006           dcsync_attack.yml
Privilege Escalation   T1548.003           sudo_interpreter_escalation.yml
Persistence            T1078 / T1078.003   ssh_brute_force_to_root.yml
```

More rules being added as lab coverage expands.
