#!/usr/bin/env python3
"""
Log Anomaly Detector
====================
Parses Apache/Nginx access logs and Windows-style auth logs to detect:
  - Brute-force login attempts
  - Directory traversal patterns
  - Suspicious user agents (scanners, exploit tools)
  - High-frequency requests from a single IP (DDoS indicators)
  - Non-standard HTTP methods
  - Access outside business hours (configurable)

Author : Matthew Vaishnav
Course : CST — Conestoga College
Usage  : python anomaly_detector.py --log access.log --format apache --output alerts.json
"""

import re
import json
import argparse
import ipaddress
from datetime import datetime, time
from collections import defaultdict
from pathlib import Path


# ── Configuration ─────────────────────────────────────────────────────────────

THRESHOLDS = {
    "brute_force_window_seconds": 60,
    "brute_force_max_attempts": 10,
    "high_freq_rps": 50,          # requests per 10s window = suspicious
    "alert_outside_hours": True,
    "business_hours_start": time(7, 0),
    "business_hours_end": time(20, 0),
}

SUSPICIOUS_AGENTS = [
    r"sqlmap", r"nikto", r"nmap", r"masscan", r"nessus",
    r"burpsuite", r"dirbuster", r"gobuster", r"metasploit",
    r"python-requests/2\.[01]", r"curl/7\.[0-4]",
    r"<script", r"\.\./",
]

TRAVERSAL_PATTERNS = [
    r"\.\./", r"%2e%2e", r"\.\.%2f", r"%2e%2e%2f",
    r"/etc/passwd", r"/etc/shadow", r"/proc/self",
    r"cmd\.exe", r"powershell", r"eval\(", r"base64_decode",
]

ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

APACHE_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?'
)

AUTH_PATTERN = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+) (?P<time>\S+) \S+ sshd\[.*?\]: '
    r'(?P<event>Failed|Accepted|Invalid) (?:password|publickey|user) '
    r'(?:for (?:invalid user )?)?(?P<user>\S+) from (?P<ip>\S+)'
)


def parse_apache_line(line: str) -> dict | None:
    m = APACHE_PATTERN.match(line)
    if not m:
        return None
    try:
        dt = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        dt = None
    return {
        "ip": m.group("ip"),
        "timestamp": dt,
        "method": m.group("method"),
        "path": m.group("path"),
        "status": int(m.group("status")),
        "agent": m.group("agent") or "",
        "raw": line.strip(),
    }


def parse_auth_line(line: str) -> dict | None:
    m = AUTH_PATTERN.match(line)
    if not m:
        return None
    return {
        "ip": m.group("ip"),
        "user": m.group("user"),
        "event": m.group("event"),
        "raw": line.strip(),
        "timestamp": None,
    }


class AlertEngine:
    def __init__(self):
        self.alerts = []
        self._ip_requests: dict[str, list[datetime]] = defaultdict(list)
        self._ip_failures: dict[str, list[datetime]] = defaultdict(list)
        self._seen_ips: set = set()

    def _add_alert(self, severity: str, category: str, ip: str, detail: str, raw: str):
        alert = {
            "severity": severity,
            "category": category,
            "source_ip": ip,
            "detail": detail,
            "raw_log": raw,
            "detected_at": datetime.utcnow().isoformat() + "Z",
        }
        self.alerts.append(alert)
        icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "⚪")
        print(f"  {icon} [{severity}] {category} — {ip} — {detail}")

    def check_apache(self, entry: dict):
        ip = entry["ip"]
        path = entry["path"]
        method = entry["method"]
        agent = entry["agent"].lower()
        status = entry["status"]
        ts = entry["timestamp"]

        if method not in ALLOWED_METHODS:
            self._add_alert("HIGH", "Suspicious HTTP Method", ip,
                            f"Method '{method}' on {path}", entry["raw"])

        for pat in TRAVERSAL_PATTERNS:
            if re.search(pat, path, re.IGNORECASE):
                self._add_alert("HIGH", "Path Traversal / Injection Attempt", ip,
                                f"Pattern '{pat}' in path: {path}", entry["raw"])
                break

        for pat in SUSPICIOUS_AGENTS:
            if re.search(pat, agent, re.IGNORECASE):
                self._add_alert("HIGH", "Malicious User Agent", ip,
                                f"Agent matched '{pat}': {agent[:80]}", entry["raw"])
                break

        if status in (400, 403, 404):
            if ts:
                self._ip_requests[ip].append(ts)
                window = [t for t in self._ip_requests[ip]
                          if (ts - t).total_seconds() <= 10]
                self._ip_requests[ip] = window
                if len(window) >= THRESHOLDS["high_freq_rps"]:
                    if ip not in self._seen_ips:
                        self._seen_ips.add(ip)
                        self._add_alert("MEDIUM", "High-Frequency Error Requests", ip,
                                        f"{len(window)} {status}s in 10s window", entry["raw"])

        if ts and THRESHOLDS["alert_outside_hours"]:
            lt = ts.time().replace(tzinfo=None)
            if not (THRESHOLDS["business_hours_start"] <= lt <= THRESHOLDS["business_hours_end"]):
                self._add_alert("LOW", "After-Hours Access", ip,
                                f"Request at {lt} to {path}", entry["raw"])

    def check_auth(self, entry: dict):
        ip = entry["ip"]
        if entry["event"] == "Failed":
            self._ip_failures[ip].append(datetime.utcnow())
            count = len(self._ip_failures[ip])
            if count == THRESHOLDS["brute_force_max_attempts"]:
                self._add_alert("HIGH", "Brute Force Login Attempt", ip,
                                f"{count} failed SSH logins for user '{entry['user']}'",
                                entry["raw"])
        elif entry["event"] == "Accepted":
            if len(self._ip_failures[ip]) >= 5:
                self._add_alert("HIGH", "Successful Login After Multiple Failures", ip,
                                f"Login succeeded for '{entry['user']}' after "
                                f"{len(self._ip_failures[ip])} failures",
                                entry["raw"])

    def summary(self) -> dict:
        counts = defaultdict(int)
        for a in self.alerts:
            counts[a["severity"]] += 1
        return {
            "total_alerts": len(self.alerts),
            "by_severity": dict(counts),
            "unique_source_ips": len({a["source_ip"] for a in self.alerts}),
            "alerts": self.alerts,
        }


def main():
    parser = argparse.ArgumentParser(description="Log Anomaly Detector — SOC Tool")
    parser.add_argument("--log", required=True, help="Path to log file")
    parser.add_argument("--format", choices=["apache", "auth"], default="apache")
    parser.add_argument("--output", default="alerts.json")
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args()

    engine = AlertEngine()

    if args.demo:
        demo_lines = [
            '192.168.1.50 - - [10/Jan/2024:03:22:11 +0000] "GET /admin/../../etc/passwd HTTP/1.1" 400 512 "-" "sqlmap/1.7"',
            '10.0.0.5 - - [10/Jan/2024:14:00:01 +0000] "POST /login HTTP/1.1" 401 256 "-" "Mozilla/5.0"',
            '203.0.113.99 - - [10/Jan/2024:02:15:00 +0000] "TRACE / HTTP/1.1" 200 128 "-" "curl/7.1"',
        ]
        print("\n🔍 Running in DEMO mode...\n")
        for line in demo_lines:
            entry = parse_apache_line(line)
            if entry:
                engine.check_apache(entry)
    else:
        log_path = Path(args.log)
        if not log_path.exists():
            print(f"❌ Log file not found: {args.log}")
            return
        parse_fn = parse_apache_line if args.format == "apache" else parse_auth_line
        check_fn = engine.check_apache if args.format == "apache" else engine.check_auth
        print(f"\n🔍 Analyzing {log_path.name}...\n")
        with log_path.open() as f:
            for line in f:
                entry = parse_fn(line)
                if entry:
                    check_fn(entry)

    result = engine.summary()
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2, default=str)

    print(f"\n{'─'*50}")
    print(f"  📊 Total Alerts : {result['total_alerts']}")
    print(f"  🔴 HIGH         : {result['by_severity'].get('HIGH', 0)}")
    print(f"  🟡 MEDIUM       : {result['by_severity'].get('MEDIUM', 0)}")
    print(f"  🔵 LOW          : {result['by_severity'].get('LOW', 0)}")
    print(f"  💾 Saved to     : {args.output}")
    print(f"{'─'*50}\n")


if __name__ == "__main__":
    main()
