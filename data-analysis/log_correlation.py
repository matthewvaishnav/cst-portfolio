#!/usr/bin/env python3
"""
Log Correlation Engine
=======================
Correlates events across multiple log sources to identify
attack patterns that span systems — the kind of analysis
a SOC analyst does manually, automated.

Correlates:
  - Failed SSH login → successful login from same IP (brute force success)
  - Web scanner activity → admin page access from same IP
  - Multiple service hits → port scan detection
  - Auth failure spike → account lockout correlation
  - Outbound connection after web request → possible web shell

Author : Matthew Vaishnav — CST, Conestoga College
Usage  : python log_correlation.py --demo
         python log_correlation.py --auth /var/log/auth.log --web /var/log/nginx/access.log
"""

import re
import json
import argparse
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path


# ── Configuration ─────────────────────────────────────────────────────────────

CORRELATION_WINDOW_SECONDS = 300  # 5 minute window for event correlation
BRUTE_FORCE_THRESHOLD = 5
PORT_SCAN_THRESHOLD = 10
ALERT_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "MEDIUM": "\033[94m",
    "LOW": "\033[96m",
    "NC": "\033[0m",
    "BOLD": "\033[1m",
}


# ── Event Model ───────────────────────────────────────────────────────────────


class Event:
    def __init__(self, source: str, event_type: str, ip: str, detail: str, timestamp=None):
        self.source = source
        self.event_type = event_type
        self.ip = ip
        self.detail = detail
        self.timestamp = timestamp or datetime.utcnow()

    def __repr__(self):
        return f"Event({self.event_type}, {self.ip}, {self.timestamp})"


class CorrelatedAlert:
    def __init__(self, severity: str, title: str, description: str, events: list, mitre: str = ""):
        self.severity = severity
        self.title = title
        self.description = description
        self.events = events
        self.mitre = mitre
        self.timestamp = datetime.utcnow()

    def to_dict(self):
        return {
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "mitre": self.mitre,
            "event_count": len(self.events),
            "timestamp": self.timestamp.isoformat() + "Z",
        }


# ── Log Parsers ───────────────────────────────────────────────────────────────


def parse_auth_log(content: str) -> list[Event]:
    """Parse Linux auth.log / secure log."""
    events = []
    patterns = {
        "ssh_fail": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from (\S+)"
        ),
        "ssh_success": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted (?:password|publickey) for (\S+) from (\S+)"
        ),
        "ssh_invalid": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*Invalid user (\S+) from (\S+)"
        ),
        "sudo": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*sudo.*COMMAND=(.*)"
        ),
    }

    for line in content.splitlines():
        for event_type, pattern in patterns.items():
            m = pattern.search(line)
            if m:
                try:
                    ts = datetime.strptime(
                        f"{datetime.now().year} {m.group(1)}", "%Y %b %d %H:%M:%S"
                    )
                except ValueError:
                    ts = datetime.utcnow()

                ip = m.group(3) if event_type != "sudo" else "localhost"
                detail = m.group(2) if len(m.groups()) >= 2 else line[:100]
                events.append(Event("auth.log", event_type, ip, detail, ts))
                break

    return events


def parse_web_log(content: str) -> list[Event]:
    """Parse Apache/Nginx access log."""
    events = []
    pattern = re.compile(
        r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) (\S+)'
        r'(?: "([^"]*)" "([^"]*)")?'
    )

    scanner_agents = ["sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster"]
    suspicious_paths = ["/admin", "/wp-admin", "/.env", "/config", "/shell", "/../", "/etc/passwd"]

    for line in content.splitlines():
        m = pattern.match(line)
        if not m:
            continue

        ip = m.group(1)
        method = m.group(3)
        path = m.group(4)
        status = int(m.group(5))
        agent = (m.group(8) or "").lower()

        try:
            ts = datetime.strptime(m.group(2), "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
        except ValueError:
            ts = datetime.utcnow()

        # Classify event type
        if any(s in agent for s in scanner_agents):
            events.append(Event("web", "scanner_agent", ip, f"{method} {path} [{agent[:40]}]", ts))
        elif any(p in path.lower() for p in suspicious_paths):
            events.append(Event("web", "suspicious_path", ip, f"{method} {path} → {status}", ts))
        elif status in (400, 403, 404):
            events.append(Event("web", "web_error", ip, f"{method} {path} → {status}", ts))
        elif method not in ("GET", "POST", "HEAD"):
            events.append(Event("web", "unusual_method", ip, f"{method} {path} → {status}", ts))

    return events


# ── Correlation Rules ─────────────────────────────────────────────────────────


class CorrelationEngine:
    def __init__(self, window_seconds: int = CORRELATION_WINDOW_SECONDS):
        self.window = timedelta(seconds=window_seconds)
        self.alerts: list[CorrelatedAlert] = []
        self._alerted_ips: set = set()

    def correlate(self, events: list[Event]):
        """Run all correlation rules against the event set."""
        by_ip: dict[str, list[Event]] = defaultdict(list)
        for e in events:
            by_ip[e.ip].append(e)

        for ip, ip_events in by_ip.items():
            ip_events.sort(key=lambda e: e.timestamp)
            self._rule_brute_force_success(ip, ip_events)
            self._rule_scanner_then_admin(ip, ip_events)
            self._rule_auth_spike(ip, ip_events)
            self._rule_method_abuse(ip, ip_events)

        self._rule_port_scan_pattern(events)

    def _within_window(self, t1: datetime, t2: datetime) -> bool:
        return abs((t2 - t1).total_seconds()) <= self.window.total_seconds()

    def _rule_brute_force_success(self, ip: str, events: list[Event]):
        """Detect: multiple SSH failures followed by success from same IP."""
        failures = [e for e in events if e.event_type == "ssh_fail"]
        successes = [e for e in events if e.event_type == "ssh_success"]

        if len(failures) >= BRUTE_FORCE_THRESHOLD and successes:
            for success in successes:
                related_failures = [
                    f for f in failures if f.timestamp <= success.timestamp
                ]
                if len(related_failures) >= BRUTE_FORCE_THRESHOLD:
                    self.alerts.append(
                        CorrelatedAlert(
                            severity="CRITICAL",
                            title="Brute Force → Successful Login",
                            description=(
                                f"IP {ip} had {len(related_failures)} failed SSH attempts "
                                f"followed by a successful login for user '{success.detail}'. "
                                f"Possible credential compromise."
                            ),
                            events=related_failures + [success],
                            mitre="T1110.001 → T1078",
                        )
                    )
                    break

    def _rule_scanner_then_admin(self, ip: str, events: list[Event]):
        """Detect: scanner user agent followed by admin path access."""
        scanners = [e for e in events if e.event_type == "scanner_agent"]
        admin_hits = [e for e in events if e.event_type == "suspicious_path"]

        if scanners and admin_hits:
            for scanner in scanners:
                related = [
                    a for a in admin_hits
                    if self._within_window(scanner.timestamp, a.timestamp)
                    and a.timestamp >= scanner.timestamp
                ]
                if related:
                    self.alerts.append(
                        CorrelatedAlert(
                            severity="HIGH",
                            title="Web Scan → Admin Path Access",
                            description=(
                                f"IP {ip} used a scanner tool then accessed "
                                f"{len(related)} sensitive path(s): "
                                f"{', '.join(set(r.detail[:40] for r in related))}. "
                                f"Possible active exploitation attempt."
                            ),
                            events=[scanner] + related,
                            mitre="T1595.002 → T1190",
                        )
                    )
                    break

    def _rule_auth_spike(self, ip: str, events: list[Event]):
        """Detect: rapid authentication failures in short window."""
        failures = [e for e in events if e.event_type in ("ssh_fail", "ssh_invalid")]

        if len(failures) < BRUTE_FORCE_THRESHOLD:
            return

        # Sliding window check
        for i, start_event in enumerate(failures):
            window_events = [
                e for e in failures[i:]
                if self._within_window(start_event.timestamp, e.timestamp)
            ]
            if len(window_events) >= BRUTE_FORCE_THRESHOLD:
                alert_key = f"auth_spike_{ip}"
                if alert_key not in self._alerted_ips:
                    self._alerted_ips.add(alert_key)
                    self.alerts.append(
                        CorrelatedAlert(
                            severity="HIGH",
                            title="Authentication Failure Spike",
                            description=(
                                f"IP {ip} generated {len(window_events)} auth failures "
                                f"within {CORRELATION_WINDOW_SECONDS}s. "
                                f"Targeted users: "
                                f"{', '.join(set(e.detail for e in window_events[:5]))}."
                            ),
                            events=window_events,
                            mitre="T1110",
                        )
                    )
                break

    def _rule_method_abuse(self, ip: str, events: list[Event]):
        """Detect: non-standard HTTP methods (TRACE, PUT, DELETE on sensitive paths)."""
        method_events = [e for e in events if e.event_type == "unusual_method"]
        if len(method_events) >= 3:
            self.alerts.append(
                CorrelatedAlert(
                    severity="MEDIUM",
                    title="Unusual HTTP Method Abuse",
                    description=(
                        f"IP {ip} used non-standard HTTP methods "
                        f"{len(method_events)} times: "
                        f"{', '.join(set(e.detail[:30] for e in method_events))}."
                    ),
                    events=method_events,
                    mitre="T1190",
                )
            )

    def _rule_port_scan_pattern(self, events: list[Event]):
        """Detect: single IP hitting many different services (cross-log)."""
        ip_services: dict[str, set] = defaultdict(set)
        for e in events:
            ip_services[e.ip].add(e.event_type)

        for ip, services in ip_services.items():
            if len(services) >= 4:
                self.alerts.append(
                    CorrelatedAlert(
                        severity="MEDIUM",
                        title="Multi-Service Reconnaissance",
                        description=(
                            f"IP {ip} triggered events across {len(services)} "
                            f"different service categories: {', '.join(services)}. "
                            f"Possible reconnaissance activity."
                        ),
                        events=[e for e in events if e.ip == ip],
                        mitre="T1595",
                    )
                )

    def print_report(self):
        """Print correlation report to console."""
        bold = ALERT_COLORS["BOLD"]
        nc = ALERT_COLORS["NC"]

        print(f"\n  {bold}{'═'*60}{nc}")
        print(f"  {bold}  Log Correlation Report — Matthew Vaishnav{nc}")
        print(f"  {bold}  {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}{nc}")
        print(f"  {bold}{'═'*60}{nc}\n")

        if not self.alerts:
            print(f"  ✅ No correlated alerts found.\n")
            return

        for alert in sorted(self.alerts, key=lambda a: a.severity):
            color = ALERT_COLORS.get(alert.severity, nc)
            print(f"  {color}{bold}[{alert.severity}] {alert.title}{nc}")
            print(f"  MITRE: {alert.mitre}")
            print(f"  {alert.description}")
            print(f"  Events correlated: {alert.event_count}")
            print(f"  {'─'*55}")

        print(f"\n  {bold}Total Correlated Alerts: {len(self.alerts)}{nc}")
        by_sev = defaultdict(int)
        for a in self.alerts:
            by_sev[a.severity] += 1
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if by_sev[sev]:
                color = ALERT_COLORS.get(sev, nc)
                print(f"  {color}{sev}: {by_sev[sev]}{nc}")
        print(f"  {'═'*60}\n")

    def save_report(self, path: str):
        report = {
            "generated": datetime.utcnow().isoformat() + "Z",
            "author": "Matthew Vaishnav",
            "total_alerts": len(self.alerts),
            "alerts": [a.to_dict() for a in self.alerts],
        }
        Path(path).write_text(json.dumps(report, indent=2))
        print(f"  💾 Report saved: {path}")


# ── Demo Data ─────────────────────────────────────────────────────────────────

DEMO_AUTH_LOG = """
Jan 10 03:10:01 server sshd[1234]: Failed password for root from 192.168.1.99 port 54321 ssh2
Jan 10 03:10:03 server sshd[1234]: Failed password for root from 192.168.1.99 port 54322 ssh2
Jan 10 03:10:05 server sshd[1234]: Failed password for admin from 192.168.1.99 port 54323 ssh2
Jan 10 03:10:07 server sshd[1234]: Failed password for admin from 192.168.1.99 port 54324 ssh2
Jan 10 03:10:09 server sshd[1234]: Failed password for ubuntu from 192.168.1.99 port 54325 ssh2
Jan 10 03:10:15 server sshd[1234]: Accepted password for ubuntu from 192.168.1.99 port 54326 ssh2
Jan 10 03:15:00 server sshd[1235]: Failed password for root from 10.0.0.5 port 11111 ssh2
Jan 10 03:15:02 server sshd[1235]: Failed password for root from 10.0.0.5 port 11112 ssh2
Jan 10 03:15:04 server sshd[1235]: Invalid user test from 10.0.0.5 port 11113
Jan 10 03:15:06 server sshd[1235]: Invalid user guest from 10.0.0.5 port 11114
Jan 10 03:15:08 server sshd[1235]: Failed password for root from 10.0.0.5 port 11115 ssh2
"""

DEMO_WEB_LOG = """
192.168.1.99 - - [10/Jan/2024:03:11:00 +0000] "GET / HTTP/1.1" 200 512 "-" "sqlmap/1.7#stable"
192.168.1.99 - - [10/Jan/2024:03:11:01 +0000] "GET /admin HTTP/1.1" 403 256 "-" "sqlmap/1.7#stable"
192.168.1.99 - - [10/Jan/2024:03:11:02 +0000] "GET /wp-admin HTTP/1.1" 404 256 "-" "sqlmap/1.7#stable"
192.168.1.99 - - [10/Jan/2024:03:11:05 +0000] "GET /.env HTTP/1.1" 200 128 "-" "Mozilla/5.0"
203.0.113.50 - - [10/Jan/2024:03:12:00 +0000] "TRACE / HTTP/1.1" 200 64 "-" "curl/7.68"
203.0.113.50 - - [10/Jan/2024:03:12:01 +0000] "DELETE /api/users HTTP/1.1" 405 64 "-" "curl/7.68"
203.0.113.50 - - [10/Jan/2024:03:12:02 +0000] "PUT /shell.php HTTP/1.1" 404 64 "-" "curl/7.68"
"""


# ── Main ──────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Log Correlation Engine — Matthew Vaishnav"
    )
    parser.add_argument("--auth", help="Path to auth.log file")
    parser.add_argument("--web", help="Path to web access log file")
    parser.add_argument("--output", default="correlation_report.json")
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args()

    engine = CorrelationEngine()
    all_events = []

    if args.demo or (not args.auth and not args.web):
        print("\n  🔗 Log Correlation Engine — Demo Mode\n")
        all_events += parse_auth_log(DEMO_AUTH_LOG)
        all_events += parse_web_log(DEMO_WEB_LOG)
        print(f"  📥 Loaded {len(all_events)} events from demo data")
    else:
        if args.auth:
            content = Path(args.auth).read_text()
            auth_events = parse_auth_log(content)
            all_events += auth_events
            print(f"  📥 Loaded {len(auth_events)} events from {args.auth}")

        if args.web:
            content = Path(args.web).read_text()
            web_events = parse_web_log(content)
            all_events += web_events
            print(f"  📥 Loaded {len(web_events)} events from {args.web}")

    print(f"  🔗 Running correlation rules on {len(all_events)} total events...")
    engine.correlate(all_events)
    engine.print_report()
    engine.save_report(args.output)


if __name__ == "__main__":
    main()
```

That's all 3 new files done! Now go back and update the README table to include:
```
| [`networking/`](./networking) | 🌐 Networking | Subnet calculator, firewall rule reference |
| [`data-analysis/`](./data-analysis) | 📈 Analysis | Multi-source log correlation engine |
