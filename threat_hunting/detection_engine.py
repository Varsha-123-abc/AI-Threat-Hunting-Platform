
from datetime import datetime, timedelta, timezone
import json
from collections import Counter, defaultdict
from pathlib import Path

LOG_FILE = Path("logs/security_events.json")


# MITRE ATT&CK mappings for the current detection rules.
# These mappings are investigative hypotheses, not proof of compromise.
MITRE_MAPPINGS = {
    "Repeated Login Failures": {
        "mitre_technique_id": "T1110",
        "mitre_technique": "Brute Force",
        "mitre_tactic": "Credential Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1110/"
    },
    "Success After Repeated Failures": {
        "mitre_technique_id": "T1110",
        "mitre_technique": "Brute Force",
        "mitre_tactic": "Credential Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1110/"
    },
    "Suspicious Command Execution": {
        "mitre_technique_id": "T1059",
        "mitre_technique": "Command and Scripting Interpreter",
        "mitre_tactic": "Execution",
        "mitre_url": "https://attack.mitre.org/techniques/T1059/"
    },
    "Download and Outbound Connection": {
        "mitre_technique_id": "T1105",
        "mitre_technique": "Ingress Tool Transfer",
        "mitre_tactic": "Command and Control",
        "mitre_url": "https://attack.mitre.org/techniques/T1105/"
    }
}


def load_events():
    with LOG_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def calculate_threat_score(alert):
    """Calculate a transparent rule-based score between 0 and 100."""

    severity_scores = {
        "Critical": 85,
        "High": 70,
        "Medium": 45,
        "Low": 20
    }

    score = severity_scores.get(alert.get("severity", "Low"), 20)
    rule = alert.get("rule", "")

    if rule == "Repeated Login Failures":
        count = alert.get("count", 0)
        if count >= 10:
            score += 15
        elif count >= 5:
            score += 10

    elif rule == "Success After Repeated Failures":
        score += 10

    elif rule == "Download and Outbound Connection":
        score += 10

    return min(score, 100)


def detect_threats(events):
    alerts = []
    failures_by_ip = Counter()
    events_by_host = defaultdict(list)

    for event in events:
        events_by_host[event["host"]].append(event)

        if event["event_type"] == "login_failure":
            failures_by_ip[event["source_ip"]] += 1

    # Rule 1: Repeated failed logins from one IP within 30-minute windows.
    login_failures_by_ip = defaultdict(list)
    for event in events:
        if event.get("event_type") == "login_failure":
            login_failures_by_ip[event.get("source_ip")].append(event)

    for ip, failures in login_failures_by_ip.items():
        failures.sort(key=lambda event: str(event.get("timestamp", "")))
        window = []
        window_start = None

        for event in failures:
            timestamp = event.get("timestamp")
            current_time = None

            if timestamp:
                try:
                    current_time = datetime.fromisoformat(
                        str(timestamp).replace("Z", "+00:00")
                    )
                except ValueError:
                    current_time = None

            if window and current_time is not None and window_start is not None:
                try:
                    elapsed = (current_time - window_start).total_seconds()
                except TypeError:
                    elapsed = 0

                if elapsed > 30 * 60:
                    if len(window) >= 3:
                        affected_hosts = sorted({
                            item.get("host", "Unknown") for item in window
                        })
                        alerts.append({
                            "rule": "Repeated Login Failures",
                            "severity": "High",
                            "host": affected_hosts[0] if len(affected_hosts) == 1 else "Multiple",
                            "source_ip": ip,
                            "count": len(window),
                            "affected_hosts": affected_hosts,
                            "first_timestamp": window[0].get("timestamp"),
                            "last_timestamp": window[-1].get("timestamp"),
                            "description": (
                                f"{len(window)} failed logins from {ip}; "
                                "possible brute-force activity."
                            )
                        })
                    window = []
                    window_start = None

            window.append(event)
            if current_time is not None and window_start is None:
                window_start = current_time

        if len(window) >= 3:
            affected_hosts = sorted({
                item.get("host", "Unknown") for item in window
            })
            alerts.append({
                "rule": "Repeated Login Failures",
                "severity": "High",
                "host": affected_hosts[0] if len(affected_hosts) == 1 else "Multiple",
                "source_ip": ip,
                "count": len(window),
                "affected_hosts": affected_hosts,
                "first_timestamp": window[0].get("timestamp"),
                "last_timestamp": window[-1].get("timestamp"),
                "description": (
                    f"{len(window)} failed logins from {ip}; "
                    "possible brute-force activity."
                )
            })

    # Rule 2: Successful login after repeated failures
    for host, host_events in events_by_host.items():
        failed_ips = Counter()

        for event in host_events:
            ip = event["source_ip"]

            if event["event_type"] == "login_failure":
                failed_ips[ip] += 1

            elif (
                event["event_type"] == "login_success"
                and failed_ips[ip] >= 3
            ):
                alerts.append({
                    "rule": "Success After Repeated Failures",
                    "severity": "Critical",
                    "host": host,
                    "user": event["user"],
                    "source_ip": ip,
                    "timestamp": event.get("timestamp"),
                    "description": (
                        "A successful login followed repeated failures "
                        "from the same IP."
                    )
                })

    # Rule 3: Suspicious command execution
    for event in events:
        if event["event_type"] == "suspicious_command":
            alerts.append({
                "rule": "Suspicious Command Execution",
                "severity": "Medium",
                "host": event["host"],
                "user": event["user"],
                "source_ip": event["source_ip"],
                "timestamp": event.get("timestamp"),
                "description": (
                    f"Suspicious process: {event['process']}"
                )
            })

    # Rule 4: File download followed by an outbound connection
    def parse_event_time(event):
        """Return a timezone-normalized timestamp, or None if invalid."""
        value = event.get("timestamp")

        if not value or not isinstance(value, str):
            return None

        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None

        # Treat timestamps without a timezone as UTC.
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    for host, host_events in events_by_host.items():
        downloads = [
            event for event in host_events
            if event.get("event_type") == "file_download"
        ]

        connections = [
            event for event in host_events
            if event.get("event_type") == "outbound_connection"
        ]

        for download in downloads:
            download_time = parse_event_time(download)
            if download_time is None:
                continue

            for connection in connections:
                connection_time = parse_event_time(connection)
                if connection_time is None:
                    continue

                same_ip = (
                    download.get("source_ip")
                    == connection.get("source_ip")
                )
                elapsed = connection_time - download_time
                within_window = (
                    timedelta(0)
                    <= elapsed
                    <= timedelta(minutes=15)
                )

                if same_ip and within_window:
                    alerts.append({
                        "rule": "Download and Outbound Connection",
                        "severity": "High",
                        "host": host,
                        "user": download.get("user", "Unknown"),
                        "source_ip": download.get("source_ip"),
                        "timestamp": connection.get("timestamp"),
                        "description": (
                            "A file download was followed by an "
                            "outbound connection from the same IP "
                            "within 15 minutes."
                        )
                    })

    # Add MITRE mapping, threat score, and priority to each alert.
    for alert in alerts:
        mapping = MITRE_MAPPINGS.get(alert["rule"], {})

        alert.update(mapping)

        score = calculate_threat_score(alert)
        alert["threat_score"] = score

        if score >= 85:
            alert["priority"] = "Critical"
        elif score >= 70:
            alert["priority"] = "High"
        elif score >= 40:
            alert["priority"] = "Medium"
        else:
            alert["priority"] = "Low"

    return alerts


if __name__ == "__main__":
    events = load_events()
    alerts = detect_threats(events)

    print(f"\nEvents analyzed: {len(events)}")
    print(f"Alerts generated: {len(alerts)}\n")

    for number, alert in enumerate(alerts, start=1):
        print(f"Alert #{number}")
        print(f"Rule: {alert['rule']}")
        print(f"Severity: {alert['severity']}")
        print(f"Threat score: {alert['threat_score']}/100")
        print(f"Priority: {alert['priority']}")
        print(
            "MITRE ATT&CK:",
            alert.get("mitre_technique_id", "Unmapped"),
            "-",
            alert.get("mitre_technique", "Unmapped")
        )
        print(f"Tactic: {alert.get('mitre_tactic', 'Unknown')}")
        print(f"Reference: {alert.get('mitre_url', 'N/A')}")
        print(f"Details: {alert['description']}")
        print("-" * 50)
