
import sys
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database import initialize_database, save_incident
from threat_hunting.detection_engine import load_events, detect_threats

CORRELATION_GAP_MINUTES = 30


def get_value(item, *keys, default="Unknown"):
    """Return the first non-empty value from a dictionary."""
    if not isinstance(item, dict):
        return default
    for key in keys:
        value = item.get(key)
        if value is not None and value != "":
            return value
    return default


def parse_timestamp(value):
    """Parse an ISO timestamp, returning None when unavailable."""
    if value in (None, "", "Unknown"):
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (TypeError, ValueError):
        return None


def event_timestamp(item):
    return get_value(item, "timestamp", "time", "datetime", default="")


def event_host(item):
    return get_value(item, "host", "hostname", "computer", default="Unknown")


def event_ip(item):
    return get_value(item, "source_ip", "src_ip", "ip", default="Unknown")


def create_incident_id(host, source_ip, first_timestamp):
    """Generate a stable ID for the same host/IP/event-window start."""
    identity = f"{host}|{source_ip}|{first_timestamp}"
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:10].upper()
    return f"INC-{digest}"


def calculate_incident_priority(score):
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def split_event_groups(events, gap_minutes=CORRELATION_GAP_MINUTES):
    """Group by host/IP and split when consecutive valid timestamps exceed the gap."""
    base_groups = defaultdict(list)
    for event in events:
        base_groups[(event_host(event), event_ip(event))].append(event)

    result = []
    max_gap = gap_minutes * 60

    for (host, source_ip), host_events in base_groups.items():
        host_events.sort(key=lambda e: (
            parse_timestamp(event_timestamp(e)) is None,
            parse_timestamp(event_timestamp(e)) or datetime.max.replace(
                tzinfo=timezone.utc
            ),
            str(event_timestamp(e)),
        ))

        current = []
        previous_time = None

        for event in host_events:
            current_time = parse_timestamp(event_timestamp(event))

            if (
                current
                and current_time is not None
                and previous_time is not None
                and (current_time - previous_time).total_seconds() > max_gap
            ):
                result.append((host, source_ip, current))
                current = []

            current.append(event)
            if current_time is not None:
                previous_time = current_time

        if current:
            result.append((host, source_ip, current))

    return result


def alert_matches_group(alert, host, source_ip, group_events):
    """Match an alert by host/IP and, when available, its time information."""
    alert_host = get_value(
        alert, "host", "hostname", "computer", default="Unknown"
    )
    affected_hosts = alert.get("affected_hosts", [])
    if isinstance(affected_hosts, str):
        affected_hosts = [affected_hosts]

    host_matches = (
        alert_host == host
        or host in affected_hosts
        or alert_host in ("Unknown", "")
    )
    if not host_matches:
        return False

    alert_ip = get_value(alert, "source_ip", "src_ip", "ip", default="Unknown")
    if alert_ip not in ("Unknown", "", source_ip):
        return False

    event_times = [
        parse_timestamp(event_timestamp(event))
        for event in group_events
    ]
    event_times = [value for value in event_times if value is not None]

    # Alerts without timestamps retain backward-compatible matching.
    alert_start = parse_timestamp(
        alert.get("first_timestamp") or alert.get("timestamp")
    )
    alert_end = parse_timestamp(
        alert.get("last_timestamp") or alert.get("timestamp")
    )

    if not event_times or (alert_start is None and alert_end is None):
        return True

    group_start = min(event_times)
    group_end = max(event_times)

    if alert_start is None:
        alert_start = alert_end
    if alert_end is None:
        alert_end = alert_start

    return alert_start <= group_end and alert_end >= group_start


def correlate_incidents(events, alerts):
    """Correlate host/IP event windows with matching detection alerts."""
    incidents = []

    for host, source_ip, group_events in split_event_groups(events):
        incident_alerts = [
            alert for alert in alerts
            if alert_matches_group(alert, host, source_ip, group_events)
        ]

        if not incident_alerts:
            continue

        group_events.sort(key=lambda event: str(event_timestamp(event)))
        first_timestamp = event_timestamp(group_events[0]) or "Unknown"
        incident_id = create_incident_id(host, source_ip, first_timestamp)
        saved_alerts = [dict(alert) for alert in incident_alerts]

        severity_scores = {
            "Critical": 85, "High": 70, "Medium": 45, "Low": 20
        }
        threat_score = max(
            (
                int(alert.get("threat_score") or severity_scores.get(
                    alert.get("severity", "Low"), 20
                ))
                for alert in saved_alerts
            ),
            default=0,
        )
        priority = calculate_incident_priority(threat_score)

        severity_order = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        severity = max(
            (str(alert.get("severity", "Low")) for alert in saved_alerts),
            key=lambda value: severity_order.get(value, 0),
            default="Low",
        )

        timeline = []
        for event in group_events:
            timeline.append({
                "timestamp": event_timestamp(event),
                "event": get_value(
                    event, "event", "event_type", "action", "description",
                    default="Security event",
                ),
                "user": get_value(event, "user", "username"),
                "host": get_value(event, "host", "hostname", default=host),
                "source_ip": get_value(
                    event, "source_ip", "src_ip", "ip", default=source_ip
                ),
                "process": get_value(
                    event, "process", "process_name", "Image",
                    default="Not recorded",
                ),
                "process_id": get_value(
                    event, "process_id", "pid", "ProcessId",
                    default="Not recorded",
                ),
                "parent_process": get_value(
                    event, "parent_process", "parent_process_name",
                    "ParentImage", default="Not recorded",
                ),
                "command_line": get_value(
                    event, "command_line", "cmdline", "CommandLine",
                    "command", default="Not recorded",
                ),
                "details": dict(event),
            })

        highest_alert = max(
            saved_alerts,
            key=lambda alert: int(alert.get("threat_score") or 0),
            default=None,
        )
        risk_summary = (
            highest_alert.get("description")
            or highest_alert.get("rule")
            or "Suspicious activity detected; investigate the incident."
        )

        incidents.append({
            "incident_id": incident_id,
            "host": host,
            "severity": severity,
            "users": sorted({
                str(get_value(event, "user", "username"))
                for event in group_events
            }),
            "source_ips": [source_ip],
            "alerts": saved_alerts,
            "timeline": timeline,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "threat_score": threat_score,
            "priority": priority,
            "risk_summary": risk_summary,
        })

    return incidents


def main():
    print("[*] Initializing database...")
    initialize_database()

    print("[*] Loading security events...")
    events = load_events()
    if not events:
        print("[!] No security events found. Check your log file.")
        return

    print(f"[+] Loaded {len(events)} security events.")
    print("[*] Running threat detection...")
    alerts = detect_threats(events) or []
    print(f"[+] Detected {len(alerts)} alerts.")

    print("[*] Correlating events into incidents...")
    incidents = correlate_incidents(events, alerts)
    if not incidents:
        print("[!] No incidents were created.")
        return

    print("[*] Saving incidents to the database...")
    for incident in incidents:
        save_incident(incident)
        print(
            f"[+] {incident['incident_id']} | Host: {incident['host']} | "
            f"Score: {incident['threat_score']}/100 | "
            f"Priority: {incident['priority']} | "
            f"Alerts: {len(incident['alerts'])}"
        )

    print(f"\n[✓] Finished. Processed {len(incidents)} incidents.")


if __name__ == "__main__":
    main()
