
import json
from pathlib import Path

LOG_FILE = Path("logs/security_events.json")

events = [
    {
        "timestamp": "2026-10-14T09:00:00",
        "host": "web01",
        "user": "alice",
        "source_ip": "192.168.1.20",
        "event_type": "login_success",
        "process": "sshd",
        "details": "Normal user login"
    },
    {
        "timestamp": "2026-10-14T09:05:00",
        "host": "web01",
        "user": "admin",
        "source_ip": "203.0.113.50",
        "event_type": "login_failure",
        "process": "sshd",
        "details": "Invalid password"
    },
    {
        "timestamp": "2026-10-14T09:05:10",
        "host": "web01",
        "user": "admin",
        "source_ip": "203.0.113.50",
        "event_type": "login_failure",
        "process": "sshd",
        "details": "Invalid password"
    },
    {
        "timestamp": "2026-10-14T09:05:20",
        "host": "web01",
        "user": "admin",
        "source_ip": "203.0.113.50",
        "event_type": "login_failure",
        "process": "sshd",
        "details": "Invalid password"
    },
    {
        "timestamp": "2026-10-14T09:05:30",
        "host": "web01",
        "user": "admin",
        "source_ip": "203.0.113.50",
        "event_type": "login_success",
        "process": "sshd",
        "details": "Successful login after failures"
    },
    {
        "timestamp": "2026-10-14T09:06:00",
        "host": "web01",
        "user": "admin",
        "source_ip": "203.0.113.50",
        "event_type": "suspicious_command",
        "process": "whoami",
        "details": "Identity discovery command"
    },
    {
        "timestamp": "2026-10-14T09:07:00",
        "host": "web01",
        "user": "admin",
        "source_ip": "203.0.113.50",
        "event_type": "file_download",
        "process": "curl",
        "details": "Downloaded a simulated suspicious file"
    },
    {
        "timestamp": "2026-10-14T09:08:00",
        "host": "web01",
        "user": "admin",
        "source_ip": "203.0.113.50",
        "event_type": "outbound_connection",
        "process": "unknown",
        "details": "Connection to simulated external address"
    },
    {
        "timestamp": "2026-10-14T09:10:00",
        "host": "workstation01",
        "user": "bob",
        "source_ip": "192.168.1.25",
        "event_type": "login_success",
        "process": "sshd",
        "details": "Normal user login"
    }
]

LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

with LOG_FILE.open("w", encoding="utf-8") as file:
    json.dump(events, file, indent=4)

print(f"Generated {len(events)} synthetic security events.")
print(f"Saved to: {LOG_FILE}")
