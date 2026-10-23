import json
from pathlib import Path

from threat_hunting.detection_engine import detect_threats


def test_alerts_include_correlation_metadata():
    events = json.loads(
        Path("logs/security_events.json").read_text(encoding="utf-8")
    )
    alerts = detect_threats(events)

    assert alerts, "Expected the sample log to generate alerts"

    repeated = next(
        alert for alert in alerts
        if alert["rule"] == "Repeated Login Failures"
    )

    assert repeated["affected_hosts"]
    assert repeated["first_timestamp"]
    assert repeated["last_timestamp"]

    for rule in (
        "Success After Repeated Failures",
        "Suspicious Command Execution",
        "Download and Outbound Connection",
    ):
        alert = next(item for item in alerts if item["rule"] == rule)
        assert alert.get("timestamp"), f"Missing timestamp for {rule}"
