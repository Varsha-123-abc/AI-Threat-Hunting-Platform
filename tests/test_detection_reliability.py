from datetime import datetime, timedelta, timezone

from threat_hunting.detection_engine import detect_threats


def make_event(event_type, timestamp, source_ip="192.0.2.10",
               host="test-host", user="analyst", **extra):
    event = {
        "event_type": event_type,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "host": host,
        "user": user,
    }
    event.update(extra)
    return event


def test_malformed_download_timestamp_does_not_crash():
    events = [
        make_event(
            "file_download",
            "not-a-valid-timestamp",
            process="curl",
        ),
        make_event(
            "outbound_connection",
            "2026-10-23T10:05:00+00:00",
            destination_ip="198.51.100.20",
        ),
    ]

    alerts = detect_threats(events)
    assert isinstance(alerts, list)


def test_failed_logins_separated_by_more_than_30_minutes_do_not_correlate():
    start = datetime(2026, 10, 23, 10, 0, tzinfo=timezone.utc)
    events = [
        make_event(
            "login_failure",
            (start + timedelta(minutes=offset)).isoformat(),
        )
        for offset in (0, 5, 40, 45)
    ]

    alerts = detect_threats(events)

    assert not any(
        alert["rule"] == "Repeated Login Failures"
        for alert in alerts
    )


def test_download_correlation_requires_connection_within_15_minutes():
    start = datetime(2026, 10, 23, 10, 0, tzinfo=timezone.utc)
    events = [
        make_event(
            "file_download",
            start.isoformat(),
            process="curl",
        ),
        make_event(
            "outbound_connection",
            (start + timedelta(minutes=16)).isoformat(),
            destination_ip="198.51.100.20",
        ),
    ]

    alerts = detect_threats(events)

    assert not any(
        alert["rule"] == "Download and Outbound Connection"
        for alert in alerts
    )
