from threat_hunting.incident_correlator import correlate_incidents


def make_event(timestamp, host="web01", source_ip="203.0.113.50",
               event_type="login_failure", user="analyst"):
    return {
        "timestamp": timestamp,
        "host": host,
        "source_ip": source_ip,
        "event_type": event_type,
        "user": user,
    }


def make_alert(host="web01", source_ip="203.0.113.50",
               rule="Repeated Login Failures", severity="High",
               **extra):
    alert = {
        "host": host,
        "source_ip": source_ip,
        "rule": rule,
        "severity": severity,
        "threat_score": 70,
        "description": "Test detection alert",
    }
    alert.update(extra)
    return alert


def test_matching_alert_creates_incident():
    events = [
        make_event("2026-10-14T09:05:00"),
        make_event("2026-10-14T09:06:00"),
    ]
    alerts = [make_alert()]

    incidents = correlate_incidents(events, alerts)

    assert len(incidents) == 1
    assert incidents[0]["host"] == "web01"
    assert len(incidents[0]["alerts"]) == 1
    assert len(incidents[0]["timeline"]) == 2


def test_multiple_host_alert_matches_affected_hosts():
    events = [
        make_event("2026-10-14T09:05:00", host="web01"),
        make_event("2026-10-14T09:06:00", host="db01"),
    ]
    alerts = [
        make_alert(
            host="Multiple",
            affected_hosts=["web01", "db01"],
        )
    ]

    incidents = correlate_incidents(events, alerts)

    assert {incident["host"] for incident in incidents} == {
        "web01", "db01"
    }
    assert all(incident["alerts"] for incident in incidents)


def test_events_more_than_30_minutes_apart_are_separate_incidents():
    events = [
        make_event("2026-10-14T09:00:00"),
        make_event("2026-10-14T10:00:00"),
    ]
    alerts = [
        make_alert(timestamp="2026-10-14T09:00:00"),
        make_alert(timestamp="2026-10-14T10:00:00"),
    ]

    incidents = correlate_incidents(events, alerts)

    assert len(incidents) == 2
    assert all(len(incident["timeline"]) == 1 for incident in incidents)
    assert incidents[0]["incident_id"] != incidents[1]["incident_id"]


def test_events_within_30_minutes_stay_in_one_incident():
    events = [
        make_event("2026-10-14T09:00:00"),
        make_event("2026-10-14T09:20:00"),
    ]
    alerts = [
        make_alert(timestamp="2026-10-14T09:00:00"),
        make_alert(timestamp="2026-10-14T09:20:00"),
    ]

    incidents = correlate_incidents(events, alerts)

    assert len(incidents) == 1
    assert len(incidents[0]["timeline"]) == 2


def test_incident_id_is_stable_for_same_event_group():
    events = [
        make_event("2026-10-14T09:00:00"),
        make_event("2026-10-14T09:05:00"),
    ]
    alerts = [make_alert()]

    first = correlate_incidents(events, alerts)
    second = correlate_incidents(events, alerts)

    assert first[0]["incident_id"] == second[0]["incident_id"]
