
import json
from pathlib import Path

from flask import (
    Flask,
    render_template,
    request,
    abort,
    send_file,
    redirect,
    url_for,
)

from database import (
    initialize_database,
    get_all_incidents,
    update_incident_status,
    add_investigation_note,
    get_investigation_notes,
    get_incident_audit_log,
)

from threat_hunting.report_generator import (
    generate_incident_pdf,
    load_incident_from_row,
)

app = Flask(__name__)


def prepare_incident(incident):
    """Convert JSON fields from SQLite into Python objects."""
    incident = dict(incident)

    for field in ("users", "source_ips", "alerts", "timeline"):
        value = incident.get(field, [])

        if isinstance(value, str):
            try:
                incident[field] = json.loads(value)
            except json.JSONDecodeError:
                incident[field] = []

    incident.setdefault("threat_score", 0)
    incident.setdefault("priority", "Low")
    incident.setdefault("risk_summary", "Not assessed")
    incident.setdefault("status", "New")
    return incident



@app.route("/")
def dashboard():
    initialize_database()

    all_incidents = [
        prepare_incident(item) for item in get_all_incidents()
    ]

    # Count incidents by severity
    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }

    # Count incidents by investigation status
    status_counts = {
        "New": 0,
        "Investigating": 0,
        "Resolved": 0,
    }

    for incident in all_incidents:
        severity = incident.get("severity", "Low")
        status = incident.get("status", "New")

        if severity in severity_counts:
            severity_counts[severity] += 1

        if status in status_counts:
            status_counts[status] += 1

    # Existing severity filter
    selected_severity = request.args.get("severity", "All")
    valid_severities = {
        "All", "Critical", "High", "Medium", "Low"
    }

    if selected_severity not in valid_severities:
        selected_severity = "All"

    # New status filter
    selected_status = request.args.get("status", "All")
    valid_statuses = {
        "All", "New", "Investigating", "Resolved"
    }

    if selected_status not in valid_statuses:
        selected_status = "All"

    incidents = all_incidents

    if selected_severity != "All":
        incidents = [
            incident for incident in incidents
            if incident.get("severity") == selected_severity
        ]

    if selected_status != "All":
        incidents = [
            incident for incident in incidents
            if incident.get("status", "New") == selected_status
        ]

    return render_template(
        "dashboard.html",
        incidents=incidents,
        severity_counts=severity_counts,
        status_counts=status_counts,
        selected_severity=selected_severity,
        selected_status=selected_status,
    )

@app.route("/incident/<incident_id>")
def incident_details(incident_id):
    rows = get_all_incidents()

    row = next(
        (
            item for item in rows
            if item["incident_id"] == incident_id
        ),
        None,
    )

    if row is None:
        abort(404)

    incident = prepare_incident(row)
    notes = get_investigation_notes(incident_id)
    audit_events = get_incident_audit_log(incident_id)

    return render_template(
        "incident.html",
        incident=incident,
        notes=notes,
        audit_events=audit_events,
    )

@app.route("/incident/<incident_id>/status", methods=["POST"])
def update_status(incident_id):
    """Update an incident's investigation status."""
    status = request.form.get("status", "")

    if status not in {"New", "Investigating", "Resolved"}:
        abort(400)

    updated = update_incident_status(incident_id, status)

    if not updated:
        abort(404)

    return redirect(
        url_for("incident_details", incident_id=incident_id)
    )

@app.route("/incident/<incident_id>/notes", methods=["POST"])
def add_incident_note(incident_id):
    """Save an investigation note for an incident."""

    note = request.form.get("note", "").strip()

    if not note or len(note) > 5000:
        abort(400)

    saved = add_investigation_note(incident_id, note)

    if not saved:
        abort(404)

    return redirect(
        url_for("incident_details", incident_id=incident_id)
    )


@app.route("/incident/<incident_id>/download")
def download_incident_report(incident_id):
    rows = get_all_incidents()

    row = next(
        (
            item for item in rows
            if item["incident_id"] == incident_id
        ),
        None,
    )

    if row is None:
        abort(404)

    incident = load_incident_from_row(row)
    incident["investigation_notes"] = get_investigation_notes(incident_id)
    incident["audit_events"] = get_incident_audit_log(incident_id)
    report_dir = Path("reports")
    report_dir.mkdir(parents=True, exist_ok=True)

    pdf_path = report_dir / f"{incident_id}_report.pdf"

    generate_incident_pdf(incident, pdf_path)

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=f"{incident_id}_report.pdf",
        mimetype="application/pdf",
    )


if __name__ == "__main__":
    initialize_database()
    app.run(host="127.0.0.1", port=5000, debug=True)
