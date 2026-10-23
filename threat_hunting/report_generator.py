
import json
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


def safe_text(value):
    """Escape text before placing it inside a ReportLab Paragraph."""
    return escape(str(value))


def generate_incident_pdf(incident, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"Incident Report - {incident['incident_id']}",
        author="AI Threat Hunting Platform",
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#0f4c81"),
        spaceAfter=16,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#0f4c81"),
        spaceBefore=12,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="SmallCell",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10,
        wordWrap="CJK",
    ))

    story = [
        Paragraph("SECURITY INCIDENT REPORT", styles["ReportTitle"]),
        Paragraph(
            "AI-Powered Threat Hunting Platform",
            styles["Heading2"],
        ),
        Spacer(1, 8),
    ]

    metadata = [
        ["Incident ID", safe_text(incident["incident_id"])],
        ["Host", safe_text(incident["host"])],
        ["Severity", safe_text(incident["severity"])],
        ["Created At", safe_text(incident.get("created_at", "N/A"))],
        ["Users", safe_text(", ".join(incident["users"]))],
        ["Source IPs", safe_text(", ".join(incident["source_ips"]))],
    ]

    metadata_table = Table(metadata, colWidths=[38 * mm, 125 * mm])
    metadata_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8eef5")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))

    story.extend([
        Paragraph("Incident Overview", styles["SectionHeading"]),
        metadata_table,
        Paragraph("Investigation Summary", styles["SectionHeading"]),
        Paragraph(
            "This report summarizes alerts and events associated with "
            "the selected incident. Findings are based on the supplied "
            "log data and require analyst validation.",
            styles["BodyText"],
        ),
        Paragraph("Detection Alerts", styles["SectionHeading"]),
    ])

    for index, alert in enumerate(incident["alerts"], start=1):
        story.append(Paragraph(
            f"{index}. {safe_text(alert.get('rule', 'Unknown rule'))}",
            styles["Heading3"],
        ))
        story.append(Paragraph(
            f"Severity: {safe_text(alert.get('severity', 'Unknown'))}",
            styles["BodyText"],
        ))
        story.append(Paragraph(
            safe_text(alert.get("description", "")),
            styles["BodyText"],
        ))
        story.append(Spacer(1, 6))

    story.append(Paragraph(
        "Investigation Notes",
        styles["SectionHeading"],
    ))

    investigation_notes = incident.get("investigation_notes", [])

    if investigation_notes:
        for index, note in enumerate(investigation_notes, start=1):
            note_text = safe_text(note.get("note", ""))
            note_text = note_text.replace("\n", "<br/>")
            created_at = safe_text(note.get("created_at", "Unknown"))

            story.append(Paragraph(
                f"{index}. {note_text}",
                styles["BodyText"],
            ))
            story.append(Paragraph(
                f"Saved at: {created_at}",
                styles["SmallCell"],
            ))
            story.append(Spacer(1, 8))
    else:
        story.append(Paragraph(
            "No investigation notes recorded for this incident.",
            styles["BodyText"],
        ))

    story.append(Spacer(1, 8))


    timeline_data = [[
        "Timestamp",
        "Event",
        "User",
        "Process / PID",
        "Parent Process",
        "Command Line / Details",
    ]]

    for event in incident.get("timeline", []):
        details = event.get("details", {})

        # Original event details may be a dictionary or a text string.
        if not isinstance(details, dict):
            details = {"description": str(details)}

        event_name = (
            event.get("event")
            or event.get("event_type")
            or event.get("action")
            or event.get("description")
            or details.get("event")
            or details.get("event_type")
            or "Security event"
        )

        process = (
            event.get("process")
            or event.get("process_name")
            or details.get("process")
            or details.get("process_name")
            or details.get("Image")
            or "Not recorded"
        )

        process_id = (
            event.get("process_id")
            or event.get("pid")
            or details.get("process_id")
            or details.get("pid")
            or details.get("ProcessId")
            or "Not recorded"
        )

        parent_process = (
            event.get("parent_process")
            or details.get("parent_process")
            or details.get("parent_process_name")
            or details.get("ParentImage")
            or "Not recorded"
        )

        command_line = (
            event.get("command_line")
            or details.get("command_line")
            or details.get("cmdline")
            or details.get("CommandLine")
            or details.get("command")
            or "Not recorded"
        )

        # Preserve other useful event fields as readable text.
        excluded = {
            "timestamp", "time", "datetime",
            "event", "event_type", "action", "description",
            "user", "username", "host", "hostname",
            "source_ip", "src_ip", "ip",
            "process", "process_name", "process_id", "pid",
            "parent_process", "parent_process_name",
            "command_line", "cmdline", "command",
            "Image", "ProcessId", "ParentImage", "CommandLine",
        }

        extra_details = {
            key: value
            for key, value in details.items()
            if key not in excluded
        }

        detail_text = f"Command: {command_line}"

        if extra_details:
            detail_text += "\n" + json.dumps(
                extra_details, ensure_ascii=False, default=str
            )

        timeline_data.append([
            Paragraph(
                safe_text(event.get("timestamp", "")),
                styles["SmallCell"],
            ),
            Paragraph(safe_text(event_name), styles["SmallCell"]),
            Paragraph(
                safe_text(event.get("user", "")),
                styles["SmallCell"],
            ),
            Paragraph(
                safe_text(f"{process} / {process_id}"),
                styles["SmallCell"],
            ),
            Paragraph(
                safe_text(parent_process),
                styles["SmallCell"],
            ),
            Paragraph(
                safe_text(detail_text),
                styles["SmallCell"],
            ),
        ])

    timeline_table = Table(
        timeline_data,
        colWidths=[27 * mm, 27 * mm, 17 * mm, 31 * mm, 34 * mm, 49 * mm],
        repeatRows=1,
    )

    timeline_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f4c81")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))

    story.append(Paragraph(
        "Chronological Event Timeline",
        styles["SectionHeading"],
    ))
    story.append(timeline_table)

    # Include the persistent incident investigation audit trail.
    story.append(Paragraph(
        "Investigation Audit Trail",
        styles["SectionHeading"],
    ))

    audit_events = incident.get("audit_events", [])

    if audit_events:
        for event in audit_events:
            action = safe_text(event.get("action", "Audit event"))
            details = safe_text(event.get("details", ""))
            details = details.replace("\\n", "<br/>")
            created_at = safe_text(
                event.get("created_at", "Unknown")
            )

            story.append(Paragraph(action, styles["Heading3"]))
            story.append(Paragraph(details, styles["BodyText"]))
            story.append(Paragraph(
                f"Recorded at: {created_at}",
                styles["SmallCell"],
            ))
            story.append(Spacer(1, 6))
    else:
        story.append(Paragraph(
            "No audit events recorded for this incident.",
            styles["BodyText"],
        ))

    story.append(Spacer(1, 16))
    story.append(Paragraph(
        "Analyst note: This report is generated automatically. "
        "Severity and detection results should be reviewed before "
        "taking incident response actions.",
        styles["Italic"],
    ))

    def add_page_number(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)
        canvas.drawString(
            18 * mm, 10 * mm, "AI Threat Hunting Platform"
        )
        canvas.drawRightString(
            A4[0] - 18 * mm, 10 * mm,
            f"Page {document.page}",
        )
        canvas.restoreState()

    doc.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number,
    )


def load_incident_from_row(row):
    """Convert a database row into a report-ready incident dictionary."""
    incident = dict(row)

    for field in ("users", "source_ips", "alerts", "timeline"):
        if isinstance(incident[field], str):
            incident[field] = json.loads(incident[field])

    return incident
