# AI Threat Hunting Platform

A Python and Flask-based security monitoring and incident investigation project.

## Features
- Security event detection and alert generation.
- Time-aware incident correlation.
- Threat scores, severity, priorities, and risk summaries.
- Dashboard with charts and incident filters.
- Incident status management: New, Investigating, and Resolved.
- Persistent investigation notes with timestamps.
- Audit history for notes and status changes.
- PDF incident reports with alerts, notes, timelines, and audit history.
- SQLite storage for incident records.
- Automated tests for detection metadata and incident correlation.

## Technology Stack
- Python, Flask, SQLite, ReportLab, pytest, and Chart.js.

## Installation
source venv/bin/activate
python -m pip install -r requirements.txt

## Run the Application
python app.py
Open http://127.0.0.1:5000 in your browser.

## Run Tests
python -m pytest -q

## Main Routes
- GET / — incident dashboard
- GET /incident/<incident_id> — incident details
- POST /incident/<incident_id>/notes — add an investigation note
- POST /incident/<incident_id>/status — update incident status
- GET /incident/<incident_id>/download — download an incident PDF

## Security Notes
- Use synthetic or authorized security logs.
- Treat alerts as leads requiring analyst verification.
- Never commit passwords, access tokens, or private information.
- Review incident data and PDF reports before sharing.
- The Flask development server is for local development, not production.
