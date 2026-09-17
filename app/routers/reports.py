import sqlite3
from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse

from app.db.database import get_db
from app.services.audit_logger import (
    fetch_recent_audit_logs,
    render_audit_table_html,
)

router = APIRouter(prefix="/api/v1/reports", tags=["Reports & Dashboards"])


@router.get("/preview", response_class=HTMLResponse)
def generate_printable_report_preview(
    report_title: str = Query(
        "Q1 Executive Billing Statement",
        description="Title displayed on the printable HTML report header",
    ),
    client_name: str = Query(
        "Acme Global Corp",
        description="Client organization name displayed on the report",
    ),
    custom_notes: str = Query(
        "All payments settled within Net-30 terms.",
        description="Custom analyst commentary or HTML notes section",
    ),
):
    """
    Render a printable HTML executive billing statement preview.

    VULNERABILITY: Web Security - Reflected Cross-Site Scripting (XSS)
    User-controlled query parameters (`report_title`, `client_name`, and `custom_notes`)
    are directly interpolated into an HTML response body without context-aware encoding
    or `html.escape()` sanitization, allowing arbitrary JavaScript execution in the victim's browser.
    """
    html_document = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Report Preview - {report_title}</title>
    <style>
        body {{ font-family: 'Helvetica Neue', Arial, sans-serif; margin: 3rem; background: #fcfcfc; color: #222; }}
        .report-container {{ max-width: 800px; margin: auto; background: #fff; padding: 2.5rem; border: 1px solid #ddd; border-radius: 6px; }}
        .header {{ border-bottom: 2px solid #0f172a; padding-bottom: 1rem; margin-bottom: 1.5rem; }}
        .meta {{ font-size: 1.05rem; margin-bottom: 1rem; color: #334155; }}
        .notes-box {{ background: #f8fafc; border: 1px solid #cbd5e1; padding: 1rem; border-radius: 4px; margin-top: 1.5rem; }}
    </style>
</head>
<body>
    <div class="report-container">
        <div class="header">
            <h1>{report_title}</h1>
            <p>FinPulse Automated Statement Generator</p>
        </div>
        <div class="meta">
            Prepared for client organization: <strong>{client_name}</strong>
        </div>
        <div class="notes-box">
            <h4>Analyst Notes & Terms</h4>
            <div>{custom_notes}</div>
        </div>
    </div>
</body>
</html>"""

    return HTMLResponse(content=html_document, status_code=200)


@router.get("/audit-feed", response_class=HTMLResponse)
def view_security_audit_feed(
    filter_banner: str = Query(
        "",
        description="Optional filter banner label displayed at the top of the dashboard",
    ),
    limit: int = Query(25, ge=1, le=100),
    db: sqlite3.Connection = Depends(get_db),
):
    """
    Render an HTML dashboard displaying recent system and user audit events.

    VULNERABILITY: Web Security - Stored & Reflected Cross-Site Scripting (XSS)
    Both the `filter_banner` query parameter and stored database fields (`actor`, `details`)
    are rendered into HTML via `render_audit_table_html()` without HTML escaping.
    """
    logs = fetch_recent_audit_logs(db, limit=limit)
    dashboard_html = render_audit_table_html(logs=logs, filter_banner=filter_banner)
    return HTMLResponse(content=dashboard_html, status_code=200)
