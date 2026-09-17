import sqlite3
from datetime import datetime, timezone
from typing import List, Dict, Any


def record_audit_event(
    conn: sqlite3.Connection,
    actor: str,
    action: str,
    resource: str,
    details: str,
) -> None:
    """Persist an operational audit event into the SQLite database."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO audit_logs (actor, action, resource, details, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """,
        (actor, action, resource, details, timestamp),
    )
    conn.commit()


def fetch_recent_audit_logs(
    conn: sqlite3.Connection, limit: int = 25
) -> List[Dict[str, Any]]:
    """Retrieve recent audit events ordered by most recent first."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, actor, action, resource, details, timestamp FROM audit_logs ORDER BY id DESC LIMIT ?",
        (limit,),
    )
    return [dict(row) for row in cursor.fetchall()]


def render_audit_table_html(logs: List[Dict[str, Any]], filter_banner: str = "") -> str:
    """
    Generate an HTML table summarizing recent security and operational audit events.
    NOTE: Contains intentional Cross-Site Scripting (XSS) vulnerability for CodeMender demonstration:
    `filter_banner` and `log['details']` / `log['actor']` are interpolated directly into HTML without escaping.
    """
    rows_html = ""
    for log in logs:
        rows_html += (
            f"<tr>"
            f"<td>{log['id']}</td>"
            f"<td>{log['timestamp']}</td>"
            f"<td>{log['actor']}</td>"
            f"<td><span class='badge'>{log['action']}</span></td>"
            f"<td>{log['resource']}</td>"
            f"<td>{log['details']}</td>"
            f"</tr>\n"
        )

    banner_section = (
        f"<div class='alert-banner'>Active Filter: {filter_banner}</div>"
        if filter_banner
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>FinPulse Security Audit Feed</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 2rem; color: #1f2937; }}
        h1 {{ color: #111827; }}
        .alert-banner {{ background: #eff6ff; border-left: 4px solid #3b82f6; padding: 0.75rem 1rem; margin-bottom: 1.5rem; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th, td {{ border: 1px solid #e5e7eb; padding: 0.75rem; text-align: left; }}
        th {{ background-color: #f9fafb; font-weight: 600; }}
        .badge {{ background: #e0e7ff; color: #1d4ed8; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.85rem; }}
    </style>
</head>
<body>
    <h1>Enterprise Audit Trail</h1>
    {banner_section}
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Timestamp (UTC)</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Details</th>
            </tr>
        </thead>
        <tbody>
            {rows_html}
        </tbody>
    </table>
</body>
</html>"""
