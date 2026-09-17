# FinPulse Enterprise Portal API (`cm-python-sample`)

A realistic Python **FastAPI** sample application designed to demonstrate **Google CodeMender**, an AI code scanning and automated vulnerability remediation agent.

FinPulse simulates an internal enterprise financial portal used for invoice management, document archiving, webhook/FX integrations, and HTML executive reporting.

---

## Repository Structure

This repository contains **13 files** organized across **4 module directories** (`app`, `app/db`, `app/routers`, `app/services`):

```text
cm-python-sample/
├── .gitignore
├── README.md
├── requirements.txt
└── app/
    ├── __init__.py
    ├── config.py
    ├── main.py
    ├── db/
    │   ├── database.py         # SQLite connection & sample data seeding
    │   └── schemas.py          # Pydantic request/response schemas
    ├── routers/
    │   ├── invoices.py         # Injection: SQL Injection (SQLi)
    │   ├── documents.py        # Injection: Path Traversal
    │   ├── integrations.py     # Web Security: Server-Side Request Forgery (SSRF)
    │   └── reports.py          # Web Security: Cross-Site Scripting (XSS)
    └── services/
        └── audit_logger.py     # Audit logging & unescaped HTML table renderer (XSS sink)
```

---

## Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the FastAPI server:**
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```

3. **Explore Interactive API Docs:**
   Open `http://127.0.0.1:8000/docs` in your browser. On startup, the application automatically initializes a local SQLite database (`data/finpulse.db`) and sample document storage (`storage/`).

---

## Intentional Vulnerabilities for CodeMender Demo

This repository contains intentional security vulnerabilities across four core categories:

### 1. Injection: SQL Injection (SQLi)
* **Location:** `app/routers/invoices.py`
  * `GET /api/v1/invoices/search` (`search_invoices`): Concatenates `customer_name`, `status`, and `sort_by` directly into raw SQL string queries executed via `cursor.execute()`.
  * `GET /api/v1/invoices/lookup/{invoice_number}` (`lookup_invoice_by_number`): Interpolates `invoice_number` directly into the SQL `WHERE` clause.
* **Example Proof of Concept:**
  ```bash
  curl "http://127.0.0.1:8000/api/v1/invoices/search?customer_name=%27%20OR%201=1--"
  ```
* **Expected Remediation:** Use parameterized SQL queries (`?` placeholders) and validate `sort_by` against an explicit allowlist of column names.

---

### 2. Injection: Path Traversal
* **Location:** `app/routers/documents.py`
  * `GET /api/v1/documents/download` (`download_document`): Uses `os.path.join(settings.DOCUMENTS_BASE_DIR, category, filename)` without canonicalizing the path or verifying containment within `DOCUMENTS_BASE_DIR`.
  * `POST /api/v1/documents/template-preview` (`preview_report_template`): Concatenates user-supplied `template_path` directly with `settings.TEMPLATES_DIR` and reads the file.
* **Example Proof of Concept:**
  ```bash
  curl "http://127.0.0.1:8000/api/v1/documents/download?category=receipts&filename=../../../../etc/passwd"
  ```
* **Expected Remediation:** Resolve paths using `Path.resolve()` and verify that the target path is strictly inside the allowed base directory using `.is_relative_to(base_dir)`.

---

### 3. Web Security: Server-Side Request Forgery (SSRF)
* **Location:** `app/routers/integrations.py`
  * `POST /api/v1/integrations/webhook-test` (`test_webhook_delivery`): Sends an outbound HTTP POST request using `requests.post(payload.target_url)` without validating the destination host or blocking loopback/private/cloud metadata IPs (`127.0.0.1`, `169.254.169.254`, RFC 1918 ranges), returning the full response body to the client.
  * `GET /api/v1/integrations/fetch-exchange-rates` (`fetch_partner_exchange_rates`): Calls `urllib.request.urlopen(provider_url)` on an unvalidated query parameter.
* **Example Proof of Concept:**
  ```bash
  curl -X POST "http://127.0.0.1:8000/api/v1/integrations/webhook-test" \
       -H "Content-Type: application/json" \
       -d '{"target_url": "http://127.0.0.1:8000/", "event_type": "ping"}'
  ```
* **Expected Remediation:** Parse the URL scheme (`https` only), resolve the hostname to IP addresses, block loopback/private/link-local ranges (`ipaddress.ip_address.is_private`, `is_loopback`, `is_link_local`), or enforce an explicit domain allowlist.

---

### 4. Web Security: Cross-Site Scripting (XSS)
* **Location:** `app/routers/reports.py` & `app/services/audit_logger.py`
  * `GET /api/v1/reports/preview` (`generate_printable_report_preview`): **Reflected XSS** — Directly embeds user-supplied query parameters (`report_title`, `client_name`, `custom_notes`) into an HTML document returned via `HTMLResponse`.
  * `GET /api/v1/reports/audit-feed` (`view_security_audit_feed` -> `render_audit_table_html`): **Stored & Reflected XSS** — Renders both the `filter_banner` query parameter and database-stored audit log entries (`details`, `actor`) into an HTML table without `html.escape()` encoding.
* **Example Proof of Concept:**
  ```bash
  curl "http://127.0.0.1:8000/api/v1/reports/preview?report_title=%3Cscript%3Ealert(document.domain)%3C/script%3E"
  ```
* **Expected Remediation:** Sanitize all dynamic values rendered into HTML using `html.escape()` or use Jinja2 templates configured with `autoescape=True`.
