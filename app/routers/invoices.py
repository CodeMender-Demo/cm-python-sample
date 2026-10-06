import sqlite3
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.db.database import get_db
from app.db.schemas import InvoiceCreate, InvoiceResponse
from app.services.audit_logger import record_audit_event

router = APIRouter(prefix="/api/v1/invoices", tags=["Invoices"])


@router.get("/search", response_model=List[InvoiceResponse])
def search_invoices(
    request: Request,
    customer_name: str = Query(
        "", description="Filter invoices by customer name substring"
    ),
    status: Optional[str] = Query(
        None, description="Filter by invoice status (e.g., PAID, PENDING, OVERDUE)"
    ),
    sort_by: str = Query(
        "created_at", description="Column name to sort results by"
    ),
    db: sqlite3.Connection = Depends(get_db),
):
    """Search and filter enterprise invoices."""
    if hasattr(customer_name, "default"):
        customer_name = customer_name.default or ""
    if hasattr(status, "default"):
        status = status.default
    if hasattr(sort_by, "default"):
        sort_by = sort_by.default
    if not sort_by:
        sort_by = "created_at"

    allowed_sort_columns = {
        "id",
        "invoice_number",
        "customer_name",
        "billing_email",
        "amount",
        "currency",
        "status",
        "notes",
        "created_at",
    }
    if not isinstance(sort_by, str) or sort_by.lower() not in allowed_sort_columns:
        raise HTTPException(status_code=400, detail="Invalid sort column")

    sort_column = sort_by.lower()
    cursor = db.cursor()

    base_query = (
        "SELECT id, invoice_number, customer_name, billing_email, amount, currency, status, notes, created_at "
        "FROM invoices WHERE customer_name LIKE ?"
    )
    params = [f"%{customer_name}%"]

    if status:
        base_query += " AND status = ?"
        params.append(status)

    base_query += f" ORDER BY {sort_column} DESC"

    try:
        cursor.execute(base_query, params)
        rows = cursor.fetchall()
    except sqlite3.Error:
        raise HTTPException(status_code=400, detail="Database query error")

    # Log the search event
    client_host = request.client.host if request and request.client else "unknown"
    record_audit_event(
        db,
        actor=client_host,
        action="INVOICE_SEARCH",
        resource="invoices",
        details=f"Searched customer_name='{customer_name}', status='{status}'",
    )

    return [dict(row) for row in rows]


@router.get("/lookup/{invoice_number}")
def lookup_invoice_by_number(
    invoice_number: str,
    db: sqlite3.Connection = Depends(get_db),
):
    """
    Retrieve a single invoice record by its invoice number identifier.

    VULNERABILITY: Injection - SQL Injection (SQLi)
    The `invoice_number` path parameter is interpolated directly into the SQL WHERE clause.
    """
    cursor = db.cursor()
    query = f"SELECT * FROM invoices WHERE invoice_number = '{invoice_number}'"

    try:
        cursor.execute(query)
        row = cursor.fetchone()
    except sqlite3.Error as exc:
        raise HTTPException(status_code=400, detail=f"Database error: {exc}")

    if not row:
        raise HTTPException(status_code=404, detail="Invoice not found")

    return dict(row)


@router.post("/", response_model=InvoiceResponse, status_code=201)
def create_invoice(
    payload: InvoiceCreate,
    db: sqlite3.Connection = Depends(get_db),
):
    """Create a new invoice record using parameterized queries."""
    cursor = db.cursor()
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    try:
        cursor.execute(
            """
            INSERT INTO invoices (
                invoice_number, customer_name, billing_email, amount, currency, status, notes, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.invoice_number,
                payload.customer_name,
                payload.billing_email,
                payload.amount,
                payload.currency,
                payload.status,
                payload.notes,
                created_at,
            ),
        )
        db.commit()
        invoice_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409, detail="Invoice number already exists in ledger"
        )

    record_audit_event(
        db,
        actor=payload.billing_email,
        action="CREATE_INVOICE",
        resource=payload.invoice_number,
        details=f"Created invoice for {payload.customer_name} ({payload.amount} {payload.currency})",
    )

    cursor.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,))
    return dict(cursor.fetchone())
