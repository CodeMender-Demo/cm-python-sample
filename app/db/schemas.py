from typing import Dict, Optional
from pydantic import BaseModel, Field


class InvoiceCreate(BaseModel):
    invoice_number: str = Field(..., example="INV-2026-105")
    customer_name: str = Field(..., example="Initech LLC")
    billing_email: str = Field(..., example="accounts@initech.example.com")
    amount: float = Field(..., gt=0, example=5400.00)
    currency: str = Field(default="USD", example="USD")
    status: str = Field(default="PENDING", example="PENDING")
    notes: Optional[str] = Field(default="", example="Consulting services")


class InvoiceResponse(BaseModel):
    id: int
    invoice_number: str
    customer_name: str
    billing_email: str
    amount: float
    currency: str
    status: str
    notes: Optional[str]
    created_at: str


class WebhookTestRequest(BaseModel):
    target_url: str = Field(
        ...,
        description="Endpoint URL to test webhook delivery against",
        example="https://partner.example.com/webhooks/finpulse",
    )
    event_type: str = Field(default="invoice.paid", example="invoice.paid")
    custom_headers: Optional[Dict[str, str]] = Field(
        default_factory=dict,
        example={"X-Partner-Token": "test-secret-key"},
    )


class TemplatePreviewRequest(BaseModel):
    template_path: str = Field(
        ...,
        description="Relative path to the HTML template file in storage",
        example="quarterly_summary.html",
    )
    company_header: str = Field(
        default="FinPulse Enterprise Client",
        description="Header string injected into template preview",
    )
