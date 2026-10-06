import ipaddress
import json
import socket
import urllib.parse
import urllib.request
from urllib.error import URLError
import requests
from fastapi import APIRouter, HTTPException, Query

from app.config import settings
from app.db.schemas import WebhookTestRequest

router = APIRouter(prefix="/api/v1/integrations", tags=["Integrations & Webhooks"])


def _validate_webhook_url(url: str) -> None:
    """
    Validate that target webhook URL has a valid scheme and resolves to an allowed public IP.
    Blocks private networks (RFC 1918), loopback (127.0.0.1/::1), link-local (169.254.0.0/16),
    and reserved/multicast/unspecified addresses.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid target URL format.",
        )

    if parsed.scheme.lower() not in ("http", "https"):
        raise HTTPException(
            status_code=400,
            detail="Invalid target URL scheme: only HTTP and HTTPS are supported.",
        )

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(
            status_code=400,
            detail="Invalid target URL: missing hostname.",
        )

    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, socket.herror) as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Unable to resolve target URL host '{hostname}': {exc}",
        )

    if not addr_info:
        raise HTTPException(
            status_code=400,
            detail=f"Unable to resolve target URL host '{hostname}'.",
        )

    for entry in addr_info:
        ip_str = entry[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid IP address resolved for host '{hostname}': {ip_str}",
            )

        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise HTTPException(
                status_code=400,
                detail=f"Webhook delivery to private, loopback, or internal addresses is prohibited: {ip_str}",
            )


@router.post("/webhook-test")
def test_webhook_delivery(payload: WebhookTestRequest):
    """
    Send a test event payload to a partner's webhook URL to verify connectivity.
    """
    _validate_webhook_url(payload.target_url)

    test_body = {
        "event": payload.event_type,
        "source": "FinPulse-Enterprise-Gateway",
        "test_mode": True,
        "sample_invoice_id": "INV-2026-001",
    }

    headers = {"Content-Type": "application/json", "User-Agent": "FinPulse-Webhook/1.2"}
    if payload.custom_headers:
        safe_custom_headers = {
            k: v for k, v in payload.custom_headers.items()
            if k.lower() not in ("host", "content-length")
        }
        headers.update(safe_custom_headers)

    try:
        response = requests.post(
            payload.target_url,
            json=test_body,
            headers=headers,
            timeout=settings.WEBHOOK_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Webhook delivery to target URL failed: {exc}",
        )

    return {
        "target_url": payload.target_url,
        "status_code": response.status_code,
        "response_headers": dict(response.headers),
        "response_body": response.text[:4096],
    }


@router.get("/fetch-exchange-rates")
def fetch_partner_exchange_rates(
    provider_url: str = Query(
        default=settings.DEFAULT_EXCHANGE_RATE_URL,
        description="Remote JSON feed URL for currency exchange rates",
    ),
):
    """
    Fetch currency exchange rates from a configurable external feed URL.

    VULNERABILITY: Web Security - Server-Side Request Forgery (SSRF)
    `urllib.request.urlopen()` is called directly on the user-controlled `provider_url`
    query parameter without scheme validation (allowing `file://`, `http://`, etc.)
    or destination host allowlisting.
    """
    try:
        req = urllib.request.Request(
            provider_url,
            headers={"User-Agent": "FinPulse-FX-Sync/1.2"},
        )
        with urllib.request.urlopen(
            req, timeout=settings.WEBHOOK_TIMEOUT_SECONDS
        ) as resp:
            raw_data = resp.read().decode("utf-8", errors="replace")
    except URLError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Unable to fetch exchange rate feed from '{provider_url}': {exc}",
        )

    try:
        parsed = json.loads(raw_data)
        return {"provider": provider_url, "data": parsed}
    except json.JSONDecodeError:
        return {"provider": provider_url, "raw_response": raw_data[:4096]}
