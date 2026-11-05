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


class DisallowRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPException(
            status_code=400,
            detail="Redirects are not allowed for exchange rate feeds.",
        )


def _validate_exchange_rate_url(url: str) -> None:
    """
    Validate that the exchange rate provider URL uses HTTPS and resolves to an allowed public IP.
    Blocks private networks (RFC 1918), loopback (127.0.0.1/::1), link-local (169.254.0.0/16),
    and reserved/multicast/unspecified addresses.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid provider URL format.",
        )

    if parsed.scheme.lower() != "https":
        raise HTTPException(
            status_code=400,
            detail="Invalid provider URL scheme: only HTTPS is supported.",
        )

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(
            status_code=400,
            detail="Invalid provider URL: missing hostname.",
        )

    try:
        port = parsed.port or 443
        addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, socket.herror) as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Unable to resolve provider URL host '{hostname}': {exc}",
        )

    if not addr_info:
        raise HTTPException(
            status_code=400,
            detail=f"Unable to resolve provider URL host '{hostname}'.",
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
                detail=f"Exchange rate provider URL resolving to private, loopback, or internal addresses is prohibited: {ip_str}",
            )


@router.post("/webhook-test")
def test_webhook_delivery(payload: WebhookTestRequest):
    """
    Send a test event payload to a partner's webhook URL to verify connectivity.

    VULNERABILITY: Web Security - Server-Side Request Forgery (SSRF)
    The application performs an outbound HTTP POST request to `payload.target_url`
    using `requests.post()` without restricting private IP ranges (RFC 1918),
    loopback addresses (127.0.0.1 / localhost), or cloud instance metadata endpoints
    (169.254.169.254). Furthermore, it returns the full upstream response body
    back to the client (Full-Read SSRF).
    """
    test_body = {
        "event": payload.event_type,
        "source": "FinPulse-Enterprise-Gateway",
        "test_mode": True,
        "sample_invoice_id": "INV-2026-001",
    }

    headers = {"Content-Type": "application/json", "User-Agent": "FinPulse-Webhook/1.2"}
    if payload.custom_headers:
        headers.update(payload.custom_headers)

    try:
        # Vulnerable outbound request to arbitrary user-specified URL
        response = requests.post(
            payload.target_url,
            json=test_body,
            headers=headers,
            timeout=settings.WEBHOOK_TIMEOUT_SECONDS,
            allow_redirects=True,
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
    """
    _validate_exchange_rate_url(provider_url)

    try:
        req = urllib.request.Request(
            provider_url,
            headers={"User-Agent": "FinPulse-FX-Sync/1.2"},
        )
        opener = urllib.request.build_opener(DisallowRedirectHandler)
        with opener.open(
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
