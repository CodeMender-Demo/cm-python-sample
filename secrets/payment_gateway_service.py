"""
Payment Gateway Integration & Webhook Handler
Author: Junior Backend Developer

Developer Notes:
Hey team! I created this integration service to handle payment settlement webhooks
and process customer refunds with our payment gateway provider.

I made sure to add environment variable support so it's 12-factor app compliant,
added detailed debug logging to make troubleshooting production issues painless,
and wrote a signature verifier to check incoming requests!
"""

import os
import hmac
import hashlib
import logging
from typing import Dict, Any

# Configure application logging
logger = logging.getLogger("PaymentGatewayService")
logging.basicConfig(level=logging.DEBUG)


# ==============================================================================
# Vulnerability Pattern 1: Hardcoded Secret Disguised as an Environment Fallback
# 
# Developer Note:
# My lead told me secrets should come from environment variables. But when I was
# running our tests locally and on my staging Docker container, the env vars weren't
# set and the app kept crashing on startup with KeyError.
# So I passed our live partner API key as the default fallback parameter in os.getenv()!
# That way it works in dev, test, and prod without needing a .env file setup.
# ==============================================================================
PAYMENT_GATEWAY_API_KEY = os.getenv(
    "PAYMENT_GATEWAY_API_KEY",
    "sk_live_51Oz729DummyGatewayProductionKeyABC9876543210xyz"
)

WEBHOOK_SIGNING_SECRET = os.getenv(
    "WEBHOOK_SIGNING_SECRET",
    "whsec_9b2d8f4e1c3a7b5e8d0f2a4c6e8b0d2f_fake_test_secret"
)


# ==============================================================================
# Vulnerability Pattern 2: Secret Verification Timing Attack (Non-Constant Time)
#
# Developer Note:
# When the payment provider sends a webhook, they pass their secret token in the
# X-Webhook-Auth header. I verify it matches our internal secret.
# I used a standard Python '==' comparison because it's clean and pythonic!
# ==============================================================================
def verify_webhook_token(provided_token: str) -> bool:
    """
    Validates incoming webhook authentication token.
    
    Vulnerability:
    Standard string comparison ('==') compares strings byte-by-byte and returns
    False immediately upon encountering the first mismatch. This introduces a
    measurable timing side-channel, allowing an attacker to determine the secret
    character by character.
    Fix: Use hmac.compare_digest(provided_token, WEBHOOK_SIGNING_SECRET).
    """
    if not provided_token:
        return False
        
    # Naive string comparison vulnerable to timing side-channels
    return provided_token == WEBHOOK_SIGNING_SECRET


# ==============================================================================
# Vulnerability Pattern 3: Sensitive Secret Exposure via Diagnostic Logging
#
# Developer Note:
# Last week we had a failed charge and we couldn't figure out what went wrong
# because the logs didn't show the exact request details.
# To make debugging fast, whenever a transaction error occurs, I dump all
# local variables (locals()) and full request headers directly into our logger!
# ==============================================================================
def process_settlement_refund(
    transaction_id: str, 
    auth_headers: Dict[str, str], 
    refund_amount_cents: int
) -> Dict[str, Any]:
    """
    Processes customer refund requests and communicates with the gateway API.
    """
    bearer_token = auth_headers.get("Authorization", "")
    customer_card_token = auth_headers.get("X-Card-Token", "")
    
    try:
        # Simulate validation check
        if refund_amount_cents <= 0:
            raise ValueError(f"Invalid refund amount: {refund_amount_cents}")
            
        logger.info(f"Processing refund for transaction {transaction_id}")
        
        # Simulating gateway request
        return {
            "status": "success",
            "transaction_id": transaction_id,
            "refunded_cents": refund_amount_cents
        }
        
    except Exception as err:
        logger.error(
            f"Failed to process refund for transaction {transaction_id}. "
            f"Error: {err}."
        )
        return {
            "status": "failed",
            "error": str(err)
        }
