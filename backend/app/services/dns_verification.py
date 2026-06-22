"""
DNS TXT-based site ownership verification.

Flow:
  1. generate_verification_token(site_id) → deterministic HMAC token
  2. User adds TXT record: trustscanner-verify=<token>
  3. verify_ownership(domain, site_id) → bool

Security:
  - Token is HMAC-SHA256(secret_key, site_id) — unforgeable without the key
  - DNS lookup is async, timeout capped to avoid hanging requests
  - No sensitive details leaked in error responses
"""

import hashlib
import hmac

import dns.asyncresolver
import dns.exception

from app.core.config import settings

_TXT_PREFIX = "trustscanner-verify="
_DNS_TIMEOUT = 5.0


def generate_verification_token(site_id: str) -> str:
    """Return the expected TXT record value for a given site_id."""
    return hmac.new(
        settings.secret_key.encode(),
        site_id.encode(),
        hashlib.sha256,
    ).hexdigest()


def get_expected_txt(site_id: str) -> str:
    return f"{_TXT_PREFIX}{generate_verification_token(site_id)}"


async def verify_ownership(domain: str, site_id: str) -> bool:
    """
    Look up TXT records for domain and check for the verification token.

    Returns True if found, False otherwise.  Never raises.
    """
    expected = get_expected_txt(site_id)
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = _DNS_TIMEOUT

    try:
        answers = await resolver.resolve(domain, "TXT")
        for rdata in answers:
            for txt_string in rdata.strings:
                if txt_string.decode("utf-8", errors="ignore") == expected:
                    return True
    except Exception:
        pass

    return False
