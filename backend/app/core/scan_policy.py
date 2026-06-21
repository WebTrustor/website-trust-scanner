"""
Scan Policy Engine.

Decision order (highest priority first):
  1. Do Not Scan list — hard block, no override possible
  2. Scan type availability — PUBLIC_TRUST is the only type open in Phase 3
  3. All other types require an Authorization Record (Phase 6)

This module is pure logic: it receives data objects and raises or returns.
Database queries happen in the calling service layer.
"""

from enum import Enum

from app.core.exceptions import (
    AuthorizationRequiredError,
    DomainBlockedError,
    ScanNotAllowedError,
)


class ScanType(str, Enum):
    PUBLIC_TRUST = "public_trust"
    SECURITY_HEADERS = "security_headers"
    SSL_AUDIT = "ssl_audit"
    CONTENT_SCAN = "content_scan"
    FULL_SECURITY = "full_security"


# Scan types that are fully open without authentication or Authorization Record.
# Extend this set only when a new scan type has been reviewed for safety.
_PUBLIC_SCAN_TYPES: frozenset[ScanType] = frozenset({ScanType.PUBLIC_TRUST})

# Scan types that are permanently disallowed regardless of role or record.
# These are listed here as documentation; they are not in ScanType at all.
_PERMANENTLY_FORBIDDEN: frozenset[str] = frozenset(
    {
        "port_scan",
        "xss_test",
        "sql_injection_test",
        "brute_force",
        "directory_enumeration",
        "admin_panel_detection",
        "sensitive_file_harvest",
    }
)


def check_scan_allowed(
    *,
    domain: str,
    scan_type: ScanType,
    is_on_do_not_scan_list: bool,
    has_active_authorization: bool = False,
) -> None:
    """
    Assert that a scan is permitted.  Raises on the first violated policy.

    Parameters
    ----------
    domain:
        The target domain (used only for error messages).
    scan_type:
        The requested scan type.
    is_on_do_not_scan_list:
        True if the domain was found in the do_not_scan table.
    has_active_authorization:
        True if a valid, unexpired Authorization Record exists for this domain
        and the authenticated user is the verified owner.
    """
    # 1. Do Not Scan — unconditional block
    if is_on_do_not_scan_list:
        raise DomainBlockedError(
            message=f"Domain '{domain}' is on the Do Not Scan list",
        )

    # 2. Permanently forbidden types should never reach here, but guard anyway
    if scan_type.value in _PERMANENTLY_FORBIDDEN:
        raise ScanNotAllowedError(
            message=f"Scan type '{scan_type.value}' is permanently disallowed",
        )

    # 3. Public scan types — always allowed (after DNS check)
    if scan_type in _PUBLIC_SCAN_TYPES:
        return

    # 4. All other scan types require an Authorization Record
    if not has_active_authorization:
        raise AuthorizationRequiredError(
            message=(
                f"Scan type '{scan_type.value}' requires a valid Authorization "
                "Record from the verified site owner"
            ),
        )

    # Authorization present — scan is allowed
    return
