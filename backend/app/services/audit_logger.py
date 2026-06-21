"""
Centralised audit logging service.

Rules enforced here:
  - actor_ip is stored in the DB but NEVER returned by any API endpoint.
  - Sensitive keys are stripped from `details` before persistence.
  - This is an append-only log: no update or delete helpers are provided.
"""

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog

logger = logging.getLogger(__name__)

# Keys whose values must never appear in the audit log details
_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "hashed_password",
        "secret",
        "secret_key",
        "api_key",
        "access_token",
        "refresh_token",
        "token",
        "authorization",
        "cookie",
        "set-cookie",
        "private_key",
        "credit_card",
        "card_number",
        "cvv",
        "ssn",
        "raw_html",
        "file_content",
        "file_contents",
    }
)


def _sanitize_details(details: dict[str, Any] | None) -> dict[str, Any] | None:
    """
    Recursively strip sensitive keys from a details dict.

    Values are replaced with the sentinel "[REDACTED]" rather than being
    deleted so that the audit record still reveals that a field was present.
    """
    if details is None:
        return None

    sanitized: dict[str, Any] = {}
    for key, value in details.items():
        if key.lower() in _SENSITIVE_KEYS:
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_details(value)
        elif isinstance(value, list):
            sanitized[key] = [
                _sanitize_details(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            sanitized[key] = value

    return sanitized


async def log_event(
    db: AsyncSession,
    *,
    action: str,
    outcome: str = "success",
    actor_id: str | None = None,
    actor_role: str | None = None,
    actor_ip: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """
    Write one audit log entry.

    This function never raises — a logging failure must not break the
    caller's business logic.  Errors are emitted as ERROR-level log lines
    so the on-call engineer can investigate.
    """
    try:
        entry = AuditLog(
            action=action,
            outcome=outcome,
            actor_id=actor_id,
            actor_role=actor_role,
            actor_ip=actor_ip,
            resource_type=resource_type,
            resource_id=resource_id,
            details=_sanitize_details(details),
        )
        db.add(entry)
        await db.flush()  # Get the DB-generated id without committing the outer txn
    except Exception:
        logger.exception(
            "audit_logger: failed to write audit event action=%s actor_id=%s",
            action,
            actor_id,
        )
