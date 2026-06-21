"""
Rate limiter configuration using slowapi (Starlette/FastAPI wrapper for limits).

Tiers:
  - Guest / IP-based  : 10 public scans / hour per IP
  - Authenticated user: 60 scans / hour per account
  - Per-domain cap    : 5 scans / hour per target domain (across all users)

Usage in route handlers:
    from app.core.rate_limiter import limiter
    from slowapi.util import get_remote_address

    @router.post("/scans/public")
    @limiter.limit("10/hour")
    async def public_scan(request: Request, ...):
        ...
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

# Key function: fall back to remote IP.
# Authenticated routes override this with user_id in the route decorator.
limiter = Limiter(key_func=get_remote_address, default_limits=["200/hour"])

# Exportable limit strings so tests and routes share one source of truth.
GUEST_SCAN_LIMIT = "10/hour"
USER_SCAN_LIMIT = "60/hour"
DOMAIN_SCAN_LIMIT = "5/hour"
