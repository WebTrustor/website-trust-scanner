from fastapi import status


class AppError(Exception):
    """Base application exception."""

    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    error_code: str = "INTERNAL_ERROR"
    message: str = "An unexpected error occurred"

    def __init__(self, message: str | None = None, detail: str | None = None):
        self.message = message or self.__class__.message
        self.detail = detail
        super().__init__(self.message)


# ── URL / SSRF ──────────────────────────────────────────────────────────────

class URLValidationError(AppError):
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    error_code = "INVALID_URL"
    message = "The provided URL is invalid"


class URLNotSafeError(AppError):
    status_code = status.HTTP_400_BAD_REQUEST
    error_code = "URL_NOT_SAFE"
    message = "The URL resolves to a disallowed address"


class SSRFBlockedError(URLNotSafeError):
    error_code = "SSRF_BLOCKED"
    message = "The URL targets a private or reserved address"


# ── Scan policy ──────────────────────────────────────────────────────────────

class DomainBlockedError(AppError):
    status_code = status.HTTP_403_FORBIDDEN
    error_code = "DOMAIN_BLOCKED"
    message = "This domain is on the Do Not Scan list"


class ScanNotAllowedError(AppError):
    status_code = status.HTTP_403_FORBIDDEN
    error_code = "SCAN_NOT_ALLOWED"
    message = "This scan type is not allowed for this site"


class AuthorizationRequiredError(AppError):
    status_code = status.HTTP_403_FORBIDDEN
    error_code = "AUTHORIZATION_REQUIRED"
    message = "An Authorization Record is required for this scan"


# ── Rate limiting ────────────────────────────────────────────────────────────

class RateLimitExceededError(AppError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    error_code = "RATE_LIMIT_EXCEEDED"
    message = "Too many requests — please slow down"
