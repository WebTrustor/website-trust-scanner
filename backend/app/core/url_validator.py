"""
URL Safety Validator — SSRF prevention layer.

Every URL that the backend would fetch on behalf of a user MUST pass
validate_url() before any outbound request is made.  The same check is
repeated after every HTTP redirect so a redirect chain cannot escape to a
private address.

Blocked ranges (RFC-based):
  - Loopback          127.0.0.0/8,  ::1
  - Private           10/8, 172.16/12, 192.168/16
  - Link-local        169.254.0.0/16,  fe80::/10
  - Cloud metadata    169.254.169.254  (AWS/GCP/Azure IMDSv1)
  - Unique-local IPv6 fc00::/7
  - Multicast         224.0.0.0/4,  ff00::/8
  - Unspecified       0.0.0.0/8,  ::

Allowed schemes: https only (http kept for explicit opt-in in tests only).
"""

import ipaddress
import re
import socket
from urllib.parse import urlparse

from app.core.exceptions import SSRFBlockedError, URLValidationError

# Maximum label length, total hostname length, port range
_MAX_HOSTNAME_LEN = 253
_MAX_LABEL_LEN = 63
_ALLOWED_SCHEMES = {"https", "http"}

# Networks that are never safe to reach from the scanner
_BLOCKED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    # Loopback
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv6Network("::1/128"),
    # Private
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    # Link-local / cloud metadata (AWS IMDSv1, Azure IMDS, GCP metadata)
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv6Network("fe80::/10"),
    # Cloud metadata explicit
    ipaddress.IPv4Network("169.254.169.254/32"),
    # Unique-local IPv6
    ipaddress.IPv6Network("fc00::/7"),
    # Multicast
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv6Network("ff00::/8"),
    # Unspecified / any
    ipaddress.IPv4Network("0.0.0.0/8"),
    # Shared address space (RFC 6598, carrier-grade NAT)
    ipaddress.IPv4Network("100.64.0.0/10"),
    # Documentation ranges (should never be real destinations)
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
    # Benchmarking
    ipaddress.IPv4Network("198.18.0.0/15"),
]


def _is_ip_blocked(ip_str: str) -> bool:
    """Return True if the resolved IP falls in any blocked network."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable → block

    if addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_multicast:
        return True

    for net in _BLOCKED_NETWORKS:
        if addr in net:
            return True

    return False


def _is_valid_hostname(hostname: str) -> bool:
    """Lightweight hostname syntax check (no DNS lookup)."""
    if not hostname or len(hostname) > _MAX_HOSTNAME_LEN:
        return False
    # Strip trailing dot (FQDN)
    hostname = hostname.rstrip(".")
    labels = hostname.split(".")
    if len(labels) < 2:
        return False
    label_re = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
    for label in labels:
        if len(label) > _MAX_LABEL_LEN or not label_re.match(label):
            return False
    return True


def _resolve_hostname(hostname: str) -> list[str]:
    """
    Resolve a hostname to IP addresses using getaddrinfo.

    Returns a list of IP strings.  Raises URLValidationError if the hostname
    cannot be resolved.
    """
    try:
        results = socket.getaddrinfo(hostname, None)
        return list({r[4][0] for r in results})  # deduplicate
    except socket.gaierror as exc:
        raise URLValidationError(
            message=f"Cannot resolve hostname '{hostname}'",
            detail=str(exc),
        ) from exc


def validate_url(url: str, *, allow_http: bool = False) -> str:
    """
    Validate *url* for safety.  Raises URLValidationError or SSRFBlockedError.

    Returns the normalised URL string on success.

    Steps:
      1. Parse and check scheme.
      2. Extract and validate hostname syntax.
      3. Reject bare IPs that are in blocked ranges (before DNS).
      4. Resolve hostname → IPs and block any private/reserved address.
    """
    if not url or not isinstance(url, str):
        raise URLValidationError(message="URL must be a non-empty string")

    url = url.strip()

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()

    allowed = _ALLOWED_SCHEMES if allow_http else {"https"}
    if scheme not in allowed:
        raise URLValidationError(
            message=f"Scheme '{scheme}' is not allowed; use https"
        )

    hostname = parsed.hostname
    if not hostname:
        raise URLValidationError(message="URL has no hostname")

    # Check port range if present (urlparse raises ValueError for >65535)
    try:
        port = parsed.port
    except ValueError as exc:
        raise URLValidationError(message=f"Invalid port in URL: {exc}") from exc
    if port is not None and not (1 <= port <= 65535):
        raise URLValidationError(message=f"Port {port} is out of range")

    # If the hostname is a raw IP address, check it immediately
    try:
        ipaddress.ip_address(hostname)
        if _is_ip_blocked(hostname):
            raise SSRFBlockedError(
                message="Direct IP addresses in private/reserved ranges are not allowed",
                detail=f"Blocked address: {hostname}",
            )
        # Raw public IP — no DNS needed
        return url
    except ValueError:
        pass  # It's a hostname, not a raw IP

    # Hostname syntax check
    if not _is_valid_hostname(hostname):
        raise URLValidationError(
            message=f"Invalid hostname format: '{hostname}'"
        )

    # DNS resolution + SSRF check
    resolved_ips = _resolve_hostname(hostname)
    for ip in resolved_ips:
        if _is_ip_blocked(ip):
            raise SSRFBlockedError(
                message="The hostname resolves to a private or reserved IP address",
                detail=f"Hostname '{hostname}' resolved to blocked IP: {ip}",
            )

    return url


def validate_redirect_url(url: str) -> str:
    """
    Validate a redirect target before following it.

    Identical rules to validate_url but always called with allow_http=True
    because redirect chains from an https origin may hit an http hop.
    """
    return validate_url(url, allow_http=True)
