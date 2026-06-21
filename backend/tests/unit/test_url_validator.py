"""
Unit tests for URL Safety Validator (SSRF prevention).

DNS resolution is monkeypatched so tests run without network access.
"""

import socket
import pytest

from app.core.url_validator import validate_url, validate_redirect_url
from app.core.exceptions import SSRFBlockedError, URLValidationError


# ── Helpers ──────────────────────────────────────────────────────────────────

def _mock_resolve(ip: str):
    """Return a patched getaddrinfo that always resolves to `ip`."""
    def _getaddrinfo(host, port, *args, **kwargs):
        return [(None, None, None, None, (ip, 0))]
    return _getaddrinfo


# ── Scheme validation ─────────────────────────────────────────────────────────

class TestScheme:
    def test_https_allowed(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", _mock_resolve("93.184.216.34"))
        result = validate_url("https://example.com")
        assert result == "https://example.com"

    def test_http_blocked_by_default(self):
        with pytest.raises(URLValidationError) as exc:
            validate_url("http://example.com")
        assert exc.value.error_code == "INVALID_URL"

    def test_http_allowed_with_flag(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", _mock_resolve("93.184.216.34"))
        result = validate_url("http://example.com", allow_http=True)
        assert result == "http://example.com"

    def test_ftp_blocked(self):
        with pytest.raises(URLValidationError):
            validate_url("ftp://example.com")

    def test_file_scheme_blocked(self):
        with pytest.raises(URLValidationError):
            validate_url("file:///etc/passwd")

    def test_javascript_scheme_blocked(self):
        with pytest.raises(URLValidationError):
            validate_url("javascript:alert(1)")

    def test_empty_string_raises(self):
        with pytest.raises(URLValidationError):
            validate_url("")

    def test_none_raises(self):
        with pytest.raises(URLValidationError):
            validate_url(None)  # type: ignore[arg-type]


# ── Private IP blocking (raw IP in URL) ───────────────────────────────────────

class TestRawIPBlocking:
    @pytest.mark.parametrize("ip", [
        "127.0.0.1",
        "127.0.0.2",
        "127.255.255.255",
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.255.255",
        "169.254.0.1",
        "169.254.169.254",    # AWS/GCP/Azure metadata
        "0.0.0.0",
        "100.64.0.1",          # Carrier-grade NAT
        "192.0.2.1",           # TEST-NET-1
        "198.51.100.1",        # TEST-NET-2
        "203.0.113.1",         # TEST-NET-3
        "198.18.0.1",          # Benchmarking
        "224.0.0.1",           # Multicast
    ])
    def test_private_ipv4_blocked(self, ip):
        with pytest.raises(SSRFBlockedError) as exc:
            validate_url(f"https://{ip}", allow_http=True)
        assert exc.value.error_code == "SSRF_BLOCKED"

    def test_loopback_ipv6_blocked(self):
        with pytest.raises(SSRFBlockedError):
            validate_url("https://[::1]", allow_http=True)

    def test_public_ip_allowed(self, monkeypatch):
        # Public IP — no DNS resolution needed, should pass directly
        result = validate_url("https://93.184.216.34")
        assert "93.184.216.34" in result


# ── DNS-resolved private IP blocking ─────────────────────────────────────────

class TestDNSResolutionBlocking:
    @pytest.mark.parametrize("resolved_ip", [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
    ])
    def test_hostname_resolving_to_private_blocked(self, monkeypatch, resolved_ip):
        monkeypatch.setattr(socket, "getaddrinfo", _mock_resolve(resolved_ip))
        with pytest.raises(SSRFBlockedError) as exc:
            validate_url("https://internal.example.com")
        assert exc.value.error_code == "SSRF_BLOCKED"

    def test_hostname_resolving_to_public_allowed(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", _mock_resolve("93.184.216.34"))
        result = validate_url("https://example.com")
        assert result == "https://example.com"

    def test_dns_failure_raises_validation_error(self, monkeypatch):
        def _fail(*args, **kwargs):
            raise socket.gaierror("Name resolution failed")
        monkeypatch.setattr(socket, "getaddrinfo", _fail)
        with pytest.raises(URLValidationError) as exc:
            validate_url("https://nonexistent.invalid")
        assert exc.value.error_code == "INVALID_URL"


# ── Hostname syntax validation ────────────────────────────────────────────────

class TestHostnameSyntax:
    def test_valid_hostname(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", _mock_resolve("1.2.3.4"))
        assert validate_url("https://valid-host.example.com")

    def test_no_hostname_raises(self):
        with pytest.raises(URLValidationError):
            validate_url("https://")

    def test_label_too_long_raises(self, monkeypatch):
        long_label = "a" * 64
        with pytest.raises(URLValidationError):
            validate_url(f"https://{long_label}.example.com")

    def test_hostname_too_long_raises(self, monkeypatch):
        long = ("a" * 50 + ".") * 6  # > 253 chars
        with pytest.raises(URLValidationError):
            validate_url(f"https://{long}")

    def test_single_label_hostname_rejected(self, monkeypatch):
        # Bare hostname like "https://localhost" has only one label
        with pytest.raises(URLValidationError):
            validate_url("https://localhost")

    def test_invalid_port_range_raises(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", _mock_resolve("1.2.3.4"))
        with pytest.raises(URLValidationError):
            validate_url("https://example.com:99999")


# ── Cloud metadata endpoint ───────────────────────────────────────────────────

class TestCloudMetadata:
    def test_aws_metadata_ip_blocked(self):
        with pytest.raises(SSRFBlockedError):
            validate_url("https://169.254.169.254/latest/meta-data/")

    def test_aws_metadata_hostname_blocked(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", _mock_resolve("169.254.169.254"))
        with pytest.raises(SSRFBlockedError):
            validate_url("https://metadata.aws.internal")


# ── validate_redirect_url ─────────────────────────────────────────────────────

class TestRedirectValidation:
    def test_redirect_to_public_allowed(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", _mock_resolve("1.2.3.4"))
        result = validate_redirect_url("http://example.com/new-path")
        assert "example.com" in result

    def test_redirect_to_private_blocked(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", _mock_resolve("192.168.1.1"))
        with pytest.raises(SSRFBlockedError):
            validate_redirect_url("http://internal.example.com")

    def test_redirect_to_metadata_ip_blocked(self):
        with pytest.raises(SSRFBlockedError):
            validate_redirect_url("http://169.254.169.254/")
