"""
Unit tests for DNS TXT ownership verification.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.dns_verification import (
    generate_verification_token,
    get_expected_txt,
    verify_ownership,
)


class TestTokenGeneration:
    def test_token_is_64_hex_chars(self):
        token = generate_verification_token("some-site-id")
        assert len(token) == 64
        assert all(c in "0123456789abcdef" for c in token)

    def test_same_id_same_token(self):
        assert generate_verification_token("abc") == generate_verification_token("abc")

    def test_different_ids_different_tokens(self):
        assert generate_verification_token("id-1") != generate_verification_token("id-2")

    def test_token_changes_with_secret(self, monkeypatch):
        from app.core import config as cfg_mod
        original = generate_verification_token("x")
        monkeypatch.setattr(cfg_mod.settings, "secret_key", "different-secret")
        # Import the function fresh after monkeypatching settings
        from app.services import dns_verification as dv
        alt = dv.generate_verification_token("x")
        assert original != alt

    def test_expected_txt_has_prefix(self):
        txt = get_expected_txt("site-123")
        assert txt.startswith("trustscanner-verify=")

    def test_expected_txt_contains_token(self):
        token = generate_verification_token("site-123")
        txt = get_expected_txt("site-123")
        assert token in txt


class TestVerifyOwnership:
    @pytest.mark.asyncio
    async def test_returns_true_when_record_found(self):
        site_id = "test-site-id"
        expected = get_expected_txt(site_id)

        mock_rdata = MagicMock()
        mock_rdata.strings = [expected.encode()]
        mock_answers = [mock_rdata]

        with patch("dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(return_value=mock_answers)
            result = await verify_ownership("example.com", site_id)

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_when_record_missing(self):
        mock_rdata = MagicMock()
        mock_rdata.strings = [b"some-other-value"]
        mock_answers = [mock_rdata]

        with patch("dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(return_value=mock_answers)
            result = await verify_ownership("example.com", "site-id")

        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_on_dns_error(self):
        import dns.exception

        with patch("dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(side_effect=dns.exception.DNSException)
            result = await verify_ownership("nonexistent.example.com", "site-id")

        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_on_generic_exception(self):
        with patch("dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(side_effect=Exception("network error"))
            result = await verify_ownership("example.com", "site-id")

        assert result is False
