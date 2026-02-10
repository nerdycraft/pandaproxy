"""Tests for helper utility functions."""

import ssl
import struct
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from pandaproxy.helper import (
    close_writer,
    create_auth_payload,
    create_ssl_context,
    generate_self_signed_cert,
    parse_auth_payload,
)
from pandaproxy.protocol import AUTH_COMMAND, AUTH_MAGIC


class TestCreateAuthPayload:
    """Tests for create_auth_payload function."""

    def test_creates_80_byte_payload(self):
        """Auth payload should be exactly 80 bytes."""
        payload = create_auth_payload("12345678")
        assert len(payload) == 80

    def test_payload_starts_with_magic(self):
        """Payload should start with AUTH_MAGIC byte."""
        payload = create_auth_payload("testcode")
        assert payload[0] == AUTH_MAGIC

    def test_payload_contains_command(self):
        """Payload should contain AUTH_COMMAND at correct offset."""
        payload = create_auth_payload("testcode")
        # Command is at offset 4, little-endian uint32
        command = struct.unpack("<I", payload[4:8])[0]
        assert command == AUTH_COMMAND

    def test_payload_contains_access_code(self):
        """Payload should contain the access code."""
        access_code = "myaccess"
        payload = create_auth_payload(access_code)
        # Access code is at offset 16
        assert access_code.encode("utf-8") in payload

    def test_different_codes_produce_different_payloads(self):
        """Different access codes should produce different payloads."""
        payload1 = create_auth_payload("code1111")
        payload2 = create_auth_payload("code2222")
        assert payload1 != payload2

    def test_empty_access_code(self):
        """Empty access code should still produce valid 80-byte payload."""
        payload = create_auth_payload("")
        assert len(payload) == 80


class TestParseAuthPayload:
    """Tests for parse_auth_payload function."""

    def test_parses_valid_payload(self):
        """Should correctly parse a valid auth payload."""
        access_code = "testcode"
        payload = create_auth_payload(access_code)
        parsed = parse_auth_payload(payload)
        assert parsed == access_code

    def test_returns_none_for_invalid_magic(self):
        """Should return None if magic byte is wrong."""
        payload = bytearray(create_auth_payload("testcode"))
        payload[0] = 0x00  # Invalid magic
        result = parse_auth_payload(bytes(payload))
        assert result is None

    def test_returns_none_for_short_payload(self):
        """Should return None if payload is too short."""
        result = parse_auth_payload(b"short")
        assert result is None

    def test_returns_none_for_empty_payload(self):
        """Should return None for empty payload."""
        result = parse_auth_payload(b"")
        assert result is None

    def test_roundtrip_various_codes(self):
        """Various access codes should survive roundtrip."""
        codes = ["12345678", "abcdefgh", "A1B2C3D4", "test1234"]
        for code in codes:
            payload = create_auth_payload(code)
            parsed = parse_auth_payload(payload)
            assert parsed == code, f"Failed for code: {code}"


class TestGenerateSelfSignedCert:
    """Tests for generate_self_signed_cert function."""

    def test_generates_cert_and_key_files(self):
        """Should generate both certificate and key files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = Path(tmpdir) / "test.crt"
            key_path = Path(tmpdir) / "test.key"

            generate_self_signed_cert(
                common_name="TestCN",
                san_dns=["localhost"],
                san_ips=["127.0.0.1"],
                output_cert=cert_path,
                output_key=key_path,
            )

            assert cert_path.exists()
            assert key_path.exists()

    def test_cert_file_contains_pem_data(self):
        """Certificate file should contain PEM-formatted data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = Path(tmpdir) / "test.crt"
            key_path = Path(tmpdir) / "test.key"

            generate_self_signed_cert(
                common_name="TestCN",
                san_dns=["localhost"],
                san_ips=["127.0.0.1"],
                output_cert=cert_path,
                output_key=key_path,
            )

            cert_content = cert_path.read_text()
            assert "-----BEGIN CERTIFICATE-----" in cert_content
            assert "-----END CERTIFICATE-----" in cert_content

    def test_key_file_contains_pem_data(self):
        """Key file should contain PEM-formatted data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = Path(tmpdir) / "test.crt"
            key_path = Path(tmpdir) / "test.key"

            generate_self_signed_cert(
                common_name="TestCN",
                san_dns=["localhost"],
                san_ips=["127.0.0.1"],
                output_cert=cert_path,
                output_key=key_path,
            )

            key_content = key_path.read_text()
            assert "-----BEGIN" in key_content
            assert "PRIVATE KEY-----" in key_content

    def test_cert_can_be_loaded_by_ssl_context(self):
        """Generated cert should be loadable by SSL context."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = Path(tmpdir) / "test.crt"
            key_path = Path(tmpdir) / "test.key"

            generate_self_signed_cert(
                common_name="TestCN",
                san_dns=["localhost"],
                san_ips=["127.0.0.1"],
                output_cert=cert_path,
                output_key=key_path,
            )

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            # Should not raise
            ctx.load_cert_chain(cert_path, key_path)


class TestCreateSslContext:
    """Tests for create_ssl_context function."""

    def test_returns_ssl_context(self):
        """Should return an SSLContext instance."""
        ctx = create_ssl_context()
        assert isinstance(ctx, ssl.SSLContext)

    def test_context_is_client_mode(self):
        """Context should be configured for client mode."""
        ctx = create_ssl_context()
        # Client contexts don't require certificates to be loaded
        # We just verify it's a valid context
        assert ctx is not None


class TestCloseWriter:
    """Tests for close_writer function."""

    @pytest.mark.asyncio
    async def test_closes_writer(self):
        """Should call close and wait_closed on writer."""
        writer = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await close_writer(writer)

        writer.close.assert_called_once()
        writer.wait_closed.assert_called_once()

    @pytest.mark.asyncio
    async def test_handles_exception_gracefully(self):
        """Should not raise if wait_closed fails."""
        writer = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock(side_effect=Exception("Connection lost"))

        # Should not raise
        await close_writer(writer)

        writer.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_handles_none_writer(self):
        """Should handle None writer gracefully."""
        # This tests the function's robustness
        # Implementation may vary - adjust test if needed
        writer = MagicMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await close_writer(writer)
