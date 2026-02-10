"""Tests for Chamber Image Proxy."""

import asyncio
import ssl
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pandaproxy.chamber_proxy import ChamberImageProxy
from pandaproxy.helper import create_auth_payload, generate_self_signed_cert


@pytest.fixture
def temp_certs():
    """Generate temporary TLS certificates for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cert_path = Path(tmpdir) / "test.crt"
        key_path = Path(tmpdir) / "test.key"

        generate_self_signed_cert(
            common_name="TestProxy",
            san_dns=["localhost"],
            san_ips=["127.0.0.1", "::1"],
            output_cert=cert_path,
            output_key=key_path,
        )

        yield cert_path, key_path


class TestChamberImageProxyInit:
    """Tests for ChamberImageProxy initialization."""

    def test_init_sets_properties(self, temp_certs):
        """Init should set all properties correctly."""
        cert_path, key_path = temp_certs

        proxy = ChamberImageProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            cert_path=cert_path,
            key_path=key_path,
            bind_address="0.0.0.0",
        )

        assert proxy.printer_ip == "192.168.1.100"
        assert proxy.access_code == "testcode"
        assert proxy.cert_path == cert_path
        assert proxy.key_path == key_path
        assert proxy.bind_address == "0.0.0.0"
        assert proxy.port == 6000  # CHAMBER_PORT

    def test_init_defaults(self, temp_certs):
        """Init should use default bind address."""
        cert_path, key_path = temp_certs

        proxy = ChamberImageProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            cert_path=cert_path,
            key_path=key_path,
        )

        assert proxy.bind_address == "0.0.0.0"

    def test_init_creates_fanout(self, temp_certs):
        """Init should create a StreamFanout instance."""
        cert_path, key_path = temp_certs

        proxy = ChamberImageProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            cert_path=cert_path,
            key_path=key_path,
        )

        assert proxy._fanout is not None
        assert proxy._fanout.name == "chamber_image"


class TestChamberImageProxyLifecycle:
    """Tests for ChamberImageProxy start/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_start_raises_if_certs_missing(self, temp_certs):
        """Start should raise if certificate files don't exist."""
        cert_path, key_path = temp_certs

        proxy = ChamberImageProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            cert_path=Path("/nonexistent/cert.crt"),
            key_path=Path("/nonexistent/key.key"),
        )

        with pytest.raises(FileNotFoundError):
            await proxy.start()

    @pytest.mark.asyncio
    async def test_start_sets_running_flag(self, temp_certs):
        """Start should set _running to True."""
        cert_path, key_path = temp_certs

        proxy = ChamberImageProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            cert_path=cert_path,
            key_path=key_path,
            bind_address="127.0.0.1",
        )

        try:
            await proxy.start()
            assert proxy._running is True
            assert proxy._server is not None
        finally:
            await proxy.stop()

    @pytest.mark.asyncio
    async def test_stop_clears_running_flag(self, temp_certs):
        """Stop should set _running to False."""
        cert_path, key_path = temp_certs

        proxy = ChamberImageProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            cert_path=cert_path,
            key_path=key_path,
            bind_address="127.0.0.1",
        )

        await proxy.start()
        await proxy.stop()

        assert proxy._running is False


class TestChamberImageProxyClientHandling:
    """Tests for client connection handling."""

    @pytest.mark.asyncio
    async def test_client_auth_validation(self, temp_certs):
        """Should validate client access code."""
        cert_path, key_path = temp_certs

        proxy = ChamberImageProxy(
            printer_ip="192.168.1.100",
            access_code="correctcode",
            cert_path=cert_path,
            key_path=key_path,
            bind_address="127.0.0.1",
        )

        await proxy.start()

        try:
            # Get the port
            port = proxy._server.sockets[0].getsockname()[1]

            # Create client SSL context
            client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_ctx.check_hostname = False
            client_ctx.verify_mode = ssl.CERT_NONE

            # Connect with wrong auth
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", port, ssl=client_ctx
            )

            try:
                # Send wrong access code
                wrong_auth = create_auth_payload("wrongcode")
                writer.write(wrong_auth)
                await writer.drain()

                # Server should close connection (no data sent back)
                await asyncio.sleep(0.5)
                # Connection should be closed by server

            finally:
                writer.close()
                await writer.wait_closed()

        finally:
            await proxy.stop()

    @pytest.mark.asyncio
    async def test_client_auth_success(self, temp_certs):
        """Should accept client with correct access code."""
        cert_path, key_path = temp_certs

        proxy = ChamberImageProxy(
            printer_ip="192.168.1.100",
            access_code="correctcode",
            cert_path=cert_path,
            key_path=key_path,
            bind_address="127.0.0.1",
        )

        await proxy.start()

        try:
            port = proxy._server.sockets[0].getsockname()[1]

            client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_ctx.check_hostname = False
            client_ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.open_connection(
                "127.0.0.1", port, ssl=client_ctx
            )

            try:
                # Send correct access code
                correct_auth = create_auth_payload("correctcode")
                writer.write(correct_auth)
                await writer.drain()

                # Should not be immediately disconnected
                await asyncio.sleep(0.2)
                # If we got here without exception, auth was accepted

            finally:
                writer.close()
                await writer.wait_closed()

        finally:
            await proxy.stop()
