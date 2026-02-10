"""Tests for MQTT Proxy."""

import asyncio
import ssl
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pandaproxy.helper import generate_self_signed_cert
from pandaproxy.mqtt_proxy import MQTTProxy


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


class TestMQTTProxyInit:
    """Tests for MQTTProxy initialization."""

    def test_init_sets_properties(self, temp_certs):
        """Init should set all properties correctly."""
        cert_path, key_path = temp_certs

        proxy = MQTTProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            serial_number="ABC123",
            cert_path=cert_path,
            key_path=key_path,
            bind_address="0.0.0.0",
        )

        assert proxy.printer_ip == "192.168.1.100"
        assert proxy.access_code == "testcode"
        assert proxy.serial_number == "ABC123"
        assert proxy.cert_path == cert_path
        assert proxy.key_path == key_path
        assert proxy.bind_address == "0.0.0.0"
        assert proxy.port == 8883  # MQTT_PORT

    def test_init_defaults(self, temp_certs):
        """Init should use default bind address."""
        cert_path, key_path = temp_certs

        proxy = MQTTProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            serial_number="ABC123",
            cert_path=cert_path,
            key_path=key_path,
        )

        assert proxy.bind_address == "0.0.0.0"


class TestMQTTProxyLifecycle:
    """Tests for MQTTProxy start/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_start_raises_if_certs_missing(self, temp_certs):
        """Start should raise if certificate files don't exist."""
        cert_path, key_path = temp_certs

        proxy = MQTTProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            serial_number="ABC123",
            cert_path=Path("/nonexistent/cert.crt"),
            key_path=Path("/nonexistent/key.key"),
        )

        with pytest.raises(FileNotFoundError):
            await proxy.start()

    @pytest.mark.asyncio
    async def test_start_creates_server(self, temp_certs):
        """Start should create a server."""
        cert_path, key_path = temp_certs

        proxy = MQTTProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            serial_number="ABC123",
            cert_path=cert_path,
            key_path=key_path,
            bind_address="127.0.0.1",
        )

        try:
            await proxy.start()
            assert proxy._server is not None
            assert proxy._running is True
        finally:
            await proxy.stop()

    @pytest.mark.asyncio
    async def test_stop_clears_server(self, temp_certs):
        """Stop should clear server reference."""
        cert_path, key_path = temp_certs

        proxy = MQTTProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            serial_number="ABC123",
            cert_path=cert_path,
            key_path=key_path,
            bind_address="127.0.0.1",
        )

        await proxy.start()
        await proxy.stop()

        assert proxy._running is False

    @pytest.mark.asyncio
    async def test_double_start_raises_address_in_use(self, temp_certs):
        """Calling start() twice without stop() should fail (port already bound)."""
        cert_path, key_path = temp_certs

        proxy = MQTTProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            serial_number="ABC123",
            cert_path=cert_path,
            key_path=key_path,
            bind_address="127.0.0.1",
        )

        try:
            await proxy.start()
            server1 = proxy._server

            # Second start should raise OSError (address already in use)
            # because the port is already bound
            with pytest.raises(OSError):
                await proxy.start()

            # Original server should still be the same
            assert proxy._server is server1
        finally:
            await proxy.stop()


class TestMQTTProxyConnection:
    """Tests for MQTT proxy client connections."""

    @pytest.mark.asyncio
    async def test_accepts_tls_connection(self, temp_certs):
        """Should accept TLS connections."""
        cert_path, key_path = temp_certs

        proxy = MQTTProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            serial_number="ABC123",
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

            # Should be able to connect
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port, ssl=client_ctx),
                timeout=5.0,
            )

            writer.close()
            await writer.wait_closed()

        finally:
            await proxy.stop()

    @pytest.mark.asyncio
    async def test_multiple_clients(self, temp_certs):
        """Should handle multiple concurrent clients."""
        cert_path, key_path = temp_certs

        proxy = MQTTProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            serial_number="ABC123",
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

            # Connect multiple clients
            connections = []
            for _ in range(3):
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", port, ssl=client_ctx),
                    timeout=5.0,
                )
                connections.append((reader, writer))

            # All should be connected
            assert len(connections) == 3

            # Clean up
            for _, writer in connections:
                writer.close()
                await writer.wait_closed()

        finally:
            await proxy.stop()
