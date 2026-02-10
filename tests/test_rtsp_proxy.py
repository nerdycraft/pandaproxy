"""Tests for RTSP Proxy using FFmpeg and MediaMTX."""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pandaproxy.helper import generate_self_signed_cert
from pandaproxy.rtsp_proxy import (
    MEDIAMTX_CONFIG_TEMPLATE,
    RTSPProxy,
    check_dependencies,
)


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


class TestCheckDependencies:
    """Tests for check_dependencies function."""

    def test_returns_tuple(self):
        """Should return a tuple of (bool, list)."""
        result = check_dependencies()
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], list)

    def test_detects_missing_ffmpeg(self):
        """Should detect when ffmpeg is missing."""
        with patch("shutil.which") as mock_which:
            mock_which.side_effect = lambda cmd: None if cmd == "ffmpeg" else "/usr/bin/mediamtx"

            ok, missing = check_dependencies()

            assert ok is False
            assert "ffmpeg" in missing
            assert "mediamtx" not in missing

    def test_detects_missing_mediamtx(self):
        """Should detect when mediamtx is missing."""
        with patch("shutil.which") as mock_which:
            mock_which.side_effect = lambda cmd: None if cmd == "mediamtx" else "/usr/bin/ffmpeg"

            ok, missing = check_dependencies()

            assert ok is False
            assert "mediamtx" in missing
            assert "ffmpeg" not in missing

    def test_detects_both_missing(self):
        """Should detect when both dependencies are missing."""
        with patch("shutil.which", return_value=None):
            ok, missing = check_dependencies()

            assert ok is False
            assert "ffmpeg" in missing
            assert "mediamtx" in missing

    def test_returns_ok_when_both_present(self):
        """Should return ok when both dependencies are present."""
        with patch("shutil.which", return_value="/usr/bin/mock"):
            ok, missing = check_dependencies()

            assert ok is True
            assert missing == []


class TestMediaMTXConfigTemplate:
    """Tests for MediaMTX configuration template."""

    def test_template_contains_required_placeholders(self):
        """Template should contain all required format placeholders."""
        assert "{rtsp_port}" in MEDIAMTX_CONFIG_TEMPLATE
        assert "{access_code}" in MEDIAMTX_CONFIG_TEMPLATE
        assert "{server_cert}" in MEDIAMTX_CONFIG_TEMPLATE
        assert "{server_key}" in MEDIAMTX_CONFIG_TEMPLATE

    def test_template_formats_correctly(self):
        """Template should format with all placeholders filled."""
        formatted = MEDIAMTX_CONFIG_TEMPLATE.format(
            rtsp_port=322,
            access_code="testcode",
            server_cert="/path/to/cert.crt",
            server_key="/path/to/key.key",
        )

        assert "322" in formatted
        assert "testcode" in formatted
        assert "/path/to/cert.crt" in formatted
        assert "/path/to/key.key" in formatted

    def test_template_has_bblp_user(self):
        """Template should configure bblp as the auth user (BambuLab standard)."""
        assert "bblp" in MEDIAMTX_CONFIG_TEMPLATE

    def test_template_uses_tcp_protocol(self):
        """Template should use TCP for RTSP transport."""
        assert "tcp" in MEDIAMTX_CONFIG_TEMPLATE

    def test_template_enables_rtsp_encryption(self):
        """Template should enable RTSP encryption (RTSPS)."""
        assert 'rtspEncryption: "yes"' in MEDIAMTX_CONFIG_TEMPLATE


class TestRTSPProxyInit:
    """Tests for RTSPProxy initialization."""

    def test_init_sets_properties(self, temp_certs):
        """Init should set all properties correctly."""
        cert_path, key_path = temp_certs

        proxy = RTSPProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            cert_path=cert_path,
            key_path=key_path,
            bind_address="0.0.0.0",
            mediamtx_internal_port=8554,
        )

        assert proxy.printer_ip == "192.168.1.100"
        assert proxy.access_code == "testcode"
        assert proxy.cert_path == cert_path
        assert proxy.key_path == key_path
        assert proxy.bind_address == "0.0.0.0"
        assert proxy.port == 322  # Standard RTSPS port
        assert proxy.mediamtx_internal_port == 8554

    def test_init_defaults(self, temp_certs):
        """Init should use default values."""
        cert_path, key_path = temp_certs

        proxy = RTSPProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            cert_path=cert_path,
            key_path=key_path,
        )

        assert proxy.bind_address == "0.0.0.0"
        assert proxy.mediamtx_internal_port == 8554

    def test_init_state(self, temp_certs):
        """Init should set up proper initial state."""
        cert_path, key_path = temp_certs

        proxy = RTSPProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            cert_path=cert_path,
            key_path=key_path,
        )

        assert proxy._ffmpeg_process is None
        assert proxy._mediamtx_process is None
        assert proxy._running is False
        assert proxy._config_path is None


class TestRTSPProxyLifecycle:
    """Tests for RTSPProxy start/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_start_raises_if_dependencies_missing(self, temp_certs):
        """Start should raise if ffmpeg or mediamtx is missing."""
        cert_path, key_path = temp_certs

        proxy = RTSPProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            cert_path=cert_path,
            key_path=key_path,
        )

        with patch(
            "pandaproxy.rtsp_proxy.check_dependencies", return_value=(False, ["ffmpeg", "mediamtx"])
        ):
            with pytest.raises(RuntimeError) as exc_info:
                await proxy.start()

            assert "Missing required dependencies" in str(exc_info.value)
            assert "ffmpeg" in str(exc_info.value)
            assert "mediamtx" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_start_raises_if_certs_missing(self, temp_certs):
        """Start should raise if certificate files don't exist."""
        cert_path, key_path = temp_certs

        proxy = RTSPProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            cert_path=Path("/nonexistent/cert.crt"),
            key_path=Path("/nonexistent/key.key"),
        )

        with (
            patch("pandaproxy.rtsp_proxy.check_dependencies", return_value=(True, [])),
            pytest.raises(FileNotFoundError),
        ):
            await proxy.start()

    @pytest.mark.asyncio
    async def test_start_sets_running_flag(self, temp_certs):
        """Start should set _running to True."""
        cert_path, key_path = temp_certs

        proxy = RTSPProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            cert_path=cert_path,
            key_path=key_path,
        )

        # Create mock process - use MagicMock since terminate()/kill() are sync methods
        # Only wait() is async on asyncio.subprocess.Process
        mock_process = MagicMock()
        mock_process.stdout = AsyncMock()
        mock_process.stderr = AsyncMock()
        mock_process.returncode = None
        mock_process.wait = AsyncMock()

        with (
            patch("pandaproxy.rtsp_proxy.check_dependencies", return_value=(True, [])),
            patch("asyncio.create_subprocess_exec", return_value=mock_process),
            patch("asyncio.sleep", new_callable=AsyncMock),
        ):
            try:
                await proxy.start()
                assert proxy._running is True
                assert proxy._config_path is not None
            finally:
                await proxy.stop()

    @pytest.mark.asyncio
    async def test_stop_clears_running_flag(self, temp_certs):
        """Stop should set _running to False."""
        cert_path, key_path = temp_certs

        proxy = RTSPProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            cert_path=cert_path,
            key_path=key_path,
        )

        # Create mock process - use MagicMock since terminate()/kill() are sync methods
        # Only wait() is async on asyncio.subprocess.Process
        mock_process = MagicMock()
        mock_process.stdout = AsyncMock()
        mock_process.stderr = AsyncMock()
        mock_process.returncode = None
        mock_process.wait = AsyncMock()

        with (
            patch("pandaproxy.rtsp_proxy.check_dependencies", return_value=(True, [])),
            patch("asyncio.create_subprocess_exec", return_value=mock_process),
            patch("asyncio.sleep", new_callable=AsyncMock),
        ):
            await proxy.start()
            await proxy.stop()

            assert proxy._running is False

    @pytest.mark.asyncio
    async def test_stop_without_start(self, temp_certs):
        """Stop should handle being called without start."""
        cert_path, key_path = temp_certs

        proxy = RTSPProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            cert_path=cert_path,
            key_path=key_path,
        )

        # Should not raise
        await proxy.stop()
        assert proxy._running is False


class TestRTSPProxyConfig:
    """Tests for MediaMTX configuration generation."""

    @pytest.mark.asyncio
    async def test_creates_config_file(self, temp_certs):
        """Should create a valid config file."""
        cert_path, key_path = temp_certs

        proxy = RTSPProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            cert_path=cert_path,
            key_path=key_path,
        )

        config_path = await proxy._create_mediamtx_config()

        try:
            assert config_path.exists()
            content = config_path.read_text()

            # Check content
            assert "322" in content  # RTSP port
            assert "testcode" in content  # Access code
            assert str(cert_path.absolute()) in content
            assert str(key_path.absolute()) in content
        finally:
            if config_path.exists():
                config_path.unlink()

    @pytest.mark.asyncio
    async def test_config_raises_if_certs_missing(self, temp_certs):
        """Should raise if cert files are missing."""
        cert_path, key_path = temp_certs

        proxy = RTSPProxy(
            printer_ip="192.168.1.100",
            access_code="testcode",
            cert_path=Path("/nonexistent/cert.crt"),
            key_path=Path("/nonexistent/key.key"),
        )

        with pytest.raises(FileNotFoundError):
            await proxy._create_mediamtx_config()


class TestRTSPProxyStreaming:
    """Tests for RTSP streaming URL construction."""

    def test_source_url_format(self, temp_certs):
        """FFmpeg should use correct source URL format."""
        cert_path, key_path = temp_certs

        proxy = RTSPProxy(
            printer_ip="192.168.1.100",
            access_code="secretcode",
            cert_path=cert_path,
            key_path=key_path,
        )

        # The source URL is constructed in _start_ffmpeg
        # Format: rtsps://bblp:<access_code>@<ip>:322/streaming/live/1
        # We can't directly test the private method without mocking,
        # but we can verify the components are stored correctly
        assert proxy.printer_ip == "192.168.1.100"
        assert proxy.access_code == "secretcode"
        assert proxy.port == 322
