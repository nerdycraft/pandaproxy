"""Tests for protocol constants."""

from pandaproxy.protocol import (
    AUTH_COMMAND,
    AUTH_MAGIC,
    CERT_FILENAME,
    CHAMBER_PORT,
    FTP_PORT,
    KEY_FILENAME,
    MAX_PAYLOAD_SIZE,
    MQTT_PORT,
    RTSP_PORT,
)


class TestPortConstants:
    """Tests for port number constants."""

    def test_rtsp_port(self):
        """RTSP port should be 322."""
        assert RTSP_PORT == 322

    def test_chamber_port(self):
        """Chamber port should be 6000."""
        assert CHAMBER_PORT == 6000

    def test_mqtt_port(self):
        """MQTT port should be 8883."""
        assert MQTT_PORT == 8883

    def test_ftp_port(self):
        """FTP port should be 990."""
        assert FTP_PORT == 990


class TestAuthConstants:
    """Tests for authentication constants."""

    def test_auth_magic_is_byte(self):
        """AUTH_MAGIC should be a single byte value."""
        assert isinstance(AUTH_MAGIC, int)
        assert 0 <= AUTH_MAGIC <= 255

    def test_auth_magic_value(self):
        """AUTH_MAGIC should be 0x40."""
        assert AUTH_MAGIC == 0x40

    def test_auth_command_is_int(self):
        """AUTH_COMMAND should be an integer."""
        assert isinstance(AUTH_COMMAND, int)

    def test_auth_command_value(self):
        """AUTH_COMMAND should be 0x3000."""
        assert AUTH_COMMAND == 0x3000


class TestPayloadConstants:
    """Tests for payload size constants."""

    def test_max_payload_size(self):
        """MAX_PAYLOAD_SIZE should be reasonable for images."""
        assert MAX_PAYLOAD_SIZE > 0
        # Should be at least 1MB for camera frames
        assert MAX_PAYLOAD_SIZE >= 1024 * 1024

    def test_max_payload_size_value(self):
        """MAX_PAYLOAD_SIZE should be 10 million bytes."""
        assert MAX_PAYLOAD_SIZE == 10_000_000


class TestCertConstants:
    """Tests for certificate filename constants."""

    def test_cert_filename(self):
        """CERT_FILENAME should be a string."""
        assert isinstance(CERT_FILENAME, str)
        assert len(CERT_FILENAME) > 0

    def test_key_filename(self):
        """KEY_FILENAME should be a string."""
        assert isinstance(KEY_FILENAME, str)
        assert len(KEY_FILENAME) > 0

    def test_cert_and_key_different(self):
        """Cert and key filenames should be different."""
        assert CERT_FILENAME != KEY_FILENAME
