"""Tests for ping module."""

import socket
from unittest.mock import MagicMock, patch

import pytest

from network_utils.ping import (
    PingResult,
    _checksum,
    _create_icmp_packet,
    _resolve_host,
    is_host_reachable,
    ping,
    ping_multiple,
    ping_stream,
)


class TestPingResult:
    """Tests for PingResult dataclass."""

    def test_default_values(self):
        """Test PingResult default values."""
        result = PingResult(host="example.com", is_reachable=True)
        assert result.host == "example.com"
        assert result.is_reachable is True
        assert result.packets_sent == 0
        assert result.packets_received == 0
        assert result.packet_loss == 0.0
        assert result.min_rtt is None
        assert result.avg_rtt is None
        assert result.max_rtt is None
        assert result.error is None


class TestChecksum:
    """Tests for _checksum function."""

    def test_checksum_calculation(self):
        """Test ICMP checksum calculation."""
        # Test with known data
        data = b"\x08\x00\x00\x00\x00\x01\x00\x01"
        result = _checksum(data)
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFF

    def test_checksum_odd_length(self):
        """Test checksum with odd length data."""
        data = b"\x08\x00\x00"
        result = _checksum(data)
        assert isinstance(result, int)


class TestCreateIcmpPacket:
    """Tests for _create_icmp_packet function."""

    def test_packet_structure(self):
        """Test ICMP packet structure."""
        packet = _create_icmp_packet(seq=1, packet_id=1234)

        # Header is 8 bytes, payload is 56 bytes by default
        assert len(packet) == 8 + 56

        # First byte should be ICMP Echo Request type (8)
        assert packet[0] == 8
        # Second byte (code) should be 0
        assert packet[1] == 0

    def test_packet_with_custom_payload(self):
        """Test ICMP packet with custom payload size."""
        packet = _create_icmp_packet(seq=1, packet_id=1234, payload_size=32)
        assert len(packet) == 8 + 32


class TestResolveHost:
    """Tests for _resolve_host function."""

    def test_resolve_valid_ip(self):
        """Test resolving a valid IP address."""
        ip = _resolve_host("8.8.8.8")
        assert ip == "8.8.8.8"

    @patch("socket.gethostbyname")
    def test_resolve_hostname(self, mock_gethostbyname):
        """Test resolving a hostname."""
        mock_gethostbyname.return_value = "142.250.80.46"
        ip = _resolve_host("google.com")
        assert ip == "142.250.80.46"

    @patch("socket.gethostbyname")
    def test_resolve_invalid_hostname(self, mock_gethostbyname):
        """Test resolving an invalid hostname."""
        mock_gethostbyname.side_effect = socket.gaierror("Name resolution failed")

        with pytest.raises(ValueError, match="Cannot resolve hostname"):
            _resolve_host("invalid.hostname.test")


class TestPing:
    """Tests for ping function."""

    @patch("socket.gethostbyname")
    def test_ping_invalid_host(self, mock_resolve):
        """Test ping with invalid host."""
        mock_resolve.side_effect = socket.gaierror("Name resolution failed")

        result = ping("invalid.hostname.test", count=1)

        assert result.is_reachable is False
        assert "Cannot resolve" in result.error

    @patch("network_utils.ping.socket.socket")
    @patch("socket.gethostbyname")
    def test_ping_permission_denied(self, mock_resolve, mock_socket):
        """Test ping without root privileges."""
        mock_resolve.return_value = "8.8.8.8"
        mock_socket.side_effect = PermissionError()

        result = ping("8.8.8.8", count=1)

        assert result.is_reachable is False
        assert "Permission denied" in result.error

    @patch("network_utils.ping.os.getpid", return_value=12345)
    @patch("network_utils.ping.socket.socket")
    @patch("socket.gethostbyname")
    def test_ping_success(self, mock_resolve, mock_socket_class, mock_getpid):
        """Test successful ping."""
        mock_resolve.return_value = "8.8.8.8"

        # Create mock socket
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        # Mock ICMP reply (IP header + ICMP header)
        # IP header: 20 bytes, TTL at byte 8
        ip_header = bytes([0] * 8 + [64] + [0] * 11)  # TTL = 64
        # ICMP header: type=0 (reply), code=0, checksum, id, seq
        import struct

        packet_id = 12345 & 0xFFFF
        icmp_header = struct.pack("!BBHHH", 0, 0, 0, packet_id, 1)
        mock_reply = ip_header + icmp_header + bytes(56)

        mock_sock.recvfrom.return_value = (mock_reply, ("8.8.8.8", 0))

        result = ping("8.8.8.8", count=1, timeout=1)

        assert result.packets_sent == 1
        mock_sock.sendto.assert_called()
        mock_sock.close.assert_called()


class TestIsHostReachable:
    """Tests for is_host_reachable function."""

    @patch("network_utils.ping.ping")
    def test_host_reachable(self, mock_ping):
        """Test when host is reachable."""
        mock_ping.return_value = PingResult(host="8.8.8.8", is_reachable=True)
        assert is_host_reachable("8.8.8.8") is True
        mock_ping.assert_called_once_with("8.8.8.8", count=1, timeout=5)

    @patch("network_utils.ping.ping")
    def test_host_unreachable(self, mock_ping):
        """Test when host is unreachable."""
        mock_ping.return_value = PingResult(host="invalid.host", is_reachable=False)
        assert is_host_reachable("invalid.host") is False


class TestPingMultiple:
    """Tests for ping_multiple function."""

    @patch("socket.gethostbyname")
    def test_ping_multiple_hosts(self, mock_resolve):
        """Test pinging multiple hosts."""
        mock_resolve.side_effect = socket.gaierror("Name resolution failed")

        results = ping_multiple(["invalid1", "invalid2", "invalid3"], count=1)

        assert len(results) == 3
        assert all(not r.is_reachable for r in results)


class TestPingStream:
    """Tests for ping_stream function."""

    @patch("socket.gethostbyname")
    def test_ping_stream_invalid_host(self, mock_resolve):
        """Test ping_stream with invalid host."""
        mock_resolve.side_effect = socket.gaierror("Name resolution failed")

        lines = list(ping_stream("invalid", count=1))

        assert len(lines) == 1
        assert "Cannot resolve" in lines[0]

    @patch("network_utils.ping.socket.socket")
    @patch("socket.gethostbyname")
    def test_ping_stream_permission_denied(self, mock_resolve, mock_socket):
        """Test ping_stream without root privileges."""
        mock_resolve.return_value = "8.8.8.8"
        mock_socket.side_effect = PermissionError()

        lines = list(ping_stream("8.8.8.8", count=1))

        assert any("Permission denied" in line for line in lines)
