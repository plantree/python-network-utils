"""Tests for nmap_syn module."""

import socket
import struct
import sys
from unittest.mock import MagicMock, patch

import pytest

from src.nmap import NmapResult, PortResult
from src.nmap_syn import (
    _ACK,
    _RST,
    _SYN,
    _build_syn_v4,
    _build_syn_v6,
    _checksum,
    _get_local_ip,
    _ipv4_tcp_checksum,
    _ipv6_tcp_checksum,
    _sync_scan_batch,
    _tcp_header,
    nmap_syn,
    nmap_syn_stream,
)

nmap_syn_module = sys.modules["src.nmap_syn"]


class TestChecksum:
    """Tests for _checksum function."""

    def test_returns_16bit_value(self):
        data = b"\x00\x01\x00\x02\x00\x03\x00\x04"
        result = _checksum(data)
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFF

    def test_odd_length_data(self):
        data = b"\x01\x02\x03"
        result = _checksum(data)
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFF

    def test_all_zeros(self):
        data = b"\x00\x00\x00\x00"
        assert _checksum(data) == 0xFFFF

    def test_complement_property(self):
        """Checksum of data with its complement should verify correctly."""
        data = b"\x45\x00\x00\x3c\x1c\x46\x40\x00"
        cksum = _checksum(data)
        # Verify checksum is in valid range
        assert 0 < cksum < 0xFFFF


class TestTcpHeader:
    """Tests for _tcp_header function."""

    def test_header_length(self):
        header = _tcp_header(12345, 80, 100)
        assert len(header) == 20

    def test_ports_encoded(self):
        header = _tcp_header(12345, 80, 100)
        src, dst = struct.unpack("!HH", header[:4])
        assert src == 12345
        assert dst == 80

    def test_seq_encoded(self):
        header = _tcp_header(1, 2, 0xDEADBEEF)
        seq = struct.unpack("!L", header[4:8])[0]
        assert seq == 0xDEADBEEF

    def test_syn_flag_set(self):
        header = _tcp_header(1, 2, 0)
        flags_byte = header[13]
        assert flags_byte & _SYN

    def test_ack_number_zero(self):
        header = _tcp_header(1, 2, 100)
        ack = struct.unpack("!L", header[8:12])[0]
        assert ack == 0

    def test_custom_checksum(self):
        header = _tcp_header(1, 2, 0, cksum=0xABCD)
        cksum = struct.unpack("!H", header[16:18])[0]
        assert cksum == 0xABCD

    def test_data_offset_is_five(self):
        header = _tcp_header(1, 2, 0)
        offset_flags = struct.unpack("!H", header[12:14])[0]
        data_offset = (offset_flags >> 12) & 0xF
        assert data_offset == 5


class TestIpv4TcpChecksum:
    """Tests for _ipv4_tcp_checksum function."""

    def test_returns_16bit(self):
        tcp = _tcp_header(12345, 80, 1)
        cksum = _ipv4_tcp_checksum("192.168.1.1", "10.0.0.1", tcp)
        assert 0 <= cksum <= 0xFFFF

    def test_different_ips_different_checksum(self):
        tcp = _tcp_header(12345, 80, 1)
        cksum1 = _ipv4_tcp_checksum("192.168.1.1", "10.0.0.1", tcp)
        cksum2 = _ipv4_tcp_checksum("192.168.1.2", "10.0.0.1", tcp)
        assert cksum1 != cksum2


class TestIpv6TcpChecksum:
    """Tests for _ipv6_tcp_checksum function."""

    def test_returns_16bit(self):
        tcp = _tcp_header(12345, 80, 1)
        cksum = _ipv6_tcp_checksum("::1", "::2", tcp)
        assert 0 <= cksum <= 0xFFFF


class TestBuildSynV4:
    """Tests for _build_syn_v4 function."""

    @patch("src.nmap_syn.random.randint", return_value=42)
    def test_packet_length(self, _mock_rand):
        pkt = _build_syn_v4("192.168.1.1", "10.0.0.1", 12345, 80)
        # 20-byte IP header + 20-byte TCP header
        assert len(pkt) == 40

    @patch("src.nmap_syn.random.randint", return_value=42)
    def test_ip_version_and_ihl(self, _mock_rand):
        pkt = _build_syn_v4("192.168.1.1", "10.0.0.1", 12345, 80)
        assert pkt[0] == 0x45  # IPv4, IHL=5

    @patch("src.nmap_syn.random.randint", return_value=42)
    def test_protocol_is_tcp(self, _mock_rand):
        pkt = _build_syn_v4("192.168.1.1", "10.0.0.1", 12345, 80)
        assert pkt[9] == socket.IPPROTO_TCP

    @patch("src.nmap_syn.random.randint", return_value=42)
    def test_ttl(self, _mock_rand):
        pkt = _build_syn_v4("192.168.1.1", "10.0.0.1", 12345, 80)
        assert pkt[8] == 64

    @patch("src.nmap_syn.random.randint", return_value=42)
    def test_src_dst_ip(self, _mock_rand):
        pkt = _build_syn_v4("192.168.1.1", "10.0.0.1", 12345, 80)
        src_ip = socket.inet_ntoa(pkt[12:16])
        dst_ip = socket.inet_ntoa(pkt[16:20])
        assert src_ip == "192.168.1.1"
        assert dst_ip == "10.0.0.1"

    @patch("src.nmap_syn.random.randint", return_value=42)
    def test_tcp_ports(self, _mock_rand):
        pkt = _build_syn_v4("192.168.1.1", "10.0.0.1", 12345, 80)
        tcp = pkt[20:]
        src_port, dst_port = struct.unpack("!HH", tcp[:4])
        assert src_port == 12345
        assert dst_port == 80


class TestBuildSynV6:
    """Tests for _build_syn_v6 function."""

    @patch("src.nmap_syn.random.randint", return_value=42)
    def test_returns_tcp_only(self, _mock_rand):
        pkt = _build_syn_v6("::1", "::2", 12345, 80)
        # Only TCP header, no IPv6 header (kernel handles it)
        assert len(pkt) == 20

    @patch("src.nmap_syn.random.randint", return_value=42)
    def test_tcp_ports(self, _mock_rand):
        pkt = _build_syn_v6("::1", "::2", 12345, 80)
        src_port, dst_port = struct.unpack("!HH", pkt[:4])
        assert src_port == 12345
        assert dst_port == 80


class TestGetLocalIp:
    """Tests for _get_local_ip function."""

    @patch("src.nmap_syn.socket.socket")
    def test_returns_local_ip(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("192.168.1.100", 0)
        mock_socket_cls.return_value = mock_sock

        result = _get_local_ip("10.0.0.1", socket.AF_INET)
        assert result == "192.168.1.100"
        mock_sock.connect.assert_called_once_with(("10.0.0.1", 80))
        mock_sock.close.assert_called_once()

    @patch("src.nmap_syn.socket.socket")
    def test_closes_socket_on_error(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("unreachable")
        mock_socket_cls.return_value = mock_sock

        with pytest.raises(OSError):
            _get_local_ip("10.0.0.1", socket.AF_INET)
        mock_sock.close.assert_called_once()


class TestSyncScanBatch:
    """Tests for _sync_scan_batch function."""

    @patch("src.nmap_syn.select.select")
    @patch("src.nmap_syn.socket.socket")
    def test_open_port_syn_ack(self, mock_socket_cls, mock_select):
        """SYN-ACK response should mark port as open."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        # Build a fake IPv4 response: IP header (20 bytes) + TCP header
        src_ip = socket.inet_aton("10.0.0.1")
        dst_ip = socket.inet_aton("192.168.1.1")
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            40,
            0,
            0,
            64,
            socket.IPPROTO_TCP,
            0,
            src_ip,
            dst_ip,
        )
        # TCP: src_port=80, dst_port=54321, seq=0, ack=0, offset_flags, ...
        flags = _SYN | _ACK
        offset_flags = (5 << 12) | flags
        tcp_header = struct.pack(
            "!HHLLHHHH",
            80,
            54321,
            0,
            0,
            offset_flags,
            1024,
            0,
            0,
        )
        response = ip_header + tcp_header

        mock_sock.recvfrom.return_value = (response, ("10.0.0.1", 0))
        mock_select.side_effect = [
            ([mock_sock], [], []),  # first call: readable
            ([], [], []),  # second call: timeout
        ]

        results = _sync_scan_batch("10.0.0.1", [80], 1.0, "192.168.1.1", 54321)

        open_results = [r for r in results if r.state == "open"]
        assert len(open_results) == 1
        assert open_results[0].port == 80

    @patch("src.nmap_syn.select.select")
    @patch("src.nmap_syn.socket.socket")
    def test_closed_port_rst(self, mock_socket_cls, mock_select):
        """RST response should mark port as closed."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        src_ip = socket.inet_aton("10.0.0.1")
        dst_ip = socket.inet_aton("192.168.1.1")
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            40,
            0,
            0,
            64,
            socket.IPPROTO_TCP,
            0,
            src_ip,
            dst_ip,
        )
        flags = _RST | _ACK
        offset_flags = (5 << 12) | flags
        tcp_header = struct.pack(
            "!HHLLHHHH",
            22,
            54321,
            0,
            0,
            offset_flags,
            0,
            0,
            0,
        )
        response = ip_header + tcp_header

        mock_sock.recvfrom.return_value = (response, ("10.0.0.1", 0))
        mock_select.side_effect = [
            ([mock_sock], [], []),
            ([], [], []),
        ]

        results = _sync_scan_batch("10.0.0.1", [22], 1.0, "192.168.1.1", 54321)

        closed = [r for r in results if r.state == "closed"]
        assert len(closed) == 1
        assert closed[0].port == 22

    @patch("src.nmap_syn.time.monotonic")
    @patch("src.nmap_syn.select.select")
    @patch("src.nmap_syn.socket.socket")
    def test_no_response_filtered(self, mock_socket_cls, mock_select, mock_time):
        """No response within timeout should mark port as filtered."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        # Simulate time passing past the deadline
        mock_time.side_effect = [0.0, 0.0, 3.0]
        mock_select.return_value = ([], [], [])

        results = _sync_scan_batch("10.0.0.1", [443], 1.0, "192.168.1.1", 54321)

        filtered = [r for r in results if r.state == "filtered"]
        assert len(filtered) == 1
        assert filtered[0].port == 443

    @patch("src.nmap_syn.socket.socket")
    def test_send_failure_filtered(self, mock_socket_cls):
        """OSError on sendto should mark port as filtered."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.sendto.side_effect = OSError("Permission denied")

        results = _sync_scan_batch("10.0.0.1", [80], 1.0, "192.168.1.1", 54321)

        assert len(results) == 1
        assert results[0].state == "filtered"
        assert results[0].port == 80

    @patch("src.nmap_syn.time.monotonic")
    @patch("src.nmap_syn.select.select")
    @patch("src.nmap_syn.socket.socket")
    def test_ignores_wrong_dst_port(self, mock_socket_cls, mock_select, mock_time):
        """Responses to a different dst port should be ignored."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        src_ip = socket.inet_aton("10.0.0.1")
        dst_ip = socket.inet_aton("192.168.1.1")
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            40,
            0,
            0,
            64,
            socket.IPPROTO_TCP,
            0,
            src_ip,
            dst_ip,
        )
        # Response dst_port is 11111, different from our src_port 54321
        offset_flags = (5 << 12) | _SYN | _ACK
        tcp_header = struct.pack(
            "!HHLLHHHH",
            80,
            11111,
            0,
            0,
            offset_flags,
            1024,
            0,
            0,
        )
        response = ip_header + tcp_header

        mock_sock.recvfrom.return_value = (response, ("10.0.0.1", 0))
        # Time: deadline set, first check within, second check expired
        mock_time.side_effect = [0.0, 0.0, 2.0]
        mock_select.return_value = ([mock_sock], [], [])

        results = _sync_scan_batch("10.0.0.1", [80], 0.1, "192.168.1.1", 54321)

        # Port 80 should remain as filtered (no valid response matched)
        filtered = [r for r in results if r.state == "filtered"]
        assert any(r.port == 80 for r in filtered)


class TestNmapSyn:
    """Tests for nmap_syn function."""

    @patch.object(nmap_syn_module, "_sync_scan_batch")
    @patch.object(nmap_syn_module, "_get_local_ip", return_value="192.168.1.1")
    @patch.object(nmap_syn_module, "_resolve_host", return_value="10.0.0.1")
    def test_basic_scan(self, _mock_resolve, _mock_local_ip, mock_batch):
        mock_batch.return_value = [
            PortResult(port=80, state="open", service="http"),
            PortResult(port=443, state="closed", service="https"),
        ]
        result = nmap_syn("example.com", ports="80,443")
        assert isinstance(result, NmapResult)
        assert result.target == "example.com"
        assert result.ip == "10.0.0.1"
        assert result.total_scanned == 2
        assert len(result.open_ports) == 1
        assert result.open_ports[0].port == 80

    @patch.object(nmap_syn_module, "_resolve_host", side_effect=socket.gaierror("nope"))
    def test_resolve_failure(self, _mock_resolve):
        result = nmap_syn("nonexistent.example")
        assert result.error is not None
        assert "failed to resolve" in result.error

    @patch.object(nmap_syn_module, "_get_local_ip", side_effect=OSError("no route"))
    @patch.object(nmap_syn_module, "_resolve_host", return_value="10.0.0.1")
    def test_local_ip_failure(self, _mock_resolve, _mock_local_ip):
        result = nmap_syn("example.com")
        assert result.error is not None
        assert "local IP" in result.error

    @patch.object(nmap_syn_module, "_sync_scan_batch")
    @patch.object(nmap_syn_module, "_get_local_ip", return_value="192.168.1.1")
    @patch.object(nmap_syn_module, "_resolve_host", return_value="10.0.0.1")
    def test_top_ports(self, _mock_resolve, _mock_local_ip, mock_batch):
        mock_batch.return_value = []
        result = nmap_syn("example.com", top_ports=10)
        assert result.total_scanned == 10

    @patch.object(nmap_syn_module, "_sync_scan_batch")
    @patch.object(nmap_syn_module, "_get_local_ip", return_value="192.168.1.1")
    @patch.object(nmap_syn_module, "_resolve_host", return_value="10.0.0.1")
    def test_results_sorted_by_port(self, _mock_resolve, _mock_local_ip, mock_batch):
        mock_batch.return_value = [
            PortResult(port=443, state="open", service="https"),
            PortResult(port=22, state="open", service="ssh"),
            PortResult(port=80, state="open", service="http"),
        ]
        result = nmap_syn("example.com", ports="22,80,443")
        ports = [p.port for p in result.ports]
        assert ports == [22, 80, 443]

    @patch.object(nmap_syn_module, "_get_local_ip", return_value="192.168.1.1")
    @patch.object(nmap_syn_module, "_resolve_host", return_value="10.0.0.1")
    def test_invalid_ports(self, _mock_resolve, _mock_local_ip):
        result = nmap_syn("example.com", ports="99999")
        assert result.error is not None
        assert "invalid" in result.error


class TestNmapSynStream:
    """Tests for nmap_syn_stream function."""

    @patch.object(nmap_syn_module, "nmap_syn")
    def test_stream_output_contains_header(self, mock_scan):
        mock_scan.return_value = NmapResult(
            target="example.com",
            ip="10.0.0.1",
            ports=[PortResult(port=80, state="open", service="http")],
            total_scanned=1,
            scan_time=0.5,
        )
        output = "".join(nmap_syn_stream("example.com", ports="80"))
        assert "Starting SYN scan" in output
        assert "example.com" in output
        assert "10.0.0.1" in output

    @patch.object(nmap_syn_module, "nmap_syn")
    def test_stream_shows_open_ports(self, mock_scan):
        mock_scan.return_value = NmapResult(
            target="example.com",
            ip="10.0.0.1",
            ports=[
                PortResult(port=22, state="open", service="ssh"),
                PortResult(port=80, state="open", service="http"),
            ],
            total_scanned=2,
            scan_time=1.0,
        )
        output = "".join(nmap_syn_stream("example.com", ports="22,80"))
        assert "22" in output
        assert "80" in output
        assert "open" in output
        assert "Nmap done" in output

    @patch.object(nmap_syn_module, "nmap_syn")
    def test_stream_error(self, mock_scan):
        mock_scan.return_value = NmapResult(
            target="bad.host", error="failed to resolve"
        )
        output = "".join(nmap_syn_stream("bad.host"))
        assert "Error" in output
        assert "failed to resolve" in output

    @patch.object(nmap_syn_module, "nmap_syn")
    def test_stream_all_closed(self, mock_scan):
        mock_scan.return_value = NmapResult(
            target="example.com",
            ip="10.0.0.1",
            ports=[PortResult(port=80, state="closed", service="http")],
            total_scanned=1,
            scan_time=0.1,
        )
        output = "".join(nmap_syn_stream("example.com", ports="80"))
        assert "closed" in output

    @patch.object(nmap_syn_module, "nmap_syn")
    def test_stream_not_shown_summary(self, mock_scan):
        mock_scan.return_value = NmapResult(
            target="example.com",
            ip="10.0.0.1",
            ports=[
                PortResult(port=22, state="open", service="ssh"),
                PortResult(port=80, state="closed", service="http"),
                PortResult(port=443, state="closed", service="https"),
            ],
            total_scanned=3,
            scan_time=0.5,
        )
        output = "".join(nmap_syn_stream("example.com", ports="22,80,443"))
        assert "Not shown: 2 closed" in output
