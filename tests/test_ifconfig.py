"""Tests for ifconfig module."""

import struct
import sys
from unittest.mock import MagicMock, patch

import pytest

from src.ifconfig import (
    IFF_BROADCAST,
    IFF_LOOPBACK,
    IFF_MULTICAST,
    IFF_RUNNING,
    IFF_UP,
    InterfaceInfo,
    _format_bytes,
    _get_interface_names,
    _get_interface_stats,
    format_interface,
    get_interface_info,
    ifconfig,
    ifconfig_stream,
)

# Get actual module reference (src.ifconfig is shadowed by the function)
ifconfig_module = sys.modules["src.ifconfig"]


class TestInterfaceInfo:
    """Tests for InterfaceInfo dataclass."""

    def test_default_values(self):
        """Test InterfaceInfo default values."""
        info = InterfaceInfo(name="eth0")
        assert info.name == "eth0"
        assert info.ip_address is None
        assert info.netmask is None
        assert info.broadcast is None
        assert info.mac_address is None
        assert info.mtu == 0
        assert info.flags == 0
        assert info.is_up is False
        assert info.is_running is False
        assert info.is_loopback is False
        assert info.rx_bytes == 0
        assert info.tx_bytes == 0
        assert info.errors == []

    def test_with_values(self):
        """Test InterfaceInfo with values."""
        info = InterfaceInfo(
            name="eth0",
            ip_address="192.168.1.100",
            netmask="255.255.255.0",
            broadcast="192.168.1.255",
            mac_address="aa:bb:cc:dd:ee:ff",
            mtu=1500,
            is_up=True,
            is_running=True,
        )
        assert info.ip_address == "192.168.1.100"
        assert info.netmask == "255.255.255.0"
        assert info.mtu == 1500
        assert info.is_up is True


class TestFormatBytes:
    """Tests for _format_bytes function."""

    def test_bytes(self):
        """Test bytes formatting."""
        assert _format_bytes(0) == "0 B"
        assert _format_bytes(512) == "512 B"
        assert _format_bytes(999) == "999 B"

    def test_kilobytes(self):
        """Test KB formatting."""
        assert _format_bytes(1000) == "1.0 KB"
        assert _format_bytes(2000) == "2.0 KB"
        assert _format_bytes(1500) == "1.5 KB"

    def test_megabytes(self):
        """Test MB formatting."""
        assert _format_bytes(1000 * 1000) == "1.0 MB"
        assert _format_bytes(1000 * 1000 * 5) == "5.0 MB"

    def test_gigabytes(self):
        """Test GB formatting."""
        assert _format_bytes(1000 * 1000 * 1000) == "1.0 GB"
        assert _format_bytes(1000 * 1000 * 1000 * 2) == "2.0 GB"


class TestGetInterfaceNames:
    """Tests for _get_interface_names function."""

    @patch("socket.if_nameindex")
    def test_using_socket(self, mock_if_nameindex):
        """Test getting interface names using socket.if_nameindex."""
        mock_if_nameindex.return_value = [(1, "lo"), (2, "eth0"), (3, "wlan0")]

        names = _get_interface_names()

        assert names == ["lo", "eth0", "wlan0"]
        mock_if_nameindex.assert_called_once()

    @patch("socket.if_nameindex")
    @patch.object(ifconfig_module, "Path")
    def test_fallback_to_sys(self, mock_path_class, mock_if_nameindex):
        """Test fallback to /sys/class/net when socket fails."""
        mock_if_nameindex.side_effect = OSError("Not supported")

        # Create mock directory structure
        mock_net_path = MagicMock()
        mock_net_path.exists.return_value = True

        mock_lo = MagicMock()
        mock_lo.name = "lo"
        mock_lo.is_dir.return_value = True

        mock_eth0 = MagicMock()
        mock_eth0.name = "eth0"
        mock_eth0.is_dir.return_value = True

        mock_net_path.iterdir.return_value = [mock_lo, mock_eth0]
        mock_path_class.return_value = mock_net_path

        names = _get_interface_names()

        assert "lo" in names
        assert "eth0" in names


class TestGetInterfaceStats:
    """Tests for _get_interface_stats function."""

    @patch.object(ifconfig_module, "Path")
    def test_stats_exist(self, mock_path_class):
        """Test reading interface statistics."""
        mock_stats_path = MagicMock()
        mock_stats_path.exists.return_value = True

        # Mock stat files
        stat_values = {
            "rx_bytes": "12345",
            "tx_bytes": "67890",
            "rx_packets": "100",
            "tx_packets": "200",
            "rx_errors": "0",
            "tx_errors": "0",
            "rx_dropped": "0",
            "tx_dropped": "0",
        }

        def mock_stat_file(stat_name):
            mock_file = MagicMock()
            mock_file.exists.return_value = True
            # Mock the open() context manager
            mock_file_handle = MagicMock()
            mock_file_handle.read.return_value = stat_values.get(stat_name, "0")
            mock_file.open.return_value.__enter__.return_value = mock_file_handle
            mock_file.open.return_value.__exit__.return_value = False
            return mock_file

        mock_stats_path.__truediv__ = lambda self, name: mock_stat_file(name)
        mock_path_class.return_value = mock_stats_path

        stats = _get_interface_stats("eth0")

        assert stats["rx_bytes"] == 12345
        assert stats["tx_bytes"] == 67890
        assert stats["rx_packets"] == 100
        assert stats["tx_packets"] == 200

    @patch.object(ifconfig_module, "Path")
    def test_stats_not_exist(self, mock_path_class):
        """Test when stats directory doesn't exist."""
        mock_stats_path = MagicMock()
        mock_stats_path.exists.return_value = False
        mock_path_class.return_value = mock_stats_path

        stats = _get_interface_stats("nonexistent")

        assert stats["rx_bytes"] == 0
        assert stats["tx_bytes"] == 0


class TestFormatInterface:
    """Tests for format_interface function."""

    def test_format_loopback(self):
        """Test formatting loopback interface."""
        info = InterfaceInfo(
            name="lo",
            ip_address="127.0.0.1",
            netmask="255.0.0.0",
            mac_address="00:00:00:00:00:00",
            mtu=65536,
            flags=IFF_UP | IFF_LOOPBACK | IFF_RUNNING,
            is_up=True,
            is_running=True,
            is_loopback=True,
            rx_bytes=1000,
            tx_bytes=1000,
            rx_packets=10,
            tx_packets=10,
        )

        output = format_interface(info)

        assert "lo:" in output
        assert "UP" in output
        assert "LOOPBACK" in output
        assert "RUNNING" in output
        assert "127.0.0.1" in output
        assert "255.0.0.0" in output
        assert "65536" in output

    def test_format_ethernet(self):
        """Test formatting ethernet interface."""
        info = InterfaceInfo(
            name="eth0",
            ip_address="192.168.1.100",
            netmask="255.255.255.0",
            broadcast="192.168.1.255",
            mac_address="aa:bb:cc:dd:ee:ff",
            mtu=1500,
            flags=IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST,
            is_up=True,
            is_running=True,
            is_broadcast=True,
            is_multicast=True,
            rx_bytes=1024 * 1024,
            tx_bytes=512 * 1024,
            rx_packets=1000,
            tx_packets=500,
        )

        output = format_interface(info)

        assert "eth0:" in output
        assert "UP" in output
        assert "BROADCAST" in output
        assert "RUNNING" in output
        assert "MULTICAST" in output
        assert "192.168.1.100" in output
        assert "192.168.1.255" in output
        assert "aa:bb:cc:dd:ee:ff" in output
        assert "1500" in output

    def test_format_down_interface(self):
        """Test formatting interface that is down."""
        info = InterfaceInfo(
            name="eth1",
            mtu=1500,
            flags=0,
            is_up=False,
            is_running=False,
        )

        output = format_interface(info)

        assert "eth1:" in output
        assert "DOWN" in output


class TestIfconfigStream:
    """Tests for ifconfig_stream function."""

    @patch.object(ifconfig_module, "_get_interface_names")
    def test_nonexistent_interface(self, mock_get_names):
        """Test ifconfig_stream with nonexistent interface."""
        mock_get_names.return_value = ["lo", "eth0"]

        lines = list(ifconfig_stream("nonexistent"))

        assert len(lines) == 1
        assert "No such device" in lines[0]

    @patch.object(ifconfig_module, "get_interface_info")
    @patch.object(ifconfig_module, "_get_interface_names")
    def test_specific_interface(self, mock_get_names, mock_get_info):
        """Test ifconfig_stream with specific interface."""
        mock_get_names.return_value = ["lo", "eth0"]
        mock_get_info.return_value = InterfaceInfo(
            name="lo",
            ip_address="127.0.0.1",
            netmask="255.0.0.0",
            mtu=65536,
            is_up=True,
            is_loopback=True,
        )

        lines = list(ifconfig_stream("lo"))

        assert len(lines) > 0
        output = "".join(lines)
        assert "lo:" in output
        assert "127.0.0.1" in output

    @patch.object(ifconfig_module, "get_all_interfaces")
    def test_all_interfaces(self, mock_get_all):
        """Test ifconfig_stream with all interfaces."""
        mock_get_all.return_value = [
            InterfaceInfo(name="lo", ip_address="127.0.0.1", mtu=65536, is_up=True),
            InterfaceInfo(
                name="eth0", ip_address="192.168.1.100", mtu=1500, is_up=True
            ),
        ]

        lines = list(ifconfig_stream())

        output = "".join(lines)
        assert "lo:" in output
        assert "eth0:" in output


class TestIfconfig:
    """Tests for ifconfig function."""

    @patch.object(ifconfig_module, "_get_interface_names")
    def test_nonexistent_interface_raises(self, mock_get_names):
        """Test ifconfig raises for nonexistent interface."""
        mock_get_names.return_value = ["lo", "eth0"]

        with pytest.raises(ValueError, match="No such device"):
            ifconfig("nonexistent")

    @patch.object(ifconfig_module, "get_interface_info")
    @patch.object(ifconfig_module, "_get_interface_names")
    def test_specific_interface(self, mock_get_names, mock_get_info):
        """Test ifconfig with specific interface."""
        mock_get_names.return_value = ["lo", "eth0"]
        mock_info = InterfaceInfo(name="eth0", ip_address="192.168.1.100")
        mock_get_info.return_value = mock_info

        result = ifconfig("eth0")

        assert len(result) == 1
        assert result[0].name == "eth0"

    @patch.object(ifconfig_module, "get_all_interfaces")
    def test_all_interfaces(self, mock_get_all):
        """Test ifconfig with all interfaces."""
        mock_get_all.return_value = [
            InterfaceInfo(name="lo"),
            InterfaceInfo(name="eth0"),
        ]

        result = ifconfig()

        assert len(result) == 2


class TestGetInterfaceInfo:
    """Tests for get_interface_info function."""

    @patch.object(ifconfig_module, "_get_interface_stats")
    @patch.object(ifconfig_module, "_get_mtu")
    @patch.object(ifconfig_module, "_get_flags")
    @patch.object(ifconfig_module, "_get_mac_address")
    @patch.object(ifconfig_module, "_ioctl_get_string")
    @patch("socket.socket")
    def test_get_interface_info(
        self,
        mock_socket_class,
        mock_ioctl_string,
        mock_get_mac,
        mock_get_flags,
        mock_get_mtu,
        mock_get_stats,
    ):
        """Test get_interface_info retrieves all information."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        mock_ioctl_string.side_effect = [
            "192.168.1.100",  # IP address
            "255.255.255.0",  # Netmask
            "192.168.1.255",  # Broadcast
        ]
        mock_get_mac.return_value = "aa:bb:cc:dd:ee:ff"
        mock_get_flags.return_value = IFF_UP | IFF_RUNNING | IFF_BROADCAST
        mock_get_mtu.return_value = 1500
        mock_get_stats.return_value = {
            "rx_bytes": 1000,
            "tx_bytes": 2000,
            "rx_packets": 10,
            "tx_packets": 20,
            "rx_errors": 0,
            "tx_errors": 0,
            "rx_dropped": 0,
            "tx_dropped": 0,
        }

        info = get_interface_info("eth0")

        assert info.name == "eth0"
        assert info.ip_address == "192.168.1.100"
        assert info.netmask == "255.255.255.0"
        assert info.broadcast == "192.168.1.255"
        assert info.mac_address == "aa:bb:cc:dd:ee:ff"
        assert info.mtu == 1500
        assert info.is_up is True
        assert info.is_running is True
        assert info.rx_bytes == 1000
        assert info.tx_bytes == 2000
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_socket_error(self, mock_socket_class):
        """Test handling socket creation error."""
        mock_socket_class.side_effect = OSError("Cannot create socket")

        info = get_interface_info("eth0")

        assert info.name == "eth0"
        assert len(info.errors) == 1
        assert "Cannot create socket" in info.errors[0]


class TestIoctlGetString:
    """Tests for _ioctl_get_string function."""

    @patch("fcntl.ioctl")
    def test_successful_ioctl(self, mock_ioctl):
        """Test successful ioctl call returns IP address."""
        from src.ifconfig import SIOCGIFADDR, _ioctl_get_string

        # Create mock result with IP address at offset 20-24
        # IP 192.168.1.100 = bytes [192, 168, 1, 100]
        result = b"\x00" * 20 + bytes([192, 168, 1, 100]) + b"\x00" * 232
        mock_ioctl.return_value = result

        mock_sock = MagicMock()
        mock_sock.fileno.return_value = 3

        ip = _ioctl_get_string(mock_sock, "eth0", SIOCGIFADDR)

        assert ip == "192.168.1.100"
        mock_ioctl.assert_called_once()

    @patch("fcntl.ioctl")
    def test_ioctl_error(self, mock_ioctl):
        """Test ioctl error returns None."""
        from src.ifconfig import SIOCGIFADDR, _ioctl_get_string

        mock_ioctl.side_effect = OSError("ioctl failed")

        mock_sock = MagicMock()
        mock_sock.fileno.return_value = 3

        ip = _ioctl_get_string(mock_sock, "eth0", SIOCGIFADDR)

        assert ip is None


class TestGetMacAddress:
    """Tests for _get_mac_address function."""

    @patch("fcntl.ioctl")
    def test_successful_mac(self, mock_ioctl):
        """Test successful MAC address retrieval."""
        from src.ifconfig import _get_mac_address

        # MAC address at offset 18-24: aa:bb:cc:dd:ee:ff
        result = (
            b"\x00" * 18 + bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]) + b"\x00" * 232
        )
        mock_ioctl.return_value = result

        mock_sock = MagicMock()
        mock_sock.fileno.return_value = 3

        mac = _get_mac_address(mock_sock, "eth0")

        assert mac == "aa:bb:cc:dd:ee:ff"

    @patch("fcntl.ioctl")
    def test_mac_error(self, mock_ioctl):
        """Test MAC address error returns None."""
        from src.ifconfig import _get_mac_address

        mock_ioctl.side_effect = OSError("ioctl failed")

        mock_sock = MagicMock()
        mac = _get_mac_address(mock_sock, "eth0")

        assert mac is None


class TestGetFlags:
    """Tests for _get_flags function."""

    @patch("fcntl.ioctl")
    def test_successful_flags(self, mock_ioctl):
        """Test successful flags retrieval."""
        from src.ifconfig import IFF_RUNNING, IFF_UP, _get_flags

        # Flags at offset 16-18: UP | RUNNING = 0x41
        flags_value = IFF_UP | IFF_RUNNING
        result = b"\x00" * 16 + struct.pack("H", flags_value) + b"\x00" * 238
        mock_ioctl.return_value = result

        mock_sock = MagicMock()
        mock_sock.fileno.return_value = 3

        flags = _get_flags(mock_sock, "eth0")

        assert flags == flags_value

    @patch("fcntl.ioctl")
    def test_flags_error(self, mock_ioctl):
        """Test flags error returns 0."""
        from src.ifconfig import _get_flags

        mock_ioctl.side_effect = OSError("ioctl failed")

        mock_sock = MagicMock()
        flags = _get_flags(mock_sock, "eth0")

        assert flags == 0


class TestGetMtu:
    """Tests for _get_mtu function."""

    @patch("fcntl.ioctl")
    def test_successful_mtu(self, mock_ioctl):
        """Test successful MTU retrieval."""
        from src.ifconfig import _get_mtu

        # MTU at offset 16-20: 1500
        result = b"\x00" * 16 + struct.pack("I", 1500) + b"\x00" * 236
        mock_ioctl.return_value = result

        mock_sock = MagicMock()
        mock_sock.fileno.return_value = 3

        mtu = _get_mtu(mock_sock, "eth0")

        assert mtu == 1500

    @patch("fcntl.ioctl")
    def test_mtu_error(self, mock_ioctl):
        """Test MTU error returns 0."""
        from src.ifconfig import _get_mtu

        mock_ioctl.side_effect = OSError("ioctl failed")

        mock_sock = MagicMock()
        mtu = _get_mtu(mock_sock, "eth0")

        assert mtu == 0


class TestGetAllInterfaces:
    """Tests for get_all_interfaces function."""

    @patch.object(ifconfig_module, "get_interface_info")
    @patch.object(ifconfig_module, "_get_interface_names")
    def test_get_all_interfaces(self, mock_get_names, mock_get_info):
        """Test getting all interfaces."""
        from src.ifconfig import get_all_interfaces

        mock_get_names.return_value = ["lo", "eth0", "wlan0"]
        mock_get_info.side_effect = [
            InterfaceInfo(name="lo", is_loopback=True),
            InterfaceInfo(name="eth0", is_up=True),
            InterfaceInfo(name="wlan0", is_up=False),
        ]

        interfaces = get_all_interfaces()

        assert len(interfaces) == 3
        assert interfaces[0].name == "lo"
        assert interfaces[1].name == "eth0"
        assert interfaces[2].name == "wlan0"

    @patch.object(ifconfig_module, "_get_interface_names")
    def test_get_all_interfaces_empty(self, mock_get_names):
        """Test getting all interfaces when none exist."""
        from src.ifconfig import get_all_interfaces

        mock_get_names.return_value = []

        interfaces = get_all_interfaces()

        assert len(interfaces) == 0
