"""Tests for lsof module."""

import sys
from unittest.mock import MagicMock, mock_open, patch

import pytest

from src.lsof import (
    SocketInfo,
    TcpState,
    _build_inode_to_process_map,
    _format_address,
    _format_name,
    _parse_addr_port,
    _parse_hex_addr_v4,
    _parse_hex_addr_v6,
    _parse_proc_net_file,
    _try_service_name,
    _uid_to_username,
    lsof,
    lsof_stream,
)

# Get actual module reference
lsof_module = sys.modules["src.lsof"]


# ---------------------------------------------------------------------------
# Test data: sample /proc/net/tcp lines
# ---------------------------------------------------------------------------
# Columns: sl  local_address rem_address   st tx_queue:rx_queue ...  uid  ... inode
PROC_NET_TCP_HEADER = (
    "  sl  local_address rem_address   st tx_queue rx_queue "
    "tr tm->when retrnsmt   uid  timeout inode\n"
)
# 0.0.0.0:22 -> 0.0.0.0:0, LISTEN, uid=0, inode=12345
PROC_NET_TCP_LISTEN = (
    "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 "
    "00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
)
# 127.0.0.1:8080 -> 127.0.0.1:54321, ESTABLISHED, uid=1000, inode=67890
PROC_NET_TCP_ESTAB = (
    "   1: 0100007F:1F90 0100007F:D431 01 00000001:00000002 "
    "00:00000000 00000000  1000        0 67890 1 0000000000000000 100 0 0 10 0\n"
)
# UDP: 0.0.0.0:53 -> 0.0.0.0:0, state=7 (UNCONN), uid=0, inode=11111
PROC_NET_UDP_UNCONN = (
    "   0: 00000000:0035 00000000:0000 07 00000000:00000000 "
    "00:00000000 00000000     0        0 11111 1 0000000000000000 100 0 0 10 0\n"
)
# IPv6 TCP LISTEN on :::80, inode=22222
PROC_NET_TCP6_LISTEN = (
    "   0: 00000000000000000000000000000000:0050 "
    "00000000000000000000000000000000:0000 0A 00000000:00000000 "
    "00:00000000 00000000     0        0 22222 1 0000000000000000 100 0 0 10 0\n"
)


# ---------------------------------------------------------------------------
# TcpState enum
# ---------------------------------------------------------------------------
class TestTcpState:
    """Tests for TcpState enum."""

    def test_values(self):
        assert TcpState.ESTABLISHED == 1
        assert TcpState.LISTEN == 10
        assert TcpState.CLOSE == 7

    def test_all_states_have_names(self):
        from src.lsof import _TCP_STATE_NAMES

        for s in TcpState:
            assert s.value in _TCP_STATE_NAMES
            assert _TCP_STATE_NAMES[s.value] == s.name


# ---------------------------------------------------------------------------
# SocketInfo dataclass
# ---------------------------------------------------------------------------
class TestSocketInfo:
    """Tests for SocketInfo dataclass."""

    def test_default_values(self):
        info = SocketInfo(
            protocol="tcp",
            local_address="0.0.0.0",
            local_port=80,
            remote_address="0.0.0.0",
            remote_port=0,
            state="LISTEN",
            inode=1234,
            uid=0,
        )
        assert info.protocol == "tcp"
        assert info.local_port == 80
        assert info.pid is None
        assert info.process_name is None
        assert info.fd is None
        assert info.tx_queue == 0
        assert info.rx_queue == 0

    def test_with_process_info(self):
        info = SocketInfo(
            protocol="tcp",
            local_address="0.0.0.0",
            local_port=80,
            remote_address="0.0.0.0",
            remote_port=0,
            state="LISTEN",
            inode=1234,
            uid=0,
            pid=1000,
            process_name="nginx",
            fd=3,
        )
        assert info.pid == 1000
        assert info.process_name == "nginx"
        assert info.fd == 3


# ---------------------------------------------------------------------------
# Address parsing
# ---------------------------------------------------------------------------
class TestParseHexAddrV4:
    """Tests for _parse_hex_addr_v4."""

    def test_loopback(self):
        # 127.0.0.1 in little-endian hex = 0100007F
        assert _parse_hex_addr_v4("0100007F") == "127.0.0.1"

    def test_any(self):
        assert _parse_hex_addr_v4("00000000") == "0.0.0.0"

    def test_typical(self):
        # 192.168.1.1 = C0.A8.01.01 -> LE = 0101A8C0
        assert _parse_hex_addr_v4("0101A8C0") == "192.168.1.1"


class TestParseHexAddrV6:
    """Tests for _parse_hex_addr_v6."""

    def test_any(self):
        result = _parse_hex_addr_v6("00000000000000000000000000000000")
        assert result == "::"

    def test_loopback(self):
        result = _parse_hex_addr_v6("00000000000000000000000001000000")
        assert result == "::1"


class TestParseAddrPort:
    """Tests for _parse_addr_port."""

    def test_ipv4(self):
        ip, port = _parse_addr_port("0100007F:1F90", is_ipv6=False)
        assert ip == "127.0.0.1"
        assert port == 8080

    def test_ipv4_zero(self):
        ip, port = _parse_addr_port("00000000:0000", is_ipv6=False)
        assert ip == "0.0.0.0"
        assert port == 0

    def test_ipv6(self):
        ip, port = _parse_addr_port(
            "00000000000000000000000000000000:0050", is_ipv6=True
        )
        assert ip == "::"
        assert port == 80


# ---------------------------------------------------------------------------
# _parse_proc_net_file
# ---------------------------------------------------------------------------
class TestParseProcNetFile:
    """Tests for _parse_proc_net_file."""

    def test_tcp_listen(self):
        data = PROC_NET_TCP_HEADER + PROC_NET_TCP_LISTEN
        with patch("builtins.open", mock_open(read_data=data)):
            sockets = _parse_proc_net_file("/proc/net/tcp", "tcp")

        assert len(sockets) == 1
        s = sockets[0]
        assert s.protocol == "tcp"
        assert s.local_address == "0.0.0.0"
        assert s.local_port == 22
        assert s.remote_address == "0.0.0.0"
        assert s.remote_port == 0
        assert s.state == "LISTEN"
        assert s.inode == 12345
        assert s.uid == 0

    def test_tcp_established(self):
        data = PROC_NET_TCP_HEADER + PROC_NET_TCP_ESTAB
        with patch("builtins.open", mock_open(read_data=data)):
            sockets = _parse_proc_net_file("/proc/net/tcp", "tcp")

        assert len(sockets) == 1
        s = sockets[0]
        assert s.local_address == "127.0.0.1"
        assert s.local_port == 8080
        assert s.remote_address == "127.0.0.1"
        assert s.remote_port == 54321
        assert s.state == "ESTABLISHED"
        assert s.uid == 1000
        assert s.inode == 67890

    def test_tcp_queues(self):
        data = PROC_NET_TCP_HEADER + PROC_NET_TCP_ESTAB
        with patch("builtins.open", mock_open(read_data=data)):
            sockets = _parse_proc_net_file("/proc/net/tcp", "tcp")

        s = sockets[0]
        assert s.tx_queue == 1
        assert s.rx_queue == 2

    def test_udp_unconn(self):
        data = PROC_NET_TCP_HEADER + PROC_NET_UDP_UNCONN
        with patch("builtins.open", mock_open(read_data=data)):
            sockets = _parse_proc_net_file("/proc/net/udp", "udp")

        assert len(sockets) == 1
        s = sockets[0]
        assert s.protocol == "udp"
        assert s.local_port == 53
        assert s.state == "UNCONN"

    def test_tcp6_listen(self):
        data = PROC_NET_TCP_HEADER + PROC_NET_TCP6_LISTEN
        with patch("builtins.open", mock_open(read_data=data)):
            sockets = _parse_proc_net_file("/proc/net/tcp6", "tcp6")

        assert len(sockets) == 1
        s = sockets[0]
        assert s.protocol == "tcp6"
        assert s.local_address == "::"
        assert s.local_port == 80
        assert s.state == "LISTEN"

    def test_multiple_lines(self):
        data = PROC_NET_TCP_HEADER + PROC_NET_TCP_LISTEN + PROC_NET_TCP_ESTAB
        with patch("builtins.open", mock_open(read_data=data)):
            sockets = _parse_proc_net_file("/proc/net/tcp", "tcp")

        assert len(sockets) == 2

    def test_file_not_found(self):
        with patch("builtins.open", side_effect=FileNotFoundError):
            sockets = _parse_proc_net_file("/proc/net/tcp", "tcp")
        assert sockets == []

    def test_permission_denied(self):
        with patch("builtins.open", side_effect=PermissionError):
            sockets = _parse_proc_net_file("/proc/net/tcp", "tcp")
        assert sockets == []

    def test_malformed_line_skipped(self):
        data = PROC_NET_TCP_HEADER + "short line\n" + PROC_NET_TCP_LISTEN
        with patch("builtins.open", mock_open(read_data=data)):
            sockets = _parse_proc_net_file("/proc/net/tcp", "tcp")
        assert len(sockets) == 1


# ---------------------------------------------------------------------------
# _build_inode_to_process_map
# ---------------------------------------------------------------------------
class TestBuildInodeToProcessMap:
    """Tests for _build_inode_to_process_map."""

    @patch("os.readlink")
    @patch.object(lsof_module, "Path")
    def test_basic_mapping(self, mock_path_class, mock_readlink):
        mock_proc = MagicMock()

        # Create a pid directory entry
        mock_pid_entry = MagicMock()
        mock_pid_entry.name = "1234"
        mock_pid_entry.is_dir.return_value = True

        # comm file
        mock_comm = MagicMock()
        mock_comm.read_text.return_value = "nginx\n"

        # fd directory with one socket entry
        mock_fd_dir = MagicMock()
        mock_fd_entry = MagicMock()
        mock_fd_entry.name = "5"
        mock_fd_entry.__str__ = lambda self: "/proc/1234/fd/5"
        mock_fd_dir.iterdir.return_value = [mock_fd_entry]

        # Use a dict to return the right mock for each key
        children = {"comm": mock_comm, "fd": mock_fd_dir}
        mock_pid_entry.__truediv__ = lambda self, key: children.get(key, MagicMock())

        mock_readlink.return_value = "socket:[99999]"

        # Non-pid entry (should be skipped)
        mock_other = MagicMock()
        mock_other.name = "self"

        mock_proc.iterdir.return_value = [mock_pid_entry, mock_other]
        mock_path_class.return_value = mock_proc

        mapping = _build_inode_to_process_map()

        assert 99999 in mapping
        pid, comm, fd = mapping[99999]
        assert pid == 1234
        assert comm == "nginx"
        assert fd == 5

    @patch.object(lsof_module, "Path")
    def test_permission_error(self, mock_path_class):
        mock_proc = MagicMock()

        mock_pid_entry = MagicMock()
        mock_pid_entry.name = "1"

        mock_comm = MagicMock()
        mock_comm.read_text.side_effect = PermissionError

        mock_fd_dir = MagicMock()
        mock_fd_dir.iterdir.side_effect = PermissionError

        mock_pid_entry.__truediv__ = lambda self, key: {
            "comm": mock_comm,
            "fd": mock_fd_dir,
        }.get(key, MagicMock())

        mock_proc.iterdir.return_value = [mock_pid_entry]
        mock_path_class.return_value = mock_proc

        mapping = _build_inode_to_process_map()
        assert mapping == {}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
class TestUidToUsername:
    """Tests for _uid_to_username."""

    @patch("pwd.getpwuid")
    def test_known_user(self, mock_getpwuid):
        mock_entry = MagicMock()
        mock_entry.pw_name = "root"
        mock_getpwuid.return_value = mock_entry
        assert _uid_to_username(0) == "root"

    @patch("pwd.getpwuid")
    def test_unknown_uid(self, mock_getpwuid):
        mock_getpwuid.side_effect = KeyError
        assert _uid_to_username(99999) == "99999"


class TestTryServiceName:
    """Tests for _try_service_name."""

    def test_zero_port(self):
        assert _try_service_name(0, "tcp") is None

    @patch("socket.getservbyport")
    def test_known_service(self, mock_getserv):
        mock_getserv.return_value = "http"
        assert _try_service_name(80, "tcp") == "http"
        mock_getserv.assert_called_once_with(80, "tcp")

    @patch("socket.getservbyport")
    def test_known_service_tcp6(self, mock_getserv):
        mock_getserv.return_value = "http"
        assert _try_service_name(80, "tcp6") == "http"
        mock_getserv.assert_called_once_with(80, "tcp")

    @patch("socket.getservbyport")
    def test_unknown_service(self, mock_getserv):
        mock_getserv.side_effect = OSError
        assert _try_service_name(54321, "tcp") is None


class TestFormatAddress:
    """Tests for _format_address."""

    def test_wildcard_v4(self):
        assert _format_address("0.0.0.0", 0, False) == "*:*"

    def test_wildcard_v6(self):
        assert _format_address("::", 0, True) == "*:*"

    def test_wildcard_addr_with_port(self):
        assert _format_address("0.0.0.0", 80, False) == "*:80"

    def test_v4_addr_port(self):
        assert _format_address("192.168.1.1", 8080, False) == "192.168.1.1:8080"

    def test_v6_addr_port(self):
        assert _format_address("::1", 443, True) == "[::1]:443"

    def test_v6_wildcard_with_port(self):
        assert _format_address("::", 53, True) == "*:53"

    @patch("socket.getservbyport")
    def test_resolve_service(self, mock_getserv):
        mock_getserv.return_value = "http"
        result = _format_address(
            "0.0.0.0", 80, False, resolve_services=True, proto="tcp"
        )
        assert result == "*:http"


# ---------------------------------------------------------------------------
# _format_name
# ---------------------------------------------------------------------------
class TestFormatName:
    """Tests for _format_name."""

    def test_listen_socket(self):
        sock = SocketInfo(
            protocol="tcp",
            local_address="0.0.0.0",
            local_port=80,
            remote_address="0.0.0.0",
            remote_port=0,
            state="LISTEN",
            inode=1,
            uid=0,
        )
        result = _format_name(sock)
        assert result == "*:80 (LISTEN)"

    def test_established_socket(self):
        sock = SocketInfo(
            protocol="tcp",
            local_address="192.168.1.1",
            local_port=8080,
            remote_address="10.0.0.1",
            remote_port=443,
            state="ESTABLISHED",
            inode=2,
            uid=1000,
        )
        result = _format_name(sock)
        assert result == "192.168.1.1:8080->10.0.0.1:443 (ESTABLISHED)"

    def test_ipv6_listen(self):
        sock = SocketInfo(
            protocol="tcp6",
            local_address="::",
            local_port=443,
            remote_address="::",
            remote_port=0,
            state="LISTEN",
            inode=3,
            uid=0,
        )
        result = _format_name(sock)
        assert result == "*:443 (LISTEN)"

    def test_no_state(self):
        sock = SocketInfo(
            protocol="udp",
            local_address="0.0.0.0",
            local_port=53,
            remote_address="0.0.0.0",
            remote_port=0,
            state=None,
            inode=4,
            uid=0,
        )
        result = _format_name(sock)
        assert result == "*:53"


# ---------------------------------------------------------------------------
# lsof (main function)
# ---------------------------------------------------------------------------
class TestLsof:
    """Tests for the lsof function."""

    def _make_socket(self, **kwargs):
        defaults = dict(
            protocol="tcp",
            local_address="0.0.0.0",
            local_port=80,
            remote_address="0.0.0.0",
            remote_port=0,
            state="LISTEN",
            inode=1,
            uid=0,
        )
        defaults.update(kwargs)
        return SocketInfo(**defaults)

    @patch.object(lsof_module, "_build_inode_to_process_map", return_value={})
    @patch.object(lsof_module, "_parse_proc_net_file")
    def test_returns_all_protocols(self, mock_parse, mock_map):
        mock_parse.return_value = [self._make_socket()]
        lsof()
        # Called for tcp, tcp6, udp, udp6
        assert mock_parse.call_count == 4

    @patch.object(lsof_module, "_build_inode_to_process_map", return_value={})
    @patch.object(lsof_module, "_parse_proc_net_file")
    def test_filter_protocols(self, mock_parse, mock_map):
        mock_parse.return_value = [self._make_socket()]
        lsof(protocols=["tcp"])
        assert mock_parse.call_count == 1

    @patch.object(lsof_module, "_build_inode_to_process_map", return_value={})
    @patch.object(lsof_module, "_parse_proc_net_file")
    def test_filter_port(self, mock_parse, mock_map):
        mock_parse.return_value = [
            self._make_socket(local_port=80),
            self._make_socket(local_port=443, inode=2),
        ]
        result = lsof(protocols=["tcp"], port=80)
        assert len(result) == 1
        assert result[0].local_port == 80

    @patch.object(lsof_module, "_build_inode_to_process_map", return_value={})
    @patch.object(lsof_module, "_parse_proc_net_file")
    def test_filter_remote_port(self, mock_parse, mock_map):
        mock_parse.return_value = [
            self._make_socket(local_port=54321, remote_port=80, state="ESTABLISHED"),
        ]
        result = lsof(protocols=["tcp"], port=80)
        assert len(result) == 1

    @patch.object(lsof_module, "_build_inode_to_process_map")
    @patch.object(lsof_module, "_parse_proc_net_file")
    def test_filter_pid(self, mock_parse, mock_map):
        s = self._make_socket(inode=100)
        mock_parse.return_value = [s]
        mock_map.return_value = {100: (42, "nginx", 3)}
        result = lsof(protocols=["tcp"], pid=42)
        assert len(result) == 1
        assert result[0].pid == 42

    @patch.object(lsof_module, "_build_inode_to_process_map")
    @patch.object(lsof_module, "_parse_proc_net_file")
    def test_filter_pid_no_match(self, mock_parse, mock_map):
        s = self._make_socket(inode=100)
        mock_parse.return_value = [s]
        mock_map.return_value = {100: (42, "nginx", 3)}
        result = lsof(protocols=["tcp"], pid=999)
        assert len(result) == 0

    @patch.object(lsof_module, "_build_inode_to_process_map", return_value={})
    @patch.object(lsof_module, "_parse_proc_net_file")
    def test_filter_state(self, mock_parse, mock_map):
        mock_parse.return_value = [
            self._make_socket(local_port=80, state="LISTEN"),
            self._make_socket(local_port=8080, state="ESTABLISHED", inode=2),
        ]
        result = lsof(protocols=["tcp"], state="LISTEN")
        assert len(result) == 1
        assert result[0].state == "LISTEN"

    @patch.object(lsof_module, "_build_inode_to_process_map", return_value={})
    @patch.object(lsof_module, "_parse_proc_net_file")
    def test_filter_state_case_insensitive(self, mock_parse, mock_map):
        mock_parse.return_value = [
            self._make_socket(state="LISTEN"),
        ]
        result = lsof(protocols=["tcp"], state="listen")
        assert len(result) == 1

    @patch.object(lsof_module, "_build_inode_to_process_map")
    @patch.object(lsof_module, "_parse_proc_net_file")
    def test_enriches_process_info(self, mock_parse, mock_map):
        mock_parse.return_value = [self._make_socket(inode=555)]
        mock_map.return_value = {555: (100, "python", 7)}
        result = lsof(protocols=["tcp"])
        assert result[0].pid == 100
        assert result[0].process_name == "python"
        assert result[0].fd == 7

    @patch.object(lsof_module, "_build_inode_to_process_map", return_value={})
    @patch.object(lsof_module, "_parse_proc_net_file")
    def test_sort_order(self, mock_parse, mock_map):
        mock_parse.return_value = [
            self._make_socket(local_port=443, state="ESTABLISHED", inode=2),
            self._make_socket(local_port=80, state="LISTEN", inode=3),
            self._make_socket(local_port=22, state="LISTEN", inode=4),
        ]
        result = lsof(protocols=["tcp"])
        # LISTEN first, then by port
        assert result[0].local_port == 22
        assert result[0].state == "LISTEN"
        assert result[1].local_port == 80
        assert result[1].state == "LISTEN"
        assert result[2].local_port == 443
        assert result[2].state == "ESTABLISHED"


# ---------------------------------------------------------------------------
# lsof_stream
# ---------------------------------------------------------------------------
class TestLsofStream:
    """Tests for lsof_stream."""

    @patch.object(lsof_module, "lsof", return_value=[])
    def test_empty(self, mock_lsof):
        lines = list(lsof_stream())
        assert any("No open network sockets" in line for line in lines)

    @patch.object(lsof_module, "_uid_to_username", return_value="root")
    @patch.object(lsof_module, "lsof")
    def test_header_format(self, mock_lsof, mock_uid):
        sock = SocketInfo(
            protocol="tcp",
            local_address="0.0.0.0",
            local_port=22,
            remote_address="0.0.0.0",
            remote_port=0,
            state="LISTEN",
            inode=12345,
            uid=0,
            pid=1023,
            process_name="sshd",
            fd=3,
        )
        mock_lsof.return_value = [sock]

        lines = list(lsof_stream())
        header = lines[0]
        assert "COMMAND" in header
        assert "PID" in header
        assert "USER" in header
        assert "FD" in header
        assert "TYPE" in header
        assert "DEVICE" in header
        assert "NODE" in header
        assert "NAME" in header

    @patch.object(lsof_module, "_uid_to_username", return_value="root")
    @patch.object(lsof_module, "lsof")
    def test_output_row(self, mock_lsof, mock_uid):
        sock = SocketInfo(
            protocol="tcp",
            local_address="0.0.0.0",
            local_port=22,
            remote_address="0.0.0.0",
            remote_port=0,
            state="LISTEN",
            inode=12345,
            uid=0,
            pid=1023,
            process_name="sshd",
            fd=3,
        )
        mock_lsof.return_value = [sock]

        lines = list(lsof_stream())
        # lines[0] = header, lines[1] = data row
        row = lines[1]
        assert "sshd" in row
        assert "1023" in row
        assert "root" in row
        assert "3u" in row
        assert "IPv4" in row
        assert "TCP" in row
        assert "*:22 (LISTEN)" in row

    @patch.object(lsof_module, "_uid_to_username", return_value="user")
    @patch.object(lsof_module, "lsof")
    def test_ipv6_type(self, mock_lsof, mock_uid):
        sock = SocketInfo(
            protocol="tcp6",
            local_address="::",
            local_port=443,
            remote_address="::",
            remote_port=0,
            state="LISTEN",
            inode=22222,
            uid=1000,
            pid=500,
            process_name="nginx",
            fd=4,
        )
        mock_lsof.return_value = [sock]

        lines = list(lsof_stream())
        row = lines[1]
        assert "IPv6" in row
        assert "TCP" in row
        assert "nginx" in row

    @patch.object(lsof_module, "_uid_to_username", return_value="root")
    @patch.object(lsof_module, "lsof")
    def test_udp_node(self, mock_lsof, mock_uid):
        sock = SocketInfo(
            protocol="udp",
            local_address="0.0.0.0",
            local_port=53,
            remote_address="0.0.0.0",
            remote_port=0,
            state="UNCONN",
            inode=11111,
            uid=0,
            pid=200,
            process_name="dnsmasq",
            fd=5,
        )
        mock_lsof.return_value = [sock]

        lines = list(lsof_stream())
        row = lines[1]
        assert "UDP" in row
        assert "IPv4" in row

    @patch.object(lsof_module, "_uid_to_username", return_value="root")
    @patch.object(lsof_module, "lsof")
    def test_no_pid(self, mock_lsof, mock_uid):
        sock = SocketInfo(
            protocol="tcp",
            local_address="0.0.0.0",
            local_port=80,
            remote_address="0.0.0.0",
            remote_port=0,
            state="LISTEN",
            inode=1,
            uid=0,
        )
        mock_lsof.return_value = [sock]

        lines = list(lsof_stream())
        row = lines[1]
        # pid and command should show "-"
        assert "  -" in row

    @patch.object(lsof_module, "_uid_to_username", return_value="root")
    @patch.object(lsof_module, "lsof")
    def test_total_line(self, mock_lsof, mock_uid):
        mock_lsof.return_value = [
            SocketInfo(
                protocol="tcp",
                local_address="0.0.0.0",
                local_port=p,
                remote_address="0.0.0.0",
                remote_port=0,
                state="LISTEN",
                inode=p,
                uid=0,
                pid=1,
                process_name="test",
                fd=3,
            )
            for p in (22, 80, 443)
        ]

        lines = list(lsof_stream())
        assert any("Total: 3 socket(s)" in line for line in lines)


# ---------------------------------------------------------------------------
# CLI (_parse_port_spec)
# ---------------------------------------------------------------------------
class TestCli:
    """Tests for CLI argument parsing."""

    def test_parse_port_spec_plain(self):
        from src.lsof_cli import _parse_port_spec

        assert _parse_port_spec("80") == 80

    def test_parse_port_spec_colon_prefix(self):
        from src.lsof_cli import _parse_port_spec

        assert _parse_port_spec(":8080") == 8080

    def test_parse_port_spec_invalid(self):
        import argparse

        from src.lsof_cli import _parse_port_spec

        with pytest.raises(argparse.ArgumentTypeError):
            _parse_port_spec("abc")

    def test_parse_port_spec_out_of_range(self):
        import argparse

        from src.lsof_cli import _parse_port_spec

        with pytest.raises(argparse.ArgumentTypeError):
            _parse_port_spec("99999")

    @patch.object(lsof_module, "_build_inode_to_process_map", return_value={})
    @patch.object(lsof_module, "_parse_proc_net_file", return_value=[])
    def test_cli_main_no_args(self, mock_parse, mock_map):
        from src.lsof_cli import main

        with patch("sys.argv", ["netlsof"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 0

    @patch.object(lsof_module, "_build_inode_to_process_map", return_value={})
    @patch.object(lsof_module, "_parse_proc_net_file", return_value=[])
    def test_cli_tcp_flag(self, mock_parse, mock_map):
        from src.lsof_cli import main

        with patch("sys.argv", ["netlsof", "-t"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 0

    @patch.object(lsof_module, "_build_inode_to_process_map", return_value={})
    @patch.object(lsof_module, "_parse_proc_net_file", return_value=[])
    def test_cli_udp_flag(self, mock_parse, mock_map):
        from src.lsof_cli import main

        with patch("sys.argv", ["netlsof", "-u"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 0

    @patch.object(lsof_module, "_build_inode_to_process_map", return_value={})
    @patch.object(lsof_module, "_parse_proc_net_file", return_value=[])
    def test_cli_port_filter(self, mock_parse, mock_map):
        from src.lsof_cli import main

        with patch("sys.argv", ["netlsof", "-i", ":80"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 0

    @patch.object(lsof_module, "_build_inode_to_process_map", return_value={})
    @patch.object(lsof_module, "_parse_proc_net_file", return_value=[])
    def test_cli_state_filter(self, mock_parse, mock_map):
        from src.lsof_cli import main

        with patch("sys.argv", ["netlsof", "-s", "LISTEN"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 0
