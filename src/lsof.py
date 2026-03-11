"""lsof - List open files related to Internet sockets.

A python reimplementation of the `lsof -i` command, which lists
open files related to Internet sockets.

Run with: sudo python -m src.lsof
Or: sudo .venv/bin/netlsof

Example:
    $ sudo python -m src.lsof
    $ sudo python -m src.lsof -p 1234
    $ sudo python -m src.lsof -t -s LISTEN
    $ sudo python -m src.lsof -i :80
"""

import os
import pwd
import socket
import struct
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Dict, Generator, List, Optional, Tuple


# TCP connection states from the Linux kernel (include/net/tcp_states.h)
class TcpState(IntEnum):
    """TCP socket states as defined by the Linux kernel."""

    ESTABLISHED = 1
    SYNC_SENT = 2
    SYNC_RECV = 3
    FIN_WAIT1 = 4
    FIN_WAIT2 = 5
    TIME_WAIT = 6
    CLOSE = 7
    CLOSE_WAIT = 8
    LAST_ACK = 9
    LISTEN = 10
    CLOSING = 11


_TCP_STATE_NAMES: Dict[int, str] = {s.value: s.name for s in TcpState}

# /proc/net files for each protocol family
_PROC_NET_FILES: Dict[str, str] = {
    "tcp": "/proc/net/tcp",
    "tcp6": "/proc/net/tcp6",
    "udp": "/proc/net/udp",
    "udp6": "/proc/net/udp6",
}


@dataclass
class SocketInfo:
    """Information about an open network socket."""

    protocol: str  # "tcp", "tcp6", "udp", or "udp6"
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: Optional[str]
    inode: int
    uid: int
    tx_queue: int = 0
    rx_queue: int = 0
    pid: Optional[int] = None
    process_name: Optional[str] = None
    fd: Optional[int] = None


def _parse_hex_addr_v4(hex_addr: str) -> str:
    """Convert a 32-bit hex IPv4 address to dotted-quad."""
    return socket.inet_ntoa(struct.pack("<I", int(hex_addr, 16)))


def _parse_hex_addr_v6(hex_addr: str) -> str:
    """Convert a 128-bit hex IPv6 address to standard notation."""
    raw = b""
    for i in range(0, 32, 8):
        word = int(hex_addr[i : i + 8], 16)
        raw += struct.pack("<I", word)
    return socket.inet_ntop(socket.AF_INET6, raw)


def _parse_addr_port(addr_port: str, is_ipv6: bool) -> Tuple[str, int]:
    """Split `HEX_ADDR:HEX_PORT` into (IP, port)."""
    addr_hex, port_hex = addr_port.split(":")
    port = int(port_hex, 16)
    if is_ipv6:
        ip = _parse_hex_addr_v6(addr_hex)
    else:
        ip = _parse_hex_addr_v4(addr_hex)
    return ip, port


def _parse_proc_net_file(path: str, protocol: str) -> List[SocketInfo]:
    """Parse one of the /proc/net/{tcp, tcp6, udp, udp6} files and return a list of SocketInfo."""
    sockets: List[SocketInfo] = []
    is_ipv6 = protocol.endswith("6")
    is_tcp = protocol.startswith("tcp")

    try:
        with open(path) as f:
            lines = f.readlines()
    except (FileNotFoundError, PermissionError):
        return sockets

    for line in lines[1:]:  # Skip header line
        fields = line.strip().split()
        if len(fields) < 10:
            continue  # Malformed line

        local_addr, local_port = _parse_addr_port(fields[1], is_ipv6)
        remote_addr, remote_port = _parse_addr_port(fields[2], is_ipv6)

        state_hex = fields[3]
        queue_parts = fields[4].split(":")
        tx_queue = int(queue_parts[0], 16) if len(queue_parts) == 2 else 0
        rx_queue = int(queue_parts[1], 16) if len(queue_parts) == 2 else 0
        uid = int(fields[7])
        inode = int(fields[9])

        if is_tcp:
            state_val = int(state_hex, 16)
            state = _TCP_STATE_NAMES.get(state_val, f"UNKNOWN({state_hex})")
        else:
            # UDP: kernel uses 1=ESTABLISHED, 7=CLOSE
            state_val = int(state_hex, 16)
            if state_val == 7:
                state = "UNCONN"
            elif state_val == 1:
                state = "ESTABLISHED"
            else:
                state = None

        sockets.append(
            SocketInfo(
                protocol=protocol,
                local_address=local_addr,
                local_port=local_port,
                remote_address=remote_addr,
                remote_port=remote_port,
                state=state,
                inode=inode,
                uid=uid,
                tx_queue=tx_queue,
                rx_queue=rx_queue,
            )
        )

    return sockets


def _build_inode_to_process_map() -> Dict[int, Tuple[int, str, int]]:
    """Map socket inodes to (pid, process_name, fd)."""
    mapping: Dict[int, Tuple[int, str, int]] = {}
    proc = Path("/proc")

    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)

        # Read process command name (/proc/PID/comm)
        try:
            comm = (entry / "comm").read_text().strip()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            comm = "?"

        # Scan file descriptors for this process
        fd_dir = entry / "fd"
        try:
            for fd_entry in fd_dir.iterdir():
                try:
                    link = os.readlink(str(fd_entry))
                    if link.startswith("socket:["):
                        inode = int(link[8:-1])
                        fd_num = int(fd_entry.name)
                        mapping[inode] = (pid, comm, fd_num)
                except (
                    FileNotFoundError,
                    PermissionError,
                    ProcessLookupError,
                    ValueError,
                    OSError,
                ):
                    continue
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue

    return mapping


def _uid_to_username(uid: int) -> str:
    """Resolve a UID to a username."""
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _try_service_name(port: int, proto: str) -> Optional[str]:
    """Try to resolve a port number to a service name."""
    if port == 0:
        return None
    base_proto = "tcp" if proto.startswith("tcp") else "udp"
    try:
        return socket.getservbyport(port, base_proto)
    except OSError:
        return None


def _format_address(
    addr: str,
    port: int,
    is_ipv6: bool,
    *,
    resolve_services: bool = False,
    proto: str = "tcp",
) -> str:
    """Format address:port for display."""
    if addr in ("0.0.0.0", "::", "::ffff:0.0.0.0"):
        addr_str = "*"
    else:
        addr_str = addr

    if port == 0 and addr_str == "*":
        return "*:*"

    if resolve_services:
        svc = _try_service_name(port, proto)
        port_str = svc if svc else str(port)
    else:
        port_str = str(port)

    if is_ipv6 and addr_str != "*":
        return f"[{addr_str}]:{port_str}"
    return f"{addr_str}:{port_str}"


def lsof(
    protocols: Optional[List[str]] = None,
    port: Optional[int] = None,
    pid: Optional[int] = None,
    state: Optional[str] = None,
) -> List[SocketInfo]:
    """List open network sockets matching the given filters.

    Args:
        protocols: Protocol families to include, e.g. tcp, udp6, and None means all
        port: Show only sockets whose local or remote port.
        pid: Show only sockets owned by this process ID.
        state: Show only sockets in this TCP state, e.g. LISTEN, etc.

    Returns:
        A sorted list of `SocketInfo`.
    """
    if protocols is None:
        protocols = list(_PROC_NET_FILES.keys())

    all_sockets: List[SocketInfo] = []
    for proto in protocols:
        path = _PROC_NET_FILES.get(proto)
        if path:
            all_sockets.extend(_parse_proc_net_file(path, proto))

    # Enrich with process info
    inode_map = _build_inode_to_process_map()
    for sock in all_sockets:
        info = inode_map.get(sock.inode)
        if info:
            sock.pid, sock.process_name, sock.fd = info

    # Filters
    result = all_sockets
    if port is not None:
        result = [s for s in result if s.local_port == port or s.remote_port == port]
    if pid is not None:
        result = [s for s in result if s.pid == pid]
    if state is not None:
        state_upper = state.upper()
        result = [s for s in result if s.state and s.state.upper() == state_upper]

    # Sort by protocol, state, local port
    _state_order = {"LISTEN": 0, "ESTABLISHED": 1}
    result.sort(
        key=lambda s: (
            s.protocol,
            _state_order.get(s.state or "", 99),
            s.local_port,
        )
    )

    return result


def _format_name(sock: SocketInfo, *, resolve_services: bool = False) -> str:
    """Format the NAME column in lsof style: local->remote (STATE)."""
    is_ipv6 = sock.protocol.endswith("6")
    local = _format_address(
        sock.local_address,
        sock.local_port,
        is_ipv6,
        resolve_services=resolve_services,
        proto=sock.protocol,
    )
    remote = _format_address(
        sock.remote_address,
        sock.remote_port,
        is_ipv6,
        resolve_services=resolve_services,
        proto=sock.protocol,
    )

    # For listening/unconnected sockets, omit the remote part if it's *:*
    if remote == "*:*":
        name = local
    else:
        name = f"{local}->{remote}"

    if sock.state:
        name += f" ({sock.state})"

    return name


def lsof_stream(
    protocols: Optional[List[str]] = None,
    port: Optional[int] = None,
    pid: Optional[int] = None,
    state: Optional[str] = None,
    resolve_services: bool = False,
) -> Generator[str, None, None]:
    """Yield lines of lsof output for open network sockets matching the given filters."""
    sockets = lsof(protocols=protocols, port=port, pid=pid, state=state)

    if not sockets:
        yield "No open network sockets found.\n"
        return

    # Header (matches real lsof -i output)
    yield (
        f"{'COMMAND':<16} {'PID':>7} {'USER':<10} {'FD':>5} "
        f"{'TYPE':<6} {'DEVICE':>7} {'SIZE/OFF':>8} {'NODE':<5} NAME\n"
    )

    for sock in sockets:
        command = (sock.process_name or "-")[:16]
        pid_str = str(sock.pid) if sock.pid is not None else "-"
        user = _uid_to_username(sock.uid)
        fd_str = f"{sock.fd}u" if sock.fd is not None else "-"
        type_str = "IPv6" if sock.protocol.endswith("6") else "IPv4"
        node = "TCP" if sock.protocol.startswith("tcp") else "UDP"
        device = str(sock.inode)
        name = _format_name(sock, resolve_services=resolve_services)

        yield (
            f"{command:<16} {pid_str:>7} {user:<10} {fd_str:>5} "
            f"{type_str:<6} {device:>7} {'0t0':>8} {node:<5} {name}\n"
        )

    yield ""
    yield f"Total: {len(sockets)} socket(s)\n"


if __name__ == "__main__":
    from .lsof_cli import main

    main()
