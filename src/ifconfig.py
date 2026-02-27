"""ifconfig tool - display network interface configuration.

Run with: python -m src.ifconfig [interface]
Or: .venv/bin/netifconfig [interface]
"""

import fcntl
import socket
import struct

# ioctl request codes for network interface configuration
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

SIOCGIFADDR = 0x8915  # Get IP address
SIOCGIFNETMASK = 0x891B  # Get network mask
SIOCGIFHWADDR = 0x8927  # Get hardware address
SIOCGIFMTU = 0x8921  # Get MTU
SIOCGIFFLAGS = 0x8913  # Get interface flags
SIOCGIBRDADDR = 0x8919  # Get broadcast address

# interface flags
IFF_UP = 0x1  # Interface is up
IFF_BROADCAST = 0x2  # Broadcast address valid
IFF_LOOPBACK = 0x8  # Is a loopback network
IFF_RUNNING = 0x40  # Resources allocated
IFF_MULTICAST = 0x1000  # Supports multicast


@dataclass
class InterfaceInfo:
    """Information about a network interface."""

    name: str
    ip_address: Optional[str] = None
    netmask: Optional[str] = None
    broadcast: Optional[str] = None
    mac_address: Optional[str] = None
    ipv6_address: Optional[str] = None
    ipv6_prefixlen: int = 0
    ipv6_scope: Optional[str] = None
    mtu: int = 0
    txqueuelen: int = 0
    flags: int = 0
    is_up: bool = False
    is_running: bool = False
    is_loopback: bool = False
    is_broadcast: bool = False
    is_multicast: bool = False
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_packets: int = 0
    tx_packets: int = 0
    rx_errors: int = 0
    tx_errors: int = 0
    rx_dropped: int = 0
    tx_dropped: int = 0
    errors: list = field(default_factory=list)


def _get_interface_names() -> list[str]:
    """Get a list of network interface names."""
    try:
        return [name for _, name in socket.if_nameindex()]
    except (OSError, AttributeError):
        # Fallback: read from /sys/class/net (Linux specific)
        net_path = Path("/sys/class/net")
        if net_path.exists() and net_path.is_dir():
            return [p.name for p in net_path.iterdir() if p.is_dir()]
        return []


def _ioctl_get_string(sock: socket.socket, ifname: str, code: int) -> Optional[str]:
    """Perform ioctl and extrace IP address string."""
    try:
        # struct ifreg is 40 bytes, interface name is first 16 bytes
        ifreq = struct.pack("256s", ifname[:15].encode("utf-8"))
        result = fcntl.ioctl(sock.fileno(), code, ifreq)
        # IP address is at offset 20-24 in the result
        return socket.inet_ntoa(result[20:24])
    except (OSError, IOError):
        return None


def _get_mac_address(sock: socket.socket, ifname: str) -> Optional[str]:
    """Get MAC address for interface."""
    try:
        ifreg = struct.pack("256s", ifname[:15].encode("utf-8"))
        result = fcntl.ioctl(sock.fileno(), SIOCGIFHWADDR, ifreg)
        # MAC address is at offset 18-24 in the result
        mac_bytes = result[18:24]
        return ":".join(f"{b:02x}" for b in mac_bytes)
    except (OSError, IOError):
        return None


def _get_flags(sock: socket.socket, ifname: str) -> int:
    """Get interface flags."""
    try:
        ifreq = struct.pack("256s", ifname[:15].encode("utf-8"))
        result = fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, ifreq)
        # Flags are at offset 16-18 in the result
        return int(struct.unpack("H", result[16:18])[0])
    except (OSError, IOError):
        return 0


def _get_mtu(sock: socket.socket, ifname: str) -> int:
    """Get interface MTU."""
    try:
        ifreq = struct.pack("256s", ifname[:15].encode("utf-8"))
        result = fcntl.ioctl(sock.fileno(), SIOCGIFMTU, ifreq)
        # MTU is at offset 16-20 in the result
        return int(struct.unpack("I", result[16:20])[0])
    except (OSError, IOError):
        return 0


def _get_interface_stats(ifname: str) -> dict:
    """Get interface statistics from /sys/class/net."""
    stats = {
        "rx_bytes": 0,
        "tx_bytes": 0,
        "rx_packets": 0,
        "tx_packets": 0,
        "rx_errors": 0,
        "tx_errors": 0,
        "rx_dropped": 0,
        "tx_dropped": 0,
    }

    stats_path = Path(f"/sys/class/net/{ifname}/statistics")
    if not stats_path.exists():
        return stats

    for stat_name in stats:
        stat_file = stats_path / stat_name
        if stat_file.exists():
            try:
                with stat_file.open() as f:
                    stats[stat_name] = int(f.read().strip())
            except (OSError, ValueError):
                pass

    return stats


def _get_txqueuelen(ifname: str) -> int:
    """Get interface TX queue length from /sys/class/net."""
    txqueuelen_path = Path(f"/sys/class/net/{ifname}/tx_queue_len")
    if txqueuelen_path.exists():
        try:
            with txqueuelen_path.open() as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            pass
    return 0


def _get_ipv6_info(ifname: str) -> tuple[Optional[str], int, Optional[str]]:
    """Get IPv6 address info from /proc/net/if_inet6."""
    try:
        with open("/proc/net/if_inet6") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 6 and parts[5] == ifname:
                    # Parse IPv6 address (it's in hex without colons)
                    addr_hex = parts[0]
                    # Convert to proper IPv6 format
                    addr_parts = [addr_hex[i : i + 4] for i in range(0, 32, 4)]
                    ipv6_addr = ":".join(addr_parts)
                    # Compress the address
                    try:
                        import ipaddress

                        ipv6_addr = str(ipaddress.IPv6Address(ipv6_addr))
                    except (ImportError, ValueError):
                        pass

                    prefixlen = int(parts[2], 16)
                    scope_id = int(parts[3], 16)

                    # Map scope ID to name
                    scope_map = {
                        0x00: "global",
                        0x10: "host",
                        0x20: "link",
                        0x40: "site",
                    }
                    scope = scope_map.get(scope_id, f"0x{scope_id:02x}")

                    return ipv6_addr, prefixlen, scope
    except (OSError, IOError):
        pass
    return None, 0, None


def get_interface_info(ifname: str) -> InterfaceInfo:
    """Get information for a specific network interface."""
    info = InterfaceInfo(name=ifname)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as e:
        info.errors.append(f"Failed to create socket: {e}")
        return info

    try:
        # Get IP address
        info.ip_address = _ioctl_get_string(sock, ifname, SIOCGIFADDR)

        # Get netmask
        info.netmask = _ioctl_get_string(sock, ifname, SIOCGIFNETMASK)

        # Get broadcast address
        info.broadcast = _ioctl_get_string(sock, ifname, SIOCGIBRDADDR)

        # Get MAC address
        info.mac_address = _get_mac_address(sock, ifname)

        # Get MTU
        info.mtu = _get_mtu(sock, ifname)

        # Get flags
        info.flags = _get_flags(sock, ifname)
        info.is_up = bool(info.flags & IFF_UP)
        info.is_running = bool(info.flags & IFF_RUNNING)
        info.is_loopback = bool(info.flags & IFF_LOOPBACK)
        info.is_broadcast = bool(info.flags & IFF_BROADCAST)
        info.is_multicast = bool(info.flags & IFF_MULTICAST)

        # Get interface statistics
        stats = _get_interface_stats(ifname)
        info.rx_bytes = stats["rx_bytes"]
        info.tx_bytes = stats["tx_bytes"]
        info.rx_packets = stats["rx_packets"]
        info.tx_packets = stats["tx_packets"]
        info.rx_errors = stats["rx_errors"]
        info.tx_errors = stats["tx_errors"]
        info.rx_dropped = stats["rx_dropped"]
        info.tx_dropped = stats["tx_dropped"]

        # Get TX queue length
        info.txqueuelen = _get_txqueuelen(ifname)

        # Get IPv6 info
        info.ipv6_address, info.ipv6_prefixlen, info.ipv6_scope = _get_ipv6_info(ifname)

    finally:
        sock.close()

    return info


def get_all_interfaces() -> list[InterfaceInfo]:
    """Get information for all network interfaces."""
    interfaces = []
    for ifname in _get_interface_names():
        interfaces.append(get_interface_info(ifname))
    return interfaces


def _format_bytes(nbytes: int) -> str:
    """Format bytes into human-readable string (decimal, like ifconfig)."""
    if nbytes < 1000:
        return f"{nbytes} B"
    elif nbytes < 1000**2:
        return f"{nbytes / 1000:.1f} KB"
    elif nbytes < 1000**3:
        return f"{nbytes / 1000**2:.1f} MB"
    else:
        return f"{nbytes / 1000**3:.1f} GB"


def format_interface(info: InterfaceInfo) -> str:
    """Format interface information into a string."""
    lines = []

    # First line: interface name and flags
    flags = []
    if info.is_up:
        flags.append("UP")
    if info.is_broadcast:
        flags.append("BROADCAST")
    if info.is_loopback:
        flags.append("LOOPBACK")
    if info.is_running:
        flags.append("RUNNING")
    if info.is_multicast:
        flags.append("MULTICAST")

    if not info.is_up:
        flags.append("DOWN")
    flags_str = ",".join(flags) if flags else "NO FLAGS"
    lines.append(f"{info.name}: flags={info.flags}<{flags_str}>  mtu {info.mtu}")

    # Second line: inet address
    if info.ip_address:
        line = f"        inet {info.ip_address}"
        if info.netmask:
            line += f"  netmask {info.netmask}"
        if info.broadcast and not info.is_loopback:
            line += f"  broadcast {info.broadcast}"
        lines.append(line)

    # IPv6 address line
    if info.ipv6_address:
        scope_id = (
            "0x20"
            if info.ipv6_scope == "link"
            else ("0x10" if info.ipv6_scope == "host" else "0x00")
        )
        lines.append(
            f"        inet6 {info.ipv6_address}  prefixlen {info.ipv6_prefixlen}  "
            f"scopeid {scope_id}<{info.ipv6_scope}>"
        )

    # MAC address (ether) or loop line with txqueuelen and type
    if info.is_loopback:
        lines.append(f"        loop  txqueuelen {info.txqueuelen}  (Local Loopback)")
    elif info.mac_address and info.mac_address != "00:00:00:00:00:00":
        lines.append(
            f"        ether {info.mac_address}  txqueuelen {info.txqueuelen}  (Ethernet)"
        )

    # RX packets and bytes
    lines.append(
        f"        RX packets {info.rx_packets}  bytes {info.rx_bytes} "
        f"({_format_bytes(info.rx_bytes)})"
    )

    # RX errors and dropped
    lines.append(
        f"        RX errors {info.rx_errors}  dropped {info.rx_dropped}  "
        f"overruns 0  frame 0"
    )

    # TX packets and bytes
    lines.append(
        f"        TX packets {info.tx_packets}  bytes {info.tx_bytes} "
        f"({_format_bytes(info.tx_bytes)})"
    )

    # TX errors and dropped
    lines.append(
        f"        TX errors {info.tx_errors}  dropped {info.tx_dropped} "
        f"overruns 0  carrier 0  collisions 0"
    )

    return "\n".join(lines)


def ifconfig_stream(interface: Optional[str] = None):
    """Generate ifconfig output for the specified interface or all interfaces."""
    if interface:
        # Check if the specified interface exists
        available_interfaces = _get_interface_names()
        if interface not in available_interfaces:
            yield f"{interface}: error fetching interface information: No such device\n"
            return

        info = get_interface_info(interface)
        yield format_interface(info) + "\n"
    else:
        interfaces = get_all_interfaces()
        for info in interfaces:
            yield format_interface(info) + "\n"


def ifconfig(interface: Optional[str] = None) -> list[InterfaceInfo]:
    """Get interface information.

    Args:
        interface: Optional interface name. If None, returns all interfaces.

    Returns:
        List of InterfaceInfo objects.

    Raises:
        ValueError: If specified interface does not exist.
    """
    if interface:
        available_interfaces = _get_interface_names()
        if interface not in available_interfaces:
            raise ValueError(
                f"{interface}: error fetching interface information: No such device"
            )
        return [get_interface_info(interface)]
    return get_all_interfaces()


if __name__ == "__main__":
    # If run as a script, display all interfaces
    for line in ifconfig_stream():
        print(line, end="", flush=True)
