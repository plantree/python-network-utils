"""Python Network Utilities Library."""

__version__ = "0.1.0"

from .ifconfig import (
    InterfaceInfo,
    get_all_interfaces,
    get_interface_info,
    ifconfig_stream,
)
from .ping import (
    PingResult,
    is_host_reachable,
    ping,
    ping_multiple,
    ping_stream,
)
from .traceroute import traceroute_stream

__all__ = [
    "ping",
    "ping_stream",
    "PingResult",
    "is_host_reachable",
    "ping_multiple",
    "traceroute_stream",
    "ifconfig_stream",
    "get_interface_info",
    "get_all_interfaces",
    "InterfaceInfo",
]
