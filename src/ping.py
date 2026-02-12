"""Ping tool using ICMP sockets.

Run with: sudo python -m network_utils <host>
Or: sudo .venv/bin/netping <host>
"""

# ICMP types
import os
import socket
import struct
import time
from dataclasses import dataclass
from typing import Generator, Optional

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0


@dataclass
class PingResult:
    """Result of a ping operation."""

    host: str
    is_reachable: bool
    packets_sent: int = 0
    packets_received: int = 0
    packet_loss: float = 0.0
    min_rtt: Optional[float] = None
    avg_rtt: Optional[float] = None
    max_rtt: Optional[float] = None
    error: Optional[str] = None


@dataclass
class PingResponse:
    """Single ping response."""

    seq: int
    ttl: int
    rtt: float  # in milliseconds
    ip: str
    bytes: int = 64


def _checksum(data: bytes) -> int:
    """Calculate ICMP checksum."""
    if len(data) % 2:
        data += b"\x00"

    total = sum(int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _create_icmp_packet(packet_id: int, seq: int, payload_size: int = 56) -> bytes:
    """Create an ICMP echo request packet."""
    # ICMP Echo Request Packet Structure (RFC 792)
    #
    #  0                            15                               31
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |     Type (8)  |    Code (0)   |           Checksum            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |           Identifier          |        Sequence Number        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                         Payload Data                          |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # Header: type(1), code(1), checksum(2), id(2), seq(2) = 8 bytes
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, packet_id, seq)
    payload = bytes(range(payload_size))

    # Calculate checksum
    checksum = _checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, checksum, packet_id, seq)

    return header + payload


def _parse_icmp_reply(data: bytes, packet_id: int) -> Optional[tuple]:
    """Parse ICMP reply packet."""

    # IP Header Structure
    # 0                              15                              31
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |Version|  IHL  |Type of Service|          Total Length         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |         Identification        |Flags|      Fragment Offset    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |  Time to Live |    Protocol   |         Header Checksum       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # IP header is 20 bytes.
    ip_header = data[:20]
    ttl = ip_header[8]

    # ICMP Reply Packet Structure (RFC 792)
    #  0                            15                               31
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |     Type (0)  |    Code (0)   |           Checksum            |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |           Identifier          |        Sequence Number        |
    icmp_header = data[20:28]
    icmp_type, code, checksum, recv_id, seq = struct.unpack("!BBHHH", icmp_header)

    # Check checksum
    if _checksum(icmp_header + data[28:]) != 0:
        return None

    if icmp_type == ICMP_ECHO_REPLY and code == 0 and recv_id == packet_id:
        return seq, ttl

    return None


def _resolve_host(host: str) -> str:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        raise ValueError(f"Cannot resolve hostname: {host}")


def ping_stream(
    host: str, count: int = 4, timeout: int = 5
) -> Generator[str, None, int]:
    """Ping a host using ICMP echo requests."""
    try:
        ip = _resolve_host(host)
    except ValueError as e:
        yield f"ping: {e}\n"
        return 1

    packet_id = os.getpid() & 0xFFFF
    payload_size = 56

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
    except PermissionError:
        msg = "ping: Permission denied. "
        msg += "Run with root/administrator privileges.\n"
        yield msg
        return 1
    except Exception as e:
        yield f"ping: {e}\n"
        return 1

    # IP header (20) + ICMP header (8)
    total_size = payload_size + 28
    yield f"PING {host} ({ip}) {payload_size}({total_size}) bytes of data.\n"

    rtts = []
    packets_received = 0

    try:
        for seq in range(1, count + 1):
            packet = _create_icmp_packet(packet_id, seq)

            send_time = time.perf_counter()
            sock.sendto(packet, (ip, 0))

            try:
                data, _ = sock.recvfrom(1024)
                recv_time = time.perf_counter()

                result = _parse_icmp_reply(data, packet_id)
                if result:
                    recv_seq, ttl = result
                    rtt = (recv_time - send_time) * 1000  # in milliseconds
                    rtts.append(rtt)
                    packets_received += 1

                    # Get reverse DNS (optional, may fail)
                    nbytes = payload_size + 8
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                        yield (
                            f"{nbytes} bytes from {hostname} ({ip}): "
                            f"icmp_seq={recv_seq} ttl={ttl} "
                            f"time={rtt:.1f} ms\n"
                        )
                    except socket.herror:
                        yield (
                            f"{nbytes} bytes from {ip}: "
                            f"icmp_seq={recv_seq} ttl={ttl} "
                            f"time={rtt:.1f} ms\n"
                        )

            except socket.timeout:
                yield f"Request timeout for icmp_seq {seq}\n"

            # Wait before sending the next packet
            if seq < count:
                elapsed = time.perf_counter() - send_time
                if elapsed < 1:
                    time.sleep(1 - elapsed)
    finally:
        sock.close()

    # Print statistics
    yield f"\n--- {host} ping statistics ---\n"
    packet_loss = ((count - packets_received) / count) * 100
    yield (
        f"{count} packets transmitted, {packets_received} packets received, "
        f"{packet_loss:.1f}% packet loss\n"
    )

    if rtts:
        avg = sum(rtts) / len(rtts)
        yield (f"rtt min/avg/max = " f"{min(rtts):.3f}/{avg:.3f}/{max(rtts):.3f} ms\n")

    return 0 if packets_received > 0 else 1


def ping(host: str, count: int = 4, timeout: int = 5) -> PingResult:
    """Ping a host and return result."""
    try:
        ip = _resolve_host(host)
    except ValueError as e:
        return PingResult(host=host, is_reachable=False, error=str(e))

    packet_id = os.getpid() & 0xFFFF

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
    except PermissionError:
        return PingResult(
            host=host,
            is_reachable=False,
            error="Permission denied. Run with root/administrator privileges.",
        )
    except Exception as e:
        return PingResult(host=host, is_reachable=False, error=str(e))

    rtts = []
    packets_received = 0

    try:
        for seq in range(1, count + 1):
            packet = _create_icmp_packet(packet_id, seq)
            send_time = time.perf_counter()
            sock.sendto(packet, (ip, 0))

            try:
                data, _ = sock.recvfrom(1024)
                recv_time = time.perf_counter()

                parsed = _parse_icmp_reply(data, packet_id)
                if parsed:
                    rtt = (recv_time - send_time) * 1000
                    rtts.append(rtt)
                    packets_received += 1
            except socket.timeout:
                pass

            if seq < count:
                elapsed = time.perf_counter() - send_time
                if elapsed < 1:
                    time.sleep(1 - elapsed)
    finally:
        sock.close()

    if count > 0:
        packet_loss = ((count - packets_received) / count) * 100
    else:
        packet_loss = 0

    result = PingResult(
        host=host,
        is_reachable=packets_received > 0,
        packets_sent=count,
        packets_received=packets_received,
        packet_loss=packet_loss,
    )

    if rtts:
        result.min_rtt = min(rtts)
        result.avg_rtt = sum(rtts) / len(rtts)
        result.max_rtt = max(rtts)

    return result


def is_host_reachable(host: str, timeout: int = 5) -> bool:
    """Check if a host is reachable via ping."""
    result = ping(host, count=1, timeout=timeout)
    return result.is_reachable


def ping_multiple(hosts: list, count: int = 4, timeout: int = 5) -> list:
    """Ping multiple hosts sequentially."""
    return [ping(host, count=count, timeout=timeout) for host in hosts]


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: sudo python -m network_utils <host>")
        sys.exit(1)

    host = sys.argv[1]
    for line in ping_stream(host):
        print(line, end="", flush=True)
