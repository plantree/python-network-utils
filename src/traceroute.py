"""Traceroute tool using ICMP sockets.

Traces the route packets take to reach a destination by sending
ICMP Echo Request packets with increasing TTL values.

Run with: sudo python -m src.traceroute <host>
Or: sudo .venv/bin/nettraceroute <host>
"""

import os
import socket
import struct
import time
from typing import Optional

# ICMP types
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_TIME_EXCEEDED = 11


def _checksum(data: bytes) -> int:
    """Calculate ICMP checksum."""
    if len(data) % 2:
        data += b"\x00"

    total = sum(int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _create_icmp_packet(packet_id: int, seq: int) -> bytes:
    """Create an ICMP echo request packet."""
    # ICMP Echo Request Packet Structure (RFC 792)
    #
    #  0                            15                               31
    # +-------------------------------+-------------------------------+
    # |     Type (8)                  |     Code (0)                  |
    # +-------------------------------+-------------------------------+
    # |          Checksum             |       Identifier              |
    # +-------------------------------+-------------------------------+
    # |        Sequence Number        |                               |
    # +-------------------------------+         Payload (data)        |
    # |                                                               |
    # +---------------------------------------------------------------+

    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, packet_id, seq)
    payload = bytes(range(56))

    checksum = _checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, checksum, packet_id, seq)

    return header + payload


def _resolve_host(host: str) -> str:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        raise ValueError(f"Cannot resolve host: {host}")


def _get_hostname(ip: str) -> Optional[str]:
    """Get hostname from IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None


def traceroute_stream(
    host: str,
    max_hops: int = 30,
    timeout: int = 3,
    probes: int = 3,
):
    """Perform traceroute to the specified host, yielding output lines."""
    try:
        dest_ip = _resolve_host(host)
    except ValueError as e:
        yield f"traceroute: {e}\n"
        return 1

    yield f"traceroute to {host} ({dest_ip}), {max_hops} hops max, {probes} probes per hop\n"

    packet_id = os.getpid() & 0xFFFF
    seq = 0

    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_sock.settimeout(timeout)
    except PermissionError:
        yield "traceroute: Permission denied. Run with root/administrator privileges.\n"
        yield "Run with root/administrator privileges.\n"
        return 1
    except Exception as e:
        yield f"traceroute: {e}\n"
        return 1

    reached = False
    try:
        for ttl in range(1, max_hops + 1):
            # Set TTL for this hop
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            line = f"{ttl:2d}  "
            last_addr = None

            for _ in range(probes):
                seq += 1
                packet = _create_icmp_packet(packet_id, seq)

                send_time = time.perf_counter()
                send_sock.sendto(packet, (dest_ip, 0))

                try:
                    data, addr = recv_sock.recvfrom(1024)
                    recv_time = time.perf_counter()
                    rtt = (recv_time - send_time) * 1000  # in ms

                    curr_addr = addr[0]

                    # Check checksum and type
                    icmp_data = data[20:]  # Skip IP header
                    if _checksum(icmp_data) != 0:
                        continue

                    # Parse ICMP reply
                    icmp_type = data[20]

                    if icmp_type == ICMP_TIME_EXCEEDED:
                        # Time exceeded
                        if curr_addr != last_addr:
                            if last_addr is not None:
                                line += "   "
                            hostname = _get_hostname(curr_addr)
                            if hostname:
                                line += f"{hostname} ({curr_addr}) "
                            else:
                                line += f"{curr_addr} "
                            last_addr = curr_addr
                        line += f"{rtt:.3f} ms "

                    elif icmp_type == ICMP_ECHO_REPLY:
                        # Reached destination
                        if curr_addr != last_addr:
                            if last_addr is not None:
                                line += "   "
                            hostname = _get_hostname(curr_addr)
                            if hostname:
                                line += f"{hostname} ({curr_addr}) "
                            else:
                                line += f"{curr_addr} "
                            last_addr = curr_addr
                        line += f"{rtt:.3f} ms "

                        reached = True

                except socket.timeout:
                    line += " * "

            yield line + "\n"

            if reached:
                break
    finally:
        send_sock.close()
        recv_sock.close()

    return 0 if reached else 1


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: sudo python -m src.traceroute <host>")
        sys.exit(1)

    host = sys.argv[1]
    for line in traceroute_stream(host):
        print(line, end="", flush=True)
