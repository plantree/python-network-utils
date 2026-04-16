"""nmap_syn - TCP SYN (half-open) port scanner using raw sockets.

Unlike the TCP connect scan, this performs a SYN scan:
- Sends a TCP SYN packet to the target port
- SYN-ACK response indicates the port is open (connection can be completed)
- RST response indicates the port is closed
- No response or ICMP unreachable indicates the port is filtered (firewalled)

Requires root/sudo for raw socket access.

Run with: sudo python -m src.nmap_syn <host> [--ports 22,80,443] [--top-ports 100]

Example usage:
    $ sudo python -m src.nmap_syn scanme.nmap.org --ports 22,80,443
    $ sudo python -m src.nmap_syn example.com --top-ports 100
"""

import random
import select
import socket
import struct
import time
from typing import Generator, List, Optional, Set

from .nmap import (
    DEFAULT_PORTS,
    DEFAULT_TIMEOUT,
    MAX_CONCURRENT,
    TOP_PORTS,
    NmapResult,
    PortResult,
    _addr_family,
    _get_service,
    _parse_ports,
    _resolve_host,
)

# TCP flag bitmasks (byte 13 of TCP header)
_SYN = 0x02
_RST = 0x04
_ACK = 0x10


def _checksum(data: bytes) -> int:
    """Calculate checksum for TCP packet."""
    if len(data) % 2:
        data += b"\x00"

    total = sum(int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _get_local_ip(target_ip: str, family: socket.AddressFamily) -> str:
    """Determine the local IP address used to route to *target_ip*."""
    s = socket.socket(family, socket.SOCK_DGRAM)
    try:
        s.connect((target_ip, 80))
        return str(s.getsockname()[0])
    finally:
        s.close()


def _tcp_header(src_port: int, dst_port: int, seq: int, cksum: int = 0) -> bytes:
    """Construct a TCP header with SYN flag set."""
    offset_flags = (5 << 12) | _SYN  # Data offset (5) and SYN flag
    return struct.pack(
        "!HHLLHHHH",
        src_port,
        dst_port,
        seq,
        0,  # ack_seq
        offset_flags,
        1024,  # window
        cksum,
        0,  # urg_ptr
    )


def _ipv4_tcp_checksum(src_ip: str, dst_ip: str, tcp: bytes) -> int:
    """Calculate TCP checksum with IPv4 pseudo-header."""
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        socket.IPPROTO_TCP,
        len(tcp),
    )
    return _checksum(pseudo + tcp)


def _ipv6_tcp_checksum(src_ip: str, dst_ip: str, tcp: bytes) -> int:
    """Calculate TCP checksum with IPv6 pseudo-header."""
    pseudo = struct.pack(
        "!16s16sI3xB",
        socket.inet_pton(socket.AF_INET6, src_ip),
        socket.inet_pton(socket.AF_INET6, dst_ip),
        len(tcp),
        socket.IPPROTO_TCP,
    )
    return _checksum(pseudo + tcp)


def _build_syn_v4(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
) -> bytes:
    """Return a complete IPv4 packet with TCP SYN."""
    seq = random.randint(0, 0xFFFFFFFF)
    tcp = _tcp_header(src_port, dst_port, seq)
    cksum = _ipv4_tcp_checksum(src_ip, dst_ip, tcp)
    tcp = _tcp_header(src_port, dst_port, seq, cksum)

    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # Version and IHL
        0,  # DSCP/ECN
        20 + len(tcp),  # Total length
        random.randint(1, 0xFFFF),  # Identification
        0,  # Flags/Fragment offset
        64,  # TTL
        socket.IPPROTO_TCP,
        0,  # Header checksum (kernel will fill)
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    return ip + tcp


def _build_syn_v6(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
) -> bytes:
    """Return a complete IPv6 packet with TCP SYN (kernel adds IPv6 header)."""
    seq = random.randint(0, 0xFFFFFFFF)
    tcp = _tcp_header(src_port, dst_port, seq)
    cksum = _ipv6_tcp_checksum(src_ip, dst_ip, tcp)
    return _tcp_header(
        src_port, dst_port, seq, cksum
    )  # IPv6 header is handled by kernel


def _sync_scan_batch(
    ip: str, ports: List[int], timeout: float, src_ip: str, src_port: int
) -> List[PortResult]:
    """Send SYN probes to *ip* on *ports* and return results."""
    family = _addr_family(ip)
    results: List[PortResult] = []
    pending: Set[int] = set(ports)

    if family == socket.AF_INET:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    else:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)

    try:
        # Send SYN packets
        for port in ports:
            try:
                if family == socket.AF_INET:
                    packet = _build_syn_v4(src_ip, ip, src_port, port)
                else:
                    packet = _build_syn_v6(src_ip, ip, src_port, port)
                sock.sendto(packet, (ip, port))
            except OSError:
                pending.discard(port)
                results.append(
                    PortResult(port=port, state="filtered", service=_get_service(port))
                )

        # Receive responses
        deadline = time.monotonic() + timeout

        while pending and time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            try:
                readable, _, _ = select.select([sock], [], [], remaining)
            except (OSError, ValueError):
                break

            if not readable:
                continue

            try:
                data, addr = sock.recvfrom(1024)
            except OSError:
                continue

            if family == socket.AF_INET:
                # Received data = IP header + TCP header
                if len(data) < 40:
                    continue
                ihl = (data[0] & 0x0F) * 4
                if len(data) < ihl + 20:
                    continue
                # Verify source IP matches target
                if socket.inet_ntoa(data[12:16]) != ip:
                    continue
                tcp = data[ihl:]
            else:
                # IPv6 raw sockets deliver only the TCP segment
                if len(data) < 20:
                    continue
                if addr[0] != ip:
                    continue
                tcp = data

            resp_src_port = (tcp[0] << 8) | tcp[1]
            resp_dst_port = (tcp[2] << 8) | tcp[3]
            flags = tcp[13]

            if resp_dst_port != src_port:
                continue
            if resp_src_port not in pending:
                continue

            pending.discard(resp_src_port)

            if flags & _SYN and flags & _ACK:
                state = "open"
            elif flags & _RST:
                state = "closed"
            else:
                state = "filtered"

            results.append(
                PortResult(
                    port=resp_src_port, state=state, service=_get_service(resp_src_port)
                )
            )
    finally:
        sock.close()

    # No response within timeout -> filtered
    for port in pending:
        results.append(
            PortResult(port=port, state="filtered", service=_get_service(port))
        )

    return results


def nmap_syn(
    target: str,
    ports: Optional[str] = None,
    top_ports: Optional[int] = None,
    max_concurrent: int = MAX_CONCURRENT,
) -> NmapResult:
    """Perform an nmap-style TCP SYN scan."""
    try:
        ip = _resolve_host(target)
    except (socket.gaierror, ValueError) as e:
        return NmapResult(
            target=target, error=f"failed to resolve {target!r}: {e}"
        )

    family = _addr_family(ip)
    try:
        src_ip = _get_local_ip(ip, family)
    except OSError as e:
        return NmapResult(
            target=target, ip=ip, error=f"failed to determine local IP for {ip!r}: {e}"
        )

    src_port = random.randint(1024, 65535)

    # Determine port list
    if top_ports is not None:
        port_list = sorted(TOP_PORTS[:top_ports])
    elif ports is not None:
        try:
            port_list = _parse_ports(ports)
        except ValueError as e:
            return NmapResult(
                target=target, ip=ip, error=f"invalid port specification {ports!r}: {e}"
            )
    else:
        port_list = _parse_ports(DEFAULT_PORTS)

    start = time.perf_counter()
    results: List[PortResult] = []

    for i in range(0, len(port_list), max_concurrent):
        batch = port_list[i : i + max_concurrent]
        batch_results = _sync_scan_batch(ip, batch, DEFAULT_TIMEOUT, src_ip, src_port)
        results.extend(batch_results)

    elapsed = time.perf_counter() - start
    results.sort(key=lambda r: r.port)

    return NmapResult(
        target=target,
        ip=ip,
        ports=results,
        total_scanned=len(port_list),
        scan_time=elapsed,
    )


def nmap_syn_stream(
    target: str,
    ports: Optional[str] = None,
    top_ports: Optional[int] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_concurrent: int = MAX_CONCURRENT,
) -> Generator[str, None, None]:
    """Yield nmap SYN scan results as formatted strings."""
    port_desc = ports or f"top {top_ports} ports"
    yield (
        f"Starting SYN scan on {target} ({port_desc})"
        f" at {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
    )

    result = nmap_syn(
        target, ports=ports, top_ports=top_ports, max_concurrent=max_concurrent
    )

    if result.error:
        yield f"Error: {result.error}\n"
        return

    host_line = f"Nmap scan report for {result.target}"
    if result.target != result.ip:
        host_line += f" ({result.ip})"
    yield host_line + "\n"

    open_ports = result.open_ports
    filtered_ports = result.filtered_ports
    closed_count = result.closed_count
    filtered_count = result.filtered_count

    not_shown_parts: List[str] = []
    if closed_count > 0:
        not_shown_parts.append(f"{closed_count} closed")

    shown: List[PortResult] = sorted(open_ports + filtered_ports, key=lambda r: r.port)

    if not_shown_parts and shown:
        yield f"Not shown: {', '.join(not_shown_parts)}\n"

    if shown:
        yield "PORT     STATE    SERVICE\n"
        for r in shown:
            yield f"{r.port:<8} {r.state:<7} {r.service}\n"
    else:
        yield f"All {result.total_scanned} scanned ports are "
        if closed_count and not filtered_count:
            yield "closed"
        elif filtered_count and not closed_count:
            yield "filtered"
        else:
            yield f"closed ({closed_count}) or filtered ({filtered_count})"

    yield (
        f"\nNmap done: 1 IP address (1 host up) "
        f"scanned in {result.scan_time:.2f} seconds\n"
    )


if __name__ == "__main__":
    from .nmap_syn_cli import main

    main()
