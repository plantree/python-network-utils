"""nmap - A Python-based port scanner using raw sockets.

A Python reimplementation of nmap's TCP connect using non-blocking
sockets and `select()` for I/O multiplexing. Produces output similar
to namp.

Run with: python src/nmap.py <options> <host>

Example usage:
    $ python src/nmap.py scanme.nmap.org
    $ python src/nmap.py -p 22,80,443 example.com
    $ python src/nmap.py -p 1-1000 example.com
    $ python src/nmap.py --top-ports 100 example.com
"""

import errno
import select
import socket
import time
from dataclasses import dataclass, field
from typing import Dict, Generator, List, Optional, Set, Tuple

DEFAULT_TIMEOUT = 2.0  # seconds per connection attempt
DEFAULT_PORTS = "1-10000"  # default port range to scan
MAX_CONCURRENT = 256  # max sockets in flight at once

# Top 100 ports
TOP_PORTS = [
    80,
    23,
    443,
    21,
    22,
    25,
    3389,
    110,
    445,
    139,
    143,
    53,
    135,
    3306,
    8080,
    1723,
    111,
    995,
    993,
    5900,
    1025,
    587,
    8888,
    199,
    1720,
    465,
    548,
    113,
    81,
    6001,
    10000,
    514,
    5060,
    179,
    1026,
    2000,
    8443,
    8000,
    32768,
    554,
    26,
    1433,
    49152,
    2001,
    515,
    8008,
    49154,
    1027,
    5666,
    646,
    5000,
    5631,
    631,
    49153,
    8081,
    2049,
    88,
    79,
    5800,
    106,
    2121,
    1110,
    49155,
    6000,
    513,
    990,
    5357,
    427,
    49156,
    543,
    544,
    5101,
    144,
    7,
    389,
    8009,
    3128,
    444,
    9999,
    5009,
    7070,
    5190,
    3000,
    5432,
    1900,
    3986,
    13,
    1029,
    9,
    5051,
    6646,
    49157,
    1028,
    873,
    1755,
    2717,
    4899,
    9100,
    119,
    37,
]

# Well-known port -> service name
SERVICES: Dict[int, str] = {
    7: "echo",
    9: "discard",
    13: "daytime",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    37: "time",
    53: "domain",
    79: "finger",
    80: "http",
    81: "http-alt",
    88: "kerberos",
    106: "pop3pw",
    110: "pop3",
    111: "rpcbind",
    113: "ident",
    119: "nntp",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    144: "news",
    179: "bgp",
    199: "smux",
    389: "ldap",
    427: "svrloc",
    443: "https",
    444: "snpp",
    445: "microsoft-ds",
    465: "smtps",
    513: "login",
    514: "shell",
    515: "printer",
    543: "klogin",
    544: "kshell",
    548: "afp",
    554: "rtsp",
    587: "submission",
    631: "ipp",
    646: "ldp",
    873: "rsync",
    990: "ftps",
    993: "imaps",
    995: "pop3s",
    1025: "NFS-or-IIS",
    1026: "LSA-or-nterm",
    1027: "IIS",
    1028: "unknown",
    1029: "ms-lsa",
    1110: "nfsd-status",
    1433: "ms-sql-s",
    1720: "h323q931",
    1723: "pptp",
    1755: "wms",
    1900: "upnp",
    2000: "cisco-sccp",
    2001: "dc",
    2049: "nfs",
    2121: "ccproxy-ftp",
    2717: "pn-requester",
    3000: "ppp",
    3128: "squid-http",
    3306: "mysql",
    3389: "ms-wbt-server",
    3986: "mapper-ws",
    4899: "radmin",
    5000: "upnp",
    5009: "airport-admin",
    5051: "ida-agent",
    5060: "sip",
    5101: "admdog",
    5190: "aol",
    5357: "wsdapi",
    5432: "postgresql",
    5631: "pcanywheredata",
    5666: "nrpe",
    5800: "vnc-http",
    5900: "vnc",
    6000: "X11",
    6001: "X11:1",
    6646: "unknown",
    7070: "realserver",
    8000: "http-alt",
    8008: "http-alt",
    8009: "ajp13",
    8080: "http-proxy",
    8081: "blackice-icecap",
    8443: "https-alt",
    8888: "sun-answerbook",
    9100: "jetdirect",
    9999: "abyss",
    10000: "snet-sensor-mgmt",
    32768: "filenet-tms",
    49152: "unknown",
    49153: "unknown",
    49154: "unknown",
    49155: "unknown",
    49156: "unknown",
    49157: "unknown",
}


@dataclass
class PortResult:
    """Result for a single port scan."""

    port: int
    state: str  # "open", "closed", "filtered"
    service: str = ""


@dataclass
class NmapResult:
    """Result of a port scan."""

    target: str
    ip: str = ""
    ports: List[PortResult] = field(default_factory=list)
    total_scanned: int = 0
    scan_time: float = 0.0
    error: Optional[str] = None

    @property
    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def filtered_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state == "filtered"]

    @property
    def closed_count(self) -> int:
        return sum(1 for p in self.ports if p.state == "closed")

    @property
    def filtered_count(self) -> int:
        return sum(1 for p in self.ports if p.state == "filtered")


def _parse_ports(port_spec: str) -> List[int]:
    """Parse nmap-style port specification.

    Examples: `22`, `22,80`, `1-1000`
    """
    ports: Set[int] = set()
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start = int(start_str)
            end = int(end_str)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"invalid port: {p}")
            ports.add(p)
    return sorted(ports)


def _get_service(port: int) -> str:
    """Get service name for a port number."""
    return SERVICES.get(port, "unknown")


def _resolve_host(host: str) -> str:
    """Resolve hostname to IP address."""
    infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    if not infos:
        raise ValueError(f"could not resolve {host}")
    return str(infos[0][4][0])


def _addr_family(ip: str) -> socket.AddressFamily:
    """Return AF_INET or AF_INET6 for an IP address string."""
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return socket.AF_INET6
    except OSError:
        return socket.AF_INET


def _scan_batch(
    ip: str,
    ports: List[int],
    timeout: float,
) -> List[PortResult]:
    """Scan a batch of ports uings select() based multiplexing."""
    results: List[PortResult] = []
    # fd -> (socket, port)
    pending: Dict[int, Tuple[socket.socket, int]] = {}
    family = _addr_family(ip)

    for port in ports:
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.setblocking(False)
            err = sock.connect_ex((ip, port))
            if err == 0:
                # Immediate success (rara for non-blocking)
                results.append(
                    PortResult(port=port, state="open", service=_get_service(port))
                )
                sock.close()
            elif err in (
                errno.EINPROGRESS,
                errno.EWOULDBLOCK,
                errno.EAGAIN,
            ):
                pending[sock.fileno()] = (sock, port)
            else:
                results.append(
                    PortResult(port=port, state="closed", service=_get_service(port))
                )
                sock.close()
        except OSError:
            results.append(
                PortResult(port=port, state="filtered", service=_get_service(port))
            )

    if not pending:
        return results

    deadline = time.monotonic() + timeout

    while pending and time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break

        sock_list = [s for s, _ in pending.values()]
        try:
            _, writable, errored = select.select(
                [], sock_list, sock_list, min(remaining, 0.5)
            )
        except (OSError, ValueError):
            break

        # Sockets that completed (success or error)
        ready: Set[int] = set()
        for sock in writable:
            ready.add(sock.fileno())
        for sock in errored:
            ready.add(sock.fileno())

        for fd in ready:
            if fd not in pending:
                continue
            sock, port = pending.pop(fd)
            err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err == 0:
                results.append(
                    PortResult(port=port, state="open", service=_get_service(port))
                )
            elif err == errno.ECONNREFUSED:
                results.append(
                    PortResult(port=port, state="closed", service=_get_service(port))
                )
            else:
                results.append(
                    PortResult(port=port, state="filtered", service=_get_service(port))
                )
            sock.close()
    # Remaining sockets timed out -> filtered
    for _, (sock, port) in pending.items():
        results.append(
            PortResult(port=port, state="filtered", service=_get_service(port))
        )
        sock.close()

    return results


def nmap(
    target: str,
    ports: Optional[str] = None,
    top_ports: Optional[int] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_concurrent: int = MAX_CONCURRENT,
) -> NmapResult:
    """Perform nmap-style TCP connect scan."""
    # Resolve target
    try:
        ip = _resolve_host(target)
    except (socket.gaierror, ValueError) as e:
        return NmapResult(target=target, error=f"failed to resolve {target!r}: {e}")

    # Determine port list
    if top_ports is not None:
        port_list = sorted(TOP_PORTS[:top_ports])
    elif ports is not None:
        try:
            port_list = _parse_ports(ports)
        except ValueError as e:
            return NmapResult(
                target=target, ip=ip, error=f"invalid port specification: {e}"
            )
    else:
        port_list = _parse_ports(DEFAULT_PORTS)

    start = time.perf_counter()
    all_results: List[PortResult] = []

    # Scan in batches to respect file descriptor limits
    for i in range(0, len(port_list), max_concurrent):
        batch_ports = port_list[i : i + max_concurrent]
        batch_results = _scan_batch(ip, batch_ports, timeout)
        all_results.extend(batch_results)

    end = time.perf_counter()

    # Sort by port number
    all_results.sort(key=lambda r: r.port)

    return NmapResult(
        target=target,
        ip=ip,
        ports=all_results,
        total_scanned=len(port_list),
        scan_time=end - start,
    )


def nmap_stream(
    target: str,
    ports: Optional[str] = None,
    top_ports: Optional[int] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_concurrent: int = MAX_CONCURRENT,
) -> Generator[str, None, None]:
    """nmap_stream version of nmap() that yields output lines as they are ready."""
    yield f"Starting Nmap scan at {time.strftime('%Y-%m-%d %H:%M:%S')}\n"

    result = nmap(
        target=target,
        ports=ports,
        top_ports=top_ports,
        timeout=timeout,
        max_concurrent=max_concurrent,
    )

    if result.error:
        yield f"Error: {result.error}\n"
        return

    # Host info
    host_line = f"Nmap scan report for {result.target}"
    if result.target != result.ip:
        host_line += f" ({result.ip})"
    yield host_line + "\n"

    open_ports = result.open_ports
    filtered_ports = result.filtered_ports
    closed = result.closed_count
    filtered = result.filtered_count

    # "Not shown" summary for non-open ports
    not_shown_parts: List[str] = []
    if closed:
        not_shown_parts.append(f"{closed} closed")

    shown_parts: List[PortResult] = []
    if open_ports:
        shown_parts.extend(open_ports)
    if filtered_ports:
        shown_parts.extend(filtered_ports)
    shown_parts = sorted(shown_parts, key=lambda p: p.port)

    if not_shown_parts and open_ports:
        yield f"Not shown: {', '.join(not_shown_parts)} ports\n"

    if shown_parts:
        yield "PORT     STATE SERVICE\n"
        for port_result in shown_parts:
            port_str = f"{port_result.port}/tcp"
            yield f"{port_str:<9} {port_result.state:<6} {port_result.service}\n"
    else:
        yield f"All {result.total_scanned} scanned ports are "
        if closed and not filtered:
            yield "closed.\n"
        elif filtered and not closed:
            yield "filtered.\n"
        else:
            yield f"closed ({closed}) or filtered ({filtered}).\n"

    yield (
        f"\nNmap done: 1 IP address (1 host up) scanned in {result.scan_time:.2f} seconds\n"
    )


if __name__ == "__main__":
    from nmap_cli import main

    main()
