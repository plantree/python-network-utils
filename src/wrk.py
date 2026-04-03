"""wrk - A python-based HTTP benchmarking tool using raw sockets.

A Python reimplementation of wrk (https://github.com/wg/wrk) using raw TCP
sockets and the ``ssl`` module.  Produces output identical to wrk.

Run with: python -m src.wrk <options> <url>
Or: .venv/bin/netwrk <options> <url>

Example usage:
    $ netwrk http://example.com
    $ netwrk -t4 -c100 -d10s http://localhost:8080
"""

import re
import select
import socket
import ssl
import threading
import time

# Constants
from dataclasses import dataclass, field
from typing import Dict, Generator, List, Optional, Tuple
from urllib.parse import urlparse

HTTP_PORT = 80
HTTPS_PORT = 443
RECV_CHUNK_SIZE = 4096
DEFAULT_THREADS = 2
DEFAULT_CONNECTIONS = 10
DEFAULT_DURATION = 10.0  # seconds
DEFAULT_TIMEOUT = 2.0  # per-request socket
USER_AGENT = "netwrk/1.0"


@dataclass
class WrkResult:
    """Result of an HTTP benchmakr run."""

    url: str
    duration: float = 0.0
    threads: int = 0
    connections: int = 0
    total_requests: int = 0
    total_bytes: int = 0
    total_errors: int = 0
    connect_errors: int = 0
    read_errors: int = 0
    write_errors: int = 0
    timeout_errors: int = 0
    status_errors: int = 0
    latencies: List[float] = field(default_factory=list)
    req_sec_per_thread: List[float] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def requests_per_sec(self) -> float:
        """Overall requests/sec."""
        if self.duration > 0:
            return self.total_requests / self.duration
        return 0.0

    @property
    def transfer_per_sec(self) -> float:
        """Bytes transferred per second."""
        if self.duration > 0:
            return self.total_bytes / self.duration
        return 0.0


# URL / connection helpers
def _parse_url(url: str) -> Tuple[str, str, int, str]:
    """Parse a URL into (scheme, host, port, path)."""
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url

    parsed = urlparse(url)
    schema = parsed.scheme.lower()
    host = parsed.hostname or ""
    port = parsed.port or (HTTPS_PORT if schema == "https" else HTTP_PORT)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return schema, host, port, path


def _parse_duration(duration_str: str) -> float:
    """Parse a duration string like '10s', '1m', '500ms' into seconds."""
    value = duration_str.strip().lower()
    match = re.match(r"^(\d+(?:\.\d+)?)(ms|s|m|h)?$", value)
    if not match:
        raise ValueError(f"invalid duration: {duration_str!r}")
    num = float(match.group(1))
    unit = match.group(2) or "s"
    if unit == "ms":
        num /= 1000
    elif unit == "m":
        num *= 60
    elif unit == "h":
        num *= 3600
    return num


def _create_connection(
    host: str,
    port: int,
    schema: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> socket.socket:
    """Create a TCP (or TLS-wrapped) socket connection."""
    addr_infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    if not addr_infos:
        raise ConnectionError(f"Could not resolve {host}:{port}")

    family, socktype, proto, _, sockaddr = addr_infos[0]
    sock = socket.socket(family, socktype, proto)
    sock.settimeout(timeout)
    sock.connect(sockaddr)

    if schema == "https":
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=host)

    return sock


def _build_request(
    host: str, port: int, path: str, headers: Optional[Dict[str, str]] = None
) -> bytes:
    """Build a minimal HTTP/1.1 GET request with keep-alive."""
    host_hdr = host if port in (HTTP_PORT, HTTPS_PORT) else f"{host}:{port}"
    req_headers: Dict[str, str] = {
        "Host": host_hdr,
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Connection": "keep-alive",
    }
    if headers:
        for k, v in headers.items():
            matched = False
            for existing in list(req_headers.keys()):
                if existing.lower() == k.lower():
                    req_headers[existing] = v
                    matched = True
                    break
            if not matched:
                req_headers[k] = v

    request_line = f"GET {path} HTTP/1.1\r\n"
    header_lines = "".join(f"{k}: {v}\r\n" for k, v in req_headers.items())
    return (request_line + header_lines + "\r\n").encode("utf-8")


def _recv_response(sock: socket.socket) -> Tuple[int, int]:
    """Read one HTTP response, return (status_code, bytes_received)."""
    buf = b""
    total_bytes = 0

    # Read until we get the full headers
    while True:
        try:
            chunk = sock.recv(RECV_CHUNK_SIZE)
        except (socket.timeout, TimeoutError, OSError):
            return -1, total_bytes
        if not chunk:
            return -1, total_bytes

        buf += chunk
        total_bytes += len(chunk)
        header_end = buf.find(b"\r\n\r\n")
        if header_end != -1:
            break
        header_end_lf = buf.find(b"\n\n")
        if header_end_lf != -1:
            header_end = header_end_lf
            break

    # Parse status code from first line
    sep = b"\r\n\r\n"
    header_end = buf.find(sep)
    if header_end == -1:
        sep = b"\n\n"
        header_end = buf.find(sep)
    head_bytes = buf[:header_end]
    body_start = header_end + len(sep)
    leftover = buf[body_start:]

    head_text = head_bytes.decode("iso-8859-1", errors="replace")
    lines = head_text.split("\r\n") if "\r\n" in head_text else head_text.split("\n")
    status_line = lines[0] if lines else ""
    parts = status_line.split(None, 2)
    status_code = 0
    if len(parts) >= 2:
        try:
            status_code = int(parts[1])
        except ValueError:
            pass

    # Parse headers (case-insensitive)
    headers_lower: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers_lower[k.strip().lower()] = v.strip()

    # Determine body length
    transfer_encoding = headers_lower.get("transfer-encoding", "").lower()
    content_length_str = headers_lower.get("content-length")
    connection = headers_lower.get("connection", "").lower()

    if "chunked" in transfer_encoding:
        # Read chunked body
        body_buf = leftover
        while True:
            eol = body_buf.find(b"\r\n")
            if eol == -1:
                try:
                    more = sock.recv(RECV_CHUNK_SIZE)
                except (socket.timeout, TimeoutError, OSError):
                    break
                if not more:
                    break
                body_buf += more
                continue
            size_str = body_buf[:eol].decode("ascii", errors="replace").strip()
            size_str = size_str.split(";", 1)[0]
            try:
                chunk_size = int(size_str, 16)
            except ValueError:
                break
            if chunk_size == 0:
                break
            needed = eol + 2 + chunk_size + 2  # size line + CRLF + chunk + CRLF
            while len(body_buf) < needed:
                try:
                    more = sock.recv(RECV_CHUNK_SIZE)
                except (socket.timeout, TimeoutError, OSError):
                    break
                if not more:
                    break
                body_buf += more
            body_buf = body_buf[needed:]
    elif content_length_str:
        try:
            content_length = int(content_length_str)
        except ValueError:
            content_length = 0
        remaining = content_length - len(leftover)
        while remaining > 0:
            try:
                chunk = sock.recv(min(RECV_CHUNK_SIZE, remaining))
            except (socket.timeout, TimeoutError, OSError):
                break
            if not chunk:
                break
            total_bytes += len(chunk)
            remaining -= len(chunk)
    elif connection == "close":
        # Read until socket closes
        while True:
            try:
                chunk = sock.recv(RECV_CHUNK_SIZE)
            except (socket.timeout, TimeoutError, OSError):
                break
            if not chunk:
                break
            total_bytes += len(chunk)

    return status_code, total_bytes


# Workder thread
@dataclass
class _ThreadResult:
    """Aggregate result for one worker thread."""

    requests: int = 0
    bytes_read: int = 0
    errors: int = 0
    connect_errors: int = 0
    read_errors: int = 0
    write_errors: int = 0
    timeout_errors: int = 0
    status_errors: int = 0
    latencies: List[float] = field(default_factory=list)


@dataclass
class _Conn:
    """Per-connection state for select-based I/O multiplexing."""

    sock: socket.socket
    phase: str  # 'send' or 'recv'
    send_buf: bytes = b""
    send_off: int = 0
    recv_buf: bytearray = field(default_factory=bytearray)
    req_start: float = 0.0


def _try_parse_response(buf: bytes) -> Optional[Tuple[int, int]]:
    """Try to parse a complete HTTP response from *buf*.

    Returns ``(status_code, consumed_bytes)`` when a complete response is
    available, or ``None`` if more data is needed.
    """
    hdr_end = buf.find(b"\r\n\r\n")
    sep_len = 4
    if hdr_end == -1:
        hdr_end = buf.find(b"\n\n")
        sep_len = 2
    if hdr_end == -1:
        return None

    body_start = hdr_end + sep_len
    head = buf[:hdr_end].decode("iso-8859-1", errors="replace")
    lines = head.split("\r\n") if "\r\n" in head else head.split("\n")

    status_code = 0
    parts = (lines[0] if lines else "").split(None, 2)
    if len(parts) >= 2:
        try:
            status_code = int(parts[1])
        except ValueError:
            pass

    hdrs: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()

    te = hdrs.get("transfer-encoding", "").lower()
    cl_str = hdrs.get("content-length")

    if "chunked" in te:
        pos = body_start
        while True:
            eol = buf.find(b"\r\n", pos)
            if eol == -1:
                return None
            size_s = buf[pos:eol].decode("ascii", errors="replace").strip()
            size_s = size_s.split(";", 1)[0]
            try:
                csz = int(size_s, 16)
            except ValueError:
                return None
            if csz == 0:
                consumed = eol + 4  # "0\r\n" + "\r\n"
                if len(buf) < consumed:
                    return None
                return (status_code, consumed)
            data_end = eol + 2 + csz + 2
            if len(buf) < data_end:
                return None
            pos = data_end
    elif cl_str:
        try:
            cl = int(cl_str)
        except ValueError:
            cl = 0
        needed = body_start + cl
        if len(buf) < needed:
            return None
        return (status_code, needed)
    else:
        # No body length indicator — assume empty body (keep-alive).
        return (status_code, body_start)


def _worker(
    schema: str,
    host: str,
    port: int,
    path: str,
    request_bytes: bytes,
    num_connections: int,
    duration: float,
    timeout: float,
    result: _ThreadResult,
) -> None:
    """Worker using select() to multiplex connections on one thread."""
    deadline = time.monotonic() + duration
    conns: List[_Conn] = []

    # Establish initial connections (blocking connect, then non-blocking I/O)
    for _ in range(num_connections):
        try:
            sock = _create_connection(host, port, schema, timeout)
            sock.setblocking(False)
            conns.append(
                _Conn(
                    sock=sock,
                    phase="send",
                    send_buf=request_bytes,
                    send_off=0,
                    req_start=time.perf_counter(),
                )
            )
        except (socket.timeout, TimeoutError):
            result.timeout_errors += 1
            result.connect_errors += 1
            result.errors += 1
        except OSError:
            result.connect_errors += 1
            result.errors += 1

    while conns and time.monotonic() < deadline:
        rlist: List[socket.socket] = []
        wlist: List[socket.socket] = []
        for c in conns:
            if c.phase == "send":
                wlist.append(c.sock)
            else:
                rlist.append(c.sock)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break

        try:
            readable, writable, _ = select.select(
                rlist,
                wlist,
                [],
                min(remaining, 0.5),
            )
        except (OSError, ValueError):
            break

        # SSL may buffer data internally; select() won't see it.
        for c in conns:
            if (
                c.phase == "recv"
                and isinstance(c.sock, ssl.SSLSocket)
                and c.sock.pending() > 0
                and c.sock not in readable
            ):
                readable.append(c.sock)

        sock_map = {id(c.sock): c for c in conns}
        dead: List[_Conn] = []

        # --- send path ---
        for sock in writable:
            c_opt = sock_map.get(id(sock))
            if c_opt is None or c_opt in dead:
                continue
            c = c_opt
            try:
                sent = sock.send(c.send_buf[c.send_off :])
                c.send_off += sent
                if c.send_off >= len(c.send_buf):
                    c.phase = "recv"
                    c.recv_buf = bytearray()
            except (BlockingIOError, ssl.SSLWantWriteError, ssl.SSLWantReadError):
                pass
            except (socket.timeout, TimeoutError):
                result.timeout_errors += 1
                result.write_errors += 1
                result.errors += 1
                _safe_close(sock)
                dead.append(c)
            except OSError:
                result.write_errors += 1
                result.errors += 1
                _safe_close(sock)
                dead.append(c)

        # --- recv path ---
        for sock in readable:
            c_opt = sock_map.get(id(sock))
            if c_opt is None or c_opt in dead:
                continue
            c = c_opt
            try:
                data = sock.recv(RECV_CHUNK_SIZE)
            except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                continue
            except (socket.timeout, TimeoutError):
                result.timeout_errors += 1
                result.read_errors += 1
                result.errors += 1
                _safe_close(sock)
                dead.append(c)
                continue
            except OSError:
                result.read_errors += 1
                result.errors += 1
                _safe_close(sock)
                dead.append(c)
                continue

            if not data:
                # Peer closed the connection
                result.read_errors += 1
                result.errors += 1
                _safe_close(sock)
                dead.append(c)
                continue

            c.recv_buf.extend(data)

            parsed = _try_parse_response(bytes(c.recv_buf))
            if parsed is not None:
                status_code, consumed = parsed
                elapsed = time.perf_counter() - c.req_start
                result.requests += 1
                result.bytes_read += consumed
                result.latencies.append(elapsed * 1000)
                if status_code >= 400:
                    result.status_errors += 1
                # Reuse connection (keep-alive): prepare next request
                leftover = c.recv_buf[consumed:]
                c.phase = "send"
                c.send_buf = request_bytes
                c.send_off = 0
                c.recv_buf = bytearray(leftover)
                c.req_start = time.perf_counter()

        # Replace dead connections
        if dead:
            for c in dead:
                conns.remove(c)
            for _ in dead:
                if time.monotonic() >= deadline:
                    break
                try:
                    sock = _create_connection(host, port, schema, timeout)
                    sock.setblocking(False)
                    conns.append(
                        _Conn(
                            sock=sock,
                            phase="send",
                            send_buf=request_bytes,
                            send_off=0,
                            req_start=time.perf_counter(),
                        )
                    )
                except (socket.timeout, TimeoutError):
                    result.timeout_errors += 1
                    result.connect_errors += 1
                    result.errors += 1
                except OSError:
                    result.connect_errors += 1
                    result.errors += 1

    # Clean up
    for c in conns:
        _safe_close(c.sock)


def _safe_close(sock: socket.socket) -> None:
    """Close a socket, ignoring errors."""
    try:
        sock.close()
    except OSError:
        pass


def _mean(value: List[float]) -> float:
    """Calculate mean of a list of floats."""
    if not value:
        return 0.0
    return sum(value) / len(value)


def _stdev(value: List[float]) -> float:
    """Calculate standard deviation of a list of floats."""
    if not value:
        return 0.0
    mean = _mean(value)
    variance = sum((x - mean) ** 2 for x in value) / len(value)
    return float(variance**0.5)


def _percentile(sorted_values: List[float], percentile: float) -> float:
    """Calculate a percentile from a sorted list of floats."""
    if not sorted_values:
        return 0.0
    idx = (percentile / 100) * (len(sorted_values) - 1)
    lo = int(idx)
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = idx - lo
    return sorted_values[lo] + frac * (sorted_values[hi] - sorted_values[lo])


def _within_stdev(values: List[float]) -> float:
    """Percentage of values within +/- 1 standard deviation."""
    if not values:
        return 0.0
    mean = _mean(values)
    stdev = _stdev(values)
    if stdev == 0:
        return 100.0
    count = sum(1 for v in values if mean - stdev <= v <= mean + stdev)
    return (count / len(values)) * 100


def _format_time(ms: float) -> str:
    """Format milliseconds as a wrk-style time."""
    if ms < 1.0:
        return f"{ms * 1000:.2f}us"
    if ms < 1000.0:
        return f"{ms:.2f}ms"
    if ms < 60000.0:
        return f"{ms / 1000:.2f}s"
    return f"{ms / 60000:.2f}m"


def _format_count(n: float) -> str:
    """Format a number into wrk-style compact format."""
    if n < 1000.0:
        return f"{n:.2f}"
    if n < 1_000_000.0:
        return f"{n / 1000:.2f}k"
    return f"{n / 1_000_000:.2f}M"


def _format_bytes(b: float) -> str:
    """Format bytes into human-readable wrk-style."""
    if b < 1024.0:
        return f"{b:.2f}B"
    if b < 1024.0**2:
        return f"{b / 1024:.2f}KB"
    if b < 1024.0**3:
        return f"{b / (1024 ** 2):.2f}MB"
    return f"{b / (1024 ** 3):.2f}GB"


def _format_duration(seconds: float) -> str:
    """Format seconds into wrk-style duration string."""
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes = int(seconds // 60)
    secs = seconds - minutes * 60
    return f"{minutes}m{secs:.2f}s"


def wrk(
    url: str,
    threads: int = DEFAULT_THREADS,
    connections: int = DEFAULT_CONNECTIONS,
    duration: float = DEFAULT_DURATION,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
) -> WrkResult:
    """Run a wrk benchmark and return the result."""
    schema, host, port, path = _parse_url(url)
    request_bytes = _build_request(host, port, path, headers)

    # Distribute connections across threads
    base_conns = connections // threads
    extra_conns = connections % threads
    thread_conns = [base_conns + (1 if i < extra_conns else 0) for i in range(threads)]

    # Launch worker threads
    thread_results: List[_ThreadResult] = []
    workers: List[threading.Thread] = []
    for i in range(threads):
        tr = _ThreadResult()
        thread_results.append(tr)
        t = threading.Thread(
            target=_worker,
            args=(
                schema,
                host,
                port,
                path,
                request_bytes,
                thread_conns[i],
                duration,
                timeout,
                tr,
            ),
            daemon=True,
        )
        workers.append(t)

    start = time.perf_counter()
    for t in workers:
        t.start()
    for t in workers:
        t.join()
    actual_duration = time.perf_counter() - start

    # Aggregate results
    result = WrkResult(
        url=url,
        duration=actual_duration,
        threads=threads,
        connections=connections,
    )

    all_latencies: List[float] = []
    all_req_sec: List[float] = []

    for tr in thread_results:
        result.total_requests += tr.requests
        result.total_bytes += tr.bytes_read
        result.total_errors += tr.errors
        result.connect_errors += tr.connect_errors
        result.read_errors += tr.read_errors
        result.write_errors += tr.write_errors
        result.timeout_errors += tr.timeout_errors
        result.status_errors += tr.status_errors
        all_latencies.extend(tr.latencies)
        all_req_sec.append(tr.requests / actual_duration)

    result.latencies = all_latencies
    result.req_sec_per_thread = all_req_sec

    return result


def wrk_stream(
    url: str,
    threads: int = DEFAULT_THREADS,
    connections: int = DEFAULT_CONNECTIONS,
    duration: float = DEFAULT_DURATION,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
    latency: bool = False,
) -> Generator[str, None, None]:
    """Yield lines of wrk-compatible output while running the benchmark."""
    yield f"Running {_format_duration(duration)} @ {url}\n"
    yield f"  {threads} threads and {connections} connections\n"

    result = wrk(url, threads, connections, duration, timeout, headers)

    if result.error:
        yield f"    Error: {result.error}\n"
        return

    # Thread stats table
    lat = result.latencies
    lat_sorted = sorted(lat)
    rps = result.req_sec_per_thread

    lat_avg = _mean(lat)
    lat_std = _stdev(lat)
    lat_max = max(lat) if lat else 0.0
    lat_within = _within_stdev(lat)

    rps_avg = _mean(rps)
    rps_std = _stdev(rps)
    rps_max = max(rps) if rps else 0.0
    rps_within = _within_stdev(rps)

    yield " Thread Stats  Avg      Stdev     Max      +/- Stdev\n"
    yield (
        f"   Latency   {_format_time(lat_avg):>8} {_format_time(lat_std):>8} "
        f"{_format_time(lat_max):>8} {lat_within:>7.2f}%\n"
    )
    yield (
        f"   Req/Sec   {_format_count(rps_avg):>8} {_format_count(rps_std):>8} "
        f"{_format_count(rps_max):>8} {rps_within:>7.2f}%\n"
    )

    # Latency distribution
    if latency and lat_sorted:
        yield "\nLatency Distribution\n"
        for p in [50, 75, 90, 99, 99.9]:
            val = _percentile(lat_sorted, p)
            yield f"  {p:>5g}%  {_format_time(val)}\n"

    # Summary
    yield f"\n  {result.total_requests} requests in {_format_duration(result.duration)}, "
    yield f"{_format_bytes(result.total_bytes)} read\n"

    # Error summary (only if there're errors)
    has_errors = (
        result.connect_errors
        or result.read_errors
        or result.write_errors
        or result.timeout_errors
    )
    if has_errors:
        yield "  Socket errors: "
        if result.connect_errors:
            yield f"{result.connect_errors} connect "
        if result.read_errors:
            yield f"{result.read_errors} read "
        if result.write_errors:
            yield f"{result.write_errors} write "
        if result.timeout_errors:
            yield f"{result.timeout_errors} timeout "
        yield "\n"
    if result.status_errors:
        yield f"  Non-2xx or 3xx responses: {result.status_errors}\n"

    yield f"Requests/sec: {_format_count(result.requests_per_sec)}\n"
    yield f"Transfer/sec: {_format_bytes(result.transfer_per_sec)}\n"


if __name__ == "__main__":
    from .wrk_cli import main

    main()
