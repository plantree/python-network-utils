"""curl - Transfer data from a URL using raw sockets.

A Python reimplementation of curl-like functionality using raw TCP sockets and
the `ssl` module for HTTPS support.

Run with: python -m src.curl <URL>
Or: .venv/bin/netcurl <URL>

Example usage:
    $ netcurl http://example.com
    $ netcurl -X POST -d "name=John" https://example.com/api
    $ netcurl -H "Authorization: Bearer TOKEN" https://example.com/secure
    $ netcurl -I https://example.com
    $ netcurl -L http://example.com/redirect
    $ netcurl -v https://example.com
"""

import gzip
import re
import socket
import ssl
import time
import zlib

# Default configuration
from dataclasses import dataclass, field
from typing import Dict, Generator, List, Optional, Tuple
from urllib.parse import urlparse

DEFAULT_TIMEOUT = 30
DEFAULT_USER_AGENT = "netcurl/1.0"
MAX_REDIRECTS = 5
HTTP_PORT = 80
HTTPS_PORT = 443
RECV_CHUNK_SIZE = 4096


@dataclass
class CurlResult:
    """Result of a curl request."""

    url: str
    effective_url: str
    method: str
    http_version: str = "HTTP/1.1"
    status_code: int = 0
    reason: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    elapsed_ms: float = 0.0
    redirect_count: int = 0
    remote_ip: str = ""
    remote_port: int = 0
    error: Optional[str] = None


def _parse_url(url: str) -> Tuple[str, str, int, str]:
    """Parse a URL into (scheme, host, port, path)."""
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url  # Default to http if no scheme provided

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    port = parsed.port or (HTTPS_PORT if scheme == "https" else HTTP_PORT)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    if parsed.fragment:
        path += "#" + parsed.fragment
    return scheme, host, port, path


def _build_request(
    method: str,
    host: str,
    port: int,
    path: str,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[str] = None,
) -> Tuple[bytes, Dict[str, str]]:
    """Build a raw HTTP request."""
    req_headers: Dict[str, str] = {
        "Host": host if port in (HTTP_PORT, HTTPS_PORT) else f"{host}:{port}",
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    }
    if headers:
        for k, v in headers.items():
            # Use case-insensitive matching for overrides
            matched = False
            for existing in list(req_headers.keys()):
                if existing.lower() == k.lower():
                    req_headers[existing] = v
                    matched = True
                    break
            if not matched:
                req_headers[k] = v

    if data is not None:
        body_bytes = data.encode("utf-8")
        req_headers["Content-Length"] = str(len(body_bytes))
        if "Content-Type" not in req_headers:
            ct_match = False
            for k in req_headers.keys():
                if k.lower() == "content-type":
                    ct_match = True
                    break
            if not ct_match:
                req_headers["Content-Type"] = "application/x-www-form-urlencoded"
    else:
        body_bytes = b""

    # Build request line
    request_line = f"{method.upper()} {path} HTTP/1.1\r\n"
    header_lines = "".join(f"{k}: {v}\r\n" for k, v in req_headers.items())
    raw = (request_line + header_lines + "\r\n").encode("utf-8") + body_bytes

    return raw, req_headers


def _create_connection(
    host: str,
    port: int,
    scheme: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> Tuple[socket.socket, str]:
    """Crreate a TCP (or TLS-wrapped) socket connection."""
    addr_infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    if not addr_infos:
        raise ConnectionError(f"Could not resolve host: {host}")

    family, socktype, proto, _, sockaddr = addr_infos[0]
    remote_ip = str(sockaddr[0])

    sock = socket.socket(family, socktype, proto)
    sock.settimeout(timeout)
    sock.connect(sockaddr)

    if scheme == "https":
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=host)

    return sock, remote_ip


def _recv_response(sock: socket.socket) -> bytes:
    """Read the full HTTP response from the socket."""
    chunks: List[bytes] = []

    while True:
        try:
            chunk = sock.recv(RECV_CHUNK_SIZE)
            if not chunk:
                break
            chunks.append(chunk)
        except (socket.timeout, TimeoutError):
            break
        except OSError:
            break

    return b"".join(chunks)


def _parse_response_head(raw: bytes) -> Tuple[str, int, str, Dict[str, str], bytes]:
    """Parse the HTTP response status line, headers, and separate body."""
    # Split headers and body
    sep = raw.find(b"\r\n\r\n")
    if sep == -1:
        sep = raw.find(b"\n\n")
        head_end = sep + 2 if sep != -1 else len(raw)
        head_bytes = raw[:sep] if sep != -1 else raw
    else:
        head_end = sep + 4
        head_bytes = raw[:sep]

    body = raw[head_end:]
    head_text = head_bytes.decode("iso-8859-1")  # HTTP headers are iso-8859-1
    lines = head_text.split("\r\n") if "\r\n" in head_text else head_text.split("\n")

    # Status line
    status_line = lines[0] if lines else ""
    parts = status_line.split(None, 2)
    http_version = parts[0] if len(parts) > 0 else "HTTP/1.1"
    status_code = int(parts[1]) if len(parts) > 1 else 0
    reason = parts[2] if len(parts) > 2 else ""

    # Headers
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    return http_version, status_code, reason, headers, body


def _decode_body(
    body: bytes,
    headers: Dict[str, str],
) -> bytes:
    """Handle chunked transfer encoding and content encoding."""
    # Handle chunked transfer encoding
    te = ""
    for k, v in headers.items():
        if k.lower() == "transfer-encoding":
            te = v.lower()
            break

    if "chunked" in te:
        body = _decode_chunked(body)

    # Handle content encoding (gzip, deflate)
    ce = ""
    for k, v in headers.items():
        if k.lower() == "content-encoding":
            ce = v.lower()
            break

    if "gzip" in ce:
        try:
            body = gzip.decompress(body)
        except Exception:
            pass  # If decompression fails, return raw body
    elif "deflate" in ce:
        try:
            body = zlib.decompress(body)
        except Exception:
            try:
                body = zlib.decompress(body, -zlib.MAX_WBITS)
            except Exception:
                pass  # If decompression fails, return raw body

    return body


def _decode_chunked(body: bytes) -> bytes:
    """Decode chunked transter-encoded body."""
    result: List[bytes] = []
    idx = 0
    while idx < len(body):
        # Find the end of the chunk-size line
        eol = body.find(b"\r\n", idx)
        if eol == -1:
            break
        size_str = body[idx:eol].decode("ascii").strip()
        if not size_str:
            idx = eol + 2
            continue
        # strip chunk extensions after ';'
        size_str = size_str.split(";", 1)[0]
        try:
            size = int(size_str, 16)
        except ValueError:
            break
        if size == 0:
            break
        chunk_start = eol + 2
        chunk_end = chunk_start + size
        if chunk_end > len(body):
            result.append(body[chunk_start:])
            break
        result.append(body[chunk_start:chunk_end])
        # skip trailing CRLF after chunk
        idx = chunk_end + 2
    return b"".join(result)


def _get_header(headers: Dict[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup."""
    name_lower = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lower:
            return v
    return None


def curl(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    follow_redirects: bool = False,
    max_redirects: int = MAX_REDIRECTS,
) -> CurlResult:
    """Perform a curl-like HTTP request and return a CurlResult dataclass."""
    original_url = url
    current_url = url
    redirect_count = 0

    while True:
        schema, host, port, path = _parse_url(current_url)
        raw_request, send_headers = _build_request(
            method, host, port, path, headers, data
        )

        start = time.perf_counter()
        try:
            sock, remote_ip = _create_connection(host, port, schema, timeout)
        except Exception as e:
            return CurlResult(
                url=original_url,
                effective_url=current_url,
                method=method,
                error=str(e),
            )

        try:
            sock.sendall(raw_request)
            raw_response = _recv_response(sock)
        except Exception as e:
            return CurlResult(
                url=original_url,
                effective_url=current_url,
                method=method,
                remote_ip=remote_ip,
                remote_port=port,
                error=str(e),
            )
        finally:
            sock.close()

        elapsed = time.perf_counter() - start

        http_version, status_code, reason, recv_headers, body = _parse_response_head(
            raw_response
        )
        body = _decode_body(body, recv_headers)

        # Handle redirects if needed
        if (
            follow_redirects
            and 300 <= status_code < 400
            and redirect_count < max_redirects
        ):
            location = _get_header(recv_headers, "Location")
            if location:
                redirect_count += 1
                # Handle relative redirects
                if location.startswith("/"):
                    base = f"{schema}://{host}"
                    if port not in (HTTP_PORT, HTTPS_PORT):
                        base += f":{port}"
                    location = base + location
                elif not re.match(r"^https?://", location, re.IGNORECASE):
                    base = f"{schema}://{host}"
                    if port not in (HTTP_PORT, HTTPS_PORT):
                        base += f":{port}"
                    location = base + "/" + location
                current_url = location
                # POST -> GET on 301/302/303
                if status_code in (301, 302, 303):
                    method = "GET"
                    data = None
                continue

        return CurlResult(
            url=original_url,
            effective_url=current_url,
            method=method,
            http_version=http_version,
            status_code=status_code,
            reason=reason,
            request_headers=send_headers,
            response_headers=recv_headers,
            body=body,
            elapsed_ms=elapsed * 1000,
            redirect_count=redirect_count,
            remote_ip=remote_ip,
            remote_port=port,
        )


def curl_stream(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    head_only: bool = False,
    include_headers: bool = False,
    verbose: bool = False,
    follow_redirects: bool = False,
) -> Generator[str, None, None]:
    """Yield lines of output from a curl-like request, including verbose and header lines.

    Args:
        url: The URL to request.
        method: HTTP method to use (default "GET").
        headers: Optional dict of additional headers to include.
        data: Optional string data to send in the request body.
        timeout: Timeout in seconds for the request.
        head_only: If True, only output response headers (like curl -I).
        include_headers: If True, include response headers in the output.
        verbose: If True, include verbose output lines (e.g. connection info).
        follow_redirects: If True, automatically follow HTTP redirects.
    """
    effective_method = "HEAD" if head_only else method

    result = curl(
        url,
        method=effective_method,
        headers=headers,
        data=data,
        timeout=timeout,
        follow_redirects=follow_redirects,
    )

    if result.error:
        yield f"curl: ({_error_code(result.error)} {result.error})\n"
        return

    # Verbose: request headers
    if verbose:
        schema, host, port, path = _parse_url(result.effective_url)
        yield f"* Trying {result.remote_ip}:{result.remote_port}...\n"
        yield "* Connected\n"
        if schema == "https":
            yield "* SSL connection established\n"
        yield f"> {effective_method} {path} {result.http_version}\r\n"
        for k, v in result.request_headers.items():
            yield f"> {k}: {v}\r\n"
        yield ">\r\n"

    # Verbose / include: response headers
    if verbose or include_headers or head_only:
        yield (f"< {result.http_version} " f"{result.status_code} {result.reason}\r\n")
        for k, v in result.response_headers.items():
            yield f"< {k}: {v}\r\n"
        yield "<\r\n"

    # Body
    if not head_only:
        try:
            yield result.body.decode("utf-8", errors="replace")
        except Exception:
            yield result.body.decode("latin-1")

    if verbose:
        yield (f"* Connection closed\n" f"({result.elapsed_ms:.2f} ms)\n")


def _error_code(error_msg: str) -> int:
    """Map common error messages to curl-like error codes."""
    msg = error_msg.lower()
    if "resolve" in msg or "getaddrinfo" in msg:
        return 6  # CURLE_COULDNT_RESOLVE_HOST
    if "connect" in msg or "refused" in msg:
        return 7  # CURLE_COULDNT_CONNECT
    if "timeout" in msg or "timed out" in msg or "time out" in msg:
        return 28  # CURLE_OPERATION_TIMEDOUT
    if "ssl" in msg or "certificate" in msg:
        return 60  # SSL certificate problem
    return 1  # CURLE_UNSUPPORTED_PROTOCOL or generic error


if __name__ == "__main__":
    from .curl_cli import main

    main()
