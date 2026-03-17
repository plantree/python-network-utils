"""Tests for curl module."""

import sys
from unittest.mock import MagicMock, patch

import pytest

from src.curl import (
    CurlResult,
    _build_request,
    _decode_body,
    _decode_chunked,
    _error_code,
    _get_header,
    _parse_response_head,
    _parse_url,
    curl,
    curl_stream,
)

# Get actual module reference
curl_module = sys.modules["src.curl"]


# ---------------------------------------------------------------------------
# URL parsing
# ---------------------------------------------------------------------------
class TestParseUrl:
    """Tests for _parse_url."""

    def test_http(self):
        scheme, host, port, path = _parse_url("http://example.com")
        assert scheme == "http"
        assert host == "example.com"
        assert port == 80
        assert path == "/"

    def test_https(self):
        scheme, host, port, path = _parse_url("https://example.com")
        assert scheme == "https"
        assert port == 443

    def test_custom_port(self):
        scheme, host, port, path = _parse_url("http://localhost:8080/api")
        assert host == "localhost"
        assert port == 8080
        assert path == "/api"

    def test_with_path_and_query(self):
        _, _, _, path = _parse_url("http://example.com/page?q=hello&lang=en")
        assert path == "/page?q=hello&lang=en"

    def test_no_scheme_defaults_http(self):
        scheme, host, port, _ = _parse_url("example.com")
        assert scheme == "http"
        assert host == "example.com"
        assert port == 80

    def test_with_fragment(self):
        _, _, _, path = _parse_url("http://example.com/page#section")
        assert "#section" in path

    def test_empty_path(self):
        _, _, _, path = _parse_url("http://example.com")
        assert path == "/"


# ---------------------------------------------------------------------------
# Request building
# ---------------------------------------------------------------------------
class TestBuildRequest:
    """Tests for _build_request."""

    def test_get_request(self):
        raw, hdrs = _build_request("GET", "example.com", 80, "/")
        text = raw.decode("utf-8")
        assert text.startswith("GET / HTTP/1.1\r\n")
        assert "Host: example.com" in text
        assert "User-Agent:" in text
        assert hdrs["Host"] == "example.com"

    def test_post_with_data(self):
        raw, hdrs = _build_request(
            "POST",
            "example.com",
            80,
            "/submit",
            data="key=val",
        )
        text = raw.decode("utf-8")
        assert text.startswith("POST /submit HTTP/1.1\r\n")
        assert "Content-Length: 7" in text
        assert text.endswith("key=val")

    def test_custom_headers(self):
        raw, hdrs = _build_request(
            "GET",
            "example.com",
            80,
            "/",
            headers={"Accept": "text/html", "X-Custom": "123"},
        )
        text = raw.decode("utf-8")
        assert "Accept: text/html" in text
        assert "X-Custom: 123" in text
        # Accept should override default
        assert hdrs["Accept"] == "text/html"

    def test_host_with_non_standard_port(self):
        _, hdrs = _build_request("GET", "example.com", 8080, "/")
        assert hdrs["Host"] == "example.com:8080"

    def test_host_standard_port_no_suffix(self):
        _, hdrs = _build_request("GET", "example.com", 443, "/")
        assert hdrs["Host"] == "example.com"

    def test_content_type_default_for_post(self):
        _, hdrs = _build_request(
            "POST",
            "example.com",
            80,
            "/",
            data="x=1",
        )
        assert hdrs.get("Content-Type") == "application/x-www-form-urlencoded"

    def test_content_type_not_overridden(self):
        _, hdrs = _build_request(
            "POST",
            "example.com",
            80,
            "/",
            headers={"Content-Type": "application/json"},
            data='{"a":1}',
        )
        assert hdrs["Content-Type"] == "application/json"

    def test_connection_close(self):
        _, hdrs = _build_request("GET", "example.com", 80, "/")
        assert hdrs["Connection"] == "close"


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------
class TestParseResponseHead:
    """Tests for _parse_response_head."""

    def test_basic(self):
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: 5\r\n"
            b"\r\n"
            b"hello"
        )
        ver, code, reason, hdrs, body = _parse_response_head(raw)
        assert ver == "HTTP/1.1"
        assert code == 200
        assert reason == "OK"
        assert hdrs["Content-Type"] == "text/html"
        assert hdrs["Content-Length"] == "5"
        assert body == b"hello"

    def test_no_body(self):
        raw = b"HTTP/1.1 204 No Content\r\n" b"Connection: close\r\n" b"\r\n"
        ver, code, reason, hdrs, body = _parse_response_head(raw)
        assert code == 204
        assert reason == "No Content"
        assert body == b""

    def test_302_redirect(self):
        raw = b"HTTP/1.1 302 Found\r\n" b"Location: https://example.com/new\r\n" b"\r\n"
        ver, code, reason, hdrs, body = _parse_response_head(raw)
        assert code == 302
        assert hdrs["Location"] == "https://example.com/new"

    def test_lf_only_separator(self):
        raw = b"HTTP/1.1 200 OK\n" b"Content-Type: text/plain\n" b"\n" b"body"
        _, code, _, hdrs, body = _parse_response_head(raw)
        assert code == 200
        assert body == b"body"


# ---------------------------------------------------------------------------
# Chunked decoding
# ---------------------------------------------------------------------------
class TestDecodeChunked:
    """Tests for _decode_chunked."""

    def test_single_chunk(self):
        data = b"5\r\nhello\r\n0\r\n\r\n"
        assert _decode_chunked(data) == b"hello"

    def test_multiple_chunks(self):
        data = b"5\r\nhello\r\n" b"6\r\n world\r\n" b"0\r\n\r\n"
        assert _decode_chunked(data) == b"hello world"

    def test_empty(self):
        data = b"0\r\n\r\n"
        assert _decode_chunked(data) == b""


# ---------------------------------------------------------------------------
# Body decoding
# ---------------------------------------------------------------------------
class TestDecodeBody:
    """Tests for _decode_body."""

    def test_plain(self):
        body = b"hello world"
        assert _decode_body(body, {}) == b"hello world"

    def test_gzip(self):
        import gzip

        original = b"hello compressed world"
        compressed = gzip.compress(original)
        result = _decode_body(compressed, {"Content-Encoding": "gzip"})
        assert result == original

    def test_chunked_then_gzip(self):
        import gzip

        original = b"chunked gzip data"
        compressed = gzip.compress(original)
        hex_len = format(len(compressed), "x")
        chunked = f"{hex_len}\r\n".encode() + compressed + b"\r\n0\r\n\r\n"
        result = _decode_body(
            chunked,
            {
                "Transfer-Encoding": "chunked",
                "Content-Encoding": "gzip",
            },
        )
        assert result == original


# ---------------------------------------------------------------------------
# Header lookup
# ---------------------------------------------------------------------------
class TestGetHeader:
    """Tests for _get_header."""

    def test_exact_match(self):
        assert _get_header({"Content-Type": "text/html"}, "Content-Type") == "text/html"

    def test_case_insensitive(self):
        assert _get_header({"content-type": "text/html"}, "Content-Type") == "text/html"

    def test_missing(self):
        assert _get_header({}, "X-Missing") is None


# ---------------------------------------------------------------------------
# Error codes
# ---------------------------------------------------------------------------
class TestErrorCode:
    """Tests for _error_code."""

    def test_resolve(self):
        assert _error_code("Could not resolve host") == 6

    def test_connect(self):
        assert _error_code("Connection refused") == 7

    def test_timeout(self):
        assert _error_code("Operation timed out") == 28

    def test_ssl(self):
        assert _error_code("SSL certificate verify failed") == 60

    def test_generic(self):
        assert _error_code("something went wrong") == 1


# ---------------------------------------------------------------------------
# CurlResult dataclass
# ---------------------------------------------------------------------------
class TestCurlResult:
    """Tests for CurlResult dataclass."""

    def test_default_values(self):
        r = CurlResult(url="http://ex.com", effective_url="http://ex.com", method="GET")
        assert r.status_code == 0
        assert r.body == b""
        assert r.error is None
        assert r.redirect_count == 0
        assert r.request_headers == {}
        assert r.response_headers == {}

    def test_with_values(self):
        r = CurlResult(
            url="http://ex.com",
            effective_url="http://ex.com",
            method="GET",
            status_code=200,
            reason="OK",
            body=b"hi",
            elapsed_ms=42.5,
        )
        assert r.status_code == 200
        assert r.body == b"hi"


# ---------------------------------------------------------------------------
# curl (integration with mock socket)
# ---------------------------------------------------------------------------
class TestCurl:
    """Tests for curl function."""

    def _mock_response(self, status=200, reason="OK", headers=None, body=b"OK"):
        hdr_dict = headers or {}
        hdr_lines = "".join(f"{k}: {v}\r\n" for k, v in hdr_dict.items())
        return (
            f"HTTP/1.1 {status} {reason}\r\n" f"{hdr_lines}" f"\r\n"
        ).encode() + body

    @patch.object(curl_module, "_recv_response")
    @patch.object(curl_module, "_create_connection")
    def test_simple_get(self, mock_conn, mock_recv):
        mock_sock = MagicMock()
        mock_conn.return_value = (mock_sock, "93.184.216.34")
        mock_recv.return_value = self._mock_response(body=b"Hello World")

        result = curl("http://example.com")

        assert result.status_code == 200
        assert result.body == b"Hello World"
        assert result.remote_ip == "93.184.216.34"
        assert result.error is None
        mock_sock.sendall.assert_called_once()
        mock_sock.close.assert_called_once()

    @patch.object(curl_module, "_recv_response")
    @patch.object(curl_module, "_create_connection")
    def test_post(self, mock_conn, mock_recv):
        mock_sock = MagicMock()
        mock_conn.return_value = (mock_sock, "1.2.3.4")
        mock_recv.return_value = self._mock_response(body=b'{"ok":true}')

        result = curl(
            "http://httpbin.org/post",
            method="POST",
            data='{"key":"val"}',
            headers={"Content-Type": "application/json"},
        )

        assert result.status_code == 200
        raw_sent = mock_sock.sendall.call_args[0][0]
        assert b"POST /post HTTP/1.1" in raw_sent
        assert b'{"key":"val"}' in raw_sent

    @patch.object(curl_module, "_recv_response")
    @patch.object(curl_module, "_create_connection")
    def test_head(self, mock_conn, mock_recv):
        mock_sock = MagicMock()
        mock_conn.return_value = (mock_sock, "1.2.3.4")
        mock_recv.return_value = self._mock_response(body=b"")

        curl(
            "http://example.com",
            method="HEAD",
        )
        raw_sent = mock_sock.sendall.call_args[0][0]
        assert b"HEAD / HTTP/1.1" in raw_sent

    @patch.object(curl_module, "_create_connection")
    def test_connection_error(self, mock_conn):
        mock_conn.side_effect = ConnectionError("refused")
        result = curl("http://localhost:9999")
        assert result.error is not None
        assert "refused" in result.error

    @patch.object(curl_module, "_recv_response")
    @patch.object(curl_module, "_create_connection")
    def test_follow_redirect(self, mock_conn, mock_recv):
        mock_sock = MagicMock()
        mock_conn.return_value = (mock_sock, "1.2.3.4")

        redirect_resp = self._mock_response(
            status=301,
            reason="Moved",
            headers={
                "Location": "http://example.com/new",
            },
            body=b"",
        )
        final_resp = self._mock_response(body=b"final")
        mock_recv.side_effect = [redirect_resp, final_resp]

        result = curl(
            "http://example.com/old",
            follow_redirects=True,
        )
        assert result.status_code == 200
        assert result.body == b"final"
        assert result.redirect_count == 1

    @patch.object(curl_module, "_recv_response")
    @patch.object(curl_module, "_create_connection")
    def test_no_follow_redirect(self, mock_conn, mock_recv):
        mock_sock = MagicMock()
        mock_conn.return_value = (mock_sock, "1.2.3.4")
        mock_recv.return_value = self._mock_response(
            status=302,
            reason="Found",
            headers={"Location": "/new"},
            body=b"",
        )

        result = curl("http://example.com/old")
        assert result.status_code == 302
        assert result.redirect_count == 0


# ---------------------------------------------------------------------------
# curl_stream
# ---------------------------------------------------------------------------
class TestCurlStream:
    """Tests for curl_stream."""

    @patch.object(curl_module, "curl")
    def test_error_output(self, mock_curl):
        mock_curl.return_value = CurlResult(
            url="http://bad.host",
            effective_url="http://bad.host",
            method="GET",
            error="Could not resolve host: bad.host",
        )
        lines = list(curl_stream("http://bad.host"))
        assert any("Could not resolve" in line for line in lines)

    @patch.object(curl_module, "curl")
    def test_body_output(self, mock_curl):
        mock_curl.return_value = CurlResult(
            url="http://example.com",
            effective_url="http://example.com",
            method="GET",
            status_code=200,
            reason="OK",
            body=b"<html>Hello</html>",
        )
        lines = list(curl_stream("http://example.com"))
        text = "".join(lines)
        assert "<html>Hello</html>" in text

    @patch.object(curl_module, "curl")
    def test_verbose_output(self, mock_curl):
        mock_curl.return_value = CurlResult(
            url="http://example.com",
            effective_url="http://example.com",
            method="GET",
            http_version="HTTP/1.1",
            status_code=200,
            reason="OK",
            request_headers={
                "Host": "example.com",
                "User-Agent": "netcurl/1.0",
            },
            response_headers={
                "Content-Type": "text/html",
            },
            body=b"body",
            remote_ip="93.184.216.34",
            remote_port=80,
        )
        lines = list(curl_stream("http://example.com", verbose=True))
        text = "".join(lines)
        assert "* Trying 93.184.216.34:80" in text
        assert "> Host: example.com" in text
        assert "< HTTP/1.1 200 OK" in text
        assert "< Content-Type: text/html" in text
        assert "body" in text

    @patch.object(curl_module, "curl")
    def test_head_only(self, mock_curl):
        mock_curl.return_value = CurlResult(
            url="http://example.com",
            effective_url="http://example.com",
            method="HEAD",
            http_version="HTTP/1.1",
            status_code=200,
            reason="OK",
            response_headers={
                "Content-Type": "text/html",
            },
            body=b"",
        )
        lines = list(curl_stream("http://example.com", head_only=True))
        text = "".join(lines)
        assert "200 OK" in text
        assert "Content-Type" in text

    @patch.object(curl_module, "curl")
    def test_include_headers(self, mock_curl):
        mock_curl.return_value = CurlResult(
            url="http://example.com",
            effective_url="http://example.com",
            method="GET",
            http_version="HTTP/1.1",
            status_code=200,
            reason="OK",
            response_headers={
                "Server": "nginx",
            },
            body=b"content",
        )
        lines = list(curl_stream("http://example.com", include_headers=True))
        text = "".join(lines)
        assert "< Server: nginx" in text
        assert "content" in text


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
class TestCli:
    """Tests for CLI argument parsing."""

    def test_parse_header_valid(self):
        from src.curl_cli import _parse_header

        k, v = _parse_header("Content-Type: application/json")
        assert k == "Content-Type"
        assert v == "application/json"

    def test_parse_header_invalid(self):
        import argparse

        from src.curl_cli import _parse_header

        with pytest.raises(argparse.ArgumentTypeError):
            _parse_header("no-colon-here")

    @patch.object(curl_module, "_recv_response")
    @patch.object(curl_module, "_create_connection")
    def test_cli_main_get(self, mock_conn, mock_recv):
        from src.curl_cli import main

        mock_sock = MagicMock()
        mock_conn.return_value = (mock_sock, "1.2.3.4")
        mock_recv.return_value = (
            b"HTTP/1.1 200 OK\r\n" b"Content-Type: text/plain\r\n" b"\r\n" b"hello"
        )

        with patch("sys.argv", ["netcurl", "http://example.com"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 0

    @patch.object(curl_module, "_recv_response")
    @patch.object(curl_module, "_create_connection")
    def test_cli_head_flag(self, mock_conn, mock_recv):
        from src.curl_cli import main

        mock_sock = MagicMock()
        mock_conn.return_value = (mock_sock, "1.2.3.4")
        mock_recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"

        with patch("sys.argv", ["netcurl", "-I", "http://example.com"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 0

    @patch.object(curl_module, "_recv_response")
    @patch.object(curl_module, "_create_connection")
    def test_cli_post_with_data(self, mock_conn, mock_recv):
        from src.curl_cli import main

        mock_sock = MagicMock()
        mock_conn.return_value = (mock_sock, "1.2.3.4")
        mock_recv.return_value = b"HTTP/1.1 200 OK\r\n\r\nok"

        with patch(
            "sys.argv",
            ["netcurl", "-d", "x=1", "http://example.com"],
        ):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 0
        # Should have sent POST
        raw_sent = mock_sock.sendall.call_args[0][0]
        assert b"POST" in raw_sent
