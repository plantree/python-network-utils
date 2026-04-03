"""Tests for wrk module."""

import socket
import sys
from unittest.mock import MagicMock, patch

import pytest

from src.wrk import (
    WrkResult,
    _build_request,
    _format_bytes,
    _format_count,
    _format_duration,
    _format_time,
    _mean,
    _parse_duration,
    _parse_url,
    _percentile,
    _recv_response,
    _safe_close,
    _stdev,
    _ThreadResult,
    _within_stdev,
    _worker,
    wrk,
    wrk_stream,
)

# Get actual module reference
wrk_module = sys.modules["src.wrk"]


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

    def test_no_scheme(self):
        scheme, host, port, _ = _parse_url("example.com/path")
        assert scheme == "http"
        assert host == "example.com"

    def test_with_query(self):
        _, _, _, path = _parse_url("http://example.com/test?q=1&v=2")
        assert path == "/test?q=1&v=2"


# ---------------------------------------------------------------------------
# Duration parsing
# ---------------------------------------------------------------------------
class TestParseDuration:
    """Tests for _parse_duration."""

    def test_seconds(self):
        assert _parse_duration("10s") == 10.0

    def test_milliseconds(self):
        assert _parse_duration("500ms") == 0.5

    def test_minutes(self):
        assert _parse_duration("2m") == 120.0

    def test_hours(self):
        assert _parse_duration("1h") == 3600.0

    def test_bare_number(self):
        assert _parse_duration("5") == 5.0

    def test_float(self):
        assert _parse_duration("1.5s") == 1.5

    def test_invalid(self):
        with pytest.raises(ValueError):
            _parse_duration("abc")


# ---------------------------------------------------------------------------
# Request building
# ---------------------------------------------------------------------------
class TestBuildRequest:
    """Tests for _build_request."""

    def test_basic(self):
        raw = _build_request("example.com", 80, "/")
        text = raw.decode("utf-8")
        assert text.startswith("GET / HTTP/1.1\r\n")
        assert "Host: example.com\r\n" in text
        assert "Connection: keep-alive\r\n" in text

    def test_custom_port(self):
        raw = _build_request("example.com", 8080, "/path")
        text = raw.decode("utf-8")
        assert "Host: example.com:8080\r\n" in text

    def test_standard_https_port(self):
        raw = _build_request("example.com", 443, "/")
        text = raw.decode("utf-8")
        assert "Host: example.com\r\n" in text

    def test_custom_headers(self):
        raw = _build_request(
            "example.com",
            80,
            "/",
            headers={"Authorization": "Bearer tok"},
        )
        text = raw.decode("utf-8")
        assert "Authorization: Bearer tok\r\n" in text

    def test_overrides_default(self):
        raw = _build_request(
            "example.com",
            80,
            "/",
            headers={"User-Agent": "custom/1.0"},
        )
        text = raw.decode("utf-8")
        assert "User-Agent: custom/1.0\r\n" in text
        assert "netwrk" not in text


# ---------------------------------------------------------------------------
# Response reading
# ---------------------------------------------------------------------------
class TestRecvResponse:
    """Tests for _recv_response."""

    def test_content_length(self):
        mock_sock = MagicMock()
        data = b"HTTP/1.1 200 OK\r\n" b"Content-Length: 5\r\n" b"\r\n" b"hello"
        mock_sock.recv.side_effect = [data, b""]
        status, nbytes = _recv_response(mock_sock)
        assert status == 200
        assert nbytes == len(data)

    def test_chunked(self):
        mock_sock = MagicMock()
        data = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"5\r\nhello\r\n"
            b"0\r\n\r\n"
        )
        mock_sock.recv.side_effect = [data, b""]
        status, nbytes = _recv_response(mock_sock)
        assert status == 200
        assert nbytes > 0

    def test_error(self):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = socket.timeout("timed out")
        status, nbytes = _recv_response(mock_sock)
        assert status == -1

    def test_empty(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""
        status, nbytes = _recv_response(mock_sock)
        assert status == -1

    def test_404(self):
        mock_sock = MagicMock()
        data = b"HTTP/1.1 404 Not Found\r\n" b"Content-Length: 0\r\n" b"\r\n"
        mock_sock.recv.side_effect = [data, b""]
        status, nbytes = _recv_response(mock_sock)
        assert status == 404


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------
class TestStatistics:
    """Tests for stats helper functions."""

    def test_mean_empty(self):
        assert _mean([]) == 0.0

    def test_mean(self):
        assert _mean([1.0, 2.0, 3.0]) == 2.0

    def test_stdev_single(self):
        assert _stdev([1.0]) == 0.0

    def test_stdev(self):
        result = _stdev([2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0])
        assert abs(result - 2.0) < 0.001

    def test_percentile_50(self):
        vals = sorted([1.0, 2.0, 3.0, 4.0, 5.0])
        assert _percentile(vals, 50) == 3.0

    def test_percentile_empty(self):
        assert _percentile([], 50) == 0.0

    def test_percentile_99(self):
        vals = sorted(list(range(1, 101)))
        p99 = _percentile([float(v) for v in vals], 99)
        assert p99 >= 99.0

    def test_within_stdev_empty(self):
        assert _within_stdev([]) == 0.0

    def test_within_stdev_uniform(self):
        assert _within_stdev([5.0, 5.0, 5.0]) == 100.0


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------
class TestFormatTime:
    """Tests for _format_time."""

    def test_microseconds(self):
        result = _format_time(0.5)
        assert "us" in result

    def test_milliseconds(self):
        result = _format_time(5.0)
        assert "ms" in result

    def test_seconds(self):
        result = _format_time(1500.0)
        assert "s" in result

    def test_minutes(self):
        result = _format_time(120000.0)
        assert "m" in result


class TestFormatCount:
    """Tests for _format_count."""

    def test_small(self):
        assert _format_count(50.0) == "50.00"

    def test_thousands(self):
        assert "k" in _format_count(5000.0)

    def test_millions(self):
        assert "M" in _format_count(2000000.0)


class TestFormatBytes:
    """Tests for _format_bytes."""

    def test_bytes(self):
        assert "B" in _format_bytes(500.0)

    def test_kb(self):
        assert "KB" in _format_bytes(2048.0)

    def test_mb(self):
        assert "MB" in _format_bytes(2 * 1024 * 1024.0)

    def test_gb(self):
        assert "GB" in _format_bytes(2 * 1024 * 1024 * 1024.0)


class TestFormatDuration:
    """Tests for _format_duration."""

    def test_seconds(self):
        assert _format_duration(10.0) == "10.00s"

    def test_minutes(self):
        result = _format_duration(90.0)
        assert "1m" in result
        assert "30.00s" in result


# ---------------------------------------------------------------------------
# WrkResult dataclass
# ---------------------------------------------------------------------------
class TestWrkResult:
    """Tests for WrkResult."""

    def test_defaults(self):
        r = WrkResult(url="http://example.com")
        assert r.total_requests == 0
        assert r.requests_per_sec == 0.0
        assert r.transfer_per_sec == 0.0

    def test_requests_per_sec(self):
        r = WrkResult(url="http://x", duration=2.0, total_requests=100)
        assert r.requests_per_sec == 50.0

    def test_transfer_per_sec(self):
        r = WrkResult(url="http://x", duration=2.0, total_bytes=2048)
        assert r.transfer_per_sec == 1024.0


# ---------------------------------------------------------------------------
# _safe_close
# ---------------------------------------------------------------------------
class TestSafeClose:
    """Tests for _safe_close."""

    def test_normal(self):
        mock_sock = MagicMock()
        _safe_close(mock_sock)
        mock_sock.close.assert_called_once()

    def test_error_ignored(self):
        mock_sock = MagicMock()
        mock_sock.close.side_effect = OSError("failed")
        _safe_close(mock_sock)  # should not raise


# ---------------------------------------------------------------------------
# _worker (mocked)
# ---------------------------------------------------------------------------
class TestWorker:
    """Tests for _worker."""

    @patch("select.select")
    @patch.object(wrk_module, "_create_connection")
    def test_basic(self, mock_conn, mock_select):
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock

        # Make select return all sockets as ready
        mock_select.side_effect = lambda r, w, x, t=None: (r, w, [])

        # Simulate successful responses
        response = b"HTTP/1.1 200 OK\r\n" b"Content-Length: 2\r\n" b"\r\n" b"OK"
        call_count = [0]

        def fake_recv(size):
            call_count[0] += 1
            if call_count[0] % 2 == 1:
                return response
            return b""

        mock_sock.recv.side_effect = fake_recv
        mock_sock.send.side_effect = lambda data: len(data)

        result = _ThreadResult()
        _worker(
            "http",
            "example.com",
            80,
            "/",
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            num_connections=1,
            duration=0.05,
            timeout=1.0,
            result=result,
        )
        assert result.requests >= 0
        mock_sock.close.assert_called()

    @patch.object(wrk_module, "_create_connection")
    def test_connect_error(self, mock_conn):
        mock_conn.side_effect = OSError("connection refused")

        result = _ThreadResult()
        _worker(
            "http",
            "badhost",
            80,
            "/",
            b"GET / HTTP/1.1\r\nHost: badhost\r\n\r\n",
            num_connections=1,
            duration=0.05,
            timeout=1.0,
            result=result,
        )
        assert result.connect_errors > 0
        assert result.errors > 0


# ---------------------------------------------------------------------------
# wrk (mocked)
# ---------------------------------------------------------------------------
class TestWrk:
    """Tests for the wrk() function."""

    @patch.object(wrk_module, "_worker")
    def test_aggregation(self, mock_worker):
        def fake_worker(
            scheme,
            host,
            port,
            path,
            req,
            num_conns,
            dur,
            tout,
            result,
        ):
            result.requests = 50
            result.bytes_read = 5000
            result.latencies = [1.0, 2.0, 3.0]

        mock_worker.side_effect = fake_worker

        result = wrk(
            "http://example.com",
            threads=2,
            connections=4,
            duration=0.1,
        )
        assert result.total_requests == 100
        assert result.total_bytes == 10000
        assert len(result.latencies) == 6
        assert result.duration > 0

    @patch.object(wrk_module, "_worker")
    def test_conn_distribution(self, mock_worker):
        conns_seen = []

        def fake_worker(
            scheme,
            host,
            port,
            path,
            req,
            num_conns,
            dur,
            tout,
            result,
        ):
            conns_seen.append(num_conns)

        mock_worker.side_effect = fake_worker

        wrk(
            "http://example.com",
            threads=3,
            connections=10,
            duration=0.01,
        )
        # 10 connections across 3 threads = 4, 3, 3
        assert sum(conns_seen) == 10
        assert len(conns_seen) == 3

    @patch.object(wrk_module, "_worker")
    def test_errors(self, mock_worker):
        def fake_worker(
            scheme,
            host,
            port,
            path,
            req,
            num_conns,
            dur,
            tout,
            result,
        ):
            result.connect_errors = 5
            result.errors = 5

        mock_worker.side_effect = fake_worker

        result = wrk(
            "http://example.com",
            threads=1,
            connections=1,
            duration=0.01,
        )
        assert result.connect_errors == 5
        assert result.total_errors == 5


# ---------------------------------------------------------------------------
# wrk_stream (mocked)
# ---------------------------------------------------------------------------
class TestWrkStream:
    """Tests for wrk_stream."""

    @patch.object(wrk_module, "_worker")
    def test_output_format(self, mock_worker):
        def fake_worker(
            scheme,
            host,
            port,
            path,
            req,
            num_conns,
            dur,
            tout,
            result,
        ):
            result.requests = 100
            result.bytes_read = 10000
            result.latencies = [1.0, 1.5, 2.0, 2.5, 3.0]

        mock_worker.side_effect = fake_worker

        output = list(
            wrk_stream(
                "http://example.com",
                threads=2,
                connections=10,
                duration=0.01,
            )
        )
        text = "".join(output)
        assert "Running" in text
        assert "http://example.com" in text
        assert "2 threads and 10 connections" in text
        assert "Thread Stats" in text
        assert "Latency" in text
        assert "Req/Sec" in text
        assert "requests in" in text
        assert "Requests/sec:" in text
        assert "Transfer/sec:" in text

    @patch.object(wrk_module, "_worker")
    def test_latency_distribution(self, mock_worker):
        def fake_worker(
            scheme,
            host,
            port,
            path,
            req,
            num_conns,
            dur,
            tout,
            result,
        ):
            result.requests = 50
            result.bytes_read = 5000
            result.latencies = [float(i) for i in range(1, 101)]

        mock_worker.side_effect = fake_worker

        output = list(
            wrk_stream(
                "http://example.com",
                threads=1,
                connections=1,
                duration=0.01,
                latency=True,
            )
        )
        text = "".join(output)
        assert "Latency Distribution" in text
        assert "50%" in text
        assert "99%" in text

    @patch.object(wrk_module, "_worker")
    def test_error_output(self, mock_worker):
        def fake_worker(
            scheme,
            host,
            port,
            path,
            req,
            num_conns,
            dur,
            tout,
            result,
        ):
            result.requests = 10
            result.bytes_read = 1000
            result.latencies = [1.0]
            result.connect_errors = 3
            result.read_errors = 1
            result.errors = 4

        mock_worker.side_effect = fake_worker

        output = list(
            wrk_stream(
                "http://example.com",
                threads=1,
                connections=1,
                duration=0.01,
            )
        )
        text = "".join(output)
        assert "Socket errors:" in text

    @patch.object(wrk_module, "_worker")
    def test_no_requests(self, mock_worker):
        def fake_worker(
            scheme,
            host,
            port,
            path,
            req,
            num_conns,
            dur,
            tout,
            result,
        ):
            pass  # no requests completed

        mock_worker.side_effect = fake_worker

        output = list(
            wrk_stream(
                "http://example.com",
                threads=1,
                connections=1,
                duration=0.01,
            )
        )
        text = "".join(output)
        assert "0 requests" in text

    @patch.object(wrk_module, "_worker")
    def test_status_errors(self, mock_worker):
        def fake_worker(
            scheme,
            host,
            port,
            path,
            req,
            num_conns,
            dur,
            tout,
            result,
        ):
            result.requests = 10
            result.bytes_read = 1000
            result.latencies = [1.0]
            result.status_errors = 5

        mock_worker.side_effect = fake_worker

        output = list(
            wrk_stream(
                "http://example.com",
                threads=1,
                connections=1,
                duration=0.01,
            )
        )
        text = "".join(output)
        assert "Non-2xx or 3xx responses: 5" in text


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
class TestCli:
    """Tests for wrk_cli."""

    @patch.object(wrk_module, "_worker")
    def test_main_runs(self, mock_worker):
        def fake_worker(
            scheme,
            host,
            port,
            path,
            req,
            num_conns,
            dur,
            tout,
            result,
        ):
            result.requests = 10
            result.bytes_read = 1000
            result.latencies = [1.0]

        mock_worker.side_effect = fake_worker

        from src.wrk_cli import main

        with patch(
            "sys.argv",
            [
                "netwrk",
                "-t",
                "1",
                "-c",
                "1",
                "-d",
                "0.01s",
                "http://example.com",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    @patch.object(wrk_module, "_worker")
    def test_latency_flag(self, mock_worker):
        def fake_worker(
            scheme,
            host,
            port,
            path,
            req,
            num_conns,
            dur,
            tout,
            result,
        ):
            result.requests = 10
            result.bytes_read = 1000
            result.latencies = [1.0, 2.0, 3.0]

        mock_worker.side_effect = fake_worker

        from src.wrk_cli import main

        with patch(
            "sys.argv",
            [
                "netwrk",
                "-t",
                "1",
                "-c",
                "1",
                "-d",
                "0.01s",
                "--latency",
                "http://example.com",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    @patch.object(wrk_module, "_worker")
    def test_header_flag(self, mock_worker):
        def fake_worker(
            scheme,
            host,
            port,
            path,
            req,
            num_conns,
            dur,
            tout,
            result,
        ):
            result.requests = 5
            result.bytes_read = 500
            result.latencies = [1.0]

        mock_worker.side_effect = fake_worker

        from src.wrk_cli import main

        with patch(
            "sys.argv",
            [
                "netwrk",
                "-t",
                "1",
                "-c",
                "1",
                "-d",
                "0.01s",
                "-H",
                "Authorization: Bearer tok",
                "http://example.com",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    def test_invalid_duration(self):
        from src.wrk_cli import main

        with patch(
            "sys.argv",
            [
                "netwrk",
                "-d",
                "abc",
                "http://example.com",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_invalid_header(self):
        from src.wrk_cli import main

        with patch(
            "sys.argv",
            [
                "netwrk",
                "-H",
                "bad-header",
                "http://example.com",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1
