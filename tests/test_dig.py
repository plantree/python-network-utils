"""Tests for dig module."""

import socket
import struct
from typing import List, Optional, Tuple
from unittest.mock import MagicMock, mock_open, patch

from src.dig import (
    DNSRecord,
    DNSResult,
    RecordClass,
    RecordType,
    _build_dns_query,
    _decode_domain_name,
    _dotify,
    _encode_domain_name,
    _format_flags,
    _format_opcode,
    _format_rcode,
    _format_record_line,
    _get_system_dns_server,
    _parse_dns_response,
    dig,
    dig_stream,
)

# --- Helper to build a minimal DNS response ---


def _build_response(
    transaction_id: int = 0x1234,
    flags: int = 0x8180,  # QR=1, RD=1, RA=1, RCODE=0
    questions: Optional[List[Tuple[str, int, int]]] = None,
    answers: Optional[List[Tuple[str, int, int, int, bytes]]] = None,
) -> bytes:
    """Build a raw DNS response packet for testing.

    Args:
        questions: list of (domain, qtype, qclass)
        answers: list of (domain, rtype, ttl, rclass, rdata)
    """
    if questions is None:
        questions = [("example.com", RecordType.A, RecordClass.IN)]
    if answers is None:
        answers = []

    qdcount = len(questions)
    ancount = len(answers)
    header = struct.pack("!HHHHHH", transaction_id, flags, qdcount, ancount, 0, 0)

    body = b""
    for domain, qtype, qclass in questions:
        body += _encode_domain_name(domain) + struct.pack("!HH", qtype, qclass)
    for domain, rtype, ttl, rclass, rdata in answers:
        body += _encode_domain_name(domain)
        body += struct.pack("!HHIH", rtype, rclass, ttl, len(rdata))
        body += rdata

    return header + body


# =============================================================================
# RecordType / RecordClass enums
# =============================================================================


class TestRecordType:
    def test_common_values(self):
        assert RecordType.A == 1
        assert RecordType.AAAA == 28
        assert RecordType.MX == 15
        assert RecordType.CNAME == 5
        assert RecordType.NS == 2
        assert RecordType.TXT == 16
        assert RecordType.SOA == 6
        assert RecordType.PTR == 12

    def test_lookup_by_name(self):
        assert RecordType["A"] == 1
        assert RecordType["MX"] == 15


class TestRecordClass:
    def test_in_class(self):
        assert RecordClass.IN == 1


# =============================================================================
# _encode_domain_name
# =============================================================================


class TestEncodeDomainName:
    def test_simple_domain(self):
        result = _encode_domain_name("example.com")
        assert result == b"\x07example\x03com\x00"

    def test_subdomain(self):
        result = _encode_domain_name("www.example.com")
        assert result == b"\x03www\x07example\x03com\x00"

    def test_trailing_dot_stripped(self):
        result = _encode_domain_name("example.com.")
        assert result == b"\x07example\x03com\x00"

    def test_single_label(self):
        result = _encode_domain_name("localhost")
        assert result == b"\x09localhost\x00"


# =============================================================================
# _decode_domain_name
# =============================================================================


class TestDecodeDomainName:
    def test_simple_domain(self):
        data = b"\x07example\x03com\x00"
        name, offset = _decode_domain_name(data, 0)
        assert name == "example.com"
        assert offset == len(data)

    def test_with_offset(self):
        prefix = b"\xff\xff"  # 2 bytes of junk
        data = prefix + b"\x07example\x03com\x00"
        name, offset = _decode_domain_name(data, 2)
        assert name == "example.com"

    def test_pointer_compression(self):
        # First name at offset 0
        data = b"\x07example\x03com\x00"
        # Pointer to offset 0
        data += b"\xc0\x00"
        name, offset = _decode_domain_name(data, len(data) - 2)
        assert name == "example.com"
        assert offset == len(data)  # after consuming the 2-byte pointer


# =============================================================================
# _build_dns_query
# =============================================================================


class TestBuildDnsQuery:
    def test_query_structure(self):
        query = _build_dns_query("example.com", RecordType.A)
        # Header is 12 bytes
        assert len(query) >= 12
        # Unpack header
        tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", query[:12])
        assert flags == 0x0100  # RD flag
        assert qd == 1
        assert an == 0
        assert ns == 0
        assert ar == 0

    def test_query_contains_domain(self):
        query = _build_dns_query("example.com", RecordType.A)
        # The encoded domain should appear in the query
        assert b"\x07example\x03com\x00" in query

    def test_query_record_type(self):
        query = _build_dns_query("example.com", RecordType.MX)
        # Last 4 bytes of question: QTYPE(2) + QCLASS(2)
        qtype, qclass = struct.unpack("!HH", query[-4:])
        assert qtype == RecordType.MX
        assert qclass == RecordClass.IN


# =============================================================================
# _parse_dns_response
# =============================================================================


class TestParseDnsResponse:
    def test_too_short_response(self):
        header, ans, auth, add, err = _parse_dns_response(b"\x00" * 5)
        assert err == "Response too short"
        assert ans == []

    def test_noerror_no_answers(self):
        resp = _build_response(answers=[])
        header, ans, auth, add, err = _parse_dns_response(resp)
        assert err is None
        assert len(ans) == 0
        assert header.flags & 0x8000  # QR bit set

    def test_a_record(self):
        rdata = socket.inet_aton("93.184.216.34")
        resp = _build_response(
            answers=[
                ("example.com", RecordType.A, 300, RecordClass.IN, rdata),
            ]
        )
        header, ans, auth, add, err = _parse_dns_response(resp)
        assert err is None
        assert len(ans) == 1
        assert ans[0].data == "93.184.216.34"
        assert ans[0].record_type == "A"
        assert ans[0].ttl == 300

    def test_multiple_a_records(self):
        resp = _build_response(
            answers=[
                (
                    "example.com",
                    RecordType.A,
                    60,
                    RecordClass.IN,
                    socket.inet_aton("1.2.3.4"),
                ),
                (
                    "example.com",
                    RecordType.A,
                    60,
                    RecordClass.IN,
                    socket.inet_aton("5.6.7.8"),
                ),
            ]
        )
        header, ans, auth, add, err = _parse_dns_response(resp)
        assert err is None
        assert len(ans) == 2
        assert ans[0].data == "1.2.3.4"
        assert ans[1].data == "5.6.7.8"

    def test_aaaa_record(self):
        rdata = socket.inet_pton(socket.AF_INET6, "2606:2800:220:1:248:1893:25c8:1946")
        resp = _build_response(
            questions=[("example.com", RecordType.AAAA, RecordClass.IN)],
            answers=[("example.com", RecordType.AAAA, 120, RecordClass.IN, rdata)],
        )
        header, ans, auth, add, err = _parse_dns_response(resp)
        assert err is None
        assert len(ans) == 1
        assert ans[0].record_type == "AAAA"
        assert "2606:2800" in ans[0].data

    def test_txt_record(self):
        txt_content = b"v=spf1 include:example.com ~all"
        rdata = bytes([len(txt_content)]) + txt_content
        resp = _build_response(
            questions=[("example.com", RecordType.TXT, RecordClass.IN)],
            answers=[("example.com", RecordType.TXT, 3600, RecordClass.IN, rdata)],
        )
        header, ans, auth, add, err = _parse_dns_response(resp)
        assert err is None
        assert len(ans) == 1
        assert ans[0].record_type == "TXT"
        assert "v=spf1" in ans[0].data

    def test_rcode_servfail(self):
        flags = 0x8182  # QR=1, RD=1, RA=1, RCODE=2 (SERVFAIL)
        resp = _build_response(flags=flags, answers=[])
        header, ans, auth, add, err = _parse_dns_response(resp)
        assert err == "SERVFAIL"
        assert header.flags == flags

    def test_rcode_nxdomain(self):
        flags = 0x8183  # RCODE=3
        resp = _build_response(flags=flags, answers=[])
        header, ans, auth, add, err = _parse_dns_response(resp)
        assert err == "NXDOMAIN"

    def test_header_fields(self):
        resp = _build_response(transaction_id=0xABCD)
        header, ans, auth, add, err = _parse_dns_response(resp)
        assert header.transaction_id == 0xABCD
        assert header.qdcount == 1
        assert header.ancount == 0

    def test_cname_record(self):
        """CNAME rdata is a fully-encoded domain name."""
        cname_rdata = _encode_domain_name("www.example.com")
        resp = _build_response(
            questions=[("alias.example.com", RecordType.CNAME, RecordClass.IN)],
            answers=[
                (
                    "alias.example.com",
                    RecordType.CNAME,
                    3600,
                    RecordClass.IN,
                    cname_rdata,
                ),
            ],
        )
        header, ans, auth, add, err = _parse_dns_response(resp)
        assert err is None
        assert len(ans) == 1
        assert ans[0].record_type == "CNAME"
        assert ans[0].data == "www.example.com"
        assert ans[0].ttl == 3600

    def test_cname_with_compression_pointer(self):
        """CNAME rdata uses a compression pointer back into the packet."""
        # Build a packet by hand so CNAME rdata contains a pointer.
        #
        # Layout:
        #   [0..11]  header (12 bytes)
        #   [12..]   question:  \x07example\x03com\x00
        #                       (13 bytes for qname, 4 for qtype+qclass = 17)
        #   [29..]   answer:    owner = pointer to offset 12 (\xc0\x0c)
        #                       type(2) + class(2) + ttl(4) + rdlength(2)
        #                       rdata = \x03www  + pointer to offset 12 (\xc0\x0c)
        #
        # The CNAME target should decode to "www.example.com".

        header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)

        # Question section
        qname = _encode_domain_name("example.com")  # 13 bytes
        question = qname + struct.pack("!HH", RecordType.CNAME, RecordClass.IN)

        # Answer section  –  owner via pointer
        ans_owner = b"\xc0\x0c"  # pointer → offset 12
        # CNAME rdata: "www" label + pointer to "example.com" at offset 12
        cname_rdata = b"\x03www\xc0\x0c"  # 6 bytes
        ans_rec = ans_owner + struct.pack(
            "!HHIH", RecordType.CNAME, RecordClass.IN, 300, len(cname_rdata)
        )
        ans_rec += cname_rdata

        pkt = header + question + ans_rec
        header_obj, ans, auth, add, err = _parse_dns_response(pkt)
        assert err is None
        assert len(ans) == 1
        assert ans[0].record_type == "CNAME"
        assert ans[0].data == "www.example.com"

    def test_ns_record(self):
        ns_rdata = _encode_domain_name("ns1.example.com")
        resp = _build_response(
            questions=[("example.com", RecordType.NS, RecordClass.IN)],
            answers=[
                (
                    "example.com",
                    RecordType.NS,
                    86400,
                    RecordClass.IN,
                    ns_rdata,
                ),
            ],
        )
        header, ans, auth, add, err = _parse_dns_response(resp)
        assert err is None
        assert len(ans) == 1
        assert ans[0].record_type == "NS"
        assert ans[0].data == "ns1.example.com"

    def test_ns_with_compression_pointer(self):
        """NS rdata uses a compression pointer."""
        header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)

        qname = _encode_domain_name("example.com")
        question = qname + struct.pack("!HH", RecordType.NS, RecordClass.IN)

        ans_owner = b"\xc0\x0c"
        ns_rdata = b"\x03ns1\xc0\x0c"  # ns1.example.com
        ans_rec = ans_owner + struct.pack(
            "!HHIH", RecordType.NS, RecordClass.IN, 7200, len(ns_rdata)
        )
        ans_rec += ns_rdata

        pkt = header + question + ans_rec
        _, ans, _, _, err = _parse_dns_response(pkt)
        assert err is None
        assert len(ans) == 1
        assert ans[0].record_type == "NS"
        assert ans[0].data == "ns1.example.com"

    def test_mx_with_compression_pointer(self):
        """MX rdata uses a compression pointer for the exchange name."""
        header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)

        qname = _encode_domain_name("example.com")
        question = qname + struct.pack("!HH", RecordType.MX, RecordClass.IN)

        ans_owner = b"\xc0\x0c"
        # MX rdata: priority(2) + mail exchange name with pointer
        mx_rdata = struct.pack("!H", 10) + b"\x04mail\xc0\x0c"
        ans_rec = ans_owner + struct.pack(
            "!HHIH", RecordType.MX, RecordClass.IN, 600, len(mx_rdata)
        )
        ans_rec += mx_rdata

        pkt = header + question + ans_rec
        _, ans, _, _, err = _parse_dns_response(pkt)
        assert err is None
        assert len(ans) == 1
        assert ans[0].record_type == "MX"
        assert ans[0].data == "mail.example.com"
        assert ans[0].priority == 10


# =============================================================================
# _get_system_dns_server
# =============================================================================


class TestGetSystemDnsServer:
    def test_reads_resolv_conf(self):
        fake_content = "# comment\nnameserver 10.0.0.1\nnameserver 10.0.0.2\n"
        with patch("builtins.open", mock_open(read_data=fake_content)):
            assert _get_system_dns_server() == "10.0.0.1"

    def test_fallback_on_error(self):
        with patch("builtins.open", side_effect=OSError):
            assert _get_system_dns_server() == "8.8.8.8"

    def test_fallback_on_empty(self):
        with patch("builtins.open", mock_open(read_data="# no nameserver\n")):
            assert _get_system_dns_server() == "8.8.8.8"


# =============================================================================
# Formatting helpers
# =============================================================================


class TestFormatFlags:
    def test_qr_rd_ra(self):
        flags = 0x8180  # QR + RD + RA
        result = _format_flags(flags)
        assert "qr" in result
        assert "rd" in result
        assert "ra" in result

    def test_qr_rd_ad(self):
        flags = 0x8120  # QR + RD + AD
        result = _format_flags(flags)
        assert "qr" in result
        assert "rd" in result
        assert "ad" in result
        assert "ra" not in result

    def test_empty_flags(self):
        assert _format_flags(0) == ""

    def test_all_flags(self):
        flags = 0x8000 | 0x0400 | 0x0200 | 0x0100 | 0x0080 | 0x0020 | 0x0010
        result = _format_flags(flags)
        for f in ["qr", "aa", "tc", "rd", "ra", "ad", "cd"]:
            assert f in result


class TestFormatOpcode:
    def test_query(self):
        assert _format_opcode(0x0000) == "QUERY"

    def test_iquery(self):
        assert _format_opcode(0x0800) == "IQUERY"

    def test_status(self):
        assert _format_opcode(0x1000) == "STATUS"


class TestFormatRcode:
    def test_noerror(self):
        assert _format_rcode(0x0000) == "NOERROR"

    def test_nxdomain(self):
        assert _format_rcode(0x0003) == "NXDOMAIN"

    def test_refused(self):
        assert _format_rcode(0x0005) == "REFUSED"


class TestDotify:
    def test_adds_dot(self):
        assert _dotify("example.com") == "example.com."

    def test_already_dotted(self):
        assert _dotify("example.com.") == "example.com."


class TestFormatRecordLine:
    def test_a_record(self):
        rec = DNSRecord(name="example.com", record_type="A", ttl=300, data="1.2.3.4")
        line = _format_record_line(rec)
        assert "example.com." in line
        assert "300" in line
        assert "IN" in line
        assert "A" in line
        assert "1.2.3.4" in line

    def test_mx_record_with_priority(self):
        rec = DNSRecord(
            name="example.com",
            record_type="MX",
            ttl=600,
            data="mail.example.com",
            priority=10,
        )
        line = _format_record_line(rec)
        assert "10 mail.example.com" in line
        assert "MX" in line


# =============================================================================
# dig() function (with mocked socket)
# =============================================================================


class TestDig:
    def test_unsupported_record_type(self):
        result = dig("example.com", record_type="INVALID")
        assert result.error == "Unsupported record type: INVALID"
        assert result.query_time_ms == 0

    @patch("src.dig.socket.socket")
    @patch("src.dig._get_system_dns_server", return_value="8.8.8.8")
    def test_successful_query(self, mock_dns_server, mock_socket_cls):
        # Build a fake response
        rdata = socket.inet_aton("93.184.216.34")
        resp = _build_response(
            transaction_id=0x1234,
            answers=[("example.com", RecordType.A, 300, RecordClass.IN, rdata)],
        )

        mock_sock = MagicMock()
        mock_sock.recvfrom.return_value = (resp, ("8.8.8.8", 53))
        mock_socket_cls.return_value = mock_sock

        result = dig("example.com", "A")
        assert result.error is None
        assert len(result.anwsers) == 1
        assert result.anwsers[0].data == "93.184.216.34"
        assert result.server == "8.8.8.8"
        assert result.response_size == len(resp)

    @patch("src.dig.socket.socket")
    @patch("src.dig._get_system_dns_server", return_value="8.8.8.8")
    def test_timeout(self, mock_dns_server, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = socket.timeout
        mock_socket_cls.return_value = mock_sock

        result = dig("example.com", "A")
        assert result.error == "Query timed out"

    @patch("src.dig.socket.socket")
    @patch("src.dig._get_system_dns_server", return_value="8.8.8.8")
    def test_os_error(self, mock_dns_server, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.sendto.side_effect = OSError("Network unreachable")
        mock_socket_cls.return_value = mock_sock

        result = dig("example.com", "A")
        assert "Network unreachable" in result.error

    def test_custom_server(self):
        with patch("src.dig.socket.socket") as mock_socket_cls:
            rdata = socket.inet_aton("1.2.3.4")
            resp = _build_response(
                answers=[
                    ("example.com", RecordType.A, 60, RecordClass.IN, rdata),
                ]
            )
            mock_sock = MagicMock()
            mock_sock.recvfrom.return_value = (resp, ("1.1.1.1", 53))
            mock_socket_cls.return_value = mock_sock

            result = dig("example.com", "A", server="1.1.1.1")
            assert result.server == "1.1.1.1"
            mock_sock.sendto.assert_called_once()
            # Verify the server address in sendto call
            call_args = mock_sock.sendto.call_args
            assert call_args[0][1] == ("1.1.1.1", 53)


# =============================================================================
# dig_stream() output format
# =============================================================================


class TestDigStream:
    @patch("src.dig.dig")
    def test_stream_output_format(self, mock_dig):
        mock_dig.return_value = DNSResult(
            domain="example.com",
            record_type="A",
            server="8.8.8.8",
            port=53,
            query_time_ms=42.5,
            transaction_id=0x1234,
            flags=0x8180,  # QR + RD + RA
            qdcount=1,
            ancount=1,
            nscount=0,
            arcount=0,
            response_size=50,
            anwsers=[
                DNSRecord(
                    name="example.com", record_type="A", ttl=300, data="93.184.216.34"
                )
            ],
        )

        output = "".join(dig_stream("example.com", "A"))
        assert ";; global options: +cmd" in output
        assert ";; Got answer:" in output
        assert "opcode: QUERY" in output
        assert "status: NOERROR" in output
        assert "id: 4660" in output  # 0x1234
        assert "flags: qr rd ra" in output
        assert "QUERY: 1" in output
        assert "ANSWER: 1" in output
        assert ";; QUESTION SECTION:" in output
        assert ";example.com." in output
        assert ";; ANSWER SECTION:" in output
        assert "example.com." in output
        assert "93.184.216.34" in output
        assert ";; Query time: 42 msec" in output
        assert ";; SERVER: 8.8.8.8#53(8.8.8.8)" in output
        assert ";; MSG SIZE  rcvd: 50" in output
        assert ";; WHEN:" in output

    @patch("src.dig.dig")
    def test_stream_error(self, mock_dig):
        mock_dig.return_value = DNSResult(
            domain="bad.example",
            record_type="A",
            server="8.8.8.8",
            port=53,
            query_time_ms=0,
            transaction_id=0x5678,
            error="Query timed out",
        )

        output = "".join(dig_stream("bad.example", "A"))
        assert ";; global options: +cmd" in output
        assert "Query timed out" in output

    @patch("src.dig.dig")
    def test_stream_recursion_warning(self, mock_dig):
        mock_dig.return_value = DNSResult(
            domain="example.com",
            record_type="A",
            server="8.8.8.8",
            port=53,
            query_time_ms=10,
            transaction_id=0x1111,
            flags=0x8120,  # QR + RD + AD (no RA)
            qdcount=1,
            ancount=1,
            nscount=0,
            arcount=0,
            response_size=40,
            anwsers=[
                DNSRecord(name="example.com", record_type="A", ttl=0, data="1.2.3.4")
            ],
        )

        output = "".join(dig_stream("example.com", "A"))
        assert "WARNING: recursion requested but not available" in output

    @patch("src.dig.dig")
    def test_stream_no_answers(self, mock_dig):
        mock_dig.return_value = DNSResult(
            domain="example.com",
            record_type="A",
            server="8.8.8.8",
            port=53,
            query_time_ms=5,
            transaction_id=0x2222,
            flags=0x8180,
            qdcount=1,
            ancount=0,
            nscount=0,
            arcount=0,
            response_size=30,
        )

        output = "".join(dig_stream("example.com", "A"))
        assert "ANSWER SECTION" not in output
        assert ";; QUESTION SECTION:" in output


# =============================================================================
# DNSResult / DNSRecord dataclass
# =============================================================================


class TestDNSResult:
    def test_default_values(self):
        result = DNSResult(
            domain="x.com", record_type="A", server="8.8.8.8", port=53, query_time_ms=0
        )
        assert result.anwsers == []
        assert result.authority == []
        assert result.additional == []
        assert result.error is None
        assert result.transaction_id == 0
        assert result.flags == 0
        assert result.response_size == 0


class TestDNSRecord:
    def test_basic_record(self):
        rec = DNSRecord(name="example.com", record_type="A", ttl=300, data="1.2.3.4")
        assert rec.priority is None

    def test_mx_record(self):
        rec = DNSRecord(
            name="example.com",
            record_type="MX",
            ttl=600,
            data="mail.example.com",
            priority=10,
        )
        assert rec.priority == 10
