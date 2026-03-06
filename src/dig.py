"""DNS lookup tool (dig-like functionality).

Run with: python -m src.dig <host>
Or: .venv/bin/netdig <host>

Example:
    $ python -m src.dig example.com
    $ python -m src.dig example.com A
"""

import socket
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from random import random
from typing import Optional


class RecordType(IntEnum):
    """DNS record types."""

    A = 1  # IPv4 address
    NS = 2  # Name server
    CNAME = 5  # Canonical name
    SOA = 6  # Start of authority
    PTR = 12  # Pointer record (reverse DNS)
    MX = 15  # Mail exchange
    TXT = 16  # Text record
    AAAA = 28  # IPv6 address


class RecordClass(IntEnum):
    """DNS record classes."""

    IN = 1  # Internet
    CS = 2  # CSNET (obsolete)
    CH = 3  # CHAOS
    HS = 4  # Hesiod


# DNS header flags
DNS_QR_QUERY = 0
DNS_QR_RESPONSE = 1
DNS_OPCODE_QUERY = 0
DNS_RCODE_OK = 0


def _get_system_dns_server() -> str:
    """Get the system's default DNS server from /etc/resolv.conf."""
    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
    except (OSError, IOError):
        pass
    return "8.8.8.8"  # Fallback to Google's public DNS server


@dataclass
class DNSRecord:
    """Represents a DNS record."""

    name: str
    record_type: str
    ttl: int
    data: str
    priority: Optional[int] = None  # For MX records


@dataclass
class DNSResult:
    """Result of a DNS query."""

    domain: str
    record_type: str
    server: str
    port: int
    query_time_ms: float
    transaction_id: int = 0
    flags: int = 0
    qdcount: int = 0
    ancount: int = 0
    nscount: int = 0
    arcount: int = 0
    response_size: int = 0
    anwsers: list[DNSRecord] = field(default_factory=list)
    authority: list[DNSRecord] = field(default_factory=list)
    additional: list[DNSRecord] = field(default_factory=list)
    error: Optional[str] = None


def _encode_domain_name(domain: str) -> bytes:
    """Encode a domain name into DNS format (length-prefixed labels)."""
    result = b""
    for label in domain.rstrip(".").split("."):
        result += bytes([len(label)]) + label.encode("ascii")
    result += b"\x00"
    return result


def _decode_domain_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a domain name from DNS format, handling compression."""
    labels = []
    end_offset = -1  # where to resume after pointer(s)

    while offset < len(data):
        length = data[offset]

        # pointer (compression)
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            if end_offset == -1:
                end_offset = offset + 2  # save resume point on first jump
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            offset = pointer
            continue

        if length == 0:
            offset += 1
            break

        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset : offset + length].decode("ascii"))
        offset += length

    if end_offset != -1:
        return ".".join(labels), end_offset
    return ".".join(labels), offset


def _build_dns_query(domain: str, record_type: RecordType) -> bytes:
    """Build a DNS query packet."""
    # Transaction ID (random 16-bit)
    transanction_id = int(random() * 65536)

    # Header
    # Flags: standard query, recursion desired
    flags = 0x0100  # RD (Recursion Desired)
    qdcount = 1  # Number of questions
    ancount = 0  # Number of answers
    nscount = 0  # Number of authority records
    arcount = 0  # Number of additional records

    header = struct.pack(
        "!HHHHHH", transanction_id, flags, qdcount, ancount, nscount, arcount
    )

    # Question section
    qname = _encode_domain_name(domain)
    qtype = record_type
    qclass = RecordClass.IN

    question = qname + struct.pack("!HH", qtype, qclass)

    return header + question


@dataclass
class DNSHeader:
    """Parsed DNS response header."""

    transaction_id: int
    flags: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int


def _parse_dns_response(
    data: bytes,
) -> tuple[DNSHeader, list[DNSRecord], list[DNSRecord], list[DNSRecord], Optional[str]]:
    """Parse a DNS response packet."""
    if len(data) < 12:
        return DNSHeader(0, 0, 0, 0, 0, 0), [], [], [], "Response too short"

    # Parse header
    (transaction_id, flags, qdcount, ancount, nscount, arcount) = struct.unpack(
        "!HHHHHH", data[:12]
    )
    header = DNSHeader(transaction_id, flags, qdcount, ancount, nscount, arcount)

    # Check response flag
    rcode = flags & 0x000F
    rcode_names = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
    }
    if rcode != DNS_RCODE_OK:
        return header, [], [], [], rcode_names.get(rcode, f"DNS error: {rcode}")

    offset = 12

    # Skip questions
    for _ in range(qdcount):
        _, offset = _decode_domain_name(data, offset)
        offset += 4  # Skip QTYPE and QCLASS

    def parse_records(count: int) -> list[DNSRecord]:
        """Parse a section of DNS records."""
        nonlocal offset
        records = []

        for _ in range(count):
            if offset >= len(data):
                break

            name, offset = _decode_domain_name(data, offset)

            if offset + 10 > len(data):
                break

            rtype, rclass, ttl, rdlength = struct.unpack(
                "!HHIH", data[offset : offset + 10]
            )
            offset += 10

            if offset + rdlength > len(data):
                break

            rdata = data[offset : offset + rdlength]
            rdata_offset = offset  # position of rdata in full packet
            offset += rdlength

            # Parse record data based on type
            record_type_name = (
                RecordType(rtype).name
                if rtype in [e.value for e in RecordType]
                else str(rtype)
            )
            priority = None
            parsed_data = ""

            if rtype == RecordType.A and rdlength == 4:
                parsed_data = socket.inet_ntoa(rdata)
            elif rtype == RecordType.AAAA and rdlength == 16:
                parsed_data = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype == RecordType.MX and rdlength >= 2:
                priority = struct.unpack("!H", rdata[:2])[0]
                mx_name, _ = _decode_domain_name(data, rdata_offset + 2)
                parsed_data = mx_name
            elif rtype in [RecordType.CNAME, RecordType.NS, RecordType.PTR]:
                parsed_data, _ = _decode_domain_name(data, rdata_offset)
            elif rtype == RecordType.TXT:
                # TXT records have length-prefixed strings
                txt_parts = []
                txt_offset = 0
                while txt_offset < rdlength:
                    txt_length = rdata[txt_offset]
                    txt_offset += 1
                    txt_parts.append(
                        rdata[txt_offset : txt_offset + txt_length].decode(
                            "utf-8", errors="replace"
                        )
                    )
                    txt_offset += txt_length
                parsed_data = "".join(txt_parts)
            elif rtype == RecordType.SOA:
                mname, new_offset = _decode_domain_name(data, rdata_offset)
                rname, new_offset = _decode_domain_name(data, new_offset)
                if new_offset + 20 <= offset:
                    serial, refresh, retry, expire, minimium = struct.unpack(
                        "!IIIII", data[new_offset : new_offset + 20]
                    )
                    parsed_data = (
                        f"{mname} {rname} {serial} "
                        f"{refresh} {retry} {expire} "
                        f"{minimium}"
                    )
                else:
                    parsed_data = f"{mname} {rname}"
            else:
                parsed_data = rdata.hex()

            records.append(
                DNSRecord(
                    name=name,
                    record_type=record_type_name,
                    ttl=ttl,
                    data=parsed_data,
                    priority=priority,
                )
            )

        return records

    anwsers = parse_records(ancount)
    authority = parse_records(nscount)
    additional = parse_records(arcount)

    return header, anwsers, authority, additional, None


def dig(
    domain: str,
    record_type: str = "A",
    server: Optional[str] = None,
    port: int = 53,
    timeout: float = 5.0,
) -> DNSResult:
    """Perform a DNS lookup.

    Args:
        domain: The domain name to query.
        record_type: The type of DNS record to query (e.g. "A", "MX").
        server: Optional DNS server to query (default: system's default).
        port: DNS server port (default: 53).

    Returns:
        DNSResult with query results.
    """
    if server is None:
        server = _get_system_dns_server()

    # Parse record type
    try:
        rtype = RecordType[record_type.upper()]
    except KeyError:
        return DNSResult(
            domain=domain,
            record_type=record_type,
            server=server,
            port=port,
            query_time_ms=0,
            error=f"Unsupported record type: {record_type}",
        )

    result = DNSResult(
        domain=domain,
        record_type=record_type.upper(),
        server=server,
        port=port,
        query_time_ms=0,
    )

    try:
        # Build query
        query = _build_dns_query(domain, rtype)

        # Send query
        # DNS typically uses UDP, but can fall back to TCP
        # for larger responses. For simplicity, we use UDP.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        start_time = time.perf_counter()
        sock.sendto(query, (server, port))

        # Receive response
        response, _ = sock.recvfrom(
            512
        )  # DNS responses are typically <= 512 bytes for UDP
        end_time = time.perf_counter()

        result.query_time_ms = (end_time - start_time) * 1000

        sock.close()

        result.response_size = len(response)

        # Parse response
        header, anwsers, authority, additional, error = _parse_dns_response(response)
        result.transaction_id = header.transaction_id
        result.flags = header.flags
        result.qdcount = header.qdcount
        result.ancount = header.ancount
        result.nscount = header.nscount
        result.arcount = header.arcount

        if error:
            result.error = error
        else:
            result.anwsers = anwsers
            result.authority = authority
            result.additional = additional

    except socket.timeout:
        result.error = "Query timed out"
    except OSError as e:
        result.error = str(e)

    return result


def _format_flags(flags: int) -> str:
    """Format DNS flags into human-readable string."""
    parts = []
    if flags & 0x8000:
        parts.append("qr")
    if flags & 0x0400:
        parts.append("aa")
    if flags & 0x0200:
        parts.append("tc")
    if flags & 0x0100:
        parts.append("rd")
    if flags & 0x0080:
        parts.append("ra")
    if flags & 0x0020:
        parts.append("ad")
    if flags & 0x0010:
        parts.append("cd")
    return " ".join(parts)


def _format_opcode(flags: int) -> str:
    """Format DNS opcode."""
    opcode = (flags >> 11) & 0xF
    opcodes = {0: "QUERY", 1: "IQUERY", 2: "STATUS"}
    return opcodes.get(opcode, str(opcode))


def _format_rcode(flags: int) -> str:
    """Format DNS response code."""
    rcode = flags & 0xF
    rcodes = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
    }
    return rcodes.get(rcode, str(rcode))


def _dotify(name: str) -> str:
    """Ensure domain name ends with a dot."""
    if not name.endswith("."):
        return name + "."
    return name


def _format_record_line(record: DNSRecord) -> str:
    """Format a DNS record in dig-style column alignment."""
    name = _dotify(record.name)
    # dig uses column-aligned formatting:
    # name(24) ttl(8) class(8) type(8) data
    name_col = f"{name:<24s}"
    ttl_col = f"{record.ttl}"
    type_col = record.record_type
    if record.priority is not None:
        data = f"{record.priority} {record.data}"
    else:
        data = record.data
    return f"{name_col}{ttl_col}\tIN\t{type_col}\t{data}"


def dig_stream(domain: str, record_type: str = "A", server: Optional[str] = None):
    """Perform a DNS query and yield results as they are received."""
    result = dig(domain, record_type, server)

    yield f"; <<>> netdig <<>> {domain} {record_type}\n"
    yield ";; global options: +cmd\n"

    if result.error:
        yield ";; Got answer:\n"
        header_line = (
            f";; ->>HEADER<<- opcode: QUERY, "
            f"status: {result.error}, "
            f"id: {result.transaction_id}"
        )
        yield f"{header_line}\n"
        return

    flags_str = _format_flags(result.flags)
    opcode_str = _format_opcode(result.flags)
    rcode_str = _format_rcode(result.flags)

    yield ";; Got answer:\n"
    header_line = (
        f";; ->>HEADER<<- opcode: {opcode_str}, "
        f"status: {rcode_str}, id: {result.transaction_id}"
    )
    yield f"{header_line}\n"
    flags_line = (
        f";; flags: {flags_str}; "
        f"QUERY: {result.qdcount}, ANSWER: {result.ancount}, "
        f"AUTHORITY: {result.nscount}, ADDITIONAL: {result.arcount}"
    )
    yield f"{flags_line}\n"

    # Warning if recursion was requested but not available
    rd = result.flags & 0x0100
    ra = result.flags & 0x0080
    if rd and not ra:
        yield ";; WARNING: recursion requested but not available\n"

    yield "\n"

    # Question section
    yield ";; QUESTION SECTION:\n"
    domain_dot = _dotify(domain)
    rtype_upper = record_type.upper()
    yield f";{domain_dot:<24s}\tIN\t{rtype_upper}\n"
    yield "\n"

    if result.anwsers:
        yield ";; ANSWER SECTION:\n"
        for record in result.anwsers:
            yield f"{_format_record_line(record)}\n"
        yield "\n"

    if result.authority:
        yield ";; AUTHORITY SECTION:\n"
        for record in result.authority:
            yield f"{_format_record_line(record)}\n"
        yield "\n"

    if result.additional:
        yield ";; ADDITIONAL SECTION:\n"
        for record in result.additional:
            yield f"{_format_record_line(record)}\n"
        yield "\n"

    yield f";; Query time: {int(result.query_time_ms)} msec\n"
    server_line = f";; SERVER: {result.server}" f"#{result.port}({result.server})"
    yield f"{server_line}\n"
    # WHEN timestamp
    now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
    yield f";; WHEN: {now}\n"
    yield f";; MSG SIZE  rcvd: {result.response_size}\n"


if __name__ == "__main__":
    from .dig_cli import main

    main()
