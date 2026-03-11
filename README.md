# python-network-utils

A Python library for network diagnostics using raw sockets and system APIs. Provides ping, traceroute, DNS lookup (dig), and network interface (ifconfig) functionality both as CLI tools and as a Python API.

## Features

- **Ping**: ICMP-based ping with RTT statistics (min/avg/max)
- **Traceroute**: Trace network path to destination using TTL manipulation
- **Dig**: DNS lookup with dig-style output (A, AAAA, MX, CNAME, NS, SOA, TXT, PTR)
- **Ifconfig**: Display network interface configuration (IP, MAC, MTU, flags, stats)
- **Lsof**: List open network sockets with process info (`lsof -i` style output)
- **CLI Tools**: `netping`, `nettraceroute`, `netdig`, `netifconfig`, and `netlsof` commands
- **Programmatic API**: Use directly in Python code
- **Streaming Output**: Real-time output via generators

## Requirements

- Python 3.8+
- Root/Administrator privileges (required for raw ICMP sockets)

## Installation

### Using venv (recommended)

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate     # Windows

# Install in development mode
pip install -e ".[dev]"
```

### Using Makefile

```bash
# Setup with development dependencies
make install-dev

# Or just production dependencies
make install
```

## Usage

### Command Line

```bash
# Ping a host (requires root)
sudo netping google.com
sudo netping -c 10 -t 3 8.8.8.8

# Traceroute to a host (requires root)
sudo nettraceroute google.com
sudo nettraceroute -m 15 -t 2 -q 3 example.com

# DNS lookup (no root required)
netdig example.com
netdig example.com MX
netdig example.com AAAA -s 8.8.8.8

# Network interface info (requires root)
sudo netifconfig
sudo netifconfig eth0

# List open network sockets (requires root)
sudo netlsof
sudo netlsof -i :80
sudo netlsof -p 1234
sudo netlsof -t -s LISTEN
sudo netlsof -u
sudo netlsof --proto tcp6
```

#### netping options

| Option | Description | Default |
|--------|-------------|---------|
| `-c, --count` | Number of ping requests | 4 |
| `-t, --timeout` | Timeout per ping (seconds) | 5 |

#### nettraceroute options

| Option | Description | Default |
|--------|-------------|---------|
| `-m, --max-hops` | Maximum number of hops | 30 |
| `-t, --timeout` | Timeout per probe (seconds) | 3 |
| `-q, --probes` | Number of probes per hop | 3 |

#### netdig options

| Option | Description | Default |
|--------|-------------|---------|
| `domain` | The domain name to query | (required) |
| `record_type` | DNS record type (A, AAAA, MX, CNAME, NS, SOA, TXT, PTR) | A |
| `-s, --server` | DNS server to query | System resolver |

#### netifconfig options

| Option | Description | Default |
|--------|-------------|---------|
| `interface` | Specific interface to display | All interfaces |

#### netlsof options

| Option | Description | Default |
|--------|-------------|----------|
| `-i, --port` | Filter by port (e.g. `:80` or `80`) | All ports |
| `-p, --pid` | Filter by process ID | All processes |
| `-s, --state` | Filter by socket state (e.g. `LISTEN`, `ESTABLISHED`) | All states |
| `-t, --tcp` | Show only TCP sockets | Off |
| `-u, --udp` | Show only UDP sockets | Off |
| `--proto` | Specific protocol (`tcp`, `tcp6`, `udp`, `udp6`; repeatable) | All |
| `-S, --services` | Resolve port numbers to service names | Off |

### Python API

```python
from src import (
    ping,
    ping_stream,
    ping_multiple,
    is_host_reachable,
    PingResult,
    traceroute_stream,
    TracerouteResult,
    HopResult,
    ifconfig_stream,
    get_interface_info,
    get_all_interfaces,
    InterfaceInfo,
)
from src.dig import dig, dig_stream, DNSResult, DNSRecord

# Simple ping - returns PingResult dataclass
result = ping("google.com", count=4, timeout=5)
print(f"Host: {result.host}")
print(f"Reachable: {result.is_reachable}")
print(f"Packets: {result.packets_sent} sent, {result.packets_received} received")
print(f"Packet Loss: {result.packet_loss:.1f}%")
if result.is_reachable:
    print(f"RTT: min={result.min_rtt:.2f} avg={result.avg_rtt:.2f} max={result.max_rtt:.2f} ms")

# Quick reachability check
if is_host_reachable("8.8.8.8"):
    print("Host is up!")

# Ping multiple hosts
results = ping_multiple(["google.com", "github.com", "8.8.8.8"])
for r in results:
    status = f"{r.avg_rtt:.2f} ms" if r.is_reachable else "unreachable"
    print(f"{r.host}: {status}")

# Stream ping output (real-time, like command line)
for line in ping_stream("google.com", count=4):
    print(line, end="")

# Stream traceroute output (real-time)
for line in traceroute_stream("google.com", max_hops=30, timeout=3, probes=3):
    print(line, end="")

# DNS lookup - returns DNSResult
result = dig("example.com", "A")
print(f"Server: {result.server}")
print(f"Query time: {result.query_time_ms:.0f} ms")
for record in result.anwsers:
    print(f"{record.name} {record.ttl} IN {record.record_type} {record.data}")

# Stream dig output (dig-style formatting)
for line in dig_stream("example.com", "MX", server="8.8.8.8"):
    print(line, end="")

# Get network interface info
for iface in get_all_interfaces():
    print(f"{iface.name}: {iface.ip_address or 'no address'}")

# Stream ifconfig output (ifconfig-style formatting)
for line in ifconfig_stream("eth0"):
    print(line, end="")

# List open network sockets (lsof-style output)
from src.lsof import lsof, lsof_stream, SocketInfo

# Get structured socket data
sockets = lsof(port=80, state="LISTEN")
for s in sockets:
    print(f"{s.process_name}:{s.pid} {s.local_address}:{s.local_port} ({s.state})")

# Stream lsof output (lsof -i style formatting)
for line in lsof_stream(protocols=["tcp"], state="LISTEN"):
    print(line, end="")
```

## API Reference

### Ping Functions

| Function | Description | Returns |
|----------|-------------|---------|
| `ping(host, count=4, timeout=5)` | Ping a host | `PingResult` |
| `ping_stream(host, count=4, timeout=5)` | Ping with streaming output | `Generator[str]` |
| `is_host_reachable(host, timeout=5)` | Quick reachability check | `bool` |
| `ping_multiple(hosts, count=4, timeout=5)` | Ping multiple hosts | `list[PingResult]` |

### Traceroute Functions

| Function | Description | Returns |
|----------|-------------|---------|
| `traceroute_stream(host, max_hops=30, timeout=3, probes=3)` | Traceroute with streaming output | `Generator[str]` |

### Dig (DNS Lookup) Functions

| Function | Description | Returns |
|----------|-------------|---------|
| `dig(domain, record_type="A", server=None, port=53, timeout=5)` | Perform a DNS query | `DNSResult` |
| `dig_stream(domain, record_type="A", server=None)` | DNS query with dig-style streaming output | `Generator[str]` |

### Ifconfig Functions

| Function | Description | Returns |
|----------|-------------|---------|
| `ifconfig_stream(interface=None)` | Display interface info with streaming output | `Generator[str]` |
| `get_interface_info(name)` | Get info for a specific interface | `InterfaceInfo` |
| `get_all_interfaces()` | Get info for all interfaces | `list[InterfaceInfo]` |

### Lsof Functions

| Function | Description | Returns |
|----------|-------------|----------|
| `lsof(protocols=None, port=None, pid=None, state=None)` | List open network sockets | `list[SocketInfo]` |
| `lsof_stream(protocols=None, port=None, pid=None, state=None, resolve_services=False)` | Stream lsof-style output | `Generator[str]` |

### Data Classes

#### PingResult
```python
@dataclass
class PingResult:
    host: str
    is_reachable: bool
    packets_sent: int = 0
    packets_received: int = 0
    packet_loss: float = 0.0
    min_rtt: Optional[float] = None
    avg_rtt: Optional[float] = None
    max_rtt: Optional[float] = None
    error: Optional[str] = None
```

#### HopResult
```python
@dataclass
class HopResult:
    hop: int
    ip: Optional[str] = None
    hostname: Optional[str] = None
    rtts: Optional[list[float]] = None
    is_timeout: bool = False
```

#### TracerouteResult
```python
@dataclass
class TracerouteResult:
    host: str
    hops: list[HopResult]
    reached: bool = False
    error: Optional[str] = None
```

#### DNSRecord
```python
@dataclass
class DNSRecord:
    name: str
    record_type: str
    ttl: int
    data: str
    priority: Optional[int] = None  # For MX records
```

#### DNSResult
```python
@dataclass
class DNSResult:
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
```

#### InterfaceInfo
```python
@dataclass
class InterfaceInfo:
    name: str
    ip_address: Optional[str] = None
    netmask: Optional[str] = None
    broadcast: Optional[str] = None
    mac_address: Optional[str] = None
    ipv6_address: Optional[str] = None
    ipv6_prefixlen: int = 0
    ipv6_scope: Optional[str] = None
    mtu: int = 0
    txqueuelen: int = 0
    flags: int = 0
    is_up: bool = False
    is_running: bool = False
    is_loopback: bool = False
    is_broadcast: bool = False
    is_multicast: bool = False
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_packets: int = 0
    tx_packets: int = 0
    rx_errors: int = 0
    tx_errors: int = 0
    rx_dropped: int = 0
    tx_dropped: int = 0
```

#### SocketInfo
```python
@dataclass
class SocketInfo:
    protocol: str              # "tcp", "tcp6", "udp", or "udp6"
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: Optional[str]
    inode: int
    uid: int
    tx_queue: int = 0
    rx_queue: int = 0
    pid: Optional[int] = None
    process_name: Optional[str] = None
    fd: Optional[int] = None
```

## Development

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage report
make test-cov

# Or directly with pytest
pytest
pytest --cov=src --cov-report=html
```

### Code Quality

```bash
# Format code
make format

# Run linters (flake8 + mypy)
make lint

# Check formatting without changes
make format-check
```

### Clean up

```bash
make clean
```

## Project Structure

```
python-network-utils/
├── src/
│   ├── __init__.py           # Package exports
│   ├── __main__.py           # Module entry point
│   ├── dig.py                # DNS lookup implementation
│   ├── dig_cli.py            # CLI for netdig command
│   ├── ifconfig.py           # Network interface info implementation
│   ├── ifconfig_cli.py       # CLI for netifconfig command
│   ├── lsof.py               # Open network sockets implementation
│   ├── lsof_cli.py           # CLI for netlsof command
│   ├── ping.py               # ICMP ping implementation
│   ├── ping_cli.py           # CLI for netping command
│   ├── traceroute.py         # ICMP traceroute implementation
│   └── traceroute_cli.py     # CLI for nettraceroute command
├── tests/
│   ├── __init__.py
│   ├── test_dig.py           # Unit tests for dig module
│   ├── test_ifconfig.py      # Unit tests for ifconfig module
│   ├── test_lsof.py          # Unit tests for lsof module
│   └── test_ping.py          # Unit tests for ping module
├── .flake8                   # Flake8 configuration
├── .gitignore
├── LICENSE
├── Makefile                  # Build automation
├── pyproject.toml            # Project configuration
├── README.md
├── requirements.txt
└── requirements-dev.txt
```

## How It Works

### Ping

The ping tool sends ICMP Echo Request packets (type 8) and listens for ICMP Echo Reply packets (type 0). It uses raw sockets which require root privileges on most systems.

### Traceroute

The traceroute tool sends ICMP Echo Request packets with incrementing TTL (Time To Live) values starting from 1. Each router along the path decrements the TTL, and when it reaches 0, the router sends back an ICMP Time Exceeded message (type 11). This allows mapping the network path to the destination.

### Dig

The dig tool builds raw DNS query packets and sends them via UDP to a DNS server (port 53). It parses the response including header flags, question, answer, authority, and additional sections. Output is formatted to match the standard `dig` command, including HEADER, FLAGS, and section-based record display. No root privileges required.

### Ifconfig

The ifconfig tool uses Linux `ioctl` system calls to query network interface information including IP addresses, MAC addresses, MTU, flags, and traffic statistics. It reads `/proc/net/dev` for packet/byte counters and `/proc/net/if_inet6` for IPv6 addresses. Requires root privileges for some operations.

### Lsof

The lsof tool reads `/proc/net/{tcp,tcp6,udp,udp6}` to enumerate open network sockets, parsing hex-encoded addresses, ports, states, UIDs, and inodes. It then scans `/proc/[pid]/fd/` to map socket inodes back to processes. Output is formatted to match `lsof -i`, showing COMMAND, PID, USER, FD, TYPE, DEVICE, NODE, and NAME columns. Requires root privileges to see all processes.

## License

MIT License
