# python-network-utils

A Python library for network diagnostics using raw sockets and system interfaces. Provides ping, traceroute, and ifconfig functionality both as CLI tools and as a Python API.

## Features

- **Ping**: ICMP-based ping with RTT statistics (min/avg/max)
- **Traceroute**: Trace network path to destination using TTL manipulation
- **Ifconfig**: Display network interface configuration (like Unix ifconfig)
- **CLI Tools**: `netping`, `nettraceroute`, and `netifconfig` commands
- **Programmatic API**: Use directly in Python code
- **Streaming Output**: Real-time output via generators

## Requirements

- Python 3.8+
- Linux (for ifconfig and raw sockets)
- Root/Administrator privileges (required for ping and traceroute)

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

# Display network interfaces (no root required)
netifconfig
netifconfig eth0
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

### Python API

```python
from src import (
    ping,
    ping_stream,
    ping_multiple,
    is_host_reachable,
    PingResult,
    traceroute_stream,
    ifconfig,
    ifconfig_stream,
    get_interface_info,
    get_all_interfaces,
    InterfaceInfo,
)

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

# Get all network interfaces
interfaces = ifconfig()
for iface in interfaces:
    print(f"{iface.name}: {iface.ip_address}")

# Get specific interface info
eth0 = get_interface_info("eth0")
print(f"IP: {eth0.ip_address}, MAC: {eth0.mac_address}, MTU: {eth0.mtu}")

# Stream ifconfig output (like command line)
for line in ifconfig_stream():
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

### Ifconfig Functions

| Function | Description | Returns |
|----------|-------------|---------|
| `ifconfig(interface=None)` | Get interface info | `list[InterfaceInfo]` |
| `ifconfig_stream(interface=None)` | Ifconfig with streaming output | `Generator[str]` |
| `get_interface_info(ifname)` | Get info for specific interface | `InterfaceInfo` |
| `get_all_interfaces()` | Get info for all interfaces | `list[InterfaceInfo]` |

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
│   ├── ping.py               # ICMP ping implementation
│   ├── ping_cli.py           # CLI for netping command
│   ├── traceroute.py         # ICMP traceroute implementation
│   ├── traceroute_cli.py     # CLI for nettraceroute command
│   ├── ifconfig.py           # Network interface configuration
│   └── ifconfig_cli.py       # CLI for netifconfig command
├── tests/
│   ├── __init__.py
│   ├── test_ping.py          # Unit tests for ping module
│   └── test_ifconfig.py      # Unit tests for ifconfig module
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

### Ifconfig

The ifconfig tool uses Linux ioctl system calls to query network interface information:
- IP address, netmask, broadcast via `SIOCGIFADDR`, `SIOCGIFNETMASK`, `SIOCGIFBRDADDR`
- MAC address via `SIOCGIFHWADDR`
- Interface flags via `SIOCGIFFLAGS`
- MTU via `SIOCGIFMTU`
- Statistics from `/sys/class/net/<interface>/statistics/`
- IPv6 addresses from `/proc/net/if_inet6`

## License

MIT License
