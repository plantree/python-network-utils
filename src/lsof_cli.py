"""Command-line interface for lsof (list open network sockets).

Usage:
    sudo netlsof
    sudo netlsof -p 1234
    sudo netlsof -i :80
    sudo netlsof -t -s LISTEN
    sudo netlsof --proto tcp
"""

import argparse
import sys

from .lsof import lsof_stream


def _parse_port_spec(spec: str) -> int:
    """Parse a port specification like ':80' or '80' into an int."""
    spec = spec.lstrip(":")
    try:
        port = int(spec)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid port: {spec!r}")
    if not 0 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"port out of range: {port}")
    return port


def main():
    """Main entry point for the netlsof CLI."""
    parser = argparse.ArgumentParser(
        prog="netlsof",
        description="List open network sockets (lsof-like functionality).",
    )
    parser.add_argument(
        "-i",
        "--port",
        type=_parse_port_spec,
        default=None,
        metavar=":[PORT]",
        help="Show only sockets matching this port (e.g. :80 or 80)",
    )
    parser.add_argument(
        "-p",
        "--pid",
        type=int,
        default=None,
        help="Show only sockets owned by this PID",
    )
    parser.add_argument(
        "-s",
        "--state",
        default=None,
        metavar="STATE",
        help="Show only sockets in this state (e.g. LISTEN, ESTABLISHED)",
    )
    parser.add_argument(
        "-t",
        "--tcp",
        action="store_true",
        help="Show only TCP sockets",
    )
    parser.add_argument(
        "-u",
        "--udp",
        action="store_true",
        help="Show only UDP sockets",
    )
    parser.add_argument(
        "--proto",
        choices=["tcp", "tcp6", "udp", "udp6"],
        action="append",
        default=None,
        help="Show only sockets of this protocol (can be repeated)",
    )
    parser.add_argument(
        "-n",
        "--numeric",
        action="store_true",
        default=True,
        help="Show numeric addresses (default, kept for compatibility)",
    )
    parser.add_argument(
        "-S",
        "--services",
        action="store_true",
        default=False,
        help="Resolve port numbers to service names",
    )

    args = parser.parse_args()

    # Build protocol list from flags
    protocols = args.proto
    if protocols is None:
        if args.tcp and not args.udp:
            protocols = ["tcp", "tcp6"]
        elif args.udp and not args.tcp:
            protocols = ["udp", "udp6"]
        # else: None → all protocols

    try:
        for line in lsof_stream(
            protocols=protocols,
            port=args.port,
            pid=args.pid,
            state=args.state,
            resolve_services=args.services,
        ):
            print(line, end="", flush=True)
        sys.exit(0)

    except PermissionError:
        print(
            "Permission denied. Try running with sudo.",
            file=sys.stderr,
        )
        sys.exit(1)

    except KeyboardInterrupt:
        print("\n--- lsof interrupted ---")
        sys.exit(130)


if __name__ == "__main__":
    main()
