"""Command-line interface for nmap SYN (half-open) port scanner.

Mirrors nmap-style output::

    sudo netnmap-syn scanme.nmap.org
    sudo netnmap-syn -p 22,80,443 example.com
    sudo netnmap-syn --top-ports 100 example.com
"""

import argparse
import os
import sys

from .nmap import DEFAULT_TIMEOUT, MAX_CONCURRENT
from .nmap_syn import nmap_syn_stream


def main() -> None:
    """Main entry point for the netnmap-syn CLI."""
    if os.geteuid() != 0:
        print(
            "Error: SYN scanning requires root privileges. Run with sudo.",
            file=sys.stderr,
        )
        sys.exit(1)

    parser = argparse.ArgumentParser(
        prog="netnmap-syn",
        description="TCP SYN (half-open) port scanner (requires root)",
    )
    parser.add_argument("target", help="Target host or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        help="Port specification (e.g. 22,80,443 or 1-1000 or 22,80,100-200)",
    )
    parser.add_argument(
        "--top-ports",
        type=int,
        metavar="N",
        help="Scan the N most common ports",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Timeout per batch in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--max-concurrent",
        type=int,
        default=MAX_CONCURRENT,
        help=f"Ports per batch (default: {MAX_CONCURRENT})",
    )
    args = parser.parse_args()

    try:
        for line in nmap_syn_stream(
            args.target,
            ports=args.ports,
            top_ports=args.top_ports,
            timeout=args.timeout,
            max_concurrent=args.max_concurrent,
        ):
            print(line, end="", flush=True)
    except KeyboardInterrupt:
        print("\n--- scan interrupted ---")
        sys.exit(130)


if __name__ == "__main__":
    main()
