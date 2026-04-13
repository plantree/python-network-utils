"""Command-line interface for nmap (TCP connect port scanner).

Mirrors nmap-style output::

    netnmap -p 22,80,443 scanme.nmap.org
    netnmap --top-ports 100 example.com
"""

import argparse
import sys

from nmap import DEFAULT_TIMEOUT, MAX_CONCURRENT, nmap_stream


def main() -> None:
    """Main entry point for the netnmap CLI."""
    parser = argparse.ArgumentParser(
        prog="netnmap",
        description="Python-based port scanner (nmap-style TCP connect scan)",
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
        help=f"Timeout per connection attempt in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--max-concurrent",
        type=int,
        default=MAX_CONCURRENT,
        help=f"Maximum concurrent connections (default: {MAX_CONCURRENT})",
    )
    args = parser.parse_args()

    try:
        for line in nmap_stream(
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
