"""Command-line interface for traceroute."""

import argparse
import sys

from .traceroute import traceroute_stream


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="nettraceroute",
        description="Trace the route packets take to reach a host.",
    )
    parser.add_argument(
        "host",
        help="The hostname or IP address to trace",
    )
    parser.add_argument(
        "-m",
        "--max-hops",
        type=int,
        default=30,
        help="Maximum number of hops (default: 30)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=3,
        help="Timeout in seconds for each probe (default: 3)",
    )
    parser.add_argument(
        "-q",
        "--probes",
        type=int,
        default=3,
        help="Number of probes per hop (default: 3)",
    )

    args = parser.parse_args()

    try:
        for line in traceroute_stream(
            args.host,
            max_hops=args.max_hops,
            timeout=args.timeout,
            probes=args.probes,
        ):
            print(line, end="", flush=True)
        sys.exit(0)

    except KeyboardInterrupt:
        print("\n--- traceroute interrupted ---")
        sys.exit(130)


if __name__ == "__main__":
    main()
