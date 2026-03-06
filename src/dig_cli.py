"""Command-line interface for DNS lookup (dig-like)."""

import argparse
import sys

from .dig import dig_stream


def main():
    """Main entry point for the netdig CLI."""
    parser = argparse.ArgumentParser(
        prog="netdig",
        description="DNS lookup utility (dig-like functionality).",
    )
    parser.add_argument(
        "domain",
        help="The domain name to query",
    )
    parser.add_argument(
        "record_type",
        nargs="?",
        default="A",
        help=(
            "DNS record type to query (default: A). "
            "Options: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA"
        ),
    )
    parser.add_argument(
        "-s",
        "--server",
        default=None,
        help="DNS server to query (default: system resolver)",
    )

    args = parser.parse_args()

    try:
        for line in dig_stream(args.domain, args.record_type, args.server):
            print(line, end="", flush=True)
        sys.exit(0)
    except KeyboardInterrupt:
        print("\n--- dig interrupted ---")
        sys.exit(130)


if __name__ == "__main__":
    main()
