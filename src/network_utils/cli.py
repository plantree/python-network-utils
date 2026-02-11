"""Command-line interface for network utilities."""

import argparse
import sys

from .ping import ping_stream


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="netping",
        description="Ping a host and display statistics.",
    )
    parser.add_argument(
        "host",
        help="The hostname or IP address to ping",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=4,
        help="Number of ping requests to send (default: 4)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=5,
        help="Timeout in seconds for each ping (default: 5)",
    )

    args = parser.parse_args()

    try:
        exit_code = 0
        for line in ping_stream(args.host, count=args.count, timeout=args.timeout):
            print(line, end="", flush=True)
        sys.exit(exit_code)

    except FileNotFoundError:
        print("Error: ping command not found")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n--- ping interrupted ---")
        sys.exit(130)


if __name__ == "__main__":
    main()
