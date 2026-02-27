"""Command-line interface for ifconfig."""

import argparse
import sys

from .ifconfig import ifconfig_stream


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="netifconfig",
        description="Display network interface configuration.",
    )
    parser.add_argument(
        "interface",
        nargs="?",
        default=None,
        help="Specific interface to display (default: all interfaces)",
    )

    args = parser.parse_args()

    try:
        for line in ifconfig_stream(args.interface):
            print(line, end="", flush=True)
        sys.exit(0)

    except KeyboardInterrupt:
        print("\n--- ifconfig interrupted ---")
        sys.exit(130)


if __name__ == "__main__":
    main()
