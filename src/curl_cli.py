"""Command-line interface for curl (HTTP transfer)."""

import argparse
import sys
from typing import Dict

from .curl import curl_stream


def _parse_header(value: str) -> tuple:
    """Parse a 'Key: Value' header string."""
    if ":" not in value:
        raise argparse.ArgumentTypeError(f"invalid header (missing ':'): {value!r}")
    k, v = value.split(":", 1)
    return k.strip(), v.strip()


def main():
    """Main entry point for the netcurl CLI."""
    parser = argparse.ArgumentParser(
        prog="netcurl",
        description=(
            "Transfer data from a URL " "(curl-like functionality using raw sockets)."
        ),
    )
    parser.add_argument(
        "url",
        help="The URL to request",
    )
    parser.add_argument(
        "-X",
        "--request",
        default="GET",
        metavar="METHOD",
        help="HTTP method (default: GET)",
    )
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        metavar="'Key: Value'",
        help="Add a request header (can be repeated)",
    )
    parser.add_argument(
        "-d",
        "--data",
        default=None,
        metavar="DATA",
        help=("Request body data (sets method to POST " "if -X is not specified)"),
    )
    parser.add_argument(
        "-I",
        "--head",
        action="store_true",
        help="Fetch headers only (HEAD request)",
    )
    parser.add_argument(
        "-i",
        "--include",
        action="store_true",
        help="Include response headers in the output",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output (show request/response headers)",
    )
    parser.add_argument(
        "-L",
        "--location",
        action="store_true",
        help="Follow redirects",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        metavar="FILE",
        help="Write body output to FILE instead of stdout",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=30,
        help="Timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "-s",
        "--silent",
        action="store_true",
        help="Silent mode (suppress progress/error messages)",
    )

    args = parser.parse_args()

    # Parse headers
    extra_headers: Dict[str, str] = {}
    for h in args.header:
        try:
            k, v = _parse_header(h)
            extra_headers[k] = v
        except argparse.ArgumentTypeError as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)

    # If -d is given without -X, default to POST
    method = args.request
    if args.data is not None and method == "GET":
        method = "POST"

    output_file = None
    try:
        if args.output:
            output_file = open(args.output, "w", encoding="utf-8")

        for line in curl_stream(
            args.url,
            method=method,
            headers=extra_headers or None,
            data=args.data,
            timeout=args.timeout,
            head_only=args.head,
            include_headers=args.include,
            verbose=args.verbose,
            follow_redirects=args.location,
        ):
            if output_file:
                # Only write body lines (not verbose/header)
                if not line.startswith(("> ", "< ", "* ")):
                    output_file.write(line)
            else:
                print(line, end="", flush=True)

        sys.exit(0)

    except KeyboardInterrupt:
        if not args.silent:
            print("\n--- curl interrupted ---")
        sys.exit(130)

    except Exception as exc:
        if not args.silent:
            print(f"curl: {exc}", file=sys.stderr)
        sys.exit(1)

    finally:
        if output_file:
            output_file.close()


if __name__ == "__main__":
    main()
