"""Command-line interface for wrk (HTTP benchmarking).

Mirrors the real ``wrk`` CLI as closely as possible::

    netwrk -t4 -c100 -d10s http://localhost:8080
"""

import argparse
import sys
from typing import Dict

from .wrk import _parse_duration, wrk_stream


def main() -> None:
    """Main entry point for the netwrk CLI."""
    parser = argparse.ArgumentParser(
        prog="netwrk",
        description="HTTP benchmarking tool (wrk-compatible output).",
        usage="netwrk <options> <url>",
    )
    parser.add_argument(
        "url",
        help="Target URL to benchmark",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=2,
        metavar="N",
        help="Number of threads to use (default: 2)",
    )
    parser.add_argument(
        "-c",
        "--connections",
        type=int,
        default=10,
        metavar="N",
        help="Number of connections to keep open (default: 10)",
    )
    parser.add_argument(
        "-d",
        "--duration",
        default="10s",
        metavar="T",
        help="Duration of test, e.g. 2s, 2m, 2h (default: 10s)",
    )
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        metavar="'Header: Value'",
        help="Add a header (can be repeated)",
    )
    parser.add_argument(
        "--timeout",
        default="2s",
        metavar="T",
        help="Socket timeout, e.g. 2s, 500ms (default: 2s)",
    )
    parser.add_argument(
        "--latency",
        action="store_true",
        help="Print latency distribution",
    )

    args = parser.parse_args()

    # Parse duration
    try:
        duration_sec = _parse_duration(args.duration)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)

    try:
        timeout_sec = _parse_duration(args.timeout)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)

    # Parse headers
    extra_headers: Dict[str, str] = {}
    for h in args.header:
        if ":" not in h:
            print(
                f"invalid header (missing ':'): {h!r}",
                file=sys.stderr,
            )
            sys.exit(1)
        k, v = h.split(":", 1)
        extra_headers[k.strip()] = v.strip()

    try:
        for line in wrk_stream(
            args.url,
            threads=args.threads,
            connections=args.connections,
            duration=duration_sec,
            timeout=timeout_sec,
            headers=extra_headers or None,
            latency=args.latency,
        ):
            print(line, end="", flush=True)
        sys.exit(0)

    except KeyboardInterrupt:
        print("\n--- benchmark interrupted ---")
        sys.exit(130)

    except Exception as exc:
        print(f"netwrk: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
