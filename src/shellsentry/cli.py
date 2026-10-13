"""Command-line entry point for ShellSentry-AI."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from .core import AuditEngine


def _port_number(value: str) -> int:
    port = int(value)
    if not 0 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 0 and 65535")
    return port


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="shellsentry")
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser("scan", help="scan a local file without executing it")
    scan.add_argument("path", type=Path)
    scan.add_argument("--output", "-o", type=Path)

    serve = subcommands.add_parser("serve", help="start the local web interface")
    serve.add_argument("--port", type=_port_number, default=8765,
                       help="preferred local port (default: 8765; 0 selects a random port)")
    serve.add_argument("--no-browser", action="store_true",
                       help="do not open the web interface automatically")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "serve":
        from .web.app import main as serve

        asyncio.run(serve(port=args.port, open_browser=not args.no_browser))
        return 0

    result = AuditEngine().audit_path(args.path)
    output = json.dumps(result.to_dict(), ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    return 0 if result.success else 1
