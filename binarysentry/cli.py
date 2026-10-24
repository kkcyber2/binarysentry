"""Command line interface for binarysentry."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analysis import Severity, analyze
from .formats import BinaryParseError, detect, parse

_ICON = {
    Severity.HIGH: "HIGH  ",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW   ",
    Severity.INFO: "INFO  ",
}


def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n}B"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="binarysentry",
        description="Inspect a binary's real format, structure and risk indicators.",
    )
    parser.add_argument("target", help="binary file to inspect")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--quiet", action="store_true", help="summary line only")
    parser.add_argument("--sections", action="store_true", help="list every section")
    parser.add_argument("--fail-on", choices=["high", "medium", "low"], default=None,
                        help="exit 1 when a finding at this level or above is present")
    args = parser.parse_args(argv)

    path = Path(args.target)
    if not path.is_file():
        print(f"error: no such file: {path}", file=sys.stderr)
        return 2

    data = path.read_bytes()
    analysis = analyze(data, filename=path.name)

    if args.json:
        print(json.dumps(analysis.to_dict(), indent=2))
    elif args.quiet:
        print(f"{analysis.verdict.value.upper()} {analysis.info.fmt.value} "
              f"{len(analysis.indicators)} indicator(s)")
    else:
        _print_human(analysis, path, len(data), show_sections=args.sections)

    if args.fail_on:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH]
        threshold = order.index(Severity(args.fail_on))
        if any(order.index(i.severity) >= threshold for i in analysis.indicators):
            return 1
    return 0


def _print_human(analysis, path: Path, size: int, show_sections: bool) -> None:
    info = analysis.info
    print(f"{path.name}  ({_fmt_size(size)})")
    print(f"  format   {info.fmt.value.upper()}")
    if info.arch:
        bits = f", {info.bits}-bit" if info.bits else ""
        endian = f", {info.endian}-endian" if info.endian else ""
        print(f"  arch     {info.arch}{bits}{endian}")
    if info.entry_point:
        print(f"  entry    0x{info.entry_point:x}")
    print(f"  sections {len(info.sections)}")

    if show_sections and info.sections:
        print()
        for section in info.sections:
            flags = ("X" if section.executable else "-") + ("W" if section.writable else "-")
            print(f"    {flags}  {section.name:<20} {section.raw_size:>9} "
                  f"entropy {section.entropy:4.2f}")

    if analysis.indicators:
        print()
        for indicator in analysis.indicators:
            print(f"  {_ICON[indicator.severity]} {indicator.message}")
            if indicator.detail:
                for part in indicator.detail.split("; "):
                    print(f"          {part}")

    print()
    verdict = analysis.verdict.value.upper()
    print(f"verdict: {verdict}")
    if analysis.suspicious:
        print("This binary has findings that warrant manual review before execution.")


if __name__ == "__main__":
    raise SystemExit(main())
