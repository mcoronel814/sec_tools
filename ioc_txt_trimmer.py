#!/usr/bin/env python3
"""
Normalize an IOC list text file:
  - Strip whitespace
  - Keep only the first token on each line
  - Lowercase
  - Deduplicate (order preserved)
  - Write results back to the same file (in-place)

Usage:
  python3 ioc_txt_trimmer.py              # processes ioc.txt
  python3 ioc_txt_trimmer.py path/to/iocs.txt
"""

from __future__ import annotations

import argparse
import sys

DEFAULT_INPUT = "ioc.txt"


def process_file(file_path: str) -> int:
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as file:
            lines = file.readlines()
    except FileNotFoundError:
        print(
            f"Error: '{file_path}' not found.\n"
            f"  cp ioc.txt.example {file_path}\n"
            "  Then paste IOCs (one per line) and re-run.",
            file=sys.stderr,
        )
        return 1

    unique_results: set[str] = set()
    processed_lines: list[str] = []

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        result = line.split(None, 1)[0].lower()
        if result not in unique_results:
            unique_results.add(result)
            print(result)
            processed_lines.append(result + "\n")

    with open(file_path, "w", encoding="utf-8") as file:
        file.writelines(processed_lines)

    print(f"\nWrote {len(processed_lines)} unique IOC(s) to {file_path}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Trim, lowercase, and dedupe an IOC text file in place.",
    )
    parser.add_argument(
        "file_path",
        nargs="?",
        default=DEFAULT_INPUT,
        help=f"IOC list to process (default: {DEFAULT_INPUT})",
    )
    args = parser.parse_args(argv)
    return process_file(args.file_path)


if __name__ == "__main__":
    sys.exit(main())
