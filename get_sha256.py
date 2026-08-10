#!/usr/bin/env python3
"""
Look up file hashes on VirusTotal and print the corresponding SHA-256.

Reads hashes (one per line) from sha1_list.txt by default.
Requires VT_API_KEY in the environment (see .env.example / README).

Usage:
  export VT_API_KEY='...'
  python3 get_sha256.py
  python3 get_sha256.py path/to/hashes.txt
"""

from __future__ import annotations

import argparse
import os
import sys

import requests

DEFAULT_INPUT = "sha1_list.txt"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Resolve file hashes to SHA-256 via VirusTotal.",
    )
    parser.add_argument(
        "hash_file",
        nargs="?",
        default=DEFAULT_INPUT,
        help=f"Text file with one hash per line (default: {DEFAULT_INPUT})",
    )
    args = parser.parse_args(argv)

    api_key = os.environ.get("VT_API_KEY", "").strip()
    if not api_key:
        print(
            "Error: VT_API_KEY is not set.\n"
            "  export VT_API_KEY='your_key'\n"
            "See .env.example and README.md.",
            file=sys.stderr,
        )
        return 1

    try:
        with open(args.hash_file, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(
            f"Error: '{args.hash_file}' not found.\n"
            f"  cp sha1_list.txt.example {args.hash_file}\n"
            "  Then paste hashes (one per line) and re-run.",
            file=sys.stderr,
        )
        return 1

    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }

    found = 0
    missing = 0
    for line in lines:
        file_hash_id = line.strip()
        if not file_hash_id or file_hash_id.startswith("#"):
            continue

        url = f"https://www.virustotal.com/api/v3/files/{file_hash_id}"
        try:
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code != 200:
                print(f"hash not found at VirusTotal: {file_hash_id}", file=sys.stderr)
                missing += 1
                continue
            converted = response.json()
            print(converted["data"]["attributes"]["sha256"])
            found += 1
        except (KeyError, ValueError, requests.RequestException):
            print(f"hash not found at VirusTotal: {file_hash_id}", file=sys.stderr)
            missing += 1

    if found == 0 and missing == 0:
        print(f"No hashes to process in '{args.hash_file}'.", file=sys.stderr)
        return 1
    return 0 if missing == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
