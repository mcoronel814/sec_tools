#!/usr/bin/env python3
"""
Look up file hashes on VirusTotal and print the corresponding SHA-256.

Reads hashes (one per line) from sha1_list.txt by default.

API key (first match wins):
  1. Environment variable VT_API_KEY (e.g. export VT_API_KEY='...')
  2. A local .env file in the current directory or next to this script
     (see .env.example — copy to .env and put your key there)

Usage:
  cp .env.example .env          # once
  # edit .env → VT_API_KEY=...
  python3 get_sha256.py
  python3 get_sha256.py path/to/hashes.txt
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import requests

DEFAULT_INPUT = "sha1_list.txt"
SCRIPT_DIR = Path(__file__).resolve().parent


def load_dotenv_file(path: Path) -> None:
    """
    Minimal .env loader (no extra packages).
    Does not override variables already set in the environment.
    """
    if not path.is_file():
        return
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.lower().startswith("export "):
            line = line[7:].strip()
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        # Strip optional matching quotes
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        if key not in os.environ:
            os.environ[key] = value


def load_api_key() -> str:
    """Load VT_API_KEY from the environment and/or a local .env file."""
    # Prefer cwd .env, then script-directory .env (so it works from any cwd)
    load_dotenv_file(Path.cwd() / ".env")
    load_dotenv_file(SCRIPT_DIR / ".env")
    return os.environ.get("VT_API_KEY", "").strip()


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

    api_key = load_api_key()
    if not api_key:
        print(
            "Error: VT_API_KEY is not set.\n"
            "\n"
            "Easiest (recommended):\n"
            "  1. cp .env.example .env\n"
            "  2. Edit .env and set:  VT_API_KEY=your_actual_key\n"
            "  3. python3 get_sha256.py\n"
            "\n"
            "Alternative (current shell only — does NOT create a .env file):\n"
            "  export VT_API_KEY='your_actual_key'\n"
            "  python3 get_sha256.py\n",
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
