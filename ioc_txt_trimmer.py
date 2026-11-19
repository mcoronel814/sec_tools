#!/usr/bin/env python3
"""
Normalize an IOC list text file for proxy / firewall blocklists:
  - Strip whitespace, comments, and anything after the first token
  - Light-refang defanged URLs (hxxps, [.] …)
  - URLs → hostname (FQDN or IP), EXCEPT when the host is on the
    shared/legit platform list (then the URL is kept)
  - A shared or exact platform name with no path is left out of the file
  - Lowercase
  - Deduplicate (order preserved)
  - Write results back to the same file (in-place)

Usage:
  python3 ioc_txt_trimmer.py
  python3 ioc_txt_trimmer.py path/to/iocs.txt
  python3 ioc_txt_trimmer.py --keep-urls          # never collapse URLs
  python3 ioc_txt_trimmer.py --hosts-only         # collapse URLs, still
                                                  # protect platform names
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_INPUT = "ioc.txt"
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_SHARED = SCRIPT_DIR / "lists" / "shared_hosts.txt"
LOCAL_SHARED = SCRIPT_DIR / "lists" / "shared_hosts.local.txt"
DEFAULT_EXACT = SCRIPT_DIR / "lists" / "never_block_exact.txt"

_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_HOST_PATH_RE = re.compile(
    r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?/.",
)


def load_host_lines(path: Path) -> set[str]:
    hosts: set[str] = set()
    if not path.is_file():
        return hosts
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        hosts.add(line.lower().rstrip("."))
    return hosts


def load_shared_hosts(extra_path: Path | None) -> set[str]:
    hosts: set[str] = set()
    paths = [DEFAULT_SHARED, LOCAL_SHARED]
    if extra_path is not None:
        paths.append(extra_path)
    for path in paths:
        hosts.update(load_host_lines(path))
    return hosts


def load_exact_platform_names() -> set[str]:
    """Hostnames that must never be the entire indicator.

    A tenant under one of these (evil.workers.dev) is still allowed.
    The name itself (workers.dev, cdn.jsdelivr.net) is not.
    """
    return load_host_lines(DEFAULT_EXACT)


def is_shared_host(host: str, shared: set[str]) -> bool:
    """True if host is listed, or is a subdomain of a listed parent."""
    host = host.lower().rstrip(".")
    if not host or not shared:
        return False
    if host in shared:
        return True
    labels = host.split(".")
    for i in range(1, len(labels)):
        if ".".join(labels[i:]) in shared:
            return True
    return False


def host_without_port(token: str) -> str:
    """Drop a numeric :port from a bare hostname. Leave every other token."""
    host, sep, port = token.rpartition(":")
    if sep and host and port.isdigit() and ":" not in host:
        return host
    return token


def is_exact_platform_name(host: str, exact: set[str]) -> bool:
    return host.lower().rstrip(".") in exact


def is_protected_platform(host: str, shared: set[str], exact: set[str]) -> bool:
    """True when writing this hostname would block a shared service."""
    host = host.lower().rstrip(".")
    if is_exact_platform_name(host, exact):
        return True
    return is_shared_host(host, shared)


def url_has_path(token: str) -> bool:
    """True when the URL carries a path, query, or fragment beyond the host."""
    candidate = token
    if candidate.startswith("//"):
        candidate = "http:" + candidate
    elif "://" not in candidate:
        candidate = "http://" + candidate
    parsed = urlparse(candidate)
    if parsed.query or parsed.fragment:
        return True
    path = parsed.path or ""
    return path not in ("", "/")


def refang(token: str) -> str:
    t = token
    for a, b in (
        ("hxxps://", "https://"),
        ("hxxp://", "http://"),
        ("fxps://", "ftps://"),
        ("fxp://", "ftp://"),
        ("[.]" , "."),
        ("(.)", "."),
        ("{.}", "."),
        ("[:]", ":"),
        ("[/]", "/"),
    ):
        t = t.replace(a, b)
        t = t.replace(a.upper(), b)
    return t


def is_hash(token: str) -> bool:
    return bool(_HASH_RE.fullmatch(token))


def is_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def looks_like_url(token: str) -> bool:
    low = token.lower()
    if "://" in low:
        return True
    if low.startswith("//") and "/" in low[2:]:
        return True
    # scheme-less host/path (dub.sh/abc, example.com/login)
    if _HOST_PATH_RE.match(token):
        return True
    return False


def url_hostname(token: str) -> str | None:
    """Return hostname (no port) from a URL-like token, or None."""
    candidate = token
    if candidate.startswith("//"):
        candidate = "http:" + candidate
    elif "://" not in candidate:
        candidate = "http://" + candidate
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").strip().rstrip(".")
    if not host:
        return None
    return host.lower()


def normalize_url(token: str) -> str:
    """Keep as URL: lowercase, drop trailing slash (except scheme-only)."""
    t = token
    if t.endswith("/") and t.count("/") > 2:
        t = t.rstrip("/")
    return t.lower()


def normalize_token(
    raw_token: str,
    shared: set[str],
    mode: str,
    exact: set[str] | None = None,
) -> tuple[str, str | None]:
    """
    Return (normalized_value, warning_or_None).

    An empty value with a ``refused platform name`` warning means the
    indicator was held back and must not be written.
    mode: 'hybrid' | 'keep-urls' | 'hosts-only'
    """
    exact = exact if exact is not None else set()
    token = refang(raw_token.strip())
    if not token:
        return "", None

    if is_hash(token) or is_ip(token):
        return token.lower(), None

    if not looks_like_url(token):
        bare = token.lower().rstrip(".")
        host = host_without_port(bare)
        if is_protected_platform(host, shared, exact):
            return "", f"refused platform name: {host}"
        return bare, None

    host = url_hostname(token)
    if not host:
        return token.lower(), None

    if is_protected_platform(host, shared, exact):
        if url_has_path(token):
            kept = normalize_url(token)
            return kept, f"kept URL (shared host {host}): {kept}"
        return "", f"refused platform name: {host}"

    if mode == "keep-urls":
        return normalize_url(token), None

    # hybrid and hosts-only. Platform names are already handled above,
    # including in hosts-only, so a CDN host is not written from this branch.
    return host, None


def process_file(
    file_path: str,
    shared: set[str],
    mode: str,
    exact: set[str] | None = None,
) -> int:
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as file:
            lines = file.readlines()
    except FileNotFoundError:
        print(
            f"Error: '{file_path}' not found.\n"
            f"  cp examples/ioc.txt.example {file_path}\n"
            "  Then paste IOCs (one per line) and re-run.",
            file=sys.stderr,
        )
        return 1

    exact = exact if exact is not None else set()
    unique_results: set[str] = set()
    processed_lines: list[str] = []
    kept_url = 0
    collapsed = 0
    other = 0
    refused = 0

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        first = line.split(None, 1)[0]
        result, note = normalize_token(first, shared, mode, exact)
        if not result:
            if note:
                print(note, file=sys.stderr)
                refused += 1
            continue
        if note:
            print(note, file=sys.stderr)
            kept_url += 1
        elif looks_like_url(refang(first)) and result != normalize_url(refang(first)):
            collapsed += 1
        else:
            other += 1
        if result not in unique_results:
            unique_results.add(result)
            print(result)
            processed_lines.append(result + "\n")

    with open(file_path, "w", encoding="utf-8") as file:
        file.writelines(processed_lines)

    print(
        f"\nWrote {len(processed_lines)} unique IOC(s) to {file_path}"
        f"  (collapsed URLs→host: {collapsed}, kept URLs: {kept_url},"
        f" other: {other}, refused platform names: {refused})",
        file=sys.stderr,
    )
    if refused:
        print(
            "Those platform names were left out of the file. "
            "Writing them would block the whole service.",
            file=sys.stderr,
        )
    if mode == "hybrid" and not shared:
        print(
            "Warning: shared-host list is empty — every URL was collapsed to a hostname.",
            file=sys.stderr,
        )
    if refused:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Trim, lowercase, and dedupe an IOC text file in place. "
            "URLs become hostnames unless the host is on the shared/legit list. "
            "A platform name with no path is left out of the file."
        ),
    )
    parser.add_argument(
        "file_path",
        nargs="?",
        default=DEFAULT_INPUT,
        help=f"IOC list to process (default: {DEFAULT_INPUT})",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--keep-urls",
        action="store_true",
        help="Never collapse URLs to hostnames (safest, noisiest).",
    )
    mode.add_argument(
        "--hosts-only",
        action="store_true",
        help=(
            "Collapse URLs to hostnames. A platform name is still kept as a "
            "URL when it has a path, and left out when it does not."
        ),
    )
    parser.add_argument(
        "--shared-hosts",
        type=Path,
        default=None,
        help="Extra shared-host file (merged with lists/shared_hosts.txt).",
    )
    args = parser.parse_args(argv)

    if args.keep_urls:
        run_mode = "keep-urls"
    elif args.hosts_only:
        run_mode = "hosts-only"
    else:
        run_mode = "hybrid"

    extra = args.shared_hosts
    if extra is not None and not extra.is_file():
        print(f"Error: shared-hosts file '{extra}' not found.", file=sys.stderr)
        return 1

    shared = load_shared_hosts(extra)
    exact = load_exact_platform_names()
    if not DEFAULT_EXACT.is_file():
        print(
            f"Warning: '{DEFAULT_EXACT.name}' was not found. "
            "Exact platform names will not be refused.",
            file=sys.stderr,
        )
    return process_file(args.file_path, shared, run_mode, exact)


if __name__ == "__main__":
    sys.exit(main())
