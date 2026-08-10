#!/usr/bin/env python3
"""
Local email header analyzer for security analysts.

Focus: spoofing / auth alignment (SPF, DKIM, DMARC), address mismatches,
Received path anomalies, and common gateway reputation signals.

Usage:
  python3 email_header_spoofing_analyzer.py              # reads header.txt in cwd
  python3 email_header_spoofing_analyzer.py header.txt
  python3 email_header_spoofing_analyzer.py -            # stdin
  cat header.txt | python3 email_header_spoofing_analyzer.py -
  python3 email_header_spoofing_analyzer.py header.txt --json
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from email.parser import BytesParser
from email.policy import default
from email.utils import parseaddr
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


@dataclass
class Finding:
    severity: str  # INFO | LOW | MEDIUM | HIGH
    category: str
    message: str


@dataclass
class AnalysisResult:
    subject: str = ""
    from_display: str = ""
    from_addr: str = ""
    from_domain: str = ""
    return_path: str = ""
    return_domain: str = ""
    reply_to: str = ""
    reply_to_domain: str = ""
    sender: str = ""
    to_addrs: str = ""
    message_id: str = ""
    date: str = ""
    findings: list[Finding] = field(default_factory=list)
    auth_results_raw: list[str] = field(default_factory=list)
    spf: list[dict[str, Any]] = field(default_factory=list)
    dkim: list[dict[str, Any]] = field(default_factory=list)
    dmarc: list[dict[str, Any]] = field(default_factory=list)
    hops: list[dict[str, Any]] = field(default_factory=list)
    gateway: dict[str, Any] = field(default_factory=dict)
    max_severity: str = "INFO"

    def add(self, severity: str, category: str, message: str) -> None:
        self.findings.append(Finding(severity, category, message))
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(self.max_severity, 0):
            self.max_severity = severity


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def parse_header_bytes(data: bytes):
    """Parse raw header bytes into Message + decoded text."""
    parser = BytesParser(policy=default)
    headers = parser.parsebytes(data)
    raw_text = data.decode("utf-8", errors="replace")
    return headers, raw_text


def load_input(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    with open(path, "rb") as f:
        return f.read()


def extract_address(value: Optional[str]) -> tuple[str, str, str]:
    """
    Return (display_name, email_address, domain) from a header value.
    """
    if not value:
        return "", "", ""
    # Flatten whitespace (folded/multiline Return-Path etc.)
    cleaned = " ".join(str(value).split())
    name, addr = parseaddr(cleaned)
    addr = (addr or "").strip().lower()
    # Fallback if parseaddr fails on odd formats
    if not addr:
        m = re.search(r"[\w.+/=-]+@[\w.-]+\.\w+", cleaned, re.I)
        if m:
            addr = m.group(0).lower()
    domain = addr.rsplit("@", 1)[-1] if "@" in addr else ""
    return (name or "").strip(), addr, domain.lower()


def org_domain(domain: str) -> str:
    """
    Cheap organizational-domain approximation (no public-suffix list).
    Good enough for common cases (example.com, mail.example.com).
    Multi-part TLDs (co.uk) may be imperfect — noted in report when relevant.
    """
    if not domain:
        return ""
    parts = domain.lower().strip(".").split(".")
    if len(parts) <= 2:
        return domain.lower()
    # Heuristic for a few common multi-part public suffixes
    multi = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au",
             "co.nz", "co.jp", "com.br", "co.in", "com.mx"}
    last_two = ".".join(parts[-2:])
    if last_two in multi and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def domains_align(a: str, b: str, relaxed: bool = True) -> bool:
    """DMARC-style alignment: exact match, or same org domain if relaxed."""
    if not a or not b:
        return False
    a, b = a.lower(), b.lower()
    if a == b:
        return True
    if relaxed:
        return org_domain(a) == org_domain(b)
    return False


def classify_ip(ip_str: str) -> str:
    """
    Classify an IP for path analysis.
    Prefer is_global for "public" (routable Internet); RFC1918/etc. as private.
    Documentation/benchmark ranges land in "special" (not treated as org-internal).
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "invalid"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    # Globally reachable unicast — use for "originating public hop"
    if ip.is_global:
        return "public"
    # RFC1918, ULA, CGNAT, etc.
    if ip.is_private:
        return "private"
    return "special"


# IPv4 and simplified IPv6 in [] or ()
_IP_PATTERNS = [
    re.compile(
        r"\[("
        r"(?:\d{1,3}\.){3}\d{1,3}"
        r"|"
        r"[0-9a-fA-F:]+"
        r")\]"
    ),
    re.compile(
        r"\(("
        r"(?:\d{1,3}\.){3}\d{1,3}"
        r")\)"
    ),
]


def extract_ips_from_received(line: str) -> list[str]:
    found: list[str] = []
    for pat in _IP_PATTERNS:
        for m in pat.finditer(line):
            candidate = m.group(1)
            try:
                ipaddress.ip_address(candidate)
                if candidate not in found:
                    found.append(candidate)
            except ValueError:
                continue
    return found


def extract_helo(line: str) -> str:
    m = re.search(r"\bHELO\s+([^\s\)]+)", line, re.I)
    if m:
        return m.group(1).rstrip(";")
    m = re.search(r"\bEHLO\s+([^\s\)]+)", line, re.I)
    if m:
        return m.group(1).rstrip(";")
    return ""


def extract_received_hops(headers, raw_header: str) -> list[str]:
    """
    Prefer parser get_all('Received') (unfolded). Fall back to raw regex.
    Order: most recent first (typical top-of-header order after get_all).
    """
    hops = headers.get_all("Received") or []
    if hops:
        # get_all returns most recent first for standard dumps
        return [f"Received: {h}" if not str(h).lower().startswith("received:") else str(h)
                for h in hops]

    received_lines = re.findall(
        r"^Received:.*?(?=\n(?:[^ \t]|$))",
        raw_header,
        re.MULTILINE | re.DOTALL,
    )
    return list(reversed(received_lines))


# ---------------------------------------------------------------------------
# Authentication-Results parsing
# ---------------------------------------------------------------------------

def _split_ar_methods(ar_value: str) -> list[str]:
    """
    Split Authentication-Results into method result chunks after the authserv-id.
    Format: authserv-id; method=result ...; method=result ...
    """
    text = " ".join(str(ar_value).split())
    # Drop authserv-id (first token before first ';')
    if ";" in text:
        text = text.split(";", 1)[1]
    parts = re.split(r";\s*", text)
    return [p.strip() for p in parts if p.strip()]


def parse_auth_results(headers) -> tuple[list[dict], list[dict], list[dict], list[str]]:
    """
    Parse all Authentication-Results headers into spf/dkim/dmarc dicts.
    Also returns raw AR strings for the report.
    """
    spf_list: list[dict] = []
    dkim_list: list[dict] = []
    dmarc_list: list[dict] = []
    raw_list: list[str] = []

    ar_headers = headers.get_all("Authentication-Results") or []
    for ar in ar_headers:
        ar_s = " ".join(str(ar).split())
        raw_list.append(ar_s)
        for chunk in _split_ar_methods(ar_s):
            low = chunk.lower()

            # SPF: spf=pass smtp.mailfrom=...  OR  spf=fail (reason)
            if low.startswith("spf="):
                m = re.match(
                    r"spf=(\w+)(?:\s*\(([^)]*)\))?(.*)$",
                    chunk,
                    re.I,
                )
                if not m:
                    continue
                result, reason, rest = m.group(1), m.group(2) or "", m.group(3) or ""
                mailfrom = ""
                helo = ""
                mf = re.search(r"smtp\.mailfrom=([^\s;]+)", rest, re.I)
                if mf:
                    mailfrom = mf.group(1).strip("<>")
                hh = re.search(r"smtp\.helo=([^\s;]+)", rest, re.I)
                if hh:
                    helo = hh.group(1).strip("<>")
                # Sometimes HELO is encoded as postmaster@host
                identity = "mailfrom" if mailfrom else ("helo" if helo else "unknown")
                if helo and not mailfrom and "helo" in rest.lower():
                    identity = "helo"
                if "smtp.helo=" in rest.lower() and "smtp.mailfrom=" not in rest.lower():
                    identity = "helo"
                spf_list.append({
                    "source": "Authentication-Results",
                    "result": result.lower(),
                    "identity": identity,
                    "mailfrom": mailfrom.lower() if mailfrom else "",
                    "helo": helo,
                    "reason": reason,
                    "raw": chunk,
                })

            # DKIM
            elif low.startswith("dkim="):
                m = re.match(
                    r"dkim=(\w+)(?:\s*\(([^)]*)\))?(.*)$",
                    chunk,
                    re.I,
                )
                if not m:
                    continue
                result, reason, rest = m.group(1), m.group(2) or "", m.group(3) or ""
                header_i = ""
                header_d = ""
                hi = re.search(r"header\.i=([^\s;]+)", rest, re.I)
                if hi:
                    header_i = hi.group(1).strip()
                hd = re.search(r"header\.d=([^\s;]+)", rest, re.I)
                if hd:
                    header_d = hd.group(1).strip().lower()
                # Domain from i= (user@domain or @domain)
                dkim_domain = header_d
                if not dkim_domain and header_i:
                    if "@" in header_i:
                        dkim_domain = header_i.rsplit("@", 1)[-1].lower()
                    else:
                        dkim_domain = header_i.lstrip("@").lower()
                dkim_list.append({
                    "source": "Authentication-Results",
                    "result": result.lower(),
                    "domain": dkim_domain,
                    "header_i": header_i,
                    "reason": reason,
                    "raw": chunk,
                })

            # DMARC
            elif low.startswith("dmarc="):
                m = re.match(
                    r"dmarc=(\w+)(?:\s*\(([^)]*)\))?(.*)$",
                    chunk,
                    re.I,
                )
                if not m:
                    continue
                result, reason, rest = m.group(1), m.group(2) or "", m.group(3) or ""
                d_domain = ""
                hd = re.search(r"(?:header\.from|d)=([^\s;]+)", rest, re.I)
                if hd:
                    d_domain = hd.group(1).strip().lower()
                # Policy from parenthetical: p=reject dis=none
                policy = ""
                disposition = ""
                pm = re.search(r"\bp=(\w+)", reason, re.I)
                if pm:
                    policy = pm.group(1).lower()
                dm = re.search(r"\bdis=(\w+)", reason, re.I)
                if dm:
                    disposition = dm.group(1).lower()
                dmarc_list.append({
                    "source": "Authentication-Results",
                    "result": result.lower(),
                    "domain": d_domain,
                    "policy": policy,
                    "disposition": disposition,
                    "reason": reason,
                    "raw": chunk,
                })

    return spf_list, dkim_list, dmarc_list, raw_list


def parse_received_spf(headers) -> list[dict]:
    """Parse Received-SPF headers (often more detail than AR)."""
    results: list[dict] = []
    for val in headers.get_all("Received-SPF") or []:
        text = " ".join(str(val).split())
        m = re.match(r"(\w+)\s*(?:\((.*?)\))?(.*)$", text, re.I | re.DOTALL)
        if not m:
            continue
        result = m.group(1).lower()
        details = (m.group(2) or "").strip()
        rest = m.group(3) or ""
        env_from = ""
        identity = ""
        client_ip = ""
        ef = re.search(r'envelope-from="?([^";\s]+)"?', rest, re.I)
        if ef:
            env_from = ef.group(1).strip("<>").lower()
        idm = re.search(r"identity=(\w+)", rest, re.I)
        if idm:
            identity = idm.group(1).lower()
        ipm = re.search(r"client-ip=([^\s;]+)", rest, re.I)
        if ipm:
            client_ip = ipm.group(1).rstrip(";")
        results.append({
            "source": "Received-SPF",
            "result": result,
            "identity": identity or "unknown",
            "mailfrom": env_from,
            "client_ip": client_ip,
            "reason": details[:300],
            "raw": text[:500],
        })
    return results


def parse_vendor_dmarc(headers, raw_header: str) -> list[dict]:
    """IronPort / other vendor DMARC headers if present."""
    out: list[dict] = []
    for name in ("X-IronPort-Dmarc-Check-Result", "X-Ironport-Dmarc-Check-Result"):
        for val in headers.get_all(name) or []:
            text = " ".join(str(val).split())
            m = re.match(r"(\w+)", text, re.I)
            if m:
                out.append({
                    "source": name,
                    "result": m.group(1).lower(),
                    "domain": "",
                    "policy": "",
                    "disposition": "",
                    "reason": text,
                    "raw": text,
                })
    # Fallback raw search
    if not out:
        for m in re.finditer(
            r"X-Ironport-Dmarc-Check-Result:\s*(\w+)",
            raw_header,
            re.I,
        ):
            out.append({
                "source": "X-Ironport-Dmarc-Check-Result",
                "result": m.group(1).lower(),
                "domain": "",
                "policy": "",
                "disposition": "",
                "reason": "",
                "raw": m.group(0),
            })
    return out


def parse_dkim_signatures(headers) -> list[dict]:
    """Extract d= / i= / s= from DKIM-Signature headers (presence, not crypto verify)."""
    sigs = []
    for val in headers.get_all("DKIM-Signature") or []:
        text = " ".join(str(val).split())
        d = re.search(r"(?:^|;)\s*d=([^;]+)", text, re.I)
        i = re.search(r"(?:^|;)\s*i=([^;]+)", text, re.I)
        s = re.search(r"(?:^|;)\s*s=([^;]+)", text, re.I)
        sigs.append({
            "d": (d.group(1).strip() if d else "").lower(),
            "i": (i.group(1).strip() if i else ""),
            "s": (s.group(1).strip() if s else ""),
        })
    return sigs


# ---------------------------------------------------------------------------
# Gateway / MTA signals
# ---------------------------------------------------------------------------

def collect_gateway_signals(headers) -> dict[str, Any]:
    g: dict[str, Any] = {}
    mapping = {
        "ironport_sender_group": "X-IronPort-SenderGroup",
        "ironport_reputation": "X-IronPort-Reputation",
        "ironport_mailflow_policy": "X-IronPort-MailFlowPolicy",
        "ironport_remote_ip": "X-IronPort-RemoteIP",
        "threat_scanner": "X-ThreatScanner-Verdict",
        "ms_scl": "X-MS-Exchange-Organization-SCL",
        "ms_auth_as": "X-MS-Exchange-Organization-AuthAs",
        "ms_auth_source": "X-MS-Exchange-Organization-AuthSource",
        "forefront_antispam": "X-Forefront-Antispam-Report",
        "tm_as_result": "X-TM-AS-Result",
        "amp_result": "X-Amp-Result",
    }
    for key, hdr in mapping.items():
        val = headers.get(hdr)
        if val is not None:
            g[key] = " ".join(str(val).split())
    return g


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

# Higher-signal subject patterns (avoid ultra-generic words like "file"/"review")
SUBJECT_URGENCY = re.compile(
    r"\b("
    r"urgent|immediate|action\s*required|verify\s*your\s*account|"
    r"password\s*(?:reset|expir)|account\s*(?:suspend|locked|compromis)|"
    r"wire\s*transfer|gift\s*card|invoice\s*attached|"
    r"final\s*notice|suspended|confirm\s*(?:your|identity)|"
    r"unusual\s*sign[- ]?in|mailbox\s*(?:full|quot)"
    r")\b",
    re.I,
)
SUBJECT_GATEWAY_TAG = re.compile(
    r"\[?\s*(suspected\s*spam|spam|phish|external|caution|external\s*email)\s*\]?",
    re.I,
)


def analyze(headers, raw_header: str) -> AnalysisResult:
    r = AnalysisResult()

    # --- Core fields ---
    from_raw = headers.get("From")
    r.from_display, r.from_addr, r.from_domain = extract_address(from_raw)
    # Keep original display string for report
    if from_raw:
        r.from_display = r.from_display or ""
        # If parseaddr got name, use it; else leave empty

    rp_raw = headers.get("Return-Path")
    _, r.return_path, r.return_domain = extract_address(rp_raw)

    rt_raw = headers.get("Reply-To") or headers.get("Reply-to")
    _, r.reply_to, r.reply_to_domain = extract_address(rt_raw)

    snd_raw = headers.get("Sender")
    _, r.sender, sender_domain = extract_address(snd_raw)

    r.subject = " ".join(str(headers.get("Subject") or "").split()) or "(none)"
    r.to_addrs = " ".join(str(headers.get("To") or "").split()) or "(none)"
    r.message_id = " ".join(str(headers.get("Message-ID") or headers.get("Message-Id") or "").split())
    r.date = " ".join(str(headers.get("Date") or "").split())

    # --- Auth results ---
    ar_spf, ar_dkim, ar_dmarc, ar_raw = parse_auth_results(headers)
    r.auth_results_raw = ar_raw
    rspf = parse_received_spf(headers)
    r.spf = ar_spf + rspf
    r.dkim = ar_dkim
    r.dmarc = ar_dmarc + parse_vendor_dmarc(headers, raw_header)
    dkim_sigs = parse_dkim_signatures(headers)

    # --- Gateway ---
    r.gateway = collect_gateway_signals(headers)

    # ========== Address / identity checks ==========
    if not r.from_addr:
        r.add("HIGH", "identity", "Missing or unparseable From address")
    else:
        r.add("INFO", "identity", f"From address: {r.from_addr}")

    # Display-name spoofing: name looks like an email or trusted domain text
    if r.from_display and r.from_domain:
        disp = r.from_display.strip().strip('"')
        # Display contains an email that differs from actual From
        embedded = re.findall(r"[\w.+-]+@[\w.-]+\.\w+", disp)
        for emb in embedded:
            emb_dom = emb.rsplit("@", 1)[-1].lower()
            if emb.lower() != r.from_addr and not domains_align(emb_dom, r.from_domain):
                r.add(
                    "HIGH",
                    "identity",
                    f"Display-name spoofing: name contains '{emb}' but actual From is {r.from_addr}",
                )
        # Display name is only a domain-like string different from From domain
        if re.fullmatch(r"[\w.-]+\.[a-z]{2,}", disp, re.I):
            if not domains_align(disp.lower(), r.from_domain):
                r.add(
                    "MEDIUM",
                    "identity",
                    f"Display name looks like domain '{disp}' but From domain is {r.from_domain}",
                )

    # From vs Return-Path
    if r.from_domain and r.return_domain:
        if r.from_domain == r.return_domain:
            r.add("INFO", "identity", "From and Return-Path domains match exactly")
        elif domains_align(r.from_domain, r.return_domain):
            r.add(
                "LOW",
                "identity",
                f"From ({r.from_domain}) and Return-Path ({r.return_domain}) "
                f"differ but share org domain ({org_domain(r.from_domain)}) — often legitimate (subdomain/ESP)",
            )
        else:
            r.add(
                "MEDIUM",
                "identity",
                f"From domain ({r.from_domain}) != Return-Path domain ({r.return_domain}) — "
                f"possible spoof, third-party sender, or mailing list",
            )
    elif r.from_domain and not r.return_domain:
        r.add("LOW", "identity", "Return-Path missing or unparseable")

    # Reply-To mismatch
    if r.reply_to and r.from_addr and r.reply_to != r.from_addr:
        if r.reply_to_domain and r.from_domain and not domains_align(r.reply_to_domain, r.from_domain):
            r.add(
                "HIGH",
                "identity",
                f"Reply-To domain ({r.reply_to_domain}) does not align with From ({r.from_domain}) — "
                f"replies may go to an attacker-controlled address",
            )
        else:
            r.add(
                "LOW",
                "identity",
                f"Reply-To ({r.reply_to}) differs from From ({r.from_addr}) but domains align",
            )

    # Sender header
    if r.sender and r.from_addr and r.sender != r.from_addr:
        if sender_domain and r.from_domain and not domains_align(sender_domain, r.from_domain):
            r.add(
                "MEDIUM",
                "identity",
                f"Sender header ({r.sender}) domain does not align with From ({r.from_domain})",
            )
        else:
            r.add("INFO", "identity", f"Sender header present: {r.sender}")

    # Message-ID domain
    if r.message_id and r.from_domain:
        mid_m = re.search(r"@([^>]+)", r.message_id)
        if mid_m:
            mid_dom = mid_m.group(1).strip().lower()
            if not domains_align(mid_dom, r.from_domain):
                r.add(
                    "LOW",
                    "identity",
                    f"Message-ID domain ({mid_dom}) does not align with From ({r.from_domain}) — "
                    f"common with ESPs; note only",
                )

    # ========== SPF ==========
    mailfrom_spf = [s for s in r.spf if s.get("identity") in ("mailfrom", "unknown", "")]
    helo_spf = [s for s in r.spf if s.get("identity") == "helo"]

    if not r.spf:
        r.add(
            "MEDIUM",
            "spf",
            "No SPF results found (no Authentication-Results spf= or Received-SPF). "
            "Header dump may be incomplete, or message was not authenticated at the edge.",
        )
    else:
        # Prefer mailfrom identity for scoring
        scored = mailfrom_spf or r.spf
        # Deduplicate by (result, identity, mailfrom)
        seen = set()
        for s in scored:
            key = (s.get("result"), s.get("identity"), s.get("mailfrom"))
            if key in seen:
                continue
            seen.add(key)
            res = (s.get("result") or "").lower()
            ident = s.get("identity") or "unknown"
            if ident == "helo":
                # HELO SPF is weak signal; only note failures lightly
                if res in ("fail", "softfail"):
                    r.add("LOW", "spf", f"SPF {res.upper()} on HELO identity (usually low impact)")
                continue
            if res == "pass":
                r.add(
                    "INFO",
                    "spf",
                    f"SPF PASS ({s.get('source')}, identity={ident})"
                    + (f" mailfrom={s['mailfrom']}" if s.get("mailfrom") else "")
                    + (f" client-ip={s['client_ip']}" if s.get("client_ip") else ""),
                )
            elif res == "fail":
                r.add(
                    "HIGH",
                    "spf",
                    f"SPF FAIL — sending IP not authorized for envelope domain"
                    + (f" ({s['mailfrom']})" if s.get("mailfrom") else ""),
                )
            elif res == "softfail":
                r.add(
                    "MEDIUM",
                    "spf",
                    f"SPF SOFTFAIL — domain discourages this sender but does not hard-fail"
                    + (f" ({s['mailfrom']})" if s.get("mailfrom") else ""),
                )
            elif res in ("none", "neutral"):
                r.add(
                    "LOW",
                    "spf",
                    f"SPF {res.upper()} — no useful SPF policy or neutral result for identity={ident}",
                )
            elif res == "temperror":
                r.add("LOW", "spf", "SPF TEMPERROR — transient DNS/lookup issue at check time")
            elif res == "permerror":
                r.add("MEDIUM", "spf", "SPF PERMERROR — broken SPF record for the domain")
            else:
                r.add("LOW", "spf", f"SPF result '{res}' (identity={ident})")

    # ========== DKIM ==========
    if not r.dkim and not dkim_sigs:
        r.add("MEDIUM", "dkim", "No DKIM results and no DKIM-Signature header found")
    elif not r.dkim and dkim_sigs:
        for sig in dkim_sigs:
            r.add(
                "LOW",
                "dkim",
                f"DKIM-Signature present (d={sig['d'] or '?'}, s={sig['s'] or '?'}) "
                f"but no Authentication-Results dkim= verdict — cannot confirm verification",
            )
    else:
        for d in r.dkim:
            res = (d.get("result") or "").lower()
            ddom = d.get("domain") or ""
            if res == "pass":
                if r.from_domain and ddom and domains_align(ddom, r.from_domain):
                    r.add(
                        "INFO",
                        "dkim",
                        f"DKIM PASS aligned with From (dkim domain={ddom}, from={r.from_domain})",
                    )
                elif r.from_domain and ddom:
                    r.add(
                        "MEDIUM",
                        "dkim",
                        f"DKIM PASS but domain ({ddom}) does not align with From ({r.from_domain}) — "
                        f"third-party sender, forwarder, or possible spoof",
                    )
                else:
                    r.add("INFO", "dkim", f"DKIM PASS (domain={ddom or 'unknown'})")
            elif res == "fail":
                r.add("HIGH", "dkim", f"DKIM FAIL — signature invalid or body/header modified ({ddom or 'unknown domain'})")
            elif res == "none":
                r.add("LOW", "dkim", "DKIM none — no signature validated")
            else:
                r.add("LOW", "dkim", f"DKIM result '{res}' domain={ddom or '?'}")

        # Signature d= vs AR
        for sig in dkim_sigs:
            if sig["d"] and r.from_domain and not domains_align(sig["d"], r.from_domain):
                # Only note if we didn't already flag misalignment via AR
                if not any("does not align" in f.message for f in r.findings if f.category == "dkim"):
                    r.add(
                        "MEDIUM",
                        "dkim",
                        f"DKIM-Signature d={sig['d']} does not align with From {r.from_domain}",
                    )

    # ========== DMARC ==========
    if not r.dmarc:
        r.add(
            "MEDIUM",
            "dmarc",
            "No DMARC results found in Authentication-Results or vendor headers",
        )
    else:
        seen_d = set()
        for d in r.dmarc:
            res = (d.get("result") or "").lower()
            key = (res, d.get("domain"), d.get("policy"))
            if key in seen_d:
                continue
            seen_d.add(key)
            policy = d.get("policy") or "unknown"
            disp = d.get("disposition") or ""
            ddom = d.get("domain") or ""
            extra = f" domain={ddom}" if ddom else ""
            if policy != "unknown":
                extra += f" p={policy}"
            if disp:
                extra += f" dis={disp}"

            if res == "pass":
                r.add("INFO", "dmarc", f"DMARC PASS{extra} — SPF/DKIM aligned with From domain policy")
            elif res == "fail":
                sev = "HIGH" if policy in ("reject", "quarantine") else "MEDIUM"
                r.add(
                    sev,
                    "dmarc",
                    f"DMARC FAIL{extra} — message does not align; "
                    + (
                        "domain owner requests reject/quarantine"
                        if policy in ("reject", "quarantine")
                        else "domain policy may be none (monitoring only)"
                    ),
                )
            elif res in ("bestguesspass", "validskip"):
                r.add("LOW", "dmarc", f"DMARC {res}{extra} — vendor soft/pass-adjacent result")
            elif res == "none":
                r.add("LOW", "dmarc", f"DMARC none{extra} — no DMARC policy published or not evaluated")
            else:
                r.add("LOW", "dmarc", f"DMARC result '{res}'{extra}")

    # ARC (informational only)
    arc = headers.get_all("ARC-Authentication-Results") or []
    if arc:
        r.add(
            "INFO",
            "arc",
            f"{len(arc)} ARC-Authentication-Results header(s) present — "
            f"message was likely forwarded; trust chain depends on ARC seal validity",
        )

    # ========== Received path ==========
    hop_lines = extract_received_hops(headers, raw_header)
    public_seen = False
    origin_public_ip = None

    # Process from oldest to newest for origin detection:
    # get_all is newest-first, so reverse for path chronology
    chronological = list(reversed(hop_lines))

    EXTERNAL_KINDS = frozenset({"public", "special"})

    for idx, hop in enumerate(chronological, 1):
        ips = extract_ips_from_received(hop)
        helo = extract_helo(hop)
        hop_info: dict[str, Any] = {
            "index_from_origin": idx,
            "helo": helo,
            "ips": [],
            "snippet": " ".join(hop.split())[:220],
        }
        for ip in ips:
            kind = classify_ip(ip)
            hop_info["ips"].append({"ip": ip, "type": kind})
            if kind in EXTERNAL_KINDS and origin_public_ip is None:
                origin_public_ip = ip
            if kind in EXTERNAL_KINDS:
                public_seen = True
        r.hops.append(hop_info)

    if origin_public_ip:
        r.add("INFO", "path", f"Earliest external connecting IP in Received chain: {origin_public_ip}")
    elif hop_lines:
        r.add(
            "LOW",
            "path",
            "No public/external IP found in Received headers — internal-only path or incomplete dump",
        )

    # Origin hop is private while later hops show external IPs (unusual path / incomplete dump)
    saw_external = False
    for hop_info in r.hops:  # chronological
        kinds = {i["type"] for i in hop_info["ips"]}
        if kinds & EXTERNAL_KINDS:
            saw_external = True
        if (
            not saw_external
            and "private" in kinds
            and hop_info["index_from_origin"] == 1
            and any(EXTERNAL_KINDS & {i["type"] for i in h["ips"]} for h in r.hops)
        ):
            r.add(
                "LOW",
                "path",
                f"Origin hop uses private IP(s) "
                f"{[i['ip'] for i in hop_info['ips'] if i['type'] == 'private']} "
                f"while external hops exist later — verify path integrity / incomplete headers",
            )

    # ========== Gateway reputation ==========
    g = r.gateway
    sg = (g.get("ironport_sender_group") or "").upper()
    if sg:
        if any(x in sg for x in ("SUSPECT", "BLACK", "BLOCK", "SPAM", "HBL")):
            r.add("HIGH", "gateway", f"IronPort SenderGroup indicates risk: {g['ironport_sender_group']}")
        elif any(x in sg for x in ("WHITE", "RELAYLIST", "TRUSTED", "ALLOWED")):
            r.add("INFO", "gateway", f"IronPort SenderGroup: {g['ironport_sender_group']}")
        else:
            r.add("LOW", "gateway", f"IronPort SenderGroup: {g['ironport_sender_group']}")

    if g.get("ironport_reputation"):
        try:
            rep = float(g["ironport_reputation"])
            if rep < -5:
                r.add("HIGH", "gateway", f"IronPort reputation very poor: {rep}")
            elif rep < 0:
                r.add("MEDIUM", "gateway", f"IronPort reputation negative: {rep}")
            else:
                r.add("INFO", "gateway", f"IronPort reputation: {rep}")
        except ValueError:
            r.add("INFO", "gateway", f"IronPort reputation: {g['ironport_reputation']}")

    if g.get("ironport_mailflow_policy"):
        pol = g["ironport_mailflow_policy"]
        if any(x in pol.lower() for x in ("quarantine", "reject", "drop", "suspect")):
            r.add("MEDIUM", "gateway", f"IronPort MailFlow policy: {pol}")
        else:
            r.add("INFO", "gateway", f"IronPort MailFlow policy: {pol}")

    if g.get("ms_scl") is not None:
        try:
            scl = int(str(g["ms_scl"]).split()[0])
            if scl >= 7:
                r.add("HIGH", "gateway", f"Exchange SCL={scl} (high spam confidence)")
            elif scl >= 5:
                r.add("MEDIUM", "gateway", f"Exchange SCL={scl} (elevated spam confidence)")
            elif scl >= 1:
                r.add("LOW", "gateway", f"Exchange SCL={scl}")
            else:
                r.add("INFO", "gateway", f"Exchange SCL={scl}")
        except ValueError:
            r.add("INFO", "gateway", f"Exchange SCL: {g['ms_scl']}")

    if g.get("ms_auth_as"):
        auth_as = g["ms_auth_as"]
        if auth_as.lower() == "anonymous":
            r.add(
                "INFO",
                "gateway",
                "Exchange AuthAs=Anonymous — typical for internet mail (not internal authenticated)",
            )
        elif auth_as.lower() in ("internal", "partner"):
            r.add("INFO", "gateway", f"Exchange AuthAs={auth_as}")
        else:
            r.add("INFO", "gateway", f"Exchange AuthAs={auth_as}")

    if g.get("threat_scanner"):
        tv = g["threat_scanner"]
        if tv.lower() not in ("negative", "clean", "n/a", ""):
            r.add("HIGH", "gateway", f"Threat scanner verdict: {tv}")
        else:
            r.add("INFO", "gateway", f"Threat scanner: {tv}")

    # ========== Subject / weak phishing heuristics ==========
    if SUBJECT_GATEWAY_TAG.search(r.subject):
        r.add(
            "MEDIUM",
            "content",
            f"Subject carries gateway/external tag: {r.subject!r}",
        )
    if SUBJECT_URGENCY.search(r.subject):
        r.add(
            "LOW",
            "content",
            "Subject matches urgency/credential-theft language patterns (weak signal — verify body)",
        )

    to_lower = r.to_addrs.lower()
    if "undisclosed-recipients" in to_lower or "undisclosed recipients" in to_lower:
        r.add("MEDIUM", "content", "To: undisclosed recipients — common in mass/phish mail")

    _, to_addr, _ = extract_address(r.to_addrs)
    if to_addr and r.from_addr and to_addr == r.from_addr:
        r.add(
            "LOW",
            "content",
            "From and To addresses are identical — sometimes used in phish to look self-sent",
        )

    # Auth passed but reputation poor → not "clean"
    auth_pass = any(
        f.category in ("spf", "dkim", "dmarc") and "PASS" in f.message and f.severity == "INFO"
        for f in r.findings
    )
    rep_risk = any(f.category == "gateway" and f.severity in ("MEDIUM", "HIGH") for f in r.findings)
    if auth_pass and rep_risk:
        r.add(
            "MEDIUM",
            "summary",
            "Authentication can PASS while the message is still unwanted/spam/BEC-prep. "
            "Auth ≠ safe — check links, attachments, and sender reputation.",
        )

    if not r.findings:
        r.add("INFO", "summary", "No notable signals extracted (header may be incomplete)")

    return r


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _sev_sort_key(f: Finding) -> tuple:
    return (-SEVERITY_ORDER.get(f.severity, 0), f.category, f.message)


def is_clear_spoof_finding(f: Finding) -> bool:
    """
    True when the finding is strong evidence of spoofing / identity abuse,
    not merely gateway reputation or spam-ish content.
    """
    msg = f.message.lower()
    cat = f.category

    if cat == "spf" and "spf fail" in msg:
        return True
    if cat == "dkim" and "dkim fail" in msg:
        return True
    if cat == "dmarc" and "dmarc fail" in msg:
        return True
    if cat == "identity":
        if "display-name spoofing" in msg:
            return True
        if "reply-to domain" in msg and "does not align" in msg:
            return True
        if "missing or unparseable from" in msg:
            return True
        if "sender header" in msg and "does not align" in msg:
            return True
        # From vs Return-Path on unrelated domains
        if "from domain" in msg and "return-path domain" in msg and "!=" in f.message:
            return True
    return False


def recommended_action(r: AnalysisResult) -> dict[str, Any]:
    """
    Derive an explicit analyst action from findings.

    BLOCK      — clear spoof / auth-failure / identity-trap evidence
    QUARANTINE — high risk but mainly reputation/gateway (auth may still pass)
    INVESTIGATE— elevated signals; do not clear yet
    MONITOR    — no high/medium header red flags
    """
    spoof = [f for f in r.findings if is_clear_spoof_finding(f)]
    high = [f for f in r.findings if f.severity == "HIGH"]
    med = [f for f in r.findings if f.severity == "MEDIUM"]
    high_spoof = [f for f in spoof if f.severity == "HIGH"]
    # MEDIUM spoof (e.g. DMARC fail with p=none, From/Return-Path mismatch) still warrants block posture
    med_spoof = [f for f in spoof if f.severity == "MEDIUM"]

    domains: list[str] = []
    for d in (r.from_domain, r.reply_to_domain, r.return_domain):
        if d and d not in domains:
            domains.append(d)

    if high_spoof or med_spoof:
        level = "BLOCK"
        lines = [
            "RECOMMENDED ACTION: BLOCK / quarantine this message.",
            "Do not click links, open attachments, or reply.",
            "Clear spoofing / authentication-failure indicators were detected:",
        ]
        for f in sorted(spoof, key=_sev_sort_key):
            lines.append(f"  - [{f.severity}/{f.category}] {f.message}")
        lines.append("Suggested follow-up:")
        lines.append("  • Delete/quarantine for the reporting user (and check other recipients).")
        if domains:
            extra = f" and address {r.reply_to}" if r.reply_to and r.reply_to != r.from_addr else ""
            lines.append(f"  • Consider gateway block / watch on: {', '.join(domains)}{extra}")
        lines.append("  • If brand impersonation: report to the real brand's abuse channel if appropriate.")
        lines.append("  • Skim body only in a safe viewer if you need IOCs (URLs, hashes).")
        return {"action": level, "spoof_findings": len(spoof), "lines": lines}

    if high:
        level = "QUARANTINE"
        lines = [
            "RECOMMENDED ACTION: QUARANTINE / hold — treat as malicious until proven safe.",
            "No classic domain-spoof auth failures, but HIGH risk signals are present",
            "(gateway reputation, spam confidence, threat verdict, etc.).",
            "Do not clear to the inbox based on headers alone.",
            "Next: inspect body/links/attachments; confirm whether the user expected this sender.",
        ]
        for f in high:
            lines.append(f"  - [{f.category}] {f.message}")
        return {"action": level, "spoof_findings": 0, "lines": lines}

    if med:
        level = "INVESTIGATE"
        lines = [
            "RECOMMENDED ACTION: INVESTIGATE — do not clear based on headers alone.",
            "Elevated (MEDIUM) signals present; spoofing is not confirmed from headers.",
            "Verify content, brand impersonation, user context, and any gateway tags.",
        ]
        return {"action": level, "spoof_findings": 0, "lines": lines}

    level = "MONITOR"
    lines = [
        "RECOMMENDED ACTION: No block recommended from headers alone.",
        "No high/medium header red flags. Headers look relatively clean.",
        "Still verify: unexpected sender? user expected this? links/attachments?",
    ]
    return {"action": level, "spoof_findings": 0, "lines": lines}


def format_report(r: AnalysisResult) -> str:
    lines: list[str] = []
    lines.append("=" * 64)
    lines.append(" EMAIL HEADER ANALYSIS (local / offline)")
    lines.append("=" * 64)
    lines.append(f"Subject      : {r.subject}")
    lines.append(f"From         : {r.from_addr or '(none)'}"
                 + (f'  (display: "{r.from_display}")' if r.from_display else ""))
    lines.append(f"From domain  : {r.from_domain or '(none)'}"
                 + (f"  (org: {org_domain(r.from_domain)})" if r.from_domain else ""))
    lines.append(f"Return-Path  : {r.return_path or '(none)'}")
    if r.return_domain:
        lines.append(f"  RP domain  : {r.return_domain}")
    lines.append(f"Reply-To     : {r.reply_to or '(none)'}")
    if r.sender:
        lines.append(f"Sender       : {r.sender}")
    lines.append(f"To           : {r.to_addrs}")
    if r.date:
        lines.append(f"Date         : {r.date}")
    if r.message_id:
        lines.append(f"Message-ID   : {r.message_id}")

    # Auth summary block
    lines.append("")
    lines.append("-" * 64)
    lines.append(" AUTHENTICATION")
    lines.append("-" * 64)
    if r.auth_results_raw:
        for i, ar in enumerate(r.auth_results_raw, 1):
            lines.append(f"  AR[{i}]: {ar[:300]}{'...' if len(ar) > 300 else ''}")
    else:
        lines.append("  (no Authentication-Results header)")

    if r.spf:
        lines.append("  SPF details:")
        for s in r.spf:
            lines.append(
                f"    - [{s.get('source')}] result={s.get('result')} "
                f"identity={s.get('identity')}"
                + (f" mailfrom={s['mailfrom']}" if s.get("mailfrom") else "")
                + (f" ip={s['client_ip']}" if s.get("client_ip") else "")
            )
    if r.dkim:
        lines.append("  DKIM details:")
        for d in r.dkim:
            lines.append(
                f"    - [{d.get('source')}] result={d.get('result')} "
                f"domain={d.get('domain') or '?'} i={d.get('header_i') or '?'}"
            )
    if r.dmarc:
        lines.append("  DMARC details:")
        for d in r.dmarc:
            lines.append(
                f"    - [{d.get('source')}] result={d.get('result')} "
                f"domain={d.get('domain') or '?'} "
                f"p={d.get('policy') or '?'} dis={d.get('disposition') or '?'}"
            )

    # Path
    lines.append("")
    lines.append("-" * 64)
    lines.append(" RECEIVED PATH (oldest → newest)")
    lines.append("-" * 64)
    if not r.hops:
        lines.append("  (no Received headers)")
    for h in r.hops:
        ip_s = ", ".join(f"{i['ip']}({i['type']})" for i in h["ips"]) or "no IP parsed"
        helo_s = f" HELO={h['helo']}" if h.get("helo") else ""
        lines.append(f"  [{h['index_from_origin']}] IPs: {ip_s}{helo_s}")
        lines.append(f"      {h['snippet']}")

    # Gateway
    if r.gateway:
        lines.append("")
        lines.append("-" * 64)
        lines.append(" GATEWAY / MTA SIGNALS")
        lines.append("-" * 64)
        for k, v in r.gateway.items():
            lines.append(f"  {k}: {v}")

    # Findings
    lines.append("")
    lines.append("-" * 64)
    lines.append(f" FINDINGS  (max severity: {r.max_severity})")
    lines.append("-" * 64)
    by_sev: dict[str, list[Finding]] = {"HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
    for f in sorted(r.findings, key=_sev_sort_key):
        by_sev.setdefault(f.severity, []).append(f)

    for sev in ("HIGH", "MEDIUM", "LOW", "INFO"):
        items = by_sev.get(sev) or []
        if not items:
            continue
        lines.append(f"  [{sev}] ({len(items)})")
        for f in items:
            lines.append(f"    • ({f.category}) {f.message}")

    # Analyst recommendation (explicit block vs quarantine vs investigate)
    lines.append("")
    lines.append("-" * 64)
    lines.append(" ANALYST TAKEAWAY")
    lines.append("-" * 64)
    action = recommended_action(r)
    lines.append(f"  Action level: {action['action']}")
    for line in action["lines"]:
        lines.append(f"  {line}")
    lines.append("  Note: This tool is offline header analysis only — it does not verify DNS live")
    lines.append("  or re-validate DKIM cryptography beyond MTA Authentication-Results.")
    lines.append("=" * 64)
    return "\n".join(lines)


def result_to_json(r: AnalysisResult) -> str:
    action = recommended_action(r)
    payload = {
        "subject": r.subject,
        "from": {"address": r.from_addr, "display": r.from_display, "domain": r.from_domain},
        "return_path": {"address": r.return_path, "domain": r.return_domain},
        "reply_to": {"address": r.reply_to, "domain": r.reply_to_domain},
        "sender": r.sender,
        "to": r.to_addrs,
        "message_id": r.message_id,
        "date": r.date,
        "max_severity": r.max_severity,
        "recommended_action": action["action"],
        "recommended_action_detail": action["lines"],
        "findings": [asdict(f) for f in sorted(r.findings, key=_sev_sort_key)],
        "spf": r.spf,
        "dkim": r.dkim,
        "dmarc": r.dmarc,
        "hops": r.hops,
        "gateway": r.gateway,
        "authentication_results": r.auth_results_raw,
    }
    return json.dumps(payload, indent=2)


def exit_code_for(r: AnalysisResult) -> int:
    """0 = clean/info, 1 = low, 2 = medium, 3 = high (for scripting)."""
    return SEVERITY_ORDER.get(r.max_severity, 0)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Analyze email headers for spoofing, auth alignment, and gateway risk signals.",
    )
    p.add_argument(
        "header_file",
        nargs="?",
        default="header.txt",
        help="Path to header dump text file, or '-' for stdin (default: header.txt)",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of the text report",
    )
    args = p.parse_args(argv)

    try:
        data = load_input(args.header_file)
    except FileNotFoundError:
        print(f"Error: file '{args.header_file}' not found.", file=sys.stderr)
        if args.header_file == "header.txt":
            print(
                "Paste the email headers into header.txt in this directory, then re-run.",
                file=sys.stderr,
            )
        return 4
    except OSError as e:
        print(f"Error reading input: {e}", file=sys.stderr)
        return 4

    if not data.strip():
        print(f"Error: '{args.header_file}' is empty. Paste headers into the file and re-run.", file=sys.stderr)
        return 4

    try:
        headers, raw_header = parse_header_bytes(data)
    except Exception as e:
        print(f"Error parsing headers: {e}", file=sys.stderr)
        return 4

    result = analyze(headers, raw_header)

    if args.json:
        print(result_to_json(result))
    else:
        print(format_report(result))

    return exit_code_for(result)


if __name__ == "__main__":
    sys.exit(main())
