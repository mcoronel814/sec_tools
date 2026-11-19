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
import base64
import ipaddress
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from email.parser import BytesParser
from email.policy import default
from email.utils import parseaddr
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
SCRIPT_DIR = Path(__file__).resolve().parent
ORG_WATCH = SCRIPT_DIR / "org_watch.txt"

# IronPort SenderGroup words. Matched on tokens so NONSPAM does not contain SPAM.
_RISK_GROUP_WORDS = ("SUSPECT", "BLACK", "BLOCK", "SPAM", "HBL")
_SAFE_GROUP_WORDS = ("WHITE", "RELAYLIST", "TRUSTED", "ALLOWED")
_FOREFRONT_HIGH_CATS = {"PHSH", "HPHSH", "PHISH", "MALW", "SPOOF", "HSPM"}
_FOREFRONT_MED_CATS = {"SPM", "BULK"}
_FOREFRONT_RISK_SFV = {"SPM", "SKS", "SKB"}
_DMARC_STRONG = {"reject", "quarantine", "oreject"}
# Parents of shared mail systems. A tenant under onmicrosoft.com can still be blocked.
# A name under one of these cannot.
_HUGE_MAIL_PARENTS = {
    "sendgrid.net",
    "secureserver.net",
    "outlook.com",
    "protection.outlook.com",
    "office365.com",
    "microsoft.com",
    "google.com",
    "googleapis.com",
    "gstatic.com",
}
_SRS_LOCAL = re.compile(r"(?:^|[+=])srs\d*=", re.I)


@dataclass
class OrgWatch:
    """Domains we send as, and display names that should only appear on them."""

    domains: set[str] = field(default_factory=set)
    names: list[str] = field(default_factory=list)


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
    to_addr: str = ""
    to_domain: str = ""
    forwarder_domain: str = ""
    received_as_bcc: bool = False
    attachment_types: list[str] = field(default_factory=list)
    signature_domains: list[str] = field(default_factory=list)
    our_domains: set[str] = field(default_factory=set)
    tenant_id: str = ""
    forward_account: str = ""
    forward_source: str = ""
    forward_account_domain: str = ""
    sendgrid_customer_id: str = ""
    prior_receipts: list[dict[str, str]] = field(default_factory=list)
    shared_relays: list[dict[str, str]] = field(default_factory=list)

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
    # Microsoft Received lines put IPv6 in parentheses, not brackets.
    re.compile(r"\(([0-9a-fA-F]{0,4}:[0-9a-fA-F:]*)\)"),
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
                # p= is the published policy. Microsoft puts the decision in action=.
                policy = ""
                disposition = ""
                blob = f"{reason} {rest}"
                pm = re.search(r"\bp=(\w+)", blob, re.I)
                if pm:
                    policy = pm.group(1).lower()
                am = re.search(r"\baction=(\w+)", blob, re.I)
                action = am.group(1).lower() if am else ""
                if not policy and action in _DMARC_STRONG | {"none"}:
                    policy = "reject" if action == "oreject" else action
                dm = re.search(r"\bdis=(\w+)", blob, re.I)
                if dm:
                    disposition = dm.group(1).lower()
                elif action:
                    disposition = action
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
        "amp_file_uploaded": "X-Amp-File-Uploaded",
        "ironport_av": "X-IronPort-AV",
    }
    for key, hdr in mapping.items():
        val = headers.get(hdr)
        if val is not None:
            g[key] = " ".join(str(val).split())
    return g


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def load_org_watch(paths: tuple[Path, ...] | None = None) -> OrgWatch:
    """Load org_watch.txt when it exists. A missing file means no org-specific checks."""
    watch = OrgWatch()
    for path in paths if paths is not None else (ORG_WATCH,):
        if not path.is_file():
            continue
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                kind, value = line.split(":", 1)
            else:
                kind, value = "domain", line
            kind = kind.strip().lower()
            value = value.strip()
            if not value:
                continue
            if kind == "domain":
                watch.domains.add(value.lower().rstrip("."))
            elif kind == "name":
                watch.names.append(value)
    return watch


def _dmarc_passed(result: AnalysisResult) -> bool:
    return any((item.get("result") or "").lower() == "pass" for item in result.dmarc)


def _aligned_dkim_pass(result: AnalysisResult) -> bool:
    if not result.from_domain:
        return False
    for item in result.dkim:
        domain = item.get("domain") or ""
        if (item.get("result") or "").lower() == "pass" and domain and domains_align(domain, result.from_domain):
            return True
    return False


def _is_mailing_list(headers) -> bool:
    return bool(headers.get("List-Id") or headers.get("List-Unsubscribe"))


def srs_forwarder_domain(return_path: str) -> str:
    """Domain that rewrote the envelope, when the local part is SRS."""
    if "@" not in return_path:
        return ""
    local, domain = return_path.rsplit("@", 1)
    if not _SRS_LOCAL.search(local):
        return ""
    return domain.lower().rstrip(".")


def ironport_attachment_types(value: str) -> list[str]:
    """File types named in an X-IronPort-AV d= field."""
    match = re.search(r'\bd="([^"]*)"', value, re.I)
    if not match:
        return []
    types: list[str] = []
    for token in re.findall(r"[A-Za-z0-9]+", match.group(1)):
        if token.lower() == "scan" or token.isdigit():
            continue
        lowered = token.lower()
        if lowered not in types:
            types.append(lowered)
    return types


def _under_huge_mail_parent(domain: str) -> bool:
    domain = domain.lower().rstrip(".")
    if domain in _HUGE_MAIL_PARENTS or domain == "onmicrosoft.com":
        return True
    return any(domain.endswith("." + parent) for parent in _HUGE_MAIL_PARENTS)


def _group_tokens(value: str) -> list[str]:
    return re.findall(r"[A-Z0-9]+", value.upper())


def _token_has_word(tokens: list[str], words: tuple[str, ...]) -> bool:
    """True when a token is the word or starts with it (BLACKLIST, SUSPECTLIST)."""
    for token in tokens:
        for word in words:
            if token == word or token.startswith(word):
                return True
    return False


def _norm_label(label: str) -> str:
    """Fold a few confusable characters so paypa1 and paypai meet paypal."""
    folded = label.lower().replace("rn", "m")
    return folded.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s"}))


def _registrable_label(domain: str) -> str:
    org = org_domain(domain)
    return org.split(".", 1)[0] if org else ""


def _claims_our_domain(domain: str, watch: OrgWatch) -> bool:
    return any(domains_align(domain, ours) for ours in watch.domains)


def parse_forefront(value: str) -> dict[str, Any]:
    """Split an X-Forefront-Antispam-Report into SCL, SFV, CAT, and DIR values."""
    parsed: dict[str, Any] = {"scl": "", "sfv": "", "cats": [], "dir": ""}
    for part in value.split(";"):
        if ":" not in part:
            continue
        key, raw_val = part.split(":", 1)
        key = key.strip().upper()
        val = raw_val.strip()
        if not key or not val:
            continue
        if key == "CAT":
            parsed["cats"].append(val.upper())
        elif key == "SFV" and not parsed["sfv"]:
            parsed["sfv"] = val.upper()
        elif key == "SCL" and not parsed["scl"]:
            parsed["scl"] = val
        elif key == "DIR" and not parsed["dir"]:
            parsed["dir"] = val.upper()
    return parsed


def sendgrid_customer_id(token: str) -> str:
    """Numeric SendGrid customer id hidden in an HTTP-injection HELO token."""
    if not re.fullmatch(r"[A-Za-z0-9+/]{6,32}", token):
        return ""
    padded = token + "=" * ((-len(token)) % 4)
    try:
        text = base64.b64decode(padded, validate=True).decode("ascii")
    except (ValueError, UnicodeDecodeError):
        return ""
    return text if text.isdigit() else ""


def _guid(value: str) -> str:
    match = re.search(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        value,
    )
    return match.group(0).lower() if match else ""


def extract_tenant_id(headers) -> str:
    """Microsoft 365 tenant GUID. The onmicrosoft name can change; this does not."""
    for name in ("X-MS-Exchange-CrossTenant-Id", "X-EOPTenantAttributedMessage"):
        val = headers.get(name)
        if not val:
            continue
        found = _guid(" ".join(str(val).split()))
        if found:
            return found
    return ""


def extract_forward_account(headers) -> tuple[str, str, str]:
    """Mailbox a forwarder named, plus the header that named it."""
    for name in ("X-CM-Forward", "X-SECURESERVER-ACCT"):
        val = headers.get(name)
        if not val:
            continue
        _, addr, domain = extract_address(str(val))
        if addr:
            return addr, domain, name
    return "", "", ""


def parse_prior_receipts(headers) -> list[dict[str, str]]:
    """Envelope facts from an earlier hop.

    ARC and Authentication-Results-Original are not this gateway's verdict,
    so they stay out of the scored SPF/DKIM/DMARC lists.
    """
    receipts: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for name in ("ARC-Authentication-Results", "Authentication-Results-Original"):
        for val in headers.get_all(name) or []:
            text = " ".join(str(val).split())
            mf = re.search(r"smtp\.mailfrom=<?([^\s;>]+)>?", text, re.I)
            rc = re.search(r"smtp\.rcpttodomain=<?([^\s;>]+)>?", text, re.I)
            ipm = re.search(r"sender ip is\s+([0-9a-fA-F:.]+)", text, re.I)
            if not ipm:
                ipm = re.search(r"client-ip=([0-9a-fA-F:.]+)", text, re.I)
            mailfrom = mf.group(1).strip().lower() if mf else ""
            rcpt = rc.group(1).strip().lower().rstrip(".") if rc else ""
            client_ip = ipm.group(1).rstrip(".;") if ipm else ""
            key = (mailfrom, rcpt, client_ip)
            if not any(key) or key in seen:
                continue
            seen.add(key)
            receipts.append({
                "source": name,
                "mailfrom": mailfrom,
                "rcpt_domain": rcpt,
                "client_ip": client_ip,
            })
    return receipts


def _mailfrom_domain(mailfrom: str) -> str:
    mailfrom = (mailfrom or "").strip().lower().rstrip(".")
    if "@" in mailfrom:
        return mailfrom.rsplit("@", 1)[-1]
    return mailfrom if "." in mailfrom else ""


def _shared_relay_note(hop: str, ip: str) -> str:
    """Shared platform address on the sending side of a hop.

    The receiving host is often a different company. Only the from-side
    hostname is allowed to explain the IP.
    """
    from_side = re.split(r"\s+by\s+", hop, maxsplit=1, flags=re.I)[0]
    if ip not in from_side:
        return ""
    low = from_side.lower()
    if "sendgrid.net" in low:
        return "shared SendGrid address. Report the customer id, not this IP."
    if "protection.outlook.com" in low:
        return "shared Microsoft 365 outbound address. Block the forwarding tenant, not this IP."
    return ""


def _filter_called_spam(subject: str, gateway: dict[str, Any]) -> bool:
    """True when a filter other than the allowlist already called the message spam."""
    if SUBJECT_RISK_TAG.search(subject or ""):
        return True
    ff_raw = gateway.get("forefront_antispam") or ""
    if ff_raw:
        ff = parse_forefront(str(ff_raw))
        if ff["sfv"] in _FOREFRONT_RISK_SFV:
            return True
        if any(
            cat in _FOREFRONT_HIGH_CATS or cat in _FOREFRONT_MED_CATS or cat == "OSPM"
            for cat in ff["cats"]
        ):
            return True
        if ff["scl"]:
            try:
                if int(str(ff["scl"]).split()[0]) >= 5:
                    return True
            except ValueError:
                pass
    if gateway.get("ms_scl") is not None:
        try:
            if int(str(gateway["ms_scl"]).split()[0]) >= 5:
                return True
        except ValueError:
            pass
    return False


def _authenticated_forward(result: AnalysisResult) -> bool:
    """DMARC passed for From, and a different domain rewrote the envelope."""
    if not _dmarc_passed(result) or not result.forwarder_domain:
        return False
    if result.from_domain and domains_align(result.forwarder_domain, result.from_domain):
        return False
    return True


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
# Whole words only. "precaution" must not match "caution", and "external"
# inside a normal sentence is not a gateway tag.
SUBJECT_RISK_TAG = re.compile(
    r"\b(suspected\s+spam|spam|phish(?:ing)?)\b",
    re.I,
)
SUBJECT_BANNER_TAG = re.compile(
    r"\[(?:external(?:\s+email)?|caution)\]",
    re.I,
)
# Weak lure words. LOW only, so an ordinary invoice does not raise the action.
SUBJECT_PAYMENT = re.compile(
    r"\b(balance|invoice|settled|payment|voicemail)\b",
    re.I,
)


def analyze(headers, raw_header: str, org: OrgWatch | None = None) -> AnalysisResult:
    r = AnalysisResult()
    if org is None:
        org = load_org_watch()

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
    _, r.to_addr, r.to_domain = extract_address(headers.get("To"))
    r.our_domains = set(org.domains)
    r.forwarder_domain = srs_forwarder_domain(r.return_path)
    r.received_as_bcc = bool(headers.get("X-MS-Exchange-Processed-By-BccFoldering"))
    r.tenant_id = extract_tenant_id(headers)
    r.forward_account, r.forward_account_domain, r.forward_source = extract_forward_account(headers)
    r.prior_receipts = parse_prior_receipts(headers)
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
    for sig in dkim_sigs:
        signed = (sig.get("d") or "").lower().rstrip(".")
        if signed and signed not in r.signature_domains:
            r.signature_domains.append(signed)

    # --- Gateway ---
    r.gateway = collect_gateway_signals(headers)
    r.attachment_types = ironport_attachment_types(str(r.gateway.get("ironport_av") or ""))

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
        elif r.forwarder_domain:
            r.add(
                "MEDIUM",
                "path",
                f"Return-Path {r.return_path} was rewritten with SRS. "
                f"{r.forwarder_domain} forwarded the message. "
                f"That domain is not the From domain ({r.from_domain}).",
            )
        elif _dmarc_passed(r) or _is_mailing_list(headers):
            why = "DMARC passed" if _dmarc_passed(r) else "mailing-list headers are present"
            r.add(
                "LOW",
                "identity",
                f"From ({r.from_domain}) and Return-Path ({r.return_domain}) differ ({why}). "
                f"Often an ESP or mailing list.",
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

    watched = OrgWatch(domains=set(r.our_domains))
    to_outside = bool(r.our_domains) and bool(r.to_domain) and not _claims_our_domain(r.to_domain, watched)
    forward_outside = (
        bool(r.our_domains)
        and bool(r.forward_account_domain)
        and not _claims_our_domain(r.forward_account_domain, watched)
    )
    if r.forward_account:
        if r.to_addr and r.to_addr == r.forward_account:
            delivered = f" Visible To is {r.to_addr}, and the message was delivered onward from that mailbox."
        elif r.to_addr:
            delivered = f" Visible To is {r.to_addr}."
        else:
            delivered = ""
        r.add(
            "MEDIUM" if forward_outside else "INFO",
            "path",
            f"{r.forward_source} names {r.forward_account} as the forwarding mailbox.{delivered}",
        )
    elif r.received_as_bcc and r.to_addr:
        r.add(
            "MEDIUM" if to_outside else "INFO",
            "path",
            f"A mailbox received this as a blind copy. Visible To is {r.to_addr}.",
        )

    # Reply-To mismatch
    if r.reply_to and r.from_addr and r.reply_to != r.from_addr:
        if r.reply_to_domain and r.from_domain and not domains_align(r.reply_to_domain, r.from_domain):
            if _dmarc_passed(r):
                r.add(
                    "MEDIUM",
                    "identity",
                    f"Reply-To ({r.reply_to}) is on {r.reply_to_domain}, while From "
                    f"({r.from_domain}) passed DMARC. Confirm replies should go there.",
                )
            else:
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

        misaligned_spf: list[str] = []
        for s in r.spf:
            if (s.get("result") or "").lower() != "pass":
                continue
            if (s.get("identity") or "") == "helo":
                continue
            mailed = _mailfrom_domain(s.get("mailfrom") or "")
            if (
                mailed
                and r.from_domain
                and not domains_align(mailed, r.from_domain)
                and mailed not in misaligned_spf
            ):
                misaligned_spf.append(mailed)
        if misaligned_spf:
            r.add(
                "INFO",
                "spf",
                "SPF pass authenticates "
                + ", ".join(misaligned_spf)
                + f", not the From domain {r.from_domain}.",
            )

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
        aligned_pass = _aligned_dkim_pass(r)
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
                if aligned_pass:
                    r.add(
                        "INFO",
                        "dkim",
                        f"Extra DKIM signature for {ddom or 'unknown domain'} did not verify. "
                        f"A signature aligned with From ({r.from_domain}) passed.",
                    )
                else:
                    r.add(
                        "HIGH",
                        "dkim",
                        f"DKIM FAIL — signature invalid or body/header modified ({ddom or 'unknown domain'})",
                    )
            elif res == "none":
                r.add("LOW", "dkim", "DKIM none — no signature validated")
            else:
                r.add("LOW", "dkim", f"DKIM result '{res}' domain={ddom or '?'}")

        # Signature d= vs AR. An aligned passing result already explains a list signature.
        if not aligned_pass:
            for sig in dkim_sigs:
                if sig["d"] and r.from_domain and not domains_align(sig["d"], r.from_domain):
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
                strong = policy in _DMARC_STRONG or disp in _DMARC_STRONG
                sev = "HIGH" if strong else "MEDIUM"
                r.add(
                    sev,
                    "dmarc",
                    f"DMARC FAIL{extra} — message does not align; "
                    + (
                        "domain owner or gateway requests reject/quarantine"
                        if strong
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
            if kind == "public":
                note = _shared_relay_note(hop, ip)
                if note and not any(item["ip"] == ip for item in r.shared_relays):
                    r.shared_relays.append({"ip": ip, "note": note})
        if (
            not r.sendgrid_customer_id
            and re.search(r"\bwith\s+HTTP\b", hop, re.I)
            and re.search(r"sendgrid|geopod|\(SG\)", hop, re.I)
        ):
            named = re.search(r"\bfrom\s+([A-Za-z0-9+/]{6,32})\b", hop)
            if named:
                r.sendgrid_customer_id = sendgrid_customer_id(named.group(1))
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

    if r.sendgrid_customer_id:
        for item in r.shared_relays:
            if "SendGrid" in item["note"]:
                item["note"] = (
                    f"shared SendGrid address. Report customer id {r.sendgrid_customer_id}, not this IP."
                )
        r.add(
            "INFO",
            "path",
            f"SendGrid HTTP API injection, customer id {r.sendgrid_customer_id}. "
            "Report that id. Do not block the shared SendGrid IP.",
        )
    for prior in r.prior_receipts:
        parts: list[str] = []
        if prior["rcpt_domain"]:
            parts.append(f"for {prior['rcpt_domain']}")
        if prior["mailfrom"]:
            parts.append(f"from envelope {prior['mailfrom']}")
        if prior["client_ip"]:
            parts.append(f"at {prior['client_ip']}")
        if parts:
            r.add(
                "INFO",
                "path",
                f"Earlier hop ({prior['source']}) accepted this " + ", ".join(parts) + ".",
            )

    # ========== Gateway reputation ==========
    g = r.gateway
    sg = g.get("ironport_sender_group") or ""
    spam_marked = _filter_called_spam(r.subject, g)
    accepted_group = bool(sg) and _token_has_word(_group_tokens(sg), ("ACCEPTLIST",))
    policy = g.get("ironport_mailflow_policy") or ""
    accepted_policy = "ACCEPTED" in policy.upper()
    allowlist_override = (accepted_group or accepted_policy) and spam_marked
    if sg:
        tokens = _group_tokens(sg)
        if _token_has_word(tokens, _RISK_GROUP_WORDS):
            r.add("HIGH", "gateway", f"IronPort SenderGroup indicates risk: {sg}")
        elif _token_has_word(tokens, _SAFE_GROUP_WORDS):
            r.add("INFO", "gateway", f"IronPort SenderGroup: {sg}")
        elif not (allowlist_override and accepted_group):
            r.add("LOW", "gateway", f"IronPort SenderGroup: {sg}")

    if g.get("ironport_reputation"):
        try:
            rep = float(g["ironport_reputation"])
            remote = g.get("ironport_remote_ip") or ""
            whose = f" for connecting IP {remote}" if remote else ""
            if rep < -5:
                r.add("HIGH", "gateway", f"IronPort reputation very poor: {rep}{whose}")
            elif rep < 0:
                r.add("MEDIUM", "gateway", f"IronPort reputation negative: {rep}{whose}")
            else:
                r.add("INFO", "gateway", f"IronPort reputation: {rep}{whose}")
        except ValueError:
            r.add("INFO", "gateway", f"IronPort reputation: {g['ironport_reputation']}")

    if policy:
        if any(x in policy.lower() for x in ("quarantine", "reject", "drop", "suspect")):
            r.add("MEDIUM", "gateway", f"IronPort MailFlow policy: {policy}")
        elif not (allowlist_override and accepted_policy):
            r.add("INFO", "gateway", f"IronPort MailFlow policy: {policy}")

    if allowlist_override:
        how: list[str] = []
        if accepted_group:
            how.append(f"sender group {sg}")
        if accepted_policy:
            how.append(f"policy {policy}")
        msg = (
            "IronPort delivered this on "
            + " and ".join(how)
            + " after another filter marked it spam."
        )
        remote = g.get("ironport_remote_ip") or ""
        if g.get("ironport_reputation") and remote:
            msg += (
                f" Reputation {g['ironport_reputation']} belongs to connecting IP {remote},"
                " not the From domain."
            )
        elif remote:
            msg += f" The connecting IP was {remote}."
        r.add("MEDIUM", "gateway", msg)

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

    if g.get("forefront_antispam"):
        ff = parse_forefront(g["forefront_antispam"])
        bits: list[str] = []
        sev_rank = 0
        high_cats = [cat for cat in ff["cats"] if cat in _FOREFRONT_HIGH_CATS]
        med_cats = [cat for cat in ff["cats"] if cat in _FOREFRONT_MED_CATS]
        if high_cats:
            bits.append("CAT=" + ",".join(high_cats))
            sev_rank = 3
        elif med_cats:
            bits.append("CAT=" + ",".join(med_cats))
            sev_rank = max(sev_rank, 2)
        outbound_note = ""
        if "OSPM" in ff["cats"]:
            bits.append("CAT=OSPM")
            sev_rank = 3
            if ff.get("dir") == "OUT":
                outbound_note = " Outbound spam from the forwarding tenant."
        sfv = ff["sfv"]
        if sfv in _FOREFRONT_RISK_SFV:
            bits.append(f"SFV={sfv}")
            sev_rank = 3
        ff_scl = None
        if ff["scl"]:
            try:
                ff_scl = int(str(ff["scl"]).split()[0])
            except ValueError:
                ff_scl = None
            if ff_scl is not None:
                bits.append(f"SCL={ff_scl}")
                if ff_scl >= 7:
                    sev_rank = 3
                elif ff_scl >= 5:
                    sev_rank = max(sev_rank, 2)
                elif ff_scl >= 1:
                    sev_rank = max(sev_rank, 1)
        exchange_scl = None
        if g.get("ms_scl") is not None:
            try:
                exchange_scl = int(str(g["ms_scl"]).split()[0])
            except ValueError:
                exchange_scl = None
        disagreement = ""
        if ff_scl is not None and exchange_scl is not None and ff_scl != exchange_scl:
            disagreement = (
                f" Exchange SCL={exchange_scl} disagrees; that score is from a later hop."
            )
        if bits and sev_rank >= 2:
            severity = "HIGH" if sev_rank >= 3 else "MEDIUM"
            r.add(
                severity,
                "gateway",
                "Forefront antispam: " + " ".join(bits) + "." + outbound_note + disagreement,
            )
        elif bits:
            r.add(
                "LOW",
                "gateway",
                "Forefront antispam: " + " ".join(bits) + "." + outbound_note + disagreement,
            )

    if r.attachment_types:
        r.add(
            "INFO",
            "content",
            "IronPort scanned attachment type(s): " + ", ".join(r.attachment_types),
        )

    amp = (g.get("amp_result") or "").strip()
    uploaded = (g.get("amp_file_uploaded") or "").strip().lower()
    if amp:
        if amp.upper() == "LOWRISK" and uploaded == "false":
            r.add(
                "MEDIUM",
                "content",
                "AMP result is LOWRISK and the file was not uploaded. The attachment was not sandboxed.",
            )
        elif amp.upper() in {"MALICIOUS", "HIGH"}:
            r.add("HIGH", "content", f"AMP result: {amp}")
        else:
            filed = ""
            if g.get("amp_file_uploaded"):
                filed = f", file uploaded={g['amp_file_uploaded']}"
            r.add("INFO", "content", f"AMP result: {amp}{filed}")

    if g.get("threat_scanner"):
        tv = g["threat_scanner"]
        if tv.lower() not in ("negative", "clean", "n/a", ""):
            r.add("HIGH", "gateway", f"Threat scanner verdict: {tv}")
        else:
            r.add("INFO", "gateway", f"Threat scanner: {tv}")

    # ========== Our domains and watched display names ==========
    if org.domains and r.from_domain and _claims_our_domain(r.from_domain, org):
        spf_fail = any(
            (item.get("result") or "").lower() in ("fail", "softfail")
            and (item.get("identity") or "") != "helo"
            for item in r.spf
        )
        dmarc_fail = any((item.get("result") or "").lower() == "fail" for item in r.dmarc)
        if dmarc_fail or (spf_fail and not _aligned_dkim_pass(r)):
            r.add(
                "HIGH",
                "identity",
                f"From uses our domain {r.from_domain} but authentication failed — "
                f"treat as impersonation",
            )
    elif org.domains and r.from_domain and not _claims_our_domain(r.from_domain, org):
        their_label = _norm_label(_registrable_label(r.from_domain))
        for ours in sorted(org.domains):
            our_label = _norm_label(_registrable_label(ours))
            if their_label and our_label and their_label == our_label:
                r.add(
                    "HIGH",
                    "identity",
                    f"From domain {r.from_domain} looks like our domain {ours}",
                )
                break

    if (
        org.names
        and org.domains
        and r.from_display
        and r.from_domain
        and not _claims_our_domain(r.from_domain, org)
    ):
        display_lower = r.from_display.lower()
        for watched in org.names:
            if watched.lower() in display_lower:
                r.add(
                    "HIGH",
                    "identity",
                    f"Watched display name '{watched}' is on {r.from_addr or r.from_domain}, "
                    f"which is not our domain",
                )
                break

    # ========== Subject / weak phishing heuristics ==========
    if SUBJECT_RISK_TAG.search(r.subject):
        r.add(
            "MEDIUM",
            "content",
            f"Subject matches a spam or phish tag: {r.subject!r}",
        )
    elif SUBJECT_BANNER_TAG.search(r.subject):
        r.add(
            "INFO",
            "content",
            f"Subject has an external/caution banner: {r.subject!r}",
        )
    if SUBJECT_URGENCY.search(r.subject):
        r.add(
            "LOW",
            "content",
            "Subject matches urgency/credential-theft language patterns (weak signal — verify body)",
        )
    if SUBJECT_PAYMENT.search(r.subject):
        r.add(
            "LOW",
            "content",
            "Subject matches payment or invoice lure language (weak signal — verify body)",
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
        if "treat as impersonation" in msg or "looks like our domain" in msg:
            return True
        if msg.startswith("watched display name"):
            return True
        if "missing or unparseable from" in msg:
            return True
        if "sender header" in msg and "does not align" in msg:
            return True
        # From vs Return-Path on unrelated domains
        if "from domain" in msg and "return-path domain" in msg and "!=" in f.message:
            return True
    return False


def _path_notes(r: AnalysisResult) -> list[str]:
    notes: list[str] = []
    if r.forwarder_domain:
        notes.append(f"Return-Path was rewritten with SRS by {r.forwarder_domain}.")

    other_dkim: list[str] = []
    for item in r.dkim:
        domain = (item.get("domain") or "").lower().rstrip(".")
        if (item.get("result") or "").lower() != "pass" or not domain:
            continue
        if r.from_domain and domains_align(domain, r.from_domain):
            continue
        if domain not in other_dkim and not _under_huge_mail_parent(domain):
            other_dkim.append(domain)
    if other_dkim:
        notes.append(
            "Passing DKIM for a domain other than From: " + ", ".join(other_dkim) + "."
        )

    infra: list[str] = []
    for signed in r.signature_domains:
        if r.from_domain and domains_align(signed, r.from_domain):
            continue
        if _under_huge_mail_parent(signed) and signed not in infra:
            infra.append(signed)
    if infra:
        notes.append(
            "Also signed through shared mail infrastructure: "
            + ", ".join(infra)
            + ". Those names are not block targets."
        )

    if r.sendgrid_customer_id:
        notes.append(
            f"SendGrid HTTP API customer id {r.sendgrid_customer_id}. "
            "Report that id. The SendGrid IP is shared."
        )
    for prior in r.prior_receipts:
        parts: list[str] = []
        if prior["rcpt_domain"]:
            parts.append(f"for {prior['rcpt_domain']}")
        if prior["mailfrom"]:
            parts.append(f"envelope {prior['mailfrom']}")
        if prior["client_ip"]:
            parts.append(f"client {prior['client_ip']}")
        if parts:
            notes.append(f"Earlier hop ({prior['source']}): " + ", ".join(parts) + ".")
    if r.forward_account:
        notes.append(f"{r.forward_source} names forwarding mailbox {r.forward_account}.")
    elif r.received_as_bcc and r.to_addr:
        notes.append(f"Received as a blind copy. Visible To is {r.to_addr}.")
    if r.attachment_types:
        notes.append(
            "IronPort scanned attachment type(s): " + ", ".join(r.attachment_types) + "."
        )
    return notes


def _block_advice(r: AnalysisResult) -> tuple[list[str], list[str], list[str]]:
    """Return (block, confirm, do_not_block) lines."""
    block: list[str] = []
    confirm: list[str] = []
    spare: list[str] = []
    seen: set[str] = set()
    watched = OrgWatch(domains=set(r.our_domains))

    def add(bucket: list[str], value: str, reason: str) -> None:
        key = value.lower()
        if not value or key in seen:
            return
        seen.add(key)
        bucket.append(f"{value} — {reason}")

    def ours(domain: str) -> bool:
        return bool(domain) and bool(r.our_domains) and _claims_our_domain(domain, watched)

    if (
        r.forwarder_domain
        and not ours(r.forwarder_domain)
        and not _under_huge_mail_parent(r.forwarder_domain)
        and not (r.from_domain and domains_align(r.forwarder_domain, r.from_domain))
    ):
        add(
            block,
            r.forwarder_domain,
            "SRS forwarder domain. The bounce address is one-time; block the domain.",
        )

    if (
        r.forward_account
        and r.forward_account_domain
        and r.our_domains
        and not ours(r.forward_account_domain)
    ):
        add(
            block,
            r.forward_account,
            "Forwarding mailbox named in the headers. The message was delivered to someone else.",
        )
        if not _under_huge_mail_parent(r.forward_account_domain):
            add(block, r.forward_account_domain, "Domain of that forwarding mailbox.")

    if (
        r.received_as_bcc
        and r.to_addr
        and r.to_domain
        and r.to_addr != r.forward_account
        and r.our_domains
        and not ours(r.to_domain)
    ):
        add(
            block,
            r.to_addr,
            "Visible recipient. A mailbox here received this as a blind copy.",
        )
        if not _under_huge_mail_parent(r.to_domain):
            add(block, r.to_domain, "Domain of that visible recipient.")

    for item in r.dkim:
        domain = (item.get("domain") or "").lower().rstrip(".")
        if (item.get("result") or "").lower() != "pass" or not domain:
            continue
        if r.from_domain and domains_align(domain, r.from_domain):
            continue
        if ours(domain) or _under_huge_mail_parent(domain):
            continue
        reason = (
            "DKIM passed for this name, which is not the From domain. "
            "Block this name only, not its parent."
        )
        if r.tenant_id and domain.endswith(".onmicrosoft.com"):
            reason += f" Tenant id {r.tenant_id}."
        add(block, domain, reason)

    if (
        r.reply_to
        and r.reply_to_domain
        and r.from_domain
        and not domains_align(r.reply_to_domain, r.from_domain)
    ):
        if _dmarc_passed(r):
            add(
                confirm,
                r.reply_to,
                "Reply-To is a different domain. From itself passed DMARC.",
            )
        else:
            add(
                block,
                r.reply_to,
                "Reply-To does not match From, and From did not pass DMARC.",
            )

    spoof = any(is_clear_spoof_finding(f) for f in r.findings)
    if spoof and not _dmarc_passed(r) and r.from_addr and not ours(r.from_domain):
        add(block, r.from_addr, "From is part of a spoof finding, and DMARC did not pass.")

    if _dmarc_passed(r) and r.from_addr:
        add(spare, r.from_addr, f"DMARC passed for {r.from_domain or 'the From domain'}.")
    for relay in r.shared_relays:
        add(spare, relay["ip"], relay["note"])
    return block, confirm, spare


def _advice_lines(r: AnalysisResult) -> list[str]:
    lines: list[str] = []
    notes = _path_notes(r)
    block, confirm, spare = _block_advice(r)
    if notes:
        lines.append("What the path shows:")
        lines.extend(f"  • {note}" for note in notes)
    if block:
        lines.append("Addresses and domains to block:")
        lines.extend(f"  • {item}" for item in block)
    if confirm:
        lines.append("Confirm before blocking:")
        lines.extend(f"  • {item}" for item in confirm)
    if spare and (block or confirm):
        lines.append("Do not block:")
        lines.extend(f"  • {item}" for item in spare)
    return lines


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
    # DMARC fail (including p=none) still warrants a block posture.
    # A From/Return-Path mismatch does not, once DMARC passed or the message is a list.
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
        lines.extend(_advice_lines(r))
        return {"action": level, "spoof_findings": len(spoof), "lines": lines}

    if high:
        level = "QUARANTINE"
        forwarded_brand = _authenticated_forward(r) and any(
            f.category == "gateway" and f.severity == "HIGH" and "Forefront" in f.message
            for f in high
        )
        if forwarded_brand:
            lines = [
                "RECOMMENDED ACTION: QUARANTINE / hold — treat as malicious until proven safe.",
                f"From domain {r.from_domain or 'the sender'} authenticated (DMARC passed). "
                f"{r.forwarder_domain} forwarded the message. That domain is not the From domain.",
                "Block the forwarders below. Leave the authenticated From address in place.",
                "Do not clear to the inbox based on headers alone.",
            ]
        else:
            lines = [
                "RECOMMENDED ACTION: QUARANTINE / hold — treat as malicious until proven safe.",
                "No classic domain-spoof auth failures, but HIGH risk signals are present",
                "(gateway reputation, spam confidence, threat verdict, etc.).",
                "Do not clear to the inbox based on headers alone.",
                "Next: inspect body/links/attachments; confirm whether the user expected this sender.",
            ]
        for f in high:
            lines.append(f"  - [{f.category}] {f.message}")
        lines.extend(_advice_lines(r))
        return {"action": level, "spoof_findings": 0, "lines": lines}

    if med:
        level = "INVESTIGATE"
        lines = [
            "RECOMMENDED ACTION: INVESTIGATE — do not clear based on headers alone.",
            "Elevated (MEDIUM) signals present; spoofing is not confirmed from headers.",
            "Verify content, brand impersonation, user context, and any gateway tags.",
        ]
        lines.extend(_advice_lines(r))
        return {"action": level, "spoof_findings": 0, "lines": lines}

    level = "MONITOR"
    lines = [
        "RECOMMENDED ACTION: No block recommended from headers alone.",
        "No high/medium header red flags. Headers look relatively clean.",
        "Still verify: unexpected sender? user expected this? links/attachments?",
    ]
    lines.extend(_advice_lines(r))
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
        "block": _block_advice(r)[0],
        "do_not_block": _block_advice(r)[2],
        "findings": [asdict(f) for f in sorted(r.findings, key=_sev_sort_key)],
        "spf": r.spf,
        "dkim": r.dkim,
        "dmarc": r.dmarc,
        "hops": r.hops,
        "gateway": r.gateway,
        "authentication_results": r.auth_results_raw,
        "tenant_id": r.tenant_id,
        "forward_account": r.forward_account,
        "sendgrid_customer_id": r.sendgrid_customer_id,
        "prior_receipts": r.prior_receipts,
        "shared_relays": r.shared_relays,
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
