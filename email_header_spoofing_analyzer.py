import re
import sys
from email.parser import BytesParser
from email.policy import default
import ipaddress

def parse_header_file(file_path):
    """Read and parse email header from a text file."""
    try:
        with open(file_path, 'rb') as f:
            raw_header = f.read()
        parser = BytesParser(policy=default)
        headers = parser.parsebytes(raw_header)
        return headers, raw_header.decode('utf-8', errors='ignore')
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error parsing header file: {e}")
        sys.exit(1)

def extract_received_hops(raw_header):
    """Extract Received header lines in reverse order (most recent first)."""
    received_lines = re.findall(r'^Received:.*?(?=\n(?:[^ \t]|$))', raw_header, re.MULTILINE | re.DOTALL)
    return list(reversed(received_lines))

def extract_ip_from_received(line):
    """Extract IP address (IPv4 or IPv6) from a Received header line."""
    ip_match = re.search(r'\[((?:\d{1,3}\.){3}\d{1,3}|[\d:a-fA-F]+(?::[\d:a-fA-F]+)*(?::[\d:a-fA-F]+)?(?:%[\w\d]+)?)\]', line)
    return ip_match.group(1) if ip_match else None

def is_private_ip(ip):
    """Check if an IP address (IPv4 or IPv6) is private."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def analyze_spoofing(headers, raw_header):
    """Analyze email header for spoofing indicators."""
    report = []
    flags = []

    # 1. Extract key fields
    from_addr = headers.get('From', 'Not found')
    return_path = headers.get('Return-Path', 'Not found')
    subject = headers.get('Subject', 'Not found')
    received_hops = extract_received_hops(raw_header)

    report.append("=== Email Header Spoofing Analysis ===")
    report.append(f"Subject: {subject}")
    report.append(f"From: {from_addr}")
    report.append(f"Return-Path: {return_path}")

    # 2. Check for sender mismatch
    from_domain = re.search(r'@([\w.-]+)', from_addr)
    return_domain = re.search(r'@([\w.-]+)', return_path)
    if from_domain and return_domain and from_domain.group(1).lower() != return_domain.group(1).lower():
        flags.append("WARNING: Mismatch between From and Return-Path domains")
        report.append(f"  - From domain: {from_domain.group(1)}")
        report.append(f"  - Return-Path domain: {return_domain.group(1)}")
        report.append("    This could indicate spoofing if the domains are unrelated.")
    else:
        report.append("  - Sender domains match or no mismatch detected.")

    # 3. Analyze SPF results
    spf_results = re.findall(r'Received-SPF:\s*(\w+)\s*\((.*?)\)(?:\s*.*?envelope-from="([^"]+)")?', raw_header, re.IGNORECASE)
    report.append("\nSPF Analysis:")
    if spf_results:
        for result, details, env_from in spf_results:
            report.append(f"  - SPF Result: {result}")
            report.append(f"    Details: {details}")
            if env_from:
                report.append(f"    Envelope-From: {env_from}")
            if result.lower() in ['fail', 'softfail']:
                flags.append(f"SPF {result.upper()}: Sending IP not authorized for envelope-from domain")
            elif result.lower() == 'pass':
                report.append("    SPF Pass: Sending IP is authorized.")
            else:
                report.append("    SPF result inconclusive.")
    else:
        report.append("  - No SPF results found.")

    # 4. Analyze DKIM results
    dkim_results = re.findall(r'dkim=(\w+)\s*\((.*?)\)\s*header\.i=@([\w.-]+)', raw_header, re.IGNORECASE)
    report.append("\nDKIM Analysis:")
    if dkim_results:
        for result, details, dkim_domain in dkim_results:
            report.append(f"  - DKIM Result: {result}")
            report.append(f"    DKIM Domain: {dkim_domain}")
            report.append(f"    Details: {details}")
            if result.lower() == 'pass':
                if from_domain and dkim_domain.lower() != from_domain.group(1).lower():
                    flags.append("DKIM Misalignment: DKIM domain does not match From domain")
                    report.append("    Warning: DKIM domain does not align with From domain, which may indicate a third-party sender or spoofing.")
                else:
                    report.append("    DKIM Pass: Signature verified and aligned with From domain.")
                    if any('Mismatch between From and Return-Path domains' in flag for flag in flags):
                        report.append("    Note: DKIM pass with sender mismatch may indicate a compromised account.")
            elif result.lower() == 'fail':
                flags.append("DKIM FAIL: Invalid signature detected")
    else:
        report.append("  - No DKIM results found.")

    # 5. Analyze DMARC results (primary)
    dmarc_results = re.findall(r'X-Ironport-Dmarc-Check-Result:\s*(\w+)(?:\s*(.*?))?(?:header\.from=([\w.-]+))?', raw_header, re.IGNORECASE)
    report.append("\nDMARC Analysis (Primary):")
    if dmarc_results:
        for result, details, dmarc_domain in dmarc_results:
            report.append(f"  - DMARC Result: {result}")
            report.append(f"    Details: {details or 'None'}")
            if dmarc_domain:
                report.append(f"    DMARC Domain: {dmarc_domain}")
            if result.lower() == 'fail':
                flags.append("DMARC FAIL: Email does not align with sender's DMARC policy")
            elif result.lower() == 'pass':
                report.append("    DMARC Pass: Email aligns with sender's DMARC policy.")
            else:
                report.append("    DMARC result inconclusive (e.g., 'validskip', 'bestguesspass', 'none').")
    else:
        report.append("  - No primary DMARC results found.")

    # 6. Analyze DMARC results from ARC headers
    arc_dmarc_results = re.findall(r'ARC-Authentication-Results:.*?dmarc=(\w+)\s*([^;]*?)(?:header\.from=([\w.-]+))?(?:;|$)', raw_header, re.IGNORECASE)
    report.append("\nDMARC Analysis (ARC Headers):")
    if arc_dmarc_results:
        for result, details, dmarc_domain in arc_dmarc_results:
            report.append(f"  - ARC DMARC Result: {result}")
            report.append(f"    Details: {details.strip()}")
            if dmarc_domain:
                report.append(f"    DMARC Domain: {dmarc_domain}")
            report.append("    Note: ARC results are from forwarding servers and may not reflect primary DMARC policy.")
    else:
        report.append("  - No ARC DMARC results found.")

    # 7. Analyze Received headers for suspicious hops
    report.append("\nReceived Hops Analysis:")
    for i, hop in enumerate(received_hops, 1):
        report.append(f"  - Hop {i}: {hop.strip()}")
        ip = extract_ip_from_received(hop)
        if ip:
            if is_private_ip(ip):
                flags.append(f"Suspicious Hop {i}: Private IP ({ip}) detected")
                report.append(f"    Warning: Private IP ({ip}) may indicate misconfigured or compromised internal server.")
            else:
                report.append(f"    IP: {ip} (Public)")

    # 8. Check for phishing indicators
    report.append("\nPhishing Indicators:")
    if headers.get('To', '').lower() == 'undisclosed recipients:;':
        flags.append("Phishing Indicator: Undisclosed recipients detected")
        report.append("  - Warning: 'To: Undisclosed recipients' is common in phishing emails.")
    if any(keyword in subject.lower() for keyword in ['pending', 'urgent', 'review', 'share', 'file']):
        flags.append("Phishing Indicator: Suspicious subject line")
        report.append("  - Warning: Subject contains keywords like 'pending', 'urgent', 'review', 'share', or 'file', common in phishing.")
    if from_addr == headers.get('To', ''):
        flags.append("Phishing Indicator: From and To addresses are identical")
        report.append("  - Warning: Identical From and To addresses are common in phishing emails to appear self-sent.")

    # 9. Generate summary
    report.append("\n=== Summary ===")
    if flags:
        report.append("Potential Spoofing/Phishing Indicators Detected:")
        for flag in flags:
            report.append(f"  - {flag}")
        report.append("\nRecommendation: Treat this email as suspicious. Verify the sender's infrastructure and check email content for malicious links or attachments.")
    else:
        report.append("No clear spoofing indicators detected based on header analysis.")
        report.append("Note: Lack of spoofing indicators does not guarantee legitimacy. Check email content and sender reputation.")

    return "\n".join(report)

def main():
    if len(sys.argv) != 2:
        print("Usage: python email_header_spoofing_analyzer.py <header_file.txt>")
        sys.exit(1)

    file_path = sys.argv[1]
    headers, raw_header = parse_header_file(file_path)
    analysis = analyze_spoofing(headers, raw_header)
    print(analysis)

if __name__ == "__main__":
    main()