# sec_tools

Small local utilities for day-to-day security analysis work.  
Python 3, run from a terminal; most tools read **local text files you create** (not shipped with the repo).

## Tools

| Script | Purpose | Default input |
|--------|---------|----------------|
| `email_header_spoofing_analyzer.py` | Offline email-header triage (SPF/DKIM/DMARC, identity, path, gateway signals) | `header.txt` |
| `ioc_txt_trimmer.py` | Clean IOC lists (first token, lowercase, dedupe, in-place) | `ioc.txt` |
| `get_sha256.py` | Resolve hashes to SHA-256 via VirusTotal | `sha1_list.txt` |

## Setup

```bash
git clone <your-repo-url> sec_tools
cd sec_tools
```

Optional (only needed for VirusTotal lookups):

```bash
pip install requests
export VT_API_KEY='your_virustotal_api_key'   # see .env.example
```

## Working data files (not in git)

Investigation inputs change constantly and may contain **internal mail headers, IOCs, or other sensitive content**.  
They are **gitignored**. Create them locally from the examples:

```bash
cp header.txt.example header.txt
cp ioc.txt.example ioc.txt
cp sha1_list.txt.example sha1_list.txt
```

Then replace the placeholder content with your real data.

| Local file | Used by | What to put in it |
|------------|---------|-------------------|
| `header.txt` | email header analyzer | Full raw email headers (Outlook / OWA / gateway dump) |
| `ioc.txt` | IOC trimmer | One IOC per line (hash, domain, URL, IP, …) |
| `sha1_list.txt` | VT SHA-256 helper | One file hash per line (MD5 / SHA-1 / SHA-256) |

`*.example` files **are** tracked in git as templates only.

## Usage

### Email header analyzer

1. Copy headers from the suspicious message into `header.txt`.
2. Run:

```bash
python3 email_header_spoofing_analyzer.py
# or:
python3 email_header_spoofing_analyzer.py path/to/other_headers.txt
python3 email_header_spoofing_analyzer.py --json
cat headers.txt | python3 email_header_spoofing_analyzer.py -
```

Exit codes: `0` INFO · `1` LOW · `2` MEDIUM · `3` HIGH · `4` I/O error.

The **ANALYST TAKEAWAY** section recommends `BLOCK`, `QUARANTINE`, `INVESTIGATE`, or `MONITOR` based on findings.

### IOC list trimmer

```bash
# edit ioc.txt, then:
python3 ioc_txt_trimmer.py
python3 ioc_txt_trimmer.py path/to/other_iocs.txt
```

Rewrites the file in place with unique, lowercased first-tokens.

### VirusTotal hash → SHA-256

```bash
export VT_API_KEY='...'
# edit sha1_list.txt, then:
python3 get_sha256.py
python3 get_sha256.py path/to/hashes.txt
```

Requires a [VirusTotal API key](https://www.virustotal.com/gui/my-apikey).  
**Never commit API keys.** Prefer environment variables (see `.env.example`).

## Repository layout

```
sec_tools/
├── README.md
├── .gitignore
├── .env.example
├── email_header_spoofing_analyzer.py
├── ioc_txt_trimmer.py
├── get_sha256.py
├── header.txt.example      # template
├── ioc.txt.example         # template
├── sha1_list.txt.example   # template
├── header.txt              # your data (gitignored)
├── ioc.txt                 # your data (gitignored)
└── sha1_list.txt           # your data (gitignored)
```

## Notes

- These tools are for **local analyst workflows**. They do not auto-remediate mail or push gateway policy.
- Header analysis is **offline**: it trusts MTA `Authentication-Results` and does not re-query DNS/DKIM.
- If you previously committed real `header.txt` / `ioc.txt` / `sha1_list.txt` or an API key, rotate any exposed secrets and treat history as sensitive.
