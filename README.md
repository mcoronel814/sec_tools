# sec_tools

Small local utilities for day-to-day security analysis work.  
Python 3, run from a terminal; most tools read **local text files you create** (not shipped with the repo).

## Tools

| Script | Purpose | Default input |
|--------|---------|----------------|
| `email_header_spoofing_analyzer.py` | Offline email-header triage (SPF/DKIM/DMARC, identity, path, gateway signals) | `header.txt` |
| `ioc_txt_trimmer.py` | Prep mixed IOCs for Netskope / Check Point (clean, collapse URLs to hosts, protect shared sites) | `ioc.txt` |
| `get_sha256.py` | Resolve hashes to SHA-256 via VirusTotal | `sha1_list.txt` |

## Setup

```bash
git clone https://github.com/mcoronel814/sec_tools.git sec_tools
cd sec_tools
```

### VirusTotal setup (only needed for `get_sha256.py`)

The header analyzer and IOC trimmer need **no** pip packages.  
`get_sha256.py` needs `requests` (listed in `requirements.txt`).

1. Install dependencies once:

```bash
pip install -r requirements.txt
```

2. Create a local `.env` file with your API key (**recommended** — one-time setup):

```bash
cp .env.example .env
```

3. Open `.env` in an editor and replace the placeholder with your real key:

```bash
# .env  (this file is gitignored)
VT_API_KEY=paste_your_real_key_here
```

Get a key from: https://www.virustotal.com/gui/my-apikey

**Note:** `export VT_API_KEY='...'` only sets the key for **that terminal session**.  
It does **not** create a `.env` file. Prefer `.env` so you do not have to export every time.

`get_sha256.py` automatically reads `.env` from the current directory or the script’s folder.

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

**Who this is for:** you pasted hashes, IPs, domains, and URLs from threat reports into one messy list, and you need a clean list to load into **Netskope** or **Check Point** — without blocking all of Google, Telegram, or a URL shortener.

No programming needed. You only edit a text file and run one command.

#### 1. Create your working file (once)

```bash
cp ioc.txt.example ioc.txt
```

#### 2. Paste IOCs into `ioc.txt`

One item per line is best. Extra notes after the IOC are OK — they get dropped. Example of a messy paste from reports:

```text
0d46907320ab55d98966389f41441aa0341a7db829cd166748d8929d466c9fba  malware sample
192.64.119.211
smartviewdevices.com
https://evil-cdn.bad-example.com/payload.exe?id=123
http://zokrie.click:4536/gate
http://abc123.attacker.workers.dev/api/session/status/dev_111
http://abc123.attacker.workers.dev/api/session/status/dev_222
hxxps://also-evil[.]example/login
https://t.me/+InviteCodeHere
https://dictanote.co/n/1393926/
dub.sh/6SaEhaD
```

#### 3. Run the trimmer

```bash
python3 ioc_txt_trimmer.py
```

It **rewrites `ioc.txt` in place** (the messy file becomes the clean file).  
It also prints each kept IOC on screen.

#### What you get back (same file, cleaned)

```text
0d46907320ab55d98966389f41441aa0341a7db829cd166748d8929d466c9fba
192.64.119.211
smartviewdevices.com
evil-cdn.bad-example.com
zokrie.click
abc123.attacker.workers.dev
also-evil.example
https://t.me/+invitecodehere
https://dictanote.co/n/1393926
dub.sh/6saehad
```

Notice:

- Two long `workers.dev` **URLs** became **one hostname** (same host, different paths).
- `hxxps://also-evil[.]example/login` was un-defanged, then reduced to `also-evil.example`.
- `t.me`, `dictanote.co`, and `dub.sh` stayed as **URLs** so you do not block all of Telegram / that SaaS / that shortener.

#### Line-by-line: what happens to each kind of IOC

| You paste | Tool writes | Why |
|-----------|-------------|-----|
| `0d4690…c9fba  malware sample` | `0d4690…c9fba` | Hash kept; note after it is dropped |
| `192.64.119.211` | `192.64.119.211` | IP unchanged |
| `smartviewdevices.com` | `smartviewdevices.com` | Already a hostname |
| `https://evil-cdn.bad-example.com/payload.exe?id=123` | `evil-cdn.bad-example.com` | Attacker URL → **full hostname only** (not the whole `bad-example.com` company) |
| `http://zokrie.click:4536/gate` | `zokrie.click` | Path and port dropped; firewall wants the host |
| Two `….workers.dev/api/session/…` URLs | **one** `….workers.dev` host | Same host, unique paths — those paths would explode a blocklist |
| `hxxps://also-evil[.]example/login` | `also-evil.example` | Defanged URL is repaired (`hxxps`/`[.]`), then collapsed |
| `https://t.me/+InviteCodeHere` | **URL kept** | `t.me` is on the shared-host list — blocking the host would block Telegram |
| `https://dictanote.co/n/1393926/` | **URL kept** | Shared/legit product; the **path** is the IOC |
| `dub.sh/6SaEhaD` | **URL kept** | Shortener — you want this exact link, not all of `dub.sh` |

**Rule of thumb**

- Dedicated malware host → keep the **hostname** (FQDN or IP).
- Shared / household-name site (Google, Telegram, shorteners, many SaaS apps) → keep the **full URL**.
- The tool never “climbs up” to a parent like `workers.dev` or `com`. It only uses the host that was actually in the URL.

#### What you will see in the terminal (besides the clean list)

Lines like this mean a URL was **left as a URL on purpose**:

```text
kept URL (shared host t.me): https://t.me/+invitecodehere
kept URL (shared host dictanote.co): https://dictanote.co/n/1393926
kept URL (shared host dub.sh): dub.sh/6saehad

Wrote 10 unique IOC(s) to ioc.txt  (collapsed URLs→host: 5, kept shared URLs: 3, other: 3)
```

Read those “kept URL” lines before you push the list to the proxy. If a host should have been collapsed (or should have been kept), add or remove it from the shared-host list (below).

#### Shared hosts (“don’t turn this URL into just the domain”)

Shipped file: **`shared_hosts.txt`** (shorteners, big tech, chat apps, common file hosts, plus some abused SaaS).  
This is a **starter list we maintain here**, not an official internet feed. Edit it, or add **your** exceptions without touching the shipped file:

```text
# shared_hosts.local.txt  (create this; it is gitignored)
your-company-saas.example
```

One hostname per line. If the URL’s host **is** that name or a **subdomain** of it, the URL is kept.

#### Optional switches (you can ignore these)

```bash
python3 ioc_txt_trimmer.py path/to/other_iocs.txt   # different file
python3 ioc_txt_trimmer.py --keep-urls              # never collapse URLs (safest, noisiest)
python3 ioc_txt_trimmer.py --hosts-only             # always collapse URLs (ignore the shared list)
python3 ioc_txt_trimmer.py --shared-hosts extra.txt # merge another host list
```

Default (no switches) is the hybrid mode shown in the examples — that is what you want day to day.

### VirusTotal hash → SHA-256

Prerequisite: `.env` with `VT_API_KEY=...` (see setup above), or `export VT_API_KEY='...'` in the current shell.

```bash
# edit sha1_list.txt (one hash per line), then:
python3 get_sha256.py
python3 get_sha256.py path/to/hashes.txt
```

**Never commit API keys** (`.env` is gitignored).

## Repository layout

```
sec_tools/
├── README.md
├── requirements.txt        # pip deps (requests for VirusTotal helper)
├── .gitignore
├── .env.example            # template for VT_API_KEY
├── .env                    # your API key (gitignored — create with: cp .env.example .env)
├── email_header_spoofing_analyzer.py
├── ioc_txt_trimmer.py
├── get_sha256.py
├── shared_hosts.txt        # don't-collapse these hosts from URL → FQDN
├── shared_hosts.local.txt  # optional extra hosts (gitignored)
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
