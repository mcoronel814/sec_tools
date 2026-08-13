# sec_tools

Small **local** helpers for day-to-day security analysis.  
No programming needed: you paste data into a text file, run one command, and read the result.

You stay in control. These tools do **not** change your mail gateway, firewall, or Netskope by themselves.

| What you want to do | Tool | File you edit |
|---------------------|------|----------------|
| A user reported a suspicious email — is it spoofed? | Email header analyzer | `header.txt` |
| I copied IOCs from reports — clean them for a blocklist | IOC list trimmer | `ioc.txt` |
| I have MD5/SHA-1 hashes — I need SHA-256 for a search | VirusTotal hash helper | `sha1_list.txt` |

---

## First-time setup

### 1. Get the folder

```bash
git clone https://github.com/mcoronel814/sec_tools.git sec_tools
cd sec_tools
```

Or download the repo and open a terminal **inside** this folder.

You need **Python 3** (on most work laptops: `python3 --version` should print a version).

### 2. Create your working text files (once)

The repo does **not** ship your real investigation data (headers, IOCs, hashes).  
Those files change every case and can be sensitive. Copy the templates:

```bash
cp header.txt.example header.txt
cp ioc.txt.example ioc.txt
cp sha1_list.txt.example sha1_list.txt
```

Then, for each case, **replace** the example text with your real paste.

| File you create | Used by | What you put in it |
|-----------------|---------|---------------------|
| `header.txt` | Email header analyzer | Full raw headers from Outlook / OWA / the gateway |
| `ioc.txt` | IOC trimmer | One IOC per line (hash, domain, URL, IP, …) |
| `sha1_list.txt` | VirusTotal helper | One file hash per line (MD5, SHA-1, or SHA-256) |

The `*.example` files stay in git as pictures of the format. Your real `header.txt` / `ioc.txt` / `sha1_list.txt` are ignored by git on purpose.

### 3. VirusTotal only (skip this if you only use headers + IOCs)

The header analyzer and IOC trimmer need **no** extra software.

The hash helper talks to VirusTotal, so it needs two things, **once**:

**A. Install the HTTP library**

```bash
pip install -r requirements.txt
```

**B. Save your API key in a `.env` file** (easiest day-to-day method)

```bash
cp .env.example .env
```

Open `.env` in any text editor and replace the placeholder:

```text
VT_API_KEY=paste_your_real_key_here
```

Get a key from: [VirusTotal → API key](https://www.virustotal.com/gui/my-apikey)

`.env` is **not** uploaded to git. Never put a real key in the code or in a ticket screenshot.

`export VT_API_KEY='...'` only lasts for **that terminal window**. It does **not** create `.env`. Prefer the `.env` file so you do not have to export every morning.

---

## Email header analyzer

**Who this is for:** a user reported a suspicious email. You copied the **headers** (not the whole inbox). You want a fast local read: did SPF/DKIM/DMARC pass? Does Reply-To look like a trap? Did IronPort already hate this sender? Should you treat it as spoofing?

No live DNS. The tool only reads what is **already in the headers** (including `Authentication-Results` from your gateway).

### 1. Create your working file (once)

```bash
cp header.txt.example header.txt
```

### 2. Paste the headers into `header.txt`

In Outlook / OWA, open the message → View → **View message details** / **Internet headers** (wording varies).  
Select **all** of the header text and paste it into `header.txt`, replacing the example.

You want the block that starts with lines like `Received:`, `From:`, `Authentication-Results:`, not just the From/Subject you see in the inbox.

### 3. Run the analyzer

From this folder:

```bash
python3 email_header_spoofing_analyzer.py
```

That reads `header.txt` automatically. No extra arguments needed.

### What you get back (on screen)

A text report with five parts:

| Section | What it is in plain language |
|---------|------------------------------|
| Top identity block | Subject, From, Return-Path, Reply-To, To, Date |
| **AUTHENTICATION** | What *your mail gateway already decided* for SPF, DKIM, DMARC |
| **RECEIVED PATH** | The hop list, oldest → newest, with public vs internal IPs |
| **GATEWAY / MTA SIGNALS** | IronPort group/reputation, Exchange SCL, threat scanner, etc. (if present) |
| **FINDINGS** + **ANALYST TAKEAWAY** | Severity-tagged bullets and a recommended **action level** |

### Action levels (read this last)

| Action | Meaning | Typical cause |
|--------|---------|----------------|
| **BLOCK** | Quarantine / delete; do not click or reply | Clear spoof signals: SPF/DKIM/DMARC **fail**, display-name spoof, Reply-To on another domain |
| **QUARANTINE** | Hold it; treat as bad until proven safe | No classic spoof, but HIGH gateway risk (e.g. IronPort `SUSPECTLIST`) |
| **INVESTIGATE** | Do not clear on headers alone | Medium signals only — check body, user context, brand impersonation |
| **MONITOR** | Headers look relatively clean | Still ask: did the user expect this sender? Any links/attachments? |

**Auth can PASS and the mail can still be junk or BEC.** Passing DMARC only means the sending domain is aligned — not that the human is trustworthy.

### Tiny picture of a spoof-shaped case

What you pasted (shortened):

```text
From: "support@legit-bank.com" <attacker@evil.example>
Reply-To: harvest@totally-different.ru
Authentication-Results: mx; spf=fail ...; dkim=fail ...; dmarc=fail (p=reject) ...
Subject: Urgent: Verify Your Account Now
```

What the takeaway is aiming at:

```text
Action level: BLOCK
RECOMMENDED ACTION: BLOCK / quarantine this message.
Do not click links, open attachments, or reply.
  - Display-name spoofing: name contains 'support@legit-bank.com' but From is attacker@evil.example
  - Reply-To domain does not align with From
  - SPF FAIL / DKIM FAIL / DMARC FAIL
```

A different real-world shape: **SPF/DKIM/DMARC all PASS**, but IronPort tagged `SUSPECTLIST` and the subject says `[SUSPECTED SPAM]`. That is usually **QUARANTINE** or **INVESTIGATE**, not “headers say spoof.” The tool will say that explicitly.

### Findings you will see often

| Finding | Plain meaning |
|---------|----------------|
| SPF / DKIM / DMARC **PASS** | Gateway accepted the sending domain as aligned |
| SPF / DKIM / DMARC **FAIL** | Sending IP or signature does not match the claimed domain — strong spoof/break signal |
| Display-name spoofing | The friendly name looks like a trusted address; the real From is someone else |
| Reply-To domain does not align | Replies may go to an attacker mailbox |
| IronPort SenderGroup / negative reputation | Your *existing* email filter already distrusts this source |
| Private IPs in later hops | Normal after mail enters your Exchange — not treated as spoof by itself |

### Optional switches (you can ignore these)

```bash
python3 email_header_spoofing_analyzer.py other_headers.txt   # a different file
python3 email_header_spoofing_analyzer.py --json              # machine-readable output
cat header.txt | python3 email_header_spoofing_analyzer.py -  # paste via pipe
```

Exit codes (for scripts): `0` INFO · `1` LOW · `2` MEDIUM · `3` HIGH · `4` file/read error.

---

## IOC list trimmer

**Who this is for:** you pasted hashes, IPs, domains, and URLs from threat reports into one messy list, and you need a clean list to load into **Netskope** or **Check Point** — without blocking all of Google, Telegram, or a URL shortener.

No programming needed. You only edit a text file and run one command.

### 1. Create your working file (once)

```bash
cp ioc.txt.example ioc.txt
```

### 2. Paste IOCs into `ioc.txt`

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

### 3. Run the trimmer

```bash
python3 ioc_txt_trimmer.py
```

It **rewrites `ioc.txt` in place** (the messy file becomes the clean file).  
It also prints each kept IOC on screen.

### What you get back (same file, cleaned)

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

### Line-by-line: what happens to each kind of IOC

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

### What you will see in the terminal (besides the clean list)

Lines like this mean a URL was **left as a URL on purpose**:

```text
kept URL (shared host t.me): https://t.me/+invitecodehere
kept URL (shared host dictanote.co): https://dictanote.co/n/1393926
kept URL (shared host dub.sh): dub.sh/6saehad

Wrote 10 unique IOC(s) to ioc.txt  (collapsed URLs→host: 5, kept shared URLs: 3, other: 3)
```

Read those “kept URL” lines before you push the list to the proxy. If a host should have been collapsed (or should have been kept), add or remove it from the shared-host list (below).

### Shared hosts (“don’t turn this URL into just the domain”)

Shipped file: **`shared_hosts.txt`** (shorteners, big tech, chat apps, common file hosts, plus some abused SaaS).  
This is a **starter list we maintain here**, not an official internet feed. Edit it, or add **your** exceptions without touching the shipped file:

```text
# shared_hosts.local.txt  (create this; it is gitignored)
your-company-saas.example
```

One hostname per line. If the URL’s host **is** that name or a **subdomain** of it, the URL is kept.

### Optional switches (you can ignore these)

```bash
python3 ioc_txt_trimmer.py path/to/other_iocs.txt   # different file
python3 ioc_txt_trimmer.py --keep-urls              # never collapse URLs (safest, noisiest)
python3 ioc_txt_trimmer.py --hosts-only             # always collapse URLs (ignore the shared list)
python3 ioc_txt_trimmer.py --shared-hosts extra.txt # merge another host list
```

Default (no switches) is the hybrid mode shown in the examples — that is what you want day to day.

---

## VirusTotal hash helper (`get_sha256.py`)

**Who this is for:** a report or ticket gave you **MD5** or **SHA-1** (or a mix), but your EDR / sandbox / sharing template wants **SHA-256**. You do not want to look up each hash by hand on the VirusTotal website.

This tool **only prints SHA-256 values** (one per line). It does not download malware and does not change `sha1_list.txt`.

You need the one-time VirusTotal setup in [First-time setup](#3-virustotal-only-skip-this-if-you-only-use-headers--iocs) (`.env` + `pip install`).

### 1. Create your working file (once)

```bash
cp sha1_list.txt.example sha1_list.txt
```

(The filename is historical — MD5, SHA-1, and SHA-256 are all fine.)

### 2. Paste hashes into `sha1_list.txt`

One hash per line. Blank lines and lines starting with `#` are skipped.

```text
da39a3ee5e6b4b0d3255bfef95601890afd80709
d41d8cd98f00b204e9800998ecf8427e
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### 3. Run the helper

```bash
python3 get_sha256.py
```

### What you get back (on screen)

For each hash VirusTotal knows, **one SHA-256**:

```text
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Copy those into your ticket, EDR search, or `ioc.txt`.

| What happens | Meaning |
|--------------|---------|
| A 64-character hex line prints | VT had that file; that is the SHA-256 |
| `hash not found at VirusTotal: …` (on the error/status stream) | VT has no record (or the key/quota failed for that lookup) |
| `Error: VT_API_KEY is not set` | `.env` is missing or the key line is still the placeholder — see setup above |
| `Error: 'sha1_list.txt' not found` | You have not created the working file yet (`cp sha1_list.txt.example sha1_list.txt`) |

### Optional switches (you can ignore these)

```bash
python3 get_sha256.py path/to/other_hashes.txt
```

---

## What’s in this folder

You do **not** need to memorize this. It is only a map.

| Name | Role |
|------|------|
| `email_header_spoofing_analyzer.py` | Header triage tool |
| `ioc_txt_trimmer.py` | IOC cleanup tool |
| `get_sha256.py` | Hash → SHA-256 via VirusTotal |
| `header.txt` / `ioc.txt` / `sha1_list.txt` | **Your** working data (not in git) |
| `*.example` | Empty-ish templates you copy once |
| `shared_hosts.txt` | Shipped “don’t collapse these sites to a hostname” list |
| `shared_hosts.local.txt` | Optional extra hosts **you** add (not in git) |
| `.env` | Your VirusTotal key (not in git) |
| `.env.example` | Template for that key file |
| `requirements.txt` | `pip install -r requirements.txt` (only for the VT helper) |

---

## Good habits

- Work **inside this folder** so the default filenames (`header.txt`, `ioc.txt`, …) just work.
- Treat headers and IOC lists as **sensitive**. They stay on your machine unless you choose to share them.
- The header tool does not re-check DNS or re-validate DKIM math. It trusts what the gateway already wrote.
- If an old copy of this repo ever had a real API key or real headers in git, **rotate the key** and treat that history as sensitive.
