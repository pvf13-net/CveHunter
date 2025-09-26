# CveHunter
Cves Hunting Tool
Resolve a target (IP or domain), pull exposed services via Shodan InternetDB, and enrich discovered CVEs with NVD base scores — fast, simple, pretty output.

Overview

Give it an IP or domain; it resolves, queries InternetDB, then concurrently scrapes NVD for CVSS base scores.

Prints Rich tables in the terminal or clean text when writing to a file.

Great for quick recon/triage during assessments.

Features:

1. Auto domain → IP resolution

2. Concurrent CVE enrichment (--threads)

3. Retries + timeouts to handle flaky networks

4. Rich terminal UI; plain text when -o is used

5. Sorted, de-duplicated hostnames/ports/CVEs

6. No API keys required

Installation
git clone https://github.com/pvf13-net/CveHunter.git
cd CveHunter

python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows (PowerShell)
.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -r requirements.txt


requirements.txt

requests
rich
beautifulsoup4

Usage
# Scan a domain (auto-resolve)
python CveHunter.py -d example.org

# Scan an IP
python CveHunter.py -d 1.2.3.4

# Save results to file (plain text)
python CveHunter.py -d example.org -o results.txt

# Tune performance / network behavior
python CveHunter.py -d example.org --threads 16 --timeout 20


CLI

usage: CveHunter.py [-h] [-d DOMAIN] [-o OUTPUT] [--threads THREADS] [--timeout TIMEOUT]


-d / --domain : IP or domain

-o / --output : Write readable text to file

--threads : Max concurrent CVE lookups (default: 8)

--timeout : HTTP timeout seconds (default: 10)

Output

Console (Rich): Banner + Hostnames + Open Ports + CVEs with base score and NVD link.
File (-o): Plain text sections. Example:

Hostnames:
 -> foo.example.org
Open Ports:
 -> 80
Vulnerabilities (CVEs):
 -> | CVE-2023-12345 | 7.5 | https://nvd.nist.gov/vuln/detail/CVE-2023-12345 |

Tips

Bigger CVE sets → increase --threads (e.g., 12–24).

Slow networks → increase --timeout.

Scraping fails sometimes; re-run or reduce threads.


Author: pvf13-net · CVE Hunting Tool — “Hunting CVEs” 🕷️
