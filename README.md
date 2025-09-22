# \# 🛡️ AppSec Lab

# 

# A collection of Application Security (AppSec) resources, labs, and tools.

# This repository is designed for learning, testing, and demonstrating application security practices, aligned with OWASP Top 10 and other security standards.


# \## Repository Structure

# 

appsec-toolkit/

├── headscan.py      # security header checker

├── xsscheck.py      # reflected XSS tester

├── sqli.py          # naive SQLi error detector

├── authcheck.py     # cookie/session security checks

├── README.md        # simple usage guide

├── requirements.txt # requests, bs4



Contents

labs/ → Hands-on vulnerable apps and exercises (e.g., XSS, SQLi, CSRF)
tools/ → Custom security scripts, payloads, and automation helpers
docs/ → Cheat sheets, references, and study notes

Learning Resources

OWASP Top 10
PortSwigger Web Security Academy
Awesome AppSec

## Quick start

Clone and install:

# Headscan

A small, friendly header checker for beginners — quick AppSec triage for HTTP response headers and cookie flags.

> **Use responsibly.** This repository is for educational purposes only. Do **not** run scans against systems you don't own or have explicit permission to test. Unauthorized testing may be illegal.

---

## Quick start

Clone the repo and prepare a Python virtual environment:

```powershell

PS D:\yalitech\Yali-Appsec> python -m venv .venv
PS D:\yalitech\Yali-Appsec> .venv\Scripts\Activate.ps1
(.venv) PS D:\yalitech\Yali-Appsec> pip install -r requirements.txt
Collecting requests>=2.0 (from -r requirements.txt (line 1))
  Using cached requests-2.32.5-py3-none-any.whl.metadata (4.9 kB)
Collecting charset_normalizer<4,>=2 (from requests>=2.0->-r requirements.txt (line 1))
  Using cached charset_normalizer-3.4.3-cp313-cp313-win_amd64.whl.metadata (37 kB)
Collecting idna<4,>=2.5 (from requests>=2.0->-r requirements.txt (line 1))
  Using cached idna-3.10-py3-none-any.whl.metadata (10 kB)
Collecting urllib3<3,>=1.21.1 (from requests>=2.0->-r requirements.txt (line 1))
  Using cached urllib3-2.5.0-py3-none-any.whl.metadata (6.5 kB)
Collecting certifi>=2017.4.17 (from requests>=2.0->-r requirements.txt (line 1))
  Using cached certifi-2025.8.3-py3-none-any.whl.metadata (2.4 kB)
Using cached requests-2.32.5-py3-none-any.whl (64 kB)
Using cached certifi-2025.8.3-py3-none-any.whl (161 kB)
Using cached charset_normalizer-3.4.3-cp313-cp313-win_amd64.whl (107 kB)
Using cached idna-3.10-py3-none-any.whl (70 kB)
Using cached urllib3-2.5.0-py3-none-any.whl (129 kB)
Installing collected packages: urllib3, idna, charset_normalizer, certifi, requests
Successfully installed certifi-2025.8.3 charset_normalizer-3.4.3 idna-3.10 requests-2.32.5 urllib3-2.5.0

[notice] A new release of pip is available: 25.0.1 -> 25.2
[notice] To update, run: python.exe -m pip install --upgrade pip
(.venv) PS D:\yalitech\Yali-Appsec>  python.exe -m pip install --upgrade pip
Requirement already satisfied: pip in d:\yalitech\yali-appsec\.venv\lib\site-packages (25.0.1)
Collecting pip
  Using cached pip-25.2-py3-none-any.whl.metadata (4.7 kB)
Using cached pip-25.2-py3-none-any.whl (1.8 MB)
Installing collected packages: pip
  Attempting uninstall: pip
    Found existing installation: pip 25.0.1
    Uninstalling pip-25.0.1:
      Successfully uninstalled pip-25.0.1
Successfully installed pip-25.2
(.venv) PS D:\yalitech\Yali-Appsec> python headscan.py https://example.com

https://example.com  -> HTTP 200
Overall quick risk: HIGH

Missing headers (simple explanation and quick fix):
 - Content-Security-Policy: Controls what websites (scripts, images, frames) your page can load.
   Quick fix: Add a CSP that allows only your site and needed services (start with: default-src 'self').
 - X-Content-Type-Options: Stops browsers guessing file types, which can prevent some attacks.
   Quick fix: Set header: X-Content-Type-Options: nosniff
 - X-Frame-Options: Prevents other sites from embedding your page (clickjacking protection).
   Quick fix: Set header: X-Frame-Options: SAMEORIGIN (or use CSP frame-ancestors).
 - Strict-Transport-Security: Tells browsers to always use HTTPS for your site (safer connections).
   Quick fix: Set header: Strict-Transport-Security: max-age=31536000; includeSubDomains
 - Referrer-Policy: Controls how much URL info is sent when users click links to other sites.
   Quick fix: Set header: Referrer-Policy: strict-origin-when-cross-origin
 - Permissions-Policy: Lets you turn off browser features like camera or microphone for your site.
   Quick fix: Set a simple one: Permissions-Policy: geolocation=(), camera=(), microphone=()

Cookies:
 - no Set-Cookie header seen

-> Advice: This site has high-risk gaps. If it's your site, apply the quick fixes above now.

Tip: For real confirmation, open the site in a browser and check Network → Response Headers.
(.venv) PS D:\yalitech\Yali-Appsec> python headscan.py https://owasp.com

https://owasp.com  -> HTTP 200
Overall quick risk: LOW

All the checked headers are present (good).

Cookies:
 - no Set-Cookie header seen

-> Advice: Low risk from these checks. Continue monitoring.

git clone https://github.com/MaharajanSec/Yali-Appsec.git
cd Yali-Appsec

# create & activate virtualenv (Windows PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1

# install deps
pip install -r requirements.txt

Run a quick scan:
python headscan.py https://example.com

You can also scan multiple sites from a file (one URL per line):
python headscan.py -f urls.txt

What it checks (plain language)

The tool looks for common security headers and cookie flags:

Content-Security-Policy — controls what external scripts/images/frames the page can load.

X-Content-Type-Options — prevents MIME sniffing (nosniff).

X-Frame-Options — prevents clickjacking (or use CSP frame-ancestors).

Strict-Transport-Security — tells browsers to always use HTTPS.

Referrer-Policy — controls what URL data is sent to other sites.

Permissions-Policy — controls browser features like camera/microphone.

Cookie flags — checks if cookies include Secure, HttpOnly, and SameSite.

The script prints friendly messages like VULNERABLE / WARNING / OK style lines to help non-experts understand.


👨‍💻 Yali Tech

This repo is part of Yali Tech’s learning and research in Application Security. We’re sharing our tools and labs openly
for educational purposes only.
GitHub: [MaharajanSec](https://github.com/MaharajanSec)

