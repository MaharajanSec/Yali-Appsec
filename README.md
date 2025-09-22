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

