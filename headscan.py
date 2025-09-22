#!/usr/bin/env python3
"""
Usage:
    python security_headers_simple.py https://example.com
"""

import requests
import sys

# Security headers we care about
NEEDED_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy"
]

def check_headers(url):
    try:
        response = requests.get(url, timeout=8)
    except Exception as e:
        print(f"[!] Could not fetch {url}: {e}")
        return

    print(f"\nChecking headers for: {url}")
    print(f"HTTP {response.status_code}\n")

    headers = response.headers

    for h in NEEDED_HEADERS:
        if h in headers:
            print(f"[+] {h} is present ✅")
        else:
            print(f"[-] {h} is missing ⚠️")

    # Small cookie check
    if "Set-Cookie" in headers:
        cookie = headers["Set-Cookie"].lower()
        if "secure" not in cookie or "httponly" not in cookie:
            print("[-] Cookies are missing Secure/HttpOnly flags ⚠️")
        else:
            print("[+] Cookies have Secure/HttpOnly flags ✅")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python security_headers_simple.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    check_headers(url)
