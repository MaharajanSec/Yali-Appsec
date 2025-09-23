#!/usr/bin/env python3
"""
headscan.py — friendly header checker for beginners

Usage:
    python headscan.py https://example.com
    python headscan.py domain.com
    python headscan.py -f urls.txt
    python headscan.py --explain full example.com
"""

from __future__ import annotations
import sys
import argparse
import re
import requests
from typing import List, Dict, Any, Tuple
from http.cookies import SimpleCookie
from urllib.parse import urlparse, urljoin

# Color constants (ANSI)
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def parse_security_headers(headers):
    # Normalize keys to lowercase
    normalized = {k.lower(): (v or "").strip() for k, v in headers.items()}

    required = {
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "SAMEORIGIN",
        "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
    }

    missing = []
    fixes = {}

    for h, fix in required.items():
        if h not in normalized or normalized[h] == "":
            missing.append(h)
            fixes[h] = fix

    high_triggers = {"content-security-policy", "strict-transport-security"}
    if any(h in high_triggers for h in missing):
        risk = "HIGH"
    elif missing:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {"missing": missing, "fixes": fixes, "risk": risk}


HEADERS_WE_CARE = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy"
]

HEADER_EXPLAIN = {
    "Content-Security-Policy": (
        "Controls what your page is allowed to load (scripts, images, frames).",
        "Add a CSP that allows only your site and the services you trust (start with: default-src 'self')."
    ),
    "X-Content-Type-Options": (
        "Stops browsers from guessing file types, which helps prevent some attacks.",
        "Set: X-Content-Type-Options: nosniff"
    ),
    "X-Frame-Options": (
        "Prevents other sites from embedding your pages (helps against clickjacking).",
        "Set: X-Frame-Options: SAMEORIGIN (or use CSP frame-ancestors)."
    ),
    "Strict-Transport-Security": (
        "Tells browsers to always use HTTPS for your site.",
        "Set: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    ),
    "Referrer-Policy": (
        "Controls how much URL info is sent when users follow links to other sites.",
        "Set: Referrer-Policy: strict-origin-when-cross-origin"
    ),
    "Permissions-Policy": (
        "Lets you turn off browser features like camera or microphone for your site.",
        "Set: Permissions-Policy: geolocation=(), camera=(), microphone=()"
    ),
}

# Human-first detailed blocks, now with CWE & CVE (NVD) links where available.
HEADER_DETAILS: Dict[str, Dict[str, Any]] = {
    "Content-Security-Policy": {
        "title": "Content-Security-Policy (CSP)",
        "what": "Think of your site as a house and CSP as the guest list. It tells the browser exactly which scripts, images, styles, frames, and other resources are allowed. If something isn't on the list, the browser refuses to load or run it.",
        "why": "Without CSP, an attacker who can inject HTML/JS (e.g., via a comment or bad sanitization) can run code in your users' browsers — steal cookies, hijack actions, or show fake UI. CSP makes many XSS attacks far harder to succeed.",
        "recommended": "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'self'",
        "apache": "Header set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'self'\"",
        "nginx": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'self'\" always;",
        "tips": "Start in Report-Only mode while tuning (so you can see violations without breaking the site). Avoid 'unsafe-eval' and 'unsafe-inline' for scripts; prefer nonces/hashes. Use browser console CSP errors to adjust the policy.",
        "cwe": "CWE-79 — Cross-site Scripting (XSS)",
        "cwe_link": "https://cwe.mitre.org/data/definitions/79.html",
        "cve_links": [
            "https://nvd.nist.gov/vuln/detail/CVE-2020-11023",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-11358"
        ]
    },

    "X-Content-Type-Options": {
        "title": "X-Content-Type-Options",
        "what": "This header tells the browser: 'Trust the Content-Type I sent. Don't guess.'",
        "why": "If browsers guess types (MIME sniffing) an attacker could upload or trick the browser into running a resource as something else (e.g., treat a file as executable JS). 'nosniff' reduces that risk.",
        "recommended": "X-Content-Type-Options: nosniff",
        "apache": "Header set X-Content-Type-Options \"nosniff\"",
        "nginx": "add_header X-Content-Type-Options \"nosniff\";",
        "tips": "Safe to enable broadly. Make sure your app returns correct Content-Type headers for uploads/downloads. Works well together with proper input validation and secure file handling.",
        "cwe": "CWE-434 / related to improper content handling",
        "cwe_link": "https://cwe.mitre.org",
        # No single canonical CVE is the 'nosniff' issue — include resources instead of a misleading CVE.
        "cve_links": [
            "https://portswigger.net/web-security/headers#x-content-type-options"
        ]
    },

    "X-Frame-Options": {
        "title": "X-Frame-Options (and frame-ancestors)",
        "what": "Controls whether other sites are allowed to embed your pages in frames/iframes.",
        "why": "If attackers can place your page inside an invisible frame and trick users into clicking, they can cause unwanted actions (clickjacking). Preventing framing stops many of these tricks.",
        "recommended": "X-Frame-Options: SAMEORIGIN",
        "apache": "Header set X-Frame-Options \"SAMEORIGIN\"",
        "nginx": "add_header X-Frame-Options \"SAMEORIGIN\";",
        "tips": "If you need selective framing (trusted partners), prefer CSP's frame-ancestors for finer control. Test embedded widgets after enabling.",
        "cwe": "CWE-1021 — Improper Restriction of Rendered UI Layers or Frames (Clickjacking)",
        "cwe_link": "https://cwe.mitre.org/data/definitions/1021.html",
        "cve_links": [
            "https://nvd.nist.gov/vuln/detail/CVE-2015-4495"
        ]
    },

    "Strict-Transport-Security": {
        "title": "Strict-Transport-Security (HSTS)",
        "what": "Tells browsers to always use HTTPS for your domain for a set time. Once the browser receives this header, it will refuse plain HTTP for that site for the specified period.",
        "why": "Without HSTS, attackers on the network can attempt downgrade or SSL-stripping attacks — tricking users into HTTP and intercepting their traffic. HSTS forces browsers to stick to HTTPS.",
        "recommended": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "apache": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
        "nginx": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
        "tips": "Only send HSTS over HTTPS responses. Be cautious with includeSubDomains and preload; ensure all subdomains are ready for HTTPS before enabling these.",
        "cwe": "CWE-319 — Cleartext Transmission of Sensitive Information",
        "cwe_link": "https://cwe.mitre.org/data/definitions/319.html",
        "cve_links": [
            "https://nvd.nist.gov/vuln/detail/CVE-2016-9244"
        ]
    },

    "Referrer-Policy": {
        "title": "Referrer-Policy",
        "what": "Controls how much of the URL (the Referer header) the browser sends when users click links or the page makes requests to third parties.",
        "why": "If URLs include sensitive info (tokens, IDs) that can leak via Referer, missing policy can expose those details to other sites. Referrer-Policy reduces accidental leaks.",
        "recommended": "Referrer-Policy: strict-origin-when-cross-origin",
        "apache": "Header set Referrer-Policy \"strict-origin-when-cross-origin\"",
        "nginx": "add_header Referrer-Policy \"strict-origin-when-cross-origin\";",
        "tips": "If you need maximum privacy, use no-referrer, but check integrations that rely on referrer data (analytics, payment flows). Test outgoing requests to ensure nothing sensitive leaks.",
        "cwe": "CWE-200 — Exposure of Sensitive Information",
        "cwe_link": "https://cwe.mitre.org/data/definitions/200.html",
        "cve_links": [
            "https://nvd.nist.gov/vuln/detail/CVE-2018-6128"
        ]
    },

    "Permissions-Policy": {
        "title": "Permissions-Policy (Feature control)",
        "what": "Lets you allow or deny powerful browser features (camera, microphone, geolocation, USB, etc.) for your pages or embedded frames.",
        "why": "If a malicious script runs on your page, it could try to access camera/microphone/geolocation. A good permissions-policy denies these by default and only allows what you actively need.",
        "recommended": "Permissions-Policy: geolocation=(), camera=(), microphone=(), midi=(), payment=(), usb=()",
        "apache": "Header set Permissions-Policy \"geolocation=(), camera=(), microphone=(), midi=(), payment=(), usb=()\"",
        "nginx": "add_header Permissions-Policy \"geolocation=(), camera=(), microphone=(), midi=(), payment=(), usb=()\";",
        "tips": "If you legitimately need a feature (e.g., camera for a video chat), allow only specific origins. Browser support and syntax change — check MDN if you rely on a particular directive.",
        "cwe": "CWE-284 — Improper Access Control",
        "cwe_link": "https://cwe.mitre.org/data/definitions/284.html",
        "cve_links": [
            "https://nvd.nist.gov/vuln/detail/CVE-2019-5825"
        ]
    }
}

SEVERITY_POINTS = {
    "Content-Security-Policy": 3,
    "X-Content-Type-Options": 2,
    "X-Frame-Options": 1,
    "Strict-Transport-Security": 3,
    "Referrer-Policy": 1,
    "Permissions-Policy": 1,
}
COOKIE_MISSING_POINTS = 4


def normalize_url(u: str) -> str:
    if not u.startswith(("http://", "https://")):
        return "https://" + u
    return u


def parse_set_cookie_header(sc_value: str) -> List[Dict[str, Any]]:
    if not sc_value:
        return []

    cookies = []
    parts = re.split(r'(?:\r\n|\n)', sc_value)
    if len(parts) == 1:
        parts = re.split(r', (?=[^ =]+=[^;]+;?)', sc_value)

    for p in parts:
        p = p.strip()
        if not p:
            continue
        try:
            sc = SimpleCookie()
            sc.load(p)
            for name, morsel in sc.items():
                attrs = {}
                low = p.lower()
                attrs['secure'] = 'secure' in low
                attrs['httponly'] = 'httponly' in low
                m = re.search(r'samesite\s*=\s*([a-zA-Z0-9_-]+)', low)
                attrs['samesite'] = m.group(1) if m else None
                cookies.append({'name': name, 'value': morsel.value, 'attrs': attrs, 'raw': p})
        except Exception:
            low = p.lower()
            attrs = {
                'secure': 'secure' in low,
                'httponly': 'httponly' in low,
                'samesite': (re.search(r'samesite\s*=', low) is not None)
            }
            name = p.split('=', 1)[0].strip() if '=' in p else p
            cookies.append({'name': name, 'value': None, 'attrs': attrs, 'raw': p})
    return cookies


def quick_check(url: str, use_head: bool = False, timeout: int = 8, verify: bool = True) -> Dict[str, Any]:
    try:
        if use_head:
            r = requests.head(url, timeout=timeout, allow_redirects=True, verify=verify)
        else:
            r = requests.get(url, timeout=timeout, allow_redirects=True, verify=verify)
    except Exception as e:
        return {"url": url, "error": str(e)}

    hdrs = {k.lower(): v for k, v in r.headers.items()}
    missing = []
    explanations: List[Tuple[str, str, str]] = []
    points = 0

    for h in HEADERS_WE_CARE:
        if h.lower() not in hdrs:
            missing.append(h)
            points += SEVERITY_POINTS.get(h, 1)
            short, fix = HEADER_EXPLAIN.get(h, ("Missing header", "Add the appropriate header"))
            explanations.append((h, short, fix))

    sc_raw = hdrs.get("set-cookie")
    cookies = parse_set_cookie_header(sc_raw) if sc_raw else []
    cookie_notes = []

    if cookies:
        for c in cookies:
            missing_flags = []
            attrs = c.get('attrs', {})
            if not attrs.get('secure'):
                missing_flags.append('Secure')
            if not attrs.get('httponly'):
                missing_flags.append('HttpOnly')
            if not attrs.get('samesite'):
                missing_flags.append('SameSite')
            if missing_flags:
                cookie_notes.append((c.get('raw') or c.get('name'), missing_flags))
                points += COOKIE_MISSING_POINTS
            else:
                cookie_notes.append((c.get('raw') or c.get('name'), []))
    else:
        cookie_notes.append(("no Set-Cookie header seen", []))

    if points >= 7:
        risk = "HIGH"
    elif points >= 3:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "url": url,
        "status": getattr(r, "status_code", None),
        "missing": missing,
        "explanations": explanations,
        "cookie_notes": cookie_notes,
        "risk": risk,
        "raw_headers": hdrs
    }


def print_header_detail(name: str):
    details = HEADER_DETAILS.get(name)
    if not details:
        return
    print(f"\n[{details['title']}]")
    print("\nWhat it does:")
    print(f"  {details['what']}")
    print("\nWhy it matters:")
    print(f"  {details['why']}")
    print("\nRecommended header:")
    print(f"  {details['recommended']}")
    print("\nHow to add it:")
    print("  Apache:")
    print(f"    {details['apache']}")
    print("  Nginx:")
    print(f"    {details['nginx']}")
    print("\nExtra tips:")
    print(f"  - {details['tips']}")
    # CWE and CVE section
    cwe = details.get('cwe')
    if cwe:
        cwe_link = details.get('cwe_link')
        if cwe_link:
            print(f"\nRelated CWE: {cwe} — {cwe_link}")
        else:
            print(f"\nRelated CWE: {cwe}")
    cve_links = details.get('cve_links', [])
    if cve_links:
        print("\nExample CVE(s) / resources:")
        for l in cve_links:
            print(f"  - {l}")
    else:
        print("\nExample CVE(s): none specific — consult CWE resources and advisories.")


def print_friendly(report: Dict[str, Any], explain: str = "short"):
    if "error" in report:
        print(f"\n{RED}{report['url']} -> ERROR: {report['error']}{RESET}")
        return

    risk_color = {"HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN}
    color = risk_color.get(report['risk'], RESET)

    print(f"\n{report['url']}  -> HTTP {report.get('status')}")
    print(f"Overall quick risk: {color}{report['risk']}{RESET}")
    if report['missing']:
        if explain == "short":
            print("\nMissing headers (simple explanation and quick fix):")
            for h, short, fix in report['explanations']:
                print(f" - {h}: {short}")
                print(f"   Quick fix: {fix}")
        else:
            # full explanations
            for h in report['missing']:
                print_header_detail(h)
    else:
        print(f"\n{GREEN}All the checked headers are present (good).{RESET}")

    print("\nCookies:")
    for item, flags in report['cookie_notes']:
        if flags:
            print(f" - {item}")
            print(f"   Issue: missing flags -> {', '.join(flags)}")
            print("   Quick fix: set cookie with Secure; HttpOnly; SameSite=Strict")
        else:
            print(f" - {item}")

    # If cvv_report included in report, show it (backwards-compatible: only shown if caller added it)
    cvv = report.get('cvv_report')
    if cvv:
        cvv_color = {"HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN}.get(cvv['cvv_risk'], RESET)
        print(f"\nCVV risk: {cvv_color}{cvv['cvv_risk']}{RESET} ({cvv['cvv_points']} pts)")
        for n in cvv.get('cvv_notes', []):
            print(f" - {n}")

    if report['risk'] == "HIGH":
        print(f"\n{RED}-> Advice: This site has high-risk gaps. If it's your site, apply the quick fixes above now.{RESET}")
    elif report['risk'] == "MEDIUM":
        print(f"\n{YELLOW}-> Advice: Medium risk. Fix cookie flags and HSTS/X-Content-Type-Options soon.{RESET}")
    else:
        print(f"\n{GREEN}-> Advice: Low risk from these checks. Continue monitoring.{RESET}")

    print("\nTip: For confirmation, open the site in a browser and check Network → Response Headers.")


def main():
    ap = argparse.ArgumentParser(description="Friendly header checker")
    ap.add_argument("urls", nargs="*", help="one or more URLs (or domain names)")
    ap.add_argument("-f", "--file", help="file with URLs, one per line")
    ap.add_argument("--head", action="store_true", help="use HTTP HEAD requests instead of GET (faster)")
    ap.add_argument("--timeout", type=int, default=8, help="request timeout in seconds (default 8)")
    ap.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    ap.add_argument("--explain", choices=["short", "full"], default="short",
                    help="level of explanation for missing headers (short=compact, full=rookie-friendly)")
    args = ap.parse_args()

    urls: List[str] = []
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as fh:
                urls.extend([x.strip() for x in fh if x.strip()])
        except Exception as e:
            print(f"Could not read file: {e}", file=sys.stderr)
            sys.exit(1)
    urls.extend(args.urls)

    if not urls:
        print("Usage: headscan.py <url> | -f file")
        sys.exit(1)

    for u in urls:
        u_norm = normalize_url(u)
        report = quick_check(u_norm, use_head=args.head, timeout=args.timeout, verify=not args.insecure)
        print_friendly(report, explain=args.explain)

if __name__ == "__main__":
    main()
