#!/usr/bin/env python3
"""
headscan.py — friendly header checker for beginners

Outputs plain-language results so non-experts (and teammates) can see:
 - what is missing,
 - why it matters in one sentence,
 - a simple fix they can give to devs/ops.

Usage:
    python headscan.py https://example.com
    python headscan.py domain.com
    python headscan.py -f urls.txt
"""

import sys
import argparse
import re
import requests

HEADERS_WE_CARE = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy"
]

# Plain-language messages and one-line fixes (non-technical)
HEADER_EXPLAIN = {
    "Content-Security-Policy": (
        "Controls what websites (scripts, images, frames) your page can load.",
        "Add a CSP that allows only your site and needed services (start with: default-src 'self')."
    ),
    "X-Content-Type-Options": (
        "Stops browsers guessing file types, which can prevent some attacks.",
        "Set header: X-Content-Type-Options: nosniff"
    ),
    "X-Frame-Options": (
        "Prevents other sites from embedding your page (clickjacking protection).",
        "Set header: X-Frame-Options: SAMEORIGIN (or use CSP frame-ancestors)."
    ),
    "Strict-Transport-Security": (
        "Tells browsers to always use HTTPS for your site (safer connections).",
        "Set header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    ),
    "Referrer-Policy": (
        "Controls how much URL info is sent when users click links to other sites.",
        "Set header: Referrer-Policy: strict-origin-when-cross-origin"
    ),
    "Permissions-Policy": (
        "Lets you turn off browser features like camera or microphone for your site.",
        "Set a simple one: Permissions-Policy: geolocation=(), camera=(), microphone=()"
    ),
}

# Simple severity points per missing header (higher = worse)
SEVERITY_POINTS = {
    "Content-Security-Policy": 3,
    "X-Content-Type-Options": 2,
    "X-Frame-Options": 1,
    "Strict-Transport-Security": 3,
    "Referrer-Policy": 1,
    "Permissions-Policy": 1,
}
# cookie problems are high priority
COOKIE_MISSING_POINTS = 4

def normalize_url(u):
    if not u.startswith(("http://", "https://")):
        return "https://" + u
    return u

def split_set_cookie(sc):
    if not sc:
        return []
    # basic split: many servers send a single header or several separated by newline
    parts = re.split(r'\r\n|\n', sc)
    if len(parts) == 1:
        # fallback split on ', ' but avoid splitting on 'Expires' by a heuristic
        parts = re.split(r', (?=[^ ]+?=)', sc)
    return [p.strip() for p in parts if p.strip()]

def quick_check(url):
    """Run a quick requests.get and return a simple report dict."""
    try:
        r = requests.get(url, timeout=8, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e)}

    # headers seen (final response); keep lowercase keys for easy check
    hdrs = {k.lower(): v for k, v in r.headers.items()}
    missing = []
    explanations = []
    points = 0

    for h in HEADERS_WE_CARE:
        if h.lower() not in hdrs:
            missing.append(h)
            points += SEVERITY_POINTS.get(h, 1)
            short, fix = HEADER_EXPLAIN.get(h, ("Missing header", "Add the appropriate header"))
            explanations.append((h, short, fix))

    # cookie checks
    cookie_notes = []
    sc = r.headers.get("Set-Cookie")
    cookies = split_set_cookie(sc)
    if cookies:
        for c in cookies:
            lc = c.lower()
            flags = []
            if "secure" not in lc:
                flags.append("Secure")
            if "httponly" not in lc:
                flags.append("HttpOnly")
            if "samesite" not in lc:
                flags.append("SameSite")
            if flags:
                cookie_notes.append((c, flags))
                points += COOKIE_MISSING_POINTS
    else:
        # no cookies at all - that's fine for static sites; note it
        cookie_notes.append(("no Set-Cookie header seen", []))

    # simple risk label
    if points >= 7:
        risk = "HIGH"
    elif points >= 3:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "url": url,
        "status": r.status_code,
        "missing": missing,
        "explanations": explanations,
        "cookie_notes": cookie_notes,
        "risk": risk
    }

def print_friendly(report):
    if "error" in report:
        print(f"\n{report['url']} -> ERROR: {report['error']}")
        return

    print(f"\n{report['url']}  -> HTTP {report['status']}")
    print(f"Overall quick risk: {report['risk']}")
    if report['missing']:
        print("\nMissing headers (simple explanation and quick fix):")
        for h, short, fix in report['explanations']:
            print(f" - {h}: {short}")
            print(f"   Quick fix: {fix}")
    else:
        print("\nAll the checked headers are present (good).")

    # cookies
    print("\nCookies:")
    for item, flags in report['cookie_notes']:
        if flags:
            print(f" - {item}")
            print(f"   Issue: missing flags -> {', '.join(flags)}")
            print("   Quick fix: set cookie with Secure; HttpOnly; SameSite=Strict")
        else:
            print(f" - {item}")

    # very short friendly closing advice
    if report['risk'] == "HIGH":
        print("\n-> Advice: This site has high-risk gaps. If it's your site, apply the quick fixes above now.")
    elif report['risk'] == "MEDIUM":
        print("\n-> Advice: Medium risk. Fix cookie flags and HSTS/X-Content-Type-Options soon.")
    else:
        print("\n-> Advice: Low risk from these checks. Continue monitoring.")

    print("\nTip: For real confirmation, open the site in a browser and check Network → Response Headers.")

def main():
    ap = argparse.ArgumentParser(description="Friendly header checker")
    ap.add_argument("urls", nargs="*", help="one or more URLs (or domain names)")
    ap.add_argument("-f", "--file", help="file with URLs, one per line")
    args = ap.parse_args()

    urls = []
    if args.file:
        try:
            with open(args.file) as fh:
                urls.extend([x.strip() for x in fh if x.strip()])
        except Exception as e:
            print(f"Could not read file: {e}")
            sys.exit(1)
    urls.extend(args.urls)

    if not urls:
        print("Usage: headscan.py <url> | -f file")
        sys.exit(1)

    for u in urls:
        u_norm = normalize = (u if u.startswith(("http://", "https://")) else "https://" + u)
        report = quick_check(u_norm)
        print_friendly(report)

if __name__ == "__main__":
    main()
