#!/usr/bin/env python3
# headscan.py — friendly header checker for beginners
#
# Usage:
#   python headscan.py https://example.com
#   python headscan.py domain.com
#   python headscan.py -f urls.txt

import sys
import argparse
import re
import requests

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

SEVERITY_POINTS = {
    "Content-Security-Policy": 3,
    "X-Content-Type-Options": 2,
    "X-Frame-Options": 1,
    "Strict-Transport-Security": 3,
    "Referrer-Policy": 1,
    "Permissions-Policy": 1,
}
COOKIE_MISSING_POINTS = 4


def normalize_url(u):
    if not u.startswith(("http://", "https://")):
        return "https://" + u
    return u


def gather_set_cookie_headers(resp):
    sc_list = []

    try:
        raw = getattr(resp, "raw", None)
        orig = getattr(raw, "_original_response", None)
        if orig is not None:
            got = orig.getheaders()
            for item in got:
                if isinstance(item, tuple) and len(item) == 2:
                    k, v = item
                else:
                    try:
                        k, v = item.split(":", 1)
                    except Exception:
                        continue
                if k.strip().lower() == "set-cookie":
                    sc_list.append(v.strip())
    except Exception:
        pass

    if not sc_list:
        raw_sc = resp.headers.get("Set-Cookie")
        if raw_sc:
            parts = re.split(r'\r\n|\n', raw_sc)
            sc_list = [p.strip() for p in parts if p.strip()]

    return sc_list


def parse_set_cookie_attributes(sc):
    parts = [p.strip() for p in sc.split(";") if p.strip()]
    attrs = {"secure": False, "httponly": False, "samesite": False}
    for p in parts[1:]:
        lower = p.lower()
        if lower == "secure":
            attrs["secure"] = True
        elif lower == "httponly":
            attrs["httponly"] = True
        elif lower.startswith("samesite"):
            attrs["samesite"] = True
    return attrs


def quick_check(url):
    try:
        r = requests.get(url, timeout=8, allow_redirects=True)
    except Exception as e:
        return {"url": url, "error": str(e)}

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

    cookie_notes = []
    sc_headers = gather_set_cookie_headers(r)

    if sc_headers:
        for sc in sc_headers:
            attrs = parse_set_cookie_attributes(sc)
            missing_flags = []
            if not attrs["secure"]:
                missing_flags.append("Secure")
            if not attrs["httponly"]:
                missing_flags.append("HttpOnly")
            if not attrs["samesite"]:
                missing_flags.append("SameSite")
            if missing_flags:
                cookie_notes.append((sc, missing_flags))
                points += COOKIE_MISSING_POINTS
            else:
                cookie_notes.append((sc, []))
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

    print("\nCookies:")
    for item, flags in report['cookie_notes']:
        if flags:
            print(f" - {item}")
            print(f"   Issue: missing flags -> {', '.join(flags)}")
            print("   Quick fix: set cookie with Secure; HttpOnly; SameSite=Strict")
        else:
            print(f" - {item}")

    if report['risk'] == "HIGH":
        print("\n-> Advice: This site has high-risk gaps. If it's your site, fix the issues above.")
    elif report['risk'] == "MEDIUM":
        print("\n-> Advice: Medium risk. Consider fixing cookie flags and missing headers soon.")
    else:
        print("\n-> Advice: Low risk from these checks. Keep monitoring.")

    print("\nTip: For verification, open the site in a browser and check Network → Response Headers.")


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
        u_norm = normalize_url(u)
        report = quick_check(u_norm)
        print_friendly(report)


if __name__ == "__main__":
    main()
