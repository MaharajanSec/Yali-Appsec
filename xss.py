#!/usr/bin/env python3
"""
xsscheck.py

A very human-style reflected XSS tester.

What it does (plain):
 - Put a small harmless payload into a query parameter.
 - Fetch the page and look for the payload string in the response body.
 - If the payload appears, report a possible reflection and show a small HTML snippet.

Important:
 - For learning only. Run only on sites you own or have explicit permission to test.
 - This is a naive check — finding a reflection means "look here", not "it's exploitable".
"""

import sys
import argparse
import requests
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, quote_plus

# A harmless payload that's easy to spot in an HTML response
DEFAULT_PAYLOAD = "<script>alert(1)</script>"

def make_test_url(base_url, param_name, payload):
    """Return the URL after adding/replacing the given query parameter with payload."""
    p = urlparse(base_url)
    params = dict(parse_qsl(p.query, keep_blank_values=True))
    params[param_name] = payload
    new_query = urlencode(params, doseq=True)
    new_p = p._replace(query=new_query)
    return urlunparse(new_p)

def get_page(url, timeout=8):
    """Simple GET with a short timeout. Returns response or None."""
    try:
        return requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        print(f"[ERROR] Network/request problem: {e}")
        return None

def find_payload(body_text, payload):
    """Naive check: does the payload text appear verbatim in the response body?"""
    return payload in body_text

def context_snippet(body_text, payload, chars=60):
    """Return a short snippet around the first payload occurrence (single-line)."""
    i = body_text.find(payload)
    if i == -1:
        return ""
    start = max(0, i - chars)
    end = min(len(body_text), i + len(payload) + chars)
    snippet = body_text[start:end]
    return snippet.replace("\n", " ").replace("\r", "")

def main():
    parser = argparse.ArgumentParser(description="Tiny reflected XSS tester — naive and educational.")
    parser.add_argument("url", help="Target URL (include http:// or https://). Prefer a URL with query parameters.")
    parser.add_argument("-p", "--param", default="q", help="Query parameter name to place payload into (default: q)")
    parser.add_argument("-x", "--payload", default=DEFAULT_PAYLOAD, help="Payload to use (default is harmless alert script)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show HTML snippet around the payload if found")
    args = parser.parse_args()

    if not args.url.startswith(("http://", "https://")):
        print("[ERROR] Please give a full URL starting with http:// or https://")
        sys.exit(1)

    test_url = make_test_url(args.url, args.param, args.payload)
    # show URL in a readable form (payload URL-encoded so user can see the exact request)
    printable_url = test_url.replace(args.payload, quote_plus(args.payload))
    print(f"[i] Testing: {printable_url}")

    resp = get_page(test_url)
    if resp is None:
        sys.exit(1)

    print(f"[i] HTTP {resp.status_code}")

    if find_payload(resp.text, args.payload):
        print("\n[!] Potential reflected XSS — payload found in response ⚠️")
        if args.verbose:
            snippet = context_snippet(resp.text, args.payload)
            if snippet:
                print("\nContext (around payload):")
                print("..." + snippet + "...")
    else:
        print("\n[-] No simple reflection detected (payload not found) ✅")

    print("\nTip: If you see a reflection, inspect the HTML context (is it inside <script>, inside an attribute, or HTML-escaped?). Test in a safe lab (Juice Shop, DVWA).")

if __name__ == "__main__":
    main()
