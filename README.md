# Yali AppSec Lab

A collection of **Application Security (AppSec)** resources, labs, and tools.  
This repository is designed for learning, testing, and demonstrating application security practices, aligned with OWASP Top 10 and other security standards.

---

## Repository structure (suggested)

```
appsec-toolkit/
├── headscan.py      # security header checker
├── xsscheck.py      # reflected XSS tester
├── sqli.py          # naive SQLi error detector
├── authcheck.py     # cookie/session security checks
├── README.md        # simple usage guide
├── requirements.txt # requests, bs4
```

Other useful folders you can add later:
- `labs/` → Hands-on vulnerable apps and exercises (XSS, SQLi, CSRF)
- `tools/` → Custom scripts, payloads, and automation helpers
- `docs/` → Cheat sheets, references, and study notes

Learning resources (links you may add in docs):
- OWASP Top 10
- PortSwigger Web Security Academy
- Awesome AppSec

---

## Headscan

headscan.py — a small, friendly header checker for beginners. Quick AppSec triage for HTTP response headers and cookie flags.

> Use responsibly. This repository is for educational purposes only. Do **not** run scans against systems you don't own or have explicit permission to test. Unauthorized testing may be illegal.

---

## Quick start

Clone the repo and prepare a Python virtual environment:

```powershell
PS D:\yalitech\Yali-Appsec> python -m venv .venv
PS D:\yalitech\Yali-Appsec> .venv\Scripts\Activate.ps1
(.venv) PS D:\yalitech\Yali-Appsec> pip install -r requirements.txt
```

pip will just download requests and a few dependencies

If pip asks you to update, you can run:
```powershell
python.exe -m pip install --upgrade pip
```

---

## Usage

Run the header scan:

```powershell
python headscan.py https://example.com
```

### Sample output (insecure site)
```
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
```

### Sample output (secure site)
```
https://owasp.com  -> HTTP 200
Overall quick risk: LOW

All the checked headers are present (good).

Cookies:
 - no Set-Cookie header seen
```

---

## Quick header cheat-sheet (for rookies)

- **Content-Security-Policy (CSP)**  
  Purpose: restrict which scripts, images and resources the page can load — strong defense against XSS.  
  Quick example: `Content-Security-Policy: default-src 'self';`

- **X-Content-Type-Options**  
  Purpose: prevent MIME sniffing.  
  Quick example: `X-Content-Type-Options: nosniff`

- **X-Frame-Options**  
  Purpose: prevent clickjacking by blocking framing.  
  Quick examples: `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`

- **Strict-Transport-Security (HSTS)**  
  Purpose: tell browsers to always use HTTPS.  
  Quick example: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`

- **Referrer-Policy**  
  Purpose: control how much referrer information is shared.  
  Quick example: `Referrer-Policy: strict-origin-when-cross-origin`

- **Permissions-Policy**  
  Purpose: opt-out of browser features (camera, mic, geolocation).  
  Quick example: `Permissions-Policy: geolocation=(), camera=(), microphone=()`

- **Set-Cookie flags** (if cookies are used)  
  Always set cookie attributes: `Secure; HttpOnly; SameSite=Strict` (or Lax depending on flow).

---

##Quick server snippets (copy-paste)

NGINX
Add these lines inside your server { ... } block:
```nginx
add_header Content-Security-Policy "default-src 'self';" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;

```

Apache
```apache
Add inside your <VirtualHost> block or .htaccess:
Header always set Content-Security-Policy "default-src 'self';"
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), camera=(), microphone=()"

```

**Flask (after_request)**
```python
@app.after_request
def set_security_headers(resp):
    resp.headers['Content-Security-Policy'] = "default-src 'self'"
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    resp.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
    return resp
```

---

## Troubleshooting & tips

- Use `curl -I https://your-site` or PowerShell:
  ```powershell
  (Invoke-WebRequest -Uri "https://example.com" -Method Head).Headers
  ```
  to view raw response headers.

- If the site is behind a proxy or CDN (Cloudflare, etc.), headers may be added/removed by the proxy — test the origin and the public URL.

- If `headscan.py` shows `no Set-Cookie header seen` but your app uses sessions, try the authenticated flow (login) — cookies are often set only after login.

- If PowerShell blocks script activation, allow for current user:
  ```powershell
  Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force
  ```

---

## About Yali Tech


Made with ❤️ at Yali Tech for learners starting their journey in AppSec. We share our tools and labs openly for educational purposes only.
Disclaimer: These resources are for educational use only. Do not use them on systems you don’t own or without explicit permission.

GitHub: [MaharajanSec](https://github.com/MaharajanSec)
