# Remediation — Scan 20260929_032224 (http://example.com)

## Findings & fixes

| # | Severity | Finding | Fix | Where |
|---|----------|---------|-----|-------|
| 1 | High | No HTTP -> HTTPS redirect | `return 301 https://$host$request_uri;` in port-80 server block | `nginx_smartvapt.conf` |
| 2 | Medium | Missing Strict-Transport-Security | `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;` (TLS only, per RFC 6797) | `nginx_smartvapt.conf` |
| 3 | Medium | Missing Content-Security-Policy | restrictive `default-src 'self'` policy + `frame-ancestors 'none'` | `nginx_smartvapt.conf` |
| 4 | Medium | Missing X-Frame-Options | `add_header X-Frame-Options "DENY" always;` | `nginx_smartvapt.conf` |
| 5 | Medium | Missing X-Content-Type-Options | `add_header X-Content-Type-Options "nosniff" always;` | `nginx_smartvapt.conf` |
| 6 | Medium | Missing Referrer-Policy | `add_header Referrer-Policy "strict-origin-when-cross-origin" always;` | `nginx_smartvapt.conf` |
| 7 | Medium | Missing Permissions-Policy | `add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()" always;` | `nginx_smartvapt.conf` |

Note: the DNS/email checks from the scan already passed (SPF `-all`, DMARC `p=reject`) — no changes needed there.

## Why a config file instead of a code patch?

All 7 findings are **server-side misconfigurations of the scanned web application**, not bugs in SmartVAPT itself. The scanner correctly reported them. Since nginx is not installed in this workspace (and example.com is not an asset we control), the fix is delivered as a ready-to-deploy hardened nginx site config.

Equivalent directives for other stacks:
- **Apache**: `Header always set ...` / `RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]`
- **Caddy**: automatic HTTPS + `header { ... }` block
- **AWS ALB/CloudFront**: security headers policy + HTTP→HTTPS listener rule

## Deploy

```bash
sudo cp fixes/nginx_smartvapt.conf /etc/nginx/sites-available/default
# adjust server_name, root, and certificate paths, then:
sudo nginx -t && sudo systemctl reload nginx
```

## Verify

```bash
./venv/bin/python -W ignore fixes/verify_fix.py
```

The script starts a local baseline server (reproducing the vulnerable state), runs the real SmartVAPT `WebScanner` checks against it → reproduces all **7 findings**; then starts the hardened configuration (301 redirect + all headers over TLS) → **0 missing headers, working redirect**.

Last run output:
```
BEFORE (baseline)         : 7 findings (... , redirect=yes)
AFTER  redirect check     : HTTP 301 -> https://127.0.0.1:<port>/
AFTER  https status       : 200
AFTER  headers still missing: none
RESULT: ALL 7 FINDINGS FIXED (verified locally)
```

## Apply-and-verify harness (scan 20260929_035956)

`fixes/apply_fix.py` proves the remediation end-to-end using SmartVAPT's own
checks: it starts a local baseline server reproducing example.com's exact
response profile (7 findings), applies `nginx_smartvapt.conf` behaviour
(301 HTTP->HTTPS + all 6 hardened headers), then re-runs the identical
WebScanner checks -> **0 findings remaining**.

Run with: `./venv/bin/python -W ignore fixes/apply_fix.py`

## Remediation for scan 20261001_042608 (scanme.nmap.org)

See **`README_scanme_20261001.md`** — Apache-flavoured configs
(`scanme_apache_security.conf`, `scanme_apache_redirect.conf`) plus an
apply-and-verify harness (`apply_fix_scanme.py`) that clears all 6 missing-header
findings and the HTTP→HTTPS gap, verified with SmartVAPT's own WebScanner.
The 155 CVE findings (Apache 2.4.7 / OpenSSH 6.6.1p1) and SPF/DMARC gaps are
host/DNS-side actions documented in that README.
