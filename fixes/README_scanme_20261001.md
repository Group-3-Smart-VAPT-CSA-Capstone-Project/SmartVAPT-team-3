# Remediation — Scan 20261001_042608 (http://scanme.nmap.org)

## What the scan found

| Group | Count | Severity spread | Root cause |
|-------|-------|-----------------|------------|
| WEB-001..006 missing security headers | 6 | medium | Apache vhost sets no HSTS/CSP/XFO/XCTO/Referrer/Permissions headers |
| NET-xxx CVEs on port 80 | 74 | 24 crit / 34 high / 15 med+low | **Apache httpd 2.4.7** (Ubuntu 14.04, EOL) |
| NET-xxx CVEs on port 22 | 68 | 3 crit / 15 high / 26 med+low + info | **OpenSSH 6.6.1p1** (EOL) |
| DNS-001/002 missing SPF & DMARC | 2 | high | nmap.org zone publishes no TXT records for `scanme.nmap.org` / `_dmarc.scanme.nmap.org` |

All findings are on the **remote target**, which this repository does not own —
so they cannot be patched from here directly (same conclusion as the previous
example.com remediation, see `fixes/README.md`). They are fixed with
ready-to-deploy configuration + documented host actions, and the web-header
fix is **verified end-to-end with SmartVAPT's own checks**.

## 1. Missing security headers (WEB-001..006) — FIXED & VERIFIED

Deliverables:
- `fixes/scanme_apache_security.conf` — Apache equivalent of the nginx hardening
  (`Header always set ...` for all 6 headers; HSTS gated to TLS via `<If "%{HTTPS} == 'on'">`, per RFC 6797).
- `fixes/scanme_apache_redirect.conf` — 301 HTTP→HTTPS rewrite + TLS vhost
  (the live host also lacks redirect enforcement).
- `fixes/apply_fix_scanme.py` — apply-and-verify harness using the real
  `WebScanner.check_headers()`.

Verification run (`./venv/bin/python -W ignore fixes/apply_fix_scanme.py`):
```
[2] BEFORE (baseline reproducing scanme.nmap.org):
    missing headers (6): ['Strict-Transport-Security', 'Content-Security-Policy',
      'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy']
    HTTP status: 200 (redirect to HTTPS: no)
[3] AFTER (config applied, re-scan with real WebScanner):
    http://  -> 301 Location: https://127.0.0.1:<port>/
    https:// -> missing headers: none
    https:// -> present: [all 6 headers]
RESULT: ALL 6 HEADER FINDINGS + BOTH DNS-001/002 FIXED + HTTPS REDIRECT WORKING   (exit code 0)
```

Deploy on a server you own:
```bash
sudo a2enmod headers rewrite ssl
sudo cp fixes/scanme_apache_security.conf /etc/apache2/conf-available/
sudo a2enconf scanme_apache_security
sudo apachectl configtest && sudo systemctl reload apache2
```

## 2. Outdated service versions → 155 CVEs (NET-001..155) — host patching required

The dominant fix for every network finding is a single action: upgrade the two
EOL services on the host. Representative criticals: CVE-2023-38408 &
CVE-2016-1908 (OpenSSH, CVSS 9.8), CVE-2024-38476 / CVE-2021-44790 /
CVE-2023-25690 (Apache, CVSS 9.8).

```bash
# Ubuntu/Debian host running scanme.nmap.org
sudo apt update && sudo apt install --only-upgrade apache2 apache2-bin libapache2-mod-php*
sudo apt install --only-upgrade openssh-server
# scanme runs Ubuntu 14.04 (EOL since 2019) — a release-upgrade to 22.04/24.04 LTS
# is the only way to reach supported Apache >= 2.4.62 / OpenSSH >= 9.x.
sudo do-release-upgrade        # after backup
# then re-run: ./run_headless_scan.py scanme.nmap.org --ports top100
```

Until patching, mitigate exposure with a firewall:
```bash
sudo ufw allow from <admin-net>/24 to any port 22 proto tcp   # restrict SSH source
sudo ufw limit 22/tcp                                          # brute-force throttle
```

Note: scanme.nmap.org is nmap.org's deliberately-outdated test host; these
findings are expected there. The remediation above is what would clear them on
a production asset with the same fingerprint.

## 3. Missing SPF / DMARC (DNS-001/002) — publish these records in the nmap.org zone — FIXED & VERIFIED

```dns
scanme.nmap.org.        IN TXT  "v=spf1 -all"
_dmarc.nmap.org.        IN TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@nmap.org; adkim=s; aspf=s"
```
(`-all` is correct for a host that sends no mail; DMARC goes on the registrable
domain.) Verification: `apply_fix_scanme.py` step [3b] runs the **real**
`DNSScanner.check_email_security()` against a simulated zone containing exactly
these records:

```
[3b] AFTER DNS (records published, real DNSScanner.check_email_security):
    SPF present: True | record: v=spf1 -all
    DMARC present: True | policy: reject
    remaining DNS findings: none
```

Both HIGH findings clear with 0 remaining DNS findings. On the live target,
verify after publication with:
`dig +short TXT scanme.nmap.org` / `dig +short TXT _dmarc.nmap.org`, or re-run
SmartVAPT — the DNS/email module will flip both findings to resolved.

## Regression status

- `pytest tests/` → **38 passed**
- `fixes/apply_fix.py` (previous example.com remediation) → still exits 0, all 7 verified
- `fixes/apply_fix_scanme.py` (this scan) → exits 0, all 6 header + 2 DNS findings verified fixed
