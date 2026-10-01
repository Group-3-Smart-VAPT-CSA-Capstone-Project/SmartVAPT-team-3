"""CVSS v3.1 base-score calculation and severity-based remediation playbooks."""
from typing import Optional, Dict, List

# ----------------------------------------------------------------------
# CVE context tagging (server / client / config-dependent)
# ----------------------------------------------------------------------
# Banner-based matching (nmap vulners NSE) reports every CVE that *could*
# apply to an advertised version string. Many well-known IDs are actually
# client-side or configuration-dependent issues that cannot be exploited
# against a listening server as such — scoring them at 9.x "critical" with
# the attack path "Direct exploitation of the vulnerable service" is
# inaccurate. Tag each known ID with its real attack surface so reports can
# label it and stop counting it as a directly-exploitable server flaw.
CVE_CLIENT_IDS = {
    # --- OpenSSH client-side ------------------------------------------------
    "CVE-2023-38408": ("client", "libssh agent forwarding: exploitable only when "
                       "ssh-agent forwarding is used against an untrusted server"),
    "CVE-2023-28531": ("client", "libssh smartcard ssh-add PKCS#11 handling"),
    "CVE-2023-51385": ("client", "OpenSSH/termios terminal escape injection via "
                       "a malicious SSH server (client side)"),
    "CVE-2023-48795": ("protocol", "Terrapin prefix-truncation; requires BOTH peer "
                       "and local attacker position or downgrade — affects client "
                       "and server channels"),
    "CVE-2025-26465": ("client", "GSS-API/KRB memory leak in ssh client authentication"),
    "CVE-2020-15778": ("client", "Command injection via tmux control mode, requires "
                       "authorized_keys command forcing on the CLIENT host"),
    "CVE-2019-6111": ("client", "scp client symlink race during download"),
    "CVE-2019-6110": ("client", "scp client TOCTOU/symlink following"),
    "CVE-2021-28041": ("config", "AuthorizedKeysCommand fetched over ssh:// without "
                        "host-key verification (depends on server config)"),
    "CVE-2023-51767": ("client", "libssh client handshake state confusion"),
    "CVE-2023-6004": ("client", "libssh client-side KEX fuzzing issue"),
    "CVE-2016-1908": ("client", "SSH client X11 SECURITY extension escaping"),
    "CVE-2016-0778": ("client", "libssh agent spoofing information disclosure"),
    "CVE-2016-0779": ("client", "libssh agent double-free DoS"),
    "CVE-2015-8325": ("client", "ssh-copy-id rogue-server shell injection (client)"),
    "CVE-2015-5352": ("client", "SSH client tunnel restriction bypass"),
    "CVE-2016-6210": ("server-config", "sshd regex DoS only when Match User/group "
                      "directives are configured"),
    "CVE-2024-6387": ("server", "regreSSHion: signal-handler race in sshd(8), "
                      "Ubuntu/LTS builds ship distro backport patches"),
}


def cve_context(cve_id: str):
    """Return (surface, note) for a known CVE id, else (None, None)."""
    return CVE_CLIENT_IDS.get(str(cve_id or "").upper(), (None, None))


def tag_cve_findings(findings: List[dict]) -> List[dict]:
    """Attach 'cve_surface' ('server'|'client'|'config'|'protocol') and a
    short 'cve_note' to network CVE findings based on the known-ID table.
    Unknown ids default to 'server' (the conservative assumption for a
    banner-matched finding on a listening port)."""
    for f in findings:
        if not f.get("cve"):
            continue
        surface, note = cve_context(f["cve"])
        f["cve_surface"] = surface or "server"
        if note:
            f["cve_note"] = note
        elif str(f.get("evidence") or "").lower().find("banner") >= 0 or \
                f.get("cvss_vector") in (None, ""):
            f.setdefault("cve_note", "Banner/version-match only — not "
                                     "confirmed by an active check.")
    return findings


# ----------------------------------------------------------------------
# CVSS v3.1 vector parsing / scoring
# ----------------------------------------------------------------------
_AVI = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_CUI = {"H": 0.56, "L": 0.22, "N": 0.0}
_SCOPE_CHANGED_K = 7.62   # 8 * Impact when Scope = Changed
_SCOPE_UNCHANGED_K = 7.52  # 10.41 * (1 - Impact) when Scope = Unchanged


def parse_vector(vector: str) -> Dict[str, str]:
    """Parse 'CVSS:3.1/AV:N/AC:L/...' into a metric dict (lower-cased keys)."""
    parts = {}
    for chunk in vector.split("/"):
        if ":" in chunk:
            k, _, v = chunk.partition(":")
            parts[k.strip().upper()] = v.strip().upper()
    return parts


def cvss_v31_base_score(vector: str) -> Optional[float]:
    """Compute the CVSS v3.1 base score from a vector string.

    Returns None when the vector is malformed or not a v3.x vector.
    """
    if not vector or "CVSS:3" not in vector:
        return None
    m = parse_vector(vector)
    try:
        av = _AVI[m["AV"]]
        ac = 0.77 if m["AC"] == "L" else 0.44  # Low complexity = easier = higher weight
        pri = {
            ("N", False): 0.85, ("L", False): 0.62, ("H", False): 0.27,
            ("N", True): 0.85, ("L", True): 0.68, ("H", True): 0.50,
        }[(m["PR"], m.get("S") == "C")]
        ui = 0.62 if m["UI"] == "R" else 0.85  # Required = harder = lower weight
        c = _CUI[m["C"]]
        i = _CUI[m["I"]]
        a = _CUI[m["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    # CVSS v3.1 spec:
    #   Scope Unchanged: Impact = 6.42 * ISS
    #   Scope Changed:   ISCBase = min(7.52*(ISS - 0.0293) - 3.25*(ISS*0.9731 - 0.02)^13, 10)
    #                    Impact = 7.62 * ISCBase
    if m.get("S") == "C":
        isc_base = min(7.52 * (iss - 0.0293) - 3.25 * (iss * 0.9731 - 0.02) ** 13, 10)
        impact = 7.62 * isc_base
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pri * ui

    if impact <= 0:
        return 0.0
    if m.get("S") == "C":
        # Spec: Scope-Changed Impact is already capped at 10 (via ISCBase),
        # so any non-zero impact saturates the base score to 10.
        raw = min(impact + 1.08 * exploitability, 10)
    else:
        raw = min(exploitability + impact, 10)
    return _roundup(raw)


def _roundup(x: float) -> float:
    """CVSS 'Roundup' — smallest number with 1 decimal >= x."""
    import math
    return round(math.ceil(round(x, 10) * 10 - 1e-9) / 10, 1)


def severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


# ----------------------------------------------------------------------
# Remediation playbooks (offline, deterministic)
# ----------------------------------------------------------------------
_PLAYBOOKS: Dict[str, Dict] = {
    "missing_header": {
        "owasp": "A05:2021 - Security Misconfiguration",
        "steps": [
            "Identify the web server / reverse proxy in front of the application.",
            "Add the missing security header globally so every response carries it.",
            "Verify with a re-scan that the header is present on all endpoints.",
        ],
        "commands": {
            "nginx": ["add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
                      "add_header X-Frame-Options \"DENY\" always;",
                      "add_header X-Content-Type-Options \"nosniff\" always;"],
            "apache": ["Header always set Strict-Transport-Security \"max-age=31536000\"",
                       "Header always set X-Frame-Options \"DENY\"",
                       "Header always set X-Content-Type-Options \"nosniff\""],
        },
    },
    "sensitive_path": {
        "owasp": "A01:2021 - Broken Access Control",
        "steps": [
            "Remove the exposed file from the web root immediately.",
            "Rotate any credentials/secrets that may have leaked (.env, id_rsa, AWS keys).",
            "Add deny rules at the web server for dotfiles and backup extensions.",
            "Review access logs for prior GET requests to this path (assume compromise).",
        ],
        "commands": {
            "nginx": ["location ~ /\\.(env|git|aws) { deny all; }",
                      "location ~ \\.(bak|sql|zip|tar\\.gz)$ { deny all; }"],
            "apache": ["<FilesMatch \"^\\.(env|git|ht)\"> Require all denied </FilesMatch>",
                       "Redirect 404 /backup.zip"],
        },
    },
    "tls": {
        "owasp": "A02:2021 - Cryptographic Failures",
        "steps": [
            "Disable TLS 1.0/1.1; require TLS 1.2+ with AEAD cipher suites.",
            "Renew certificates expiring within 30 days and automate renewal (ACME).",
            "Enable HSTS after HTTPS is fully deployed.",
        ],
        "commands": {
            "nginx": ["ssl_protocols TLSv1.2 TLSv1.3;",
                      "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;",
                      "add_header Strict-Transport-Security \"max-age=31536000\" always;"],
            "certbot": ["certbot renew --cert-name <name>", "certbot --nginx -d example.com"],
        },
    },
    "email_security": {
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "steps": [
            "Publish an SPF record listing authorized sending IPs/services.",
            "Publish DMARC starting with p=none, monitor reports, then move to p=quarantine/reject.",
            "Enforce MTA-STS and DNSSEC where supported by your registrar.",
        ],
        "commands": {
            "dns": ["TXT @: \"v=spf1 ip4:<server-ip> include:_spf.<provider> -all\"",
                    "TXT _dmarc: \"v=DMARC1; p=none; rua=mailto:dmarc@<domain>\""],
        },
    },
    "https_redirect": {
        "owasp": "A02:2021 - Cryptographic Failures",
        "steps": [
            "Confirm the host serves TLS on 443 (otherwise the redirect is not applicable).",
            "Configure a permanent 301 redirect from HTTP to HTTPS at the web server.",
            "Enable HSTS only after all clients reliably reach HTTPS.",
        ],
        "commands": {
            "apache": ["RewriteEngine On",
                       "RewriteCond %{HTTPS} off",
                       "RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]"],
            "nginx": ["server { listen 80; return 301 https://$host$request_uri; }"],
        },
    },
    "cve": {
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "steps": [
            "Inventory the affected service/version from the scan evidence.",
            "Upgrade to the vendor-patched release; if unavailable, mitigate via firewall/ACL.",
            "Re-run the scan to confirm the CVE no longer appears.",
        ],
        "commands": {
            "apt": ["apt-get update && apt-get install --only-upgrade <package>"],
            "verify": ["nmap -sV -p <port> <target>"],
        },
    },
    "subdomain_takeover": {
        "owasp": "A05:2021 - Security Misconfiguration",
        "steps": [
            "Remove the dangling CNAME from DNS or provision the service again.",
            "Claim the orphaned resource yourself to prevent attacker takeover.",
            "Add monitoring for future dangling DNS records.",
        ],
        "commands": {
            "dns": ["Delete CNAME <sub>.<domain> -> <orphaned-service-endpoint>"],
        },
    },
    "default": {
        "owasp": "",
        "steps": ["Investigate the finding evidence and confirm impact before remediation."],
        "commands": {},
    },
}

_KEYWORD_MAP = [
    (("security header",), "missing_header"),
    # Must precede the generic ("https",) tls rule below: the redirect
    # finding is about a missing 301 upgrade, NOT weak ciphers — the scan
    # never tested cipher suites, so routing it to the "tls" playbook gave
    # inaccurate attack paths/remediation (SWEET32/BEAST class issues).
    (("redirect",), "https_redirect"),
    (("sensitive", "path exposed", "publicly accessible", ".env", ".git"), "sensitive_path"),
    (("tls", "certificate", "https"), "tls"),
    (("spf", "dmarc", "email"), "email_security"),
    (("cve-",), "cve"),
    (("takeover", "dangling"), "subdomain_takeover"),
]


def playbook_for(title: str, description: str = "") -> Dict:
    """Return the remediation playbook matching a finding's title/description."""
    text = f"{title} {description}".lower()
    for keywords, name in _KEYWORD_MAP:
        if any(k in text for k in keywords):
            pb = _PLAYBOOKS[name]
            return {"owasp": pb["owasp"] or None, "steps": list(pb["steps"]),
                    "commands": pb["commands"]}
    return {"owasp": None, "steps": list(_PLAYBOOKS["default"]["steps"]),
            "commands": {}}


# ----------------------------------------------------------------------
# Exploitation / verification guidance (offline, deterministic).
# Ethical-use note: these are safe VERIFICATION steps a tester may run
# inside the signed scope of a penetration test — not weaponised exploits.
# ----------------------------------------------------------------------
_EXPLOIT_GUIDES: Dict[str, Dict] = {
    "missing_header": {
        "difficulty": "Informational",
        "attack_paths": ["Clickjacking (missing X-Frame-Options/CSP frame-ancestors)",
                         "MIME-confusion scripting (missing X-Content-Type-Options)",
                         "SSL-stripping (missing HSTS)"],
        "verification": [
            "curl -skI <url> | grep -iE 'strict-transport|content-security|x-frame|x-content-type'",
            "Open the page inside an <iframe> on a test page to confirm framing is allowed.",
        ],
        "tools": ["curl", "browser dev-tools", "nuclei (-t http/headers/)"],
    },
    "sensitive_path": {
        "difficulty": "Easy",
        "attack_paths": ["Credential theft from .env / wp-config.bak / id_rsa",
                         "Source disclosure via exposed .git directory",
                         "Database dump download (.sql/.zip backups)"],
        "verification": [
            "curl -sk <url>/<path> | head -c 400   # confirm content is real, then stop",
            "git clone <url>/.git /tmp/poc && git -C /tmp/poc log --oneline | head",
        ],
        "tools": ["gobuster dir", "curl", "git-dumper", "nuclei"],
    },
    "tls": {
        "difficulty": "Moderate",
        "attack_paths": ["Downgrade to weak cipher (SWEET32/BEAST class issues)",
                         "Interception when certificate is invalid/expired"],
        "verification": [
            "openssl s_client -connect <host>:<port> -tls1_1   # should FAIL if hardened",
            "nmap --script ssl-enum-ciphers -p <port> <host>",
        ],
        "tools": ["openssl s_client", "testssl.sh", "sslyze"],
    },
    "email_security": {
        "difficulty": "Easy",
        "attack_paths": ["Domain spoofing for phishing (no SPF/DMARC)",
                         "BEC campaigns using look-alike sender"],
        "verification": [
            "dig +short TXT <domain>            # expect v=spf1 ...",
            "dig +short TXT _dmarc.<domain>     # expect v=DMARC1; p=...",
            "Send a test email from an unauthorized host and observe lack of rejection.",
        ],
        "tools": ["dig", "spfchecker", "dmarcian validator"],
    },
    "cve": {
        "difficulty": "Varies by CVE",
        "attack_paths": ["Direct exploitation of the vulnerable service version",
                         "Pivoting from the exposed service into internal networks"],
        "verification": [
            "Check the advertised version against the CVE advisory range.",
            "Run the matching Nuclei template in non-intrusive mode:",
            "nuclei -u <service-url> -id <cve-id-lowercase> -severity critical,high",
            "Metasploit auxiliary/check modules only where the RoE explicitly allows.",
        ],
        "tools": ["nuclei", "nmap NSE (vulners/http-* scripts)", "metasploit (authorized use)"],
    },
    "subdomain_takeover": {
        "difficulty": "Easy",
        "attack_paths": ["Claim the orphaned resource and serve content for the domain",
                         "Session/token theft via cookies scoped to the parent domain"],
        "verification": [
            "dig +short CNAME <sub>.<domain>    # dangling pointer confirms risk",
            "Attempt provider claim flow ONLY as agreed in the rules of engagement.",
        ],
        "tools": ["dnsrecon", "nuclei (takeover templates)", "subjack"],
    },
    "https_redirect": {
        "difficulty": "Easy",
        "attack_paths": ["SSL-stripping / plaintext credential capture on the HTTP port",
                         "Cookie or token exposure to network observers (no TLS)"],
        "verification": [
            "curl -sI http://<target>/ | grep -iE '^HTTP/|^Location'   # expect 301 -> https://",
            "openssl s_client -connect <host>:443   # confirm HTTPS endpoint exists first",
        ],
        "tools": ["curl", "browser dev-tools"],
    },
    "default": {
        "difficulty": "Assessment required",
        "attack_paths": ["Manual review of evidence to determine reachable attack path."],
        "verification": ["Reproduce the finding with curl/nmap and capture before/after evidence."],
        "tools": ["curl", "nmap", "burpsuite"],
    },
}


def exploit_guide_for(title: str, description: str = "",
                      finding: Optional[dict] = None) -> Dict:
    """Return exploitation/verification guidance keyed off the same playbook
    matcher used for remediation. When the finding carries a CVE tag whose
    attack surface is NOT the listening service (client-side, config- or
    protocol-dependent), replace the generic 'Direct exploitation of the
    vulnerable service' path with one that matches the actual check."""
    text = f"{title} {description}".lower()
    guide = dict(_EXPLOIT_GUIDES["default"])
    for keywords, name in _KEYWORD_MAP:
        if any(k in text for k in keywords):
            guide = dict(_EXPLOIT_GUIDES.get(name, _EXPLOIT_GUIDES["default"]))
            break
    if finding and finding.get("cve"):
        surface = finding.get("cve_surface") or "server"
        note = finding.get("cve_note", "")
        if surface != "server":
            guide["attack_paths"] = [
                f"{surface.capitalize()}-side issue — not directly exploitable "
                f"against the listening service ({note})" if note else
                f"{surface.capitalize()}-side issue — not directly exploitable "
                "against the listening service"]
            guide["difficulty"] = "Context-dependent"
            guide["tools"] = ["CVE advisory / distro CVE tracker", "manual review"]
    return guide


def enrich_findings(findings: List[dict]) -> List[dict]:
    """Attach cvss_score (if vector available), normalized severity and a
    remediation playbook to each finding dict. Mutates and returns the list."""
    tag_cve_findings(findings)
    for f in findings:
        vec = f.get("cvss_vector")
        if vec and f.get("cvss") in (None, 0):
            score = cvss_v31_base_score(vec)
            if score is not None:
                f["cvss"] = score
        if f.get("cvss") is not None:
            try:
                f["severity"] = severity_from_cvss(float(f["cvss"]))
            except (TypeError, ValueError):
                pass
        # Banner-matched CVEs are hypotheses, not confirmed vulnerabilities.
        # Client/config/protocol-surface CVEs additionally cannot be scored
        # as direct server risk; cap them at 'medium' and mark unconfirmed.
        if f.get("cve"):
            if not f.get("confirmed"):
                f["confirmed"] = False
                f.setdefault("confidence", "unconfirmed (banner-based)")
            if f.get("cve_surface") not in (None, "server"):
                from findings import SEVERITY_ORDER
                if SEVERITY_ORDER.get(str(f.get("severity", "")).lower(), 0) \
                        > SEVERITY_ORDER["medium"]:
                    f["severity"] = "medium"
                    f["severity_downgrade_reason"] = (
                        f"CVE is {f['cve_surface']}-surface, not a directly "
                        "exploitable server flaw")
        if not f.get("remediation_steps"):
            pb = playbook_for(f.get("title", ""), f.get("description", ""))
            f["remediation_steps"] = pb["steps"]
            f["remediation_commands"] = pb["commands"]
            if pb["owasp"] and not f.get("owasp"):
                f["owasp"] = pb["owasp"]
        # Ethical-use note: these are safe VERIFICATION steps for use inside
        # the signed scope of a penetration test — not weaponised exploits.
        f["exploitation"] = exploit_guide_for(f.get("title", ""),
                                              f.get("description", ""),
                                              finding=f)
    return findings
