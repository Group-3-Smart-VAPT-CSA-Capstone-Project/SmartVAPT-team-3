import subprocess, re, ssl, socket, requests, dns.resolver, os
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict, List, Any
from findings import Finding
from evidence import EvidenceStore

SECURITY_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy",
                    "X-Frame-Options", "X-Content-Type-Options",
                    "Referrer-Policy", "Permissions-Policy"]

TECH_SIGNATURES = {"Server": "server", "X-Powered-By": "framework",
                   "X-AspNet-Version": "aspnet", "X-Generator": "cms"}

TECH_BODY_PATTERNS = {
    "WordPress": r"wp-content|wp-includes",
    "Drupal": r"Drupal\.settings|sites/default/files",
    "Joomla": r"/components/com_",
    "React": r"__REACT_DEVTOOLS|react\.production",
    "Vue.js": r"vue\.runtime|__VUE__",
    "Angular": r"ng-version|angular\.min\.js",
    "jQuery": r"jquery[.-]?(\d+\.\d+\.\d+)",
    "Bootstrap": r"bootstrap[.-]?(\d+\.\d+\.\d+)",
}

SENSITIVE_PATHS = [".env", ".git/config", "backup.zip", "backup.tar.gz",
                   "config.php.bak", "wp-config.php.bak", "db.sql",
                   ".htpasswd", "id_rsa", ".aws/credentials"]

def parse_auth_headers(raw: str) -> Dict[str, str]:
    """Parse a user-supplied block of HTTP headers (one 'Name: value' per
    line) into a dict. Blank lines and '#' comments are ignored.

    Typical use is authenticated scanning: Cookie, Authorization, etc.
    """
    headers: Dict[str, str] = {}
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # tolerate an accidental leading "Header-Name::" double colon
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip()
        value = value.strip()
        if name:
            headers[name] = value
    return headers


class WebScanner:
    def __init__(self, target_url: str, evidence: EvidenceStore = None, timeout: int = 10,
                 auth_headers: Dict[str, str] = None):
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url
        self.target = target_url.rstrip("/")
        self.timeout = timeout
        self.evidence = evidence
        self.auth_headers = dict(auth_headers or {})
        self._finding_idx = 0

    def _next_id(self) -> str:
        self._finding_idx += 1
        return f"WEB-{self._finding_idx:03d}"

    def check_headers(self) -> Dict[str, Any]:
        result = {"url": self.target, "missing": [], "present": [],
                  "server": None, "findings": [], "error": None}
        try:
            resp = requests.get(self.target, timeout=self.timeout, allow_redirects=True,
                            headers=self.auth_headers or None)
        except requests.RequestException as e:
            result["error"] = str(e)
            return result
        if self.evidence:
            self.evidence.save_raw("http_headers",
                "\n".join(f"{k}: {v}" for k, v in resp.headers.items()))
        result["server"] = resp.headers.get("Server", "unknown")
        h_lower = {k.lower(): v for k, v in resp.headers.items()}
        for header in SECURITY_HEADERS:
            if header.lower() in h_lower:
                result["present"].append({"header": header, "value": h_lower[header.lower()]})
            else:
                result["missing"].append(header)
                result["findings"].append(Finding(
                    id=self._next_id(), vector="web",
                    title=f"Missing security header: {header}",
                    severity="medium",
                    description=f"The HTTP response does not set {header}.",
                    evidence=f"GET {self.target} -> no '{header}' header",
                    owasp="A05:2021 - Security Misconfiguration",
                    target=self.target,
                    remediation=f"Add '{header}' to web server configuration.",
                ).to_dict())
        return result

    def detect_technologies(self) -> Dict[str, Any]:
        tech = []
        try:
            resp = requests.get(self.target, timeout=self.timeout,
                            headers=self.auth_headers or None)
        except requests.RequestException as e:
            return {"error": str(e), "technologies": []}
        for h, label in TECH_SIGNATURES.items():
            if h in resp.headers:
                tech.append({"name": resp.headers[h], "via": f"header:{h}"})
        body = resp.text[:200000]
        for name, pattern in TECH_BODY_PATTERNS.items():
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                tech.append({"name": name,
                             "version": m.group(1) if m.groups() else None,
                             "via": "body"})
        if self.evidence:
            self.evidence.save_json("technologies", tech)
        return {"technologies": tech, "count": len(tech)}

    def gobuster_scan(self, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                      progress_cb=None, stop_flag=None) -> Dict[str, Any]:
        result = {"target": self.target, "found": [], "findings": [], "error": None}
        if not os.path.exists(wordlist):
            result["error"] = f"Wordlist not found: {wordlist}"
            return result
        cmd = ["gobuster", "dir", "-u", self.target, "-w", wordlist,
               "-q", "--no-error", "-t", "20"]
        # Authenticated scanning: pass session cookie / extra headers through.
        cookie = ""
        for k, v in self.auth_headers.items():
            if k.lower() == "cookie":
                cookie = v
            else:
                cmd += ["-H", f"{k}: {v}"]
        if cookie:
            cmd += ["-c", cookie]
        raw = ""
        try:
            if progress_cb is not None:
                # Real-time mode: stream each discovered path as it appears.
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True,
                                        bufsize=1)
                lines = []
                for line in proc.stdout:
                    lines.append(line)
                    stripped = line.strip()
                    if stripped:
                        progress_cb(stripped)
                    if stop_flag and stop_flag.get("stop"):
                        proc.terminate()
                        result["error"] = "Stopped by user"
                        break
                proc.wait(timeout=300)
                raw = "".join(lines)
            else:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                raw = proc.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            result["error"] = str(e)
            return result
        if self.evidence:
            self.evidence.save_raw("gobuster_output", raw)
        for line in raw.splitlines():
            m = re.search(r"(/\S+)\s+\(Status:\s*(\d+)\)(\s*\[Size:\s*(\d+)\])?", line)
            if m:
                path = m.group(1)
                status = int(m.group(2))
                size = int(m.group(4)) if m.group(4) else 0
                result["found"].append({"path": path, "status": status, "size": size})
                if any(s in path.lower() for s in ["admin", "backup", ".git", ".env",
                                                    "config", "phpmyadmin", "wp-admin"]):
                    result["findings"].append(Finding(
                        id=self._next_id(), vector="web",
                        title=f"Sensitive path exposed: {path}",
                        severity="high" if status == 200 else "medium",
                        description=f"Path {path} returned HTTP {status}.",
                        evidence=line.strip(),
                        owasp="A05:2021 - Security Misconfiguration",
                        target=self.target,
                        remediation=f"Restrict access to {path} or remove it.",
                    ).to_dict())
        return result

    def analyze_tls(self) -> Dict[str, Any]:
        parsed = urlparse(self.target)
        if parsed.scheme != "https":
            return {"enabled": False, "note": "Target not using HTTPS", "findings": []}
        host = parsed.hostname
        port = parsed.port or 443
        result = {"enabled": True, "host": host, "port": port, "cert": {},
                  "issues": [], "findings": []}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    result["cert"] = {"subject": dict(x[0] for x in cert.get("subject", [])),
                                      "issuer": dict(x[0] for x in cert.get("issuer", [])),
                                      "notAfter": cert.get("notAfter"),
                                      "version": ssock.version(),
                                      "cipher": ssock.cipher()[0] if ssock.cipher() else None}
                    if ssock.version() in ("TLSv1", "TLSv1.1"):
                        result["issues"].append(f"Outdated {ssock.version()}")
                    # Certificate expiry validation
                    not_after = cert.get("notAfter")
                    if not_after:
                        try:
                            from email.utils import parsedate_to_datetime
                            exp = parsedate_to_datetime(not_after)
                            days_left = (exp - datetime.now(timezone.utc)).days
                            result["cert"]["days_until_expiry"] = days_left
                            if days_left < 0:
                                result["issues"].append(
                                    f"TLS certificate EXPIRED {-days_left} day(s) ago")
                            elif days_left <= 30:
                                result["issues"].append(
                                    f"TLS certificate expires soon ({days_left} days left)")
                        except (TypeError, ValueError):
                            pass
        except Exception as e:
            result["issues"].append(str(e))
            return result
        if self.evidence:
            self.evidence.save_json("tls_info", result["cert"])
        for issue in result["issues"]:
            result["findings"].append(Finding(
                id=self._next_id(), vector="web",
                title=f"TLS issue: {issue}", severity="medium",
                description=issue, evidence=str(result["cert"]),
                target=self.target,
                remediation="Disable TLS 1.0/1.1 and enable TLS 1.2+.",
            ).to_dict())
        return result

    def fetch_robots_sitemap(self) -> Dict[str, Any]:
        result = {"robots": None, "sitemap": None, "disallowed": [], "findings": []}
        try:
            r = requests.get(f"{self.target}/robots.txt", timeout=self.timeout,
                         headers=self.auth_headers or None)
            if r.status_code == 200:
                result["robots"] = r.text[:5000]
                for line in r.text.splitlines():
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            result["disallowed"].append(path)
                if self.evidence:
                    self.evidence.save_raw("robots_txt", r.text)
        except requests.RequestException:
            pass
        try:
            r = requests.get(f"{self.target}/sitemap.xml", timeout=self.timeout,
                         headers=self.auth_headers or None)
            if r.status_code == 200:
                result["sitemap"] = r.text[:5000]
                if self.evidence:
                    self.evidence.save_raw("sitemap_xml", r.text)
        except requests.RequestException:
            pass
        if result["disallowed"]:
            result["findings"].append(Finding(
                id=self._next_id(), vector="web",
                title=f"robots.txt discloses {len(result['disallowed'])} disallowed paths",
                severity="info",
                description="robots.txt reveals paths that could be sensitive.",
                evidence="\n".join(result["disallowed"][:20]),
                target=self.target,
                remediation="Do not list sensitive paths in robots.txt.",
            ).to_dict())
        return result

    def probe_sensitive_paths(self) -> Dict[str, Any]:
        result = {"found": [], "findings": []}
        for path in SENSITIVE_PATHS:
            url = f"{self.target}/{path}"
            try:
                r = requests.get(url, timeout=self.timeout, allow_redirects=False,
                         headers=self.auth_headers or None)
                if r.status_code in (200, 206):
                    result["found"].append({"path": path, "status": r.status_code,
                                            "size": len(r.content)})
                    result["findings"].append(Finding(
                        id=self._next_id(), vector="web",
                        title=f"Sensitive file publicly accessible: /{path}",
                        severity="critical",
                        description=f"/{path} is publicly readable.",
                        evidence=f"GET {url} -> {r.status_code} ({len(r.content)} bytes)",
                        owasp="A01:2021 - Broken Access Control",
                        target=self.target,
                        remediation=f"Block /{path} at web server and rotate leaked secrets.",
                    ).to_dict())
            except requests.RequestException:
                continue
        return result

    def analyze_redirects(self) -> Dict[str, Any]:
        result = {"chain": [], "findings": []}
        try:
            r = requests.get(self.target, timeout=self.timeout, allow_redirects=True,
                         headers=self.auth_headers or None)
            for h in r.history:
                result["chain"].append({"status": h.status_code, "url": h.url,
                                        "location": h.headers.get("Location")})
            result["chain"].append({"status": r.status_code, "url": r.url, "location": None})
            if self.target.startswith("http://") and not any(
                    h["url"].startswith("https://") for h in r.history):
                result["findings"].append(Finding(
                    id=self._next_id(), vector="web",
                    title="No HTTP -> HTTPS redirect", severity="high",
                    description="Plain HTTP is served without redirecting to HTTPS.",
                    evidence=f"Final URL: {r.url}",
                    owasp="A02:2021 - Cryptographic Failures",
                    target=self.target,
                    remediation="Configure 301 redirect from HTTP to HTTPS.",
                ).to_dict())
            if self.evidence:
                self.evidence.save_json("redirect_chain", result["chain"])
        except requests.RequestException as e:
            result["error"] = str(e)
        return result

class DNSScanner:
    def __init__(self, domain: str, evidence: EvidenceStore = None):
        self.domain = domain.lower().strip()
        self.evidence = evidence

    def check_email_security(self) -> Dict[str, Any]:
        spf = self._check_spf()
        dmarc = self._check_dmarc()
        findings = []
        if not spf["present"]:
            findings.append(Finding(
                id="DNS-001", vector="dns",
                title="Missing SPF record", severity="high",
                description=f"{self.domain} has no SPF TXT record.",
                evidence=spf.get("error") or "No v=spf1 TXT record found",
                owasp="A07:2021 - Identification and Authentication Failures",
                target=self.domain,
                remediation="Publish an SPF record listing authorized senders.",
            ).to_dict())
        if not dmarc["present"]:
            findings.append(Finding(
                id="DNS-002", vector="dns",
                title="Missing DMARC record", severity="high",
                description=f"_dmarc.{self.domain} has no DMARC record.",
                evidence=dmarc.get("error") or "No v=DMARC1 TXT record found",
                owasp="A07:2021 - Identification and Authentication Failures",
                target=self.domain,
                remediation="Publish DMARC with p=none first, then quarantine/reject.",
            ).to_dict())
        elif dmarc.get("policy") == "none":
            findings.append(Finding(
                id="DNS-003", vector="dns",
                title="Weak DMARC policy (p=none)", severity="medium",
                description="DMARC is published but not enforcing.",
                evidence=dmarc.get("record", ""),
                target=self.domain,
                remediation="Move DMARC policy to p=quarantine, then p=reject.",
            ).to_dict())
        result = {"domain": self.domain, "spf": spf, "dmarc": dmarc, "findings": findings}
        if self.evidence:
            self.evidence.save_json("dns_records", result)
        return result

    def _check_spf(self) -> Dict[str, Any]:
        try:
            answers = dns.resolver.resolve(self.domain, "TXT")
            for r in answers:
                txt = r.to_text().strip('"')
                if txt.startswith("v=spf1"):
                    return {"present": True, "record": txt}
            return {"present": False, "record": None, "error": "No v=spf1 record"}
        except Exception as e:
            return {"present": False, "record": None, "error": str(e)}

    def _check_dmarc(self) -> Dict[str, Any]:
        try:
            answers = dns.resolver.resolve(f"_dmarc.{self.domain}", "TXT")
            for r in answers:
                txt = r.to_text().strip('"')
                if txt.startswith("v=DMARC1"):
                    policy = "none"
                    for part in txt.split(";"):
                        if part.strip().startswith("p="):
                            policy = part.split("=")[1].strip()
                    return {"present": True, "record": txt, "policy": policy}
            return {"present": False, "record": None, "error": "No v=DMARC1 record"}
        except Exception as e:
            return {"present": False, "record": None, "error": str(e)}
