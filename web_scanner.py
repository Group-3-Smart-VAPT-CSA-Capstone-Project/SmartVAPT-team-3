import hashlib
import os
import re
import secrets
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import dns.resolver
import requests

from command_tracker import run_logged
from evidence import EvidenceStore
from findings import Finding

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

SOFT404_PROBES = 3

EXPECTED_CONTENT_TYPES = {
    ".zip":          ["application/zip"],
    ".gz":           ["application/gzip", "application/x-gzip",
                      "application/x-tar", "application/x-compressed"],
    ".tar.gz":       ["application/gzip", "application/x-gzip",
                      "application/x-tar", "application/x-compressed"],
    ".sql":          ["text/plain", "application/sql", "application/x-sql",
                      "text/x-sql"],
    ".bak":          ["text/plain", "application/octet-stream"],
    ".env":          ["text/plain", "application/octet-stream"],
    ".htpasswd":     ["text/plain", "application/octet-stream"],
    ".git/config":   ["text/plain", "application/octet-stream"],
    "id_rsa":        ["text/plain", "application/octet-stream"],
    ".aws/credentials": ["text/plain", "application/octet-stream"],
}
HTML_MIME_RE = re.compile(r"text/html|application/xhtml", re.IGNORECASE)

SIGNATURE_PATTERNS = {
    ".env":          [r"(?m)^[A-Z][A-Z0-9_.]{1,60}\s*=\s*\S"],
    ".git/config":   [r"\[core\]|\[remote"],
    "id_rsa":        [r"-----BEGIN (?:OPENSSH |RSA |DSA |EC |PGP )?PRIVATE KEY-----"],
    ".htpasswd":     [r"(?m)^[A-Za-z0-9._@\-]{2,64}:[^\s:]{13,}"],
    ".aws/credentials": [r"(?m)^\s*\[[A-Za-z0-9_\-]+\]\s*$",
                         r"(?i)(aws_access_key_id|aws_secret_access_key)\s*="],
    ".sql":          [(r"(?i)/\*.*\*/|CREATE\s+(?:TABLE|DATABASE)|INSERT\s+INTO|"
                      r"DUMP|ALTER\s+TABLE|USE\s+\w")],
    ".php.bak":      [r"<\?php|<\?=|echo\s|DB_NAME|define\s*\("],
    ".bak":          [r"<\?php|password|secret|key|host|user|define\s*\("],
}

BINARY_SIGNATURES = {
    ".zip":    [b"PK\x03\x04", b"PK\x05\x06"],
    ".tar.gz": [b"\x1f\x8b"],
    ".gz":     [b"\x1f\x8b"],
}


def _extension_key(path: str) -> str | None:
    pl = path.lower().strip("/")
    if pl in SIGNATURE_PATTERNS or pl in EXPECTED_CONTENT_TYPES:
        return pl
    candidates = sorted(set(SIGNATURE_PATTERNS) | set(EXPECTED_CONTENT_TYPES), key=len, reverse=True)
    for ext in candidates:
        if ext.startswith(".") and pl.endswith(ext):
            return ext
    base = pl.rsplit("/", 1)[-1]
    for key in set(SIGNATURE_PATTERNS) | set(EXPECTED_CONTENT_TYPES):
        if not key.startswith(".") and (base == key or pl.endswith(key)):
            return key
    return None


def _primary_mime(content_type: str | None) -> str:
    return (content_type or "").split(";")[0].strip().lower()


def _html_title(body: str) -> str | None:
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1).strip()[:200]
    return None


def matches_soft404_baseline(meta: dict[str, Any], baseline: dict[str, Any] | None) -> bool:
    if not baseline or not baseline.get("detected"):
        return False
    if baseline.get("body_sha256") and meta.get("body_sha256") == baseline["body_sha256"]:
        return True
    if baseline.get("body_size") is not None and meta.get("size") == baseline["body_size"]:
        return True
    t1, t2 = baseline.get("title"), meta.get("title")
    return bool(t1 and t2 and t1 == t2)


def content_type_ok(path: str, content_type: str | None) -> bool:
    mime = _primary_mime(content_type)
    if not mime:
        return True
    if HTML_MIME_RE.search(mime):
        return False
    ext = _extension_key(path)
    allowed = EXPECTED_CONTENT_TYPES.get(ext or "")
    if allowed:
        return mime in allowed
    return True


def has_valid_signature(path: str, head_bytes: bytes) -> bool:
    ext = _extension_key(path)
    if not ext:
        return True
    blob = head_bytes or b""
    for magic in BINARY_SIGNATURES.get(ext, []):
        if magic in blob[:16]:
            return True
    patterns = SIGNATURE_PATTERNS.get(ext, [])
    try:
        text = blob.decode("utf-8", errors="replace")
    except Exception:
        return False
    if "\x00" in text and not BINARY_SIGNATURES.get(ext):
        return False
    return any(re.search(p, text) for p in patterns)


def parse_auth_headers(raw: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
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
                 auth_headers: dict[str, str] | None = None):
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url
        self.target = target_url.rstrip("/")
        self.timeout = timeout
        self.evidence = evidence
        self.auth_headers = dict(auth_headers or {})
        self._finding_idx = 0
        p = urlparse(self.target)
        self.port = p.port or (443 if p.scheme == "https" else 80)
        self.service = "https" if p.scheme == "https" else "http"

    def set_target(self, url: str, port=None, service=None):
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        self.target = url.rstrip("/")
        p = urlparse(self.target)
        self.port = port or p.port or (443 if p.scheme == "https" else 80)
        self.service = service or ("https" if p.scheme == "https" else "http")

    def _next_id(self) -> str:
        self._finding_idx += 1
        return f"WEB-{self._finding_idx:03d}"

    def _mk_finding(self, **kw) -> dict[str, Any]:
        kw.setdefault("port", self.port)
        kw.setdefault("service", self.service)
        return Finding(**kw).to_dict()

    def tls_available(self) -> bool:
        parsed = urlparse(self.target)
        host = parsed.hostname
        port = 443
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as s, \
                    ctx.wrap_socket(s, server_hostname=host):
                return True
        except Exception:
            return False

    def check_headers(self) -> dict[str, Any]:
        result = {"url": self.target, "missing": [], "present": [],
                  "server": None, "findings": [], "error": None}
        try:
            resp = requests.get(self.target, timeout=self.timeout, allow_redirects=True,
                                headers=self.auth_headers or None)
        except requests.RequestException as e:
            result["error"] = str(e)
            return result
        if resp.status_code >= 400:
            result["error"] = (f"Server returned HTTP {resp.status_code} "
                               "to a plain GET; header audit skipped.")
            return result
        if self.evidence:
            self.evidence.save_raw("http_headers", "\n".join(f"{k}: {v}" for k, v in resp.headers.items()))
        result["server"] = resp.headers.get("Server", "unknown")
        is_https = urlparse(self.target).scheme == "https"
        h_lower = {k.lower(): v for k, v in resp.headers.items()}
        for header in SECURITY_HEADERS:
            if header.lower() == "strict-transport-security" and not is_https:
                continue
            if header.lower() in h_lower:
                result["present"].append({"header": header, "value": h_lower[header.lower()]})
            else:
                result["missing"].append(header)
                result["findings"].append(self._mk_finding(
                    id=self._next_id(), vector="web",
                    title=f"Missing security header: {header}",
                    severity="medium",
                    description=f"The HTTP response does not set {header}.",
                    evidence=f"GET {self.target} -> no '{header}' header",
                    owasp="A05:2021 - Security Misconfiguration",
                    target=self.target,
                    remediation=f"Add '{header}' to web server configuration.",
                ))
        return result

    def detect_technologies(self) -> dict[str, Any]:
        tech = []
        try:
            resp = requests.get(self.target, timeout=self.timeout,
                                headers=self.auth_headers or None)
        except requests.RequestException as e:
            return {"error": str(e), "technologies": []}
        for h in TECH_SIGNATURES:
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
                      progress_cb=None, stop_flag=None,
                      http_services: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        if http_services:
            self.set_target(http_services[0].get("url") or self.target)
        result = {"target": self.target, "found": [], "findings": [], "error": None}
        if not http_services:
            result["error"] = ("No HTTP service detected by nmap -sV for this "
                               "target; directory brute-forcing skipped.")
            return result
        if not os.path.exists(wordlist):
            result["error"] = f"Wordlist not found: {wordlist}"
            return result
        cmd = ["gobuster", "dir", "-u", self.target, "-w", wordlist,
               "-q", "--no-error", "-t", "20"]
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
                proc = run_logged(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
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
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
                raw = proc.stdout
        except FileNotFoundError:
            raw = self._python_dir_fuzz(wordlist, progress_cb, stop_flag)
            if raw is None:
                result["error"] = "Stopped by user"
        except subprocess.TimeoutExpired as e:
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
                    result["findings"].append(self._mk_finding(
                        id=self._next_id(), vector="web",
                        title=f"Sensitive path exposed: {path}",
                        severity="high" if status == 200 else "medium",
                        description=f"Path {path} returned HTTP {status}.",
                        evidence=line.strip(),
                        owasp="A05:2021 - Security Misconfiguration",
                        target=self.target,
                        remediation=f"Restrict access to {path} or remove it.",
                    ))
        return result

    def _python_dir_fuzz(self, wordlist: str, progress_cb=None, stop_flag=None):
        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed
        try:
            with open(wordlist, "r", errors="replace") as fh:
                words = [w.strip().lstrip("/") for w in fh if w.strip()]
        except OSError:
            return ""
        words = words[:4600]
        found_lines: list[str] = []
        lock = threading.Lock()

        def probe(word: str):
            url = f"{self.target}/{word}"
            try:
                resp = requests.get(url, timeout=self.timeout, allow_redirects=False,
                                    headers=self.auth_headers or None)
            except requests.RequestException:
                return None
            status = resp.status_code
            if status in (200, 201, 202, 204, 301, 302, 303, 307, 308,
                          401, 403, 405):
                size = len(resp.content)
                return f"/{word}  (Status: {status}) [Size: {size}]"
            return None

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(probe, w): w for w in words}
            for fut in as_completed(futures):
                if stop_flag and stop_flag.get("stop"):
                    pool.shutdown(wait=False, cancel_futures=True)
                    return None
                line = fut.result()
                if line:
                    with lock:
                        found_lines.append(line)
                    if progress_cb:
                        progress_cb(line)
        return "\n".join(found_lines)

    def analyze_tls(self) -> dict[str, Any]:
        parsed = urlparse(self.target)
        if parsed.scheme != "https":
            return {"enabled": False, "note": "Target not using HTTPS", "findings": []}
        host = parsed.hostname
        port = parsed.port or 443
        result = {"enabled": True, "host": host, "port": port, "cert": {},
                  "issues": [], "findings": []}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock, \
                    ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                result["cert"] = {"subject": dict(x[0] for x in cert.get("subject", [])),
                                  "issuer": dict(x[0] for x in cert.get("issuer", [])),
                                  "notAfter": cert.get("notAfter"),
                                  "version": ssock.version(),
                                  "cipher": ssock.cipher()[0] if ssock.cipher() else None}
                if ssock.version() in ("TLSv1", "TLSv1.1"):
                    result["issues"].append(f"Outdated {ssock.version()}")
                not_after = cert.get("notAfter")
                if not_after:
                    try:
                        from email.utils import parsedate_to_datetime
                        exp = parsedate_to_datetime(not_after)
                        days_left = (exp - datetime.now(timezone.utc)).days
                        result["cert"]["days_until_expiry"] = days_left
                        if days_left < 0:
                            result["issues"].append(f"TLS certificate EXPIRED {-days_left} day(s) ago")
                        elif days_left <= 30:
                            result["issues"].append(f"TLS certificate expires soon ({days_left} days left)")
                    except (TypeError, ValueError):
                        pass
        except Exception as e:
            result["issues"].append(str(e))
            return result
        if self.evidence:
            self.evidence.save_json("tls_info", result["cert"])
        for issue in result["issues"]:
            result["findings"].append(self._mk_finding(
                id=self._next_id(), vector="web",
                title=f"TLS issue: {issue}", severity="medium",
                description=issue, evidence=str(result["cert"]),
                target=self.target,
                remediation="Disable TLS 1.0/1.1 and enable TLS 1.2+.",
            ))
        return result

    def fetch_robots_sitemap(self) -> dict[str, Any]:
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
            result["findings"].append(self._mk_finding(
                id=self._next_id(), vector="web",
                title=f"robots.txt discloses {len(result['disallowed'])} disallowed paths",
                severity="info",
                description="robots.txt reveals paths that could be sensitive.",
                evidence="\n".join(result["disallowed"][:20]),
                target=self.target,
                remediation="Do not list sensitive paths in robots.txt.",
            ))
        return result

    def detect_soft404_baseline(self) -> dict[str, Any]:
        probes = []
        for _ in range(SOFT404_PROBES):
            token = secrets.token_hex(8)
            path = f"smvapt-{token}-404-{secrets.randbelow(99999)}"
            url = f"{self.target}/{path}"
            entry = {"path": path, "status": None, "size": None,
                     "body_sha256": None, "title": None, "content_type": None}
            try:
                r = requests.get(url, timeout=self.timeout, allow_redirects=False,
                                 headers=self.auth_headers or None)
                entry["status"] = r.status_code
                entry["size"] = len(r.content)
                entry["body_sha256"] = hashlib.sha256(r.content).hexdigest()
                entry["content_type"] = _primary_mime(r.headers.get("Content-Type"))
                try:
                    entry["title"] = _html_title(r.text[:20000])
                except Exception:
                    entry["title"] = None
            except requests.RequestException as e:
                entry["error"] = str(e)
            probes.append(entry)

        twos = [p for p in probes if p["status"] == 200]
        baseline = {"detected": False, "probed": len(probes), "returned_200": len(twos),
                    "note": "", "probes": probes, "body_size": None,
                    "body_sha256": None, "title": None, "content_type": None}
        if twos and len(twos) >= max(1, len(probes) - 1):
            sizes = [p["size"] for p in twos]
            hashes = [p["body_sha256"] for p in twos]
            titles = [p["title"] for p in twos if p["title"]]
            baseline["detected"] = True
            baseline["body_size"] = max(set(sizes), key=sizes.count)
            baseline["body_sha256"] = max(set(hashes), key=hashes.count)
            baseline["title"] = max(set(titles), key=titles.count) if titles else None
            baseline["content_type"] = twos[0]["content_type"]
            baseline["note"] = (f"Soft-404 baseline recorded: {len(twos)}/{len(probes)} random "
                                f"paths returned HTTP 200 (typical size "
                                f"{baseline['body_size']} bytes, title {baseline['title']!r}). "
                                f"Matching responses will be discarded during sensitive-file "
                                f"scanning.")
        elif twos:
            baseline["note"] = ("Some random paths returned 200 but no reliable "
                                "majority baseline; size/hash filtering skipped.")
        else:
            baseline["note"] = ("Server returns proper error codes for "
                                "non-existent paths; no soft-404 baseline needed.")
        self._soft404_baseline = baseline
        if self.evidence:
            self.evidence.save_json("soft404_baseline", baseline)
        return baseline

    @property
    def soft404_baseline(self) -> dict[str, Any] | None:
        cached = getattr(self, "_soft404_baseline", None)
        if cached is None:
            cached = self.detect_soft404_baseline()
        return cached

    def probe_sensitive_paths(self) -> dict[str, Any]:
        HEAD_BYTES = 400
        result = {"found": [], "findings": [], "discarded": [], "soft404_baseline": None}
        baseline = self.detect_soft404_baseline()
        result["soft404_baseline"] = {k: baseline[k] for k in ("detected", "probed", "returned_200",
                                                              "body_size", "body_sha256", "title", "note")}
        for path in SENSITIVE_PATHS:
            url = f"{self.target}/{path}"
            try:
                r = requests.get(url, timeout=self.timeout, allow_redirects=False,
                                 headers=self.auth_headers or None)
                if r.status_code not in (200, 206):
                    continue
                head = r.content[:HEAD_BYTES]
                meta = {"path": path, "status": r.status_code,
                        "size": len(r.content),
                        "body_sha256": hashlib.sha256(r.content).hexdigest(),
                        "head_sha256": hashlib.sha256(head).hexdigest(),
                        "content_type": _primary_mime(r.headers.get("Content-Type")),
                        "title": _html_title(r.text[:20000])}
            except requests.RequestException:
                continue

            if matches_soft404_baseline(meta, baseline):
                result["discarded"].append({**meta, "reason": "soft404_baseline"})
                continue
            if not content_type_ok(path, meta["content_type"]):
                result["discarded"].append({**meta, "reason": f"content_type_mismatch ({meta['content_type'] or 'missing'})"})
                continue
            if not has_valid_signature(path, head):
                result["discarded"].append({**meta, "reason": "no_content_signature"})
                continue

            result["found"].append(meta)
            result["findings"].append(self._mk_finding(
                id=self._next_id(), vector="web",
                title=f"Sensitive file publicly accessible: /{path}",
                severity="critical",
                description=f"/{path} is publicly readable and its content matches a real {path} file signature.",
                evidence=(f"GET {url} -> {meta['status']} "
                          f"({meta['size']} bytes, "
                          f"Content-Type: {meta['content_type'] or 'n/a'}, "
                          f"sha256={meta['body_sha256'][:16]}…, "
                          f"head-400 signature verified)"),
                owasp="A01:2021 - Broken Access Control",
                target=self.target,
                remediation=f"Block /{path} at web server and rotate leaked secrets.",
            ))
        return result

    def analyze_redirects(self) -> dict[str, Any]:
        result = {"chain": [], "findings": []}
        try:
            direct = requests.get(self.target, timeout=self.timeout,
                                  allow_redirects=False,
                                  headers=self.auth_headers or None)
            loc = direct.headers.get("Location") or ""
            loc_https = False
            if direct.status_code in (301, 302, 303, 307, 308) and loc:
                resolved = urlparse(urljoin(self.target, loc))
                loc_https = (resolved.scheme == "https" or
                             (not resolved.scheme and self.tls_available()))
            upgraded = bool((direct.status_code in (301, 302, 303, 307, 308)
                             and loc_https)
                            or direct.url.startswith("https://"))
            result["redirect_status"] = direct.status_code
            result["location"] = loc or None
            result["upgrades_to_https"] = upgraded

            r = requests.get(self.target, timeout=self.timeout, allow_redirects=True,
                             headers=self.auth_headers or None)
            for h in r.history:
                result["chain"].append({"status": h.status_code, "url": h.url,
                                        "location": h.headers.get("Location")})
            result["chain"].append({"status": r.status_code, "url": r.url,
                                    "location": None})
            if any(h.url.startswith("https://") for h in r.history):
                upgraded = True
                result["upgrades_to_https"] = True

            if self.target.startswith("http://") and not upgraded:
                if self.tls_available():
                    result["findings"].append(self._mk_finding(
                        id=self._next_id(), vector="web",
                        title="No HTTP -> HTTPS redirect", severity="high",
                        description=(f"{self.target} responds {direct.status_code} and "
                                     "does not redirect to an HTTPS location."),
                        evidence=(f"GET {self.target} (allow_redirects=False)"
                                  f" -> {direct.status_code}"
                                  + (f", Location: {loc}" if loc else "")),
                        owasp="A02:2021 - Cryptographic Failures",
                        target=self.target,
                        remediation="Configure 301 redirect from HTTP to HTTPS.",
                    ))
                else:
                    result["tls_unavailable"] = True
                    result["note"] = ("Host does not serve TLS on port 443; "
                                      "HTTPS-redirect finding suppressed as not applicable.")
            elif upgraded:
                result["note"] = (f"HTTP -> HTTPS redirect verified: "
                                  f"{direct.status_code} "
                                  f"Location: {loc or r.url}")
            if self.evidence:
                self.evidence.save_json("redirect_chain", result["chain"])
        except requests.RequestException as e:
            result["error"] = str(e)
        return result


class DNSScanner:
    def __init__(self, domain: str, evidence: EvidenceStore = None):
        self.domain = domain.lower().strip()
        self.evidence = evidence

    def check_email_security(self) -> dict[str, Any]:
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
            ))
        if not dmarc["present"]:
            findings.append(Finding(
                id="DNS-002", vector="dns",
                title="Missing DMARC record", severity="high",
                description=f"_dmarc.{self.domain} has no DMARC record.",
                evidence=dmarc.get("error") or "No v=DMARC1 TXT record found",
                owasp="A07:2021 - Identification and Authentication Failures",
                target=self.domain,
                remediation="Publish DMARC with p=none first, then quarantine/reject.",
            ))
        elif dmarc.get("policy") == "none":
            findings.append(Finding(
                id="DNS-003", vector="dns",
                title="Weak DMARC policy (p=none)", severity="medium",
                description="DMARC is published but not enforcing.",
                evidence=dmarc.get("record", ""),
                target=self.domain,
                remediation="Move DMARC policy to p=quarantine, then p=reject.",
            ))
        result = {"domain": self.domain, "spf": spf, "dmarc": dmarc, "findings": findings}
        if self.evidence:
            self.evidence.save_json("dns_records", result)
        return result

    def _check_spf(self) -> dict[str, Any]:
        try:
            answers = dns.resolver.resolve(self.domain, "TXT")
            for r in answers:
                txt = r.to_text().strip('"')
                if txt.startswith("v=spf1"):
                    return {"present": True, "record": txt}
            return {"present": False, "record": None, "error": "No v=spf1 record"}
        except Exception as e:
            return {"present": False, "record": None, "error": str(e)}

    def _check_dmarc(self) -> dict[str, Any]:
        try:
            answers = dns.resolver.resolve(f"_dmarc.{self.domain}", "TXT")
            for r in answers:
                txt = r.to_text().strip('"')
                if txt.startswith("v=DMARC1"):
                    policy = "none"
                    for part in txt.split(";"):
                        if part.strip().startswith("p="):
                            policy = part.split("=", 1)[1].strip()
                    return {"present": True, "record": txt, "policy": policy}
            return {"present": False, "record": None, "error": "No v=DMARC1 record"}
        except Exception as e:
            return {"present": False, "record": None, "error": str(e)}
