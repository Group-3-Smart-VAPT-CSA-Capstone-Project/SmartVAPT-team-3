"""Subdomain enumeration (DNS brute-force + certificate transparency) with
subdomain-takeover detection for dangling CNAME records.

Uses only dnspython + requests so it works without external binaries.
If the `subfinder` binary is installed it is used as an additional source.
"""
import json
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional

import dns.resolver
import requests

from evidence import EvidenceStore
from findings import Finding
from command_tracker import run_logged

# Common subdomain prefixes for DNS brute-forcing (kept small & polite)
DEFAULT_PREFIXES = [
    "www", "mail", "smtp", "pop", "imap", "api", "dev", "staging", "stage",
    "test", "qa", "beta", "admin", "portal", "vpn", "remote", "git", "gitea",
    "blog", "shop", "store", "cdn", "assets", "static", "media", "img",
    "docs", "help", "support", "status", "dashboard", "app", "m", "mobile",
    "intranet", "extranet", "backup", "db", "mysql", "postgres", "redis",
    "jenkins", "ci", "build", "auth", "login", "sso", "oauth", "nexus",
    "docker", "k8s", "kube", "monitor", "grafana", "kibana", "elastic",
]

# Dangling-CNAME fingerprints -> (service name, safe non-intrusive probe URL)
# NOTE: we only *detect* takeoverable records; we never attempt actual takeover.
TAKEOVER_FINGERPRINTS = {
    "github.io": ("GitHub Pages", "https://{host}/",
                  ["There isn't a GitHub Pages site here."]),
    "herokuapp.com": ("Heroku", "https://{host}/",
                      ["No such app", "herokucdn.com/error-pages"]),
    "azurewebsites.net": ("Azure App Service", "https://{host}/",
                          ["404 Web Site not found"]),
    "bitbucket.io": ("Bitbucket Pages", "https://{host}/",
                    ["Repository not found"]),
    "readme.io": ("ReadMe", "https://{host}/",
                  ["Project unreachable", "default project not found"]),
    "shopify.com": ("Shopify", "https://{host}/",
                    ["Sorry, this shop is currently unavailable"]),
    "tumblr.com": ("Tumblr", "https://{host}/",
                   ["Whatever you were looking for was not found"]),
    "cloudapp.net": ("Azure Cloud Services", "https://{host}/", []),
    "fastly.net": ("Fastly", "https://{host}/",
                   ["Fastly error: unknown domain"]),
    "ngrok.io": ("Ngrok", "https://{host}/",
                 ["The ngrok account was not found"]),
    "s3.amazonaws.com": ("AWS S3 bucket", "https://{host}/",
                         ["NoSuchBucket", "The specified bucket does not exist"]),
    "elasticbeanstalk.com": ("AWS Elastic Beanstalk", "https://{host}/", []),
    "fly.dev": ("Fly.io", "https://{host}/", ["Something went wrong"]),
    "vercel.app": ("Vercel", "https://{host}/", ["Deployment not found"]),
    "netlify.app": ("Netlify", "https://{host}/",
                    ["Not Found - Request ID"]),
    "pages.dev": ("Cloudflare Pages", "https://{host}/", []),
}

CNAME_SAFE = re.compile(r"^[A-Za-z0-9._-]+$")


class SubdomainScanner:
    def __init__(self, domain: str, evidence: EvidenceStore = None,
                 timeout: int = 6, threads: int = 20):
        self.domain = domain.lower().strip()
        self.evidence = evidence
        self.timeout = timeout
        self.threads = max(1, min(int(threads), 32))
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout

    # ------------------------------------------------------------------
    def enumerate(self, progress_cb: Optional[Callable[[str], None]] = None,
                  stop_flag: Optional[dict] = None) -> Dict[str, Any]:
        result: Dict[str, Any] = {"domain": self.domain, "subdomains": [],
                                  "sources": {}, "findings": [], "error": None}
        found: Dict[str, Dict[str, Any]] = {}

        def add(host: str, source: str, ips=None, cname=None):
            host = host.lower().rstrip(".")
            if not host.endswith(self.domain):
                return
            entry = found.setdefault(host, {"host": host, "sources": set(),
                                            "ips": [], "cname": None})
            entry["sources"].add(source)
            if ips:
                entry["ips"] = sorted(set(entry["ips"]) | set(ips))
            if cname and not entry["cname"]:
                entry["cname"] = cname

        def stopped() -> bool:
            return bool(stop_flag and stop_flag.get("stop"))

        # Source 1: certificate transparency (crt.sh)
        ct = [] if stopped() else self._crtsh(progress_cb)
        result["sources"]["crt.sh"] = len(ct)
        for h in ct:
            add(h, "crt.sh")

        # Source 2: subfinder binary (optional)
        sf = None if stopped() else self._subfinder(progress_cb)
        if sf is not None:
            result["sources"]["subfinder"] = len(sf)
            for h in sf:
                add(h, "subfinder")

        # Source 3: DNS brute force over existing crt.sh names + defaults
        brute_candidates = set(DEFAULT_PREFIXES) | {
            h.split(".")[0] for h in found if h.count(".") >= 1
        }
        resolved = {} if stopped() else self._brute_force(
            sorted(brute_candidates), progress_cb, stop_flag)
        result["sources"]["dns-bruteforce"] = len(resolved)
        for host, info in resolved.items():
            add(host, "dns", info.get("ips"), info.get("cname"))

        # Only keep hosts that actually resolve
        live = []
        for entry in found.values():
            try:
                ans = self._resolver.resolve(entry["host"], "A")
                entry["ips"] = sorted({r.address for r in ans})
            except Exception:
                if not entry["ips"]:
                    continue
            entry["sources"] = sorted(entry["sources"])
            live.append(entry)
        live.sort(key=lambda e: e["host"])
        result["subdomains"] = live

        # Takeover checks (detect-only)
        takeovers = self.check_takeovers(live, progress_cb)
        result["takeover_risks"] = takeovers
        for i, t in enumerate(takeovers, 1):
            result["findings"].append(Finding(
                id=f"SUB-{i:03d}", vector="recon",
                title=f"Possible subdomain takeover: {t['host']}",
                severity="critical",
                description=(f"{t['host']} has a dangling CNAME to "
                             f"{t['cname']} ({t['service']}) which appears "
                             f"unclaimed. An attacker could provision that "
                             f"service and take over the subdomain."),
                evidence=f"CNAME {t['host']} -> {t['cname']} ; "
                         f"probe response matched fingerprint: {t['matched']!r}",
                owasp="A05:2021 - Security Misconfiguration",
                target=t["host"],
                remediation=("Remove the DNS record or claim/re-provision the "
                             "orphaned service immediately."),
            ).to_dict())

        if self.evidence:
            self.evidence.save_json("subdomains", live)
            self.evidence.save_json("takeover_risks", takeovers)
        return result

    # ------------------------------------------------------------------
    def _crtsh(self, progress_cb=None) -> List[str]:
        hosts: List[str] = []
        try:
            if progress_cb:
                progress_cb(f"[recon] Querying crt.sh for *.{self.domain}")
            r = requests.get(f"https://crt.sh/?q=%25.{self.domain}"
                             f"&output=json", timeout=self.timeout + 10)
            if r.status_code == 200:
                seen = set()
                for row in r.json():
                    for cn in str(row.get("name_value", "")).splitlines():
                        cn = cn.strip().lower().lstrip("*.")
                        if cn and cn.endswith(self.domain) and cn not in seen:
                            seen.add(cn)
                            hosts.append(cn)
                if progress_cb:
                    progress_cb(f"[recon] crt.sh returned {len(hosts)} names")
        except Exception as e:
            if progress_cb:
                progress_cb(f"[recon] crt.sh failed: {e}")
        return hosts

    def _subfinder(self, progress_cb=None) -> Optional[List[str]]:
        if shutil.which("subfinder") is None:
            return None
        try:
            if progress_cb:
                progress_cb("[recon] Running subfinder...")
            proc = run_logged(["subfinder", "-d", self.domain, "-silent"],
                              popen=False, timeout=120)
            return [h.strip().lower() for h in proc.stdout.splitlines() if h.strip()]
        except Exception as e:
            if progress_cb:
                progress_cb(f"[recon] subfinder failed: {e}")
            return None

    def _brute_force(self, prefixes: List[str], progress_cb=None,
                     stop_flag=None) -> Dict[str, Dict]:
        resolved: Dict[str, Dict] = {}
        total = len(prefixes)

        def check(prefix: str):
            host = f"{prefix}.{self.domain}"
            try:
                answers = self._resolver.resolve(host, "A")
                ips = sorted({r.address for r in answers})
                cname = None
                try:
                    cnames = list(self._resolver.resolve(host, "CNAME"))
                    if cnames:
                        cname = str(cnames[0].target).rstrip(".").lower()
                except Exception:
                    pass
                return host, {"ips": ips, "cname": cname}
            except Exception:
                return host, None

        done = 0
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = [pool.submit(check, p) for p in prefixes]
            for fut in as_completed(futures):
                if stop_flag and stop_flag.get("stop"):
                    for f2 in futures:
                        f2.cancel()
                    break
                host, info = fut.result()
                done += 1
                if info:
                    resolved[host] = info
                    if progress_cb:
                        progress_cb(f"[recon] FOUND {host} -> "
                                    f"{', '.join(info['ips'])[:60]}")
                if progress_cb and (done % 25 == 0):
                    progress_cb(f"[recon] bruteforce {done}/{total} names checked")
        return resolved

    # ------------------------------------------------------------------
    def check_takeovers(self, subdomains: List[Dict], progress_cb=None
                        ) -> List[Dict[str, str]]:
        """Detect-only dangling CNAME checks against known service fingerprints."""
        risks: List[Dict[str, str]] = []
        for entry in subdomains:
            host = entry["host"]
            cname = entry.get("cname")
            if not cname:
                try:
                    ans = list(self._resolver.resolve(host, "CNAME"))
                    cname = str(ans[0].target).rstrip(".").lower() if ans else None
                except Exception:
                    cname = None
            if not cname or not CNAME_SAFE.match(cname):
                continue
            for suffix, (service, url_tpl, fingerprints) in TAKEOVER_FINGERPRINTS.items():
                if not cname.endswith(suffix):
                    continue
                url = url_tpl.format(host=host)
                try:
                    if progress_cb:
                        progress_cb(f"[recon] takeover probe {host} -> {cname}")
                    r = requests.get(url, timeout=self.timeout,
                                     allow_redirects=False)
                    body = r.text[:4000]
                    for fp in fingerprints:
                        if fp.lower() in body.lower():
                            risks.append({"host": host, "cname": cname,
                                          "service": service, "matched": fp})
                            break
                except requests.RequestException:
                    continue
                break
        return risks
