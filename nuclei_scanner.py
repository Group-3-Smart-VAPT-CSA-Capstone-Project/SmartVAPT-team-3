"""Nuclei template-based vulnerability scanning with graceful fallback.

If the nuclei binary is not installed the scanner returns an informative
result instead of crashing, so the rest of the pipeline keeps working.
"""
import json
import os
import re
import shutil
import subprocess
from typing import Any, Callable, Dict, List, Optional

from findings import Finding
from evidence import EvidenceStore
from command_tracker import run_logged

SEVERITY_MAP = {
    "critical": "critical", "high": "high", "medium": "medium",
    "hight": "high", "moderate": "medium", "low": "low",
    "info": "info", "informational": "info",
}


class NucleiScanner:
    def __init__(self, target_url: str, evidence: EvidenceStore = None,
                 templates_dir: str = None, timeout: int = 300,
                 rate_limit: int = 100, auth_headers: dict = None):
        self.target = target_url.rstrip("/")
        self.evidence = evidence
        self.templates_dir = templates_dir
        self.timeout = timeout
        self.rate_limit = max(1, min(int(rate_limit), 150))  # abuse guardrail
        self.auth_headers = dict(auth_headers or {})

    @staticmethod
    def available() -> bool:
        return shutil.which("nuclei") is not None

    def scan(self, progress_cb: Optional[Callable[[str], None]] = None,
             stop_flag: Optional[dict] = None) -> Dict[str, Any]:
        result: Dict[str, Any] = {"target": self.target, "available": False,
                                  "matched": [], "findings": [], "error": None}
        if not self.available():
            result["error"] = ("nuclei binary not found. Install it: "
                               "sudo apt install nuclei  (or download from "
                               "https://github.com/projectdiscovery/nuclei)")
            return result
        result["available"] = True

        cmd = ["nuclei", "-u", self.target, "-jsonl", "-silent",
               "-rl", str(self.rate_limit), "-timeout", "5"]
        if self.templates_dir and os.path.isdir(self.templates_dir):
            cmd += ["-t", self.templates_dir]
        # Authenticated scanning: nuclei accepts headers via -H "Name: value".
        for k, v in self.auth_headers.items():
            cmd += ["-H", f"{k}: {v}"]

        lines: List[str] = []
        try:
            proc = run_logged(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
            assert proc.stdout is not None
            for line in proc.stdout:
                if stop_flag and stop_flag.get("stop"):
                    proc.terminate()
                    result["error"] = "Stopped by user"
                    break
                stripped = line.strip()
                if not stripped:
                    continue
                lines.append(stripped)
                if progress_cb and stripped.startswith("{"):
                    try:
                        evt = json.loads(stripped)
                        progress_cb(f"[nuclei] {evt.get('severity','?').upper()} "
                                    f"{evt.get('template-id', evt.get('id','?'))}")
                    except json.JSONDecodeError:
                        pass
            proc.wait(timeout=self.timeout)
        except FileNotFoundError as e:
            result["error"] = str(e)
            return result
        except subprocess.TimeoutExpired:
            proc.kill()
            result["error"] = f"nuclei timed out after {self.timeout}s"

        raw = "\n".join(lines)
        if self.evidence:
            try:
                self.evidence.save_raw("nuclei_output", raw)
            except Exception:
                pass

        idx = 0
        seen = set()
        for line in lines:
            if not line.startswith("{"):
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            tid = evt.get("template-id") or evt.get("id") or "unknown"
            matcher = evt.get("matcher-name") or ""
            key = (tid, matcher, evt.get("host", ""))
            if key in seen:
                continue
            seen.add(key)
            sev = SEVERITY_MAP.get(str(evt.get("severity", "")).lower(), "info")
            info = {
                "template": tid,
                "matcher": matcher or None,
                "name": evt.get("info", {}).get("name") or (evt.get("matched-at") or "").split("?")[0],
                "severity": sev,
                "url": evt.get("matched-at") or evt.get("url"),
                "tags": ",".join(evt.get("info", {}).get("tags", []) or []),
                "cvss": (evt.get("info", {}).get("classification", {}) or {}).get("cvss-score"),
                "reference": (evt.get("info", {}).get("reference", []) or [None])[0],
            }
            result["matched"].append(info)
            idx += 1
            result["findings"].append(Finding(
                id=f"NUC-{idx:03d}", vector="web",
                title=f"Nuclei: {info['name']} ({tid})",
                severity=sev,
                description=info["name"],
                evidence=f"{info['url']} matched template {tid}"
                         + (f" [{matcher}]" if matcher else ""),
                cve=self._first_cve(tid, evt),
                cvss=float(info["cvss"]) if isinstance(info["cvss"], (int, float)) else None,
                owasp=self._map_owasp(info["tags"]),
                target=self.target,
                remediation=f"Follow the guidance in nuclei template '{tid}'. "
                            f"Reference: {info['reference'] or 'n/a'}",
            ).to_dict())
        return result

    @staticmethod
    def _first_cve(template_id: str, evt: dict) -> Optional[str]:
        candidates = [template_id] + list((evt.get("info", {}).get("classification", {}) or {})
                                          .get("cve-id", []) or [])
        for c in candidates:
            m = re.search(r"CVE-\d{4}-\d{4,7}", str(c))
            if m:
                return m.group(0)
        return None

    @staticmethod
    def _map_owasp(tags_csv: str) -> Optional[str]:
        t = tags_csv.lower()
        if "xss" in t:
            return "A03:2021 - Cross-Site Scripting"
        if "sqli" in t or "sql" in t:
            return "A03:2021 - Injection"
        if "lfi" in t or "rfi" in t or "rce" in t:
            return "A03:2021 - Injection"
        if "exposure" in t or "config" in t or "misconf" in t:
            return "A05:2021 - Security Misconfiguration"
        if "default-login" in t or "auth" in t:
            return "A07:2021 - Identification and Authentication Failures"
        return None
