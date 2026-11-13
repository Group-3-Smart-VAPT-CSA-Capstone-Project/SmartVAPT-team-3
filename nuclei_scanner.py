"""Nuclei template-based vulnerability scanning with graceful fallback.

If the nuclei binary is not installed the scanner returns an informative
result instead of crashing, so the rest of the pipeline keeps working.
"""
import json
import os
import re
import select
import shutil
import signal
import subprocess
import time
from collections.abc import Callable
from typing import Any

from command_tracker import run_logged
from evidence import EvidenceStore
from findings import Finding

SEVERITY_MAP = {
    "critical": "critical", "high": "high", "medium": "medium",
    "hight": "high", "moderate": "medium", "low": "low",
    "info": "info", "informational": "info",
}


class NucleiScanner:
    def __init__(self, target_url: str, evidence: EvidenceStore = None,
                 templates_dir: str | None = None, timeout: int = 300,
                 rate_limit: int = 100, auth_headers: dict | None = None):
        self.target = target_url.rstrip("/")
        self.evidence = evidence
        self.templates_dir = templates_dir
        self.timeout = timeout
        self.rate_limit = max(1, min(int(rate_limit), 150))  # abuse guardrail
        self.auth_headers = dict(auth_headers or {})

    @staticmethod
    def available() -> bool:
        return shutil.which("nuclei") is not None

    @staticmethod
    def _terminate(proc) -> None:
        """Stop a running/hung nuclei process without raising. SIGKILL as a
        last resort so a delayed scan can never block report generation."""
        if proc is None:
            return
        try:
            if proc.poll() is not None:
                return
        except Exception:
            pass
        try:
            proc.terminate()
            try:
                proc.wait(timeout=5)
                return
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                proc.kill()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def scan(self, progress_cb: Callable[[str], None] | None = None,
             stop_flag: dict | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {"target": self.target, "available": False,
                                  "matched": [], "findings": [], "error": None,
                                  "partial": False}
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

        rc = None
        lines: list[str] = []
        proc = None
        stopped_by_user = False
        timed_out = False
        try:
            proc = run_logged(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
        except FileNotFoundError as e:
            result["error"] = str(e)
            return result
        try:
            assert proc.stdout is not None
            # Deadline-based reader: iterating proc.stdout directly would
            # block forever on a hung nuclei (the iterator only surfaces the
            # timeout once the pipe closes). select() lets us enforce the
            # hard timeout while the process is silent, so a delayed scan
            # can never stall report generation.
            fd = proc.stdout.fileno()
            buf = b""
            deadline = time.monotonic() + self.timeout
            while True:
                if stop_flag and stop_flag.get("stop"):
                    self._terminate(proc)
                    result["error"] = "Stopped by user"
                    stopped_by_user = True
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                ready, _, _ = select.select([fd], [], [],
                                            min(remaining, 0.5))
                if not ready:
                    if proc.poll() is not None and not buf:
                        break          # process gone, nothing left to read
                    continue
                chunk = os.read(fd, 65536)
                if not chunk:          # EOF -> process closed stdout
                    break
                buf += chunk
                while b"\n" in buf:
                    raw_line, buf = buf.split(b"\n", 1)
                    stripped = raw_line.decode(errors="replace").strip()
                    if not stripped:
                        continue
                    lines.append(stripped)
                    if progress_cb and stripped.startswith("{"):
                        try:
                            evt = json.loads(stripped)
                            progress_cb(
                                f"[nuclei] "
                                f"{evt.get('severity', '?').upper()} "
                                f"{evt.get('template-id', evt.get('id', '?'))}")
                        except json.JSONDecodeError:
                            pass
            tail = buf.decode(errors="replace").strip()
            if tail:
                lines.append(tail)
            if timed_out:
                self._terminate(proc)
                result["error"] = (f"nuclei timed out after {self.timeout}s — "
                                   f"reporting {len(lines)} partial result(s)")
                result["partial"] = True
            else:
                proc.wait(timeout=10)
        except Exception as e:
            # Unexpected crash of the reader loop: never abort the pipeline;
            # salvage whatever output was produced before the failure.
            if proc is not None:
                try:
                    self._terminate(proc)
                except Exception:
                    pass
            result["error"] = f"nuclei failed mid-scan: {e}"
            result["partial"] = True

        rc = getattr(proc, "returncode", None) if proc else None
        if (not stopped_by_user and rc not in (None, 0)
                and not result["error"]):
            # nuclei itself crashed/exited non-zero: record it, but keep any
            # findings emitted before the crash instead of losing the vector.
            result["error"] = f"nuclei exited with code {rc}"
            result["partial"] = bool(lines)

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
    def _first_cve(template_id: str, evt: dict) -> str | None:
        candidates = [template_id] + list((evt.get("info", {}).get("classification", {}) or {})
                                          .get("cve-id", []) or [])
        for c in candidates:
            m = re.search(r"CVE-\d{4}-\d{4,7}", str(c))
            if m:
                return m.group(0)
        return None

    @staticmethod
    def _map_owasp(tags_csv: str) -> str | None:
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
