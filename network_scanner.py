import nmap
import os
import re
import subprocess
import tempfile
import time
from typing import List, Dict, Any, Callable, Optional
from findings import Finding
from evidence import EvidenceStore


class _ReportOnlyScanner:
    """Minimal stand-in for nmap.PortScanner backed by an already-parsed
    XML report (used by the real-time streaming path, where python-nmap's
    own scan() was never invoked)."""

    def __init__(self, report: Dict[str, Any], xml_raw: str = ""):
        scan = report.get("scan")
        self._report = scan if isinstance(scan, dict) else {}
        # Prefer the raw XML we captured ourselves; python-nmap's parsed
        # report may or may not embed it depending on version.
        self._xmloutput = xml_raw or (report.get("xmloutput", "") or "")

    def all_hosts(self) -> List[str]:
        return list(self._report.keys())

    def hostname(self, host):  # pragma: no cover - convenience parity
        return self[host].hostname()

    def state(self, host):     # pragma: no cover - convenience parity
        return self[host].state()

    def get_nmap_last_output(self) -> str:
        return self._xmloutput

    def __getitem__(self, host: str) -> Dict[str, Any]:
        return self._report[host]


class NetworkScanner:
    def __init__(self, target: str, evidence: EvidenceStore = None):
        self.target = target
        # Lazy: python-nmap's constructor requires the nmap binary at init;
        # defer it so streaming/legacy paths can handle a missing binary.
        self._nm = None
        self.evidence = evidence

    @property
    def nm(self):
        if self._nm is None:
            self._nm = nmap.PortScanner()
        return self._nm

    def scan(self, ports: str = "1-1000", os_detect: bool = True,
             arguments: str = None,
             progress_cb: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
        """Run an nmap scan.

        If *progress_cb* is supplied, nmap is executed as a live subprocess
        and its per-probe status lines are streamed to the callback as they
        arrive (real-time output). Without a callback, behaviour is unchanged.
        """
        if arguments is None:
            arguments = "-sV -sC --script vulners"
            if os_detect:
                arguments += " -O --osscan-guess"

        if progress_cb is not None:
            xml_path = self._scan_streaming(ports, arguments, progress_cb)
            if xml_path is None:
                # streaming path failed before producing results; fall back
                self.nm.scan(hosts=self.target, ports=ports, arguments=arguments)
            else:
                with open(xml_path, "r", errors="replace") as fh:
                    raw = fh.read()
                os.unlink(xml_path)
                report = nmap.PortScanner().analyse_nmap_xml_scan(raw)
                self._nm = _ReportOnlyScanner(report, raw)
        else:
            try:
                self.nm.scan(hosts=self.target, ports=ports, arguments=arguments)
            except nmap.PortScannerError as e:
                return {"error": str(e), "target": self.target}

        if self.evidence:
            try:
                self.evidence.save_raw("nmap_output", self._last_output())
            except Exception:
                pass
        return self._parse()

    def _last_output(self) -> str:
        nm = self._nm
        if nm is None:
            return ""
        try:
            return nm.get_nmap_last_output()
        except Exception:
            return getattr(nm, "xmloutput", "") or ""

    def _scan_streaming(self, ports: str, arguments: str,
                        progress_cb: Callable[[str], None]) -> Optional[str]:
        """Run nmap via subprocess, streaming status lines to progress_cb.

        Returns the path of a temporary XML file with the scan results, or
        None on failure (FileNotFoundError / non-zero exit).
        """
        fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="smartvapt_")
        os.close(fd)
        cmd = ["nmap"] + arguments.split() + ["-p", ports,
                                              "-oX", xml_path, self.target]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE, text=True,
                                    bufsize=1)
        except FileNotFoundError:
            os.unlink(xml_path)
            raise
        deadline = time.time() + 600  # 10-minute cap, same spirit as before
        for line in proc.stderr:
            line = line.strip()
            if line:
                progress_cb(line)
            if time.time() > deadline:
                proc.kill()
                break
        rc = proc.wait(timeout=max(1, deadline - time.time()))
        if rc != 0 and not os.path.getsize(xml_path):
            os.unlink(xml_path)
            return None
        return xml_path

    def _parse(self) -> Dict[str, Any]:
        results = {"target": self.target, "hosts": [], "os_matches": [], "findings": [],
                   "summary": {"open_ports": 0, "total_cves": 0, "critical": 0,
                               "high": 0, "medium": 0, "low": 0}}
        finding_idx = 0
        for host in self.nm.all_hosts():
            os_matches = []
            if "osmatch" in self.nm[host]:
                for m in self.nm[host]["osmatch"][:3]:
                    os_matches.append({"name": m.get("name"), "accuracy": m.get("accuracy")})
                    results["os_matches"].append({"host": host, "name": m.get("name"),
                                                  "accuracy": m.get("accuracy")})
            host_data = {"ip": host, "hostname": self.nm[host].hostname(),
                         "state": self.nm[host].state(), "os_matches": os_matches, "ports": []}
            for proto in self.nm[host].all_protocols():
                for port in self.nm[host][proto].keys():
                    info = self.nm[host][proto][port]
                    if info.get("state") != "open":
                        continue
                    results["summary"]["open_ports"] += 1
                    cves = self._extract_cves(info)
                    for cve in cves:
                        sev = cve["severity"]
                        results["summary"][sev] += 1
                        results["summary"]["total_cves"] += 1
                        finding_idx += 1
                        results["findings"].append(Finding(
                            id=f"NET-{finding_idx:03d}", vector="network",
                            title=f"{cve['id']} on {info.get('name')} port {port}",
                            severity=sev,
                            description=f"{info.get('product','')} {info.get('version','')} on port {port}/{proto} is vulnerable to {cve['id']}.",
                            evidence=cve["raw"], cve=cve["id"], cvss=cve["cvss"],
                            target=host, port=port, service=info.get("name"),
                            remediation=self._remediation_for(cve["id"]),
                        ).to_dict())
                    host_data["ports"].append({
                        "port": port, "protocol": proto, "service": info.get("name"),
                        "product": info.get("product"), "version": info.get("version"),
                        "extrainfo": info.get("extrainfo"), "cves": cves})
            results["hosts"].append(host_data)
        return results

    def _extract_cves(self, port_info: Dict) -> List[Dict]:
        cves = []
        for script_name, output in port_info.get("script", {}).items():
            if "vulners" not in script_name.lower():
                continue
            seen = set()
            for line in output.splitlines():
                # Vulners output formats vary: "CVE-XXXX-NNNN 9.8" or vector
                # strings like "CVE-XXXX-NNNN/CVSS:3.1/AV:N/... 8.1". Try the
                # simple format first, then fall back to a trailing score.
                m = re.search(r"(CVE-\d{4}-\d{4,7})\s+(?:CVSS:)?(\d+(?:\.\d+)?)\b", line)
                if not m:
                    m = re.search(r"(CVE-\d{4}-\d{4,7})\S*\s+.*?(\d\.\d)\s*$", line)
                if m:
                    cid = m.group(1)
                    if cid in seen:
                        continue
                    seen.add(cid)
                    try:
                        score = float(m.group(2))
                    except ValueError:
                        continue
                    cves.append({"id": cid, "cvss": score,
                                 "severity": self._score_to_severity(score),
                                 "raw": line.strip()})
        return cves

    @staticmethod
    def _score_to_severity(score: float) -> str:
        if score >= 9.0: return "critical"
        if score >= 7.0: return "high"
        if score >= 4.0: return "medium"
        if score > 0:    return "low"
        return "info"

    @staticmethod
    def _remediation_for(cve: str) -> str:
        return f"Upgrade the affected service to a patched version. Reference: https://nvd.nist.gov/vuln/detail/{cve}"
