import nmap
import re
from typing import List, Dict, Any
from findings import Finding
from evidence import EvidenceStore

class NetworkScanner:
    def __init__(self, target: str, evidence: EvidenceStore = None):
        self.target = target
        self.nm = nmap.PortScanner()
        self.evidence = evidence

    def scan(self, ports: str = "1-1000", os_detect: bool = True, arguments: str = None) -> Dict[str, Any]:
        if arguments is None:
            arguments = "-sV -sC --script vulners"
            if os_detect:
                arguments += " -O --osscan-guess"
        try:
            self.nm.scan(hosts=self.target, ports=ports, arguments=arguments)
        except nmap.PortScannerError as e:
            return {"error": str(e), "target": self.target}
        if self.evidence:
            try:
                self.evidence.save_raw("nmap_output", self.nm.get_nmap_last_output())
            except Exception:
                pass
        return self._parse()

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
