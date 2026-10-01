import nmap
import os
import re
import shlex
import subprocess
import tempfile
import time
from typing import List, Dict, Any, Callable, Optional
from findings import Finding
from evidence import EvidenceStore
from portsets import PORT_SETS, normalize_ports, port_arg_tokens
from advisory import (check_backports, exploit_surface, find_weak_algorithms,
                      SURFACE_NOTES)

# Canonical CVE identifier: four-digit year + 4-7 digit sequence.  Anything
# that does not match exactly is treated as unresolvable and flagged.
CVE_ID_RE = re.compile(r"^CVE-(1999|20\d{2})-(\d{4,7})$")


def cve_id_valid(cve_id: str) -> bool:
    """Format-level sanity check for a CVE id (does NOT prove it exists).

    Consecutive ids coming out of a version-banner matcher (e.g.
    CVE-2026-59995 ... CVE-2026-60002) are often legitimate reservations,
    but they must each resolve on the NVD before being reported as proven
    vulnerabilities; ids that fail even this format check are certainly
    bogus (typos / hallucinated entries) and are never escalated.
    """
    return bool(CVE_ID_RE.match((cve_id or "").strip().upper()))


# Service names / products that indicate an HTTP-speaking port (nmap -sV).
HTTP_SERVICE_TOKENS = ("http", "https", "http-proxy", "https-proxy", "ssl/http",
                       "upnp", "jetty", "tomcat", "jboss", "thrift-http",
                       "h2", "glighty", "nginx", "apache", "iis", "websocket")


def is_http_port(port_info: Dict[str, Any]) -> bool:
    """True when an nmap service dict looks like HTTP(S)."""
    name = str(port_info.get("name") or "").lower()
    product = str(port_info.get("product") or "").lower()
    tunnel = str(port_info.get("tunnel") or "").lower()
    if tunnel == "ssl" and "http" in name:
        return True
    for token in HTTP_SERVICE_TOKENS:
        if name == token or token in name or token in product:
            return True
    return False


def find_http_services(net_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract HTTP/HTTPS services from a parsed NetworkScanner result.

    Relies on version detection (-sV) having populated the service name.
    Returns [{host, port, protocol, service, product, version, tunnel, url}, ...]
    """
    out = []
    for host in net_result.get("hosts", []) or []:
        ip = host.get("ip") or host.get("hostname") or ""
        for p in host.get("ports", []) or []:
            if not is_http_port(p):
                continue
            port = p.get("port")
            svc_name = str(p.get("service") or "").lower()
            name = str(p.get("name") or "").lower()
            tunnel = str(p.get("tunnel") or "").lower()
            # nmap reports TLS-wrapped HTTP as service "ssl/http" (tunnel ssl)
            # — those ports must be probed over https://, never plain http://.
            ssl_wrap = (tunnel == "ssl" or "ssl/" in svc_name or "ssl/" in name
                        or svc_name in ("https", "https-proxy", "ssl/http"))
            scheme = "https" if ssl_wrap else "http"
            default_port = 443 if ssl_wrap else 80
            try:
                port_i = int(port)
            except (TypeError, ValueError):
                port_i = None
            hostpart = host.get("hostname") or ip or "localhost"
            url = f"{scheme}://{hostpart}"
            if port_i is not None and port_i != default_port:
                url += f":{port_i}"
            out.append({"host": host.get("ip"), "hostname": host.get("hostname"),
                        "port": port_i if port_i is not None else port,
                        "protocol": p.get("protocol", "tcp"),
                        "service": p.get("service"), "product": p.get("product"),
                        "version": p.get("version"),
                        "tunnel": p.get("tunnel"), "url": url,
                        "ssl": ssl_wrap})
    return out


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

    def scan(self, ports: str = "top1000", os_detect: bool = True,
             arguments: str = None,
             progress_cb: Optional[Callable[[str], None]] = None,
             stop_flag: Optional[Dict[str, bool]] = None) -> Dict[str, Any]:
        """Run an nmap scan.

        *ports* accepts a Nmap top-ports preset ("top100", "top1000",
        "top10000") or an explicit range/list ("80,443,8000-9000").
        Version detection (-sV) is always enabled so downstream consumers
        (e.g. gobuster) can discover which ports actually speak HTTP.

        If *progress_cb* is supplied, nmap is executed as a live subprocess
        and its per-probe status lines are streamed to the callback as they
        arrive (real-time output). Without a callback, behaviour is unchanged.
        """
        norm_ports = normalize_ports(ports) or "top1000"
        if arguments is None:
            arguments = "-sV -sC --script vulners"
            if os_detect:
                arguments += " -O --osscan-guess"

        if progress_cb is not None:
            xml_path = self._scan_streaming(norm_ports, arguments,
                                            progress_cb, stop_flag)
            if xml_path is None:
                # streaming path failed before producing results; fall back
                self.nm.scan(hosts=self.target, ports=norm_ports,
                             arguments=arguments)
            else:
                with open(xml_path, "r", errors="replace") as fh:
                    raw = fh.read()
                os.unlink(xml_path)
                report = nmap.PortScanner().analyse_nmap_xml_scan(raw)
                self._nm = _ReportOnlyScanner(report, raw)
        else:
            try:
                self.nm.scan(hosts=self.target, ports=norm_ports,
                             arguments=arguments)
            except nmap.PortScannerError as e:
                return {"error": str(e), "target": self.target}

        if self.evidence:
            try:
                self.evidence.save_raw("nmap_output", self._last_output())
            except Exception:
                pass
        parsed = self._parse()
        parsed["ports_requested"] = norm_ports
        # Surface where HTTP is actually running (from -sV service detection)
        # so web fingerprinting / gobuster / nuclei target the right port.
        http_services = find_http_services(parsed)
        parsed["http_services"] = http_services
        parsed["primary_http_url"] = (http_services[0]["url"]
                                      if http_services else None)
        return parsed

    def _last_output(self) -> str:
        nm = self._nm
        if nm is None:
            return ""
        try:
            return nm.get_nmap_last_output()
        except Exception:
            return getattr(nm, "xmloutput", "") or ""

    def _scan_streaming(self, ports: str, arguments: str,
                        progress_cb: Callable[[str], None],
                        stop_flag: Optional[Dict[str, bool]] = None) -> Optional[str]:
        """Run nmap via subprocess, streaming status lines to progress_cb.

        Returns the path of a temporary XML file with the scan results, or
        None on failure (FileNotFoundError / non-zero exit).
        """
        fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="smartvapt_")
        os.close(fd)
        cmd = ["nmap"] + arguments.split()
        # Preset ("top1000") -> "--top-ports 1000"; literal range/list
        # ("1-1000", "80,443") -> "-p <spec>" exactly as the user requested.
        cmd += port_arg_tokens(ports)
        cmd += ["-oX", xml_path, self.target]
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
                progress_cb(line)  # may raise (user stop) -> handled below
            if stop_flag and stop_flag.get("stop"):
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
                os.unlink(xml_path)
                raise RuntimeError("Scan stopped by user")
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
                               "high": 0, "medium": 0, "low": 0, "info": 0}}
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
                    banner = " ".join(str(x or "") for x in
                                      (info.get("product"), info.get("version"),
                                       info.get("extrainfo"))).strip()
                    cves = self._extract_cves(info)
                    # Cross-check every banner-derived CVE against the distro
                    # backport knowledge base BEFORE raising findings, so a
                    # patched Ubuntu revision does not produce 26 "criticals".
                    backports = check_backports(info.get("product") or "",
                                                banner, [c["id"] for c in cves])
                    weak_crypto = find_weak_algorithms(
                        "\n".join(str(v) for v in
                                  info.get("script", {}).values()))
                    for cve in cves:
                        bp = backports.get(cve["id"].upper(), {})
                        status = bp.get("status", "unknown")
                        surface = exploit_surface(cve["id"])
                        cve["backport_status"] = status
                        cve["backport_note"] = bp.get("note", "")
                        cve["surface"] = surface
                        cve["id_format_valid"] = cve_id_valid(cve["id"])
                        if status == "patched":
                            # Distro build already contains the fix: keep the
                            # entry for transparency but do not count it as a
                            # vulnerability.
                            cve["confidence"] = "confirmed"
                            cve["not_vulnerable"] = True
                            cve["severity"] = "info"
                            continue
                        if not cve["id_format_valid"]:
                            cve["confidence"] = "unverified"
                            cve["severity"] = "info"
                            cve["not_vulnerable"] = True
                            continue
                        # Banner matching only: unconfirmed until verified.
                        cve["confidence"] = ("likely" if status == "vulnerable-likely"
                                             else "unverified")
                        sev = cve["severity"]
                        results["summary"][sev] += 1
                        results["summary"]["total_cves"] += 1
                        finding_idx += 1
                        if surface in ("client", "config-dependent"):
                            desc = (f"{info.get('product','')} {info.get('version','')} "
                                    f"banner matches {cve['id']}, which is a "
                                    f"{surface.replace('-', ' ')} issue "
                                    f"({SURFACE_NOTES[surface]}) — it is NOT a "
                                    "directly exploitable server vulnerability.")
                        elif status == "vulnerable-likely":
                            desc = (f"{info.get('product','')} on port {port}/{proto} "
                                    f"is likely vulnerable to {cve['id']}: "
                                    f"{bp.get('note','')}.")
                        else:
                            desc = (f"{info.get('product','')} {info.get('version','')} "
                                    f"on port {port}/{proto} matches advisory data for "
                                    f"{cve['id']} (banner-based match, unconfirmed — "
                                    "distro backports may already include the fix).")
                        results["findings"].append(Finding(
                            id=f"NET-{finding_idx:03d}", vector="network",
                            title=(f"{cve['id']} on {info.get('name')} port {port}"
                                   + (" [unconfirmed, banner-based]"
                                      if cve["confidence"] == "unverified" else "")),
                            severity=sev,
                            description=desc,
                            evidence=cve["raw"], cve=cve["id"], cvss=cve["cvss"],
                            cvss_vector=cve.get("vector"),
                            target=host, port=port, service=info.get("name"),
                            confidence=cve["confidence"],
                            exploit_surface=surface,
                            remediation=self._remediation_for(cve["id"]),
                        ).to_dict())
                    host_data["ports"].append({
                        "port": port, "protocol": proto, "service": info.get("name"),
                        "product": info.get("product"), "version": info.get("version"),
                        "extrainfo": info.get("extrainfo"), "cves": cves,
                        "banner": banner,
                        "weak_crypto": weak_crypto})
                    # Weak crypto observed verbatim in NSE output is an
                    # actionable configuration finding, not just INFO noise.
                    flat_weak = ([f"MAC {m}" for m in weak_crypto["macs"]]
                                 + [f"Cipher {c}" for c in weak_crypto["ciphers"]]
                                 + [f"KEX {k}" for k in weak_crypto["kex"]])
                    if flat_weak:
                        finding_idx += 1
                        results["findings"].append(Finding(
                            id=f"NET-{finding_idx:03d}", vector="network",
                            title=(f"Weak cryptographic algorithms offered by "
                                   f"{info.get('name')} port {port}"),
                            severity="medium",
                            description=("The service advertises deprecated/broken "
                                         "algorithms: " + ", ".join(flat_weak) +
                                         ". SHA-1 HMACs and legacy ciphers weaken "
                                         "transport integrity and must be disabled."),
                            evidence=", ".join(flat_weak),
                            target=host, port=port, service=info.get("name"),
                            confidence="confirmed",
                            remediation=("Disable legacy MACs/ciphers/KEX in the "
                                         "service configuration (e.g. sshd_config "
                                         "MACs/Ciphers/KexAlgorithms) and reload."),
                        ).to_dict())
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
                    # Capture the full CVSS v3.x vector string when present
                    vector = None
                    vm = re.search(r"(CVSS:3\.\d/[A-Za-z0-9/:._-]+)", line)
                    if vm:
                        vector = vm.group(1)
                        try:
                            from scoring import cvss_v31_base_score
                            vscore = cvss_v31_base_score(vector)
                            if vscore is not None:
                                score = vscore
                        except Exception:
                            pass
                    cves.append({"id": cid, "cvss": score,
                                 "severity": self._score_to_severity(score),
                                 "vector": vector,
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
