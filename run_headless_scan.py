"""Headless driver that replicates main.py's scan pipeline (Streamlit-free).

Usage: python3 run_headless_scan.py <target> [--ports 1-100] [--no-network] ...
"""
import json
import sys
from datetime import datetime

from network_scanner import NetworkScanner
from web_scanner import WebScanner, DNSScanner
from nuclei_scanner import NucleiScanner
from subdomain_scanner import SubdomainScanner
from api_scanner import APIScanner
from scoring import enrich_findings
from ai_engine import AIEngine
from report_gen import generate_report
from evidence import EvidenceStore
from findings import Finding, FindingSet


def add_all(fs: FindingSet, items):
    for f in items or []:
        try:
            if isinstance(f, dict):
                fs.add(Finding(**{k: v for k, v in f.items()
                                  if k in Finding.__dataclass_fields__}))
            else:
                fs.add(f)
        except Exception as fe:
            print(f"  [warn] skipped malformed finding: {fe}")


def main():
    args = sys.argv[1:]
    target = args[0] if args else "scanme.nmap.org"
    ports = "top1000"  # default: nmap Top 1000 ports (see portsets.py)
    rest = []
    i = 1
    while i < len(args):
        if args[i] == "--ports" and i + 1 < len(args):
            ports = args[i + 1]
            i += 2
        else:
            rest.append(args[i])
            i += 1
    opts = set(a.lower() for a in rest)
    scan_nuclei = "no-nuclei" not in opts  # nuclei is ON by default
    scan_network = "no-network" not in opts
    scan_web = "no-web" not in opts
    scan_dns = "no-dns" not in opts
    scan_sub = "subdomains" in opts
    scan_api = "api" in opts

    def log(line):
        print(line.rstrip())

    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    evidence = EvidenceStore(scan_id)
    findings = FindingSet()
    results = {"target": target, "scan_id": scan_id}

    if scan_network:
        print("[*] Network scan (nmap + vulners)...")
        net_target = (target.replace("http://", "").replace("https://", "")
                      .split("/")[0].split(":")[0])
        try:
            ns = NetworkScanner(net_target, evidence=evidence)
            net_result = ns.scan(ports=ports, os_detect=False, progress_cb=log)
            results["network"] = net_result
            # Record the exact port selection for the report ("top1000" or a
            # literal range like "1-1000").
            results["ports_requested"] = ports
            add_all(findings, net_result.get("findings"))
        except Exception as e:
            results["network"] = {"error": str(e)}
            print(f"[!] network error: {e}")

    http_services = ((results.get("network") or {}).get("http_services")
                     or [])
    if not http_services and scan_web:
        # Network scan unavailable/failed -> probe common HTTP ports directly
        # so gobuster still has an nmap-equivalent discovery step.
        from portsets import probe_http_ports
        http_services = probe_http_ports(net_target)
        if http_services:
            print(f"[i] direct probe found HTTP on port "
                  f"{http_services[0]['port']} -> {http_services[0]['url']}")
    if scan_web:
        print("[*] Web app audit...")
        try:
            ws = WebScanner(target, evidence=evidence)
            if http_services:
                det_url = http_services[0].get("url") or ""
                # Always sync port/service metadata with what nmap -sV (or the
                # direct probe) actually observed; re-point whenever the
                # detected URL differs from the assumed one.
                ws.set_target(det_url,
                              port=http_services[0].get("port"),
                              service=http_services[0].get("service"))
                from urllib.parse import urlparse as _up
                req_port = _up(target if "://" in target else "http://" + target).port
                det_port = _up(det_url).port
                if det_port and det_port not in (req_port, 80, 443):
                    print(f"[i] nmap -sV found HTTP on port {det_port}; "
                          f"web audit re-pointed to {ws.target}")
            web_result = {
                "headers": ws.check_headers(),
                "technologies": ws.detect_technologies(),
                "directories": ws.gobuster_scan(progress_cb=log,
                                                http_services=http_services),
                "tls": ws.analyze_tls(),
                "robots_sitemap": ws.fetch_robots_sitemap(),
                "sensitive_paths": ws.probe_sensitive_paths(),
                "redirects": ws.analyze_redirects(),
            }
            results["web"] = web_result
            for key in ("headers", "directories", "tls", "robots_sitemap",
                        "sensitive_paths", "redirects"):
                add_all(findings, web_result.get(key, {}).get("findings"))
        except Exception as e:
            results["web"] = {"error": str(e)}
            print(f"[!] web error: {e}")

    if scan_dns:
        print("[*] DNS / email security (SPF/DMARC)...")
        domain = (target.replace("http://", "").replace("https://", "")
                  .split("/")[0].split(":")[0])
        try:
            ds = DNSScanner(domain, evidence=evidence)
            dns_result = ds.check_email_security()
            results["dns"] = dns_result
            add_all(findings, dns_result.get("findings"))
        except Exception as e:
            results["dns"] = {"error": str(e)}
            print(f"[!] dns error: {e}")

    if scan_nuclei:
        print("[*] Nuclei template scan...")
        try:
            nuc_target = (((results.get("web") or {}).get("directories") or {})
                          .get("target")) \
                or (results.get("network") or {}).get("primary_http_url") or target
            nsc = NucleiScanner(nuc_target, evidence=evidence, rate_limit=10)
            nuc_result = nsc.scan(progress_cb=log)
            results["nuclei"] = nuc_result
            add_all(findings, nuc_result.get("findings"))
            if not nuc_result.get("available"):
                print(f"[i] nuclei skipped: {nuc_result.get('error')}")
        except Exception as e:
            results["nuclei"] = {"error": str(e)}

    if scan_sub:
        print("[*] Subdomain enumeration...")
        try:
            ssc = SubdomainScanner(domain, evidence=evidence)
            sub_result = ssc.enumerate(progress_cb=log)
            results["subdomains"] = sub_result
            add_all(findings, sub_result.get("findings"))
        except Exception as e:
            results["subdomains"] = {"error": str(e)}

    if scan_api:
        print("[*] API security checks...")
        try:
            asc = APIScanner(target, evidence=evidence)
            api_result = asc.run_all(progress_cb=log)
            results["api"] = api_result
            add_all(findings, api_result.get("findings"))
        except Exception as e:
            results["api"] = {"error": str(e)}

    print("[*] Scoring / enrichment...")
    enriched = enrich_findings(findings.to_dict_list())
    results["findings"] = enriched

    print("[*] AI analysis (graceful without GEMINI_API_KEY)...")
    try:
        ai_result = AIEngine().analyze(enriched, results)
    except Exception as e:
        ai_result = {"executive_summary": f"AI unavailable: {e}",
                     "overall_risk": "Unknown", "risk_score": 0,
                     "top_findings": [], "technical_remediation": [],
                     "conclusion": ""}

    pdf_path = f"SmartVAPT_{scan_id}.pdf"
    print("[*] Generating PDF report...")
    try:
        generate_report(results, ai_result, pdf_path)
    except Exception as e:
        pdf_path = None
        print(f"[!] PDF generation failed: {e}")

    counts = {}
    for f in enriched:
        s = str(f.get("severity", "info")).lower()
        counts[s] = counts.get(s, 0) + 1
    print("\n===== SCAN SUMMARY =====")
    print(f"Target   : {target}")
    print(f"Scan ID  : {scan_id}")
    print(f"Findings : {len(enriched)} total -> {counts}")
    net = results.get("network", {})
    if net.get("summary"):
        print(f"Network  : {net['summary']}")
    print(f"Evidence : {evidence.path()}")
    print(f"Report   : {pdf_path}")

    with open(f"results_{scan_id}.json", "w") as fh:
        json.dump({"results": results, "ai": ai_result}, fh,
                  indent=2, default=str)


if __name__ == "__main__":
    main()
