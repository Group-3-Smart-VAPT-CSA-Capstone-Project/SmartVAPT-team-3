import streamlit as st
import pandas as pd
import os
from datetime import datetime

from network_scanner import NetworkScanner
from web_scanner import WebScanner, DNSScanner
from ai_engine import AIEngine
from report_gen import generate_report
from evidence import EvidenceStore
from findings import FindingSet

st.set_page_config(page_title="SmartVAPT", page_icon="SHIELD", layout="wide")
st.title("SmartVAPT")
st.caption("Tri-Vector Attack Surface Analyzer & AI Reporting Engine")
st.markdown("---")

with st.sidebar:
    st.header("Scan Configuration")
    target = st.text_input("Target (IP / domain / URL)", value="scanme.nmap.org")
    scan_network = st.checkbox("Network Scan (Nmap + vulners)", value=True)
    scan_web = st.checkbox("Web App Audit (headers + dirs)", value=True)
    scan_dns = st.checkbox("DNS / Email Security (SPF + DMARC)", value=True)
    ports = st.text_input("Port range", value="1-1000")
    run = st.button("Run SmartVAPT Scan", use_container_width=True)
    st.markdown("---")
    st.caption("Only scan systems you are authorized to test.")


if run:
    if not target:
        st.error("Please enter a target.")
        st.stop()

    progress = st.progress(0, text="Initializing...")
    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    evidence = EvidenceStore(scan_id)
    findings = FindingSet()
    results = {"target": target, "scan_id": scan_id}

    # ----------------------------------------------------------------
    # 1) NETWORK
    # ----------------------------------------------------------------
    if scan_network:
        progress.progress(15, text="Running network scan (Nmap + vulners)...")
        try:
            net_target = (target.replace("http://", "")
                                .replace("https://", "")
                                .split("/")[0].split(":")[0])
            ns = NetworkScanner(net_target, evidence=evidence)
            net_result = ns.scan(ports=ports, os_detect=False)
            results["network"] = net_result
            from findings import Finding
            for f in net_result.get("findings", []):
                try:
                    findings.add(Finding(**{
                        k: v for k, v in f.items()
                        if k in Finding.__dataclass_fields__
                    }))
                except Exception as fe:
                    st.warning(f"Skipped malformed finding: {fe}")
        except Exception as e:
            results["network"] = {"error": str(e)}
    else:
        results["network"] = {}

    # ----------------------------------------------------------------
    # 2) WEB
    # ----------------------------------------------------------------
    if scan_web:
        progress.progress(45, text="Auditing web application...")
        try:
            ws = WebScanner(target, evidence=evidence)
            web_result = {
                "headers": ws.check_headers(),
                "technologies": ws.detect_technologies(),
                "directories": ws.gobuster_scan(),
                "tls": ws.analyze_tls(),
                "robots_sitemap": ws.fetch_robots_sitemap(),
                "sensitive_paths": ws.probe_sensitive_paths(),
                "redirects": ws.analyze_redirects(),
            }
            results["web"] = web_result
            from findings import Finding
            for key in ("headers", "directories", "tls",
                        "robots_sitemap", "sensitive_paths", "redirects"):
                for f in web_result.get(key, {}).get("findings", []):
                    try:
                        findings.add(Finding(**{
                            k: v for k, v in f.items()
                            if k in Finding.__dataclass_fields__
                        }))
                    except Exception as fe:
                        st.warning(f"Skipped malformed finding: {fe}")
        except Exception as e:
            results["web"] = {"error": str(e)}
    else:
        results["web"] = {}

    # ----------------------------------------------------------------
    # 3) DNS
    # ----------------------------------------------------------------
    if scan_dns:
        progress.progress(70, text="Checking SPF / DMARC...")
        try:
            domain = (target.replace("http://", "")
                            .replace("https://", "")
                            .split("/")[0].split(":")[0])
            ds = DNSScanner(domain, evidence=evidence)
            dns_result = ds.check_email_security()
            results["dns"] = dns_result
            from findings import Finding
            for f in dns_result.get("findings", []):
                try:
                    findings.add(Finding(**{
                        k: v for k, v in f.items()
                        if k in Finding.__dataclass_fields__
                    }))
                except Exception as fe:
                    st.warning(f"Skipped malformed finding: {fe}")
        except Exception as e:
            results["dns"] = {"error": str(e)}
    else:
        results["dns"] = {}

    # ----------------------------------------------------------------
    # 4) AI
    # ----------------------------------------------------------------
    progress.progress(85, text="AI is analyzing findings...")
    try:
        engine = AIEngine()
        ai_result = engine.analyze(findings.to_dict_list(), results)
    except Exception as e:
        ai_result = {
            "executive_summary": f"AI unavailable: {e}",
            "overall_risk": "Unknown",
            "risk_score": 0,
            "top_findings": [],
            "technical_remediation": [],
            "conclusion": "",
        }

    # Expose the unified, deduplicated findings list so report_gen's
    # "Full Findings List" appendix is populated.
    results["findings"] = findings.to_dict_list()

    # ----------------------------------------------------------------
    # 5) PDF
    # ----------------------------------------------------------------
    progress.progress(95, text="Generating PDF report...")
    pdf_path = f"SmartVAPT_{scan_id}.pdf"
    try:
        generate_report(results, ai_result, pdf_path)
    except Exception as e:
        pdf_path = None
        st.warning(f"PDF generation failed: {e}")

    progress.progress(100, text="Scan complete")
    st.success(f"Scan completed for {target} — {len(findings)} findings")

    # ----------------------------------------------------------------
    # RISK SUMMARY DASHBOARD
    # ----------------------------------------------------------------
    counts = findings.counts()
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Critical", counts["critical"])
    c2.metric("High",     counts["high"])
    c3.metric("Medium",   counts["medium"])
    c4.metric("Low",      counts["low"])
    c5.metric("Info",     counts["info"])

    st.markdown("### Findings by Vector")
    vector_df = pd.DataFrame([
        {"Vector": "Network", "Count": len(findings.by_vector("network"))},
        {"Vector": "Web",     "Count": len(findings.by_vector("web"))},
        {"Vector": "DNS",     "Count": len(findings.by_vector("dns"))},
    ])
    st.bar_chart(vector_df.set_index("Vector"))

    st.subheader("Executive Summary")
    st.write(ai_result.get("executive_summary", "N/A"))

    # ----------------------------------------------------------------
    # TABS
    # ----------------------------------------------------------------
    tab1, tab2, tab3, tab4 = st.tabs(["Network", "Web", "DNS", "All Findings"])

    # ================== NETWORK TAB ==================
    with tab1:
        net = results.get("network", {}) or {}
        if net.get("error"):
            st.error(f"Network scan error: {net['error']}")
        else:
            s = net.get("summary", {})
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Open Ports", s.get("open_ports", 0))
            m2.metric("Total CVEs", s.get("total_cves", 0))
            m3.metric("High-Risk CVEs", s.get("critical", 0) + s.get("high", 0))
            m4.metric("Hosts Up", len(net.get("hosts", [])))

            os_matches = net.get("os_matches", [])
            if os_matches:
                st.markdown("#### Detected OS")
                os_df = pd.DataFrame(os_matches)
                keep = [c for c in ["host", "name", "accuracy"] if c in os_df.columns]
                if keep:
                    os_df = os_df[keep].rename(columns={
                        "host": "Host",
                        "name": "OS Guess",
                        "accuracy": "Accuracy (%)",
                    })
                    st.dataframe(os_df, use_container_width=True, hide_index=True)

            st.markdown("#### Open Ports & Services")
            rows = []
            for host in net.get("hosts", []):
                for p in host.get("ports", []):
                    rows.append({
                        "Host": host.get("ip"),
                        "Port": p.get("port"),
                        "Proto": p.get("protocol"),
                        "Service": p.get("service"),
                        "Product": p.get("product") or "-",
                        "Version": p.get("version") or "-",
                        "CVEs": len(p.get("cves", [])),
                    })
            if rows:
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
            else:
                st.info("No open ports found in the scanned range.")

    # ================== WEB TAB ==================
    with tab2:
        web = results.get("web", {}) or {}
        if web.get("error"):
            st.error(f"Web scan error: {web['error']}")
        else:
            hdrs = web.get("headers", {}) or {}
            tls = web.get("tls", {}) or {}
            techs = (web.get("technologies", {}) or {}).get("technologies", [])
            dirs = (web.get("directories", {}) or {}).get("found", [])
            sens = (web.get("sensitive_paths", {}) or {}).get("found", [])

            w1, w2, w3, w4 = st.columns(4)
            w1.metric("Server", hdrs.get("server", "unknown"))
            w2.metric("Missing Headers", len(hdrs.get("missing", [])))
            w3.metric("Technologies", len(techs))
            w4.metric("Paths Found", len(dirs) + len(sens))

            st.markdown("#### HTTP Security Headers")
            hdr_rows = []
            for h in hdrs.get("present", []):
                hdr_rows.append({
                    "Header": h["header"],
                    "Status": "Present",
                    "Value": str(h.get("value", ""))[:60],
                })
            for h in hdrs.get("missing", []):
                hdr_rows.append({"Header": h, "Status": "MISSING", "Value": ""})
            if hdr_rows:
                st.dataframe(pd.DataFrame(hdr_rows),
                             use_container_width=True, hide_index=True)

            if techs:
                st.markdown("#### Detected Technologies")
                st.dataframe(pd.DataFrame(techs),
                             use_container_width=True, hide_index=True)

            if tls.get("enabled"):
                st.markdown("#### TLS")
                cert = tls.get("cert", {})
                t1, t2, t3 = st.columns(3)
                t1.metric("TLS Version", cert.get("version", "-"))
                t2.metric("Cipher", (cert.get("cipher") or "-")[:24])
                t3.metric("Valid Until", cert.get("notAfter", "-"))

            if dirs:
                st.markdown(f"#### Discovered Directories ({len(dirs)})")
                st.dataframe(pd.DataFrame(dirs),
                             use_container_width=True, hide_index=True)

            if sens:
                st.markdown(f"#### Sensitive Paths Exposed ({len(sens)})")
                st.dataframe(pd.DataFrame(sens),
                             use_container_width=True, hide_index=True)

    # ================== DNS TAB ==================
    with tab3:
        dns = results.get("dns", {}) or {}
        if dns.get("error"):
            st.error(f"DNS scan error: {dns['error']}")
        else:
            spf = dns.get("spf", {}) or {}
            dmarc = dns.get("dmarc", {}) or {}

            d1, d2, d3 = st.columns(3)
            d1.metric("Domain", dns.get("domain", "-"))
            d2.metric("SPF", "Present" if spf.get("present") else "Missing")
            d3.metric("DMARC", "Present" if dmarc.get("present") else "Missing")

            st.markdown("#### SPF Record")
            if spf.get("present"):
                st.code(spf.get("record", ""), language="text")
            else:
                st.warning("No SPF record — email spoofing possible")

            st.markdown("#### DMARC Record")
            if dmarc.get("present"):
                st.code(dmarc.get("record", ""), language="text")
                st.caption(f"Policy: `{dmarc.get('policy', 'none')}`")
            else:
                st.warning("No DMARC record — CEO fraud / spoofing possible")

    # ================== ALL FINDINGS TAB ==================
    with tab4:
        all_findings = findings.to_dict_list()
        if all_findings:
            df = pd.DataFrame(all_findings)
            cols = [c for c in ["id", "vector", "severity", "title",
                                 "target", "cve", "cvss"] if c in df.columns]
            st.dataframe(df[cols], use_container_width=True, hide_index=True)
        else:
            st.info("No findings.")

    # ----------------------------------------------------------------
    # PDF DOWNLOAD
    # ----------------------------------------------------------------
    if pdf_path and os.path.exists(pdf_path):
        with open(pdf_path, "rb") as f:
            st.download_button(
                "Download PDF Report",
                f,
                file_name=os.path.basename(pdf_path),
                mime="application/pdf",
                use_container_width=True,
            )

else:
    st.info("Configure the scan in the sidebar and click Run SmartVAPT Scan.")
