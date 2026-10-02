import streamlit as st
import pandas as pd
import os
import time
from datetime import datetime

from network_scanner import NetworkScanner
from web_scanner import WebScanner, DNSScanner, parse_auth_headers
from nuclei_scanner import NucleiScanner
from subdomain_scanner import SubdomainScanner
from api_scanner import APIScanner
from scoring import enrich_findings
import exporters
from ai_engine import AIEngine
from report_gen import generate_report
from evidence import EvidenceStore
from findings import FindingSet
from command_tracker import tracker
from eta_estimator import ScanEta, fmt_eta

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
    st.markdown("**Extended vectors**")
    ports_mode = st.radio("Port selection",
                          ["Top 1000 most-used ports of all 65535 (recommended)",
                           "Nmap Top 100 ports (quick)",
                           "Ports 1-1000 (full low range)",
                           "Custom range / list"],
                          horizontal=False,
                          help="The recommended preset scans nmap's Top 1000 "
                               "most famous/used ports across the entire "
                               "65535-port space (--top-ports 1000) instead "
                               "of a sequential 1-1000 sweep; 'Ports 1-1000' "
                               "sweeps the whole 1-1000 range (-p 1-1000); "
                               "custom accepts e.g. 80,443,8000-9000")
    if ports_mode.startswith("Top 1000"):
        ports = "top1000"
    elif ports_mode.startswith("Nmap Top 100 "):
        ports = "top100"
    elif ports_mode.startswith("Ports 1-1000"):
        ports = "1-1000"
    else:
        ports = st.text_input("Custom port range", value="80,443,8080",
                              placeholder="e.g. 80,443,3000-4000 or 1-1000",
                              key="custom_ports")
    scan_nuclei = st.checkbox("Nuclei template scan", value=True,
                              help="Requires the 'nuclei' binary; skipped "
                                   "gracefully if absent. Enabled by default.")
    scan_sub = st.checkbox("Subdomain enum + takeover check", value=False,
                           help="crt.sh + DNS brute force; detects dangling CNAMEs (no takeover attempted)")
    scan_api = st.checkbox("API security checks", value=False,
                           help="Swagger/GraphQL/JWT/rate-limit smoke tests (OWASP API Top 10)")
    nuclei_rl = st.slider("Nuclei rate limit (req/s)", 1, 50, 10,
                          help="Keep low to avoid overloading the target")
    baseline_mode = st.toggle("Baseline / diff mode", value=False,
                              help="Compare this scan with a saved baseline and optionally save a new one")
    baseline_path = st.text_input("Baseline file", value="baseline.json",
                                  disabled=not baseline_mode,
                                  help="One file per target/environment; "
                                       "used for the NEW/FIXED/UNCHANGED diff")
    with st.expander("Authenticated scan (optional)"):
        auth_headers_raw = st.text_area(
            "HTTP headers sent with every web/API/Nuclei request",
            value="", height=110,
            placeholder="Cookie: sessionid=abc123\nAuthorization: Bearer eyJ...",
            help="One 'Name: value' per line. Lets you scan behind login "
                 "(session cookies, bearer tokens). Also forwarded to "
                 "gobuster (-c/-H) and nuclei (-H). Do not commit secrets.")
    run = st.button("Run SmartVAPT Scan", use_container_width=True)
    live_output = st.sidebar.toggle("Live scan output", value=True,
                                    help="Stream nmap/gobuster progress in real time")
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
    auth_headers = parse_auth_headers(auth_headers_raw)
    if auth_headers:
        st.caption(f"Authenticated scan: {len(auth_headers)} custom header(s) "
                   f"({', '.join(auth_headers)}) will be sent to the target.")

    # ------------------------------------------------------------------
    # Time estimate for the loading page. Before anything runs we show a
    # conservative per-vector estimate (scaled by the port preset); as each
    # step finishes its real duration is recorded in eta_history.json so the
    # NEXT scan of this target estimates from measured averages. The ETA line
    # below the progress bar refreshes every second while the scan runs.
    # ------------------------------------------------------------------
    import threading as _threading

    eta = ScanEta(target, {"network": scan_network, "web": scan_web,
                           "dns": scan_dns, "nuclei": scan_nuclei,
                           "sub": scan_sub, "api": scan_api}, ports=ports)
    est_area = st.empty()                 # headline + live countdown ticker
    bd_area = st.empty()                  # per-step breakdown (in expander)
    with st.expander("Estimated time per step"):
        bd_area.markdown("\n".join(eta.breakdown_lines()))

    progress_text = {"t": "Initializing"}
    _cur_step = {"label": None}
    _last_pct = {"v": 0}
    _scan_done = _threading.Event()

    def set_progress(pct: int, label: str | None = None):
        """Advance the bar and start/stop the matching ETA step."""
        if label:
            eta.start_step(label)
            _cur_step["label"] = label
        _last_pct["v"] = pct
        try:
            progress.progress(pct, text=f"{progress_text['t']} · {eta.remaining()}")
        except Exception:
            pass

    def show_step(pct: int, text: str, label: str | None = None):
        """Single entry point for every loading-page progress update: sets
        the current status text, marks the ETA step running, refreshes the
        bar with '~X remaining'."""
        progress_text["t"] = text
        set_progress(pct, label)

    def step_done(label: str):
        """Mark an ETA step finished (records its measured duration)."""
        eta.finish_step(label)
        if _cur_step["label"] == label:
            _cur_step["label"] = None
        try:
            bd_area.markdown("\n".join(eta.breakdown_lines()))
        except Exception:
            pass

    def _render_est():
        try:
            est_area.info(f"⏱ **{eta.headline()}** — {eta.remaining()}. "
                          "The estimate updates live as each step completes; "
                          "actual time depends on target responsiveness.")
        except Exception:
            pass      # widget context gone (script finished / session closed)

    def _ticker():
        while not _scan_done.wait(1.0):
            _render_est()
            try:
                progress.progress(_last_pct["v"],
                                  text=f"{progress_text['t']} · {eta.remaining()}")
                bd_area.markdown("\n".join(eta.breakdown_lines()))
            except Exception:
                break     # script moved past the widgets; stop refreshing

    _render_est()
    _threading.Thread(target=_ticker, daemon=True).start()

    # Real-time console: scanner status lines are appended as they arrive.
    if live_output:
        # Background-commands panel: shows the general overview of what is
        # currently running (e.g. "nmap port/vuln scan running on <target>")
        # plus every tool launched during this scan, refreshed in real time.
        cmds_area = st.empty()

        def render_commands():
            snap = tracker.snapshot()
            if not snap:
                return
            running = [s for s in snap if s["running"]]
            done = [s for s in snap if not s["running"]]
            header = (f"⚙️ **Background commands** — "
                      f"{len(running)} running, {len(done)} finished")
            rows = []
            for s in running + done:
                icon = "🟢" if s["running"] else ("✅" if s["state"] == "done" else "⚠️")
                state = "running…" if s["running"] else s["state"]
                rows.append(f"{icon} {s['desc']}  ·  {state}  ·  {s['elapsed']}s\n"
                            f"   `$ {s['cmd']}`")
            cmds_area.markdown(header + "\n\n" + "\n\n".join(rows))

        render_commands()

        log_area = st.empty()
        log_lines: list[str] = []

        def log_line(line: str):
            log_lines.append(line)
            if len(log_lines) > 200:          # keep the view bounded
                del log_lines[:-200]
            log_area.code("\n".join(log_lines))
            render_commands()                 # refresh the overview too
    else:
        def log_line(line: str):
            pass

        def render_commands():
            pass

    # Pause / stop controls for long-running scans. The callback below is
    # passed to every scanner progress_cb; scanners poll it per output line,
    # so pausing takes effect within one line of tool output.
    class ScanStopped(Exception):
        pass

    ctrl = {"paused": False, "stop": False}
    if live_output:
        pcol1, pcol2 = st.columns(2)
        with pcol1:
            pause_btn = st.button("⏸ Pause scan", use_container_width=True,
                                  key="pause_scan")
        with pcol2:
            stop_btn = st.button("⏹ Stop scan", use_container_width=True,
                                 key="stop_scan")
        if pause_btn:
            ctrl["paused"] = not ctrl["paused"]
            (st.warning("Scan paused — press again to resume.")
             if ctrl["paused"] else st.success("Scan resumed."))
        if stop_btn:
            ctrl["stop"] = True
            st.error("Stop requested — finishing current step, then aborting.")

    def gated_log(line: str):
        """progress_cb wrapper: streams output, honours pause/stop requests."""
        import time as _t
        log_line(line)
        while ctrl["paused"] and not ctrl["stop"]:
            _t.sleep(0.5)
        if ctrl["stop"]:
            raise ScanStopped("Scan stopped by user")

    run_cb = gated_log if live_output else None
    scan_stopped = False

    def stop_requested() -> bool:
        """Check the shared stop flag between steps (works even when the
        live console is off, so long as a step has run at least once)."""
        return scan_stopped or ctrl.get("stop", False)

    # ----------------------------------------------------------------
    # 1) NETWORK
    # ----------------------------------------------------------------
    if scan_network and not scan_stopped:
        show_step(15, "Running network scan (Nmap + vulners)...",
                  "Network scan (Nmap)")
        try:
            net_target = (target.replace("http://", "")
                                .replace("https://", "")
                                .split("/")[0].split(":")[0])
            ns = NetworkScanner(net_target, evidence=evidence)

            def _net_cb(line: str):
                render_commands()   # refresh overview on every nmap status line
                run_cb(line) if run_cb else None

            net_result = ns.scan(ports=ports, os_detect=False,
                                 progress_cb=_net_cb if live_output else None,
                                 stop_flag=ctrl)
            results["network"] = net_result
            # Record the exact port selection for the report ("top1000" or a
            # literal range like "1-1000").
            results["ports_requested"] = ports
            from findings import Finding
            for f in net_result.get("findings", []):
                try:
                    findings.add(Finding(**{
                        k: v for k, v in f.items()
                        if k in Finding.__dataclass_fields__
                    }))
                except Exception as fe:
                    st.warning(f"Skipped malformed finding: {fe}")
        except (ScanStopped, RuntimeError) as e:
            # ScanStopped -> user stop via progress callback;
            # RuntimeError("Scan stopped by user") -> raised by the scanner
            # when it polls the stop flag. Any other RuntimeError is reported
            # as a genuine error below.
            if isinstance(e, ScanStopped) or "stopped" in str(e).lower():
                scan_stopped = True
                results["network"] = {"stopped": True}
            else:
                results["network"] = {"error": str(e)}
        except Exception as e:
            results["network"] = {"error": str(e)}
        step_done("Network scan (Nmap)")
    else:
        results["network"] = {}

    # ----------------------------------------------------------------
    # 2) WEB
    # ----------------------------------------------------------------
    http_services = (results.get("network", {}) or {}).get("http_services") or []
    if not http_services and scan_web:
        # Network scan unavailable/failed -> probe common HTTP ports directly
        # so gobuster still targets a confirmed HTTP port (nmap-equivalent).
        from portsets import probe_http_ports
        net_host = (target.replace("http://", "").replace("https://", "")
                    .split("/")[0].split(":")[0])
        http_services = probe_http_ports(net_host)
        if http_services:
            st.caption(f"HTTP discovered on port {http_services[0]['port']} "
                       f"via direct probe ({http_services[0]['url']}).")
    if scan_web and not scan_stopped:
        show_step(45, "Auditing web application...", "Web application audit")
        try:
            ws = WebScanner(target, evidence=evidence, auth_headers=auth_headers)
            # Follow nmap -sV: if HTTP was detected on a non-default port,
            # re-point the whole web audit (headers/dirs/TLS/...) at it.
            http_services = (results.get("network", {}) or {}).get("http_services") or []
            if http_services:
                det_url = http_services[0].get("url") or ""
                # Always sync port/service metadata with nmap -sV observations
                # so every web finding carries the accurate port/service.
                ws.set_target(det_url,
                              port=http_services[0].get("port"),
                              service=http_services[0].get("service"))
            web_result = {
                "headers": ws.check_headers(),
                "technologies": ws.detect_technologies(),
                "directories": ws.gobuster_scan(
                    progress_cb=run_cb, stop_flag=ctrl,
                    http_services=http_services),
                "tls": ws.analyze_tls(),
                "robots_sitemap": ws.fetch_robots_sitemap(),
                "sensitive_paths": ws.probe_sensitive_paths(),
                "redirects": ws.analyze_redirects(),
            }
            results["web"] = web_result
            results["web_audited_url"] = ws.target
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
        except (ScanStopped, RuntimeError) as e:
            if isinstance(e, ScanStopped) or "stopped" in str(e).lower():
                scan_stopped = True
                results["web"] = {"stopped": True}
            else:
                results["web"] = {"error": str(e)}
        except Exception as e:
            results["web"] = {"error": str(e)}
        step_done("Web application audit")
    else:
        results["web"] = {}

    # ----------------------------------------------------------------
    # 3) DNS
    # ----------------------------------------------------------------
    if scan_dns and not scan_stopped:
        show_step(70, "Checking SPF / DMARC...", "DNS / email security")
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
        step_done("DNS / email security")
    else:
        results["dns"] = {}

    # ----------------------------------------------------------------
    # 3b) NUCLEI (extended web vector)
    # ----------------------------------------------------------------
    if scan_nuclei and not scan_stopped:
        show_step(74, "Running Nuclei template scan...", "Nuclei templates")
        try:
            nuc_target = ((results.get("web") or {}).get("directories") or {}).get("target") \
                or (results.get("network") or {}).get("primary_http_url") or target
            nsc = NucleiScanner(nuc_target, evidence=evidence,
                                rate_limit=nuclei_rl,
                                auth_headers=auth_headers)
            nuc_result = nsc.scan(progress_cb=run_cb, stop_flag=ctrl)
            results["nuclei"] = nuc_result
            from findings import Finding
            for f in nuc_result.get("findings", []):
                try:
                    findings.add(Finding(**{
                        k: v for k, v in f.items()
                        if k in Finding.__dataclass_fields__
                    }))
                except Exception as fe:
                    st.warning(f"Skipped malformed finding: {fe}")
            if not nuc_result.get("available"):
                st.info(f"Nuclei skipped — {nuc_result.get('error','unavailable')}")
        except (ScanStopped, RuntimeError) as e:
            if isinstance(e, ScanStopped) or "stopped" in str(e).lower():
                scan_stopped = True
                results["nuclei"] = {"stopped": True}
            else:
                results["nuclei"] = {"error": str(e)}
        except Exception as e:
            results["nuclei"] = {"error": str(e)}
        step_done("Nuclei templates")
    else:
        results["nuclei"] = {}

    # ----------------------------------------------------------------
    # 3c) SUBDOMAIN ENUM + TAKEOVER (recon vector)
    # ----------------------------------------------------------------
    if scan_sub and not scan_stopped:
        show_step(78, "Enumerating subdomains / takeover checks...",
                  "Subdomain enumeration")
        try:
            domain = (target.replace("http://", "")
                            .replace("https://", "")
                            .split("/")[0].split(":")[0])
            ssc = SubdomainScanner(domain, evidence=evidence)
            sub_result = ssc.enumerate(progress_cb=run_cb, stop_flag=ctrl)
            results["subdomains"] = sub_result
            from findings import Finding
            for f in sub_result.get("findings", []):
                try:
                    findings.add(Finding(**{
                        k: v for k, v in f.items()
                        if k in Finding.__dataclass_fields__
                    }))
                except Exception as fe:
                    st.warning(f"Skipped malformed finding: {fe}")
        except (ScanStopped, RuntimeError) as e:
            if isinstance(e, ScanStopped) or "stopped" in str(e).lower():
                scan_stopped = True
                results["subdomains"] = {"stopped": True}
            else:
                results["subdomains"] = {"error": str(e)}
        except Exception as e:
            results["subdomains"] = {"error": str(e)}
        step_done("Subdomain enumeration")
    else:
        results["subdomains"] = {}

    # ----------------------------------------------------------------
    # 3d) API SECURITY CHECKS
    # ----------------------------------------------------------------
    if scan_api and not scan_stopped:
        show_step(81, "Running API security checks...", "API security checks")
        try:
            asc = APIScanner(target, evidence=evidence, auth_headers=auth_headers)
            api_result = asc.run_all(progress_cb=run_cb, stop_flag=ctrl)
            results["api"] = api_result
            from findings import Finding
            for f in api_result.get("findings", []):
                try:
                    findings.add(Finding(**{
                        k: v for k, v in f.items()
                        if k in Finding.__dataclass_fields__
                    }))
                except Exception as fe:
                    st.warning(f"Skipped malformed finding: {fe}")
        except (ScanStopped, RuntimeError) as e:
            if isinstance(e, ScanStopped) or "stopped" in str(e).lower():
                scan_stopped = True
                results["api"] = {"stopped": True}
            else:
                results["api"] = {"error": str(e)}
        except Exception as e:
            results["api"] = {"error": str(e)}
        step_done("API security checks")
    else:
        results["api"] = {}

    # ----------------------------------------------------------------
    # 4) AI
    # ----------------------------------------------------------------
    show_step(85, "AI is analyzing findings...", "AI analysis + report")
    # Deterministic CVSS normalization + remediation playbooks first, so the
    # report is complete even when the AI is unavailable.
    enriched = enrich_findings(findings.to_dict_list())
    try:
        engine = AIEngine()
        ai_result = engine.analyze(enriched, results)
    except Exception as e:
        ai_result = {
            "executive_summary": f"AI unavailable: {e}",
            "overall_risk": "Unknown",
            "risk_score": 0,
            "top_findings": [],
            "technical_remediation": [],
            "conclusion": "",
        }

    # Merge playbook data into the unified findings list exposed to the UI
    # and every exporter/appendix.
    results["findings"] = enriched

    # ----------------------------------------------------------------
    # 4b) BASELINE / DIFF
    # ----------------------------------------------------------------
    diff_summary = None
    if baseline_mode:
        base = exporters.load_baseline(baseline_path)
        if base:
            diff = exporters.diff_findings(base, enriched)
            results["diff"] = {k: v for k, v in diff.items()}
            diff_summary = exporters.format_diff_summary(diff)
        else:
            results["diff"] = None
            st.info(f"No baseline found at '{baseline_path}' yet — run the "
                    "scan, then click 'Save current scan as baseline' in the "
                    "Exports section to enable future diffs.")
    else:
        results["diff"] = None

    if scan_stopped:
        st.warning("⏹ Scan was stopped early — the report covers only the "
                   "vectors that completed before the stop request.")

    # ----------------------------------------------------------------
    # 5) PDF
    # ----------------------------------------------------------------
    progress_text["t"] = "Generating PDF report..."
    set_progress(95)
    pdf_path = f"SmartVAPT_{scan_id}.pdf"
    try:
        generate_report(results, ai_result, pdf_path)
    except Exception as e:
        pdf_path = None
        st.warning(f"PDF generation failed: {e}")

    step_done("AI analysis + report")
    _scan_done.set()                    # stop the live ETA ticker
    total_elapsed = time.time() - eta.started
    planned = fmt_eta(eta.total_estimate())
    progress.progress(100, text=f"Scan complete — actual {fmt_eta(total_elapsed)} "
                                f"(planned ~{planned})")
    st.success(f"Scan completed for {target} in {total_elapsed:.0f}s — "
               f"{len(findings)} findings")

    # ----------------------------------------------------------------
    # RISK SUMMARY DASHBOARD
    # ----------------------------------------------------------------
    counts = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    for f in enriched:
        counts[str(f.get("severity", "info")).lower()] = \
            counts.get(str(f.get("severity", "info")).lower(), 0) + 1
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Critical", counts["critical"])
    c2.metric("High",     counts["high"])
    c3.metric("Medium",   counts["medium"])
    c4.metric("Low",      counts["low"])
    c5.metric("Info",     counts["info"])

    if diff_summary:
        st.markdown(f"**Baseline diff:** {diff_summary}")
        d = results.get("diff") or {}
        if d.get("new"):
            with st.expander(f"{len(d['new'])} NEW findings since baseline"):
                st.dataframe(pd.DataFrame(d["new"])[[c for c in
                    ["id", "vector", "severity", "title", "target"]
                    if c in d["new"][0]]], use_container_width=True, hide_index=True)
        if d.get("fixed"):
            st.caption(f"✅ {len(d['fixed'])} finding(s) from the baseline are now fixed.")

    st.markdown("### Findings by Vector")
    vector_counts: dict = {}
    for f in enriched:
        v = str(f.get("vector", "other"))
        vector_counts[v] = vector_counts.get(v, 0) + 1
    vector_df = pd.DataFrame(
        [{"Vector": k, "Count": v} for k, v in sorted(vector_counts.items())])
    st.bar_chart(vector_df.set_index("Vector"))

    st.subheader("Executive Summary")
    st.write(ai_result.get("executive_summary", "N/A"))

    # ----------------------------------------------------------------
    # TABS
    # ----------------------------------------------------------------
    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        ["Network", "Web", "DNS", "Recon / API", "All Findings"])

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
            # False-positive reduction transparency (soft-404 / MIME / signature)
            sp = web.get("sensitive_paths", {}) or {}
            base = sp.get("soft404_baseline") or {}
            disc = sp.get("discarded", [])
            if base:
                if base.get("detected"):
                    title_part = f", title {base.get('title')!r}" if base.get("title") else ""
                    st.caption(f"Soft-404 baseline: DETECTED "
                               f"({base.get('body_size')} bytes{title_part}) — "
                               f"{base.get('returned_200')}/{base.get('probed')} "
                               f"random paths returned HTTP 200.")
                else:
                    st.caption("Soft-404 baseline: not detected "
                               "(server returns real 404s for missing paths).")
            if disc:
                with st.expander(f"Filtered false positives ({len(disc)})"):
                    st.dataframe(
                        pd.DataFrame([{"path": d["path"], "status": d["status"],
                                       "size": d["size"],
                                       "Content-Type": d.get("content_type"),
                                       "Discard reason": d["reason"]} for d in disc]),
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

    # ================== RECON / API TAB ==================
    with tab4:
        nuc = results.get("nuclei", {}) or {}
        sub = results.get("subdomains", {}) or {}
        api = results.get("api", {}) or {}

        st.markdown("#### Nuclei Template Findings")
        if not (nuc.get("available") or nuc.get("matched")):
            st.info(nuc.get("error") or "Nuclei vector not run.")
        elif nuc.get("matched"):
            st.dataframe(pd.DataFrame(nuc["matched"]),
                         use_container_width=True, hide_index=True)
        else:
            st.success("Nuclei ran — no template matches.")

        st.markdown("#### Subdomains")
        subs = sub.get("subdomains", [])
        if subs:
            st.dataframe(pd.DataFrame(subs), use_container_width=True,
                         hide_index=True)
        elif sub.get("error"):
            st.error(f"Recon error: {sub['error']}")
        elif sub:
            st.info("No subdomains resolved.")

        st.markdown("#### Subdomain Takeover Risks")
        risks = sub.get("takeover_risks", [])
        if risks:
            st.error(f"{len(risks)} dangling CNAME(s) takeoverable:")
            st.dataframe(pd.DataFrame(risks), use_container_width=True,
                         hide_index=True)
        elif subs:
            st.success("No takeoverable records detected.")

        st.markdown("#### API Surface")
        eps = api.get("endpoints", [])
        if eps:
            st.dataframe(pd.DataFrame(eps), use_container_width=True,
                         hide_index=True)
        for err in api.get("errors", []):
            st.caption(f"API check note: {err}")
        if not api:
            st.info("API checks not run.")

    # ================== ALL FINDINGS TAB ==================
    with tab5:
        all_findings = enriched
        if all_findings:
            df = pd.DataFrame(all_findings)
            cols = [c for c in ["id", "vector", "severity", "title",
                                 "target", "cve", "cvss", "owasp"] if c in df.columns]
            st.dataframe(df[cols], use_container_width=True, hide_index=True)
            with st.expander("Remediation playbooks"):
                for f in all_findings[:30]:
                    steps = f.get("remediation_steps") or []
                    if not steps:
                        continue
                    st.markdown(f"**[{str(f.get('severity','')).upper()}] "
                                f"{f.get('title','')}**")
                    for s in steps:
                        st.markdown(f"- {s}")
                    for group, cmds in (f.get("remediation_commands") or {}).items():
                        st.code("\n".join(cmds), language="text")
        else:
            st.info("No findings.")

    # ----------------------------------------------------------------
    # MULTI-FORMAT EXPORTS
    # ----------------------------------------------------------------
    st.markdown("---")
    st.subheader("Exports")
    e1, e2, e3, e4 = st.columns(4)
    base_name = f"SmartVAPT_{scan_id}"
    try:
        exporters.export_json(results, ai_result, f"{base_name}.json")
        exporters.export_html(results, ai_result, f"{base_name}.html")
        exporters.export_sarif(results, f"{base_name}.sarif")
    except Exception as e:
        st.warning(f"Export generation failed: {e}")
    for col, label, fname, mime in (
        (e1, "JSON", f"{base_name}.json", "application/json"),
        (e2, "HTML dashboard", f"{base_name}.html", "text/html"),
        (e3, "SARIF 2.1.0", f"{base_name}.sarif", "application/json"),
    ):
        with col:
            if os.path.exists(fname):
                with open(fname, "rb") as fh:
                    st.download_button(label, fh, file_name=fname, mime=mime,
                                       use_container_width=True)
    with e4:
        if baseline_mode and st.button("Save current scan as baseline",
                                       use_container_width=True):
            exporters.save_baseline(results, baseline_path)
            st.toast(f"Baseline saved to {baseline_path}")

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
