import os
from datetime import datetime, timezone

from fpdf import FPDF

from config import REPORT_AUTHOR, REPORT_TITLE
from portsets import describe_ports

DEJAVU_DIR = "/usr/share/fonts/truetype/dejavu"

# Candidate paths per style, tried in order — first existing file wins.
# Some minimal images ship DejaVu without the Oblique/Italic faces, so each
# style falls back to whatever DejaVu variant is available.
_FONT_CANDIDATES = {
    "reg": [
        os.path.join(DEJAVU_DIR, "DejaVuSans.ttf"),
        os.path.join(DEJAVU_DIR, "DejaVuSerif.ttf"),
        os.path.join(DEJAVU_DIR, "DejaVuSansMono.ttf"),
    ],
    "bold": [
        os.path.join(DEJAVU_DIR, "DejaVuSans-Bold.ttf"),
        os.path.join(DEJAVU_DIR, "DejaVuSans.ttf"),
        os.path.join(DEJAVU_DIR, "DejaVuSerif-Bold.ttf"),
        os.path.join(DEJAVU_DIR, "DejaVuSansMono-Bold.ttf"),
    ],
    "italic": [
        os.path.join(DEJAVU_DIR, "DejaVuSans-Oblique.ttf"),
        os.path.join(DEJAVU_DIR, "DejaVuSans.ttf"),
        os.path.join(DEJAVU_DIR, "DejaVuSerif.ttf"),
        os.path.join(DEJAVU_DIR, "DejaVuSansMono.ttf"),
    ],
    "mono": [
        os.path.join(DEJAVU_DIR, "DejaVuSansMono.ttf"),
        os.path.join(DEJAVU_DIR, "DejaVuSans.ttf"),
        os.path.join(DEJAVU_DIR, "DejaVuSerif.ttf"),
    ],
}


def _find_font(candidates):
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


SEVERITY_COLORS = {
    "critical": (200, 0, 0),
    "high": (230, 100, 0),
    "medium": (230, 180, 0),
    "low": (0, 150, 0),
}


def _register_fonts(pdf):
    reg = _find_font(_FONT_CANDIDATES["reg"])
    bold = _find_font(_FONT_CANDIDATES["bold"]) or reg
    italic = _find_font(_FONT_CANDIDATES["italic"]) or reg
    mono = _find_font(_FONT_CANDIDATES["mono"]) or reg
    if not reg:
        raise RuntimeError(
            f"No DejaVu TrueType fonts found in {DEJAVU_DIR}; "
            "install the 'fonts-dejavu-core' package.")
    pdf.add_font("DejaVu", "", reg)
    pdf.add_font("DejaVu", "B", bold)
    pdf.add_font("DejaVu", "I", italic)
    pdf.add_font("DejaVu", "BI", bold)
    pdf.add_font("DejaVuMono", "", mono)


class PDFReport(FPDF):
    def header(self):
        self.set_font("DejaVu", "B", 14)
        self.set_text_color(30, 30, 30)
        self.set_x(self.l_margin)
        self.cell(0, 10, REPORT_TITLE, ln=True, align="C")
        self.set_font("DejaVu", "I", 9)
        self.set_text_color(100, 100, 100)
        self.set_x(self.l_margin)
        self.cell(0, 5, REPORT_AUTHOR, ln=True, align="C")
        self.ln(3)
        self.set_draw_color(180, 180, 180)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("DejaVu", "I", 8)
        self.set_text_color(120, 120, 120)
        self.set_x(self.l_margin)
        self.cell(0, 10,
                  f"Page {self.page_no()} | Generated {datetime.now(timezone.utc).astimezone():%Y-%m-%d %H:%M}",
                  align="C")


def _clean_text(text) -> str:
    """Strip characters DejaVu cannot render (tabs, control chars) so the PDF
    build emits no 'missing glyph' warnings."""
    s = str(text)
    s = s.replace("\t", "  ")
    # drop other C0/C1 control characters (keep newline/carriage return)
    s = "".join(ch for ch in s if ch in ("\n", "\r") or ord(ch) >= 32)
    return s


def _safe_multi(pdf, text, line_h=5, size=10, font="DejaVu", style=""):
    """multi_cell with cursor reset — prevents 'not enough horizontal space'."""
    pdf.set_font(font, style, size)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, line_h, _clean_text(text))
    pdf.set_x(pdf.l_margin)


def generate_report(scan_data: dict, ai_result: dict,
                    output_path: str = "SmartVAPT_Report.pdf"):
    pdf = PDFReport()
    _register_fonts(pdf)
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ---------- Title block ----------
    pdf.set_font("DejaVu", "B", 20)
    pdf.set_text_color(0, 60, 120)
    pdf.set_x(pdf.l_margin)
    pdf.cell(0, 15, "Vulnerability Assessment Report", ln=True, align="C")
    pdf.set_font("DejaVu", "", 12)
    pdf.set_text_color(60, 60, 60)
    pdf.set_x(pdf.l_margin)
    pdf.cell(0, 8, f"Target: {scan_data.get('target', 'N/A')}", ln=True, align="C")
    pdf.set_x(pdf.l_margin)
    pdf.cell(0, 8, f"Date: {datetime.now(timezone.utc).astimezone():%B %d, %Y}", ln=True, align="C")
    pdf.ln(8)

    # ---------- 1. Executive Summary ----------
    pdf.set_font("DejaVu", "B", 14)
    pdf.set_text_color(0, 60, 120)
    pdf.set_x(pdf.l_margin)
    pdf.cell(0, 10, "1. Executive Summary", ln=True)
    pdf.ln(1)
    pdf.set_text_color(30, 30, 30)
    _safe_multi(pdf, ai_result.get("executive_summary", "No summary available."),
                line_h=6, size=11)
    pdf.ln(4)

    risk = ai_result.get("overall_risk", "Unknown")
    score = ai_result.get("risk_score", 0)
    pdf.set_font("DejaVu", "B", 12)
    pdf.set_x(pdf.l_margin)
    pdf.cell(50, 8, "Overall Risk:", border=0)
    pdf.set_text_color(*SEVERITY_COLORS.get(str(risk).lower(), (0, 0, 0)))
    pdf.cell(0, 8, f"{risk}  ({score}/10)", ln=True)
    pdf.set_text_color(30, 30, 30)
    pdf.ln(4)

    # ---------- 2. Top Findings ----------
    pdf.set_font("DejaVu", "B", 14)
    pdf.set_text_color(0, 60, 120)
    pdf.set_x(pdf.l_margin)
    pdf.cell(0, 10, "2. Top Findings", ln=True)

    top_findings = ai_result.get("top_findings", []) or []
    if not top_findings:
        _safe_multi(pdf, "No findings reported.", line_h=5, size=10)
    for i, f in enumerate(top_findings, 1):
        pdf.set_font("DejaVu", "B", 11)
        pdf.set_text_color(*SEVERITY_COLORS.get(str(f.get("severity", "")).lower(),
                                                (0, 0, 0)))
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 6, _clean_text(f"{i}. {f.get('title', 'Finding')}  "
                                         f"[{f.get('severity', 'N/A')}]"))
        pdf.set_text_color(30, 30, 30)
        _safe_multi(pdf, f"Business Impact: {f.get('business_impact', 'N/A')}",
                    line_h=5, size=10)
        _safe_multi(pdf, f"Remediation: {f.get('remediation', 'N/A')}",
                    line_h=5, size=10)
        pdf.ln(2)

    # ---------- 3. Pen-Test Details & Exploitation Options ----------
    pdf.add_page()
    pdf.set_font("DejaVu", "B", 14)
    pdf.set_text_color(0, 60, 120)
    pdf.set_x(pdf.l_margin)
    pdf.cell(0, 10, "3. Penetration-Test Details & Exploitation Options", ln=True)

    _render_pentest_details(pdf, scan_data)

    # ---------- 4. Technical Remediation ----------
    pdf.add_page()
    pdf.set_font("DejaVu", "B", 14)
    pdf.set_text_color(0, 60, 120)
    pdf.set_x(pdf.l_margin)
    pdf.cell(0, 10, "4. Technical Remediation", ln=True)

    remediation = ai_result.get("technical_remediation", []) or []
    if not remediation:
        _safe_multi(pdf, "No technical remediation steps provided.",
                    line_h=5, size=10)
    for i, t in enumerate(remediation, 1):
        pdf.set_font("DejaVu", "B", 11)
        pdf.set_text_color(30, 30, 30)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 6, _clean_text(f"{i}. {t.get('finding', 'Finding')}  "
                                         f"({t.get('owasp', 'N/A')})"))
        for step in t.get("steps", []):
            _safe_multi(pdf, f"  - {step}", line_h=5, size=10)
        if t.get("commands"):
            pdf.set_fill_color(240, 240, 240)
            for cmd in t["commands"]:
                _safe_multi(pdf, f"    $ {cmd}", line_h=5, size=9,
                            font="DejaVuMono")
        pdf.ln(3)

    # ---------- 5. Appendix ----------
    pdf.add_page()
    pdf.set_font("DejaVu", "B", 14)
    pdf.set_text_color(0, 60, 120)
    pdf.set_x(pdf.l_margin)
    pdf.cell(0, 10, "5. Appendix: Scan Details", ln=True)
    pdf.ln(2)
    _render_appendix(pdf, scan_data)

    pdf.output(output_path)
    return output_path


def _render_pentest_details(pdf, scan_data: dict):
    """Section 3: methodology/scope of the pen test plus, for every finding,
    the exploitation/verification options a tester may exercise inside the
    signed scope (safe checks — not weaponised exploits)."""

    def body(text, size=10, font="DejaVu", style=""):
        pdf.set_font(font, style, size)
        pdf.set_text_color(30, 30, 30)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5, _clean_text(text))
        pdf.set_x(pdf.l_margin)

    def sub(text):
        pdf.ln(2)
        pdf.set_font("DejaVu", "B", 12)
        pdf.set_text_color(0, 60, 120)
        pdf.set_x(pdf.l_margin)
        pdf.cell(0, 7, text, ln=True)
        pdf.set_text_color(30, 30, 30)
        pdf.set_x(pdf.l_margin)

    net = scan_data.get("network", {}) or {}
    web = scan_data.get("web", {}) or {}
    nuclei = scan_data.get("nuclei", {}) or {}

    # ---- Methodology / scope ----
    sub("3.1 Test Details & Methodology")
    body(f"Target: {scan_data.get('target', 'N/A')}   "
         f"Scan ID: {scan_data.get('scan_id', 'N/A')}   "
         f"Date: {datetime.now(timezone.utc).astimezone():%Y-%m-%d %H:%M}")
    ports_requested = (scan_data.get("ports_requested")
                       or net.get("ports_requested") or "top1000")
    body(f"Ports scanned: {describe_ports(ports_requested)} "
         f"(selection: {ports_requested})")
    body("Network: nmap with version detection (-sV), default scripts (-sC) "
         "and the vulners NSE script; HTTP services were located via -sV and "
         "directory brute-forcing (gobuster dir) was executed against the "
         "detected HTTP port(s) rather than assuming port 80.")
    audited_url = ((web.get("directories") or {}).get("target")
                    or scan_data.get("web_audited_url")
                    or (net.get("primary_http_url")) or "N/A")
    body(f"Web audit base URL (nmap-confirmed): {audited_url}")
    http_services = net.get("http_services") or []
    if http_services:
        body("HTTP service(s) detected by nmap -sV:")
        for svc in http_services[:10]:
            body(f"  - {svc.get('url')}  service={svc.get('service') or '?'} "
                 f"{svc.get('product') or ''} {svc.get('version') or ''}".rstrip())
    else:
        body("No HTTP-speaking ports were detected by nmap -sV.")
    if nuclei.get("available"):
        sev_counts = {}
        for m in nuclei.get("matched", []) or []:
            s = str(m.get("severity", "info")).lower()
            sev_counts[s] = sev_counts.get(s, 0) + 1
        if nuclei.get("matched"):
            detail = f", severity breakdown {sev_counts}" if sev_counts else ""
        else:
            detail = ""
        body(f"Nuclei template scan (DEFAULT active web scanner): enabled, "
             f"{len(nuclei.get('matched', []) or [])} match(es){detail}")
    elif nuclei:
        body(f"Nuclei (default template scanner): unavailable this run — "
             f"{nuclei.get('error') or 'skipped'}. Install the 'nuclei' "
             "binary to enable it.")
    body("Rules of engagement: all steps above are non-destructive checks "
         "performed within the authorized scope of this assessment.")

    # ---- Exploitation options per finding ----
    sub("3.2 Exploitation Options (authorized verification only)")
    findings = [f for f in (scan_data.get("findings") or [])
                if str(f.get("severity", "")).lower()
                in ("critical", "high", "medium")]
    if not findings:
        body("No exploitable-severity findings recorded; nothing to verify.")
        return
    for i, f in enumerate(findings[:40], 1):
        exp = f.get("exploitation") or {}
        sev = str(f.get("severity", "?")).upper()
        pdf.set_font("DejaVu", "B", 10)
        pdf.set_text_color(*SEVERITY_COLORS.get(sev.lower(), (0, 0, 0)))
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5, _clean_text(f"{i}. [{sev}] {f.get('title','')}"))
        pdf.set_text_color(30, 30, 30)
        # Accuracy labels: banner-based CVE matches and non-server-surface
        # CVEs must not read as confirmed, directly-exploitable flaws.
        if f.get("cve"):
            surface = f.get("cve_surface") or "server"
            conf = f.get("confidence") or ("confirmed" if f.get("confirmed") else "")
            label = f"CVE attack surface: {surface}"
            if conf:
                label += f"   Confidence: {conf}"
            body(label, size=9)
            if f.get("severity_downgrade_reason"):
                body(f"Severity adjusted: {f['severity_downgrade_reason']}", size=9)
        paths = exp.get("attack_paths") or []
        if paths:
            body(f"    Attack paths : {'; '.join(paths)[:300]}", size=9)
        if exp.get("difficulty"):
            body(f"    Difficulty   : {exp['difficulty']}", size=9)
        verif = exp.get("verification") or []
        for v in verif[:4]:
            body(f"    Verify       : {v}", size=9, font="DejaVuMono")
        tools = exp.get("tools") or []
        if tools:
            body(f"    Tools        : {', '.join(tools)}", size=9)
        pdf.ln(1)
    remaining = len(findings) - 40
    if remaining > 0:
        body(f"...and {remaining} more finding(s); see section 5 for the "
             "full list.")


def _render_appendix(pdf, scan_data: dict):
    def h2(text):
        pdf.ln(3)
        pdf.set_font("DejaVu", "B", 12)
        pdf.set_text_color(0, 60, 120)
        pdf.set_x(pdf.l_margin)
        pdf.cell(0, 8, text, ln=True)
        pdf.set_text_color(30, 30, 30)
        pdf.set_x(pdf.l_margin)

    def body(text, size=10, font="DejaVu"):
        pdf.set_font(font, "", size)
        pdf.set_text_color(30, 30, 30)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5, _clean_text(text))
        pdf.set_x(pdf.l_margin)

    def kv(key, value):
        pdf.set_font("DejaVu", "B", 10)
        pdf.set_text_color(60, 60, 60)
        pdf.set_x(pdf.l_margin)
        pdf.cell(45, 6, f"{key}:", border=0)
        pdf.set_font("DejaVu", "", 10)
        pdf.set_text_color(30, 30, 30)
        pdf.set_x(pdf.l_margin + 45)
        pdf.multi_cell(0, 6, _clean_text(value))
        pdf.set_x(pdf.l_margin)

    h2("A. Target Information")
    kv("Target", scan_data.get("target", "N/A"))
    kv("Scan ID", scan_data.get("scan_id", "N/A"))

    # ---------- Geolocation / Hosting ----------
    geo = scan_data.get("geo", {}) or {}
    if geo:
        h2("A1. IP Location & Hosting (where the website is set up)")
        kv("Hostname", str(geo.get("hostname", "N/A")))
        kv("Resolved IP(s)", ", ".join(geo.get("resolved_ips", [])) or "none")
        primary = geo.get("primary") or {}
        if primary.get("found"):
            loc = ", ".join(x for x in (primary.get("city"),
                                        primary.get("region"),
                                        primary.get("country")) if x)
            kv("Location", loc or "unknown")
            kv("Coordinates", f"{primary.get('latitude')}, "
                              f"{primary.get('longitude')}")
            kv("Timezone", str(primary.get("timezone", "")))
            kv("ISP", str(primary.get("isp", "")))
            kv("Hosting Provider",
               f"{primary.get('organization', '')} ({primary.get('asn', '')})")
            if primary.get("reverse_dns"):
                kv("Reverse DNS", str(primary.get("reverse_dns")))
            kv("Lookup Source", str(primary.get("source", "")))
        else:
            body(geo.get("error") or primary.get("note")
                 or "Geolocation unavailable.")
        ws = geo.get("web_server") or {}
        if ws:
            body(f"Website served at {ws.get('url', 'N/A')} on port "
                 f"{ws.get('port', 'N/A')}"
                 + (f" (HTTP {ws.get('status')})" if ws.get("status") else "")
                 + (f"; server software: {ws.get('server')}"
                    if ws.get("server") else ""))
        extra = [l for l in geo.get("locations", [])[1:] if l.get("found")]
        for l in extra[:5]:
            body(f"Additional IP {l.get('ip')}: "
                 f"{', '.join(x for x in (l.get('city'), l.get('country')) if x)}"
                 f" · {l.get('organization') or l.get('isp') or 'unknown'}")

    # ---------- Network ----------
    net = scan_data.get("network", {}) or {}
    h2("B. Network Scan")
    if net.get("error"):
        body(f"Error: {net['error']}")
    else:
        summary = net.get("summary", {}) or {}
        kv("Open Ports", summary.get("open_ports", 0))
        kv("Ports Scanned", describe_ports(net.get("ports_requested") or "top1000"))
        kv("Total CVEs", summary.get("total_cves", 0))
        kv("Severity",
           f"Critical: {summary.get('critical', 0)}  |  "
           f"High: {summary.get('high', 0)}  |  "
           f"Medium: {summary.get('medium', 0)}  |  "
           f"Low: {summary.get('low', 0)}")
        os_matches = net.get("os_matches", [])
        if os_matches:
            body("Detected OS:")
            for m in os_matches[:5]:
                body(f"  - {m.get('name')} (accuracy {m.get('accuracy')}%)")
        for host in net.get("hosts", []):
            body(f"\nHost: {host.get('ip')}  "
                 f"({host.get('hostname') or 'no hostname'})  "
                 f"State: {host.get('state')}")
            ports = host.get("ports", [])
            if not ports:
                body("  No open ports found.")
            for p in ports:
                line = (f"  Port {p.get('port')}/{p.get('protocol')}: "
                        f"{p.get('service')} {p.get('product','')} "
                        f"{p.get('version','')}").strip()
                body(line)
                for cve in p.get("cves", []):
                    body(f"      CVE: {cve.get('id')}  "
                         f"CVSS: {cve.get('cvss')}  [{cve.get('severity')}]",
                         size=9)

    # ---------- Web ----------
    web = scan_data.get("web", {}) or {}
    h2("C. Web Application Scan")
    if web.get("error"):
        body(f"Error: {web['error']}")
    else:
        hdrs = web.get("headers", {}) or {}
        kv("Server", hdrs.get("server", "unknown"))
        missing = hdrs.get("missing", [])
        present = hdrs.get("present", [])
        body(f"Missing security headers ({len(missing)}):")
        for h in missing:
            body(f"  - {h}")
        body(f"Present security headers ({len(present)}):")
        for h in present:
            body(f"  - {h['header']}: {h['value']}")

        techs = (web.get("technologies", {}) or {}).get("technologies", [])
        if techs:
            body(f"\nDetected technologies ({len(techs)}):")
            for t in techs:
                v = f" v{t['version']}" if t.get("version") else ""
                body(f"  - {t.get('name')}{v}  (via {t.get('via')})")

        tls = web.get("tls", {}) or {}
        if tls.get("enabled"):
            cert = tls.get("cert", {})
            body(f"\nTLS: {cert.get('version','?')}  "
                 f"Cipher: {cert.get('cipher','?')}")
            body(f"  Valid until: {cert.get('notAfter','?')}")

        dirs = (web.get("directories", {}) or {}).get("found", [])
        if dirs:
            body(f"\nDiscovered directories ({len(dirs)}):")
            for d in dirs[:30]:
                body(f"  - {d['path']}  [HTTP {d['status']}]")

        sp = web.get("sensitive_paths", {}) or {}
        sens = sp.get("found", [])
        if sens:
            body(f"\nSensitive paths exposed ({len(sens)}):")
            for s in sens:
                ct = s.get("content_type") or "n/a"
                body(f"  - /{s['path']}  [HTTP {s['status']}, {ct}, "
                     f"{s.get('size')} bytes, signature verified]")
        base = sp.get("soft404_baseline") or {}
        if base:
            if base.get("detected"):
                body(f"\nSoft-404 baseline detected: random paths answer with "
                     f"HTTP 200 ({base.get('body_size')} bytes, "
                     f"title {base.get('title')!r}); matching responses are "
                     f"discarded automatically.")
            else:
                body("\nSoft-404 baseline: none (server returns real 404 "
                     "responses for missing paths).")
        disc = sp.get("discarded", [])
        if disc:
            body(f"\nFalse positives filtered during sensitive-file scan "
                 f"({len(disc)}):")
            for d in disc:
                body(f"  - /{d['path']}  [{d['reason']}]")

        redirects = web.get("redirects", {}) or {}
        chain = redirects.get("chain", [])
        if chain:
            body(f"\nRedirect chain ({len(chain)} hops):")
            for r in chain:
                body(f"  {r['status']}  {r['url']}")
        # Accuracy transparency: show the explicit redirect probe result so a
        # reader can verify any 'No HTTP -> HTTPS redirect' claim (or its
        # absence) against the raw status/Location.
        if redirects.get("redirect_status") is not None:
            verdict = ("upgrades to HTTPS"
                       if redirects.get("upgrades_to_https")
                       else "does NOT upgrade to HTTPS")
            body(f"Explicit redirect probe (allow_redirects=False): "
                 f"{redirects['redirect_status']}"
                 + (f" Location: {redirects['location']}"
                    if redirects.get("location") else "")
                 + f" — {verdict}.")
        if redirects.get("note"):
            body(f"Note: {redirects['note']}")

    # ---------- DNS ----------
    dns = scan_data.get("dns", {}) or {}
    h2("D. DNS / Email Security")
    if dns.get("error"):
        body(f"Error: {dns['error']}")
    else:
        kv("Domain", dns.get("domain", "N/A"))
        spf = dns.get("spf", {}) or {}
        dmarc = dns.get("dmarc", {}) or {}
        kv("SPF Present", "Yes" if spf.get("present") else "No")
        if spf.get("present"):
            body(f"  Record: {spf.get('record')}")
        kv("DMARC Present", "Yes" if dmarc.get("present") else "No")
        if dmarc.get("present"):
            body(f"  Record: {dmarc.get('record')}")
            body(f"  Policy: {dmarc.get('policy')}")

    # ---------- Nuclei (extended web vector) ----------
    nuc = scan_data.get("nuclei", {}) or {}
    if nuc.get("matched"):
        h2("E. Nuclei Template Matches")
        for m in nuc["matched"][:40]:
            body(f"  - [{str(m.get('severity','?')).upper()}] "
                 f"{m.get('name')} ({m.get('template')}) -> {m.get('url')}")

    # ---------- Subdomains / takeover ----------
    sub = scan_data.get("subdomains", {}) or {}
    if sub.get("subdomains"):
        h2("F. Subdomain Enumeration")
        body(f"Subdomains found: {len(sub['subdomains'])}")
        for s in sub["subdomains"][:40]:
            cname = f"  CNAME: {s['cname']}" if s.get("cname") else ""
            body(f"  - {s.get('host')}  "
                 f"({', '.join(s.get('sources', []))}){cname}")
        risks = sub.get("takeover_risks", [])
        if risks:
            body(f"\nPOTENTIAL SUBDOMAIN TAKEOVERS ({len(risks)}):")
            for r in risks:
                body(f"  !! {r.get('host')} -> {r.get('cname')} "
                     f"[{r.get('service')}] fingerprint={r.get('matched')}")

    # ---------- API surface ----------
    api = scan_data.get("api", {}) or {}
    if api.get("endpoints"):
        h2("G. API Surface")
        for ep in api["endpoints"]:
            methods = ",".join(ep.get("methods", [])) if ep.get("methods") else "-"
            body(f"  - {ep.get('path')}  HTTP {ep.get('status')}  "
                 f"type={ep.get('type','-')}  methods={methods}")

    # ---------- Baseline diff ----------
    diff = scan_data.get("diff")
    if isinstance(diff, dict):
        h2("H. Baseline Diff (continuous monitoring)")
        body(f"New: {len(diff.get('new', []))}   Fixed: {len(diff.get('fixed', []))}   "
             f"Persisting: {len(diff.get('persisting', []))}   "
             f"Escalated: {len(diff.get('escalated', []))}")
        for f in diff.get("new", [])[:20]:
            body(f"  + NEW [{str(f.get('severity','')).upper()}] {f.get('title')}")
        for f in diff.get("fixed", [])[:20]:
            body(f"  - FIXED {f.get('title')}")

    # ---------- Findings ----------
    findings = scan_data.get("findings", [])
    if findings:
        h2("I. Full Findings List")
        for i, f in enumerate(findings, 1):
            sev = str(f.get("severity", "")).lower()
            pdf.set_font("DejaVu", "B", 10)
            pdf.set_text_color(*SEVERITY_COLORS.get(sev, (0, 0, 0)))
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, 5,
                           _clean_text(f"{i}. [{str(f.get('severity','?')).upper()}] "
                                       f"{f.get('title','')}"))
            pdf.set_text_color(30, 30, 30)
            pdf.set_font("DejaVu", "", 9)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, 4, _clean_text(f"    Target: {f.get('target','')}"))
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, 4, _clean_text(f"    Evidence: {str(f.get('evidence',''))[:200]}"))
            steps = f.get("remediation_steps") or []
            if steps:
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(0, 4,
                               _clean_text(f"    Remediation: {'; '.join(steps)[:240]}"))
            pdf.ln(1)
