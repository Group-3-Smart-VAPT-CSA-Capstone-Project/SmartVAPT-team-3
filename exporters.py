"""Multi-format export: JSON, HTML dashboard, SARIF 2.1.0, plus a
baseline/diff engine for continuous monitoring between scans."""
import html
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
               "low": "note", "info": "note"}

TOOL_VERSION = "1.1.0"


# ----------------------------------------------------------------------
# JSON export
# ----------------------------------------------------------------------
def export_json(results: Dict[str, Any], ai_result: Dict[str, Any],
                path: str) -> str:
    payload = {
        "tool": "SmartVAPT",
        "version": TOOL_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": results.get("target"),
        "scan_id": results.get("scan_id"),
        "summary": ai_result_summary(ai_result),
        "findings": results.get("findings", []),
        "raw": {k: v for k, v in results.items()
                if k not in ("findings",)},
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2, default=str)
    return path


def ai_result_summary(ai_result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "overall_risk": ai_result.get("overall_risk"),
        "risk_score": ai_result.get("risk_score"),
        "executive_summary": ai_result.get("executive_summary"),
    }


# ----------------------------------------------------------------------
# SARIF 2.1.0 export (for GitHub Code Scanning / CI ingestion)
# ----------------------------------------------------------------------
def _rule_id(finding: Dict[str, Any]) -> str:
    if finding.get("cve"):
        return finding["cve"]
    m = re.search(r"Nuclei:.*\(([\w./-]+)\)", finding.get("title", ""))
    if m:
        return f"nuclei/{m.group(1)}"
    prefix = {"network": "NET", "web": "WEB", "dns": "DNS", "recon": "SUB",
              "api": "API"}.get(finding.get("vector", ""), "GEN")
    return f"smartvapt/{prefix}/{finding.get('id', 'X')}"


def export_sarif(results: Dict[str, Any], path: str) -> str:
    findings = results.get("findings", [])
    rules: Dict[str, Dict[str, Any]] = {}
    sarif_results = []
    for f in findings:
        rid = _rule_id(f)
        sev = str(f.get("severity", "info")).lower()
        rules.setdefault(rid, {
            "id": rid,
            "name": rid.split("/")[-1],
            "shortDescription": {"text": f.get("title", rid)[:300]},
            "fullDescription": {"text": f.get("description", "")},
            "defaultConfiguration": {"level": SARIF_LEVEL.get(sev, "note")},
            "properties": {"security-severity":
                           str(float(f.get("cvss") or 0))},
        })
        if f.get("owasp"):
            rules[rid].setdefault("properties", {})["tags"] = [f["owasp"]]
        loc: Dict[str, Any] = {"physicalLocation": {
            "artifactLocation": {"uri": f.get("target", "unknown")}}}
        entry: Dict[str, Any] = {
            "ruleId": rid,
            "level": SARIF_LEVEL.get(sev, "note"),
            "message": {"text": f.get("evidence", f.get("title", ""))},
            "locations": [loc],
            "partialFingerprints": {
                "smartvaptFindingId": str(f.get("id", ""))},
        }
        sarif_results.append(entry)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "SmartVAPT",
                "version": TOOL_VERSION,
                "informationUri": "https://github.com/ictacademy/smartvapt",
                "rules": list(rules.values()),
            }},
            "columnKind": "utf16CodeUnits",
            "results": sarif_results,
        }],
    }
    with open(path, "w") as f:
        json.dump(sarif, f, indent=2)
    return path


# ----------------------------------------------------------------------
# HTML export (self-contained dashboard, no external assets)
# ----------------------------------------------------------------------
SEV_COLORS = {"critical": "#c80000", "high": "#e66400", "medium": "#d4a017",
              "low": "#2e8b57", "info": "#5b8db8"}


def export_html(results: Dict[str, Any], ai_result: Dict[str, Any],
                path: str) -> str:
    findings = results.get("findings", [])
    counts: Dict[str, int] = {s: 0 for s in SEVERITY_RANK}
    for f in findings:
        counts[str(f.get("severity", "info")).lower()] = \
            counts.get(str(f.get("severity", "info")).lower(), 0) + 1

    esc = html.escape
    rows = []
    for f in sorted(findings, key=lambda x: -SEVERITY_RANK.get(
            str(x.get("severity", "info")).lower(), 0)):
        sev = str(f.get("severity", "info")).lower()
        steps = "".join(f"<li>{esc(str(s))}</li>"
                        for s in f.get("remediation_steps", []))
        cmds = "".join(
            f"<pre>{esc(c)}</pre>"
            for group in (f.get("remediation_commands") or {}).values()
            for c in group)
        rows.append(f"""
        <tr>
          <td><span class="sev" style="background:{SEV_COLORS.get(sev,'#888')}">
              {esc(sev.upper())}</span></td>
          <td>{esc(str(f.get('id','')))}</td>
          <td>{esc(str(f.get('vector','')))}</td>
          <td><b>{esc(str(f.get('title','')))}</b><br>
              <small>{esc(str(f.get('description',''))[:300])}</small></td>
          <td>{esc(str(f.get('target','')))}</td>
          <td>{esc(str(f.get('cve') or '-'))}<br>
              {esc(str(f.get('cvss') or ''))}</td>
          <td>{esc(str(f.get('owasp') or '-'))}</td>
          <td><details><summary>Remediation</summary>
              <ul>{steps}</ul>{cmds}</details></td>
        </tr>""")

    metrics = "".join(
        f'<div class="metric" style="border-color:{SEV_COLORS[s]}">'
        f'<span>{counts.get(s,0)}</span>{s.upper()}</div>'
        for s in ("critical", "high", "medium", "low", "info"))

    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>SmartVAPT Report — {esc(str(results.get('target','')))}</title>
<style>
 body{{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#f6f7f9;color:#222}}
 h1{{color:#003c78}} .metrics{{display:flex;gap:12px;margin:16px 0}}
 .metric{{background:#fff;border-left:5px solid #888;padding:10px 16px;
         border-radius:6px;min-width:90px;text-align:center;font-size:12px}}
 .metric span{{display:block;font-size:26px;font-weight:700}}
 table{{width:100%;border-collapse:collapse;background:#fff;font-size:13px}}
 th,td{{padding:8px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}}
 th{{background:#003c78;color:#fff}}
 .sev{{color:#fff;padding:2px 8px;border-radius:10px;font-size:11px}}
 summary{{cursor:pointer;color:#003c78}}
 pre{{background:#272822;color:#f8f8f2;padding:6px;border-radius:4px;overflow-x:auto}}
 .card{{background:#fff;padding:16px;border-radius:8px;margin:12px 0}}
</style></head><body>
<h1>SmartVAPT Security Assessment</h1>
<p><b>Target:</b> {esc(str(results.get('target','')))} &nbsp;|&nbsp;
<b>Scan ID:</b> {esc(str(results.get('scan_id','')))} &nbsp;|&nbsp;
<b>Generated:</b> {datetime.now():%Y-%m-%d %H:%M}</p>
<div class="card"><h2>Executive Summary</h2>
<p>{esc(str(ai_result.get('executive_summary','N/A')))}</p>
<p><b>Overall risk:</b> {esc(str(ai_result.get('overall_risk','Unknown')))}
({esc(str(ai_result.get('risk_score',0)))}/10)</p></div>
<div class="metrics">{metrics}</div>
<table><thead><tr><th>Severity</th><th>ID</th><th>Vector</th><th>Finding</th>
<th>Target</th><th>CVE / CVSS</th><th>OWASP</th><th>Remediation</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=8>No findings.</td></tr>'}</tbody></table>
<p><small>Generated by SmartVAPT v{TOOL_VERSION}. Only assess systems you are
authorized to test.</small></p>
</body></html>"""
    with open(path, "w") as f:
        f.write(doc)
    return path


# ----------------------------------------------------------------------
# Baseline / diff mode (continuous monitoring)
# ----------------------------------------------------------------------
def save_baseline(results: Dict[str, Any], path: str = "baseline.json") -> str:
    payload = {
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "target": results.get("target"),
        "scan_id": results.get("scan_id"),
        "findings": results.get("findings", []),
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2, default=str)
    return path


def load_baseline(path: str) -> Optional[Dict[str, Any]]:
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _key(f: Dict[str, Any]) -> str:
    """Stable identity for a finding across scans (ignores per-scan IDs)."""
    return "|".join(str(f.get(k, "") or "") for k in
                    ("vector", "title", "target", "port", "cve")).lower()


def diff_findings(baseline: Dict[str, Any],
                  current: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
    base_map = {_key(f): f for f in baseline.get("findings", [])}
    cur_map = {_key(f): f for f in current}
    new = [cur_map[k] for k in cur_map if k not in base_map]
    fixed = [base_map[k] for k in base_map if k not in cur_map]
    persist = [cur_map[k] for k in cur_map if k in base_map]
    sev_up = [cur_map[k] for k in cur_map
              if k in base_map and
              SEVERITY_RANK.get(str(cur_map[k].get("severity", "")).lower(), 0) >
              SEVERITY_RANK.get(str(base_map[k].get("severity", "")).lower(), 0)]
    return {"new": sorted(new, key=lambda f: -SEVERITY_RANK.get(
                str(f.get("severity", "info")).lower(), 0)),
            "fixed": fixed, "persisting": persist, "escalated": sev_up}


def format_diff_summary(diff: Dict[str, List[Dict]]) -> str:
    return (f"+{len(diff['new'])} new | "
            f"-{len(diff['fixed'])} fixed | "
            f"{len(diff['persisting'])} persisting | "
            f"{len(diff['escalated'])} escalated")
