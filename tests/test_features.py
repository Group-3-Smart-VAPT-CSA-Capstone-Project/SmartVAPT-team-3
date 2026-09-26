"""Tests for the feature batch: auth headers, CVSS scoring, playbooks,
exporters (SARIF/HTML/baseline/diff), nuclei/gobuster command wiring."""
import json
import pytest

from web_scanner import WebScanner, parse_auth_headers
from api_scanner import APIScanner
from scoring import cvss_v31_base_score, severity_from_cvss, playbook_for, enrich_findings
import exporters


class TestAuthHeaders:
    def test_parse_basic(self):
        h = parse_auth_headers("Cookie: a=1; b=2\nAuthorization: Bearer xyz")
        assert h == {"Cookie": "a=1; b=2", "Authorization": "Bearer xyz"}

    def test_parse_ignores_junk(self):
        h = parse_auth_headers("# comment\n\nnocolon\nX-Token: t")
        assert h == {"X-Token": "t"}

    def test_parse_empty(self):
        assert parse_auth_headers("") == {}
        assert parse_auth_headers(None) == {}

    def test_webscanner_stores_headers(self):
        ws = WebScanner("example.com", auth_headers={"Cookie": "s=1"})
        assert ws.auth_headers == {"Cookie": "s=1"}

    def test_webscanner_default_no_headers(self):
        ws = WebScanner("example.com")
        assert ws.auth_headers == {}

    def test_apiscanner_hdrs_merge(self):
        a = APIScanner("example.com", auth_headers={"Authorization": "Bearer t"})
        merged = a._hdrs({"Content-Type": "application/json"})
        assert merged["Authorization"] == "Bearer t"
        assert merged["Content-Type"] == "application/json"
        # no auth -> None so requests uses defaults
        assert APIScanner("example.com")._hdrs() is None


class TestCVSS:
    def test_known_vector(self):
        # CVE-2021-44228 (Log4Shell) official base score 10.0
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        assert cvss_v31_base_score(v) == 10.0

    def test_mid_vector(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"
        s = cvss_v31_base_score(v)
        assert s is not None and 2.0 <= s <= 6.0

    def test_bad_vector_returns_none(self):
        assert cvss_v31_base_score("not-a-vector") is None

    def test_severity_bands(self):
        # Official CVSS v3.1 severity ranges
        assert severity_from_cvss(10.0) == "critical"
        assert severity_from_cvss(9.5) == "critical"
        assert severity_from_cvss(8.0) == "high"
        assert severity_from_cvss(6.5) == "medium"
        assert severity_from_cvss(4.5) == "medium"
        assert severity_from_cvss(3.0) == "low"
        assert severity_from_cvss(0.5) == "low"
        assert severity_from_cvss(0.0) == "info"


class TestPlaybooks:
    def test_header_playbook_matches(self):
        pb = playbook_for("Missing security header: Content-Security-Policy")
        assert pb["steps"]

    def test_enrich_adds_playbook_and_score(self):
        out = enrich_findings([{
            "id": "W1", "vector": "web", "title": "Missing security header: X-Frame-Options",
            "severity": "info", "description": "", "evidence": "",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        }])
        f = out[0]
        assert f["remediation_steps"]
        assert f["cvss"] is not None
        assert f["severity"] in ("low", "medium", "high", "critical", "info")


class TestExporters:
    RESULTS = {
        "target": "example.com", "scan_id": "t1",
        "findings": [{"id": "F1", "vector": "web", "title": "Missing header",
                      "severity": "medium", "description": "CSP missing",
                      "evidence": "GET /", "cvss": 5.3,
                      "owasp": "A05:2021"}],
        "network": {}, "web": {}, "dns": {},
    }
    AI = {"executive_summary": "s", "overall_risk": "Medium", "risk_score": 50,
          "top_findings": [], "technical_remediation": [], "conclusion": ""}

    def test_json_export(self, tmp_path):
        p = exporters.export_json(self.RESULTS, self.AI, str(tmp_path / "o.json"))
        data = json.load(open(p))
        assert data["findings"][0]["id"] == "F1"

    def test_sarif_export_valid_structure(self, tmp_path):
        p = exporters.export_sarif(self.RESULTS, str(tmp_path / "o.sarif"))
        sarif = json.load(open(p))
        assert sarif["$schema"].endswith(".json")
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"]
        assert len(run["results"]) >= 1
        assert run["results"][0]["ruleId"]

    def test_html_export(self, tmp_path):
        p = exporters.export_html(self.RESULTS, self.AI, str(tmp_path / "o.html"))
        html = open(p).read()
        assert "<html" in html.lower() and "Missing header" in html

    def test_baseline_save_load_diff(self, tmp_path):
        bp = str(tmp_path / "base.json")
        exporters.save_baseline(self.RESULTS, bp)
        loaded = exporters.load_baseline(bp)
        assert loaded["target"] == "example.com"
        # nothing changed
        same = exporters.diff_findings(loaded, self.RESULTS["findings"])
        assert not same["new"] and not same["fixed"]
        # one fixed, one new
        moved = [dict(self.RESULTS["findings"][0], id="F2", title="New issue")]
        d = exporters.diff_findings(loaded, moved)
        assert any(f["id"] == "F1" for f in d["fixed"])
        assert any(f["id"] == "F2" for f in d["new"])
        assert "NEW" in exporters.format_diff_summary(d).upper() or \
               "new" in exporters.format_diff_summary(d).lower()

    def test_load_missing_baseline(self, tmp_path):
        assert exporters.load_baseline(str(tmp_path / "nope.json")) is None


class TestNucleiCommandWiring:
    def test_auth_headers_in_argv(self, monkeypatch):
        import nuclei_scanner as ns_mod
        captured = {}

        class FakeProc:
            stdout = iter([])
            stderr = iter([])
            returncode = 0
            def wait(self, timeout=None): return 0
            def terminate(self): pass
            def kill(self): pass

        def fake_popen(cmd, **kw):
            captured["cmd"] = cmd
            return FakeProc()

        monkeypatch.setattr(ns_mod.shutil, "which", lambda x: "/usr/bin/nuclei")
        monkeypatch.setattr(ns_mod.subprocess, "Popen", fake_popen)
        sc = ns_mod.NucleiScanner("https://x.example", auth_headers={"Cookie": "a=1"})
        sc.scan()
        cmd = captured["cmd"]
        i = cmd.index("-H")
        assert cmd[i + 1] == "Cookie: a=1"

    def test_rate_limit_clamped(self):
        from nuclei_scanner import NucleiScanner
        assert NucleiScanner("x", rate_limit=9999).rate_limit == 150
        assert NucleiScanner("x", rate_limit=0).rate_limit == 1


class TestGobusterAuthWiring:
    def test_cookie_and_headers_appended(self, monkeypatch):
        import web_scanner as wsm
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            raise FileNotFoundError  # stop right after argv built
        monkeypatch.setattr(wsm.os.path, "exists", lambda p: True)
        monkeypatch.setattr(wsm.subprocess, "run", fake_run)
        ws = wsm.WebScanner("https://x.example",
                            auth_headers={"Cookie": "sid=9", "X-Env": "prod"})
        res = ws.gobuster_scan(wordlist="/tmp/common.txt")
        cmd = captured["cmd"]
        assert "-c" in cmd and cmd[cmd.index("-c") + 1] == "sid=9"
        assert "-H" in cmd and cmd[cmd.index("-H") + 1] == "X-Env: prod"
        assert not res.get("error")  # error=None -> falsy; gracefully handled
