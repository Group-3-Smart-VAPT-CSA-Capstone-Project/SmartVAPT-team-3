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
        # gobuster now only fires against an nmap -sV-confirmed HTTP endpoint,
        # so the test supplies one (HTTP detected on 8443 instead of 80).
        services = [{"url": "https://x.example:8443", "port": 8443,
                     "service": "https"}]
        res = ws.gobuster_scan(wordlist="/tmp/common.txt",
                               http_services=services)
        cmd = captured["cmd"]
        assert "-u" in cmd and cmd[cmd.index("-u") + 1] == "https://x.example:8443"
        assert "-c" in cmd and cmd[cmd.index("-c") + 1] == "sid=9"
        assert "-H" in cmd and cmd[cmd.index("-H") + 1] == "X-Env: prod"
        assert not res.get("error")  # error=None -> falsy; gracefully handled


class TestSoft404AndSignatureValidation:
    """False-positive reduction for sensitive-path probing:
    soft-404 baseline, Content-Type enforcement, content signatures."""

    # ---- pure helper tests ------------------------------------------------
    def test_extension_key_resolution(self):
        from web_scanner import _extension_key
        assert _extension_key("backup.zip") == ".zip"
        assert _extension_key("backup.tar.gz") == ".tar.gz"
        assert _extension_key("db.sql") == ".sql"
        assert _extension_key(".env") == ".env"
        assert _extension_key(".git/config") == ".git/config"
        assert _extension_key("id_rsa") == "id_rsa"
        assert _extension_key(".htpasswd") == ".htpasswd"
        assert _extension_key("wp-config.php.bak") == ".php.bak"
        assert _extension_key("unknownthing") is None

    def test_content_type_zip_requires_application_zip(self):
        from web_scanner import content_type_ok
        assert content_type_ok("backup.zip", "application/zip")
        assert content_type_ok("backup.zip", "application/zip; charset=x")
        assert not content_type_ok("backup.zip", "text/html")           # FP
        assert not content_type_ok("backup.zip", "text/html; charset=UTF-8")
        assert content_type_ok("backup.zip", None)  # missing header -> other layers decide

    def test_content_type_sql(self):
        from web_scanner import content_type_ok
        assert content_type_ok("db.sql", "text/plain")
        assert content_type_ok("db.sql", "application/sql")
        assert not content_type_ok("db.sql", "text/html")

    def test_signature_env(self):
        from web_scanner import has_valid_signature
        assert has_valid_signature(".env", b"APP_ENV=production\nDB_PASSWORD=s3cret\n")
        assert not has_valid_signature(".env", b"<html><body>Not Found</body></html>")

    def test_signature_git_config(self):
        from web_scanner import has_valid_signature
        assert has_valid_signature(".git/config", b"[core]\n\trepositoryformatversion = 0\n")
        assert has_valid_signature(".git/config", b'[remote "origin"]\n\turl = x\n')
        assert not has_valid_signature(".git/config", b"Welcome to our site!")

    def test_signature_id_rsa(self):
        from web_scanner import has_valid_signature
        assert has_valid_signature("id_rsa", b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNz")
        assert has_valid_signature("id_rsa", b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpA")
        assert not has_valid_signature("id_rsa", b"<html>404</html>")

    def test_signature_htpasswd(self):
        from web_scanner import has_valid_signature
        assert has_valid_signature(".htpasswd", b"admin:$apr1$Zx7L9k2Q$eI6BvY0dGxWqXg0mP2uYV/\n")
        assert not has_valid_signature(".htpasswd", b"just some random page text here")

    def test_signature_binary_magic(self):
        from web_scanner import has_valid_signature
        assert has_valid_signature("backup.zip", b"PK\x03\x04\x14\x00\x00\x00")
        assert not has_valid_signature("backup.zip", b"<html>oops</html>")
        assert has_valid_signature("backup.tar.gz", b"\x1f\x8b\x08\x00junk")
        assert not has_valid_signature("backup.tar.gz", b"hello world")

    def test_soft404_match_by_size_hash_title(self):
        from web_scanner import matches_soft404_baseline
        base = {"detected": True, "body_size": 1845,
                "body_sha256": "abc123", "title": "Custom 404 Page"}
        assert matches_soft404_baseline({"size": 1845, "body_sha256": "zzz"}, base)
        assert matches_soft404_baseline({"size": 10, "body_sha256": "abc123"}, base)
        assert matches_soft404_baseline({"size": 10, "body_sha256": "z",
                                         "title": "Custom 404 Page"}, base)
        assert not matches_soft404_baseline({"size": 99, "body_sha256": "other"}, base)
        # no baseline -> nothing matches (no over-filtering)
        assert not matches_soft404_baseline({"size": 1845}, {"detected": False})
        assert not matches_soft404_baseline({"size": 1845}, None)

    # ---- end-to-end probe_sensitive_paths with mocked responses -----------
    def _mk_resp(self, status, body=b"", ctype=None):
        import requests

        class R:
            def __init__(self):
                self.status_code = status
                self.content = body
                self.headers = {}
                if ctype:
                    self.headers["Content-Type"] = ctype
            @property
            def text(self):
                return self.content.decode("utf-8", errors="replace")
        return R()

    def _fake_get_factory(self, routes, soft404_body):
        import requests

        def fake_get(url, **kw):
            path = url.split("://", 1)[-1].split("/", 1)[1]
            if path in routes:
                return routes[path]
            if path.startswith("smvapt-"):
                return self._mk_resp(200, soft404_body, "text/html")
            return self._mk_resp(404, b"Not Found", "text/html")
        return fake_get

    def test_probe_discards_soft404_mimes_and_bad_signatures(self, monkeypatch):
        import web_scanner as wsm
        soft_body = b"<html><head><title>Page Not Found</title></head>" + b"x" * 1781
        real_env = self._mk_resp(200, b"APP_KEY=base64:abcdef=\nDB_HOST=localhost\n",
                                 "text/plain")
        html_like_env = self._mk_resp(200, soft_body, "text/html")  # same size as baseline
        zip_as_html = self._mk_resp(200, b"<html>coming soon</html>", "text/html")
        real_zip = self._mk_resp(200, b"PK\x03\x04" + b"\x00" * 500, "application/zip")
        bogus_id_rsa = self._mk_resp(200, b"<pre>Directory listing</pre>", "text/plain")
        routes = {".env": real_env, "backup.zip": zip_as_html,
                  "id_rsa": bogus_id_rsa}
        # a soft-404 server also answers /.env-style misses with the generic page
        monkeypatch.setattr(wsm.requests, "get",
                            self._fake_get_factory(routes, soft_body))
        ws = wsm.WebScanner("http://target.example")
        res = ws.probe_sensitive_paths()
        found = {f["path"] for f in res["found"]}
        assert found == {".env"}, f"only signature-valid .env should survive: {found}"
        reasons = {d["path"]: d["reason"] for d in res["discarded"]}
        assert reasons["backup.zip"].startswith("content_type_mismatch")
        assert reasons["id_rsa"] == "no_content_signature"
        assert res["soft404_baseline"]["detected"] is True
        assert res["soft404_baseline"]["body_size"] == len(soft_body)
        titles = [f["title"] for f in res["findings"]]
        assert any("Sensitive file publicly accessible: /.env" in t for t in titles)

    def test_probe_real_files_when_no_soft404(self, monkeypatch):
        import web_scanner as wsm
        real_git = self._mk_resp(200, b"[core]\nrepositoryformatversion = 0\n",
                                 "text/plain")
        routes = {".git/config": real_git}
        # proper 404s on random paths -> no baseline detected
        def fake_get(url, **kw):
            path = url.split("://", 1)[-1].split("/", 1)[1]
            if path in routes:
                return routes[path]
            return self._mk_resp(404, b"Not Found", "text/html")
        monkeypatch.setattr(wsm.requests, "get", fake_get)
        ws = wsm.WebScanner("http://target.example")
        res = ws.probe_sensitive_paths()
        assert res["soft404_baseline"]["detected"] is False
        assert [f["path"] for f in res["found"]] == [".git/config"]
        assert res["discarded"] == []

    def test_detect_soft404_baseline_records_size_and_title(self, monkeypatch):
        import web_scanner as wsm
        body = b"<html><title>Default Page</title>" + b"y" * 1723
        def fake_get(url, **kw):
            return self._mk_resp(200, body, "text/html")
        monkeypatch.setattr(wsm.requests, "get", fake_get)
        ws = wsm.WebScanner("http://target.example")
        base = ws.detect_soft404_baseline()
        assert base["detected"] is True
        assert base["probed"] == wsm.SOFT404_PROBES
        assert base["body_size"] == len(body)
        assert base["title"] == "Default Page"
        # cached and reused
        assert ws.soft404_baseline is base


class TestGeoLocator:
    def test_extract_host_variants(self):
        from geo_locator import extract_host
        assert extract_host("https://Example.com:8443/path?q=1") == "example.com"
        assert extract_host("scanme.nmap.org") == "scanme.nmap.org"
        assert extract_host("http://10.0.0.5") == "10.0.0.5"
        assert extract_host("") == ""

    def test_resolve_ips_literal(self):
        from geo_locator import resolve_ips
        assert resolve_ips("192.168.1.1") == ["192.168.1.1"]
        assert resolve_ips("") == []

    def test_private_ip_not_looked_up(self):
        from geo_locator import geolocate_ip
        for ip in ("127.0.0.1", "10.10.10.10", "192.168.5.5", "169.254.1.1"):
            r = geolocate_ip(ip)
            assert r.get("private") and not r.get("found"), (ip, r)

    def test_hosting_summary_fallback(self):
        from geo_locator import hosting_summary
        assert hosting_summary({}) == "Unknown"
        assert hosting_summary({"found": False, "error": "boom"}) == "boom"
        s = hosting_summary({"found": True, "city": "X", "country": "Y",
                             "organization": "Z", "asn": "AS1"})
        assert "X" in s and "Z" in s and "AS1" in s

    def test_geolocator_private_target(self):
        from geo_locator import GeoLocator
        g = GeoLocator("192.168.5.5").locate()
        assert g["hostname"] == "192.168.5.5"
        assert g["resolved_ips"] == ["192.168.5.5"]
        assert g["locations"][0].get("private")
