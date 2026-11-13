"""Resilience tests: a crashed or delayed vector (e.g. nuclei) must never
prevent the report from including the results of the other vectors
(nmap, gobuster/web checks, DNS, ...)."""
import json
import subprocess

import pytest

from nuclei_scanner import NucleiScanner


def _evt(template="test-template", severity="high", name="Test Match",
         host="http://target"):
    return json.dumps({"template-id": template, "severity": severity,
                       "info": {"name": name}, "matched-at": host + "/x"})


class FakeProc:
    """Minimal stand-in for the Popen object returned by run_logged."""

    def __init__(self, lines, rc=0, hang=False):
        self._lines = lines
        self.returncode = None if hang else rc
        self.terminated = False
        self.killed = False
        self.pid = 12345

    @property
    def stdout(self):
        yield from self._lines

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired(["nuclei"], timeout)
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9


@pytest.fixture
def no_shutil_which(monkeypatch):
    monkeypatch.setattr("nuclei_scanner.shutil.which",
                        lambda _: "/usr/bin/nuclei")


class TestNucleiCrashResilience:
    def test_nonzero_exit_keeps_partial_matches(self, monkeypatch,
                                                no_shutil_which):
        # nuclei crashes mid-run after emitting one valid match.
        proc = FakeProc([_evt() + "\n", "boom\n"], rc=1)
        monkeypatch.setattr("nuclei_scanner.run_logged",
                            lambda *a, **k: proc)
        res = NucleiScanner("http://target").scan()
        assert res["available"] is True
        assert res["partial"] is True
        assert "exited with code 1" in res["error"]
        # The partial finding survives so it reaches the report.
        assert len(res["matched"]) == 1
        assert len(res["findings"]) == 1
        assert res["findings"][0]["title"].startswith("Nuclei:")

    def test_reader_crash_salvages_output(self, monkeypatch,
                                          no_shutil_which):
        # An unexpected exception while reading stdout must not propagate.
        class Exploding(FakeProc):
            @property
            def stdout(self):
                yield _evt(template="first") + "\n"
                raise OSError("pipe exploded")

        monkeypatch.setattr("nuclei_scanner.run_logged",
                            lambda *a, **k: Exploding([], rc=None))
        res = NucleiScanner("http://target").scan()
        assert res["partial"] is True
        assert "failed mid-scan" in res["error"]
        assert len(res["matched"]) == 1  # salvaged before the crash

    def test_hang_timeout_returns_instead_of_blocking(self, monkeypatch,
                                                      no_shutil_which):
        # A delayed/hung nuclei is killed and scan() still returns with the
        # matches streamed so far — the pipeline can generate the report.
        # Uses a real (hanging) subprocess to also verify the deadline-based
        # stdout reader does not block on a silent pipe.
        import os
        import stat as stat_mod
        import tempfile
        import time

        d = tempfile.mkdtemp()
        fake = os.path.join(d, "nuclei")
        evt = _evt(template="early")
        with open(fake, "w") as fh:
            fh.write("#!/bin/sh\n"
                     f"echo '{evt}'\n"
                     "sleep 60\n")
        os.chmod(fake, os.stat(fake).st_mode | stat_mod.S_IEXEC)
        monkeypatch.setenv("PATH", d + os.pathsep + os.environ["PATH"])
        t0 = time.monotonic()
        res = NucleiScanner("http://target", timeout=2).scan()
        elapsed = time.monotonic() - t0
        assert elapsed < 15          # returned promptly, did not wait 60s
        assert res["partial"] is True
        assert "timed out" in res["error"]
        assert len(res["matched"]) == 1

    def test_missing_binary_is_graceful(self, monkeypatch):
        monkeypatch.setattr("nuclei_scanner.shutil.which", lambda _: None)
        res = NucleiScanner("http://target").scan()
        assert res["available"] is False
        assert res["findings"] == []
        assert "not found" in res["error"]


class TestReportSurvivesVectorFailure:
    def test_pdf_generated_with_nuclei_error_and_other_vectors(self, tmp_path):
        from report_gen import generate_report

        ai = {"executive_summary": "s", "overall_risk": "High",
              "risk_score": 7, "top_findings": [],
              "technical_remediation": [], "conclusion": ""}
        scan_data = {
            "target": "example.com", "scan_id": "TEST",
            "network": {"summary": {"open_ports": 2, "total_cves": 0,
                                    "critical": 0, "high": 0},
                        "hosts": [{"ip": "1.2.3.4", "ports": [
                            {"port": 80, "protocol": "tcp",
                             "service": "http"}]}],
                        "http_services": [{"url": "http://example.com",
                                           "port": 80, "service": "http"}]},
            "web": {"headers": {"server": "nginx", "present": [],
                                "missing": ["CSP"], "findings": []},
                    "directories": {"target": "http://example.com",
                                    "found": [{"path": "/admin",
                                               "status": 200, "size": 10}],
                                    "findings": []},
                    "tls": {}, "technologies": {},
                    "partial_errors": ["redirects"]},
            "dns": {"spf": {"present": True, "record": "v=spf1 -all"},
                    "dmarc": {"present": False}},
            # nuclei crashed mid-scan but produced one partial match
            "nuclei": {"target": "http://example.com", "available": True,
                       "partial": True, "error": "nuclei exited with code 1",
                       "matched": [{"template": "t1", "matcher": "",
                                    "name": "Partial Match",
                                    "severity": "high",
                                    "url": "http://example.com/x",
                                    "tags": "", "cvss": None,
                                    "reference": None}],
                       "findings": []},
            "findings": [],
        }
        out = tmp_path / "report.pdf"
        generate_report(scan_data, ai, str(out))
        assert out.exists() and out.stat().st_size > 1000
        pdf_bytes = out.read_bytes()[:5]
        assert pdf_bytes == b"%PDF-"
