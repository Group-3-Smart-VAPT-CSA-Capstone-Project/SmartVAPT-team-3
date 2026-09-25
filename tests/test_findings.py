import pytest
from findings import Finding, FindingSet

class TestFinding:
    def test_severity_rank_ordering(self):
        crit = Finding(id="1", vector="web", title="x", severity="critical",
                       description="", evidence="")
        low = Finding(id="2", vector="web", title="y", severity="low",
                      description="", evidence="")
        assert crit.severity_rank > low.severity_rank

    def test_to_dict_roundtrip(self):
        f = Finding(id="NET-001", vector="network", title="CVE-x",
                    severity="high", description="d", evidence="e",
                    cve="CVE-2021-1234", cvss=9.8)
        d = f.to_dict()
        assert d["id"] == "NET-001"
        assert d["cve"] == "CVE-2021-1234"

class TestFindingSet:
    def setup_method(self):
        self.fs = FindingSet()
        self.fs.add(Finding(id="A", vector="web", title="low",
                            severity="low", description="", evidence=""))
        self.fs.add(Finding(id="B", vector="web", title="crit",
                            severity="critical", description="", evidence=""))
        self.fs.add(Finding(id="C", vector="dns", title="med",
                            severity="medium", description="", evidence=""))

    def test_dedupe_by_id(self):
        self.fs.add(Finding(id="A", vector="web", title="dup",
                            severity="low", description="", evidence=""))
        assert len(self.fs) == 3

    def test_sorted_by_severity(self):
        ordered = [f.id for f in self.fs.all()]
        assert ordered == ["B", "C", "A"]

    def test_by_vector(self):
        assert len(self.fs.by_vector("web")) == 2
        assert len(self.fs.by_vector("dns")) == 1

    def test_counts(self):
        c = self.fs.counts()
        assert c["critical"] == 1
        assert c["medium"] == 1
        assert c["low"] == 1
