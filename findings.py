from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict
from datetime import datetime, timezone

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

@dataclass
class Finding:
    id: str
    vector: str
    title: str
    severity: str
    description: str
    evidence: str
    cve: Optional[str] = None
    cvss: Optional[float] = None
    owasp: Optional[str] = None
    target: str = ""
    port: Optional[int] = None
    service: Optional[str] = None
    confirmed: Optional[bool] = None
    confidence: Optional[str] = None
    cve_surface: Optional[str] = None
    cve_note: Optional[str] = None
    severity_downgrade_reason: Optional[str] = None
    remediation: str = ""
    cvss_vector: Optional[str] = None
    remediation_steps: Optional[list] = None
    remediation_commands: Optional[dict] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict:
        return asdict(self)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity.lower(), 0)

class FindingSet:
    def __init__(self):
        self._findings: List[Finding] = []
        self._ids = set()

    def add(self, finding: Finding):
        if finding.id in self._ids:
            return
        self._ids.add(finding.id)
        self._findings.append(finding)

    def extend(self, findings: List[Finding]):
        for f in findings:
            self.add(f)

    def all(self) -> List[Finding]:
        return sorted(self._findings, key=lambda f: -f.severity_rank)

    def by_vector(self, vector: str) -> List[Finding]:
        return [f for f in self.all() if f.vector == vector]

    def remove(self, finding_id: str) -> bool:
        """Drop a finding by id (used e.g. to exclude CVEs validated as
        already patched by the distro). Returns True when removed."""
        before = len(self._findings)
        self._findings = [f for f in self._findings if f.id != finding_id]
        self._ids.discard(finding_id)
        return len(self._findings) < before

    def list(self) -> List[Finding]:
        return self.all()

    def counts(self) -> Dict[str, int]:
        c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self._findings:
            c[f.severity.lower()] = c.get(f.severity.lower(), 0) + 1
        return c

    def to_dict_list(self) -> List[Dict]:
        return [f.to_dict() for f in self.all()]

    def __len__(self):
        return len(self._findings)
