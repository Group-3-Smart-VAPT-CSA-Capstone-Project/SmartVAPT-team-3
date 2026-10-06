import builtins
from dataclasses import asdict, dataclass, field
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
    cve: str | None = None
    cvss: float | None = None
    owasp: str | None = None
    target: str = ""
    port: int | None = None
    service: str | None = None
    confirmed: bool | None = None
    confidence: str | None = None
    cve_surface: str | None = None
    cve_note: str | None = None
    severity_downgrade_reason: str | None = None
    remediation: str = ""
    cvss_vector: str | None = None
    remediation_steps: list | None = None
    remediation_commands: dict | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity.lower(), 0)

class FindingSet:
    def __init__(self):
        self._findings: list[Finding] = []
        self._ids = set()

    def add(self, finding: Finding):
        if finding.id in self._ids:
            return
        self._ids.add(finding.id)
        self._findings.append(finding)

    def extend(self, findings: list[Finding]):
        for f in findings:
            self.add(f)

    def all(self) -> list[Finding]:
        return sorted(self._findings, key=lambda f: -f.severity_rank)

    def by_vector(self, vector: str) -> list[Finding]:
        return [f for f in self.all() if f.vector == vector]

    def remove(self, finding_id: str) -> bool:
        """Drop a finding by id (used e.g. to exclude CVEs validated as
        already patched by the distro). Returns True when removed."""
        before = len(self._findings)
        self._findings = [f for f in self._findings if f.id != finding_id]
        self._ids.discard(finding_id)
        return len(self._findings) < before

    def list(self) -> list[Finding]:
        return self.all()

    def counts(self) -> dict[str, int]:
        c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self._findings:
            c[f.severity.lower()] = c.get(f.severity.lower(), 0) + 1
        return c

    def to_dict_list(self) -> builtins.list[dict]:
        return [f.to_dict() for f in self.all()]

    def __len__(self):
        return len(self._findings)
