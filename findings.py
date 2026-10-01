from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict
from datetime import datetime, timezone

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------
# Every finding carries an explicit confidence so the reader can tell a
# directly-observed issue apart from one inferred from a version banner.
CONFIDENCE_ORDER = {"confirmed": 2, "likely": 1, "unverified": 0}
CONFIDENCE_LABELS = {
    "confirmed": "Confirmed",     # observed directly in this scan's evidence
    "likely": "Likely",           # strong inference (e.g. CVE DB match on a banner)
    "unverified": "Unverified",   # banner/version based only; not proof-of-concept
}


def normalize_confidence(value) -> str:
    """Return a canonical lower-case confidence string ('unverified' default)."""
    v = str(value or "").strip().lower()
    return v if v in CONFIDENCE_ORDER else "unverified"

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
    remediation: str = ""
    cvss_vector: Optional[str] = None
    remediation_steps: Optional[list] = None
    remediation_commands: Optional[dict] = None
    # Confidence: "confirmed" | "likely" | "unverified" (see CONFIDENCE_LABELS).
    confidence: str = "confirmed"
    # Exploitation surface for CVE findings: "server" | "client" |
    # "config-dependent". Client-side / config-dependent CVEs must never be
    # scored as directly-exploitable server vulnerabilities.
    exploit_surface: str = "server"
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
        # Severity first, then confidence (a Confirmed High outranks an
        # Unverified High), then id for stable output.
        return sorted(self._findings,
                      key=lambda f: (-f.severity_rank,
                                     -CONFIDENCE_ORDER.get(
                                         normalize_confidence(f.confidence), 0),
                                     f.id))

    def by_vector(self, vector: str) -> List[Finding]:
        return [f for f in self.all() if f.vector == vector]

    def counts(self) -> Dict[str, int]:
        c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self._findings:
            c[f.severity.lower()] = c.get(f.severity.lower(), 0) + 1
        return c

    def to_dict_list(self) -> List[Dict]:
        return [f.to_dict() for f in self.all()]

    def __len__(self):
        return len(self._findings)
