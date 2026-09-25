
import json
from google import genai
from config import GEMINI_API_KEY, GEMINI_MODEL

# Note: google-genai SDK uses different safety setting format
# Safety settings are configured per-request if needed

SYSTEM_PROMPT = """You are a Senior Penetration Tester and CISO advisor.
You will receive raw vulnerability data from an automated VAPT scan covering:
1. Network infrastructure (open ports, services, CVEs)
2. Web application security (HTTP headers, exposed directories)
3. Domain/identity security (SPF, DMARC)

Your job:
- Correlate findings into business risk.
- Map issues to OWASP Top 10 where applicable.
- Prioritize by CVSS and exploitability.
- Produce a concise EXECUTIVE SUMMARY (non-technical) and a TECHNICAL REMEDIATION section with exact commands/config snippets.
- Use professional language suitable for C-suite.

Return ONLY valid JSON in this schema:
{
  "executive_summary": "...",
  "overall_risk": "Critical|High|Medium|Low",
  "risk_score": 0-10,
  "top_findings": [
    {"title": "...", "severity": "...", "business_impact": "...", "remediation": "..."}
  ],
  "technical_remediation": [
    {"finding": "...", "owasp": "...", "steps": ["...", "..."], "commands": ["..."]}
  ],
  "conclusion": "..."
}
"""


class AIEngine:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or GEMINI_API_KEY
        if not self.api_key or self.api_key == "YOUR_GEMINI_API_KEY_HERE":
            raise ValueError("GEMINI_API_KEY not configured. Set env var or edit config.py")
        
        # New SDK client initialization
        self.client = genai.Client(api_key=self.api_key)

    def analyze(self, findings: list, scan_summary: dict) -> dict:
        prompt = self._build_prompt(findings, scan_summary)
        try:
            response = self.client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
                config={
                    "system_instruction": SYSTEM_PROMPT,
                }
            )
            text = response.text.strip()
            if text.startswith("```"):
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            return json.loads(text)
        except json.JSONDecodeError:
            return {
                "executive_summary": response.text,
                "overall_risk": "Unknown",
                "risk_score": 0,
                "top_findings": [],
                "technical_remediation": [],
                "conclusion": "AI returned non-JSON response.",
            }
        except Exception as e:
            # Fallback: deterministic report from findings (no AI)
            fallback = self._fallback_summary(findings)
            fallback["conclusion"] = (
                f"Note: AI analysis unavailable ({type(e).__name__}). "
                "This report was generated using deterministic severity mapping. "
                "Check API key validity and re-run for the full AI narrative."
            )
            return fallback

    def _build_prompt(self, findings: list, scan_summary: dict) -> str:
        return f"""Analyze the following VAPT scan results and produce a JSON report
as specified in your system instructions.

=== UNIFIED FINDINGS ({len(findings)} total) ===
{json.dumps(findings, indent=2, default=str)[:10000]}

=== SCAN SUMMARY ===
{json.dumps(scan_summary, indent=2, default=str)[:2000]}

Return ONLY JSON. No markdown. No explanations outside JSON.
"""

    @staticmethod
    def _fallback_summary(findings: list) -> dict:
        """Generate a real executive summary from findings without the AI."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = (f.get("severity") or "").lower()
            if sev in counts:
                counts[sev] += 1

        total = len(findings)
        if counts["critical"]:
            risk, score = "Critical", min(10, 8 + counts["critical"] * 0.5)
        elif counts["high"]:
            risk, score = "High", 6 + min(2, counts["high"] * 0.4)
        elif counts["medium"]:
            risk, score = "Medium", 4.0
        elif counts["low"] or counts["info"]:
            risk, score = "Low", 2.0
        else:
            risk, score = "Low", 1.0

        summary = (
            f"SmartVAPT identified {total} findings across the assessed attack surface "
            f"— {counts['critical']} critical, {counts['high']} high, "
            f"{counts['medium']} medium, {counts['low']} low, {counts['info']} informational. "
            f"Overall risk has been rated {risk.upper()} ({score:.1f}/10) based on the "
            f"highest-severity issues discovered. Immediate attention is recommended for "
            f"all critical and high severity findings."
        )

        top = sorted(findings, key=lambda f: (
            -{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            .get((f.get("severity") or "").lower(), 0)
        ))[:10]

        return {
            "executive_summary": summary,
            "overall_risk": risk,
            "risk_score": round(score, 1),
            "top_findings": [
                {
                    "title": f.get("title", ""),
                    "severity": (f.get("severity") or "").capitalize(),
                    "business_impact": f.get("description", ""),
                    "remediation": f.get("remediation", ""),
                }
                for f in top
            ],
            "technical_remediation": [
                {
                    "finding": f.get("title", ""),
                    "owasp": f.get("owasp", "N/A"),
                    "steps": [f.get("remediation", "See finding description.")],
                    "commands": [],
                }
                for f in top if f.get("severity") in ("critical", "high")
            ],
            "conclusion": "",
        }
