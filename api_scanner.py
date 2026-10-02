"""Lightweight, safe API security checks (OWASP API Security Top 10 aligned).

Passive/low-interaction only: banner discovery, OPTIONS verb probing,
GraphQL introspection, JWT decode & weak-alg detection, rate-limit smoke
test (small burst), and common misconfig probes. No exploitation payloads.
"""
import json
import re
import time
from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlparse

import requests

from evidence import EvidenceStore
from findings import Finding

API_HINTS = ["/api", "/api/v1", "/api/docs", "/api/swagger.json",
             "/swagger.json", "/openapi.json", "/v2/api-docs",
             "/v3/api-docs", "/docs", "/redoc", "/graphql", "/api/graphql",
             "/rest/v1", "/wp-json", "/.well-known/openid-configuration"]

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]*)?")
WEAK_JWT_ALGS = {"none", "hs256"}  # alg=none handled separately; HS256 w/ secret risk


class APIScanner:
    def __init__(self, target_url: str, evidence: EvidenceStore = None,
                 timeout: int = 10, auth_headers: Dict[str, str] = None):
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url
        self.target = target_url.rstrip("/")
        self.origin = f"{urlparse(self.target).scheme}://{urlparse(self.target).netloc}"
        self.timeout = timeout
        self.evidence = evidence
        self.auth_headers = dict(auth_headers or {})
        self._idx = 0

    def _hdrs(self, extra: Dict[str, str] = None) -> Dict[str, str]:
        h = dict(self.auth_headers)
        if extra:
            h.update(extra)
        return h or None

    def _next_id(self) -> str:
        self._idx += 1
        return f"API-{self._idx:03d}"

    def run_all(self, progress_cb: Optional[Any] = None,
                stop_flag: Optional[dict] = None) -> Dict[str, Any]:
        result: Dict[str, Any] = {"target": self.target, "endpoints": [],
                                  "findings": [], "errors": []}
        steps = [
            ("Discover API endpoints", self.discover_endpoints),
            ("Probe HTTP verbs", self.check_methods),
            ("Check GraphQL introspection", self.check_graphql),
            ("Scan responses for JWTs", self.check_jwt),
            ("Rate-limit smoke test", self.check_rate_limit),
        ]
        for label, fn in steps:
            if stop_flag and stop_flag.get("stop"):
                result["errors"].append(f"{label}: skipped (scan stopped by user)")
                continue
            if progress_cb:
                progress_cb(f"[api] {label}...")
            try:
                fn(result)
            except Exception as e:  # keep pipeline resilient
                result["errors"].append(f"{label}: {e}")
        if self.evidence:
            self.evidence.save_json("api_scan", {k: v for k, v in result.items()
                                                 if k != "findings"})
        return result

    # ------------------------------------------------------------------
    def discover_endpoints(self, result: Dict):
        for hint in API_HINTS:
            url = urljoin(self.origin, hint)
            try:
                r = requests.get(url, timeout=self.timeout, allow_redirects=False,
                         headers=self._hdrs())
            except requests.RequestException:
                continue
            if r.status_code in (200, 201, 401, 403):
                ep = {"path": hint, "status": r.status_code,
                      "size": len(r.content),
                      "type": self._classify(r)}
                result["endpoints"].append(ep)
                if ep["type"] in ("swagger", "openapi"):
                    result["findings"].append(Finding(
                        id=self._next_id(), vector="web",
                        title=f"Public API documentation exposed: {hint}",
                        severity="medium",
                        description="Full API schema is publicly reachable, "
                                    "aiding attacker reconnaissance.",
                        evidence=f"GET {url} -> {r.status_code} ({ep['type']})",
                        owasp="API1:2023 - Broken Object Level Authorization",
                        target=url,
                        remediation="Restrict API docs to authenticated/"
                                    "internal users or remove in production.",
                    ).to_dict())

    @staticmethod
    def _classify(resp: requests.Response) -> str:
        ct = resp.headers.get("Content-Type", "").lower()
        body = resp.text[:2000].lower()
        if "swagger" in body or '"openapi"' in body or '"swagger":' in body:
            return "swagger"
        if "openid" in body or "authorization_endpoint" in body:
            return "oidc"
        if "json" in ct:
            return "json"
        if "<html" in body and ("swagger" in body or "redoc" in body):
            return "docs-ui"
        return "other"

    def check_methods(self, result: Dict):
        try:
            r = requests.options(self.origin, timeout=self.timeout,
                            headers=self._hdrs())
        except requests.RequestException as e:
            result["errors"].append(f"OPTIONS: {e}")
            return
        allow = set(v.strip().upper() for v in
                    (r.headers.get("Allow", "") + "," +
                     r.headers.get("Access-Control-Allow-Methods", "")).split(",")
                    if v.strip())
        dangerous = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"} & allow
        entry = {"path": "/", "status": r.status_code,
                 "methods": sorted(allow)}
        result["endpoints"].append(entry)
        if "TRACE" in allow or "CONNECT" in allow:
            result["findings"].append(Finding(
                id=self._next_id(), vector="web",
                title=f"Dangerous HTTP methods enabled: {sorted(allow)}",
                severity="medium",
                description="TRACE can enable XST attacks; CONNECT can abuse "
                            "the server as a proxy.",
                evidence=f"OPTIONS {self.origin} -> Allow={r.headers.get('Allow')}",
                owasp="API4:2023 - Lack of Resources / Rate Limiting",
                target=self.origin,
                remediation="Disable TRACE/CONNECT; restrict PUT/DELETE to "
                            "authenticated API routes only.",
            ).to_dict())
        elif dangerous:
            result["findings"].append(Finding(
                id=self._next_id(), vector="web",
                title=f"Write-capable HTTP verbs advertised: {sorted(dangerous)}",
                severity="info",
                description="Server advertises state-changing verbs on the "
                            "root resource; verify authorization on each.",
                evidence=f"OPTIONS {self.origin} -> {sorted(allow)}",
                target=self.origin,
                remediation="Ensure BOLA/BFLA controls on PUT/PATCH/DELETE.",
            ).to_dict())

    def check_graphql(self, result: Dict):
        for path in ("/graphql", "/api/graphql", "/query"):
            url = urljoin(self.origin, path)
            try:
                r = requests.post(url, timeout=self.timeout,
                                  json={"query": "{ __schema { types { name } } }"},
                                  headers=self._hdrs({"Content-Type": "application/json"}))
            except requests.RequestException:
                continue
            if r.status_code == 200 and "__schema" in (r.text[:500] + str(r.request.body)):
                if "types" in r.text and "__typename" in r.text or '"types"' in r.text:
                    result["findings"].append(Finding(
                        id=self._next_id(), vector="web",
                        title=f"GraphQL introspection enabled at {path}",
                        severity="medium",
                        description="Introspection exposes the full schema, "
                                    "mapping every query/mutation for attackers.",
                        evidence=f"POST {url} __schema query -> 200 with schema",
                        owasp="API4:2023 - Lack of Resources or Rate Limiting",
                        target=url,
                        remediation="Disable introspection in production "
                                    "(GRAPHQL_INTROSPECTION=false) and require auth.",
                    ).to_dict())
                    return

    def check_jwt(self, result: Dict):
        for hint in ("/api/login", "/api/auth", "/login", "/api/token", "/oauth/token"):
            url = urljoin(self.origin, hint)
            try:
                r = requests.get(url, timeout=self.timeout, headers=self._hdrs())
            except requests.RequestException:
                continue
            m = JWT_RE.search(r.text)
            if not m:
                continue
            token = m.group(0)
            decoded = self._decode_jwt(token)
            if not decoded:
                continue
            header = decoded.get("header", {})
            payload = decoded.get("payload", {})
            alg = str(header.get("alg", "")).lower()
            issues = []
            if alg == "none":
                issues.append("alg=none accepted/present")
            if alg == "hs256":
                issues.append("HS256 symmetric algorithm — vulnerable to "
                              "weak-secret brute force & RS256->HS256 confusion")
            if payload.get("exp") and payload["exp"] < time.time():
                issues.append("expired JWT served publicly")
            if issues:
                result["findings"].append(Finding(
                    id=self._next_id(), vector="web",
                    title=f"Weak JWT observed at {hint}",
                    severity="high" if alg == "none" else "medium",
                    description="; ".join(issues),
                    evidence=f"token header={json.dumps(header)[:200]}",
                    owasp="API2:2023 - Broken Authentication",
                    target=url,
                    remediation="Use RS256/ES256 with key rotation, reject "
                                "alg=none, and never leak tokens in GET responses.",
                ).to_dict())

    @staticmethod
    def _decode_jwt(token: str) -> Optional[Dict]:
        import base64

        def b64(part: str) -> bytes:
            pad = "=" * (-len(part) % 4)
            return base64.urlsafe_b64decode(part + pad)
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return None
            return {"header": json.loads(b64(parts[0])),
                    "payload": json.loads(b64(parts[1]))}
        except Exception:
            return None

    def check_rate_limit(self, result: Dict):
        """Small burst (<=10 req/s) smoke test — deliberately gentle."""
        url = self.origin
        sent = ok = 0
        try:
            for _ in range(10):
                r = requests.get(url, timeout=self.timeout, headers=self._hdrs())
                sent += 1
                if r.status_code in (429,):
                    ok += 1
                time.sleep(0.12)
        except requests.RequestException as e:
            result["errors"].append(f"rate-limit: {e}")
            return
        if ok == 0:
            result["findings"].append(Finding(
                id=self._next_id(), vector="web",
                title="No rate limiting detected on root endpoint",
                severity="low",
                description=f"{sent} rapid requests all succeeded (no HTTP 429). "
                            "Endpoint may be susceptible to brute force/DoS.",
                evidence=f"{sent} requests in ~{sent*0.12:.0f}s, 0 throttled",
                owasp="API4:2023 - Lack of Resources or Rate Limiting",
                target=url,
                remediation="Add per-IP/per-token rate limits at the gateway "
                            "(e.g., nginx limit_req_zone).",
            ).to_dict())
