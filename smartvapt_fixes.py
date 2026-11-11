"""Accuracy helpers for SmartVAPT findings and Ubuntu OpenSSH CVE checks."""
from __future__ import annotations

import re
import shutil
import subprocess
from urllib.parse import urljoin

import requests

try:
    from scoring import cve_context
except Exception:  # Keep the scanner importable if scoring is unavailable.
    def cve_context(cve_id: str) -> tuple[str | None, str | None]:
        return None, None

DEFAULT_TIMEOUT = 15
UA = {"User-Agent": "Mozilla/5.0 (SmartVAPT accuracy-check)"}
SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
_USEC_API = "https://ubuntu.com/security/cves/{cve}.json"
NOT_AFFECTED = "__not-affected__"
_ubuntu_status_cache: dict[str, dict[str, str | None]] = {}

_OPENSSH_UBUNTU_RE = re.compile(
    r"OpenSSH[ _](?P<up>\d+\.\d+[a-z]?\d*(?:p\d+)?)"
    r"[\s_-]+Ubuntu[\s_-]+(?P<tail>[^,;()]*)"
    r"(?=\s*(?:Ubuntu Linux|Linux|\(|~\d{2}\.\d{2}|[,;]|$))",
    re.IGNORECASE,
)
# The Ubuntu package revision is contiguous, e.g. 3ubuntu0.17 or
# 2ubuntu2.13. Do not require whitespace after "ubuntu".
_UBUNTU_TAIL_REV_RE = re.compile(
    r"(?P<rev>\d+)ubuntu\.?(?P<revb>\d+(?:\.\d+)?)", re.IGNORECASE
)
_UBUNTU_TAIL_REL_RE = re.compile(r"(?P<rel>\d{2}\.\d{2}(?:\.\d+)?)")
_HMU_RE = re.compile(r"[~ ](\d{2}\.\d{2})(?:\.\d+)?$")
_KNOWN_UBUNTU_SERIES = {
    "25.04": "plucky", "24.10": "oracular", "24.04": "noble",
    "23.10": "mantic", "23.04": "lunar", "22.10": "kinetic",
    "22.04": "jammy", "21.10": "impish", "21.04": "hirsute",
    "20.10": "groovy", "20.04": "focal", "19.10": "eoan",
    "19.04": "disco", "18.10": "cosmic", "18.04": "bionic",
    "16.04": "xenial", "14.04": "trusty", "12.04": "precise",
    "10.04": "lucid",
}
_UPSTREAM_TO_RELEASE = {
    "9.9": "25.04", "9.6": "24.10", "9.3": "24.04",
    "9.0": "23.10", "8.9": "22.04", "8.6": "21.10",
    "8.4": "21.04", "8.2": "20.04", "8.0": "20.10",
    "7.9": "19.10", "7.6": "18.04", "7.2": "16.04",
    "6.6": "14.04", "5.9": "12.04",
}


def _ubuntu_release_from_suffix(hmu: str | None, base: str, up: str = "") -> str:
    if hmu:
        return hmu
    if "." in base:
        return base
    return _UPSTREAM_TO_RELEASE.get(".".join(up.split(".")[:2]), "")


def parse_openssh_banner(banner: str) -> dict[str, object] | None:
    """Parse an Ubuntu OpenSSH banner; return None for non-Ubuntu banners."""
    match = _OPENSSH_UBUNTU_RE.search(banner or "")
    if not match:
        return None
    upstream = match.group("up")
    tail = match.group("tail").strip()
    rev_match = _UBUNTU_TAIL_REV_RE.search(tail)
    base, revision = ((rev_match.group("rev"), rev_match.group("revb"))
                      if rev_match else ("", ""))
    rel_match = _UBUNTU_TAIL_REL_RE.search(tail) if not rev_match else None
    explicit_release = rel_match.group("rel") if rel_match else ""
    hmu_match = _HMU_RE.search(banner or "")
    release = (hmu_match.group(1) if hmu_match else explicit_release[:5]
               if explicit_release else _ubuntu_release_from_suffix("", base, upstream))
    deb_revision = f"{base}ubuntu{revision}" if base else ""
    package_version = f"1:{upstream}-{deb_revision}" if deb_revision else ""
    return {
        "upstream": upstream,
        "release": release,
        "series": _KNOWN_UBUNTU_SERIES.get(release, release),
        "debian_base": base,
        "package_version": package_version,
        "revision": revision,
    }


def confidence_for(finding: dict) -> str:
    if finding.get("cve"):
        status = str((finding.get("ubuntu_validation") or {}).get("status") or "").lower()
        if status == "patched":
            return "patched"
        if status == "vulnerable":
            return "likely"
        explicit = str(finding.get("confidence") or "").lower()
        if ("unconfirmed" not in explicit and finding.get("cvss_vector")
                and not finding.get("cve_note")):
            return "confirmed"
        return "unconfirmed"
    if finding.get("confirmed") is True:
        return "confirmed"
    confidence = str(finding.get("confidence") or "").lower()
    for level in ("confirmed", "likely", "unconfirmed"):
        if level in confidence:
            return level
    return "likely"


def adjust_severity(finding: dict) -> dict:
    """Attach confidence and cap unconfirmed or non-server CVEs at Medium."""
    confidence = confidence_for(finding)
    finding["confidence"] = confidence
    finding.setdefault("target", finding.get("evidence_target", "")
                       or finding.get("service") or finding.get("id", ""))
    if not finding.get("cve"):
        return finding
    surface = finding.get("cve_surface") or cve_context(finding["cve"])[0] or "server"
    finding["cve_surface"] = surface
    rank = SEVERITY_ORDER.get(str(finding.get("severity", "")).lower(), 0)
    if confidence != "confirmed" and rank > SEVERITY_ORDER["medium"]:
        finding["severity"] = "medium"
        finding["severity_downgrade_reason"] = (
            "Banner/version match only - not confirmed by an active check; "
            "Ubuntu distro builds may backport fixes without changing upstream version.")
    if surface != "server":
        if rank > SEVERITY_ORDER["medium"]:
            finding["severity"] = "medium"
            reason = f"CVE is {surface}-surface, not directly exploitable against the listening service"
            previous = finding.get("severity_downgrade_reason")
            finding["severity_downgrade_reason"] = f"{previous}; {reason}" if previous else reason
        title = str(finding.get("title", ""))
        title = re.sub(r"\s*on\s+\S+\s+port\s+\d+$", "", title)
        finding["title"] = title + f" [{surface}-side]"
    return finding


def _resolve_location(base_url: str, location: str) -> str:
    return urljoin(base_url or "", location or "")


def attack_paths_for(result: dict) -> list[str]:
    if not result.get("vulnerable"):
        return ["Verification only: confirm the HTTP-to-HTTPS behavior inside the authorized scope."]
    if result.get("status") == 200:
        return [
            "Cleartext interception: content served over plain HTTP can be read or modified on the network path.",
            "SSL stripping may prevent users from reaching the HTTPS origin.",
            "Cookies without Secure may be exposed over the cleartext channel.",
        ]
    detail = result.get("detail", "")
    return [f"Upgrade bypass: {detail}"] if detail else ["HTTP upgrade does not reach HTTPS."]


def check_http_to_https(host: str, timeout: int = DEFAULT_TIMEOUT,
                        session: requests.Session | None = None) -> dict:
    """Probe a host's HTTP redirect without assuming a successful upgrade."""
    client = session or requests.Session()
    url = host if re.match(r"^https?://", host) else f"http://{host}"
    if url.startswith("https://"):
        url = "http://" + url[len("https://"):]
    result = {"redirects_ok": True, "vulnerable": False, "status": None,
              "location": "", "final_url": "", "detail": "", "attack_paths": []}
    try:
        response = client.get(url, timeout=timeout, allow_redirects=False, headers=UA)
    except requests.RequestException as exc:
        result["detail"] = f"Plain HTTP probe failed ({type(exc).__name__}); no content observed."
        result["attack_paths"] = attack_paths_for(result)
        return result
    result["status"] = response.status_code
    location = response.headers.get("Location", "")
    result["location"] = _resolve_location(response.url, location)
    if 300 <= response.status_code < 400:
        try:
            followed = client.get(url, timeout=timeout, allow_redirects=True, headers=UA)
            result["final_url"] = followed.url
        except requests.RequestException:
            result["final_url"] = result["location"]
        if ((response.status_code in (301, 302, 303, 307, 308)
             and result["location"].startswith("https://"))
                or str(result["final_url"]).startswith("https://")):
            result["detail"] = f"Verified HTTPS redirect: {result['location'] or result['final_url']}"
        else:
            result.update(redirects_ok=False, vulnerable=True,
                          detail=f"Redirect does not reach HTTPS: {result['location']}")
    elif response.status_code == 200:
        result.update(redirects_ok=False, vulnerable=True,
                      detail=f"Plain HTTP returned 200 ({len(response.content)} bytes).")
    else:
        result["detail"] = f"HTTP answered {response.status_code}; no cleartext content observed."
    result["attack_paths"] = attack_paths_for(result)
    return result


def normalize_package_version(info: dict[str, object]) -> str | None:
    return str(info.get("package_version") or "").strip() or None


def ubuntu_release_for_banner(banner: str) -> str | None:
    info = parse_openssh_banner(banner)
    return str(info["series"]) if info else None


def get_ubuntu_cve_status(cve_id: str, series: str, package: str = "openssh",
                          session: requests.Session | None = None,
                          timeout: int = DEFAULT_TIMEOUT) -> str | None:
    """Return the Ubuntu tracker fixed package version, sentinel, or None."""
    cache = _ubuntu_status_cache.setdefault(series, {})
    key = cve_id.upper()
    if key in cache:
        return cache[key]
    fixed = None
    try:
        response = (session or requests.Session()).get(
            _USEC_API.format(cve=key), timeout=timeout, headers=UA)
        if response.ok:
            document = response.json()
            packages = document.get("packages") or (document.get("data") or {}).get("packages", [])
            for pkg in packages:
                if str(pkg.get("name", "")).lower() != package.lower():
                    continue
                for status in pkg.get("statuses", []):
                    if str(status.get("release_codename", "")).lower() != series.lower():
                        continue
                    state = str(status.get("status", "")).lower()
                    if state in ("not-affected", "does-not-exist", "dne"):
                        fixed = NOT_AFFECTED
                    elif state == "released":
                        match = re.search(r"\d+:\S+-\S+|\S+-\S+", str(status.get("description") or ""))
                        if match:
                            fixed = match.group(0)
    except (requests.RequestException, ValueError, TypeError):
        fixed = None
    cache[key] = fixed
    return fixed


def dpkg_compare(installed: str, operator: str, fixed: str) -> bool | None:
    dpkg = shutil.which("dpkg")
    if not dpkg:
        return None
    try:
        result = subprocess.run([dpkg, "--compare-versions", installed, operator, fixed],
                                capture_output=True, text=True, timeout=10, check=False)
        return result.returncode == 0 if result.returncode in (0, 1) else None
    except (subprocess.SubprocessError, OSError):
        return None


def validate_ssh_cve(cve_id: str, banner: str,
                     session: requests.Session | None = None,
                     timeout: int = DEFAULT_TIMEOUT) -> dict:
    result = {"cve": cve_id.upper(), "status": "unconfirmed", "installed": None,
              "fixed": None, "release": None,
              "detail": "Not an Ubuntu distro OpenSSH banner; unconfirmed, banner-based."}
    info = parse_openssh_banner(banner)
    if not info:
        return result
    installed = normalize_package_version(info)
    series = str(info["series"])
    result["installed"], result["release"] = installed, series
    fixed = get_ubuntu_cve_status(cve_id, series, session=session, timeout=timeout)
    result["fixed"] = None if fixed == NOT_AFFECTED else fixed
    if fixed == NOT_AFFECTED:
        result.update(status="patched", detail=f"Ubuntu tracker marks {series} not affected.")
    elif fixed is None:
        result["detail"] = "Ubuntu tracker unavailable or no released fix; unconfirmed, banner-based."
    elif not installed:
        result["detail"] = "Banner has no package revision to compare; unconfirmed, banner-based."
    else:
        older = dpkg_compare(installed, "lt", fixed)
        if older is None:
            result["detail"] = "dpkg unavailable; version comparison is unconfirmed."
        elif older:
            result.update(status="vulnerable", detail=f"Installed {installed} < fixed {fixed} ({series}).")
        else:
            result.update(status="patched", detail=f"Installed {installed} >= fixed {fixed}; backport applied.")
    return result


def group_cves_by_release(findings: list[dict], banner: str) -> dict[str, list[dict]]:
    release = ubuntu_release_for_banner(banner) or "unknown"
    return {release: [finding for finding in findings if finding.get("cve")]}


def apply_validations(findings: list[dict], banner: str,
                      session: requests.Session | None = None,
                      service_filter: str | None = None) -> dict:
    buckets = {"vulnerable": [], "patched": [], "unconfirmed": []}
    for finding in findings:
        if not finding.get("cve"):
            continue
        if service_filter and str(finding.get("service") or "").lower() != service_filter.lower():
            finding.setdefault("confidence", "unconfirmed (banner-based)")
            buckets["unconfirmed"].append(finding)
            continue
        validation = validate_ssh_cve(finding["cve"], banner, session=session)
        finding["ubuntu_validation"] = validation
        if validation["status"] == "patched":
            finding.update(confidence="patched (not vulnerable)", confirmed=False,
                           severity="info", severity_downgrade_reason=validation["detail"])
            buckets["patched"].append(finding)
            continue
        finding["confirmed"] = False
        surface, note = cve_context(finding["cve"])
        if surface:
            finding.setdefault("cve_surface", surface)
        if note:
            finding.setdefault("cve_note", note)
        if validation["status"] == "vulnerable":
            finding["confidence"] = "likely (Ubuntu tracker confirms unfixed)"
            if finding.get("cve_surface") not in (None, "server") and \
                    SEVERITY_ORDER.get(str(finding.get("severity", "")).lower(), 0) > SEVERITY_ORDER["medium"]:
                finding["severity"] = "medium"
                finding["severity_downgrade_reason"] = "Non-server CVE surface; direct server impact not established."
            buckets["vulnerable"].append(finding)
        else:
            finding["confidence"] = "unconfirmed (banner-based)"
            adjust_severity(finding)
            buckets["unconfirmed"].append(finding)
    return buckets


__all__ = [
    "apply_validations", "adjust_severity", "confidence_for",
    "check_http_to_https", "attack_paths_for", "get_ubuntu_cve_status",
    "parse_openssh_banner", "ubuntu_release_for_banner", "validate_ssh_cve",
]
