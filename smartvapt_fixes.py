"""smartvapt_fixes.py - drop-in accuracy fixes for the SmartVAPT scanner
and report generator.

Addresses the three accuracy problems raised in the review of
SmartVAPT_20261001_044715.pdf (scanme.nmap.org, headline "Critical 9.5/10"):

1. Confidence / target on every finding + severity demotion.
   Every finding now carries ``confidence`` ("unconfirmed", "likely" or
   "confirmed") and its real ``target``.  adjust_severity() demotes
   banner-only CVE matches and client-side / config-dependent CVEs so raw
   CVSS is never reported as the effective risk.

2. "No HTTP -> HTTPS redirect [High]" false positive.
   check_http_to_https() probes the *actual* redirect chain with a plain
   GET issued directly against http://host (allow_redirects=False), then
   follows separately.  The finding is only returned when plain HTTP
   really serves content (status 200) without upgrading to https://.
   A 301/308 whose Location resolves to https:// verifies the redirect -
   exactly the case the old code got wrong when it judged the FINAL url
   instead of the response's status + Location header.
   attack_paths_for() also generates the finding's attack paths from the
   actual probe result, so they can no longer contradict the evidence
   (the old report paired this finding with weak-TLS-cipher paths that
   nothing in the scan tested).

3. Banner-based SSH CVEs on Ubuntu distro builds.
   validate_ssh_cve() looks each CVE up in Ubuntu's security data
   (ubuntu.com/security/cves JSON API, Launchpad libssh mirror as
   fallback) for the release detected in the banner, compares the
   installed package version with the fixed one via
   ``dpkg --compare-versions``, and marks patched CVEs as "patched"
   (excluded from findings) instead of "vulnerable".  When the lookup
   cannot be completed the CVE stays "unconfirmed, banner-based" - never
   silently promoted to confirmed.

Network-dependent helpers degrade gracefully: any failure keeps the
finding at "unconfirmed (banner-based)" rather than guessing.
"""

from __future__ import annotations

import re
import shutil
import subprocess

import requests

try:  # surface table lives in scoring.py; fall back to a local copy offline
    from scoring import cve_context
except Exception:  # pragma: no cover - import-time safety only
    def cve_context(cve_id: str) -> tuple[str | None, str | None]:
        return None, None

DEFAULT_TIMEOUT = 15
UA = {"User-Agent": "Mozilla/5.0 (SmartVAPT accuracy-check)"}

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


# ----------------------------------------------------------------------
# 1. Banner parsing + confidence model
# ----------------------------------------------------------------------

# Accepts the raw SSH banner ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.17"),
# nmap's split product/version/extrainfo ("OpenSSH 8.9p1 Ubuntu 3ubuntu0.17")
# and HMU-suffixed variants ("... 3ubuntu0.17\n~22.04.1").
# The Ubuntu part is either a Debian revision tail ('3ubuntu0.17') or a
# standalone MM.YY release number ('Ubuntu 22.04').
_OPENSSH_UBUNTU_RE = re.compile(
    r"OpenSSH[ _](?P<up>\d+\.\d+[a-z]?\d*(?:p\d+)?)"   # upstream: 8.9p1/6.6.1p1
    # Debian revisions may be multi-digit ('2ubuntu2.13', '3ubuntu0.17') and
    # the release tail may carry dots/spaces ('Ubuntu 14.04.6 LTS').
    r"[\s_-]+Ubuntu[\s_-]+(?P<tail>[^,;()]*?)"
    r"(?=\s*(?:Ubuntu Linux|Linux|\(|~\d{2}\.\d{2}|\s*[,;]|$))",
    re.IGNORECASE)
_UBUNTU_TAIL_REV_RE = re.compile(
    r"(?P<rev>\d+)ubuntu\.?(?P<revb>\d+(?:\.\d+)?)", re.IGNORECASE)
_UBUNTU_TAIL_REL_RE = re.compile(r"(?P<rel>\d{2}\.\d{2}(?:\.\d+)?)")
_HMU_RE = re.compile(r"[~ ](\d{2}\.\d{2})(?:\.\d+)?$")  # '...~22.04.1' HMU suffix

# Stable releases we map unknown interim suffixes onto (newest first).
_KNOWN_UBUNTU_SERIES = {
    "25.04": "plucky", "24.10": "oracular", "24.04": "noble",
    "23.10": "mantic", "23.04": "lunar", "22.10": "kinetic",
    "22.04": "jammy", "21.10": "impish", "21.04": "hirsute",
    "20.10": "groovy", "20.04": "focal", "19.10": "eoan",
    "19.04": "disco", "18.10": "cosmic", "18.04": "bionic",
}

# Ubuntu OpenSSH source-debian-revision bases -> MM.YY release, in the
# order Ubuntu has bumped the packaging revision over time (jammy=3,
# focal=5, noble=6...).  The *same* base number means different releases
# depending on the upstream version, so resolution is two-dimensional:
# a base only maps to releases whose window contains the observed
# upstream major; when several still match, the newest wins.
_BASE_RELEASES = [
    # (debian_base, min_upstream_major_inclusive, release)
    ("1", 0.0,  "10.04"),
    ("2", 5.9,  "16.04"),   # xenial: openssh 1:7.2p2-2ubuntuX
    ("3", 8.0,  "22.04"),   # jammy:  1:8.9p1-3ubuntuX
    ("3", 0.0,  "18.04"),   # bionic: 1:7.6p1-3ubuntuX  (older base reuse)
    ("4", 8.0,  "23.10"),
    ("4", 0.0,  "18.10"),
    ("5", 9.0,  "24.04"),   # noble:  1:9.6p1-5ubuntuX
    ("5", 8.0,  "20.04"),   # focal:  1:8.2p1-5ubuntuX
    ("5", 0.0,  "19.10"),
    ("6", 9.0,  "24.10"),
    ("6", 0.0,  "23.04"),
    ("7", 0.0,  "25.04"),
    ("8", 0.0,  "25.10"),
]


def parse_openssh_banner(banner: str) -> dict[str, object] | None:
    """Extract the Ubuntu source-package version an OpenSSH banner implies.

    'OpenSSH 8.9p1 Ubuntu 3ubuntu0.17'  (reported by nmap as product/version)
    -> {'upstream': '8.9p1', 'series': 'jammy', 'release': '22.04',
        'package_version': '1:8.9p1-3ubuntu0.17', 'revision': '0.17'}

    Returns None when the banner is not an Ubuntu distro OpenSSH build.
    """
    m = _OPENSSH_UBUNTU_RE.search(banner or "")
    if not m:
        return None
    up = m.group("up")
    # Rebuild the FULL Debian revision from the matched banner text
    # ('3ubuntu0.17' in 'OpenSSH 8.9p1 Ubuntu 3ubuntu0.17'): Ubuntu's
    # security-tracker fixed-version strings look like
    # '1:8.9p1-3ubuntu0.10', so epoch + upstream + exact revision are all
    # needed for a meaningful dpkg comparison.  Multi-digit bases and
    # multi-dot tails ('2ubuntu2.13') are handled by the tail regexes.
    tail = (m.group("tail") or "").strip()
    tm = _UBUNTU_TAIL_REV_RE.search(tail)
    base, revb = (tm.group("rev"), tm.group("revb")) if tm else ("", "")
    rel_m = _UBUNTU_TAIL_REL_RE.search(tail) if not tm else None
    if base:
        # The banner tail '3ubuntu0.17' splits as rev='3', revb='0.17';
        # rejoin WITHOUT inserting an extra dot (the '.' belongs to revb).
        deb_rev = f"{base}ubuntu{revb}" if revb else f"{base}ubuntu"
    else:
        deb_rev = ""
    rev_tail = revb or ""
    rel = rel_m.group("rel") if rel_m else ""
    if not base and rel:
        # 'Ubuntu 22.04' style - release number, no Debian revision tail.
        # An exact comparison is not possible, so keep package_version
        # empty and let the caller stay 'unconfirmed' rather than
        # comparing against a fabricated string.
        base, rev_tail, deb_rev = "", "", ""
    hmu = _HMU_RE.search(banner or "")
    release = _ubuntu_release_from_suffix(hmu.group(1) if hmu else None,
                                          base, _upstream_major(up))
    if not release:                        # MM.YY given directly in banner
        release = rel.rstrip(".")[:5] if rel else ""
    pkg = f"1:{up}-{deb_rev}" if deb_rev else ""
    return {
        "upstream": up,
        "release": release,
        "series": _KNOWN_UBUNTU_SERIES.get(release, release),
        "debian_base": base,
        "package_version": pkg,
        "revision": rev_tail,
    }


def _upstream_major(up: str) -> float:
    try:
        return float(re.match(r"(\d+)\.", up).group(1))
    except (AttributeError, ValueError):
        return 0.0


def _ubuntu_release_from_suffix(hmu: str | None, base: str,
                                up_major: float = 0.0) -> str:
    """Resolve the MM.YY userspace release an OpenSSH package belongs to.

    An HMU suffix ('~22.04.1') wins; a base that already looks like a
    release ('22.04') is used directly; a short Debian revision base
    resolves through _BASE_RELEASES using the upstream major version to
    disambiguate reused numbering.  Returns '' when nothing identifies
    the release (caller falls back to the MM.YY captured from the banner).
    """
    if hmu:
        return hmu
    if "." in base:
        return base
    if not base:
        return ""
    matches = [rel for b, minmaj, rel in _BASE_RELEASES
               if b == base and up_major >= minmaj]
    if not matches:
        return base + ".04"
    # Newest release among the plausible windows (list is oldest→newest
    # within each base, so take the last match with highest minmaj).
    best = max(((minmaj, rel) for b, minmaj, rel in _BASE_RELEASES
                if b == base and up_major >= minmaj), key=lambda x: x[0])
    return best[1]


# ----------------------------------------------------------------------
# 2. adjust_severity - confidence-driven demotion
# ----------------------------------------------------------------------

_CONF_RANK = {"confirmed": 3, "likely": 2, "unconfirmed": 1}


def confidence_for(finding: dict) -> str:
    """Derive the confidence level of a finding from its own evidence.

    Precedence matters for CVE findings: a banner/version match is a
    hypothesis, never a confirmed vulnerability - even when an earlier
    pipeline stage stamped ``confirmed=True`` / ``confidence='confirmed'``
    on the dict (those stamps only mean "the scanner observed this
    reliably", not that the flaw was actively verified).  Ubuntu-tracker
    results win when present: 'vulnerable' -> likely, 'patched'/'not
    affected' -> patched.  Only CVEs carrying a CVSS vector *and* no
    distro-backport caveat qualify as 'confirmed'.
    """
    if finding.get("cve"):
        v = finding.get("ubuntu_validation") or {}
        vstat = str(v.get("status") or "").lower()
        if vstat == "patched":
            return "patched"
        if vstat == "vulnerable":
            return "likely"
        explicit = str(finding.get("confidence") or "").lower()
        if ("unconfirmed" not in explicit and finding.get("cvss_vector")
                and not finding.get("cve_note")):
            return "confirmed"   # scored advisory, not a distro-build guess
        return "unconfirmed"     # banner/version match only
    if finding.get("confirmed") is True:
        return "confirmed"
    conf = str(finding.get("confidence") or "").lower()
    for level in ("confirmed", "likely", "unconfirmed"):
        if level in conf:
            return level
    if finding.get("cve"):
        return "unconfirmed"  # banner match unless something proved otherwise
    return "likely"           # direct observation (header missing, DNS record…)


def adjust_severity(finding: dict) -> dict:
    """Attach confidence/target and demote what the evidence doesn't support.

    Mutates and returns the finding:
      - banner-only CVE matches are capped at 'medium' (they are hypotheses,
        not confirmed vulnerabilities);
      - client-/config-surface CVEs are additionally rewritten so the title
        and attack paths say who is actually exposed;
      - demotions record 'severity_downgrade_reason' for the report.
    """
    conf = confidence_for(finding)
    finding["confidence"] = conf
    finding.setdefault("target", finding.get("evidence_target", "")
                       or finding.get("service") or finding.get("id", ""))
    if not finding.get("cve"):
        return finding

    surface = finding.get("cve_surface") or (cve_context(finding["cve"])[0]) or "server"
    finding["cve_surface"] = surface
    rank = SEVERITY_ORDER.get(str(finding.get("severity", "")).lower(), 0)
    if conf != "confirmed" and rank > SEVERITY_ORDER["medium"]:
        finding["severity"] = "medium"
        finding["severity_downgrade_reason"] = (
            "Banner/version match only - not confirmed by an active check "
            "(Ubuntu distro builds backport fixes without changing the "
            "upstream version string)")
    if surface != "server" and rank > SEVERITY_ORDER["medium"]:
        finding["severity"] = "medium"
        prior = finding.get("severity_downgrade_reason")
        reason = (f"CVE is {surface}-side/configuration-dependent, not "
                  "directly exploitable against the listening service")
        finding["severity_downgrade_reason"] = f"{prior}; {reason}" if prior else reason
    if surface != "server":
        finding["title"] = re.sub(
            r"\s*on\s+\S+\s+port\s+\d+$", "", str(finding.get("title", ""))) + \
            f" [{surface}-side]"
    return finding


# ----------------------------------------------------------------------
# 3. check_http_to_https - real redirect probe (false-positive fix)
# ----------------------------------------------------------------------

def _resolve_location(final_url: str, location: str) -> str:
    from urllib.parse import urljoin
    return urljoin(final_url or "", location or "")


def check_http_to_https(host: str, timeout: int = DEFAULT_TIMEOUT,
                        session: requests.Session | None = None) -> dict:
    """Probe whether plain HTTP actually upgrades to HTTPS.

    Returns a dict:
      redirects_ok : bool  - True when NOT vulnerable
      vulnerable   : bool
      status       : int|None  (of the direct http:// GET)
      location     : str  (Location header, resolved)
      final_url    : str  (after following the chain)
      detail       : str
      attack_paths : list generated FROM the actual check (see
                     attack_paths_for) - never the canned TLS-cipher text.

    Only raises the finding when plain HTTP really returns 200 (content
    served over cleartext).  30x to https://, connection refused, or a
    non-HTTP port verify the redirect / make the claim inapplicable.
    """
    s = session or requests.Session()
    url = host if re.match(r"^https?://", host) else f"http://{host}"
    if url.startswith("https://"):  # normalise to the plain-HTTP probe
        url = "http://" + url[len("https://"):]
    out: dict = {"redirects_ok": True, "vulnerable": False, "status": None,
                 "location": "", "final_url": "", "detail": "",
                 "attack_paths": []}
    try:
        direct = s.get(url, timeout=timeout, allow_redirects=False,
                      headers=UA)
    except requests.RequestException as e:
        out["detail"] = f"Plain HTTP probe failed ({type(e).__name__}); " \
                        "no cleartext content observed - finding not raised."
        out["attack_paths"] = attack_paths_for(out)
        return out

    out["status"] = direct.status_code
    loc = direct.headers.get("Location", "")
    out["location"] = _resolve_location(direct.url, loc)
    followed = None
    if 300 <= direct.status_code < 400:
        try:
            followed = s.get(url, timeout=timeout, allow_redirects=True,
                             headers=UA)
            out["final_url"] = followed.url
        except requests.RequestException:
            out["final_url"] = out["location"]
        upgraded = (direct.status_code in (301, 302, 303, 307, 308)
                    and out["location"].startswith("https://")) \
            or str(out["final_url"]).startswith("https://")
        if upgraded:
            out["detail"] = (f"Verified: {direct.status_code} "
                             f"{url} -> {out['location'] or out['final_url']}"
                             " (HTTPS). Redirect present - not vulnerable.")
            out["attack_paths"] = attack_paths_for(out)
            return out
        out["redirects_ok"] = False
        out["vulnerable"] = True
        out["detail"] = (f"Redirect loop/off-site hop: {direct.status_code} "
                         f"Location={out['location']} never reaches https://")
    elif direct.status_code == 200:
        out["redirects_ok"] = False
        out["vulnerable"] = True
        out["detail"] = (f"Plain HTTP returns 200 ({len(direct.content)} "
                         "bytes) with no upgrade - cleartext content served.")
    else:
        out["detail"] = f"HTTP answered {direct.status_code}; no cleartext " \
                        "content served - finding not raised."
    out["attack_paths"] = attack_paths_for(out)
    return out


def attack_paths_for(result: dict) -> list[str]:
    """Generate attack paths from the ACTUAL redirect check result."""
    if not result.get("vulnerable"):
        return [("Verification only: confirm the 3xx-to-https:// behaviour "
                "with `curl -sI http://<target>` inside the signed scope.")]
    detail = result.get("detail", "")
    if result.get("status") == 200:
        return [
            ("Cleartext interception: content served over plain HTTP can be "
            "read/modified by anyone on the network path (MITM)."),
            ("SSL-strip: users typed or linked to https:// can be downgraded "
            "to the http:// origin because no upgrade exists."),
            ("Session cookies set without Secure transport may leak over the "
            "cleartext channel."),
        ]
    return [f"Upgrade bypass: {detail}"] if detail else \
        [("HTTP->HTTPS upgrade does not reach https://; traffic may stay "
         "on the cleartext channel.")]


# ----------------------------------------------------------------------
# 4. validate_ssh_cve - Ubuntu CVE tracker cross-check
# ----------------------------------------------------------------------

_USEC_API = "https://ubuntu.com/security/cves/{cve}.json"
_LP_API = ("https://api.launchpad.net/1.0/opensource/"
           "?ws.op=getPublishedVersions&exact_match=true&text={pkg}")

# per-release cached {cve: fixed_binary_version_or_None}
_ubuntu_status_cache: dict[str, dict[str, str | None]] = {}

# sentinel returned by get_ubuntu_cve_status() when Ubuntu explicitly says
# the release is not affected / package did not exist in it.
NOT_AFFECTED = "__not-affected__"


def normalize_package_version(info: dict[str, object]) -> str | None:
    """Return the Debian source-package version an Ubuntu OpenSSH banner
    implies (e.g. '1:8.9p1-3ubuntu0.17'), or None when the banner does not
    carry enough information to compare reliably.

    This is what gets fed to ``dpkg --compare-versions`` against the fixed
    versions published by the Ubuntu security tracker; those strings look
    like '1:8.9p1-3ubuntu0.10', so the epoch and full Debian revision must
    be preserved verbatim.
    """
    pkg = str(info.get("package_version") or "").strip()
    return pkg or None


def ubuntu_release_for_banner(banner: str) -> str | None:
    """Return the 'jammy'-style series an OpenSSH banner implies."""
    info = parse_openssh_banner(banner)
    return info["series"] if info else None


def get_ubuntu_cve_status(cve_id: str, series: str,
                          package: str = "openssh",
                          session: requests.Session | None = None,
                          timeout: int = DEFAULT_TIMEOUT) -> str | None:
    """Fixed binary package version of ``package`` for ``cve_id`` in
    ``series`` from Ubuntu's security data, or None when the tracker has
    no released fix to compare against (unfixed / not-affected / unknown).

    Primary source: ubuntu.com/security/cves JSON API.  Verified live
    against CVE-2024-6387 - the real shape is::

        {"packages": [{"name": "openssh",
                       "statuses": [{"release_codename": "jammy",
                                     "status": "released",
                                     "description": "1:8.9p1-3ubuntu0.10",
                                     "pocket": "security"}, ...]}, ...]}

    i.e. NO 'data' wrapper, keyed by release_codename, with the fixed
    version carried in 'description'.  Statuses 'not-affected'/'DNE' are
    recorded as NOT_AFFECTED so callers can report 'patched' without a
    version comparison; 'needed'/'pending'/'deferred' map to None (the
    release is unfixed - banner matching stays unconfirmed rather than
    silently promoted).  Fallback for a missing 'released' entry:
    Launchpad published versions of the source package (latest candidate).
    Cached per (series, cve).
    """
    cache = _ubuntu_status_cache.setdefault(series, {})
    key = cve_id.upper()
    if key in cache:
        return cache[key]
    s = session or requests.Session()
    fixed: str | None = None
    try:
        r = s.get(_USEC_API.format(cve=key), timeout=timeout, headers=UA)
        if r.ok:
            doc = r.json()
            # tolerate both the raw document and a {'data': ...} wrapper
            if isinstance(doc.get("packages"), list):
                pkgs = doc["packages"]
            else:
                pkgs = (doc.get("data") or {}).get("packages", [])
            for pkg in pkgs:
                if str(pkg.get("name", "")).lower() != package.lower():
                    continue
                best_pocket_rank = -1
                for st in pkg.get("statuses", []):
                    if str(st.get("release_codename", "")).lower() != series.lower():
                        continue
                    state = str(st.get("status", "")).lower()
                    desc = str(st.get("description") or "")
                    if state == "released":
                        m = re.search(r"\d+:\S+-\S+", desc) or \
                            re.search(r"\S+-\S+", desc)
                        cand = m.group(0) if m else ""
                        if not cand:
                            continue
                        pocket_rank = 1 if st.get("pocket") == "security" else 0
                        if pocket_rank >= best_pocket_rank:
                            best_pocket_rank = pocket_rank
                            fixed = cand
                    elif state in ("not-affected", "does-not-exist", "dne"):
                        # only claim not-affected when it is the decisive
                        # status (no released fix found for this release)
                        if fixed is None:
                            fixed = NOT_AFFECTED
            # NOTE: no blind Launchpad fallback inside the loop - an
            # arbitrary "latest published version" would fabricate a
            # fixed-version string for CVEs the tracker marks needed/
            # pending/unfixed, which is exactly the over-reporting this
            # module exists to prevent.
    except (requests.RequestException, ValueError):
        fixed = None
    cache[key] = fixed
    return fixed


def _launchpad_latest(session: requests.Session, src_pkg: str,
                      timeout: int = DEFAULT_TIMEOUT) -> str | None:
    try:
        r = session.get(_LP_API.format(pkg=src_pkg), timeout=timeout,
                        headers=UA)
        if r.ok:
            entries = r.json().get("entries", [])
            if entries:
                return entries[0].get("version")
    except (requests.RequestException, ValueError, IndexError):
        pass
    return None


def dpkg_compare(a: str, op: str, b: str) -> bool | None:
    """dpkg --compare-versions wrapper; None when dpkg is unavailable."""
    dpkg = shutil.which("dpkg")
    if not dpkg:
        return None
    try:
        res = subprocess.run([dpkg, "--compare-versions", a, op, b],
                             capture_output=True, text=True, timeout=10,
                             check=False)
        if res.returncode not in (0, 1):
            return None
        return res.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return None


def validate_ssh_cve(cve_id: str, banner: str,
                     session: requests.Session | None = None,
                     timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Cross-check one banner-derived CVE against Ubuntu's security data.

    Returns {'cve', 'status': patched|vulnerable|unconfirmed,
             'installed', 'fixed', 'release', 'detail'}.
    'patched' means the distro package version already contains the fix
    (compared with dpkg --compare-versions); such CVEs must NOT be
    reported as vulnerabilities.  Anything the lookup can't settle stays
    'unconfirmed, banner-based'.
    """
    out = {"cve": cve_id.upper(), "status": "unconfirmed", "installed": None,
           "fixed": None, "release": None,
           "detail": "Not an Ubuntu distro OpenSSH banner; "
                     "unconfirmed, banner-based."}
    info = parse_openssh_banner(banner)
    if not info:
        return out
    installed = normalize_package_version(info)
    out["installed"], out["release"] = installed, str(info["series"])
    fixed = get_ubuntu_cve_status(cve_id, str(info["series"]), session=session,
                                  timeout=timeout)
    out["fixed"] = None if fixed == NOT_AFFECTED else fixed
    if fixed == NOT_AFFECTED:
        out["status"] = "patched"
        out["detail"] = (f"Ubuntu security data marks {info['series']} as "
                         "not-affected for this CVE - not vulnerable.")
        return out
    if fixed is None:
        out["detail"] = ("Ubuntu tracker/Launchpad unreachable or CVE not "
                         "listed as fixed for this release - unconfirmed, "
                         "banner-based.")
        return out
    if not installed:
        out["detail"] = ("Banner carries no Debian revision tail; cannot "
                         "compare versions - unconfirmed, banner-based.")
        return out
    older = dpkg_compare(installed, "lt", fixed)
    if older is None:
        out["detail"] = (f"dpkg unavailable; cannot compare {installed} vs "
                         f"fixed {fixed} - unconfirmed, banner-based.")
        return out
    if older:
        out["status"] = "vulnerable"
        out["detail"] = (f"Installed {installed} < fixed {fixed} per Ubuntu "
                         f"security data ({info['series']}).")
    else:
        out["status"] = "patched"
        out["detail"] = (f"Installed {installed} >= fixed {fixed} per Ubuntu "
                         f"security data ({info['series']}) - distro "
                         "backport already applied; not vulnerable.")
    return out


def group_cves_by_release(findings: list[dict], banner: str) -> dict[str, list[dict]]:
    """Group CVE findings under the release their banner implies, so the
    report states which Ubuntu series the validation ran against."""
    release = ubuntu_release_for_banner(banner) or "unknown"
    grouped: dict[str, list[dict]] = {}
    for f in findings:
        if f.get("cve"):
            grouped.setdefault(release, []).append(f)
    return grouped


def apply_validations(findings: list[dict], banner: str,
                      session: requests.Session | None = None) -> dict:
    """Run validate_ssh_cve() over every CVE finding from one SSH banner.

    Marks each finding with 'ubuntu_validation'; patched CVEs get
    confidence='patched (not vulnerable)', severity='info' and are moved
    to the returned 'patched' list so scanners can exclude them from the
    vulnerability count.  Returns {'vulnerable', 'patched', 'unconfirmed'}
    lists of findings.
    """
    buckets: dict[str, list[dict]] = {"vulnerable": [], "patched": [],
                                      "unconfirmed": []}
    for f in findings:
        if not f.get("cve"):
            continue
        v = validate_ssh_cve(f["cve"], banner, session=session)
        f["ubuntu_validation"] = v
        if v["status"] == "patched":
            f["confidence"] = "patched (not vulnerable)"
            f["confirmed"] = False
            f["severity"] = "info"
            f["severity_downgrade_reason"] = v["detail"]
            buckets["patched"].append(f)
        else:
            f["confirmed"] = False
            # Re-derive the surface tag BEFORE demoting so client/config
            # CVEs get both caps applied.
            if not f.get("cve_surface"):
                try:
                    from scoring import cve_context as _ctx
                except ImportError:
                    _ctx = None
                if _ctx:
                    surf, note = _ctx(f["cve"])
                    if surf:
                        f["cve_surface"] = surf
                    if note and not f.get("cve_note"):
                        f["cve_note"] = note
            vstat = v["status"]
            if vstat == "vulnerable":
                f["confidence"] = "likely (Ubuntu tracker confirms unfixed)"
                # Vendor-confirmed unfixed: keep the CVSS severity for
                # server-surface CVEs, but client/config/protocol-surface
                # flaws are never direct server risk - cap at medium.
                if f.get("cve_surface") not in (None, "server"):
                    from findings import SEVERITY_ORDER
                    if SEVERITY_ORDER.get(str(f.get("severity", "")).lower(), 0) \
                            > SEVERITY_ORDER["medium"]:
                        f["severity"] = "medium"
                        f["severity_downgrade_reason"] = (
                            f"CVE is {f['cve_surface']}-surface, not a "
                            "directly exploitable server flaw")
                buckets["vulnerable"].append(f)
            else:
                f["confidence"] = "unconfirmed (banner-based)"
                adjust_severity(f)
                buckets["unconfirmed"].append(f)
    return buckets
