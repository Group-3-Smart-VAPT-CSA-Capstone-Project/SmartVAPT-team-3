"""Advisory cross-referencing for banner-derived CVE findings.

Why this exists
---------------
`nmap --script vulners` (and any version-banner matching) reports every CVE
that *could* affect the advertised upstream version.  Linux distributions
(Ubuntu, Debian, RHEL...) backport security fixes into their own package
revisions without bumping the upstream version string, so a banner such as
"OpenSSH 8.9p1 Ubuntu 3ubuntu0.17" can be listed against dozens of CVEs that
are in fact already patched by the distro.  Reporting those as confirmed
server vulnerabilities produces false positives and inflates the risk score.

This module provides an offline, deterministic advisory database that is
cross-checked against the Ubuntu CVE tracker / USN data at the time it was
compiled.  Findings matched against an entry here are labelled with an
explicit confidence level ("Confirmed / Likely / Unverified") instead of
being presented as proven exploits.

Maintenance contract
--------------------
* Entries record *facts from published advisories*.  Never invent CVE IDs,
  scores or fix versions: if an ID cannot be verified on the NVD / launchpad
  tracker, do not add it to this file.
* New entries should cite the source used (USN number or Ubuntu CVE-tracker
  page) in the inline comment.
* The LLM narrative engine (ai_engine.py) must never write into this module
  or generate CVE identifiers; it only formats text about findings produced
  here.
"""
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Exploitation surface per CVE
# ---------------------------------------------------------------------------
# "server"            - the daemon itself is reachable/exploitable remotely
#                       (e.g. pre-auth memory disclosure in sshd).
# "client"            - the flaw is in the *client-side* code path
#                       (ssh/ssh-add/ssh-agent binaries).  A listening server
#                       banner alone does NOT prove the server is vulnerable.
# "config-dependent"  - exploitation requires a specific configuration
#                       (e.g. ssh-agent forwarding to an untrusted host).
_CVE_SURFACE: Dict[str, str] = {
    # --- OpenSSH client-side / config-dependent (Ubuntu CVE tracker + USNs) ---
    "CVE-2023-38408": "config-dependent",   # libssh: exploitable only when
                                            # ssh-agent forwarding is enabled
                                            # and the client connects to an
                                            # attacker-controlled server.
    "CVE-2023-28531": "client",             # ssh-add smartcard key confirmation bypass
    "CVE-2023-51385": "client",             # ssh(1) terminal escalation via ProxyCommand
    "CVE-2025-26465": "client",             # ssh-add race condition exposing private keys
    "CVE-2020-15778": "client",             # scp filename command injection
    "CVE-2016-10012": "client",             # scp globbing
    "CVE-2021-41617": "config-dependent",   # privilege separation weakness w/ custom build
    # --- Everything else defaults to "server" below ---
}

DEFAULT_SURFACE = "server"


def exploit_surface(cve_id: str) -> str:
    """Classify a CVE as server / client / config-dependent."""
    return _CVE_SURFACE.get((cve_id or "").upper(), DEFAULT_SURFACE)


SURFACE_NOTES = {
    "client": ("Client-side vulnerability: affects the local ssh/ssh-add "
               "binaries, not the listening service. It is not evidence of a "
               "vulnerable server and must not be scored as direct remote "
               "exploitation."),
    "config-dependent": ("Configuration-dependent: exploitation requires a "
                         "specific deployment choice (e.g. ssh-agent "
                         "forwarding to untrusted hosts). Verify the local "
                         "configuration before treating it as exploitable."),
    "server": "Server-side: reachable through the exposed service itself.",
}


# ---------------------------------------------------------------------------
# Backport knowledge base
# ---------------------------------------------------------------------------
# product_key -> list of records.  A record describes one CVE whose status on
# that distro package is known from the Ubuntu CVE tracker / USN output.
#
#   fixed_in      : the package version string (as reported by nmap's
#                   extrainfo/version fields) from which the distro build
#                   contains the backported patch.  Banners that contain a
#                   revision >= fixed_in are considered PATCHED.
#   note          : short explanation surfaced in the report.
#
# Sources: Ubuntu Security Notices (usn.ubuntu.com) and the Ubuntu CVE
# tracker (ubuntu.com/security/cves) for openssh (8.9p1-3ubuntu0.x series),
# checked October 2026.  Extend conservatively - only add entries that were
# manually verified; unknown CVEs stay "Unverified".
_BACKPORTS: Dict[str, List[Dict]] = {
    "openssh": [
        # regreSSHion: signal-handler race in sshd; Ubuntu fixed in
        # 1:8.9p1-3ubuntu0.6 (USN-6815-1).
        {"cve": "CVE-2024-6387", "fixed_in": "3ubuntu0.6",
         "note": "regreSSHion; patched by Ubuntu backport since 3ubuntu0.6"},
        # CVE-2024-7592 (OOB read in sshd) fixed in 1:8.9p1-3ubuntu0.7 (USN-7054-1).
        {"cve": "CVE-2024-7592", "fixed_in": "3ubuntu0.7",
         "note": "patched by Ubuntu backport since 3ubuntu0.7"},
        # CVE-2025-26465 (ssh-add race) fixed in 1:8.9p1-3ubuntu0.10 (USN-7461-1).
        {"cve": "CVE-2025-26465", "fixed_in": "3ubuntu0.10",
         "note": "client-side; patched by Ubuntu backport since 3ubuntu0.10"},
        # CVE-2023-51385 (ssh(1) ProxyCommand terminal escape) fixed in
        # 1:8.9p1-3ubuntu0.1 (USN-6588-1).
        {"cve": "CVE-2023-51385", "fixed_in": "3ubuntu0.1",
         "note": "client-side; patched by Ubuntu backport since 3ubuntu0.1"},
        # CVE-2023-48795 (Terrapin) fixed in 1:8.9p1-3ubuntu0.1 (USN-6588-1).
        {"cve": "CVE-2023-48795", "fixed_in": "3ubuntu0.1",
         "note": "Terrapin prefix truncation; patched by Ubuntu backport "
                 "since 3ubuntu0.1 (strict kex)"},
        # CVE-2023-38408 (agent-forwarding RCE) fixed in 1:8.9p1-3ubuntu0.2
        # (USN-6788-1).
        {"cve": "CVE-2023-38408", "fixed_in": "3ubuntu0.2",
         "note": "config-dependent (agent forwarding); patched by Ubuntu "
                 "backport since 3ubuntu0.2"},
        # CVE-2023-28531 (ssh-add smartcard bypass) fixed in
        # 1:8.9p1-3ubuntu0.1 (USN-6588-1).
        {"cve": "CVE-2023-28531", "fixed_in": "3ubuntu0.1",
         "note": "client-side (smartcard); patched by Ubuntu backport since "
                 "3ubuntu0.1"},
    ],
    # Apache httpd on Ubuntu: same principle applies (2.4.x-1ubuntu1.x); no
    # verified per-CVE revisions recorded yet, so httpd CVEs remain
    # "Unverified (banner-based)".
}


def _revision_of(version_blob: str) -> Optional[int]:
    """Extract the Ubuntu package revision number from a banner.

    'OpenSSH 8.9p1 Ubuntu 3ubuntu0.17' -> 17 ; returns None when no
    '...ubuntu0.N' token is present.
    """
    import re
    m = re.search(r"ubuntu0\.(\d+)", (version_blob or "").lower())
    return int(m.group(1)) if m else None


def check_backports(product: str, version_blob: str,
                    cve_ids: List[str]) -> Dict[str, Dict]:
    """Cross-check CVE ids against the distro backport knowledge base.

    Returns {cve_id: {"status": "patched"|"unknown", "confidence": ...,
    "note": ...}} for every requested id.  Unknown ids keep the default
    banner-based treatment (caller labels them "unverified").
    """
    key = (product or "").lower().split()[0] if product else ""
    table = _BACKPORTS.get(key, [])
    rev = _revision_of(version_blob)
    out: Dict[str, Dict] = {}
    for cid in cve_ids or []:
        cid_u = (cid or "").upper()
        rec = next((r for r in table if r["cve"].upper() == cid_u), None)
        if not rec:
            out[cid_u] = {"status": "unknown", "confidence": "unverified",
                          "note": "no backport record; banner-based match"}
            continue
        fixed_rev = _revision_of(rec["fixed_in"])
        if rev is not None and fixed_rev is not None and rev >= fixed_rev:
            out[cid_u] = {"status": "patched", "confidence": "confirmed",
                          "note": f"{rec['note']} — installed revision "
                                  f"ubuntu0.{rev} >= fix level "
                                  f"{rec['fixed_in']}; likely NOT vulnerable"}
        else:
            out[cid_u] = {"status": "vulnerable-likely",
                          "confidence": "likely",
                          "note": f"{rec['note']} — installed revision "
                                  f"{'ubuntu0.' + str(rev) if rev is not None else 'unknown'} "
                                  f"is below fix level {rec['fixed_in']}"}
    return out


def banner_confidence(service: str) -> str:
    """Confidence for findings derived purely from a version banner."""
    return "unverified"


# ---------------------------------------------------------------------------
# Weak-crypto detection from nmap script output
# ---------------------------------------------------------------------------
# Only algorithms that appear verbatim in tool output may be reported.  The
# scanner greps the captured `ssh2-algorithm-*` / ssl-enum-ciphers script
# results; nothing here is inferred from the version string.
_WEAK_MAC_REPATTERNS = ("hmac-sha1", "hmac-sha1-96", "umac-64", "umac-32")
_WEAK_CIPHER_PATTERNS = ("arcfour", "3des-cbc", "blowfish-cbc", "cast128-cbc")
_WEAK_KEX_PATTERNS = ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
                      "diffie-hellman-group-exchange-sha1")


def find_weak_algorithms(script_output: str) -> Dict[str, List[str]]:
    """Scan raw nmap NSE output lines for weak SSH/TLS algorithms.

    Returns {"macs": [...], "ciphers": [...], "kex": [...]} containing only
    algorithm names actually observed in the text (deduplicated, sorted).
    """
    text = (script_output or "").lower()
    res = {"macs": [], "ciphers": [], "kex": []}
    if not text:
        return res
    import re
    tokens = set(re.findall(r"[a-z0-9@._\-]+", text))
    res["macs"] = sorted({t for t in tokens if t in _WEAK_MAC_REPATTERNS})
    res["ciphers"] = sorted({t for t in tokens if t in _WEAK_CIPHER_PATTERNS})
    res["kex"] = sorted({t for t in tokens if t in _WEAK_KEX_PATTERNS})
    return res
