"""IP geolocation & hosting-provider lookup for SmartVAPT.

Resolves the target to its IP address(es) and looks up where that IP is
physically located and which hosting provider / data centre the website is
set up on (ISP + organization). This gives assessors quick context about
hosting jurisdiction and provider before writing the report.

Data sources (free, no API key required):
  * ip-api.com   — primary: country/region/city, lat/lon, ASN, ISP, org
  * ipwho.is     — fallback with the same field names

Private / loopback addresses are detected locally and never sent to an
external service. All network calls fail gracefully (the returned dict just
carries an ``error`` key) so a scan never breaks because geolocation is
unreachable.
"""
import ipaddress
import re
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

# Public lookups: local DNS resolution first, then these JSON APIs.
_IPAPI_URL = "http://ip-api.com/line/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,query"
_IPOOIS_URL = "https://ipwho.is/{ip}"

_DEFAULT_TIMEOUT = 8


def extract_host(target: str) -> str:
    """Pull the bare hostname/IP out of 'http://host:port/path' style input."""
    t = (target or "").strip()
    if not t:
        return ""
    if "//" not in t:
        t = "//" + t          # so urlparse handles host:port without scheme
    p = urlparse(t)
    host = (p.hostname or "").strip().lower()
    if not host:              # bare IPv6 like '::1' parses oddly; fall back
        host = t.lstrip("/").split("/")[0].split(":")[0]
    return host


def resolve_ips(host: str) -> List[str]:
    """Resolve a hostname to every IPv4/IPv6 address it points at.

    If the target is already an IP literal it is returned as-is.
    """
    host = extract_host(host)
    if not host:
        return []
    try:                                    # already an IP literal?
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    ips: List[str] = []
    try:
        for info in socket.getaddrinfo(host, None):
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    return ips


def _is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (a.is_private or a.is_loopback or a.is_link_local
            or a.is_multicast or a.is_reserved)


def _fetch_ipapi(ip: str, timeout: int) -> Optional[Dict[str, Any]]:
    """ip-api.com line endpoint — returns dict or None on failure."""
    try:
        r = requests.get(_IPAPI_URL.format(ip=ip), timeout=timeout)
        if r.status_code != 200:
            return None
        parts = r.text.strip().split(";")
        if len(parts) < 3 or parts[0].lower() != "success":
            return None
        keys = ["status", "message", "country", "countryCode", "region",
                "regionName", "city", "zip", "lat", "lon", "timezone",
                "isp", "org", "as", "asname", "reverse", "query"]
        d = dict(zip(keys, parts))
        if d.get("status", "").lower() != "success":
            return None
        return {
            "source": "ip-api.com",
            "ip": d.get("query", ip),
            "country": d.get("country", ""),
            "country_code": d.get("countryCode", ""),
            "region": d.get("regionName", ""),
            "city": d.get("city", ""),
            "postal_code": d.get("zip", ""),
            "latitude": d.get("lat", ""),
            "longitude": d.get("lon", ""),
            "timezone": d.get("timezone", ""),
            "isp": d.get("isp", ""),
            "organization": d.get("org", "") or d.get("isp", ""),
            "asn": d.get("as", ""),
            "reverse_dns": d.get("reverse", ""),
        }
    except Exception:
        return None


def _fetch_ipwhois(ip: str, timeout: int) -> Optional[Dict[str, Any]]:
    """ipwho.is JSON fallback — returns dict or None on failure."""
    try:
        r = requests.get(_IPOOIS_URL.format(ip=ip), timeout=timeout)
        if r.status_code != 200:
            return None
        j = r.json()
        if not isinstance(j, dict) or j.get("success") is False:
            return None
        conn = j.get("connection") or {}
        return {
            "source": "ipwho.is",
            "ip": j.get("ip", ip),
            "country": j.get("country", ""),
            "country_code": j.get("country_code", ""),
            "region": j.get("region", ""),
            "city": j.get("city", ""),
            "postal_code": j.get("postal", ""),
            "latitude": j.get("latitude", ""),
            "longitude": j.get("longitude", ""),
            "timezone": (j.get("timezone") or {}).get("id", ""),
            "isp": conn.get("isp", ""),
            "organization": conn.get("org", "") or conn.get("isp", ""),
            "asn": f"AS{conn.get('asn')}" if conn.get("asn") else "",
            "reverse_dns": j.get("connection", {}).get("domain", "") or "",
        }
    except Exception:
        return None


def geolocate_ip(ip: str, timeout: int = _DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """Look up one IP's location + hosting provider. Never raises."""
    result: Dict[str, Any] = {"ip": ip, "found": False}
    if not ip:
        result["error"] = "No IP provided."
        return result
    if _is_private(ip):
        result["private"] = True
        result["note"] = ("Private/reserved address — geolocation skipped "
                          "(not sent to external services).")
        return result
    for fetcher in (_fetch_ipapi, _fetch_ipwhois):
        data = fetcher(ip, timeout)
        if data:
            result.update(data)
            result["found"] = True
            return result
    result["error"] = "Geolocation services unreachable (offline or blocked)."
    return result


def hosting_summary(info: Dict[str, Any]) -> str:
    """One-line human summary: city, region, country · ISP / Org (ASN)."""
    if not info or not info.get("found"):
        return info.get("note") or info.get("error") or "Unknown"
    loc = ", ".join(x for x in (info.get("city"), info.get("region"),
                                info.get("country")) if x)
    prov = info.get("organization") or info.get("isp") or ""
    asn = info.get("asn") or ""
    parts = [loc or "Location unknown"]
    if prov:
        parts.append(f"{prov} ({asn})" if asn else prov)
    return " · ".join(parts)


class GeoLocator:
    """Locate a scan target's IP(s) and identify where the website is hosted."""

    def __init__(self, target: str, evidence=None, timeout: int = _DEFAULT_TIMEOUT):
        self.target = target
        self.evidence = evidence
        self.timeout = timeout

    def locate(self) -> Dict[str, Any]:
        """Resolve the target host to IPs and geolocate each one.

        Returns::

            {
              "target": original target string,
              "hostname": extracted host,
              "resolved_ips": [...],
              "locations": [ {geolocation dict per IP}, ... ],
              "primary": {geolocation dict of first resolved IP},
              "summary": "Mumbai, Maharashtra, India · AS16509 Amazon.com Inc.",
              "web_server": {"port": 443, "url": "https://..."} | {},
            }
        """
        host = extract_host(self.target)
        out: Dict[str, Any] = {"target": self.target, "hostname": host,
                               "resolved_ips": [], "locations": [],
                               "primary": {}, "summary": "",
                               "web_server": {}}
        if not host:
            out["error"] = "Could not parse a hostname from the target."
            return out

        ips = resolve_ips(host)
        out["resolved_ips"] = ips
        for ip in ips:
            info = geolocate_ip(ip, timeout=self.timeout)
            out["locations"].append(info)
            if not out["primary"].get("found") and info.get("found"):
                out["primary"] = info
        if not ips:
            out["error"] = f"DNS resolution failed for '{host}'."

        # Where the website itself is set up: the HTTP/HTTPS endpoint and
        # the port it answers on (well-known defaults when not specified).
        out["web_server"] = self._web_server_info(host)

        out["summary"] = (hosting_summary(out["primary"])
                          if out["primary"] else
                          out.get("error", "Location unavailable"))

        if self.evidence:
            try:
                self.evidence.save_json("geolocation", out)
            except Exception:
                pass      # evidence store must never break the scan
        return out

    def _web_server_info(self, host: str) -> Dict[str, Any]:
        """Describe the web endpoint of the target (scheme/port/server)."""
        t = (self.target or "").strip()
        scheme = "https" if t.startswith("https://") else \
                 "http" if t.startswith("http://") else ""
        port = None
        m = re.search(r"://[^/:]+:(\d+)", t)
        if m:
            port = int(m.group(1))
        elif scheme == "":
            # Bare host: probe http first, then https, to find where the
            # site is actually served.
            for cand_scheme in ("https", "http"):
                url = f"{cand_scheme}://{host}"
                try:
                    r = requests.get(url, timeout=min(self.timeout, 5),
                                     allow_redirects=True,
                                     headers={"User-Agent": "Mozilla/5.0"})
                    if r.ok or r.is_redirect:
                        scheme = cand_scheme
                        port = 443 if cand_scheme == "https" else 80
                        server = r.headers.get("Server", "")
                        return {"url": url, "port": port,
                                "status": r.status_code,
                                "server": server,
                                "final_url": r.url}
                except Exception:
                    continue
            return {"url": f"http://{host}", "port": 80, "status": None,
                    "server": "", "final_url": ""}
        if port is None:
            port = 443 if scheme == "https" else 80
        server = ""
        final_url = f"{scheme}://{host}"
        try:
            r = requests.head(final_url, timeout=min(self.timeout, 5),
                              allow_redirects=True,
                              headers={"User-Agent": "Mozilla/5.0"})
            server = r.headers.get("Server", "")
            final_url = r.url
        except Exception:
            pass
        return {"url": final_url, "port": port, "status": None,
                "server": server, "final_url": final_url}


if __name__ == "__main__":      # quick CLI: python geo_locator.py <target>
    import json
    import sys
    tgt = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    print(json.dumps(GeoLocator(tgt).locate(), indent=2))
