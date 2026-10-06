"""Nmap port-set helpers: Top 100 / 1000 / 10000 and custom range parsing.

Used by the UI, the headless driver and the network scanner so that every
entry point understands the same port selection syntax:

    "top100" / "top-100" / "Top 100"   -> nmap's Top 100 ports
    "top1000" / "top-1000"             -> nmap's Top 1000 ports
    "80,443,8000-9000"                 -> literal port list / ranges
"""
import re

PORT_SETS = {
    "top100": {"label": "Nmap Top 100 ports", "spec": "--top-ports 100"},
    "top1000": {"label": "Top 1000 most-used ports of all 65535",
                "spec": "--top-ports 1000"},
    "top10000": {"label": "Nmap Top 10000 ports (slow)", "spec": "--top-ports 10000"},
    # Literal full low range, kept as an explicit preset so the UI/driver
    # never hardcodes it inside the scanner.
    "1-1000": {"label": "Ports 1-1000 (full low range)", "spec": "-p 1-1000"},
}

DEFAULT_PORT_SET = "top1000"

_RANGE_RE = re.compile(r"^(\d{1,5})\s*-\s*(\d{1,5})$")


def normalize_ports(value: str) -> str:
    """Map a user-supplied port selection to a canonical key or spec string.

    Returns one of the PORT_SETS keys ("top100"/"top1000"/"top10000"), a
    sanitized literal port spec ("80,443,8000-9000"), or "" when *value* is
    not recognised (callers should fall back to DEFAULT_PORT_SET).
    """
    if value is None:
        return ""
    v = str(value).strip().lower().replace(" ", "")
    v = v.replace("nmap", "").lstrip("-")
    m = re.match(r"^top(\d+)$", v)
    if m:
        key = f"top{m.group(1)}"
        return key if key in PORT_SETS else ""
    # Literal port list: numbers, commas, dashes (ranges), optional /proto
    if re.match(r"^[0-9,\-\/\w]+$", v) and any(ch.isdigit() for ch in v):
        parts = []
        for tok in str(value).strip().split(","):
            tok = tok.strip()
            if not tok:
                continue
            if _RANGE_RE.match(tok):
                lo, hi = (int(x) for x in _RANGE_RE.match(tok).groups())
                if 1 <= lo <= hi <= 65535:
                    parts.append(f"{lo}-{hi}")
                continue
            if tok.isdigit() and 1 <= int(tok) <= 65535:
                parts.append(str(int(tok)))
        return ",".join(parts)
    return ""


def resolve_ports(value: str) -> str:
    """Like normalize_ports but never returns empty — falls back to default."""
    return normalize_ports(value) or DEFAULT_PORT_SET


def port_set_nargs(spec: str) -> int:
    """Number of trailing argv tokens an nmap port argument consumes.

    "--top-ports 1000" -> 1 ; "-p 80,443" -> 1 ; bare target -> 0.
    """
    toks = spec.split()
    if not toks:
        return 0
    if toks[0] in ("--top-ports", "-p", "--port-ratio"):
        return 1
    return 0


def port_arg_tokens(value: str) -> list:
    """Translate a normalized port selection into nmap CLI tokens.

    "top100"/"top1000"/"top10000" -> ["--top-ports", "N"]
    literal range/list ("1-1000", "80,443") -> ["-p", "<spec>"]
    """
    norm = resolve_ports(value)
    if norm in PORT_SETS:
        spec = PORT_SETS[norm]["spec"].split()
        # Presets like "top1000" -> ["--top-ports", "1000"]; literal-range
        # presets like "1-1000" already carry their own "-p <spec>" tokens,
        # so use them verbatim instead of mis-rendering "--top-ports 1-1000".
        if spec and spec[0] == "--top-ports" and norm.startswith("top"):
            return [spec[0], norm.replace("top", "")]
        return spec
    return ["-p", norm]


def describe_ports(value: str) -> str:
    """Human-readable description used in the UI/report."""
    norm = resolve_ports(value)
    if norm in PORT_SETS:
        return PORT_SETS[norm]["label"]
    return f"Custom range: {norm}"


# Common HTTP(S)-speaking ports probed when nmap -sV data is unavailable.
COMMON_HTTP_PORTS = (80, 443, 8000, 8080, 8443, 8888, 3000, 5000,
                     9000, 9443, 10000)


def probe_http_ports(host: str, ports=COMMON_HTTP_PORTS,
                     timeout: float = 2.0) -> list:
    """Lightweight stand-in for `nmap -sV` HTTP discovery.

    Connects to each candidate port and sends a tiny HEAD request; returns
    the same dict shape as network_scanner.find_http_services so gobuster /
    nuclei can target the confirmed HTTP port even when the full network
    scan was skipped or failed.
    """
    import socket

    def _entry(port, scheme):
        default_port = 443 if scheme == "https" else 80
        url = f"{scheme}://{host}" + ("" if port == default_port else f":{port}")
        return {"host": host, "hostname": host, "port": port,
                "protocol": "tcp", "service": scheme, "product": None,
                "version": None, "tunnel": "ssl" if scheme == "https" else "",
                "url": url, "ssl": scheme == "https"}

    out = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                pass
        except OSError:
            continue
        # Port open — decide http vs https with a quick TLS handshake.
        scheme = "http"
        try:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as s, \
                    ctx.wrap_socket(s, server_hostname=host):
                scheme = "https"
        except Exception:
            scheme = "http"
        # Confirm it actually speaks HTTP with a minimal HEAD request.
        try:
            req = (f"HEAD / HTTP/1.0\r\nHost: {host}\r\n"
                   f"User-Agent: SmartVAPT-probe\r\n\r\n").encode()
            with socket.create_connection((host, port), timeout=timeout) as s:
                if scheme == "https":
                    import ssl as _ssl
                    ctx = _ssl._create_unverified_context()
                    s = ctx.wrap_socket(s, server_hostname=host)
                s.sendall(req)
                banner = s.recv(64)
            if banner.startswith(b"HTTP/"):
                out.append(_entry(port, scheme))
        except OSError:
            continue
    return out
