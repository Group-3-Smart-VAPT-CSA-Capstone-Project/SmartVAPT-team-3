"""command_tracker.py — registry of background commands for the live scan output.

Every external tool the scanners launch (nmap, gobuster, nuclei, subfinder, …)
is announced here via ``run_logged()`` before it executes: the exact command
line, the human-readable description ("nmap running on scanme.nmap.org"), and
the Popen handle are recorded.  The Streamlit UI renders this registry as a
"Background commands" panel in the live scan output section so the operator
can see *what is actually running* at any moment, with elapsed time and
liveness (running / finished / stopped).

The registry is process-global and thread-safe because scanners run in the
same process (and the web audit runs in a worker thread).
"""
from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from typing import Callable, Dict, List, Optional


class CommandTracker:
    def __init__(self, max_entries: int = 50):
        self._lock = threading.Lock()
        self._entries: List[Dict] = []
        self._max = max_entries

    # ------------------------------------------------------------------ record
    def start(self, cmd: list, desc: str, proc: Optional[subprocess.Popen] = None) -> Dict:
        """Register a launched command. Returns the entry dict."""
        entry = {
            "cmd": [str(c) for c in cmd],
            "desc": desc,
            "start": time.time(),
            "end": None,
            "rc": None,
            "proc": proc,
        }
        with self._lock:
            self._entries.append(entry)
            if len(self._entries) > self._max:
                del self._entries[: len(self._entries) - self._max]
        return entry

    def finish(self, entry: Dict, rc=None):
        entry["end"] = time.time()
        entry["rc"] = rc

    # ------------------------------------------------------------------- query
    def snapshot(self) -> List[Dict]:
        """Copy of all entries with liveness resolved (safe for UI rendering)."""
        now = time.time()
        out = []
        with self._lock:
            for e in list(self._entries):
                rc = e["rc"]
                alive = False
                if e["proc"] is not None:
                    p = e["proc"].poll()
                    if p is not None:
                        alive = False
                        if rc is None:
                            rc = p
                            e["rc"] = p
                        if e["end"] is None:
                            e["end"] = now
                    else:
                        alive = True
                elif e["end"] is None:
                    # No handle (blocking subprocess.run style): still running
                    # until the caller marks it finished.
                    alive = True
                end = e["end"] if e["end"] is not None else now
                out.append({
                    "cmd": " ".join(e["cmd"]),
                    "desc": e["desc"],
                    "elapsed": round(end - e["start"], 1),
                    "state": "running" if alive else
                             ("done" if rc == 0 else f"exit {rc}"),
                    "running": alive,
                })
        return out


# Process-global registry used by all scanners + the UI.
tracker = CommandTracker()


def describe(cmd: list) -> str:
    """Human summary like 'nmap running on scanme.nmap.org' /
    'gobuster dir brute-force on https://example.com'."""
    if not cmd:
        return "command"
    tool = os.path.basename(str(cmd[0]))
    rest = [str(a) for a in cmd[1:]]
    # Flags that consume the following token as their value (never a target).
    value_flags = {"-oX", "-oN", "-oG", "-p", "-P", "--top-ports", "-T",
                   "-t", "-w", "-rl", "-timeout", "-H", "-c", "-e", "-iL"}

    def looks_like_target(tok: str) -> bool:
        t = tok.lower()
        if t.startswith(("http://", "https://")):
            return True
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", t):          # IPv4
            return True
        if "%" in t or "/" in t:                             # CIDR / path
            return True
        if "." in t and not t.startswith("-"):               # hostname/domain
            return True
        return False

    target = ""
    for i, a in enumerate(rest):
        if a in value_flags:
            continue
        if i > 0 and rest[i - 1] in value_flags:
            continue                                          # it's a flag value
        if a.startswith("-"):
            continue
        if looks_like_target(a):
            target = a
            break
    mode = ""
    if tool == "gobuster" and "dir" in rest:
        mode = "dir brute-force "
    elif tool == "nmap":
        mode = "port/vuln scan "
    if target:
        return f"{tool} {mode}running on {target}".replace("  ", " ")
    return f"{tool} {mode.strip()} running".strip()


def run_logged(cmd: list, *, desc: str = None,
               stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
               text: bool = True, bufsize: int = 1,
               popen: bool = True, timeout: Optional[float] = None,
               **kwargs):
    """Launch *cmd* through subprocess and announce it in the tracker.

    popen=True  -> returns the Popen object (entry closed when the caller
                   polls/finishes it; snapshot() auto-detects exit codes).
    popen=False -> blocking subprocess.run; entry marked finished on return
                   (or on timeout/nonzero exit).
    """
    d = desc or describe(cmd)
    if popen:
        proc = subprocess.Popen(cmd, stdout=stdout, stderr=stderr,
                                text=text, bufsize=bufsize, **kwargs)
        tracker.start(cmd, d, proc)
        return proc
    try:
        res = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout, **kwargs)
        tracker.finish(tracker.start(cmd, d, None), rc=res.returncode)
        return res
    except subprocess.TimeoutExpired as e:
        tracker.finish(tracker.start(cmd, d, None), rc="timeout")
        raise
    except OSError as e:
        tracker.finish(tracker.start(cmd, d, None), rc=str(e))
        raise
