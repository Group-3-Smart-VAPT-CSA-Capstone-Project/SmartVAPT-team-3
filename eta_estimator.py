"""eta_estimator.py — scan-time estimation for the SmartVAPT loading page.

Gives the operator a realistic "this scan will take about X minutes" figure
*before* the first step runs, then refines it live:

  * ``static_estimate``     – conservative per-vector estimates (seconds),
                              scaled by the port-selection preset. These are
                              worst-case planning numbers based on the tool's
                              own timeouts (e.g. nmap is capped at 10 min in
                              network_scanner._scan_streaming).
  * ``record_duration``     – every scanner step reports how long it actually
                              took; durations persist across scans in
                              ``eta_history.json`` so later estimates use the
                              observed average for this machine/network when
                              there is enough history, and fall back to the
                              static estimate otherwise.
  * ``ScanEta.remaining()`` – combines per-step estimates with what has been
                              measured so far (observed steps count as their
                              real duration; the running step counts its
                              elapsed time only once it exceeds the estimate)
                              into an ETA string like
                              ``~4m 35s remaining • started 12s ago``.

The history file is best-effort: if it cannot be read/written the estimator
silently degrades to static-only estimates.
"""
from __future__ import annotations

import json
import os
import time

HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "eta_history.json")
MIN_SAMPLES = 2          # observed averages need >= 2 samples to be trusted
RECENT_SAMPLES = 10      # rolling window of recent durations used


# --------------------------------------------------------------- formatting
def fmt_eta(seconds: float | None) -> str:
    """Human-readable duration: '45s', '3m 20s', '1h 05m'."""
    if seconds is None:
        return "unknown"
    s = max(0, int(round(seconds)))
    if s < 60:
        return f"{s}s"
    m, r = divmod(s, 60)
    if m < 60:
        return f"{m}m {r:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h {m:02d}m"


def _scale_for_ports(ports: str) -> float:
    p = (ports or "").strip().lower()
    if p in ("top100", "top-100"):
        return 0.5
    if p in ("top1000", "top-1000"):
        return 1.0
    if "," in p:                       # explicit list: scale by count vs 1000
        try:
            n = sum(len(str(x).split("-")) for x in p.split(","))
            return max(0.4, min(2.0, n / 1000.0 + 0.3))
        except Exception:
            return 1.0
    try:                               # literal range e.g. '1-1000', '22'
        lo, hi = (p.split("-") + [p])[:2]
        span = abs(int(hi) - int(lo)) + 1
        return max(0.4, min(2.0, span / 1000.0 + 0.3))
    except ValueError:
        return 1.0


# ------------------------------------------------------------------ history
class _History:
    """Rolling store of observed per-step durations (plain JSON file)."""

    def __init__(self, path: str = HISTORY_FILE):
        self.path = path
        self.data: dict[str, list[float]] = {}
        self.load()

    def load(self):
        try:
            with open(self.path) as fh:
                raw = json.load(fh)
            self.data = {k: [float(x) for x in v][-RECENT_SAMPLES:]
                         for k, v in raw.items()}
        except Exception:
            self.data = {}

    def record(self, key: str, seconds: float):
        self.data.setdefault(key, []).append(max(0.0, float(seconds)))
        self.data[key] = self.data[key][-RECENT_SAMPLES:]
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(self.data, fh)
            os.replace(tmp, self.path)
        except Exception:
            pass                      # persistence is best-effort

    def average(self, key: str) -> float | None:
        vals = self.data.get(key) or []
        if len(vals) < MIN_SAMPLES:
            return None               # not enough evidence yet
        return sum(vals) / len(vals)


# ---------------------------------------------------------------- estimator
class ScanEta:
    """Tracks planned steps + live progress and renders an ETA line."""

    def __init__(self, target: str, enabled: dict[str, bool],
                 ports: str = "top1000", history_file: str = HISTORY_FILE):
        self.target = target
        self.ports_scale = _scale_for_ports(ports)
        self.history = _History(history_file)
        self.steps: list[dict] = []
        self.started = time.time()

        # name -> (static worst-case seconds, history key suffix)
        vectors = [
            ("Network scan (Nmap)",   600.0, "network", True),
            ("Web application audit", 180.0, "web",     True),
            ("DNS / email security",   20.0, "dns",     True),
            ("Nuclei templates",      180.0, "nuclei",  True),
            ("Subdomain enumeration", 240.0, "sub",     False),
            ("API security checks",    90.0, "api",     False),
            ("AI analysis + report",   45.0, "report",  True),
        ]
        for label, base, suffix, default_on in vectors:
            if not enabled.get(suffix, default_on):
                continue
            est = base * (self.ports_scale if suffix == "network" else 1.0)
            obs = self.history.average(f"{suffix}:{target}")
            self.steps.append({"label": label, "key": f"{suffix}:{target}",
                               "static": est, "observed": obs,
                               "start": None, "end": None})

    # -- planning ---------------------------------------------------------
    def _step_estimate(self, st: dict) -> float:
        """Best current guess for one step: observed mean, else static."""
        return st["observed"] if st["observed"] is not None else st["static"]

    def total_estimate(self) -> float:
        return sum(self._step_estimate(s) for s in self.steps)

    def headline(self) -> str:
        """One-line pre-scan estimate shown on the loading page."""
        secs = self.total_estimate()
        n_obs = sum(1 for s in self.steps if s["observed"] is not None)
        basis = ("based on past scans of this target" if n_obs == len(self.steps)
                 and self.steps else
                 "partly from past scans" if n_obs else
                 "conservative worst-case estimate")
        return f"Estimated duration ~{fmt_eta(secs)} ({basis})"

    # -- live tracking ----------------------------------------------------
    def start_step(self, label: str):
        for s in self.steps:
            if s["label"] == label and s["start"] is None:
                s["start"] = time.time()
                return

    def finish_step(self, label: str):
        for s in self.steps:
            if s["label"] == label and s["start"] is not None and s["end"] is None:
                s["end"] = time.time()
                dur = s["end"] - s["start"]
                self.history.record(s["key"], dur)
                s["observed"] = self.history.average(s["key"]) or dur
                return

    def remaining(self) -> str:
        """ETA line for the progress bar text, e.g.
        '~4m 35s remaining • started 12s ago'. Safe before any step starts."""
        now = time.time()
        rem = 0.0
        for s in self.steps:
            est = self._step_estimate(s)
            if s["end"] is not None:
                continue                       # completed: contributes 0
            elif s["start"] is not None:
                el = now - s["start"]
                # count elapsed only past the estimate (don't double-count)
                rem += max(est - el, 0.0) if el <= est else est * 0.15
            else:
                rem += est
        return f"~{fmt_eta(rem)} remaining • started {fmt_eta(now - self.started)} ago"

    def breakdown_lines(self) -> list[str]:
        """Per-step detail for the expander on the loading page."""
        out = []
        for s in self.steps:
            est = self._step_estimate(s)
            src = "measured avg" if s["observed"] is not None else "worst case"
            if s["end"] is not None:
                state = f"done in {fmt_eta(s['end'] - s['start'])}"
            elif s["start"] is not None:
                state = f"running… {fmt_eta(time.time() - s['start'])}"
            else:
                state = "queued"
            out.append(f"- **{s['label']}** — est. {fmt_eta(est)} ({src}) · {state}")
        return out


def record_ai_duration(key_target: str, seconds: float,
                       history_file: str = HISTORY_FILE):
    """Helper for callers that track AI/report time outside the step loop."""
    _History(history_file).record(f"report:{key_target}", seconds)
