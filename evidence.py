import json
import os
from datetime import datetime, timezone


def new_scan_id() -> str:
    """Local-time YYYYMMDD_HHMMSS identifier shared by the scan entry points."""
    return datetime.now(timezone.utc).astimezone().strftime("%Y%m%d_%H%M%S")


class EvidenceStore:
    def __init__(self, scan_id: str | None = None, base_dir: str = "evidence"):
        self.scan_id = scan_id or new_scan_id()
        self.base_dir = os.path.join(base_dir, self.scan_id)
        os.makedirs(self.base_dir, exist_ok=True)

    def save_raw(self, name: str, content: str):
        path = os.path.join(self.base_dir, f"{name}.txt")
        with open(path, "w") as f:
            f.write(content or "")
        return path

    def save_json(self, name: str, data):
        path = os.path.join(self.base_dir, f"{name}.json")
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return path

    def save_binary(self, name: str, content: bytes):
        path = os.path.join(self.base_dir, f"{name}.bin")
        with open(path, "wb") as f:
            f.write(content)
        return path

    def path(self) -> str:
        return self.base_dir
