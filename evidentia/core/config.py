"""Application paths and persisted settings."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, fields
from pathlib import Path


def data_dir() -> Path:
    """Root directory for the case database, keys and case artefacts.

    Override with the EVIDENTIA_HOME environment variable (used by tests and the demo).
    """
    p = Path(os.environ.get("EVIDENTIA_HOME") or (Path.home() / ".evidentia")).expanduser()
    p.mkdir(parents=True, exist_ok=True)
    return p


@dataclass
class Settings:
    examiner_name: str = ""
    examiner_org: str = ""
    examiner_id: str = ""
    # Physical device access is OFF unless the operator explicitly enables it.
    advanced_device_access: bool = False
    default_verify_mode: str = "sample"
    sample_percent: float = 10.0

    @classmethod
    def load(cls, base: Path | None = None) -> "Settings":
        path = (base or data_dir()) / "settings.json"
        if not path.exists():
            return cls()
        try:
            raw = json.loads(path.read_text())
        except (OSError, ValueError):
            return cls()
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in raw.items() if k in known})

    def save(self, base: Path | None = None) -> None:
        path = (base or data_dir()) / "settings.json"
        path.write_text(json.dumps(asdict(self), indent=2))

    @property
    def examiner_label(self) -> str:
        return self.examiner_name or os.environ.get("USER") or "examiner"
