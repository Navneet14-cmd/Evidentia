"""Recovery confidence score (0-100) with an explainable per-component breakdown.

    metadata       20  file-system name / timestamps / size / inode available
    validation     40  structural validator verdict (intact / partial / unknown / corrupt)
    fragmentation  20  contiguous, FS-chained, reconstructed (bifragment) or broken
    entropy        20  byte entropy within the range expected for the detected type, minus a
                       penalty for zero-filled blocks (unreadable or wiped sectors)
"""
from __future__ import annotations

from dataclasses import dataclass, field

VALIDATION_POINTS = {"intact": 40, "partial": 20, "unknown": 15, "corrupt": 4}
FRAGMENT_POINTS = {
    "contiguous": (20, "contiguous allocation"),
    "fs-chain": (18, "fragmented; file-system metadata located every fragment"),
    "reconstructed": (13, "bifragment reconstruction validated end-to-end"),
    "unknown": (10, "cannot tell (file truncated or no end marker)"),
    "broken": (2, "content does not validate: likely fragmented or overwritten"),
}


@dataclass
class ScoreResult:
    total: int
    components: list[dict] = field(default_factory=list)

    @property
    def grade(self) -> str:
        return "high" if self.total >= 80 else "medium" if self.total >= 50 else "low"

    def to_dict(self) -> dict:
        return {"total": self.total, "grade": self.grade, "components": self.components}


def compute_score(*, has_name: bool, has_times: bool, has_inode: bool, size_consistent: bool,
                  validation_status: str, fragmentation: str, entropy: float,
                  expected_entropy: tuple[float, float], zero_ratio: float) -> ScoreResult:
    comps = []
    md = 6 * has_name + 6 * has_times + 4 * size_consistent + 4 * has_inode
    parts = [p for p, ok in (("name", has_name), ("timestamps", has_times), ("size", size_consistent),
                             ("inode/path", has_inode)) if ok]
    comps.append({"key": "metadata", "label": "Metadata availability", "points": md, "max": 20,
                  "reason": ("file-system metadata: " + ", ".join(parts)) if parts
                  else "carved from raw bytes: no file-system metadata"})

    vp = VALIDATION_POINTS.get(validation_status, 0)
    comps.append({"key": "validation", "label": "Structural validation", "points": vp, "max": 40,
                  "reason": f"validator verdict: {validation_status}"})

    fp, freason = FRAGMENT_POINTS.get(fragmentation, FRAGMENT_POINTS["unknown"])
    comps.append({"key": "fragmentation", "label": "Fragmentation", "points": fp, "max": 20,
                  "reason": freason})

    lo, hi = expected_entropy
    dist = 0.0 if lo <= entropy <= hi else (lo - entropy if entropy < lo else entropy - hi)
    ep = max(0.0, 20 - 8 * dist)
    penalty = min(12.0, zero_ratio * 40)
    ep = max(0.0, ep - penalty)
    reason = f"entropy {entropy:.2f} bits/byte (expected {lo:.1f}-{hi:.1f})"
    if zero_ratio > 0.01:
        reason += f"; {zero_ratio:.0%} zero-filled blocks"
    comps.append({"key": "entropy", "label": "Entropy / content", "points": round(ep), "max": 20,
                  "reason": reason})
    total = int(round(sum(c["points"] for c in comps)))
    return ScoreResult(max(0, min(100, total)), comps)
