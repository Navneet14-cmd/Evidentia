"""Firmware Purge commands for real devices — documented and guarded.

They only run on Linux with root, with Advanced device access enabled, after every safety check
(not system disk, nothing mounted, typed confirmation) and with dry-run off. On images the engine
simulates them; on macOS/Windows the commands are shown and must be run with vendor tools.
"""
from __future__ import annotations

import shutil
import subprocess
import sys

PASSWORD = "Evidentia"  # temporary ATA security password, cleared by the erase itself


def commands(technique: str, device: str) -> list[list[str]]:
    if technique == "ata-secure-erase":
        return [["hdparm", "-I", device],
                ["hdparm", "--user-master", "u", "--security-set-pass", PASSWORD, device],
                ["hdparm", "--user-master", "u", "--security-erase-enhanced", PASSWORD, device]]
    if technique == "nvme-sanitize-block":
        return [["nvme", "id-ctrl", device, "-H"], ["nvme", "sanitize", device, "--sanact=2"],
                ["nvme", "sanitize-log", device]]
    if technique == "nvme-sanitize-crypto":
        return [["nvme", "id-ctrl", device, "-H"], ["nvme", "sanitize", device, "--sanact=4"],
                ["nvme", "sanitize-log", device]]
    if technique == "crypto-erase":
        if "nvme" in device:
            return [["nvme", "format", device, "--ses=2"]]
        return [["hdparm", "--yes-i-know-what-i-am-doing", "--sanitize-crypto-scramble", device]]
    return []


def preflight(technique: str, device: str) -> list[str]:
    """Return blocking problems for running a firmware command on this host."""
    problems = []
    if not sys.platform.startswith("linux"):
        problems.append("firmware Purge commands are only executed on Linux in this prototype; "
                        "use the commands shown with vendor tools")
    cmds = commands(technique, device)
    for tool in {c[0] for c in cmds}:
        if not shutil.which(tool):
            problems.append(f"required tool '{tool}' not installed")
    if technique == "ata-secure-erase" and not problems:
        out = subprocess.run(["hdparm", "-I", device], capture_output=True, text=True).stdout
        if "not\tfrozen" not in out and "not frozen" not in out:
            problems.append("drive security is FROZEN (suspend/resume or hot-plug the drive, then retry)")
    return problems


def execute(technique: str, device: str, log) -> list[dict]:
    results = []
    for cmd in commands(technique, device):
        log("$ " + " ".join(cmd))
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=6 * 3600)
        results.append({"cmd": cmd, "returncode": p.returncode, "stdout": p.stdout[-2000:], "stderr": p.stderr[-2000:]})
        if p.returncode != 0:
            raise RuntimeError(f"command failed ({p.returncode}): {' '.join(cmd)}: {p.stderr.strip()}")
    return results
