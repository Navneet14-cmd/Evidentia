"""Physical device enumeration and the safety policy that guards every device access.

Policy (enforced by :func:`assert_device_allowed`):
  * device access is opt-in ("advanced" flag) — by default only image files are accepted;
  * the system/boot disk is always refused;
  * any disk with a mounted volume is refused (unmount it first);
  * destructive operations additionally require the operator to type the device name
    (:func:`confirm_device_name`) and support a dry-run mode (see ``sanitize``).

Supported platforms: macOS (diskutil) and Linux (lsblk/sysfs). On Windows device access is
disabled entirely (see README "Windows caveats").
"""
from __future__ import annotations

import json
import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass, field


class SafetyError(RuntimeError):
    """Raised when an operation would violate the evidence/device safety policy."""


SYSTEM_MOUNTS = ("/", "/boot", "/boot/efi", "/efi", "/usr", "/var", "/home", "[SWAP]")


@dataclass
class DeviceInfo:
    path: str                       # e.g. /dev/disk4 or /dev/sdb
    name: str                       # what the operator must type to confirm, e.g. disk4 / sdb
    size: int = 0
    model: str = ""
    serial: str = ""
    media_type: str = "unknown"     # HDD | SSD | NVMe | USB | image | unknown
    transport: str = ""
    removable: bool = False
    internal: bool | None = None
    is_system: bool = False
    mountpoints: list[str] = field(default_factory=list)
    partitions: list[str] = field(default_factory=list)

    def refusal_reasons(self) -> list[str]:
        reasons = []
        if self.is_system:
            reasons.append("system/boot disk")
        if self.mountpoints:
            shown = ", ".join(m for m in self.mountpoints[:4] if m)
            reasons.append(f"has mounted volume(s): {shown}")
        return reasons

    @property
    def allowed(self) -> bool:
        return not self.refusal_reasons()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["refusal_reasons"] = self.refusal_reasons()
        return d


def is_device_path(path: str) -> bool:
    try:
        st = os.stat(path)
    except OSError:
        return False
    return stat.S_ISBLK(st.st_mode) or stat.S_ISCHR(st.st_mode)


# --------------------------------------------------------------------------- macOS
def _run_plist(args: list[str]) -> dict:
    out = subprocess.run(args, capture_output=True, check=True, timeout=20).stdout
    return plistlib.loads(out)


def _macos_devices() -> list[DeviceInfo]:
    listing = _run_plist(["diskutil", "list", "-plist"])
    entries = listing.get("AllDisksAndPartitions", [])
    mounts: dict[str, list[str]] = {}
    parts: dict[str, list[str]] = {}
    synthesized_backing: dict[str, str] = {}
    for e in entries:
        did = e["DeviceIdentifier"]
        mps = [e.get("MountPoint")] if e.get("MountPoint") else []
        mps += [p["MountPoint"] for p in e.get("Partitions", []) if p.get("MountPoint")]
        mps += [v["MountPoint"] for v in e.get("APFSVolumes", []) if v.get("MountPoint")]
        mounts[did] = mps
        parts[did] = [p["DeviceIdentifier"] for p in e.get("Partitions", [])]
        for store in e.get("APFSPhysicalStores", []):
            synthesized_backing[did] = store["DeviceIdentifier"]
    # An APFS container (synthesized disk) inherits onto its physical whole disk.
    for synth, store in synthesized_backing.items():
        m = re.match(r"(disk\d+)", store)
        if m:
            mounts.setdefault(m.group(1), []).extend(mounts.get(synth, []))
    devices = []
    for did in mounts:
        if did in synthesized_backing:
            continue
        try:
            info = _run_plist(["diskutil", "info", "-plist", did])
        except (subprocess.SubprocessError, OSError):
            info = {}
        if info.get("VirtualOrPhysical") == "Virtual" and did not in parts:
            continue
        protocol = info.get("BusProtocol", "")
        solid = bool(info.get("SolidState"))
        if "USB" in protocol:
            media = "USB"
        elif "NVMe" in protocol or "PCI" in protocol or "Apple Fabric" in protocol:
            media = "NVMe" if solid else "HDD"
        else:
            media = "SSD" if solid else "HDD"
        mps = mounts.get(did, [])
        devices.append(DeviceInfo(
            path=f"/dev/{did}", name=did, size=int(info.get("TotalSize") or info.get("Size") or 0),
            model=info.get("MediaName", ""), serial=info.get("SerialNumber", ""),
            media_type=media, transport=protocol,
            removable=bool(info.get("RemovableMediaOrExternalDevice") or info.get("Removable")),
            internal=info.get("Internal"),
            is_system=any(m == "/" or m.startswith("/System/Volumes") for m in mps),
            mountpoints=mps, partitions=parts.get(did, [])))
    return devices


# --------------------------------------------------------------------------- Linux
def _linux_devices() -> list[DeviceInfo]:
    cols = "NAME,PATH,SIZE,MODEL,SERIAL,TYPE,ROTA,TRAN,RM,MOUNTPOINT"
    out = subprocess.run(["lsblk", "-J", "-b", "-o", cols], capture_output=True, check=True,
                         timeout=20).stdout
    tree = json.loads(out).get("blockdevices", [])

    def collect(node, acc_mounts, acc_parts):
        for key in ("mountpoint", "mountpoints"):
            v = node.get(key)
            if isinstance(v, list):
                acc_mounts.extend(x for x in v if x)
            elif v:
                acc_mounts.append(v)
        for child in node.get("children", []) or []:
            acc_parts.append(child.get("name"))
            collect(child, acc_mounts, acc_parts)

    devices = []
    for d in tree:
        if d.get("type") not in ("disk",):
            continue
        mps, prts = [], []
        collect(d, mps, prts)
        tran = (d.get("tran") or "").lower()
        rota = d.get("rota") in (True, "1", 1)
        media = "NVMe" if tran == "nvme" or d["name"].startswith("nvme") else \
            "USB" if tran == "usb" else ("HDD" if rota else "SSD")
        devices.append(DeviceInfo(
            path=d.get("path") or f"/dev/{d['name']}", name=d["name"], size=int(d.get("size") or 0),
            model=(d.get("model") or "").strip(), serial=(d.get("serial") or "").strip(),
            media_type=media, transport=tran, removable=d.get("rm") in (True, "1", 1),
            is_system=any(m in SYSTEM_MOUNTS for m in mps), mountpoints=mps, partitions=prts))
    return devices


def list_devices() -> list[DeviceInfo]:
    """Enumerate whole physical disks with their safety status. Never raises."""
    try:
        if sys.platform == "darwin" and shutil.which("diskutil"):
            return _macos_devices()
        if sys.platform.startswith("linux") and shutil.which("lsblk"):
            return _linux_devices()
    except (subprocess.SubprocessError, OSError, ValueError, KeyError):
        return []
    return []


def whole_disk_name(path: str) -> str:
    """/dev/rdisk4s1 -> disk4 ; /dev/sdb2 -> sdb ; /dev/nvme0n1p3 -> nvme0n1."""
    name = os.path.basename(path)
    if name.startswith("rdisk"):
        name = name[1:]
    m = re.match(r"(disk\d+)", name) or re.match(r"(nvme\d+n\d+)", name) or \
        re.match(r"(mmcblk\d+)", name) or re.match(r"([shv]d[a-z]+)", name)
    return m.group(1) if m else name


def find_device(path: str, devices: list[DeviceInfo] | None = None) -> DeviceInfo | None:
    target = whole_disk_name(path)
    for d in devices if devices is not None else list_devices():
        if d.name == target:
            return d
    return None


def assert_device_allowed(path: str, *, advanced: bool, purpose: str = "access",
                          devices: list[DeviceInfo] | None = None) -> DeviceInfo:
    """Raise :class:`SafetyError` unless ``path`` is a device the policy permits."""
    if sys.platform.startswith("win"):
        raise SafetyError("Physical device access is not supported on Windows in this prototype.")
    if not advanced:
        raise SafetyError(
            f"Refusing to {purpose} physical device {path}: device access is disabled. "
            "Work on a disk image, or enable Advanced device access in Settings / --advanced.")
    dev = find_device(path, devices)
    if dev is None:
        raise SafetyError(f"Refusing to {purpose} {path}: not a recognised whole physical disk.")
    reasons = dev.refusal_reasons()
    if reasons:
        raise SafetyError(f"Refusing to {purpose} {dev.path}: " + "; ".join(reasons) + ".")
    return dev


def confirm_device_name(dev: DeviceInfo, typed: str) -> None:
    if (typed or "").strip() != dev.name:
        raise SafetyError(f"Confirmation failed: type the exact device name '{dev.name}' to proceed.")


# Paths that file-level sanitization must never touch.
_PROTECTED_PREFIXES = ("/System", "/usr", "/bin", "/sbin", "/etc", "/private/etc", "/Library",
                       "/Applications", "/boot", "/lib", "/lib64", "/opt/homebrew", "/proc", "/sys",
                       "/dev", "/var/lib", "C:\\Windows", "C:\\Program Files")


def assert_safe_host_path(path: str) -> None:
    real = os.path.realpath(path)
    home = os.path.realpath(os.path.expanduser("~"))
    if real in ("/", home) or os.path.dirname(real) == real:
        raise SafetyError(f"Refusing to sanitize {real}: filesystem root or home directory.")
    for p in _PROTECTED_PREFIXES:
        if real == p or real.startswith(p.rstrip("/\\") + os.sep):
            raise SafetyError(f"Refusing to sanitize {real}: protected system location.")
