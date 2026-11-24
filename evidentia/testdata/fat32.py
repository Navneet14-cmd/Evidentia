"""Minimal, spec-compliant FAT32 image builder with precise control over cluster placement.

Lets the generator create deleted entries (0xE5 + freed FAT chain), fragmented files, orphaned
data (no directory entry) and in-place corruption, all at known offsets.
"""
from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from datetime import datetime

EOC = 0x0FFFFFFF


def _fat_datetime(dt: datetime) -> tuple[int, int]:
    date = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day
    time = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
    return date, time


def _short_name(name: str, used: set[str]) -> bytes:
    base, _, ext = name.rpartition(".") if "." in name else (name, "", "")
    clean = lambda s: "".join(c for c in s.upper() if c.isalnum() or c in "_-~")  # noqa: E731
    b, e = clean(base), clean(ext)[:3]
    for i in range(1, 100):
        cand = (b[:8] if len(b) <= 8 and i == 1 else f"{b[:6]}~{i}")[:8]
        key = f"{cand}.{e}"
        if key not in used:
            used.add(key)
            return cand.ljust(8).encode() + e.ljust(3).encode()
    raise ValueError("cannot create short name")


def _lfn_checksum(sfn: bytes) -> int:
    s = 0
    for c in sfn:
        s = (((s & 1) << 7) + (s >> 1) + c) & 0xFF
    return s


def _lfn_entries(name: str, sfn: bytes) -> list[bytes]:
    chk = _lfn_checksum(sfn)
    units = list(name.encode("utf-16-le"))
    chars = [units[i] | (units[i + 1] << 8) for i in range(0, len(units), 2)]
    chars.append(0x0000)
    while len(chars) % 13:
        chars.append(0xFFFF)
    parts = [chars[i:i + 13] for i in range(0, len(chars), 13)]
    out = []
    for idx, part in enumerate(parts, 1):
        seq = idx | (0x40 if idx == len(parts) else 0)
        b = struct.pack("<B5HBBB6HH2H", seq, *part[:5], 0x0F, 0, chk, *part[5:11], 0, *part[11:13])
        out.append(b)
    return list(reversed(out))


@dataclass
class _Node:
    name: str
    is_dir: bool
    clusters: list[int] = field(default_factory=list)
    size: int = 0
    deleted: bool = False
    children: list["_Node"] = field(default_factory=list)
    mtime: datetime = datetime(2026, 11, 1, 9, 30, 0)


class Fat32Image:
    def __init__(self, size: int = 72 * 1024 * 1024, sectors_per_cluster: int = 2, label: str = "EVIDENTIA"):
        self.bps = 512
        self.spc = sectors_per_cluster
        self.cluster_size = self.bps * self.spc
        self.total_sectors = size // self.bps
        self.reserved = 32
        tmp1 = self.total_sectors - self.reserved
        tmp2 = (256 * self.spc + 2) // 2
        self.fat_sectors = math.ceil(tmp1 / tmp2)
        self.data_start = (self.reserved + 2 * self.fat_sectors) * self.bps
        self.cluster_count = (self.total_sectors - self.reserved - 2 * self.fat_sectors) // self.spc
        if self.cluster_count < 65525:
            raise ValueError("image too small for a spec-compliant FAT32 volume")
        self.label = label
        self.fat = [0] * (self.cluster_count + 2)
        self.fat[0], self.fat[1] = 0x0FFFFFF8, EOC
        self.buf = bytearray(size)
        self.next_free = 3
        self.root = _Node("", True, clusters=[2])
        self.fat[2] = EOC
        self.dir_clusters = 8

    # -- geometry helpers ------------------------------------------------------
    def offset(self, cluster: int) -> int:
        return self.data_start + (cluster - 2) * self.cluster_size

    def clusters_for(self, size: int) -> int:
        return max(1, -(-size // self.cluster_size))

    def alloc(self, n: int) -> list[int]:
        out = list(range(self.next_free, self.next_free + n))
        self.next_free += n
        return out

    def skip(self, n: int) -> None:
        self.next_free += n

    def write_clusters(self, clusters: list[int], data: bytes) -> None:
        cs = self.cluster_size
        for i, c in enumerate(clusters):
            chunk = data[i * cs:(i + 1) * cs]
            o = self.offset(c)
            self.buf[o:o + len(chunk)] = chunk

    # -- tree building ---------------------------------------------------------
    def mkdir(self, parent: _Node | None, name: str) -> _Node:
        parent = parent or self.root
        node = _Node(name, True, clusters=self.alloc(self.dir_clusters))
        parent.children.append(node)
        return node

    def add_file(self, parent: _Node | None, name: str, data: bytes, *, clusters: list[int] | None = None,
                 deleted: bool = False, mtime: datetime | None = None) -> _Node:
        parent = parent or self.root
        clusters = clusters or self.alloc(self.clusters_for(len(data)))
        self.write_clusters(clusters, data)
        node = _Node(name, False, clusters, len(data), deleted)
        if mtime:
            node.mtime = mtime
        parent.children.append(node)
        return node

    def write_raw(self, clusters: list[int], data: bytes) -> None:
        """Data with no directory entry (orphaned / unallocated)."""
        self.write_clusters(clusters, data)

    # -- serialisation ---------------------------------------------------------
    def _chain(self, node: _Node) -> None:
        if node.deleted:
            return  # deleted: chain freed (entries stay 0)
        for a, b in zip(node.clusters, node.clusters[1:]):
            self.fat[a] = b
        self.fat[node.clusters[-1]] = EOC

    def _dirent(self, sfn: bytes, attr: int, cluster: int, size: int, dt: datetime) -> bytes:
        date, time = _fat_datetime(dt)
        return struct.pack("<11sBBBHHHHHHHI", sfn, attr, 0, 0, time, date, date, cluster >> 16,
                           time, date, cluster & 0xFFFF, size)

    def _write_dir(self, node: _Node, parent_cluster: int) -> None:
        ents: list[bytes] = []
        if node is self.root:
            ents.append(struct.pack("<11sB20s", self.label.ljust(11).encode()[:11], 0x08, b"\0" * 20))
        else:
            ents.append(self._dirent(b".          ", 0x10, node.clusters[0], 0, node.mtime))
            ents.append(self._dirent(b"..         ", 0x10, parent_cluster if parent_cluster != 2 else 0, 0, node.mtime))
        used: set[str] = set()
        for ch in node.children:
            sfn = _short_name(ch.name, used)
            lfns = _lfn_entries(ch.name, sfn)
            attr = 0x10 if ch.is_dir else 0x20
            sfe = self._dirent(sfn, attr, ch.clusters[0], 0 if ch.is_dir else ch.size, ch.mtime)
            group = lfns + [sfe]
            if ch.deleted:
                group = [b"\xe5" + g[1:] for g in group]
            ents.extend(group)
            self._chain(ch)
            if ch.is_dir:
                self._write_dir(ch, node.clusters[0])
        raw = b"".join(ents)
        if len(raw) > len(node.clusters) * self.cluster_size:
            raise ValueError(f"directory {node.name!r} too large")
        self.write_clusters(node.clusters, raw)
        for a, b in zip(node.clusters, node.clusters[1:]):
            self.fat[a] = b
        self.fat[node.clusters[-1]] = EOC

    def build(self) -> bytes:
        self._write_dir(self.root, 0)
        bs = bytearray(512)
        struct.pack_into("<3s8sHBHBHHBHHHII", bs, 0, b"\xEB\x58\x90", b"EVIDNTIA", self.bps, self.spc,
                         self.reserved, 2, 0, 0, 0xF8, 0, 32, 64, 0, self.total_sectors)
        struct.pack_into("<IHHIHH12sBBBI11s8s", bs, 36, self.fat_sectors, 0, 0, 2, 1, 6, b"\0" * 12,
                         0x80, 0, 0x29, 0x20261123, self.label.ljust(11).encode()[:11], b"FAT32   ")
        bs[510:512] = b"\x55\xAA"
        free = sum(1 for v in self.fat[2:] if v == 0)
        fsinfo = bytearray(512)
        struct.pack_into("<I", fsinfo, 0, 0x41615252)
        struct.pack_into("<III", fsinfo, 484, 0x61417272, free, self.next_free)
        fsinfo[510:512] = b"\x55\xAA"
        for base in (0, 6):
            self.buf[base * 512:(base + 1) * 512] = bs
            self.buf[(base + 1) * 512:(base + 2) * 512] = fsinfo
        fat_bytes = struct.pack(f"<{len(self.fat)}I", *self.fat)
        for i in range(2):
            o = (self.reserved + i * self.fat_sectors) * self.bps
            self.buf[o:o + len(fat_bytes)] = fat_bytes
        return bytes(self.buf)
