"""Read-only evidence source.

Every recovery read goes through :class:`EvidenceSource`, which opens the image (or an opt-in,
policy-approved device) with ``O_RDONLY`` and deliberately exposes no write method. Integrity is
additionally proven by hashing the source before and after each recovery run.
"""
from __future__ import annotations

import os
import stat
import struct
import sys
import threading

from .devices import SafetyError, assert_device_allowed

IMAGE_EXTENSIONS = (".dd", ".img", ".raw", ".bin", ".001", ".iso")


class EvidenceSource:
    def __init__(self, path: str | os.PathLike, *, advanced: bool = False):
        self.path = os.fspath(path)
        st = os.stat(self.path)
        self.is_device = stat.S_ISBLK(st.st_mode) or stat.S_ISCHR(st.st_mode)
        self.device = None
        if self.is_device:
            self.device = assert_device_allowed(self.path, advanced=advanced, purpose="read")
        elif not stat.S_ISREG(st.st_mode):
            raise SafetyError(f"{self.path} is neither a regular image file nor a block device")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        self._fd = os.open(self.path, flags)
        self._lock = threading.Lock()
        self.sector = 512
        self.size = self._detect_size(st)

    # -- size -----------------------------------------------------------------
    def _detect_size(self, st) -> int:
        if not self.is_device:
            return st.st_size
        if sys.platform == "darwin":
            import fcntl
            DKIOCGETBLOCKSIZE, DKIOCGETBLOCKCOUNT = 0x40046418, 0x40086419
            bs = struct.unpack("I", fcntl.ioctl(self._fd, DKIOCGETBLOCKSIZE, b"\0" * 4))[0]
            cnt = struct.unpack("Q", fcntl.ioctl(self._fd, DKIOCGETBLOCKCOUNT, b"\0" * 8))[0]
            self.sector = bs or 512
            return bs * cnt
        return os.lseek(self._fd, 0, os.SEEK_END)

    # -- reads ----------------------------------------------------------------
    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or offset >= self.size or size <= 0:
            return b""
        size = min(size, self.size - offset)
        if self.is_device:  # raw devices need sector-aligned I/O
            start = offset - offset % self.sector
            end = -(-(offset + size) // self.sector) * self.sector
            return self._pread(start, end - start)[offset - start: offset - start + size]
        return self._pread(offset, size)

    def _pread(self, offset: int, size: int) -> bytes:
        if hasattr(os, "pread"):
            chunks, got = [], 0
            while got < size:
                b = os.pread(self._fd, size - got, offset + got)
                if not b:
                    break
                chunks.append(b)
                got += len(b)
            return b"".join(chunks)
        with self._lock:  # Windows: no pread
            os.lseek(self._fd, offset, os.SEEK_SET)
            return os.read(self._fd, size)

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __repr__(self) -> str:
        kind = "device" if self.is_device else "image"
        return f"<EvidenceSource {kind} {self.path} {self.size} bytes read-only>"
