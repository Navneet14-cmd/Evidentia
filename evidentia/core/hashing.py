"""Streaming SHA-256 (primary) and MD5 (legacy compatibility) hashing."""
from __future__ import annotations

import hashlib
import os
from typing import Callable, Iterable

from .jobs import JobContext, NULL_CONTEXT

DEFAULT_ALGOS = ("sha256", "md5")
CHUNK = 4 * 1024 * 1024


def hash_bytes(data: bytes, algos: Iterable[str] = DEFAULT_ALGOS) -> dict:
    return {a: hashlib.new(a, data).hexdigest() for a in algos}


def hash_reader(read: Callable[[int, int], bytes], total: int, algos: Iterable[str] = DEFAULT_ALGOS,
                ctx: JobContext = NULL_CONTEXT, offset: int = 0, label: str = "Hashing") -> dict:
    hs = {a: hashlib.new(a) for a in algos}
    done = 0
    while done < total:
        ctx.check()
        n = min(CHUNK, total - done)
        block = read(offset + done, n)
        if not block:
            break
        for h in hs.values():
            h.update(block)
        done += len(block)
        ctx.progress(done / total if total else 1.0, f"{label} {done >> 20}/{total >> 20} MiB")
    return {a: h.hexdigest() for a, h in hs.items()}


def hash_file(path: str | os.PathLike, algos: Iterable[str] = DEFAULT_ALGOS,
              ctx: JobContext = NULL_CONTEXT) -> dict:
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        def read(off: int, n: int) -> bytes:
            fh.seek(off)
            return fh.read(n)
        return hash_reader(read, size, algos, ctx)
