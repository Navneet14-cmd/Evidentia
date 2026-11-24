"""Byte-level statistics used by carving heuristics and confidence scoring."""
from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0..8)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def sampled_entropy(data: bytes, max_bytes: int = 1 << 20) -> float:
    """Entropy over an evenly strided sample of at most ``max_bytes`` (in 4 KiB slices)."""
    if len(data) <= max_bytes:
        return shannon_entropy(data)
    slices = max_bytes // 4096
    step = len(data) // slices
    sample = b"".join(data[i:i + 4096] for i in range(0, len(data), step))
    return shannon_entropy(sample)


def zero_block_ratio(data: bytes, block: int = 512) -> float:
    """Fraction of ``block``-sized blocks that are entirely zero (a hint of missing sectors)."""
    if len(data) < block:
        return 0.0
    zero = bytes(block)
    total = len(data) // block
    zeros = sum(1 for i in range(0, total * block, block) if data[i:i + block] == zero)
    return zeros / total
