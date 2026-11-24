"""Overwrite patterns. The random pattern is a ChaCha20 keystream, so any block can be regenerated
at any offset for read-back verification without storing the written data."""
from __future__ import annotations

import os
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SEGMENT = 64 << 32  # bytes per 32-bit ChaCha20 block counter (256 GiB)


class Pattern:
    name = "pattern"
    verifiable = True

    def block(self, offset: int, n: int) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError

    def describe(self) -> str:
        return self.name


class ConstPattern(Pattern):
    def __init__(self, value: int):
        self.value = value
        self.name = "zeros (0x00)" if value == 0 else f"constant 0x{value:02X}"
        self._cache = bytes([value]) * (1 << 20)

    def block(self, offset: int, n: int) -> bytes:
        return self._cache[:n] if n <= len(self._cache) else bytes([self.value]) * n


class RandomPattern(Pattern):
    name = "random (ChaCha20 keystream)"

    def __init__(self, key: bytes | None = None, nonce: bytes | None = None):
        self.key = key or os.urandom(32)
        self.nonce8 = nonce or os.urandom(8)

    def block(self, offset: int, n: int) -> bytes:
        out = bytearray()
        start = offset - offset % 64
        skip = offset - start
        need = n + skip
        pos = start
        while need > 0:
            seg, rel = divmod(pos, SEGMENT)
            take = min(need, SEGMENT - rel)
            nonce = struct.pack("<I", rel // 64) + self.nonce8 + struct.pack("<I", seg)
            enc = Cipher(algorithms.ChaCha20(self.key, nonce), mode=None).encryptor()
            out += enc.update(bytes(take))
            pos += take
            need -= take
        return bytes(out[skip:skip + n])


class CryptoEraseSim:
    """Simulated cryptographic erase: encrypt the medium in place with AES-256-CTR under an
    ephemeral key, then destroy the key. This is exactly the end state of a real crypto-erase
    (ciphertext under an unrecoverable media encryption key)."""

    name = "AES-256-CTR in-place encryption + key destruction (simulated crypto-erase)"

    def __init__(self):
        self._key = bytearray(os.urandom(32))
        self._iv = os.urandom(12)

    def transform(self, offset: int, data: bytes) -> bytes:
        if not self._key:
            raise RuntimeError("media encryption key already destroyed")
        start = offset - offset % 16
        counter = self._iv + struct.pack(">I", (start // 16) & 0xFFFFFFFF)
        enc = Cipher(algorithms.AES(bytes(self._key)), modes.CTR(counter)).encryptor()
        pad = offset - start
        return enc.update(bytes(pad) + data)[pad:]

    def destroy_key(self) -> None:
        for i in range(len(self._key)):
            self._key[i] = 0
        self._key = bytearray()
