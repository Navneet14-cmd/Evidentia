"""Ed25519 signing identity for the installation (ledger entries, anchors, certificates)."""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


class Signer:
    """Loads or creates an Ed25519 key pair under ``<data_dir>/keys``.

    Prototype note: the private key is stored unencrypted with 0600 permissions. Production use
    should keep it in an HSM / OS keychain / smart card.
    """

    def __init__(self, key_dir: str | os.PathLike):
        self.dir = Path(key_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        priv_path = self.dir / "ed25519_private.pem"
        if priv_path.exists():
            self._priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
        else:
            self._priv = Ed25519PrivateKey.generate()
            pem = self._priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption())
            fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(pem)
            (self.dir / "ed25519_public.pem").write_bytes(self.public_pem)
        self.public_raw = self._priv.public_key().public_bytes(serialization.Encoding.Raw,
                                                                 serialization.PublicFormat.Raw)

    @property
    def public_pem(self) -> bytes:
        return self._priv.public_key().public_bytes(serialization.Encoding.PEM,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo)

    @property
    def public_b64(self) -> str:
        return b64(self.public_raw)

    @property
    def fingerprint(self) -> str:
        h = hashlib.sha256(self.public_raw).hexdigest()[:32]
        return ":".join(h[i:i + 4] for i in range(0, 32, 4))

    def sign(self, data: bytes) -> str:
        return b64(self._priv.sign(data))


def verify_signature(public_b64: str, signature_b64: str, data: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64)).verify(base64.b64decode(signature_b64), data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
