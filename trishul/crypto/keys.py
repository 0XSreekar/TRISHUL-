# SPDX-License-Identifier: Apache-2.0
"""Ed25519 key ring. Deterministic from a seed for the demo; signatures cover JCS bytes."""

import base64
import binascii

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from trishul.crypto.jcs import jcs

DEFAULT_KEY_NAMES = ("gateway", "approver", "mandate-issuer")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    if not text.isascii():
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _derive_secret(seed: int, name: str) -> bytes:
    """HKDF-SHA256 over the decimal seed with the key name as ``info`` (demo keys only)."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"trishul-key-v1",
        info=name.encode("utf-8"),
    )
    return hkdf.derive(str(seed).encode("ascii"))


class KeyRing:
    """key_id -> Ed25519 keypair. Verification-only entries hold just a public key."""

    def __init__(self) -> None:
        self._private: dict[str, Ed25519PrivateKey] = {}
        self._public: dict[str, Ed25519PublicKey] = {}

    @classmethod
    def from_seed(cls, seed: int, names: tuple[str, ...] = DEFAULT_KEY_NAMES) -> "KeyRing":
        ring = cls()
        for name in names:
            ring.add_private(name, Ed25519PrivateKey.from_private_bytes(_derive_secret(seed, name)))
        return ring

    @classmethod
    def generate(cls, names: tuple[str, ...] = DEFAULT_KEY_NAMES) -> "KeyRing":
        ring = cls()
        for name in names:
            ring.add_private(name, Ed25519PrivateKey.generate())
        return ring

    def add_private(self, key_id: str, key: Ed25519PrivateKey) -> None:
        self._private[key_id] = key
        self._public[key_id] = key.public_key()

    def add_public(self, key_id: str, key: Ed25519PublicKey) -> None:
        self._public[key_id] = key

    def key_ids(self) -> list[str]:
        return sorted(self._public)

    def public_bytes(self, key_id: str) -> bytes:
        return self._public[key_id].public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def public_ring(self) -> "KeyRing":
        """A copy holding only public keys (cannot sign)."""
        ring = KeyRing()
        ring._public = dict(self._public)
        return ring

    def sign(self, key_id: str, payload: object) -> str:
        """base64url Ed25519 signature over ``jcs(payload)``. KeyError if no private key."""
        return b64url(self._private[key_id].sign(jcs(payload)))

    def verify(self, key_id: str, payload: object, signature: str) -> bool:
        """True iff ``signature`` is valid for ``jcs(payload)``. Never raises on bad input."""
        public = self._public.get(key_id)
        if public is None:
            return False
        try:
            public.verify(b64url_decode(signature), jcs(payload))
        except (InvalidSignature, ValueError, binascii.Error, TypeError):
            return False
        return True
