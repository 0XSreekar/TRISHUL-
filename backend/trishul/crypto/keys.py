# SPDX-License-Identifier: Apache-2.0
"""Ed25519 key ring. Runtime keys are random (see ``trishul.crypto.keystore``); ``from_seed`` exists
for unit tests only. Signatures cover JCS bytes."""

import base64
import binascii
import hashlib
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from trishul.crypto.jcs import jcs

PURPOSES = ("mandate-signer", "approval-signer", "tree-head-signer", "gateway-tool")
# pre-Phase-4 key names, kept so unit-test fixtures keep working (they map to a purpose)
LEGACY_PURPOSE = {
    "gateway": "tree-head-signer",
    "approver": "approval-signer",
    "mandate-issuer": "mandate-signer",
}
DEFAULT_KEY_NAMES = (*PURPOSES, *LEGACY_PURPOSE)
_KID_RE = re.compile(r"^(?P<purpose>[a-z-]+)-(?P<fp>[0-9a-f]{12})$")


def purpose_of(kid: str) -> str | None:
    """The purpose a key id belongs to (``<purpose>-<12 hex>``), or None if it is not one."""
    if kid in PURPOSES:
        return kid
    if kid in LEGACY_PURPOSE:
        return LEGACY_PURPOSE[kid]
    match = _KID_RE.match(kid)
    if match and match["purpose"] in PURPOSES:
        return match["purpose"]
    return None


def fingerprint(public_raw: bytes) -> str:
    """First 12 hex chars of sha256(raw public key); the suffix of every runtime key id."""
    return hashlib.sha256(public_raw).hexdigest()[:12]


def make_kid(purpose: str, public_raw: bytes) -> str:
    return f"{purpose}-{fingerprint(public_raw)}"


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
        self._active: dict[str, str] = {}

    @classmethod
    def from_seed(cls, seed: int, names: tuple[str, ...] = DEFAULT_KEY_NAMES) -> "KeyRing":
        """Deterministic keys from a (public) seed. UNIT TESTS ONLY: never used at runtime."""
        ring = cls()
        for name in names:
            ring.add_private(name, Ed25519PrivateKey.from_private_bytes(_derive_secret(seed, name)))
            if name in PURPOSES:
                ring.set_active(name, name)
        return ring

    @classmethod
    def generate(cls, purposes: tuple[str, ...] = PURPOSES) -> "KeyRing":
        """A fresh random in-memory ring (kid ``<purpose>-<12 hex>``); nothing is persisted."""
        ring = cls()
        for purpose in purposes:
            key = Ed25519PrivateKey.generate()
            raw = key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            kid = make_kid(purpose, raw)
            ring.add_private(kid, key)
            ring.set_active(purpose, kid)
        return ring

    def set_active(self, purpose: str, kid: str) -> None:
        if purpose_of(kid) != purpose or kid not in self._public:
            raise KeyError(f"{kid!r} is not a known {purpose} key")
        self._active[purpose] = kid

    def active_kid(self, purpose: str) -> str:
        """The key id currently used to sign for ``purpose`` (KeyError: fail closed)."""
        return self._active[purpose]

    def can_sign(self, kid: str) -> bool:
        return kid in self._private

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
        ring._active = dict(self._active)
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
