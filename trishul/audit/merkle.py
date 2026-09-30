"""RFC 6962 Merkle tree: hashing, roots, inclusion and consistency proofs and verifiers.

All functions take/return raw 32-byte digests; ``hexd``/``unhex`` convert for storage.
"""

import hashlib
from collections.abc import Sequence

EMPTY_ROOT = hashlib.sha256(b"").digest()


def hexd(digest: bytes) -> str:
    return digest.hex()


def unhex(text: str) -> bytes:
    return bytes.fromhex(text)


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than ``n`` (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def mth(leaves: Sequence[bytes]) -> bytes:
    """Merkle Tree Hash over already-hashed leaves (RFC 6962 section 2.1)."""
    n = len(leaves)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return leaves[0]
    k = _split(n)
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def inclusion_proof(index: int, leaves: Sequence[bytes]) -> list[bytes]:
    """Audit path for ``leaves[index]`` in the tree over ``leaves`` (RFC 6962 section 2.1.1)."""
    n = len(leaves)
    if not 0 <= index < n:
        raise IndexError("leaf index out of range")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return [*inclusion_proof(index, leaves[:k]), mth(leaves[k:])]
    return [*inclusion_proof(index - k, leaves[k:]), mth(leaves[:k])]


def _subproof(m: int, leaves: Sequence[bytes], complete: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if complete else [mth(leaves)]
    k = _split(n)
    if m <= k:
        return [*_subproof(m, leaves[:k], complete), mth(leaves[k:])]
    return [*_subproof(m - k, leaves[k:], False), mth(leaves[:k])]


def consistency_proof(first: int, leaves: Sequence[bytes]) -> list[bytes]:
    """Proof that the tree of the first ``first`` leaves is a prefix of the tree over ``leaves``
    (RFC 6962 section 2.1.2). Empty for ``first`` in {0, len(leaves)}."""
    n = len(leaves)
    if not 0 <= first <= n:
        raise ValueError("first must be within 0..len(leaves)")
    if first in (0, n):
        return []
    return _subproof(first, leaves, True)


def verify_inclusion(
    leaf: bytes, index: int, size: int, proof: Sequence[bytes], root: bytes
) -> bool:
    """RFC 9162 section 2.1.3.2 verification (identical hashing to RFC 6962)."""
    if index < 0 or size <= 0 or index >= size:
        return False
    fn, sn = index, size - 1
    r = leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(
    first: int,
    second: int,
    first_root: bytes,
    second_root: bytes,
    proof: Sequence[bytes],
) -> bool:
    """RFC 9162 section 2.1.4.2 verification."""
    if first < 0 or second < first:
        return False
    if first == second:
        return not proof and first_root == second_root
    if first == 0:
        return not proof
    path = list(proof)
    if first & (first - 1) == 0:
        path.insert(0, first_root)
    if not path:
        return False
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root
