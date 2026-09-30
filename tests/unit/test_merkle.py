import hashlib

import pytest

from trishul.audit import merkle

# Certificate Transparency reference vectors (RFC 6962 test data).
LEAVES = [
    b"",
    bytes.fromhex("00"),
    bytes.fromhex("10"),
    bytes.fromhex("2021"),
    bytes.fromhex("3031"),
    bytes.fromhex("40414243"),
    bytes.fromhex("5051525354555657"),
    bytes.fromhex("606162636465666768696a6b6c6d6e6f"),
]
ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]


def hashed(n: int) -> list[bytes]:
    return [merkle.leaf_hash(f"leaf-{i}".encode()) for i in range(n)]


def test_empty_root() -> None:
    assert merkle.mth([]) == hashlib.sha256(b"").digest()


@pytest.mark.parametrize("n", range(1, 9))
def test_rfc6962_vector_roots(n: int) -> None:
    assert merkle.hexd(merkle.mth([merkle.leaf_hash(x) for x in LEAVES[:n]])) == ROOTS[n - 1]


def test_hash_prefixes() -> None:
    assert merkle.leaf_hash(b"x") == hashlib.sha256(b"\x00x").digest()
    assert (
        merkle.node_hash(b"a" * 32, b"b" * 32)
        == hashlib.sha256(b"\x01" + b"a" * 32 + b"b" * 32).digest()
    )


@pytest.mark.parametrize("n", range(1, 41))
def test_inclusion_proofs(n: int) -> None:
    leaves = hashed(n)
    root = merkle.mth(leaves)
    for i in range(n):
        proof = merkle.inclusion_proof(i, leaves)
        assert merkle.verify_inclusion(leaves[i], i, n, proof, root)
        assert not merkle.verify_inclusion(leaves[i], (i + 1) % n if n > 1 else 1, n, proof, root)
        assert not merkle.verify_inclusion(merkle.leaf_hash(b"evil"), i, n, proof, root)
        if proof:
            bad = [proof[0][:-1] + bytes([proof[0][-1] ^ 1]), *proof[1:]]
            assert not merkle.verify_inclusion(leaves[i], i, n, bad, root)
            assert not merkle.verify_inclusion(leaves[i], i, n, proof[:-1], root)
        assert not merkle.verify_inclusion(leaves[i], i, n, [*proof, root], root)


@pytest.mark.parametrize("n", range(1, 41))
def test_consistency_proofs(n: int) -> None:
    leaves = hashed(n)
    second_root = merkle.mth(leaves)
    for m in range(1, n + 1):
        first_root = merkle.mth(leaves[:m])
        proof = merkle.consistency_proof(m, leaves)
        assert merkle.verify_consistency(m, n, first_root, second_root, proof)
        assert not merkle.verify_consistency(m, n, merkle.leaf_hash(b"x"), second_root, proof)
        assert not merkle.verify_consistency(m, n, first_root, merkle.leaf_hash(b"x"), proof)
        if proof:
            assert not merkle.verify_consistency(m, n, first_root, second_root, proof[:-1])
            bad = [*proof[:-1], proof[-1][:-1] + bytes([proof[-1][-1] ^ 1])]
            assert not merkle.verify_consistency(m, n, first_root, second_root, bad)


def test_known_rfc_proof_shapes() -> None:
    leaves = [merkle.leaf_hash(x) for x in LEAVES]
    assert len(merkle.inclusion_proof(0, leaves)) == 3
    assert len(merkle.consistency_proof(3, leaves[:7])) == 4
    with pytest.raises(IndexError):
        merkle.inclusion_proof(8, leaves)
