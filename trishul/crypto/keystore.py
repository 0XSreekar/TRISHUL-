# SPDX-License-Identifier: Apache-2.0
"""On-disk key store: random Ed25519 keys under ``<TRISHUL_HOME>/keys`` (dir 0700, files 0600).

Layout: ``<kid>.key`` (base64url raw private key), ``<kid>.pub`` (base64url raw public key) and
``keyring.json`` = ``{purpose: {"active": kid, "all": [kid, ...]}}``. Rotation adds a key and moves
``active``; old kids stay on disk so signatures that recorded them still verify.

Loading refuses (``KeyStoreError``, fail closed) when the directory or any secret file is group or
world accessible, when a key file does not match its kid, or when a purpose has no usable key.
Private keys are never logged or serialised anywhere except these files. Production deployments
belong in a KMS/HSM (see docs/threat-model.md); this store is the demo implementation.
"""

import contextlib
import fcntl
import json
import os
import stat
from collections.abc import Iterator
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from trishul.crypto.keys import PURPOSES, KeyRing, b64url, b64url_decode, make_kid, purpose_of

KEYRING_FILE = "keyring.json"
_RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class KeyStoreError(Exception):
    """The key directory is missing, malformed or has unsafe permissions."""


def default_home() -> Path:
    return Path(os.environ.get("TRISHUL_HOME", ".trishul"))


def keys_dir(home: Path | None = None) -> Path:
    return (home if home is not None else default_home()) / "keys"


def _check_mode(path: Path, *, directory: bool) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        want = "0700" if directory else "0600"
        raise KeyStoreError(f"{path} is accessible by group/other (mode {mode:04o}); need {want}")


def _write_private(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()


@contextlib.contextmanager
def _locked(directory: Path) -> Iterator[None]:
    fd = os.open(directory / ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)  # closing releases the flock


def _ensure_dir(directory: Path) -> None:
    directory.parent.mkdir(parents=True, exist_ok=True)
    directory.mkdir(mode=0o700, exist_ok=True)
    _check_mode(directory, directory=True)


def _read_index(directory: Path) -> dict[str, dict[str, object]]:
    try:
        raw = json.loads((directory / KEYRING_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise KeyStoreError(f"cannot read {directory / KEYRING_FILE}: {exc}") from exc
    if not isinstance(raw, dict):
        raise KeyStoreError("keyring.json is not an object")
    return raw


def _new_key(directory: Path, purpose: str) -> str:
    key = Ed25519PrivateKey.generate()
    raw_pub = key.public_key().public_bytes(*_RAW)
    kid = make_kid(purpose, raw_pub)
    raw_priv = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    _write_private(directory / f"{kid}.key", b64url(raw_priv).encode("ascii"))
    _write_private(directory / f"{kid}.pub", b64url(raw_pub).encode("ascii"))
    return kid


def _write_index(directory: Path, index: dict[str, dict[str, object]]) -> None:
    _write_private(directory / KEYRING_FILE, json.dumps(index, sort_keys=True, indent=2).encode())


def _entry(index: dict[str, dict[str, object]], purpose: str) -> tuple[str, list[str]]:
    entry = index.get(purpose)
    if not isinstance(entry, dict):
        raise KeyStoreError(f"no key registered for purpose {purpose}")
    active, every = entry.get("active"), entry.get("all")
    if (
        not isinstance(active, str)
        or not isinstance(every, list)
        or not all(isinstance(k, str) for k in every)
        or active not in every
    ):
        raise KeyStoreError(f"malformed keyring entry for {purpose}")
    return active, [str(k) for k in every]


def load_ring(home: Path | None = None, *, create: bool = False) -> KeyRing:
    """Load (and with ``create=True`` first generate) the full private ring for ``home``."""
    directory = keys_dir(home)
    if create:
        _ensure_dir(directory)
        with _locked(directory):
            if not (directory / KEYRING_FILE).exists():
                index: dict[str, dict[str, object]] = {}
                for purpose in PURPOSES:
                    kid = _new_key(directory, purpose)
                    index[purpose] = {"active": kid, "all": [kid]}
                _write_index(directory, index)
    if not directory.is_dir():
        raise KeyStoreError(f"key directory {directory} does not exist")
    _check_mode(directory, directory=True)
    _check_mode(directory / KEYRING_FILE, directory=False)
    index = _read_index(directory)
    ring = KeyRing()
    for purpose in PURPOSES:
        active, every = _entry(index, purpose)
        for kid in every:
            if purpose_of(kid) != purpose:
                raise KeyStoreError(f"{kid} is not a {purpose} key id")
            path = directory / f"{kid}.key"
            try:
                _check_mode(path, directory=False)
                private = Ed25519PrivateKey.from_private_bytes(
                    b64url_decode(path.read_text(encoding="ascii").strip())
                )
            except KeyStoreError:
                raise
            except (OSError, ValueError) as exc:
                raise KeyStoreError(f"cannot load key {kid}: {type(exc).__name__}") from exc
            if make_kid(purpose, private.public_key().public_bytes(*_RAW)) != kid:
                raise KeyStoreError(f"key file {kid} does not match its key id")
            ring.add_private(kid, private)
        ring.set_active(purpose, active)
    return ring


def load_or_create(home: Path | None = None) -> KeyRing:
    return load_ring(home, create=True)


def rotate(home: Path | None, purpose: str) -> str:
    """Add a new key for ``purpose`` and make it active; old kids stay verifiable."""
    if purpose not in PURPOSES:
        raise KeyStoreError(f"unknown purpose {purpose!r}; expected one of {', '.join(PURPOSES)}")
    load_or_create(home)
    directory = keys_dir(home)
    with _locked(directory):
        index = _read_index(directory)
        _, every = _entry(index, purpose)
        kid = _new_key(directory, purpose)
        index[purpose] = {"active": kid, "all": [*every, kid]}
        _write_index(directory, index)
    return kid


def load_public(directory: Path) -> KeyRing:
    """Verification-only ring from ``*.pub`` files + ``keyring.json`` (what tool servers hold).

    Private key files in the same directory are never opened."""
    index = _read_index(directory)
    ring = KeyRing()
    for purpose in PURPOSES:
        active, every = _entry(index, purpose)
        for kid in every:
            try:
                raw = b64url_decode((directory / f"{kid}.pub").read_text(encoding="ascii").strip())
                public = Ed25519PublicKey.from_public_bytes(raw)
            except (OSError, ValueError) as exc:
                raise KeyStoreError(f"cannot load public key {kid}: {type(exc).__name__}") from exc
            if purpose_of(kid) != purpose or make_kid(purpose, raw) != kid:
                raise KeyStoreError(f"public key file {kid} does not match its key id")
            ring.add_public(kid, public)
        ring.set_active(purpose, active)
    return ring


def write_public(ring: KeyRing, destination: Path) -> None:
    """Write only ``keyring.json`` and ``*.pub`` for ``ring`` to ``destination``: what a tools
    container (which must not be able to read private keys) loads with ``load_public``."""
    destination.mkdir(parents=True, exist_ok=True)
    index: dict[str, dict[str, object]] = {}
    for purpose in PURPOSES:
        kids = [k for k in ring.key_ids() if purpose_of(k) == purpose and k != purpose]
        if not kids:
            continue
        for kid in kids:
            (destination / f"{kid}.pub").write_text(
                b64url(ring.public_bytes(kid)), encoding="ascii"
            )
        index[purpose] = {"active": ring.active_kid(purpose), "all": kids}
    tmp = destination / f".{KEYRING_FILE}.{os.getpid()}.tmp"
    tmp.write_text(json.dumps(index, sort_keys=True, indent=2), encoding="utf-8")
    os.replace(tmp, destination / KEYRING_FILE)
