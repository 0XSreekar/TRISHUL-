"""Users, roles and server-side sessions stored in the shared SQLite database.

Roles: ``approver`` (may approve/reject step-up approvals) and ``operator`` (may run operator
actions through a session). The two never overlap: an operator session cannot approve and an
approver session cannot run operator actions. Session ids are 256-bit random values; only their
SHA-256 is stored. Nothing here logs a password, hash or session id.
"""

import hashlib
import os
import secrets
import sqlite3
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Mapping
from typing import Literal, NamedTuple

from trishul.auth.passwords import MAX_PASSWORD_LENGTH, burn_verify, hash_password, verify_password

Role = Literal["approver", "operator"]
APPROVER_ENV = "TRISHUL_APPROVER_PASSWORD"
OPERATOR_ENV = "TRISHUL_OPERATOR_PASSWORD"
DEMO_ACCOUNTS: tuple[tuple[str, Role, str], ...] = (
    ("approver", "approver", APPROVER_ENV),
    ("operator", "operator", OPERATOR_ENV),
)

IDLE_SECONDS = 30 * 60
ABSOLUTE_SECONDS = 8 * 3600
LOGIN_PER_MINUTE = 5
MAX_USERNAME = 64
MAX_TRACKED_CLIENTS = 10_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
    user_id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('approver','operator')),
    pw_hash TEXT NOT NULL,
    created_at REAL NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions(
    sid_sha256 TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id),
    csrf TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_seen REAL NOT NULL,
    expires_at REAL NOT NULL
);
"""


class AuthError(Exception):
    """Uniform authentication failure (never says whether the user exists)."""


class RateLimitedError(AuthError):
    """Too many login attempts from one client key."""


class User(NamedTuple):
    user_id: str
    username: str
    role: Role


class Session(NamedTuple):
    user_id: str
    username: str
    role: Role
    csrf: str


def user_id_for(username: str) -> str:
    """Stable id derived from the username so audit leaves stay comparable across resets."""
    return "usr_" + hashlib.sha256(username.encode()).hexdigest()[:12]


def _sid_hash(sid: str) -> str:
    return hashlib.sha256(sid.encode()).hexdigest()


class AuthService:
    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        clock: Callable[[], float] = time.time,
        mono: Callable[[], float] = time.monotonic,
    ) -> None:
        self.conn = conn
        self.clock = clock
        self.mono = mono
        self._attempts: OrderedDict[str, deque[float]] = OrderedDict()
        conn.executescript(SCHEMA)

    # --- accounts ------------------------------------------------------------------------
    def upsert_user(self, username: str, password: str, role: Role) -> tuple[str, bool]:
        """Create or update a user; returns ``(user_id, created)``. Raises ``ValueError`` if the
        password is too short or the username invalid."""
        if not username or len(username) > MAX_USERNAME or not username.isascii():
            raise ValueError("invalid username")
        if role not in ("approver", "operator"):
            raise ValueError("invalid role")
        pw_hash = hash_password(password)
        existed = (
            self.conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
            is not None
        )
        uid = user_id_for(username)
        self.conn.execute(
            "INSERT INTO users(user_id, username, role, pw_hash, created_at, disabled)"
            " VALUES (?,?,?,?,?,0) ON CONFLICT(username) DO UPDATE SET"
            " role=excluded.role, pw_hash=excluded.pw_hash, disabled=0",
            (uid, username, role, pw_hash, self.clock()),
        )
        return uid, not existed

    def provision_demo_accounts(self, env: Mapping[str, str] | None = None) -> dict[str, str]:
        """Create ``approver`` / ``operator`` from their env passwords. A missing or too-short
        password leaves that account uncreated (approvals then fail closed). Returns a status
        per account; never the password."""
        src = os.environ if env is None else env
        out: dict[str, str] = {}
        for username, role, var in DEMO_ACCOUNTS:
            password = src.get(var, "")
            if not password:
                out[username] = f"not created: set {var} (at least 12 characters)"
                continue
            try:
                _, created = self.upsert_user(username, password, role)
            except ValueError:
                out[username] = f"not created: {var} must be 12-{MAX_PASSWORD_LENGTH} characters"
                continue
            out[username] = "created" if created else "updated"
        return out

    # --- authentication ------------------------------------------------------------------
    def authenticate(self, username: str, password: str, role: Role | None = None) -> User | None:
        """Verify credentials (no session, no rate limit: CLI and ``login`` build on this)."""
        if (
            not isinstance(username, str)
            or not isinstance(password, str)
            or not 0 < len(username) <= MAX_USERNAME
            or len(password) > MAX_PASSWORD_LENGTH
        ):
            burn_verify("x")
            return None
        row = self.conn.execute(
            "SELECT user_id, username, role, pw_hash, disabled FROM users WHERE username=?",
            (username,),
        ).fetchone()
        if row is None:
            burn_verify(password)
            return None
        ok = verify_password(row["pw_hash"], password)
        if not ok or row["disabled"] or (role is not None and row["role"] != role):
            return None
        return User(row["user_id"], row["username"], row["role"])

    def _rate_limit(self, client_key: str) -> None:
        now = self.mono()
        window = self._attempts.get(client_key)
        if window is None:
            window = self._attempts[client_key] = deque()
            while len(self._attempts) > MAX_TRACKED_CLIENTS:
                self._attempts.popitem(last=False)
        self._attempts.move_to_end(client_key)
        while window and now - window[0] >= 60.0:
            window.popleft()
        if len(window) >= LOGIN_PER_MINUTE:
            raise RateLimitedError("too many login attempts")
        window.append(now)

    def login(self, username: str, password: str, client_key: str) -> tuple[str, Session]:
        """Returns ``(session_id, session)``. Raises ``RateLimitedError`` / ``AuthError``."""
        self._rate_limit(client_key)
        user = self.authenticate(username, password)
        if user is None:
            raise AuthError("invalid credentials")
        now = self.clock()
        sid = secrets.token_urlsafe(32)  # 256 bits
        csrf = secrets.token_urlsafe(32)
        self.conn.execute(
            "INSERT INTO sessions(sid_sha256, user_id, csrf, created_at, last_seen, expires_at)"
            " VALUES (?,?,?,?,?,?)",
            (_sid_hash(sid), user.user_id, csrf, now, now, now + ABSOLUTE_SECONDS),
        )
        self.conn.execute("DELETE FROM sessions WHERE expires_at<=?", (now,))
        return sid, Session(user.user_id, user.username, user.role, csrf)

    def session(self, sid: str | None) -> Session | None:
        """The live session for ``sid`` (touching ``last_seen``), else None."""
        if not sid or len(sid) > 128:
            return None
        key = _sid_hash(sid)
        row = self.conn.execute(
            "SELECT s.csrf, s.last_seen, s.expires_at, u.user_id, u.username, u.role, u.disabled"
            " FROM sessions s JOIN users u ON u.user_id = s.user_id WHERE s.sid_sha256=?",
            (key,),
        ).fetchone()
        if row is None:
            return None
        now = self.clock()
        if row["disabled"] or now >= row["expires_at"] or now - row["last_seen"] >= IDLE_SECONDS:
            self.conn.execute("DELETE FROM sessions WHERE sid_sha256=?", (key,))
            return None
        self.conn.execute("UPDATE sessions SET last_seen=? WHERE sid_sha256=?", (now, key))
        return Session(row["user_id"], row["username"], row["role"], row["csrf"])

    def logout(self, sid: str | None) -> None:
        if sid:
            self.conn.execute("DELETE FROM sessions WHERE sid_sha256=?", (_sid_hash(sid),))
