"""SQLite store shared by servers, guards, approvals and the audit log (WAL, one schema).

Connections are in autocommit mode (``isolation_level=None``); callers open transactions
explicitly with ``transaction(conn)`` (``BEGIN IMMEDIATE``) or use ``SAVEPOINT`` for previews.
All timestamps are RFC 3339 UTC strings; all money is integer paise.
"""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from trishul.store.ids import IdGen

DEMO_NOW = datetime(2026, 9, 30, 9, 0, 0, tzinfo=UTC)
DEMO_PRINCIPAL = "user_demo"
DEMO_ACCOUNT = "acct_demo"
DEMO_BALANCE_PAISE = 5_000_000  # INR 50,000.00
FIXTURES_DIR = Path(__file__).resolve().parents[2] / "tests" / "fixtures"
BUSY_TIMEOUT_MS = 5000

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS accounts(
    account_id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL UNIQUE,
    balance_paise INTEGER NOT NULL CHECK (balance_paise >= 0),
    currency TEXT NOT NULL DEFAULT 'INR'
);
CREATE TABLE IF NOT EXISTS payees(
    payee_id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    vpa TEXT NOT NULL,
    name TEXT NOT NULL,
    added_by TEXT NOT NULL DEFAULT 'seed',
    created_ts TEXT NOT NULL,
    UNIQUE(principal_id, vpa)
);
CREATE TABLE IF NOT EXISTS ledger(
    txn_id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    payee_vpa TEXT NOT NULL,
    amount_paise INTEGER NOT NULL CHECK (amount_paise > 0),
    balance_after INTEGER NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    task_id TEXT,
    call_id TEXT,
    ts TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ledger_by_principal_ts ON ledger(principal_id, ts);
CREATE TABLE IF NOT EXISTS mandates(
    mandate_id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    key_id TEXT NOT NULL,
    body TEXT NOT NULL,
    sig TEXT NOT NULL,
    nbf TEXT NOT NULL,
    exp TEXT NOT NULL,
    created_ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS mandate_nonces(
    nonce TEXT PRIMARY KEY,
    mandate_id TEXT NOT NULL REFERENCES mandates(mandate_id),
    ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS consents(
    consent_id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    category TEXT NOT NULL,
    purposes TEXT NOT NULL,
    exp TEXT NOT NULL,
    withdrawn_at TEXT
);
CREATE TABLE IF NOT EXISTS consent_epoch(
    id INTEGER PRIMARY KEY CHECK (id = 1),
    epoch INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals(
    approval_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    call_digest TEXT NOT NULL,
    canonical_call TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected')),
    created_ts TEXT NOT NULL,
    decided_ts TEXT,
    approver TEXT,
    token TEXT,
    token_id TEXT UNIQUE,
    consumed_ts TEXT
);
CREATE INDEX IF NOT EXISTS approvals_by_task_tool ON approvals(task_id, tool);
CREATE TABLE IF NOT EXISTS audit_leaves(
    idx INTEGER PRIMARY KEY,
    payload BLOB NOT NULL,
    leaf_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tree_heads(
    size INTEGER PRIMARY KEY,
    root TEXT NOT NULL,
    ts TEXT NOT NULL,
    sig TEXT NOT NULL,
    key_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS documents(
    doc_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    trust TEXT NOT NULL,
    mime TEXT NOT NULL DEFAULT 'text/html',
    content TEXT NOT NULL,
    meta TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS customers(
    customer_id TEXT PRIMARY KEY,
    principal_id TEXT,
    name TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    pan TEXT,
    aadhaar TEXT,
    address TEXT,
    extra TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS inbox(
    mail_id TEXT PRIMARY KEY,
    sender TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS outbox(
    mail_id TEXT PRIMARY KEY,
    sender TEXT NOT NULL,
    to_addr TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    task_id TEXT,
    call_id TEXT,
    ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS task_bindings(
    task_id TEXT PRIMARY KEY,
    principal TEXT NOT NULL,
    purpose TEXT NOT NULL,
    category TEXT NOT NULL,
    text TEXT NOT NULL,
    params TEXT NOT NULL DEFAULT '{}',
    created_ts TEXT NOT NULL
);
"""

TABLES = (
    "meta",
    "accounts",
    "payees",
    "ledger",
    "mandates",
    "mandate_nonces",
    "consents",
    "consent_epoch",
    "approvals",
    "audit_leaves",
    "tree_heads",
    "documents",
    "customers",
    "inbox",
    "outbox",
    "task_bindings",
)
# children before parents so foreign keys never block the wipe
_WIPE_ORDER = (
    "mandate_nonces",
    "mandates",
    "ledger",
    "accounts",
    "payees",
    "consents",
    "consent_epoch",
    "approvals",
    "audit_leaves",
    "tree_heads",
    "documents",
    "customers",
    "inbox",
    "outbox",
    "task_bindings",
    "meta",
)


def iso(ts: datetime) -> str:
    """RFC 3339 UTC with ``Z`` suffix (lexicographically sortable)."""
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)


def connect(path: str | Path) -> sqlite3.Connection:
    """Open (creating if needed) a WAL database with foreign keys and a busy timeout."""
    conn = sqlite3.connect(
        str(path),
        timeout=BUSY_TIMEOUT_MS / 1000,
        isolation_level=None,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA)
    conn.execute("INSERT OR IGNORE INTO consent_epoch(id, epoch) VALUES (1, 0)")
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """``BEGIN IMMEDIATE`` ... ``COMMIT`` (``ROLLBACK`` on error). Not re-entrant."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


# --- deterministic demo state -----------------------------------------------------------

_DEMO_PAYEES = (
    ("Acme Supplies", "acme.supplies@okbank"),
    ("Bharat Stationers", "bharat.stationers@okbank"),
    ("City Couriers", "city.couriers@okbank"),
)


def _load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _seed_customers(conn: sqlite3.Connection, ids: IdGen, fixtures: Path) -> None:
    path = fixtures / "crm_seed.json"
    if not path.is_file():
        return
    data = _load_json(path)
    rows = data.get("customers", []) if isinstance(data, dict) else data
    if not isinstance(rows, list):
        return
    known = ("name", "email", "phone", "pan", "aadhaar", "address")
    for row in rows:
        if not isinstance(row, dict):
            continue
        cid = str(row.get("customer_id") or row.get("id") or ids.new("cust"))
        principal = row.get("principal_id") or row.get("principal") or cid
        extra = {k: v for k, v in row.items() if k not in (*known, "customer_id", "id")}
        conn.execute(
            "INSERT INTO customers(customer_id, principal_id, name, email, phone, pan, aadhaar,"
            " address, extra) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                cid,
                None if principal is None else str(principal),
                str(row.get("name", cid)),
                *(None if row.get(k) is None else str(row[k]) for k in known[1:]),
                json.dumps(extra, sort_keys=True),
            ),
        )


def _seed_consents(conn: sqlite3.Connection, fixtures: Path) -> None:
    path = fixtures / "consent_seed.json"
    if not path.is_file():
        return
    data = _load_json(path)
    rows = data.get("consents", []) if isinstance(data, dict) else data
    if not isinstance(rows, list):
        return
    for row in rows:
        if isinstance(row, dict):
            withdrawn = row.get("withdrawn_at")
            conn.execute(
                "INSERT INTO consents(consent_id, principal_id, category, purposes, exp,"
                " withdrawn_at) VALUES (?,?,?,?,?,?)",
                (
                    str(row["consent_id"]),
                    str(row["principal_id"]),
                    str(row["category"]),
                    json.dumps(row.get("purposes", []), sort_keys=True),
                    str(row["exp"]),
                    None if withdrawn is None else str(withdrawn),
                ),
            )


def _seed_documents(conn: sqlite3.Connection, ids: IdGen, fixtures: Path) -> None:
    folder = fixtures / "invoices"
    if not folder.is_dir():
        return
    for path in sorted(folder.iterdir()):
        if not path.is_file() or path.suffix not in (".html", ".txt"):
            continue
        # Heuristic: injected/external fixtures are untrusted; everything else is a user upload.
        trust = "external" if "inject" in path.stem else "user_upload"
        conn.execute(
            "INSERT INTO documents(doc_id, name, trust, mime, content) VALUES (?,?,?,?,?)",
            (
                ids.new("doc"),
                path.name,
                trust,
                "text/html" if path.suffix == ".html" else "text/plain",
                path.read_text(encoding="utf-8"),
            ),
        )


def reset(
    conn: sqlite3.Connection,
    seed: int = 42,
    *,
    now: datetime = DEMO_NOW,
    fixtures_dir: Path | None = None,
) -> IdGen:
    """Wipe every table and reseed deterministic demo state. Returns the ``IdGen`` to continue
    with (same seed => same ids, ledger, documents). Fixtures are loaded only if present."""
    fixtures = FIXTURES_DIR if fixtures_dir is None else fixtures_dir
    ids = IdGen(seed)
    ts = iso(now)
    with transaction(conn):
        for table in _WIPE_ORDER:
            conn.execute(f"DELETE FROM {table}")  # noqa: S608 - fixed table names
        conn.execute("INSERT INTO consent_epoch(id, epoch) VALUES (1, 0)")
        conn.execute("INSERT INTO meta(key, value) VALUES ('seed', ?)", (str(seed),))
        conn.execute(
            "INSERT INTO accounts(account_id, principal_id, balance_paise) VALUES (?,?,?)",
            (DEMO_ACCOUNT, DEMO_PRINCIPAL, DEMO_BALANCE_PAISE),
        )
        for name, vpa in _DEMO_PAYEES:
            conn.execute(
                "INSERT INTO payees(payee_id, principal_id, vpa, name, created_ts)"
                " VALUES (?,?,?,?,?)",
                (ids.new("payee"), DEMO_PRINCIPAL, vpa, name, ts),
            )
        _seed_customers(conn, ids, fixtures)
        _seed_consents(conn, fixtures)
        _seed_documents(conn, ids, fixtures)
    return ids
