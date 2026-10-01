# SPDX-License-Identifier: Apache-2.0
"""Entry point for one demo server: ``python -m trishul.gateway.server_main <upi|crm|mail|files>
--db PATH --keys DIR [--id-base N] [--transport stdio|http --host H --port P]``.

All servers share the WAL SQLite file and hold **public keys only** (``--keys``): every call must
carry a gateway-signed token (see ``trishul.crypto.toolauth``). The default transport is stdio (no
socket at all). The HTTP transport is for Docker; the bind host must be ``127.0.0.1``, a unix
socket (``unix:/path``) or a specific non-wildcard address/hostname, never ``0.0.0.0`` / ``::``.
"""

import argparse
import ipaddress
import os
import sqlite3
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from trishul.crypto.keystore import load_public
from trishul.crypto.toolauth import ToolTokenVerifier
from trishul.servers import (
    build_crm_server,
    build_files_server,
    build_mail_server,
    build_upi_server,
)
from trishul.store.db import DEMO_NOW, connect
from trishul.store.ids import IdGen

_ID_COLUMNS = (("ledger", "txn_id"), ("payees", "payee_id"), ("outbox", "mail_id"))


def id_start(conn: sqlite3.Connection, floor: int) -> int:
    """Counter start for a fresh server process.

    The gateway's stdio proxy may spawn a new subprocess per request, so a counter that restarts at
    ``--id-base`` would re-issue ids already stored (``UNIQUE constraint failed: ledger.txn_id`` on
    the second payment). Resume above the highest counter embedded in any stored id
    (``<prefix>_<counter:06d><4 hex>``); a pure function of the database, so ``demo reset``
    still reproduces the same ids.
    """
    top = floor
    for table, col in _ID_COLUMNS:
        for (value,) in conn.execute(f"SELECT {col} FROM {table}"):  # noqa: S608 - constants
            digits = str(value).partition("_")[2][:-4]
            if digits.isdigit():
                top = max(top, int(digits))
    return top


class BindError(ValueError):
    """The requested bind address would expose the tool server beyond the gateway."""


def validate_bind_host(host: str) -> str:
    """Return ``host`` if it is an acceptable bind address, else raise ``BindError``."""
    candidate = host.strip()
    if not candidate:
        raise BindError("empty bind host is refused (it means all interfaces)")
    if candidate.startswith("unix:"):
        if not candidate[5:]:
            raise BindError("unix socket path is empty")
        return candidate
    bare = candidate.strip("[]")
    if bare in {"*", "0", "::", "0.0.0.0"}:  # noqa: S104 - these are the values we refuse
        raise BindError(f"wildcard bind host {host!r} is refused")
    try:
        unspecified = ipaddress.ip_address(bare).is_unspecified
    except ValueError:
        unspecified = False  # a hostname: allowed (it resolves to one specific address)
    if unspecified:
        raise BindError(f"wildcard bind host {host!r} is refused")
    return candidate


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="trishul-server")
    parser.add_argument("name", choices=["upi", "crm", "mail", "files"])
    parser.add_argument("--db", required=True)
    parser.add_argument("--id-base", type=int, default=1_000_000)
    parser.add_argument("--keys", required=True, type=Path, help="directory with public keys")
    parser.add_argument(
        "--clock",
        choices=["fixed", "live"],
        default=os.environ.get("TRISHUL_CLOCK", "fixed"),
        help="timestamps for ledger rows: fixed demo clock (default, deterministic) or wall clock",
    )
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args(argv)
    if args.transport == "http":
        try:
            args.host = validate_bind_host(args.host)
        except BindError as exc:
            parser.error(str(exc))
    conn = connect(args.db)
    keys_dir: Path = args.keys
    verifier = ToolTokenVerifier(conn, load_public(keys_dir), reload=lambda: load_public(keys_dir))
    ids = IdGen(42, start=id_start(conn, args.id_base))
    clock = (lambda: datetime.now(UTC)) if args.clock == "live" else (lambda: DEMO_NOW)
    server = {
        "upi": lambda: build_upi_server(conn, ids, verifier=verifier, clock=clock),
        "crm": lambda: build_crm_server(conn, verifier=verifier),
        "mail": lambda: build_mail_server(conn, ids, verifier=verifier, clock=clock),
        "files": lambda: build_files_server(conn, verifier=verifier),
    }[args.name]()
    if args.transport == "stdio":
        server.run(transport="stdio", show_banner=False)
    elif args.host.startswith("unix:"):
        server.run(
            transport="http",
            show_banner=False,
            uvicorn_config={"uds": args.host[5:]},
        )
    else:
        server.run(transport="http", show_banner=False, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
