# SPDX-License-Identifier: Apache-2.0
"""Entry point for one demo server as a stdio subprocess: ``python -m trishul.gateway.server_main
<upi|crm|mail|files> --db PATH --id-base N``. All servers share the WAL SQLite file."""

import argparse
import sqlite3
from collections.abc import Sequence

from trishul.servers import (
    build_crm_server,
    build_files_server,
    build_mail_server,
    build_upi_server,
)
from trishul.store.db import connect
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


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="trishul-server")
    parser.add_argument("name", choices=["upi", "crm", "mail", "files"])
    parser.add_argument("--db", required=True)
    parser.add_argument("--id-base", type=int, default=1_000_000)
    args = parser.parse_args(argv)
    conn = connect(args.db)
    ids = IdGen(42, start=id_start(conn, args.id_base))
    server = {
        "upi": lambda: build_upi_server(conn, ids),
        "crm": lambda: build_crm_server(conn),
        "mail": lambda: build_mail_server(conn, ids),
        "files": lambda: build_files_server(conn),
    }[args.name]()
    server.run(transport="stdio", show_banner=False)


if __name__ == "__main__":
    main()
