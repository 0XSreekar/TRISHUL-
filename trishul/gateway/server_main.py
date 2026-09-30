"""Entry point for one demo server as a stdio subprocess: ``python -m trishul.gateway.server_main
<upi|crm|mail|files> --db PATH --id-base N``. All servers share the WAL SQLite file."""

import argparse
from collections.abc import Sequence

from trishul.servers import (
    build_crm_server,
    build_files_server,
    build_mail_server,
    build_upi_server,
)
from trishul.store.db import connect
from trishul.store.ids import IdGen


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="trishul-server")
    parser.add_argument("name", choices=["upi", "crm", "mail", "files"])
    parser.add_argument("--db", required=True)
    parser.add_argument("--id-base", type=int, default=1_000_000)
    args = parser.parse_args(argv)
    conn = connect(args.db)
    ids = IdGen(42, start=args.id_base)
    server = {
        "upi": lambda: build_upi_server(conn, ids),
        "crm": lambda: build_crm_server(conn),
        "mail": lambda: build_mail_server(conn, ids),
        "files": lambda: build_files_server(conn),
    }[args.name]()
    server.run(transport="stdio", show_banner=False)


if __name__ == "__main__":
    main()
