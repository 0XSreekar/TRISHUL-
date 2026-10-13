# SPDX-License-Identifier: Apache-2.0
"""Run the four demo tool servers over HTTP in one container (the Docker ``tools`` service).

``python -m trishul.gateway.tools_supervisor --db DB --keys PUBDIR --host H --port 9000`` starts
``server_main`` for upi/crm/mail/files on ports 9001..9004 (``--port`` + index + 1), waits for the
gateway to publish its public keys first, and exits non-zero (stopping the rest) as soon as any
server dies so the container restarts as a unit. The bind host is validated by ``server_main``:
wildcard addresses are refused.
"""

import argparse
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from trishul.gateway.pipeline import NAMESPACES
from trishul.gateway.server_main import BindError, validate_bind_host

KEYRING_WAIT_S = 120.0


def server_command(
    name: str, index: int, db: Path, keys: Path, host: str, base_port: int
) -> list[str]:
    return [
        sys.executable,
        "-m",
        "trishul.gateway.server_main",
        name,
        "--db",
        str(db),
        "--keys",
        str(keys),
        "--id-base",
        str((index + 1) * 1_000_000),  # same ids the stdio config uses
        "--transport",
        "http",
        "--host",
        host,
        "--port",
        str(base_port + index + 1),
    ]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trishul-tools")
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--keys", required=True, type=Path, help="public key directory")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=9000, help="base port; servers use +1..+4")
    args = parser.parse_args(argv)
    try:
        host = validate_bind_host(args.host)
    except BindError as exc:
        parser.error(str(exc))
    deadline = time.monotonic() + KEYRING_WAIT_S
    while not (args.keys / "keyring.json").exists():
        if time.monotonic() > deadline:
            print("gateway public keys never appeared; refusing to start", file=sys.stderr)
            return 1
        time.sleep(0.5)
    procs = [
        subprocess.Popen(server_command(ns, i, args.db, args.keys, host, args.port))  # noqa: S603
        for i, ns in enumerate(NAMESPACES)
    ]
    try:
        while all(p.poll() is None for p in procs):
            time.sleep(1.0)
    except KeyboardInterrupt:
        return 0
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
    return 1


if __name__ == "__main__":
    sys.exit(main())
