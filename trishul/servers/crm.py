# SPDX-License-Identifier: Apache-2.0
"""CRM demo server. Returns full records; response minimisation is applied later by the gateway."""

import json
import sqlite3
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError


def _record(row: sqlite3.Row) -> dict[str, Any]:
    record: dict[str, Any] = {
        k: row[k] for k in ("customer_id", "name", "email", "phone", "pan", "aadhaar", "address")
    }
    record.update(json.loads(row["extra"]))
    return record


def build_crm_server(conn: sqlite3.Connection) -> FastMCP:
    server = FastMCP("crm")

    def fetch(customer_id: str) -> dict[str, Any]:
        row = conn.execute("SELECT * FROM customers WHERE customer_id=?", (customer_id,)).fetchone()
        if row is None:
            raise ToolError(f"unknown customer {customer_id}")
        return _record(row)

    @server.tool
    async def read_customer_data(customer_id: str, fields: list[str]) -> dict[str, Any]:
        """Return the customer record (``fields`` is advisory; the gateway minimises)."""
        return fetch(customer_id)

    @server.tool
    async def export_records(customer_ids: list[str], destination: str) -> dict[str, Any]:
        """Export the given customers' records to ``destination``."""
        records = [fetch(c) for c in customer_ids]
        return {"destination": destination, "count": len(records), "records": records}

    return server
