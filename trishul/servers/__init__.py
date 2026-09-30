"""Demo MCP servers (separate FastMCP instances over the shared SQLite store)."""

from trishul.servers.crm import build_crm_server
from trishul.servers.files import build_files_server
from trishul.servers.mail import build_mail_server
from trishul.servers.upi import build_upi_server, preview_pay_upi

__all__ = [
    "build_crm_server",
    "build_files_server",
    "build_mail_server",
    "build_upi_server",
    "preview_pay_upi",
]
