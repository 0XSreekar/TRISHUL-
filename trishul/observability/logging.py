"""Structlog-free JSON logging that scrubs secrets/PII before anything is written."""

import json
import logging
from datetime import UTC, datetime

from trishul.contracts.patterns import scrub_text

_STD_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {
    "message",
    "asctime",
    "taskName",
}


def scrub_value(value: object) -> object:
    """Recursively scrub strings (and keys); non-JSON objects are stringified then scrubbed."""
    if isinstance(value, str):
        return scrub_text(value)
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, dict):
        return {scrub_text(str(k)): scrub_value(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [scrub_value(v) for v in value]
    return scrub_text(str(value))


class JsonFormatter(logging.Formatter):
    """One JSON object per line; the redaction backstop runs on every field."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": scrub_text(record.getMessage()),
        }
        extras = {k: v for k, v in record.__dict__.items() if k not in _STD_ATTRS}
        if extras:
            payload["fields"] = scrub_value(extras)
        if record.exc_info:
            payload["exc"] = scrub_text(self.formatException(record.exc_info))
        return json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)


def get_logger(name: str, stream: logging.Handler | None = None) -> logging.Logger:
    """Logger wired to :class:`JsonFormatter`; idempotent per name."""
    logger = logging.getLogger(name)
    if not any(isinstance(h.formatter, JsonFormatter) for h in logger.handlers):
        handler = stream or logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    return logger
