# SPDX-License-Identifier: Apache-2.0
"""Reader errors (kept import-light: the gateway pipeline imports this)."""

READER_INVALID_RULE = "CORE.READER.INVALID"


class ExtractionError(Exception):
    """Reader output did not validate (or could not be produced): the call is DENY."""
