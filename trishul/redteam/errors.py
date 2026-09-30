# SPDX-License-Identifier: Apache-2.0
"""Refusal raised by the red-team service; ``status`` is the HTTP status the API maps it to."""


class RedTeamError(Exception):
    def __init__(self, code: str, status: int) -> None:
        super().__init__(code)
        self.code, self.status = code, status
