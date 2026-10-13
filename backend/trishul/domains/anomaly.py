# SPDX-License-Identifier: Apache-2.0
"""Robust amount anomaly signal (spec section 4): median/MAD z-score over payee history.

Never produces ALLOW: it can only tighten a decision (ML stage = ``max``).
"""

import math
import sqlite3
from collections.abc import Sequence
from statistics import median

from trishul.contracts.decisions import Decision

MIN_SAMPLES = 5
Z_THRESHOLD = 3.5
MAD_SCALE = 1.4826


def robust_z(history: Sequence[int], amount: int) -> float | None:
    """``|x - median| / (1.4826 * MAD)``; None with fewer than ``MIN_SAMPLES`` samples.

    A zero MAD (all history identical) gives 0.0 for the median amount and ``inf`` otherwise.
    """
    if len(history) < MIN_SAMPLES:
        return None
    med = median(history)
    mad = median(abs(h - med) for h in history)
    deviation = abs(amount - med)
    if mad == 0:
        return 0.0 if deviation == 0 else math.inf
    return float(deviation / (MAD_SCALE * mad))


def anomaly_decision(
    history: Sequence[int], amount: int, threshold: float = Z_THRESHOLD
) -> Decision | None:
    """``Decision.STEP_UP`` when the robust z exceeds ``threshold``; otherwise None (no signal)."""
    z = robust_z(history, amount)
    if z is None or not z > threshold:
        return None
    return Decision.STEP_UP


def payee_history(conn: sqlite3.Connection, principal: str, payee_vpa: str) -> list[int]:
    """Past payment amounts (paise) from the real ledger, oldest first."""
    rows = conn.execute(
        "SELECT amount_paise FROM ledger WHERE principal_id=? AND payee_vpa=? ORDER BY ts, txn_id",
        (principal, payee_vpa),
    ).fetchall()
    return [int(r["amount_paise"]) for r in rows]
