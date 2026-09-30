import math

from trishul.contracts.decisions import Decision
from trishul.domains.anomaly import anomaly_decision, payee_history, robust_z
from trishul.store.db import connect, reset

HIST = [4400, 4500, 4600, 4500, 4450, 4550]


def test_fewer_than_five_samples_no_signal() -> None:
    assert robust_z([4500] * 4, 999_999) is None
    assert anomaly_decision([4500] * 4, 999_999) is None


def test_robust_z_value() -> None:
    # median 4500, abs devs [100,0,100,0,50,50] -> MAD 50 -> z = 5000/(1.4826*50)
    z = robust_z(HIST, 9500)
    assert z is not None and abs(z - 5000 / (1.4826 * 50)) < 1e-9


def test_outlier_steps_up_never_allows() -> None:
    assert anomaly_decision(HIST, 450_000) == Decision.STEP_UP
    assert anomaly_decision(HIST, 4500) is None
    assert anomaly_decision(HIST, 4600) is None


def test_threshold_is_strict() -> None:
    # exactly z == 3.5 -> not above the threshold
    x = 4500 + int(3.5 * 1.4826 * 50)
    z = robust_z(HIST, x)
    assert z is not None
    assert (anomaly_decision(HIST, x) is None) == (z <= 3.5)


def test_zero_mad() -> None:
    same = [1000] * 6
    assert robust_z(same, 1000) == 0.0
    assert robust_z(same, 1001) == math.inf
    assert anomaly_decision(same, 1001) == Decision.STEP_UP


def test_history_from_ledger() -> None:
    conn = reset_conn()
    for i, amt in enumerate(HIST):
        conn.execute(
            "INSERT INTO ledger(txn_id, principal_id, account_id, payee_vpa, amount_paise,"
            " balance_after, ts) VALUES (?,?,?,?,?,?,?)",
            (f"t{i}", "user_demo", "acct_demo", "a@upi", amt, 0, f"2026-09-0{i + 1}T00:00:00Z"),
        )
    assert payee_history(conn, "user_demo", "a@upi") == HIST
    assert payee_history(conn, "user_demo", "other@upi") == []


def reset_conn():  # type: ignore[no-untyped-def]
    conn = connect(":memory:")
    reset(conn)
    return conn
