from datetime import UTC, datetime

from hypothesis import given, settings
from hypothesis import strategies as st

from trishul.audit.log import AuditLog
from trishul.audit.verify import verify
from trishul.crypto.keys import KeyRing
from trishul.store.db import connect

T0 = datetime(2026, 9, 30, tzinfo=UTC)


@settings(max_examples=60, deadline=None)
@given(
    n=st.integers(1, 30),
    every=st.integers(1, 8),
    which=st.data(),
)
def test_single_byte_mutation_gives_exact_index(n: int, every: int, which: st.DataObject) -> None:
    conn = connect(":memory:")
    keys = KeyRing.from_seed(42)
    log = AuditLog(conn, keys, sth_every=every, clock=lambda: T0)
    for i in range(n):
        log.append({"i": i, "note": f"event {i}"})
    assert verify(conn, keys).ok
    index = which.draw(st.integers(0, n - 1))
    payload = bytearray(log.payload(index))
    pos = which.draw(st.integers(0, len(payload) - 1))
    payload[pos] ^= which.draw(st.integers(1, 255))
    conn.execute("UPDATE audit_leaves SET payload=? WHERE idx=?", (bytes(payload), index))
    result = verify(conn, keys)
    assert not result.ok
    assert result.bad_index == index
    expected = tuple(s for s in range(every, n + 1, every) if s > index)
    assert result.invalid_sths == expected
