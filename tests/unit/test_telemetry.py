import asyncio
import threading

from opentelemetry.trace import Tracer

from trishul.telemetry.events import EventBus
from trishul.telemetry.otel import setup_tracing, stage_span


async def _take(sub, n):
    return [await asyncio.wait_for(sub.__anext__(), 2) for _ in range(n)]


async def test_ordering_and_schema():
    bus = EventBus()
    sub = bus.subscribe()
    seqs = [bus.publish({"type": "call", "id": f"c{i}"}) for i in range(5)]
    got = await _take(sub, 5)
    assert seqs == [1, 2, 3, 4, 5]
    assert [e["seq"] for e in got] == seqs
    assert all(e["schema_version"] == 2 for e in got)


async def test_dedup_call_id():
    bus = EventBus()
    a = bus.publish({"type": "call", "id": "x"})
    b = bus.publish({"type": "call", "id": "x", "decision": "DENY"})
    assert a == b
    sub = bus.subscribe(resume_from=0)
    assert len(await _take(sub, 1)) == 1
    assert bus.publish({"type": "resolution", "id": "x"}) == a + 1


async def test_resume_after_reconnect():
    bus = EventBus()
    for i in range(5):
        bus.publish({"type": "call", "id": f"c{i}"})
    sub = bus.subscribe(resume_from=3)
    got = await _take(sub, 2)
    assert [e["seq"] for e in got] == [4, 5]
    bus.publish({"type": "call", "id": "c5"})
    assert (await _take(sub, 1))[0]["seq"] == 6


async def test_resume_older_than_ring_yields_gap():
    bus = EventBus(ring_size=4)
    for i in range(10):
        bus.publish({"type": "call", "id": f"c{i}"})
    sub = bus.subscribe(resume_from=2)
    got = await _take(sub, 5)
    assert got[0]["type"] == "gap" and got[0]["from"] == 3 and got[0]["to"] == 6
    assert [e["seq"] for e in got[1:]] == [7, 8, 9, 10]


async def test_backpressure_gap():
    bus = EventBus(client_queue=3)
    sub = bus.subscribe()
    for i in range(10):
        bus.publish({"type": "call", "id": f"c{i}"})
    await asyncio.sleep(0)
    got = await _take(sub, 4)
    assert got[0] == {"type": "gap", "from": 1, "to": 7, "schema_version": 2}
    assert [e["seq"] for e in got[1:]] == [8, 9, 10]


async def test_sanitization():
    bus = EventBus()
    sub = bus.subscribe()
    bus.publish(
        {
            "type": "call",
            "id": "s1",
            "reason": "<script>alert(1)</script> & \x00ok\x1b",
            "args": {"password": "hunter2", "note": "mail bob@example.com now", "n": 3},
            "list": ["<b>", "sk-abcdefghijklmnop123"],
        }
    )
    e = (await _take(sub, 1))[0]
    assert e["reason"] == "&lt;script&gt;alert(1)&lt;/script&gt; &amp; ok"
    assert e["args"]["password"] == "[REDACTED]"
    assert "bob@example.com" not in e["args"]["note"]
    assert e["args"]["n"] == 3
    assert e["list"][0] == "&lt;b&gt;" and "sk-abc" not in e["list"][1]


async def test_thread_safe_publish_and_close():
    bus = EventBus()
    sub = bus.subscribe()
    t = threading.Thread(target=lambda: [bus.publish({"type": "x"}) for _ in range(20)])
    t.start()
    t.join()
    got = await _take(sub, 20)
    assert [e["seq"] for e in got] == list(range(1, 21))
    bus.close()
    try:
        await asyncio.wait_for(sub.__anext__(), 1)
        raise AssertionError("expected stop")
    except StopAsyncIteration:
        pass


def test_percentiles_from_real_spans():
    provider, metrics = setup_tracing()
    tracer: Tracer = provider.get_tracer("t")
    assert metrics.percentiles() == {}
    for _ in range(10):
        with stage_span(tracer, "policy", correlation_id="c1", tool="pay") as st:
            pass
        assert st.duration_ms >= 0
    with tracer.start_as_current_span("other"):
        pass
    p = metrics.percentiles()
    assert set(p) == {"policy"}
    assert p["policy"]["n"] == 10
    assert p["policy"]["p50_ms"] <= p["policy"]["p99_ms"]
    assert p["policy"]["p50_ms"] > 0
