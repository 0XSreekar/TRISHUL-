"""In-memory OpenTelemetry tracing: per-stage span durations and percentiles."""

import math
import os
import threading
import time
from collections import defaultdict, deque
from collections.abc import Iterator
from contextlib import contextmanager

from opentelemetry.context import Context
from opentelemetry.sdk.trace import ReadableSpan, Span, SpanProcessor, TracerProvider
from opentelemetry.trace import Tracer

STAGE_PREFIX = "trishul.stage."
_MAX_SAMPLES = 10_000


class StageMetrics(SpanProcessor):
    """Collects durations (ms) of spans named ``trishul.stage.<stage>``."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._durations: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=_MAX_SAMPLES))

    def on_start(self, span: Span, parent_context: Context | None = None) -> None:
        return None

    def on_end(self, span: ReadableSpan) -> None:
        if (
            not span.name.startswith(STAGE_PREFIX)
            or span.start_time is None
            or span.end_time is None
        ):
            return
        with self._lock:
            self._durations[span.name[len(STAGE_PREFIX) :]].append(
                (span.end_time - span.start_time) / 1e6
            )

    def shutdown(self) -> None:
        return None

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True

    def percentiles(self) -> dict[str, dict[str, float | int | None]]:
        with self._lock:
            snap = {k: sorted(v) for k, v in self._durations.items()}
        out: dict[str, dict[str, float | int | None]] = {}
        for stage, vals in snap.items():
            n = len(vals)
            if n == 0:
                out[stage] = {"p50_ms": None, "p99_ms": None, "n": 0}
                continue
            out[stage] = {"p50_ms": _rank(vals, 50), "p99_ms": _rank(vals, 99), "n": n}
        return out


def _rank(sorted_vals: list[float], pct: int) -> float:
    idx = max(1, math.ceil(pct / 100 * len(sorted_vals))) - 1
    return sorted_vals[idx]


def setup_tracing() -> tuple[TracerProvider, StageMetrics]:
    provider = TracerProvider()
    metrics = StageMetrics()
    provider.add_span_processor(metrics)
    if os.environ.get("TRISHUL_OTEL_CONSOLE") == "1":
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor

        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
    return provider, metrics


class StageTimer:
    def __init__(self) -> None:
        self.duration_ms: float = 0.0


@contextmanager
def stage_span(
    tracer: Tracer, stage: str, *, correlation_id: str, tool: str
) -> Iterator[StageTimer]:
    timer = StageTimer()
    start = time.perf_counter()
    with tracer.start_as_current_span(
        STAGE_PREFIX + stage, attributes={"correlation_id": correlation_id, "tool": tool}
    ):
        try:
            yield timer
        finally:
            timer.duration_ms = (time.perf_counter() - start) * 1000.0
