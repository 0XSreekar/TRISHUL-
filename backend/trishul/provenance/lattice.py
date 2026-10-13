# SPDX-License-Identifier: Apache-2.0
"""Join / order on labels. Pure functions; no declassification exists (A6)."""

from collections.abc import Iterable

from trishul.contracts.labels import Label


def bottom() -> Label:
    return Label.bottom()


def join(a: Label, b: Label) -> Label:
    """Least upper bound: ``(max level, ∪ sources, ∪ tags)``."""
    return Label(level=max(a.level, b.level), sources=a.sources | b.sources, tags=a.tags | b.tags)


def join_all(labels: Iterable[Label]) -> Label:
    """Join of any number of labels; ``bottom`` for none."""
    result = bottom()
    for label in labels:
        result = join(result, label)
    return result


def leq(a: Label, b: Label) -> bool:
    """Partial order: ``a ⊑ b`` iff level, sources and tags are all ≤ / ⊆."""
    return a.level <= b.level and a.sources <= b.sources and a.tags <= b.tags
