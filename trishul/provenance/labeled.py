"""``Labeled[T]``: values that cannot be relabelled downward through the public API."""

from collections.abc import Callable
from typing import Final, NoReturn

from trishul.contracts.labels import Label
from trishul.provenance.lattice import join, join_all

_KEY: Final = object()


class Labeled[T]:
    """An immutable ``(value, label)`` pair.

    Direct construction is refused. The only paths are :meth:`source` (ingress adapters) and
    :func:`derive`, whose result label is always ``⊒`` the join of its parents' labels.
    """

    __slots__ = ("_label", "_value")
    _value: T
    _label: Label

    def __init__(self, value: T, label: Label, *, _key: object = None) -> None:
        if _key is not _KEY:
            raise TypeError("use Labeled.source() at ingress or derive() to build Labeled values")
        object.__setattr__(self, "_value", value)
        object.__setattr__(self, "_label", label)

    @property
    def value(self) -> T:
        return self._value

    @property
    def label(self) -> Label:
        return self._label

    @classmethod
    def source(cls, value: T, label: Label) -> "Labeled[T]":
        """Ingress only: attach a label to a value that has no labeled parents."""
        return cls(value, label, _key=_KEY)

    def map[R](self, fn: Callable[[T], R], *, extra: Label | None = None) -> "Labeled[R]":
        return derive(fn, self, extra=extra)

    def paraphrase[R](self, fn: Callable[[T], R]) -> "Labeled[R]":
        """A paraphrase is a transformation; it keeps the full label of the original."""
        return derive(fn, self)

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise AttributeError("Labeled is immutable")

    def __delattr__(self, name: str) -> NoReturn:
        raise AttributeError("Labeled is immutable")

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, Labeled)
            and self._value == other._value
            and self._label == other._label
        )

    __hash__ = None  # type: ignore[assignment]

    def __repr__(self) -> str:
        return f"Labeled(<value>, label={self._label!r})"


def derive[R](
    fn: Callable[..., R],
    *parents: Labeled[object],
    extra: Label | None = None,
) -> Labeled[R]:
    """Apply ``fn`` to the parents' values; label = ``join(parents' labels) ⊔ extra``."""
    if not parents:
        raise ValueError("derive() needs at least one parent; use Labeled.source() at ingress")
    result = fn(*(p.value for p in parents))
    if isinstance(result, Labeled):
        raise TypeError("fn must return a plain value; labels are computed by derive()")
    label = join_all(p.label for p in parents)
    if extra is not None:
        label = join(label, extra)
    return Labeled(result, label, _key=_KEY)
