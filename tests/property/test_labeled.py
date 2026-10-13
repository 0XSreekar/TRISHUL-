import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.property.strategies import labels
from trishul.contracts.labels import Label
from trishul.provenance.labeled import Labeled, derive
from trishul.provenance.lattice import join_all, leq


def test_direct_construction_refused() -> None:
    with pytest.raises(TypeError):
        Labeled("x", Label.bottom())
    with pytest.raises(TypeError):
        Labeled("x", Label.bottom(), _key=object())


def test_immutable() -> None:
    item = Labeled.source("x", Label.bottom())
    with pytest.raises(AttributeError):
        item._label = Label.bottom()  # type: ignore[misc]
    with pytest.raises(AttributeError):
        item.value = "y"  # type: ignore[misc]


def test_derive_needs_parent_and_plain_result() -> None:
    with pytest.raises(ValueError):
        derive(lambda: "x")
    parent = Labeled.source("x", Label.bottom())
    with pytest.raises(TypeError):
        derive(lambda v: Labeled.source(v, Label.bottom()), parent)


@given(st.lists(labels, min_size=1, max_size=5), labels)
def test_derive_never_loses_parent_labels(parent_labels: list[Label], extra: Label) -> None:
    parents = [Labeled.source(i, lab) for i, lab in enumerate(parent_labels)]
    child = derive(lambda *vs: sum(vs), *parents, extra=extra)
    assert child.label == join_all([*parent_labels, extra])
    assert all(leq(lab, child.label) for lab in parent_labels)
    assert leq(extra, child.label)


@given(labels, st.integers(min_value=1, max_value=8))
def test_transform_and_paraphrase_chains_keep_label(label: Label, depth: int) -> None:
    item = Labeled.source("secret text", label)
    current = item
    for i in range(depth):
        current = current.paraphrase(lambda s: s + "!") if i % 2 else current.map(str.upper)
    assert leq(label, current.label)
    assert current.label == label


@given(labels, labels)
def test_multi_parent_join(a: Label, b: Label) -> None:
    child = derive(lambda x, y: x + y, Labeled.source("a", a), Labeled.source("b", b))
    assert leq(a, child.label) and leq(b, child.label)
