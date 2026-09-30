from hypothesis import given

from tests.property.strategies import labels
from trishul.contracts.labels import Label
from trishul.provenance.lattice import bottom, join, join_all, leq


@given(labels, labels, labels)
def test_join_associative(a: Label, b: Label, c: Label) -> None:
    assert join(join(a, b), c) == join(a, join(b, c))


@given(labels, labels)
def test_join_commutative(a: Label, b: Label) -> None:
    assert join(a, b) == join(b, a)


@given(labels)
def test_join_idempotent_and_bottom_identity(a: Label) -> None:
    assert join(a, a) == a
    assert join(a, bottom()) == a


@given(labels, labels)
def test_join_is_upper_bound_and_monotone(a: Label, b: Label) -> None:
    j = join(a, b)
    assert leq(a, j) and leq(b, j)


@given(labels, labels, labels)
def test_join_is_least_upper_bound(a: Label, b: Label, c: Label) -> None:
    if leq(a, c) and leq(b, c):
        assert leq(join(a, b), c)


@given(labels, labels, labels)
def test_join_monotone_in_each_argument(a: Label, b: Label, c: Label) -> None:
    if leq(a, b):
        assert leq(join(a, c), join(b, c))


@given(labels)
def test_leq_reflexive_and_bottom_least(a: Label) -> None:
    assert leq(a, a)
    assert leq(bottom(), a)


@given(labels, labels)
def test_leq_antisymmetric(a: Label, b: Label) -> None:
    if leq(a, b) and leq(b, a):
        assert a == b


@given(labels, labels, labels)
def test_leq_transitive(a: Label, b: Label, c: Label) -> None:
    if leq(a, b) and leq(b, c):
        assert leq(a, c)


@given(labels, labels)
def test_join_all_matches_fold(a: Label, b: Label) -> None:
    assert join_all([a, b]) == join(a, b)
    assert join_all([]) == bottom()
