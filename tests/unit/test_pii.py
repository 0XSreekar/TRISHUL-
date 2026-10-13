import pytest

from trishul.contracts.labels import Tag
from trishul.domains.pii import find_pii, label_pii, verhoeff_valid

VALID_AADHAAR = "234567890124"
INVALID_AADHAAR = "234567890125"  # last digit off by one


def kinds(text: str) -> list[str]:
    return [k for k, _ in find_pii(text)]


def test_verhoeff_known_vectors() -> None:
    assert verhoeff_valid("2363")  # Wikipedia example: payload 236 + check digit 3
    assert not verhoeff_valid("2364")
    assert verhoeff_valid(VALID_AADHAAR)
    assert not verhoeff_valid(INVALID_AADHAAR)
    assert not verhoeff_valid("")
    assert not verhoeff_valid("12a4")


def test_verhoeff_detects_every_single_digit_error() -> None:
    for pos in range(12):
        for digit in "0123456789":
            if digit != VALID_AADHAAR[pos]:
                bad = VALID_AADHAAR[:pos] + digit + VALID_AADHAAR[pos + 1 :]
                assert not verhoeff_valid(bad)


def test_aadhaar_requires_checksum_and_leading_digit() -> None:
    assert kinds(f"id {VALID_AADHAAR}") == ["aadhaar"]
    assert kinds(f"id {INVALID_AADHAAR}") == []
    assert kinds("id 134567890124") == []  # leading 1 never valid
    grouped = "2345 6789 0124"
    assert kinds(grouped) == ["aadhaar"]
    assert label_pii(INVALID_AADHAAR) == frozenset()


def test_email_phone_pan() -> None:
    text = "mail a.b+c@example.co.in, call +919876543210 or 9876543210, PAN ABCPS5678K"
    assert kinds(text) == ["email", "phone", "phone", "pan"]
    spans = dict(find_pii("x ABCPS5678K"))
    assert spans["pan"] == (2, 12)


@pytest.mark.parametrize("bad", ["ABCDE1234F", "abcps5678k", "ABCPS56789", "1234567890"])
def test_non_matches(bad: str) -> None:
    assert [k for k in kinds(bad) if k == "pan"] == []
    assert Tag.PII_PHONE not in label_pii("5876543210")


def test_label_pii_tags_and_closure() -> None:
    tags = label_pii({"a": ["x", {"b": f"aadhaar {VALID_AADHAAR}"}], "c": "ABCPS5678K"})
    assert tags == {Tag.PII, Tag.PII_AADHAAR, Tag.PII_PAN}
    assert label_pii("hello world") == frozenset()
    assert label_pii(9876543210) == {Tag.PII, Tag.PII_PHONE}
    assert label_pii(True) == frozenset()
    assert label_pii(None) == frozenset()
    assert Tag.PII_EMAIL in label_pii(["u@example.com"])
    assert Tag.PII_EMAIL in label_pii({"u@example.com": 1})  # keys are inspected too
