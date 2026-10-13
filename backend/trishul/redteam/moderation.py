# SPDX-License-Identifier: Apache-2.0
"""Deterministic display filter for public red-team text.

Moderation only affects what is *shown*: a moderated submission is still evaluated by the real
pipeline (the attack attempt is the interesting part), but its text is replaced by a placeholder
in every event and API response.
"""

import re
import unicodedata

WITHHELD = "[withheld by display filter]"

# slurs, sexual content and self-harm terms (deterministic list; matched on a folded copy)
BLOCKLIST: tuple[str, ...] = (
    "nigger",
    "nigga",
    "faggot",
    "retard",
    "chink",
    "kike",
    "spic",
    "tranny",
    "porn",
    "nude",
    "nudes",
    "blowjob",
    "handjob",
    "cumshot",
    "orgasm",
    "rape",
    "rapist",
    "incest",
    "sex",
    "sexual",
    "kys",
    "suicide",
    "kill yourself",
    "kill myself",
    "self harm",
    "selfharm",
    "cut myself",
    "hang myself",
    "end my life",
)
_LEET = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
)
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f​-‏ -‮⁠-⁤]")
_TERMS = re.compile(
    r"(?<![a-z])(?:"
    + "|".join(re.escape(t).replace(r"\ ", r"[\s_-]*") for t in BLOCKLIST)
    + r")(?![a-z])"
)


def normalise(text: str) -> str:
    """NFC-normalise and strip control / bidi / zero-width characters (newline and tab kept)."""
    return _CTRL.sub("", unicodedata.normalize("NFC", text))


def _fold(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text.lower())
    plain = "".join(c for c in decomposed if not unicodedata.combining(c))
    return re.sub(r"(.)\1{2,}", r"\1\1", plain.translate(_LEET))


def is_flagged(text: str) -> bool:
    folded = _fold(text)
    return bool(_TERMS.search(folded))


def display_text(text: str) -> tuple[str, bool]:
    """``(text_to_show, moderated)``."""
    if is_flagged(text):
        return WITHHELD, True
    return text, False
