# SPDX-License-Identifier: Apache-2.0
"""Analyse a typed request before the agent acts on it (audience page, single box).

Two independent checks; either one flags the text:
  1. the prompt-injection classifier (DeBERTa, the same model the gateway uses on documents);
  2. red-flag rules for manipulation the model is known to miss (urgency, authority claims,
     "note to the AI", claimed approvals, role/system overrides).

Flagged text is treated as untrusted content (the red-team path: the gateway denies on taint).
Clean text is treated as a plain payment request (bound as the task); the gateway then still
applies the signed mandate and caps, so it can ALLOW, STEP_UP or DENY on its own.
"""

import re
from dataclasses import dataclass, field
from typing import Any

from trishul.ml.injection import InjectionClassifier

RED_FLAGS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(p, re.I), label)
    for p, label in (
        (
            r"\b(ignore|disregard|forget|override)\b.{0,40}\b(instruction|rule|polic|previous|above|prior)",
            "tries to override the agent's instructions",
        ),
        (
            r"\b(note|message|instruction)s?\s+(to|for)\s+(the\s+)?(ai|assistant|agent|bot|model)\b",
            "speaks to the AI directly",
        ),
        (
            r"\b(system|admin|developer|root)\s*(:|mode|prompt|override)",
            "claims system or admin control",
        ),
        (
            r"\b(you are now|act as|pretend|jailbreak|do anything now)\b",
            "tries to change the agent's role",
        ),
        (
            r"\b(approv\w*|authori[sz]\w*|permission)\s+(is\s+)?(already|pre)"
            r"[- ]?(given|granted|approved|done)?",
            "claims approval was already given",
        ),
        (r"\balready\s+(approved|authori[sz]ed|verified)\b", "claims approval was already given"),
        (
            r"\b(urgent|immediately|right now|asap|act fast|within \d+ ?min)",
            "uses pressure or urgency",
        ),
        (
            r"\b(ceo|cfo|director|boss|manager|bank official|rbi|police|finance team)\b",
            "claims to be someone in authority",
        ),
        (
            r"\b(also|additionally|secretly|quietly|silently)\s+(pay|send|transfer)",
            "hides an extra payment in the text",
        ),
        (r"\b(do not|don't)\s+(tell|inform|notify|log|ask)", "asks to hide the action"),
        (r"<[^>]+>|white text|hidden text|display:\s*none", "contains hidden markup"),
    )
)


@dataclass(frozen=True)
class Analysis:
    flagged: bool
    score: float | None  # classifier injection probability, None if not run
    model: str  # "flagged" | "clean" | "unavailable" | "off"
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "flagged": self.flagged,
            "injection_score": None if self.score is None else round(self.score, 4),
            "model": self.model,
            "flags": self.flags,
        }


def red_flags(text: str) -> list[str]:
    seen: list[str] = []
    for pattern, label in RED_FLAGS:
        if pattern.search(text) and label not in seen:
            seen.append(label)
    return seen


async def analyse(text: str, clf: InjectionClassifier | None) -> Analysis:
    flags = red_flags(text)
    if clf is None:  # detectors switched off by the operator: rules only
        return Analysis(bool(flags), None, "off", flags)
    sig = await clf.classify(text)
    if sig.status != "ok":  # fail closed: an unreadable verdict never counts as clean
        return Analysis(True, sig.score, "unavailable", [*flags, "the AI detector could not run"])
    if sig.escalate:
        return Analysis(
            True, sig.score, "flagged", ["the AI injection detector flagged it", *flags]
        )
    return Analysis(bool(flags), sig.score, "clean", flags)
