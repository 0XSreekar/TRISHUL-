"""VoiceTrust: nonce liveness, quality/ASR/spoof signals and the pure decision table (T4)."""

from __future__ import annotations

import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from trishul.contracts.decisions import Decision, DecisionReason, Stage
from trishul.contracts.labels import Label, Level, SourceRef
from trishul.domains.voice_adapters import (
    ASR,
    ASRResult,
    ChainASR,
    SpoofAdapter,
    SpoofResult,
    default_spoof_adapter,
)
from trishul.domains.voice_audio import Quality, QualityReport, load_wav, quality_gate, vad_trim
from trishul.provenance.labeled import Labeled

type Liveness = Literal["match", "mismatch", "expired", "unknown"]
type SinkRisk = Literal["low", "high"]

NONCE_TTL_S = 10.0
LIVENESS_MAX_DISTANCE = 0.25
SPOOF_DENY = 0.5
SPOOF_STEP_UP = 0.2

WORDS: tuple[str, ...] = tuple(
    """
    amber anchor apple arrow aspen atlas badge banjo basil beach berry birch blaze bloom bonus
    boxer brave bread brick bridge brook cabin cable camel candy canoe cargo cedar chain chalk
    charm chess chief cider cliff clock cloud clover coast cobra comet coral cotton crane creek
    crown crystal daisy delta denim desert diver dolphin dragon dune eagle earth ember engine
    falcon feather fern ferry field finch flame flint flute forest fossil frost galaxy garden
    garlic ginger glade globe grain granite grape gravel grove harbor hazel heron honey horizon
    hunter island ivory jacket jade jasmine jungle kettle kite ladder lagoon lantern laurel
    lemon lilac linen lotus lumber magnet maple marble meadow melon mint mirror mist monsoon
    moss nectar needle nickel nomad oasis ocean olive onyx orbit orchid otter oxygen paddle palm
    panda pearl pebble pepper piano pilot pine planet plum pocket poppy prairie pulse quartz
    quill rabbit radar rain raven reef ribbon river robin rocket saddle saffron sailor sand
    scarlet shadow shell silver sketch slate solar spice spruce squid star stone storm summit
    sunset swan tablet talon tango temple thunder tiger timber topaz torch tower trail tulip
    tundra turtle umber valley velvet violet walnut water willow window winter wolf yarrow
    yellow zebra zephyr zinc apricot bamboo beacon biscuit breeze cactus canyon carbon cherry
    cosmos dagger dynamo ebony elder fabric gadget glacier hammer indigo jigsaw kernel lizard
    mango napkin orange pickle quiver rubber sponge tomato unicorn vanilla wagon acorn bishop
    dawn eclipse fjord gecko hollow iris juniper koala lava mosaic nutmeg opal parrot quince
    ripple sable thistle urchin vortex
    """.split()  # noqa: SIM905
)
assert len(WORDS) == 256, len(WORDS)  # noqa: S101 - import-time invariant on the fixed list


# ---------------------------------------------------------------- liveness


def _norm(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def normalized_distance(a: str, b: str) -> float:
    m = max(len(a), len(b))
    return 0.0 if m == 0 else levenshtein(a, b) / m


def best_window_distance(nonce_words: list[str], transcript: str) -> float:
    """Minimum normalized Levenshtein between the nonce and any word window of the transcript."""
    target = " ".join(nonce_words)
    tokens = _norm(transcript)
    if not tokens or not target:
        return 1.0
    n = len(nonce_words)
    best = 1.0
    for size in {max(1, n - 1), n, n + 1}:
        for i in range(max(1, len(tokens) - size + 1)):
            best = min(best, normalized_distance(target, " ".join(tokens[i : i + size])))
    return best


@dataclass(frozen=True)
class Nonce:
    nonce_id: str
    words: tuple[str, ...]
    issued_at: float

    @property
    def phrase(self) -> str:
        return " ".join(self.words)


class NonceService:
    """Issues 3-word challenges; TTL 10 s; single use; in-memory, keyed by session."""

    def __init__(
        self, clock: Callable[[], float] = time.monotonic, ttl_s: float = NONCE_TTL_S
    ) -> None:
        self._clock = clock
        self._ttl = ttl_s
        self._live: dict[str, dict[str, Nonce]] = {}
        # consumed-with-match ids (bounded) -> digest of the call that matched (None until bound)
        self._matched: dict[tuple[str, str], str | None] = {}

    def issue(self, session: str) -> Nonce:
        words = tuple(secrets.choice(WORDS) for _ in range(3))
        nonce = Nonce(secrets.token_hex(8), words, self._clock())
        bucket = self._live.setdefault(session, {})
        for nid in [k for k, v in bucket.items() if self._clock() - v.issued_at > self._ttl]:
            del bucket[nid]
        bucket[nonce.nonce_id] = nonce
        return nonce

    def verify(self, session: str, nonce_id: str, transcript: str | None) -> Liveness:
        """Consume the nonce (single use) and compare against the transcript.

        Unknown, reused or cross-session ids -> ``mismatch`` (fail closed). With no transcript
        the nonce is *not* consumed and liveness is ``unknown`` (nothing was attempted).
        """
        bucket = self._live.get(session, {})
        nonce = bucket.get(nonce_id)
        if nonce is None:
            return "mismatch"
        if self._clock() - nonce.issued_at > self._ttl:
            bucket.pop(nonce_id, None)
            return "expired"
        if transcript is None:
            return "unknown"
        if bucket.pop(nonce_id, None) is None:  # atomic consume: a concurrent attempt won it
            return "mismatch"
        dist = best_window_distance(list(nonce.words), transcript)
        if dist <= LIVENESS_MAX_DISTANCE:
            self._matched[(session, nonce_id)] = None  # bound to a call digest by bind_call
            while len(self._matched) > 1024:
                self._matched.pop(next(iter(self._matched)))
            return "match"
        return "mismatch"

    def bind_call(self, session: str, nonce_id: str, call_digest: str) -> None:
        """Record the digest of the call whose attempt matched this nonce (first binding wins)."""
        key = (session, nonce_id)
        if key in self._matched and self._matched[key] is None:
            self._matched[key] = call_digest

    def was_matched(self, session: str, nonce_id: str, call_digest: str) -> bool:
        """True iff this nonce was already consumed by a matching attempt *for this exact call*
        (never a fresh pass: only used to resume a call that an operator approved out of band)."""
        bound = self._matched.get((session, nonce_id))
        return bound is not None and bound == call_digest


# ---------------------------------------------------------------- decision table

R_MISMATCH = "VOICETRUST.LIVENESS.MISMATCH"
R_EXPIRED = "VOICETRUST.LIVENESS.EXPIRED"
R_LIVE_UNKNOWN = "VOICETRUST.LIVENESS.UNKNOWN"
R_SPOOF_HIGH = "VOICETRUST.SPOOF.HIGH"
R_SPOOF_SUSPECT = "VOICETRUST.SPOOF.SUSPECT"
R_QUALITY = "VOICETRUST.QUALITY.INSUFFICIENT"
R_ASR = "VOICETRUST.ASR.NOT_RUN"
R_SINK = "VOICETRUST.SINK.HIGH_RISK"

RULES: dict[str, tuple[Decision, Stage, str]] = {
    R_MISMATCH: (Decision.DENY, Stage.LABEL, "Spoken text does not match the challenge nonce"),
    R_EXPIRED: (Decision.DENY, Stage.LABEL, "Challenge nonce expired"),
    R_SPOOF_HIGH: (Decision.DENY, Stage.ML, "Anti-spoof score indicates synthetic speech"),
    R_LIVE_UNKNOWN: (Decision.STEP_UP, Stage.LABEL, "Liveness could not be established"),
    R_QUALITY: (Decision.STEP_UP, Stage.LABEL, "Audio quality low or unknown"),
    R_ASR: (Decision.STEP_UP, Stage.LABEL, "No ASR backend ran on this clip"),
    R_SPOOF_SUSPECT: (Decision.STEP_UP, Stage.ML, "Anti-spoof score is suspicious"),
    R_SINK: (Decision.STEP_UP, Stage.LABEL, "Voice command targets a high-risk sink"),
}


def voice_decision(
    quality: Quality,
    liveness: Liveness,
    asr_ran: bool,
    spoof: float | None,
    sink_risk: SinkRisk,
) -> tuple[Decision, tuple[str, ...]]:
    """Pure, total decision table. Unrecognised inputs are treated fail-closed (STEP_UP/DENY)."""
    rules: list[str] = []
    if liveness == "mismatch":
        rules.append(R_MISMATCH)
    elif liveness == "expired":
        rules.append(R_EXPIRED)
    elif liveness != "match":
        rules.append(R_LIVE_UNKNOWN)
    if spoof is not None:
        if not spoof < SPOOF_DENY:  # includes NaN
            rules.append(R_SPOOF_HIGH)
        elif spoof >= SPOOF_STEP_UP:
            rules.append(R_SPOOF_SUSPECT)
    if quality != "ok":
        rules.append(R_QUALITY)
    if asr_ran is not True:
        rules.append(R_ASR)
    if sink_risk != "low":
        rules.append(R_SINK)
    decision = Decision.combine(*(RULES[r][0] for r in rules))
    return decision, tuple(sorted(rules))


def voicetrust_facts(
    quality: Quality,
    liveness: Liveness,
    asr_ran: bool,
    spoof: float | None,
    sink_risk: SinkRisk,
) -> dict[str, bool | None]:
    """Boolean facts consumed by ``policies/voicetrust.yaml`` (never ``None``: fail-closed)."""
    high = spoof is not None and not spoof < SPOOF_DENY
    suspect = spoof is not None and not high and spoof >= SPOOF_STEP_UP
    return {
        "voice_quality_ok": quality == "ok",
        "voice_asr_ran": asr_ran is True,
        "voice_liveness_match": liveness == "match",
        "voice_liveness_mismatch": liveness == "mismatch",
        "voice_liveness_expired": liveness == "expired",
        "voice_spoof_ran": spoof is not None,
        "voice_spoof_high": high,
        "voice_spoof_suspect": suspect,
        "voice_sink_high": sink_risk != "low",
    }


def reasons_for(rule_ids: tuple[str, ...]) -> list[DecisionReason]:
    return [
        DecisionReason(rule_id=r, stage=RULES[r][1], decision=RULES[r][0], explanation=RULES[r][2])
        for r in rule_ids
    ]


# ---------------------------------------------------------------- orchestration


@dataclass(frozen=True)
class VoiceAssessment:
    clip_id: str
    quality: QualityReport
    asr: ASRResult
    spoof: SpoofResult
    liveness: Liveness
    decision: Decision
    rule_ids: tuple[str, ...]
    facts: dict[str, bool | None]
    transcript: Labeled[str] | None
    reasons: list[DecisionReason] = field(default_factory=list)


class VoiceTrust:
    def __init__(
        self,
        nonces: NonceService | None = None,
        asr: ASR | None = None,
        spoof: SpoofAdapter | None = None,
    ) -> None:
        self.nonces = nonces or NonceService()
        self.asr: ASR = asr or ChainASR()
        self.spoof: SpoofAdapter = spoof or default_spoof_adapter()

    def assess(
        self,
        session: str,
        clip_id: str,
        wav: bytes | str | Path,
        nonce_id: str,
        sink_risk: SinkRisk = "low",
    ) -> VoiceAssessment:
        load = load_wav(wav)
        qr = quality_gate(load)
        if load.samples is None:
            asr = ASRResult(None, False, "none", None, "audio rejected")
            spoof = SpoofResult(None, False, "none", None, None, "audio rejected")
        else:
            trimmed = vad_trim(load.samples)
            asr = self.asr.transcribe(trimmed)
            spoof = self.spoof.score(trimmed)
        text = asr.text if asr.ran else None
        liveness = self.nonces.verify(session, nonce_id, text)
        score = spoof.score if spoof.ran else None
        decision, rule_ids = voice_decision(qr.quality, liveness, asr.ran, score, sink_risk)
        transcript = (
            Labeled.source(
                text, Label.make(Level.UNTRUSTED, sources=[SourceRef(kind="voice", id=clip_id)])
            )
            if text is not None
            else None
        )
        return VoiceAssessment(
            clip_id=clip_id,
            quality=qr,
            asr=asr,
            spoof=spoof,
            liveness=liveness,
            decision=decision,
            rule_ids=rule_ids,
            facts=voicetrust_facts(qr.quality, liveness, asr.ran, score, sink_risk),
            transcript=transcript,
            reasons=reasons_for(rule_ids),
        )
