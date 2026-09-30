# SPDX-License-Identifier: Apache-2.0
"""Assemble ``bench/results.json`` from real measurements (never fabricated)."""

import asyncio
import importlib.metadata
import json
import platform
import statistics
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from trishul.bench.agentdojo_adapter import run_agentdojo
from trishul.bench.india import (
    DATASET,
    ML_CONFIGS,
    ROOT,
    load_dataset,
    rate,
    run_suite,
    summarize,
)

SCHEMA_VERSION = 1
RESULTS = ROOT / "bench" / "results.json"
VOICE = ROOT / "bench" / "voice.json"
VOICE_EER = ROOT / "bench" / "voice_eer.json"
LATENCY_REPEATS = 5
PACKAGES = ("fastmcp", "pydantic", "z3-solver", "numpy", "cryptography", "starlette")


def _git(*args: str) -> str:
    try:
        out = subprocess.run(  # noqa: S603
            ["git", *args],  # noqa: S607
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _cpu() -> str:
    if sys.platform == "darwin":
        brand = subprocess.run(
            ["sysctl", "-n", "machdep.cpu.brand_string"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        if brand:
            return brand
    return platform.processor() or platform.machine()


def environment() -> dict[str, Any]:
    pkgs: dict[str, str] = {}
    for name in PACKAGES:
        try:
            pkgs[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            continue
    return {
        "os": platform.platform(),
        "cpu": _cpu(),
        "python": platform.python_version(),
        "packages": pkgs,
    }


def _pct(values: list[float], q: float) -> float:
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, round(q * len(ordered) + 0.5) - 1))
    return round(ordered[idx], 3)


def _latency_block(events: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    per: dict[str, list[float]] = {}
    for ev in events:
        if ev.get("type") != "call" or ev.get("mode") == "off":
            continue
        for stage, ms in (ev.get("stage_ms") or {}).items():
            per.setdefault(stage, []).append(float(ms))
        if isinstance(ev.get("latency_ms"), int | float):
            per.setdefault("total", []).append(float(ev["latency_ms"]))
    return {
        stage: {"p50": round(statistics.median(v), 3), "p99": _pct(v, 0.99)}
        for stage, v in sorted(per.items())
    }


def _voice_eer() -> dict[str, Any] | None:
    """Summarise bench/voice_eer.json (scripts/bench_voice_eer.py) when it has measured results."""
    if not VOICE_EER.exists():
        return None
    raw = json.loads(VOICE_EER.read_text(encoding="utf-8"))
    det = raw.get("detector", {}).get("1B", {})
    if det.get("status") != "measured":
        return None
    clean = det["conditions"]["clean"]
    phone = det["conditions"]["phone_mulaw_8k"]
    small = raw.get("detector", {}).get("500M", {})
    return {
        "status": "measured",
        "source": "bench/voice.json+bench/voice_eer.json",
        "detector": "DF_Arena_1B",
        "eer": clean["eer"],
        "accuracy": clean["accuracy"],
        "bonafide_clips": clean["n_bonafide"],
        "spoof_clips": clean["n_spoof"],
        "at_threshold_0_5": {
            k: clean[k] for k in ("frr_real_flagged", "far_spoof_accepted", "accuracy")
        },
        "phone_codec": {
            k: phone[k] for k in ("eer", "frr_real_flagged", "far_spoof_accepted", "accuracy")
        },
        "by_lang_clean": clean["by_lang"],
        "by_lang_phone": phone["by_lang"],
        "owner_clips": {"clean": clean["owner_clips"], "phone": phone["owner_clips"]},
        "df_arena_500m": {
            c: {
                "eer": small["conditions"][c]["eer"],
                "accuracy": small["conditions"][c]["accuracy"],
            }
            for c in ("clean", "phone_mulaw_8k")
        }
        if small.get("status") == "measured"
        else None,
        "asr_hi_te": raw.get("asr"),
        "generated_at": raw.get("generated_at"),
        "git_commit": raw.get("git_commit"),
        "note": (
            "Bonafide: 73 LibriSpeech clips (ONE speaker), 30 FLEURS Hindi, 30 FLEURS Telugu, "
            "project owner's clips. Spoof: content-matched macOS TTS (not a neural voice clone). "
            "Phone = synthetic 8 kHz mu-law band-pass channel. Small sample; see voice_eer.json."
        ),
    }


def _voice() -> dict[str, Any]:
    raw = json.loads(VOICE.read_text(encoding="utf-8"))
    corpus = str(raw.get("corpus", ""))
    bonafide = 0 if "no bonafide" in corpus.lower() else None
    sel = raw.get("spoof_selected", {}).get("size")
    scores: list[float] = []
    for key, entry in raw.get("spoof", {}).items():
        if sel and key.startswith(f"DF_Arena_{sel}/") and entry.get("status") == "measured":
            scores = list(entry.get("spoof_scores", {}).values())
            break
    asr_entries: dict[str, Any] = raw.get("asr", {})
    first_asr: dict[str, Any] = next(iter(asr_entries.values()), {})
    asr_pool: dict[str, Any] = first_asr.get("samples", {})
    wers = [s["wer"] for s in asr_pool.values() if isinstance(s.get("wer"), int | float)]
    detected = sum(1 for s in scores if s >= 0.5)
    eer_doc = _voice_eer()
    if eer_doc is not None:
        return {
            **eer_doc,
            "asr_mean_wer_tts_en_hi_te": round(statistics.mean(wers), 4) if wers else None,
        }
    return {
        "status": "partial" if bonafide == 0 else "measured",
        "source": "bench/voice.json",
        "eer": None,
        "accuracy": None,
        "bonafide_clips": bonafide,
        "spoof_clips": len(scores),
        "spoof_recall": rate(detected, len(scores)),
        "detector": f"DF_Arena_{sel}" if sel else None,
        "asr_mean_wer": round(statistics.mean(wers), 4) if wers else None,
        "note": (
            "EER needs bonafide human speech; corpus is synthetic Apple-TTS only, so eer and "
            "accuracy are null. spoof_recall is the share of TTS clips scored >= 0.5 (recall on "
            "spoofs only, not accuracy)."
        ),
    }


def _by_category(
    scenarios: list[dict[str, Any]], on: dict[str, Any], off: dict[str, Any]
) -> dict[str, Any]:
    cats: dict[str, Any] = {}
    for kind in ("attack", "benign"):
        for cat in sorted({s["category"] for s in scenarios if s["kind"] == kind}):
            group = [s for s in scenarios if s["kind"] == kind and s["category"] == cat]
            metric = "asr" if kind == "attack" else "utility"

            def side(outs: dict[str, Any], group: list[dict[str, Any]] = group) -> dict[str, Any]:
                meas = [outs[s["id"]] for s in group if outs[s["id"]].executed is not None]
                ok = sum(1 for o in meas if o.executed)
                return {"rate": rate(ok, len(meas)), "measured": len(meas), "count": ok}

            cats[cat] = {"kind": kind, "metric": metric, "n": len(group)}
            cats[cat]["with_trishul"] = side(on)
            cats[cat]["without"] = side(off)
    return cats


async def _measure(seed: int) -> dict[str, Any]:
    ds = load_dataset()
    sc = ds["scenarios"]
    on, _ = await run_suite(seed, sc, mode="on")
    off, _ = await run_suite(seed, sc, mode="off")
    with_s, without_s = summarize(sc, on), summarize(sc, off)
    ablation = []
    for name, cfg in ML_CONFIGS.items():
        outs, _ = await run_suite(seed, sc, mode="on", ml=cfg["ml"], spoof_on=cfg["spoof"])
        s = summarize(sc, outs)
        ablation.append(
            {
                "config": name,
                "asr": s["asr"],
                "utility": s["utility"],
                "attacks_succeeded": s["attacks_succeeded"],
                "benign_completed": s["benign_completed"],
            }
        )
    lat: dict[str, list[dict[str, Any]]] = {"on": [], "off": []}
    for ml_flag, key in ((True, "on"), (False, "off")):
        for _ in range(LATENCY_REPEATS):
            _, events = await run_suite(seed, sc, mode="on", ml=ml_flag, spoof_on=ml_flag)
            lat[key].extend(events)
    failures: list[dict[str, Any]] = []
    for s in sc:
        o_on, o_off = on[s["id"]], off[s["id"]]
        for label, o in (("on", o_on), ("off", o_off)):
            if o.detail.startswith("harness_error"):
                failures.append(
                    {"id": s["id"], "kind": "harness_error", "mode": label, "detail": o.detail}
                )
        if s["kind"] == "attack" and o_on.executed:
            failures.append(
                {
                    "id": s["id"],
                    "kind": "attack_succeeded",
                    "mode": "on",
                    "detail": s["description"],
                }
            )
        if s["kind"] == "benign" and o_on.executed is not True:
            failures.append(
                {"id": s["id"], "kind": "benign_blocked", "mode": "on", "detail": s["description"]}
            )
    attacks = [s for s in sc if s["kind"] == "attack"]
    benign = [s for s in sc if s["kind"] == "benign"]
    lat_on = _latency_block(lat["on"])
    n_calls = sum(1 for e in lat["on"] if e.get("type") == "call")
    return {
        "dataset": ds["version"],
        "attacks": len(attacks),
        "benign": len(benign),
        "with": with_s,
        "without": without_s,
        "per_category": _by_category(sc, on, off),
        "ablation": ablation,
        "latency": {
            "ml_on": lat_on,
            "ml_off": _latency_block(lat["off"]),
            "samples": n_calls,
            "repeats": LATENCY_REPEATS,
            "note": "in-process pipeline stage timings over the India suite (scripted ASR/spoof)",
        },
        "failures": failures,
    }


def build_results(seed: int) -> dict[str, Any]:
    m = asyncio.run(_measure(seed))
    ag = run_agentdojo(seed)
    w, wo = m["with"], m["without"]
    dirty = bool(_git("status", "--porcelain"))
    total_on = m["latency"]["ml_on"].get("total", {})
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git_commit": _git("rev-parse", "HEAD"),
        "git_dirty": dirty,
        "seed": seed,
        "environment": environment(),
        "dataset_version": m["dataset"],
        # flat headline keys read by the landing page (percentages of the India suite, ML on)
        "suite": "India attack suite (india_v1)",
        "attack_success_rate": round(100 * (w["asr"] or 0), 1),
        "attacks_blocked": w["attacks_measured"] - w["attacks_succeeded"],
        "benign_utility": round(100 * (w["utility"] or 0), 1),
        "p99_latency_ms": total_on.get("p99"),
        "suites": {
            "india": {
                "attacks": m["attacks"],
                "benign": m["benign"],
                "with_trishul": {"asr": w["asr"], "utility": w["utility"]},
                "without": {
                    "asr": wo["asr"],
                    "utility": wo["utility"],
                    "attacks_measured": wo["attacks_measured"],
                    "benign_measured": wo["benign_measured"],
                    "note": "OFF namespace; voice scenarios have no OFF endpoint and are excluded",
                },
                "with_counts": {
                    "attacks_succeeded": w["attacks_succeeded"],
                    "attacks_measured": w["attacks_measured"],
                    "benign_completed": w["benign_completed"],
                    "benign_measured": w["benign_measured"],
                },
                "per_category": m["per_category"],
            },
            "agentdojo": ag,
        },
        "latency": m["latency"],
        "voice": _voice(),
        "ablation": m["ablation"],
        "failures": m["failures"],
        "dataset_path": str(DATASET.relative_to(ROOT)),
    }


def write_results(seed: int, path: Path = RESULTS) -> dict[str, Any]:
    results = build_results(seed)
    path.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return results


def merge_agentdojo_blocks(seed: int, path: Path = RESULTS) -> dict[str, Any]:
    """Run the block diagnostic and merge it into an existing results.json (nothing else moves)."""
    from trishul.bench.agentdojo_adapter import diagnose_blocks

    doc = json.loads(path.read_text(encoding="utf-8"))
    diag = diagnose_blocks(seed)
    doc["suites"]["agentdojo"]["block_diagnostics"] = diag
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return diag
