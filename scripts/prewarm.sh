#!/usr/bin/env bash
# Warm native model runtimes before a demo. Every step skips gracefully when a tool is absent.
set -u
cd "$(dirname "$0")/.."
say() { printf '[prewarm] %s\n' "$*"; }

if command -v ollama >/dev/null 2>&1; then
  if curl -fsS --max-time 2 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    MODEL="${OLLAMA_MODEL:-qwen3:8b}"
    if ollama list 2>/dev/null | grep -q "^${MODEL}"; then
      say "warming Ollama model ${MODEL}"
      curl -fsS --max-time 120 http://127.0.0.1:11434/api/generate \
        -d "{\"model\":\"${MODEL}\",\"prompt\":\"ok\",\"stream\":false,\"keep_alive\":\"30m\"}" >/dev/null \
        && say "ollama warm" || say "ollama warm-up failed (continuing)"
    else
      say "ollama model ${MODEL} not pulled; skipping (run: ollama pull ${MODEL})"
    fi
  else
    say "ollama installed but server not running (start: ollama serve); skipping"
  fi
else
  say "ollama not installed; skipping"
fi

if uv run python -c "import mlx_whisper, torch, transformers" >/dev/null 2>&1; then
  say "warming mlx-whisper + DF_Arena (1 s of silence; loads pinned local snapshots, read-only)"
  uv run python - <<'PY' && say "voice models warm" || say "voice warm-up failed or models absent (continuing)"
import numpy as np
from trishul.domains.voice_adapters import ChainASR, default_spoof_adapter
x = np.zeros(16000, dtype=np.float32)
asr, spoof = ChainASR(), default_spoof_adapter()
print("asr available:", asr.available(), "spoof available:", spoof.available())
if asr.available():
    asr.transcribe(x)
if spoof.available():
    spoof.score(x)
PY
else
  say "voice extras not installed (uv sync --extra voice --extra voice-ml); skipping"
fi
say "done"
exit 0
