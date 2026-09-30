"""Pinned model identities. Local LLM pins live in ``LLM_PINS`` (classifier pins live in a
separate literal so independent edits do not collide).

Digests are the full sha256 that Ollama reports in ``/api/tags`` for the pulled tag.
"""

LLM_PINS: dict[str, dict[str, str]] = {
    "Qwen/Qwen3-8B": {
        "hf_id": "Qwen/Qwen3-8B",
        "ollama_tag": "qwen3:8b",
        "digest": "500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41",
    },
    "Qwen/Qwen3-4B": {
        "hf_id": "Qwen/Qwen3-4B",
        "ollama_tag": "qwen3:4b",
        "digest": "359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7",
    },
}
