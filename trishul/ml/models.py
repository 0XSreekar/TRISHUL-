# SPDX-License-Identifier: Apache-2.0
"""Pinned model identities. Classifier pins live in ``CLASSIFIER_PINS``, local LLM pins in
``LLM_PINS`` (separate literals so independent edits do not collide).

LLM digests are the full sha256 that Ollama reports in ``/api/tags`` for the pulled tag.
"""

CLASSIFIER_PINS: dict[str, dict[str, str]] = {
    "injection": {
        "hf_id": "protectai/deberta-v3-base-prompt-injection-v2",
        # resolved once with huggingface_hub.model_info(hf_id).sha (2026-10-01)
        "revision": "90c9989b1a342275dd0d1a95aad283c04e075671",
        "license": "Apache-2.0",
        "onnx_file": "onnx/model.onnx",
        "download_hint": (
            "huggingface-cli download protectai/deberta-v3-base-prompt-injection-v2 "
            "--revision 90c9989b1a342275dd0d1a95aad283c04e075671"
        ),
    },
}

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
