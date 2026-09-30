"""Pinned model revisions. LLM pins live in a separate literal (owned by the reader/LLM work)."""

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
