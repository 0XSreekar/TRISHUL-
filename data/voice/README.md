# Voice dataset

Clips here evaluate voice anti-spoof and liveness. Audio files are git-ignored
(`data/voice/*` except this README and `manifest.csv`); only the manifest is tracked.

No clips ship with the repository. Recording real people and generating clones is a human task.

## Consent rules
- Record only people who gave written consent for this specific use (evaluation of a
  voice anti-spoof detector). Keep the signed consent outside the repo; put `yes` in the
  `consent` column only when it exists.
- Never clone a voice without the speaker's written consent for cloning. No public figures,
  no scraped audio.
- Deletion on request: a speaker can withdraw at any time. Delete every file for their
  `speaker_id`, remove their manifest rows, and rerun `scripts/voice_dataset.py validate`.

## How to record
- 16 kHz or higher, mono, 16-bit PCM WAV, 1 to 15 seconds, quiet room.
- `type`: `real` (live speaker) or `clone` (synthetic or cloned speech).
- `condition`: e.g. `clean`, `phone-8k` (see `phone-codec` below), `noisy`.
- `language`: BCP-47 tag such as `en-IN`, `hi-IN`, `te-IN`.
- `duration_s`: measured length in seconds (validated to 0.1 s).
- Clone rows must fill `source_model` (full model ID) and `source_license`.

## Manifest columns
`file,speaker_id,type,condition,language,consent,duration_s,source_model,source_license`
`file` is relative to `data/voice/`.

## Tooling
```
uv run python scripts/voice_dataset.py validate            # checks manifest and files
uv run python scripts/voice_dataset.py phone-codec IN.wav OUT.wav
```
`phone-codec` simulates an 8 kHz narrowband G.711 mu-law phone channel with numpy. If
`ffmpeg` is installed, `--amr` adds an AMR-NB round trip.

## Models and licences
The default detectors are `Speech-Arena-2025/DF_Arena_1B_V_1` and
`Speech-Arena-2025/DF_Arena_500M_V_1` (non-commercial research licence). Download them
through the optional `voice-ml` extra only with the team's approval (1.7 to 4.6 GB).
Record the TTS or clone model and its licence per clone row.
