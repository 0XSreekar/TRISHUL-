# Threat model

## Trust boundaries
1. Agent / LLM <-> gateway MCP port (:8788). The agent and all content it reads (invoices, CRM text,
   transcripts, tool arguments) are untrusted. Content gets provenance labels; labelled data cannot
   reach payment/egress sinks (I1).
2. Gateway <-> tool servers (stdio subprocesses, ALLOW-only path). Servers are not reachable from the network.
3. Operator channel: console REST/WS (:8787), CLI, approvals. Mutations require an allowlisted Origin
   (exact match, CSRF guard) and JSON bodies. Operator routes always require
   `Authorization: Bearer <operator token>` (constant-time compare; `TRISHUL_OPERATOR_TOKEN` or the generated
   `operator.token`, mode 0600), regardless of client address; no token configured fails closed. The native
   server still binds 127.0.0.1 by default (`--host`) and Docker publishes `127.0.0.1:PORT:PORT`.
4. Approvals are Ed25519-signed, bound to the exact call digest, single-use.
5. Audit store (SQLite): Merkle-chained, signed tree head; tampering is detected with exact index.
6. Native models (Ollama, mlx-whisper, DF_Arena): outside the trust core; their output may only raise a decision.
7. Public red-team wall: submissions are treated as untrusted document text, rate-limited, moderated
   for display only, evaluated in namespace `redteam`; kill switch available.

## The 7 invariants and how each is verified
| ID | Invariant | Verified by |
|---|---|---|
| I1 | No untrusted sink argument reaches ALLOW | Z3 (`trishul prove`, `tests/unit/test_z3_policy.py`) |
| I2 | ML/combination never lowers a decision | Z3 proof; also Hypothesis `tests/property/test_invariants.py` |
| I3 | Any stage 2-6 fault never ALLOWs (fail-closed) | Hypothesis `tests/property/test_failclosed.py` |
| I4 | Payment ALLOW implies a valid mandate | Z3 |
| I5 | PII purpose sinks ALLOW only with active consent | Z3 |
| I6 | Approval token valid only for the exact call | Hypothesis `tests/property/test_invariants.py` |
| I7 | Audit byte flip yields exact `bad_index` | Hypothesis `tests/property/test_audit_mutation.py` |

Z3 proves properties of the compiled policy (I1, I2, I4, I5); a deliberately unsafe fixture must yield a
counterexample (`POST /prove {policy:"unsafe_fixture"}`), and the live policy is never swapped. Runtime
properties over code paths (I3, I6, I7) are property-tested with Hypothesis, which is evidence, not proof.
I1 excludes ALLOW resting on a valid human approval for the exact call (documented trade-off).

## Measured results (from `bench/results.json`)
India suite (`india_v1`): 49 attacks, 34 benign. With TRISHUL: attack success 0.0, benign utility 0.8529 (29/34).
Unprotected (OFF namespace, 36 measured attacks): attack success 0.9167. Ablation ASR: rules_only 0.0,
rules_classifier 0.0, full 0.0 (voice ablation uses dataset-scripted spoof scores). In-process p99 total
2.103 ms (ML on).

**Measured fact: with TRISHUL on, 2 of 49 attacks succeed, both cloned-voice detector-evasion cases
(A-VCL-06 score 0.05, A-VCL-07 score 0.1). Voice is currently the one domain whose safety depends on
ML correctness.** Cloned-voice category attack success: 2/7 (0.2857).

## Honest limitations
- Voice language coverage: English is reliable; Hindi is weak; Telugu language auto-detect fails (see `docs/phase-2-report.md`; not in `bench/results.json`).
- Phone-codec degradation of the spoof detector is not measured.
- AgentDojo: banking subset only (see `bench/results.json` `suites.agentdojo.subset_note`); only money-moving tools are guarded, so this is not a general prompt-injection claim.
- Voice EER: null. Corpus is TTS-only (4 spoof clips, 0 bonafide), so only spoof recall 1.0 on TTS is shown;
  false-reject on real humans and real clone detection are unmeasured.
- DF_Arena models are non-commercial research licence.
- Approvals/tasks REST require the operator bearer token; the token file is as sensitive as the approval key.
- Docker-published ports mitigate, not replace, authentication; do not expose the API beyond loopback except the public red-team route via a tunnel.
