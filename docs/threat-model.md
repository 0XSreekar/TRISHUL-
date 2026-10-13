# Threat model

## Trust boundaries
1. Agent / LLM <-> gateway MCP port (:8788). The agent and all content it reads (invoices, CRM text,
   transcripts, tool arguments) are untrusted. Content gets provenance labels; labelled data cannot
   reach payment/egress sinks (I1).
2. Gateway <-> tool servers (stdio subprocesses, ALLOW-only path). Servers are not reachable from the
   network, and additionally demand a gateway-signed per-call token (see "Gateway bypass protection").
3. Operator channel: console REST/WS (:8787), CLI, approvals. Mutations require an allowlisted Origin
   (exact match, CSRF guard) and JSON bodies. Operator routes require either
   `Authorization: Bearer <operator token>` (constant-time compare; `TRISHUL_OPERATOR_TOKEN` or the generated
   `operator.token`, mode 0600) or an operator-role session plus `X-CSRF-Token`, regardless of client address;
   no token configured fails closed. The native server still binds 127.0.0.1 by default (`--host`) and Docker
   publishes `127.0.0.1:PORT:PORT`.
4. Approvals are Ed25519-signed, bound to the exact call digest, single-use, and made only by an
   authenticated human approver (see Roles). The approver's `user_id` is stored on the approval, inside the
   signed token claims and in an `approval_resolved` Merkle leaf.
5. Audit store (SQLite): Merkle-chained, signed tree head; tampering is detected with exact index.
6. Native models (Ollama, mlx-whisper, `Speech-Arena-2025/DF_Arena_1B_V_1`): outside the trust core; their output may only raise a decision.
7. Public red-team wall: a separate audience app (`trishul/redteam/app.py`, default :8789) with exactly
   `GET /` and `POST /submit`; it reads and sets no cookies and cannot reach approvals, policy, ML, reset or
   audit. Submissions are treated as untrusted document text, rate-limited, moderated for display only,
   evaluated in namespace `redteam`; kill switch available. The main API has no public submit route.

## Roles and sessions
| Role | How it authenticates | May do | May not do |
|---|---|---|---|
| approver | `POST /auth/login` (argon2id password, min 12 chars); HttpOnly, SameSite=Strict session cookie; `X-CSRF-Token` on approve/reject | approve/reject step-up approvals | any operator action |
| operator | bearer token (CLI/automation) or an operator session + `X-CSRF-Token` | `ml`, `mode`, unsafe-fixture proof, `demo reset`, `demo moment`, `redteam kill/fallback`, consent withdrawal, task binding | approve or reject (neither the bearer token nor an operator session is an approver credential) |
| audience | none (separate port, no cookies) | submit red-team text | everything else |

Accounts are created by `demo reset` / `trishul start` from `TRISHUL_APPROVER_PASSWORD` and `TRISHUL_OPERATOR_PASSWORD`; an unset variable leaves the account uncreated, so approvals fail closed (401). Sessions: 256-bit random ids (only the SHA-256 is stored), 30 min idle and 8 h absolute expiry, login limited to 5 attempts per minute per client with a uniform failure message. Passwords, hashes and session ids are redacted from logs and audit payloads. Every operator action is appended to the audit log before it runs (`{type: operator_action, action, actor, params}`; `actor` is `operator-token`, `cli` or the operator's `user_id`); if that append fails the action is refused. `demo reset` writes its record as the first leaf of the fresh log.

**SameSite is not a port boundary.** Cookies are scoped to host, not port, and `localhost:8787` and `localhost:8789` are the same site, so `SameSite=Strict` does not stop a page on the audience port from causing the browser to send the approver cookie to the main API. The controls that actually separate them are (1) the exact-match Origin allowlist, which never contains the audience origin (403 `forbidden_origin`), (2) the per-session `X-CSRF-Token`, which a cross-origin page cannot read because the API sends no `Access-Control-Allow-Credentials`, and (3) the audience app holding no session logic at all. Do not serve the audience page from the same origin as the console.

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

## Measured results (from `bench/results.json`, commit a924c5b, and `bench/voice_eer.json`)
India suite (`india_v1`): 49 attacks, 34 benign. With TRISHUL: attack success 0.0 (0/49), benign
utility 0.8529 (29/34). Unprotected (OFF namespace, 36 attacks with an OFF path): 0.9167. Ablation:
identical across rules_only / rules_classifier / full. Gate decision latency p99 1.754 ms (ML on).
AgentDojo banking subset (8 user tasks × 4 injections, local `Qwen/Qwen3-8B` (Ollama `qwen3:8b`)): ASR 0.2188 -> 0.0, utility
0.375 -> 0.25.

Earlier drafts reported 2/49 cloned-voice successes (A-VCL-06/07). Those are now blocked because every
voice-initiated payment needs a fresh nonce and out-of-band approval, so voice no longer depends on
the detector being right.

## Key management
- Signing keys are random Ed25519 keys (`cryptography` generate, OS entropy), never derived from the
  public demo seed, so the seed cannot be used to forge mandates, approvals, tree heads or tool tokens.
  The seed only controls data ids and fixtures. `KeyRing.from_seed` exists for unit tests only.
- Four purposes: `mandate-signer`, `approval-signer`, `tree-head-signer`, `gateway-tool`. Key id
  `<purpose>-<first 12 hex of sha256(public key)>`; every signature records its kid (mandate `key_id`,
  approval token `kid`, tree head `key_id`, tool token `kid`). A kid of the wrong purpose never verifies.
- Storage: `TRISHUL_HOME/keys` (default `./.trishul/keys`), directory 0700, files 0600. Loading refuses
  (fail closed) group/world-accessible files, a key file that does not match its kid, or a missing purpose.
- Rotation (`trishul keys rotate <purpose>`, `trishul demo reset --rotate-keys`) adds a key and moves
  `active`; old kids stay in the ring so old signatures keep verifying. A running gateway switches on restart.
- Private keys are never logged, sent over REST/WS/MCP or placed in the audit log; tokens are covered by the
  redaction backstop (`tool_token` pattern).
- Production note: keys belong in a KMS/HSM (for example cloud KMS asymmetric signing keys or a PKCS#11 HSM),
  with signing performed by the service rather than key material on disk, per-purpose IAM, audit of every
  sign call and scheduled rotation. The demo uses local files because it must run offline on one laptop.

## Gateway bypass protection
- Tool servers speak stdio by default (no socket). Over HTTP (Docker) they refuse wildcard binds
  (`0.0.0.0`, `::`, empty) at startup; allowed: `127.0.0.1`, `unix:/path` or one specific address/hostname.
- After ALLOW the gateway signs a token `{v, kid, aud, tool, args_sha256, iat, exp=iat+30 s, nonce}` bound to
  one server, one tool and the JCS hash of the exact arguments. Tool servers hold only public keys and reject
  a missing/malformed token, unknown or wrong-purpose kid, bad signature, aud/tool/args mismatch, expired
  token, `iat` more than 5 s in the future and a reused nonce (single-use via an atomic SQLite insert into
  `tool_nonces`, shared across processes). An agent never sees a token; a client-supplied one is refused.
- Docker: gateway on network `edge` (ports published to 127.0.0.1 only) and `tools` (`internal: true`, so
  no route out and no published ports); only the gateway and the tools service mount the data volume. The
  private key store is a separate volume mounted by the gateway only; tools read an exported public-key directory.
- Residual risk: the SQLite file is shared. Any process that can write the data directory can edit the ledger
  directly, forge nonce rows and bypass every check above; in Docker only gateway and tools mount it. An
  attacker who can read the gateway's private key directory (same OS user outside Docker) can mint tokens.
  A compromised gateway process is inside the trust core by definition. Replay protection depends on the
  `tool_nonces` rows surviving for the 30 s lifetime (rows are pruned only after expiry).

## Honest limitations
- Voice language coverage: Telugu auto-detect picks Tamil (CER 0.94; forced language 0.22); Hindi WER
  0.36 auto, 0.19 forced (`bench/voice_eer.json`).
- Phone codec: real-voice false rejects rise from 2.2 % (clean) to 19.4 % (synthetic 8 kHz μ-law),
  40 % for Hindi/Telugu. Real VoIP codecs (Opus/AMR) are not modelled.
- AgentDojo: banking subset only (see `bench/results.json` `suites.agentdojo.subset_note`); only money-moving tools are guarded, so this is not a general prompt-injection claim.
- Voice EER 0.0 on 134 real vs 90 content-matched TTS clips. That shows TTS is separable, not that
  neural clones are; clones and live callers are unmeasured, and the English real set is one speaker.
- `Speech-Arena-2025/DF_Arena_1B_V_1` and `Speech-Arena-2025/DF_Arena_500M_V_1` models are non-commercial research licence.
- Approvals/tasks REST require the operator bearer token; the token file is as sensitive as the approval key.
- Docker-published ports mitigate, not replace, authentication; do not expose the API beyond loopback except the public red-team route via a tunnel.
