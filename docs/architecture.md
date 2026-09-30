# Architecture

```mermaid
flowchart LR
  subgraph Agent["Untrusted agent side"]
    FB["trishul.finbot (scripted FinBot)"]
    EXT["External agent via MCP"]
    RT["trishul.redteam (wall + moderation + queue)"]
  end
  subgraph GW["trishul.gateway (single process)"]
    MW["middleware.PolicyMiddleware (FastMCP)"]
    PL["pipeline: ingress, provenance, policy, guards, ML, decision, preview, audit"]
    TN["taint.TaintRegistry"]
    BK["backend.GatewayBackend + showcase"]
  end
  subgraph Core["Deterministic core"]
    POL["trishul.policy (compiler, ast, evaluator)"]
    PRV["trishul.provenance (labels, lattice, handles)"]
    DOM["trishul.domains: payshield, purposelock, dpdp, voicetrust, anomaly, pii"]
    APR["trishul.approvals (Ed25519, exact-call digest)"]
  end
  subgraph Store["Evidence"]
    DB[("trishul.store SQLite WAL")]
    AUD["trishul.audit (Merkle log + verify)"]
    KEY["trishul.crypto (keys, JCS)"]
  end
  subgraph Tools["trishul.servers (stdio subprocesses)"]
    UPI[upi]; CRM[crm]; MAIL[mail]; FILES[files]
  end
  API["trishul.telemetry (REST + WS /events, CSRF guard, /console static)"]
  UI["Console + Landing (static HTML)"]
  Z3["trishul.verify (z3_policy, invariants)"]
  ML["Native models: mlx-whisper, Speech-Arena-2025/DF_Arena_1B_V_1, Ollama"]
  FB --> MW
  EXT --> MW
  RT --> MW
  MW --> PL
  PL --> TN & POL & PRV & DOM & APR
  DOM -. voice only .-> ML
  PL --> AUD --> DB
  AUD --> KEY
  PL -->|ALLOW only| UPI & CRM & MAIL & FILES
  UPI & CRM & MAIL & FILES --> DB
  BK --> API --> UI
  Z3 --> POL
  Z3 -->|trishul prove| API
```

Key properties
- One decision core (`trishul.policy` + `trishul.gateway.pipeline`) is shared by the gateway, the
  benchmarks (`trishul.bench`, in-process) and the Z3 translation (`trishul.verify.z3_policy`).
- Tool servers run as stdio subprocesses of the gateway (`trishul.gateway.server_main`) and share the
  WAL SQLite file; the gateway is the only network-facing entry (MCP :8788, REST/WS :8787).
- ML (voice detector, anomaly/PII signals) can only raise a decision (invariant I2), so
  `trishul ml off` never weakens rule-based denial. Voice spoof scoring is the exception in
  practice: see limitations in `docs/threat-model.md`.
- OFF mode routes calls to the isolated `demo_off` namespace, audited with `mode:"off"`.
- Native vs Docker: models always run natively; the container only holds gateway, tool servers,
  SQLite volume and static UI.
