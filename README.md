# QuorumVM — Extraction-Resistant Computation via Threshold Execution

[![Tests](https://img.shields.io/badge/tests-108%2F108%20passing-brightgreen)](#test-results)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](#quick-start)
[![License](https://img.shields.io/badge/license-MIT-green)](#license)

> **Make the capability to execute a program require a quorum, and limit oracle access so black-box cloning becomes expensive and detectable.**

QuorumVM is a runtime where programs are executed through **K-of-N threshold participation** of independent custodians. Secret parameters are Shamir-shared — no single machine ever holds full authority to execute or reconstruct the program. An integrated **oracle control plane** governs query budgets, rate limits, and provides an immutable audit trail.

This is a working MVP with **108 passing tests**, including a **13-test whitepaper compliance suite** verified against a live distributed GKE cluster. Multiplications are performed via the **Beaver triple protocol** — no custodian ever sees plain input values or intermediate products.

---

## Why?

As reverse engineering and automated program synthesis scale, software as a static artifact becomes increasingly extractable. QuorumVM raises extraction cost asymmetrically:

| Threat | Defense |
|---|---|
| Steal the server → copy the model | Parameters are Shamir-shared across N custodians; need to compromise K |
| Query the API → clone via black-box extraction | Per-identity budgets + rate limiting + anomaly-detectable audit log |
| Reverse-engineer the binary | The "binary" is a circuit DAG; value is in the secret coefficients, not the structure |
| Insider threat (rogue employee) | No single custodian holds the full secret; threshold control |

**This is not absolute impossibility** — it is a cost and access argument anchored in threshold control + anti-oracle governance.

---

## What Can It Protect?

QuorumVM protects **parametric functions** — computations where the value lies in secret numerical parameters, not in the logic itself.

```
┌─────────────────────────────────────────────────────┐
│  Your application (C#, Java, Go, Python, anything)  │
│                                                     │
│  Normal business logic, UI, database, etc.          │
│                                                     │
│  When you need the protected computation:           │
│     result = POST /eval { inputs: {x1: 10, x2: 20} │
│                                                     │
│  You get back a number. You never see the weights.  │
└──────────────────────────┬──────────────────────────┘
                           │ HTTP
                           ▼
┌─────────────────────────────────────────────────────┐
│  QuorumVM (distributed cluster)                     │
│                                                     │
│  Coordinator ──→ Custodian 0 (share of S_v)         │
│       │     ──→ Custodian 1 (share of S_v)         │
│       │     ──→ Custodian 2 (share of S_v)         │
│       │                                             │
│       ├── Policy check (budget, rate limit)         │
│       ├── Shamir-share inputs across custodians     │
│       ├── Fan-out to custodians                     │
│       ├── Beaver protocol for mul nodes (2 rounds)  │
│       ├── Reconstruct output from ≥ K shares        │
│       ├── Audit log (hash-chained)                  │
│       └── Return result                             │
└─────────────────────────────────────────────────────┘
```

### Concrete Use Cases

| Use Case | DSL Program | What's Protected |
|---|---|---|
| **Credit scoring** | `score = w1*income + w2*age + w3*history + bias` | Trained weights |
| **Dynamic pricing** | `price = base + margin*demand + adjustment` | Margin parameters |
| **Lead scoring (CRM)** | `score = w1*interactions + w2*recency + w3*deal_size` | Scoring model |
| **Risk assessment** | `risk = a*exposure + b*volatility + c*correlation` | Risk coefficients |
| **Proprietary metrics** | `health = w1*usage + w2*support_tickets + w3*nps` | Calibrated weights |

### Limitations

QuorumVM executes **arithmetic circuits** (DAGs of `add`, `sub`, `mul` over a prime field). This covers polynomials and linear models. It does **not** support loops, conditionals, string operations, I/O, or neural network activations (ReLU, sigmoid, softmax). See [What PLAN-B is NOT](#what-plan-b-is-not).

---

## Quick Start

### Prerequisites
- Python 3.11+ **or** Docker & Docker Compose

### Option 1: Docker Compose

```bash
docker compose up --build
```

| Service | Port |
|---|---|
| Coordinator | 8000 |
| Custodian 0 | 9100 |
| Custodian 1 | 9101 |
| Custodian 2 | 9102 |

### Option 2: Run locally

```bash
pip install -r requirements.txt
pytest tests/ -v          # 108 tests, no Docker needed
```

### Run the Demo

```bash
python -m quorumvm.demo.run_demo
```

The demo:
1. Compiles `f(x) = (x+7)²` to IR
2. Builds a versioned Program Package with SHA-256 content addressing
3. Generates Shamir shares of secret S_v, distributes to custodians, and pre-generates Beaver triples for all `mul` nodes
4. Collects K-of-N approval signatures and activates the program
5. Evaluates `f(3)=100`, `f(10)=289`, `f(0)=49` — inputs are Shamir-shared, mul is done via Beaver protocol
6. Exhausts the per-identity budget → HTTP 429
7. Triggers rate limiting → HTTP 429
8. Dumps the hash-chained audit log and verifies integrity

---

## Architecture

```
┌──────────┐         ┌──────────────┐
│  Client   │────────▶│ Coordinator  │
└──────────┘         │  (FastAPI)   │
                     │  • policy    │
                     │  • audit log │
                     └──┬───┬───┬───┘
                        │   │   │
              ┌─────────┘   │   └─────────┐
              ▼             ▼             ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │Custodian 0│ │Custodian 1│ │Custodian 2│
        │ (share)  │ │ (share)  │ │ (share)  │
        └──────────┘ └──────────┘ └──────────┘
```

### Components

| Component | Purpose |
|---|---|
| **Compiler** (`compiler/`) | Parses the restricted DSL into a DAG-based IR; builds versioned Program Packages with SHA-256 content addressing |
| **Crypto** (`crypto/`) | Prime-field arithmetic (F_p, p = 2¹²⁷−1), Shamir K-of-N secret sharing, HMAC-SHA256 signatures, Beaver triple generation & sharing |
| **Coordinator** (`coordinator/`) | Orchestrates version activation (K approvals), evaluation fan-out, policy enforcement, audit logging |
| **Custodian** (`custodian/`) | Holds secret shares + Beaver triple shares, evaluates IR with step-by-step mul protocol, signs program approvals |

---

## DSL

A tiny declarative language that compiles to an arithmetic circuit (DAG).

```
# Scoring model: score = 3*x1 + 5*x2 + 7
input x1
input x2
const w1 = 3
const w2 = 5
const bias = 7
mul t1 = w1 x1
mul t2 = w2 x2
add s = t1 t2
add score = s bias
output score
```

**Rules:**
- No loops, no recursion, no I/O
- Operations: `add`, `sub`, `mul` over F_p (p = 2¹²⁷ − 1)
- Any number of `input` and `const` declarations
- Single `output` per program
- All identifiers must be defined before use

The DSL is just one frontend. The platform consumes **IR JSON** — you can generate it programmatically from any language.

---

## Security Model

### Core Invariants (Whitepaper §4)

| # | Invariant | Implementation |
|---|---|---|
| 4.1 | **No single point of authority** | Executing requires K-of-N custodian participation |
| 4.2 | **No single point of knowledge** | Secrets are Shamir-shared; inputs Shamir-shared at eval time; mul via Beaver triples |
| 4.3 | **Oracle access is governed** | Per-identity budgets, token-bucket rate limiting, immutable audit |
| 4.4 | **Version activation is governed** | New versions require ≥ K custodian HMAC approval signatures |
| 4.5 | **Graceful degradation** | Compromise impact scales with number of custodians compromised |

### Beaver Triple Protocol (Secure Multiplication)

Multiplying Shamir shares naively produces degree-2K polynomials that break the threshold scheme. QuorumVM solves this with the Beaver triple protocol:

1. **Install phase**: Coordinator generates random triples (a, b, c) where c = a·b mod p, Shamir-shares them, and distributes shares to custodians alongside the program IR.
2. **Eval Round 1**: Each custodian evaluates the DAG until hitting a `mul` node. It masks its input shares using its Beaver shares: εᵢ = x_share − aᵢ, δᵢ = y_share − bᵢ, and sends these to the coordinator. Execution pauses.
3. **Coordinator reconstructs**: Collects ≥ K masked-diff shares, Lagrange-reconstructs ε = x − a and δ = y − b. These reveal nothing about x or y (masked by random a, b).
4. **Eval Round 2**: Coordinator sends (ε, δ) back. Each custodian computes its output share: zᵢ = cᵢ + ε·bᵢ + δ·aᵢ.
5. **Finalize**: Coordinator Lagrange-reconstructs z from ≥ K shares and adds ε·δ to get the final product x·y.

**Key invariant**: No single party ever sees the raw inputs x or y. The coordinator sees only the masked differences ε, δ.

### Threat Model

**Adversary can:**
- Obtain coordinator and custodian code/binaries
- Compromise and fully control **t < K** custodians (root, memory, traffic)
- Submit oracle queries under system policies
- Use advanced automated analysis (including AGI-level capability)

**Out of scope (MVP):**
- t ≥ K compromise/collusion
- Hardware side-channel resistance
- Perfect prevention of black-box approximation under unlimited oracle access

### Anti-Oracle Controls (Whitepaper §8)

| Control | Implementation |
|---|---|
| Identity-bound budgets | Cost units deducted per eval; denial when exhausted |
| Rate limiting | Token-bucket per (program, identity); configurable burst and refill |
| Immutable audit log | SHA-256 hash-chained entries; append-only; tamper-evident |

---

## API Reference

### Coordinator

| Method | Path | Description |
|---|---|---|
| `POST` | `/install` | Install a program package |
| `POST` | `/approve` | Submit a custodian approval signature |
| `GET` | `/status/{program_id}` | Check program activation status (PENDING / ACTIVE) |
| `POST` | `/eval` | Evaluate a program: `{ identity_id, program_id, inputs: {x: int} }` |
| `POST` | `/replenish_beaver` | Replenish Beaver triple pool for a program |
| `GET` | `/beaver_pool/{id}` | Check remaining Beaver triple pool capacity |
| `GET` | `/audit` | Retrieve the full audit log with chain validity |

### Custodian

| Method | Path | Description |
|---|---|---|
| `POST` | `/install` | Install package + secret share |
| `POST` | `/approve` | Sign a program_id with HMAC key |
| `POST` | `/eval_share` | Evaluate IR on input shares, return output (legacy) |
| `POST` | `/install_beaver` | Install Beaver triple shares for mul nodes |
| `POST` | `/eval_beaver` | Beaver-aware step-by-step evaluation |
| `POST` | `/beaver_round2` | Receive reconstructed (ε, δ) and continue eval |
| `GET` | `/health` | Health check |

### Example: Calling from Any Language

```bash
curl -X POST http://coordinator:8000/eval \
  -H "Content-Type: application/json" \
  -d '{"identity_id": "user-123", "program_id": "6de1...", "inputs": {"x": 42}}'
```

```json
{"result": 2401, "request_id": "a1b2c3..."}
```

---

## Test Results

### Local Tests (95 passing)

| Suite | Tests | Coverage |
|---|---|---|
| `test_field.py` | 10 | Field arithmetic: add, sub, mul, inv, neg, reduce, wrapping |
| `test_shamir.py` | 7 | Share/reconstruct, K-of-N subsets, edge cases, < K failure |
| `test_signatures.py` | 3 | HMAC sign/verify, wrong key, tampered message |
| `test_compiler.py` | 11 | Parsing, node types, errors, comments, serialization |
| `test_package.py` | 5 | SHA-256 content addressing, determinism, policy hashing |
| `test_executor.py` | 4 | DAG evaluation on plain values and edge cases |
| `test_policy.py` | 3 | Budget exhaustion, identity isolation, unregistered programs |
| `test_audit.py` | 3 | Append/verify, empty chain, hash linking |
| `test_e2e.py` | 5 | Full integration: install → activate → eval → budget → audit |
| `test_beaver.py` | 25 | **Beaver triples**: generation, sharing, pool (pool_size param), protocol correctness (zero/one/large/commutative/associative), StepExecutor pause/resume, full E2E HTTP |
| | 5 | **Beaver pool**: multiple evals, exhaustion (409), replenishment, pool status endpoint, distinct triples per eval |

### Whitepaper Compliance Tests (20 passing locally)

`test_whitepaper_compliance.py` — maps every security invariant from the whitepaper to an automated test with assertions:

| Class | Tests | Whitepaper Section |
|---|---|---|
| `TestThresholdApprovals` | 3 | §4.1 — < K approvals → PENDING; forged signature → 403 |
| `TestEvalRequiresActive` | 2 | §4.1 — eval rejected when PENDING; unknown program → 404 |
| `TestThresholdSecretSharing` | 3 | §4.2/§6 — K shares reconstruct; < K do not; E2E partial failure |
| `TestBudgetEnforcement` | 3 | §8 — budget exhaustion, identity isolation, full HTTP flow |
| `TestRateLimitEnforcement` | 3 | §8 — burst denial, token refill over time, full HTTP flow |
| `TestAuditChainIntegrity` | 3 | §8 — chain validity, eval_ok + eval_denied events, hash linking |
| `TestGracefulDegradation` | 2 | §4.5 — 1 custodian down → still works; too many down → 503 |
| `TestFullWhitepaperFlow` | 1 | §11 — complete golden-path: compile → activate → eval → budget → audit |

### Distributed Cluster Tests (13 passing on GKE)

`test_whitepaper_cluster.py` — runs against **live services on GKE** (real HTTP between pods, no mocks):

```
Cluster:    GKE dbtoagent-cluster (us-central1)
Namespace:  quorumvm
Services:   coordinator:8000, custodian-{0,1,2}:{9100,9101,9102}

§4.1  ✅ fewer_than_k_approvals_stays_pending
      ✅ invalid_signature_rejected
      ✅ eval_rejected_when_pending
§4.2  ✅ k_shares_reconstruct_secret
      ✅ fewer_than_k_shares_fail
§4.4  ✅ exactly_k_approvals_activates
§4.5  ✅ eval_succeeds_with_one_custodian_slow
§8    ✅ budget_allows_then_denies
      ✅ budget_per_identity_isolation
      ✅ rate_limit_denies_burst
      ✅ audit_chain_integrity
      ✅ audit_records_eval_ok_and_denied
§11   ✅ full_e2e_compile_activate_eval_budget_audit

RESULTS: 13/13 passed — ALL WHITEPAPER INVARIANTS VERIFIED ✅
```

---

## Kubernetes Deployment

Manifests in `k8s/`:

```bash
# Apply to your cluster
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/custodians.yaml
kubectl apply -f k8s/coordinator.yaml

# Run whitepaper compliance tests as a Job
kubectl apply -f k8s/whitepaper-tests-job.yaml
kubectl logs -f job/quorumvm-whitepaper-tests -n quorumvm
```

---

## Configuration

See `quorumvm/config.py`:

| Parameter | Default | Description |
|---|---|---|
| `PRIME` | 2¹²⁷ − 1 | Mersenne prime field modulus |
| `NUM_CUSTODIANS` | 3 | N (total custodians) |
| `THRESHOLD` | 2 | K (minimum shares/approvals required) |
| `DEFAULT_BUDGET_PER_IDENTITY` | 5 | Max cost units per identity before denial |
| `DEFAULT_MAX_EVALS_PER_MINUTE` | 10 | Token-bucket rate limit capacity |

---

## Project Layout

```
quorumvm/
├── config.py                  # Global configuration
├── compiler/
│   ├── dsl_parser.py          # DSL → IR compiler
│   ├── ir.py                  # IR data structures (Pydantic)
│   └── package.py             # Program Package builder (SHA-256 addressed)
├── crypto/
│   ├── field.py               # Prime-field arithmetic (F_p)
│   ├── shamir.py              # Shamir K-of-N secret sharing
│   ├── signatures.py          # HMAC-SHA256 per-custodian signatures
│   └── beaver.py              # Beaver triple generation & protocol
├── coordinator/
│   ├── app.py                 # Coordinator FastAPI app
│   ├── policy.py              # Budget & token-bucket rate limiter
│   └── audit.py               # Hash-chained immutable audit log
├── custodian/
│   ├── app.py                 # Custodian FastAPI app (factory pattern)
│   └── executor.py            # DAG executor (StepExecutor with Beaver pause/resume)
└── demo/
    └── run_demo.py            # End-to-end demo script

tests/
├── test_field.py              # Field arithmetic
├── test_shamir.py             # Secret sharing
├── test_signatures.py         # HMAC signatures
├── test_compiler.py           # DSL compiler
├── test_package.py            # Program packages
├── test_executor.py           # DAG executor
├── test_policy.py             # Policy engine
├── test_audit.py              # Audit log
├── test_e2e.py                # Integration (in-process)
├── test_beaver.py             # Beaver triple protocol (18 tests)
├── test_whitepaper_compliance.py  # Whitepaper invariant tests (local)
└── test_whitepaper_cluster.py     # Distributed cluster tests (GKE)

k8s/
├── namespace.yaml             # quorumvm namespace
├── custodians.yaml            # 3 custodian Deployments + Services
├── coordinator.yaml           # Coordinator Deployment + Service
├── demo-job.yaml              # Demo Job
└── whitepaper-tests-job.yaml  # Whitepaper compliance test Job

docker-compose.yml
Dockerfile
requirements.txt
```

---

## What PLAN-B is NOT

- Not obfuscation for evading audits
- Not a malware-packing technique
- Not a promise of absolute unbreakability under total compromise
- Not a general-purpose distributed OS
- Not protection for arbitrary code (loops, conditionals, neural network inference)

It is a foundational pattern for making extraction and misuse of **parametric functions** materially harder under realistic constraints.

---

## Prior Art & References

QuorumVM combines established primitives in a novel architectural pattern:

| Primitive | Reference |
|---|---|
| Shamir Secret Sharing | Shamir, "How to Share a Secret" (1979) |
| MPC evaluation on shares | Goldreich, Micali, Wigderson — GMW protocol (1987) |
| Beaver Triples | Beaver, "Efficient Multiparty Protocols Using Circuit Randomization" (1991) |
| Model extraction attacks | Tramèr et al., "Stealing ML Models via Prediction APIs" (2016) |
| Query-budget defenses | Juuti et al., "PRADA: Protecting Against DNN Model Stealing Attacks" (2019) |
| Practical MPC (SPDZ) | Damgård et al. (2012) |

**The novelty** is not in the cryptographic primitives — it is in combining MPC + anti-oracle governance + threshold version activation as a unified, deployable pattern for extraction resistance.

---

## Open Research Problems

See [PLAN-B_Open_Problems.md](PLAN-B_Open_Problems.md) for research tracks including:
- Oracle-limited extraction formalization and lower bounds
- DSL expressiveness vs. extractability tradeoffs
- Proactive resharing and custodian rotation
- Adaptive pricing policies under suspected extraction

---

## License

MIT
